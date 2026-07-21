"""
Transit Engine — Encryption & Signing as a Service.

This module implements a server-side cryptography service modelled after
HashiCorp Vault's Transit secrets engine. The central invariant is:

    The raw key material (AES key, RSA/Ed25519 private key) NEVER leaves
    the server through any API endpoint — not even to the key's owner.

All named keys are stored encrypted at rest using the vault's Data Encryption
Key (DEK), which itself lives only in RAM while the vault is unlocked.

Key hierarchy for transit keys:
    Master passphrase
        → Argon2id → KDK
            → KDK wraps DEK (AES-256-GCM)
                → DEK wraps each named key (AES-256-GCM)
                    → Named key encrypts user data / signs user messages
"""

import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage import database


# ---------------------------------------------------------------------------
# 2.1  Named Key Management — AES-256 symmetric keys
# ---------------------------------------------------------------------------

def create_key(key_name: str, owner_email: str, dek: bytes | None) -> dict:
    """
    Create a new named AES-256 encryption/decryption key for a user.

    Security invariants:
      • Vault must be unlocked (dek != None) — keys cannot be created offline.
      • The raw AES key is generated server-side and immediately wrapped by the DEK.
      • Only the wrapped (encrypted) form is persisted to the database.
      • The raw key is never returned in the response.
    """
    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        raise ValueError("INVALID_KEY_NAME")

    key_name = key_name.strip()

    conn = database.get_connection()
    # Key names are scoped per owner — two different users may each have a key
    # called "my-key" without collision (enforced by the composite PK).
    row = conn.execute(
        "SELECT key_name FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        (owner_email, key_name)
    ).fetchone()
    if row is not None:
        raise ValueError("KEY_ALREADY_EXISTS")

    # --- Generate a cryptographically strong 256-bit AES key ---
    # secrets.token_bytes() draws from the OS CSPRNG (e.g. /dev/urandom on Linux,
    # CryptGenRandom on Windows), which is seeded from hardware entropy sources.
    raw_key = secrets.token_bytes(32)

    # --- Wrap the raw key with the DEK (envelope encryption) ---
    # A fresh 96-bit nonce is generated for every encryption operation.
    # Reusing a nonce under the same key would be catastrophic for GCM
    # (it would reveal the XOR of the two plaintexts), so we never reuse.
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)
    # AESGCM.encrypt() returns ciphertext || 16-byte GCM authentication tag
    ciphertext = aesgcm.encrypt(nonce, raw_key, None)

    # Pack nonce + ciphertext as one blob so they travel together as a unit
    encrypted_key_bytes = nonce + ciphertext
    encrypted_key_material_b64 = base64.b64encode(encrypted_key_bytes).decode("utf-8")

    conn.execute(
        """
        INSERT INTO transit_keys (key_name, owner_email, key_usage, encrypted_key_material_b64)
        VALUES (?, ?, ?, ?)
        """,
        (key_name, owner_email, "ENCRYPT_DECRYPT", encrypted_key_material_b64)
    )
    conn.commit()

    # Return only metadata — raw_key and dek never appear in the response.
    return {
        "key_name": key_name,
        "owner_email": owner_email,
        "key_usage": "ENCRYPT_DECRYPT",
        "encrypted_key_material_b64": encrypted_key_material_b64
    }


def list_keys(owner_email: str) -> list[dict]:
    """
    List the names and usage types of all keys owned by the user.

    The query deliberately selects only non-sensitive columns: key_name,
    key_usage, and signing_algorithm. The encrypted_key_material_b64 and
    public_key_b64 columns are never included in the result set.
    """
    conn = database.get_connection()
    rows = conn.execute(
        "SELECT key_name, key_usage, signing_algorithm FROM transit_keys WHERE owner_email = ?",
        (owner_email,)
    ).fetchall()
    return [
        {
            "key_name": r["key_name"],
            "key_usage": r["key_usage"],
            "signing_algorithm": r["signing_algorithm"]
        }
        for r in rows
    ]


def revoke_key(key_name: str, owner_email: str) -> None:
    """
    Permanently and irrecoverably delete a named key.

    Once deleted, any ciphertext or signature produced with this key can
    never be decrypted or verified again — the encrypted key material on
    disk is gone and there is no recovery mechanism. This is by design.
    """
    if not key_name:
        raise ValueError("KEY_NOT_FOUND")

    conn = database.get_connection()
    # Only the owner can revoke their own key — the WHERE clause includes
    # owner_email to prevent one user from deleting another user's key.
    row = conn.execute(
        "SELECT key_name FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        (owner_email, key_name)
    ).fetchone()
    if row is None:
        raise ValueError("KEY_NOT_FOUND")

    conn.execute(
        "DELETE FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        (owner_email, key_name)
    )
    conn.commit()


# ---------------------------------------------------------------------------
# 2.2  Encryption / Decryption API
# ---------------------------------------------------------------------------

def encrypt(key_name: str, plaintext_b64: str, owner_email: str, dek: bytes | None) -> str:
    """
    Encrypt base64-encoded plaintext using a named AES-256-GCM key.

    Returns a self-describing ciphertext:  vault:<key_name>:<base64(nonce+ct+tag)>

    The 'vault:' prefix and embedded key_name allow the decrypt() function
    to automatically locate the correct key without the caller needing to
    track which key was used — the ciphertext is self-routing.

    Security steps (in strict order):
      1. Vault must be unlocked.
      2. Ownership check — performed BEFORE any key material is accessed.
      3. key_usage guard — ENCRYPT_DECRYPT keys only; signing keys are rejected.
      4. Unwrap the named key using the DEK.
      5. Encrypt the plaintext with a fresh nonce.
    """
    from src.storage import disk

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        # Raise PERMISSION_DENIED (not INVALID_KEY_NAME) to avoid disclosing
        # the specific validation that failed — consistent with access errors.
        raise ValueError("PERMISSION_DENIED")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # --- Access control (2.3) ---
    # If the key does not exist OR belongs to a different user, the response
    # is identical (PERMISSION_DENIED + audit log). This prevents an attacker
    # from enumerating key names by observing whether the error is "not found"
    # vs "access denied".
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "ENCRYPT_DECRYPT":
        # A signing key cannot be used for encryption — the usage field
        # enforces strict key separation (sign keys vs. encrypt keys).
        raise ValueError("INVALID_KEY_USAGE")

    # --- Unwrap the named AES key using the DEK ---
    # nonce is the first 12 bytes, ciphertext+tag are the remainder.
    encrypted_key_bytes = base64.b64decode(row["encrypted_key_material_b64"])
    key_nonce = encrypted_key_bytes[:12]
    key_ciphertext = encrypted_key_bytes[12:]

    aesgcm_dek = AESGCM(dek)
    # If the DEK or the stored blob has been tampered with, AESGCM.decrypt()
    # raises InvalidTag here, which propagates as an unhandled 500 error —
    # this indicates vault corruption, not a client error.
    raw_key = aesgcm_dek.decrypt(key_nonce, key_ciphertext, None)

    # Decode plaintext supplied by caller
    try:
        plaintext = base64.b64decode(plaintext_b64)
    except Exception:
        raise ValueError("INVALID_PLAINTEXT_BASE64")

    # --- Encrypt with the named key ---
    # Generate a fresh 96-bit nonce per encryption call.
    # This is critical: GCM security breaks completely if the same (key, nonce)
    # pair is ever reused, so nonces must be unique across all calls.
    aesgcm_key = AESGCM(raw_key)
    nonce = secrets.token_bytes(12)
    ciphertext_and_tag = aesgcm_key.encrypt(nonce, plaintext, None)

    # Encode as self-describing string: vault:<key_name>:<base64(nonce||ct||tag)>
    payload_b64 = base64.b64encode(nonce + ciphertext_and_tag).decode("utf-8")
    return f"vault:{key_name}:{payload_b64}"


def decrypt(ciphertext: str, owner_email: str, dek: bytes | None) -> str:
    """
    Decrypt a vault ciphertext string back to base64-encoded plaintext.

    The ciphertext format 'vault:<key_name>:<payload>' is self-describing:
    decrypt() extracts key_name from the ciphertext itself, so the caller
    does not need to track which key was used for encryption.

    Security steps (in strict order):
      1. Vault must be unlocked.
      2. Parse and validate the ciphertext format.
      3. Ownership check — performed BEFORE any key material is accessed.
      4. key_usage guard.
      5. Unwrap the named key using the DEK.
      6. Authenticate and decrypt the payload (GCM tag verification).
    """
    from src.storage import disk

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not ciphertext or not ciphertext.startswith("vault:"):
        raise ValueError("INVALID_CIPHERTEXT")

    # maxsplit=2 ensures key names that happen to contain ':' are parsed correctly.
    # Without the limit, a key_name like "org:team:key" would produce 4 parts
    # instead of 3, breaking the parse.
    parts = ciphertext.split(":", 2)
    if len(parts) != 3:
        raise ValueError("INVALID_CIPHERTEXT")

    _, key_name, payload_b64 = parts

    try:
        payload = base64.b64decode(payload_b64)
    except Exception:
        raise ValueError("INVALID_CIPHERTEXT")

    # Minimum size: 12-byte nonce + at least 1 byte ciphertext + 16-byte GCM tag = 29 bytes.
    # Any shorter payload is definitively malformed.
    if len(payload) < 12 + 16:
        raise ValueError("INVALID_CIPHERTEXT")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # Access control: same generic error regardless of "key not found" vs "wrong owner"
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "ENCRYPT_DECRYPT":
        raise ValueError("INVALID_KEY_USAGE")

    # Unwrap the named key with the DEK
    encrypted_key_bytes = base64.b64decode(row["encrypted_key_material_b64"])
    key_nonce = encrypted_key_bytes[:12]
    key_ciphertext = encrypted_key_bytes[12:]

    aesgcm_dek = AESGCM(dek)
    raw_key = aesgcm_dek.decrypt(key_nonce, key_ciphertext, None)

    # Unpack the payload: nonce || ciphertext || tag
    nonce = payload[:12]
    ciphertext_and_tag = payload[12:]

    aesgcm_key = AESGCM(raw_key)
    try:
        plaintext = aesgcm_key.decrypt(nonce, ciphertext_and_tag, None)
    except Exception:
        # GCM authentication tag mismatch: the ciphertext was tampered with
        # (or the wrong key was used, which should be impossible via this flow).
        # We never return partial plaintext — decryption is all-or-nothing.
        raise ValueError("DECRYPTION_FAILED")

    return base64.b64encode(plaintext).decode("utf-8")


# ---------------------------------------------------------------------------
# 2.4  Sign & Verify as a Service — asymmetric key pairs
# ---------------------------------------------------------------------------

def create_signing_key(key_name: str, signing_algorithm: str, owner_email: str, dek: bytes | None) -> dict:
    """
    Generate a named asymmetric signing key pair (RSA-2048 or Ed25519).

    Security invariants:
      • The private key is encrypted with the DEK immediately after generation.
      • The private key NEVER appears in any API response — not even in encrypted form.
      • The public key is stored server-side for use by verify() — also not returned.
      • Only key metadata (name, usage, algorithm) is returned to the caller.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
    from cryptography.hazmat.primitives import serialization

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        raise ValueError("INVALID_KEY_NAME")

    key_name = key_name.strip()

    # Only these two algorithms are supported; reject anything else explicitly.
    valid_algos = {"RSASSA_PKCS1_V1_5_SHA_256", "ED25519"}
    if signing_algorithm not in valid_algos:
        raise ValueError("INVALID_SIGNING_ALGORITHM")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT key_name FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        (owner_email, key_name)
    ).fetchone()
    if row is not None:
        raise ValueError("KEY_ALREADY_EXISTS")

    # --- Generate the key pair ---
    if signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        # RSA-2048 with PKCS#1 v1.5 padding and SHA-256.
        # 2048-bit key provides approximately 112 bits of security (NIST SP 800-57).
        # public_exponent=65537 (0x10001) is the standard Fermat prime; using a small
        # exponent (e.g. 3) would enable certain low-exponent RSA attacks.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:  # ED25519
        # Ed25519 (Edwards-curve Digital Signature Algorithm) provides ~128-bit security
        # with a much smaller key (32 bytes vs. 256 bytes for RSA-2048) and is faster
        # to sign and verify. It is also immune to timing side-channels by design.
        private_key = ed25519.Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Serialize private key to PEM/PKCS8 (unencrypted — the DEK wrap below is the encryption layer)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM (SubjectPublicKeyInfo is the standard X.509 format)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # --- Wrap the private key with the DEK ---
    # Same envelope encryption pattern as create_key(): fresh nonce, AES-256-GCM.
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, private_bytes, None)

    encrypted_key_bytes = nonce + ciphertext
    encrypted_key_material_b64 = base64.b64encode(encrypted_key_bytes).decode("utf-8")
    # Store public key as base64-encoded PEM; no encryption needed (it's public by nature)
    public_key_b64 = base64.b64encode(public_bytes).decode("utf-8")

    conn.execute(
        """
        INSERT INTO transit_keys (key_name, owner_email, key_usage, encrypted_key_material_b64, signing_algorithm, public_key_b64)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key_name, owner_email, "SIGN_VERIFY", encrypted_key_material_b64, signing_algorithm, public_key_b64)
    )
    conn.commit()

    # Return only confirmation metadata — no key material of any kind is included.
    return {
        "key_name": key_name,
        "owner_email": owner_email,
        "key_usage": "SIGN_VERIFY",
        "signing_algorithm": signing_algorithm,
        # Neither the private key (encrypted or otherwise) nor the public key
        # is returned in the API response — stored server-side only.
    }


def sign(key_name: str, message_b64: str, message_type: str, owner_email: str, dek: bytes | None) -> dict:
    """
    Sign a base64-encoded message or pre-computed digest using a named signing key.

    message_type options:
      • "RAW"    — server computes SHA-256(message) then signs the digest.
      • "DIGEST" — caller provides a pre-computed SHA-256 digest (exactly 32 bytes).

    Security steps (in strict order):
      1. Vault must be unlocked.
      2. Input validation (message_type, base64 decoding).
      3. Ownership check — BEFORE the private key is unwrapped.
      4. key_usage guard — SIGN_VERIFY keys only.
      5. Unwrap the private key with the DEK (decrypt).
      6. Sign and return the signature. The private key is held only briefly in RAM.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils
    from src.storage import disk

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        raise ValueError("PERMISSION_DENIED")

    if message_type not in {"RAW", "DIGEST"}:
        raise ValueError("INVALID_MESSAGE_TYPE")

    try:
        data = base64.b64decode(message_b64)
    except Exception:
        raise ValueError("INVALID_MESSAGE_BASE64")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # Access control: same generic PERMISSION_DENIED for "not found" and "wrong owner"
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "SIGN_VERIFY":
        # An encryption key cannot be used for signing — enforces key separation.
        raise ValueError("INVALID_KEY_USAGE")

    signing_algorithm = row["signing_algorithm"]

    # --- Unwrap the private key ---
    encrypted_key_bytes = base64.b64decode(row["encrypted_key_material_b64"])
    key_nonce = encrypted_key_bytes[:12]
    key_ciphertext = encrypted_key_bytes[12:]

    aesgcm_dek = AESGCM(dek)
    private_key_pem = aesgcm_dek.decrypt(key_nonce, key_ciphertext, None)

    # Deserialize the PEM private key from the decrypted bytes
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # --- Compute the signature ---
    if signing_algorithm == "ED25519":
        if message_type == "RAW":
            # Ed25519 signs arbitrary-length messages natively, but we hash first
            # to keep the signing contract consistent with the "DIGEST" path and
            # to bound the input size to a fixed 32 bytes in both branches.
            import hashlib
            digest = hashlib.sha256(data).digest()
        else:  # DIGEST
            digest = data
            if len(digest) != 32:
                # A SHA-256 digest is always exactly 32 bytes; anything else is malformed.
                raise ValueError("INVALID_DIGEST")
        signature = private_key.sign(digest)

    elif signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        if message_type == "RAW":
            # The cryptography library handles SHA-256 hashing internally when given
            # hashes.SHA256() — we do NOT pre-hash for RSA (that happens inside sign()).
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:  # DIGEST
            digest = data
            if len(digest) != 32:
                raise ValueError("INVALID_DIGEST")
            # When the caller provides a pre-computed digest, use Prehashed() to tell
            # the library to skip the internal hashing step and sign the digest directly.
            signature = private_key.sign(
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256())
            )
    else:
        raise ValueError("UNSUPPORTED_ALGORITHM")

    signature_b64 = base64.b64encode(signature).decode("utf-8")
    return {
        "signature": signature_b64,
        "key_name": key_name,
        "signing_algorithm": signing_algorithm
    }


def verify(key_name: str, message_b64: str, message_type: str, signature_b64: str,
           owner_email: str, expected_signing_algorithm: str | None = None) -> dict:
    """
    Verify a signature against a base64-encoded message or digest.

    Uses the stored public key — the private key is NEVER accessed during verification.

    Returns {"key_name": ..., "signature_valid": bool, "signing_algorithm": ...}.
    Invalid signatures return signature_valid=False (HTTP 200), not an error,
    so callers can distinguish "bad signature" from "API error".

    The optional expected_signing_algorithm parameter lets callers assert which
    algorithm they expect the key to use. If provided and it doesn't match the
    stored algorithm, ALGORITHM_MISMATCH is raised (HTTP 400).
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils
    from src.storage import disk

    if not key_name or not key_name.strip():
        raise ValueError("PERMISSION_DENIED")

    if message_type not in {"RAW", "DIGEST"}:
        raise ValueError("INVALID_MESSAGE_TYPE")

    try:
        data = base64.b64decode(message_b64)
    except Exception:
        raise ValueError("INVALID_MESSAGE_BASE64")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # Access control: only the key owner may verify with their own key
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "SIGN_VERIFY":
        raise ValueError("INVALID_KEY_USAGE")

    signing_algorithm = row["signing_algorithm"]

    # If caller specified an expected algorithm, enforce it.
    # This prevents accidental cross-algorithm verification where a signature
    # produced under ED25519 is verified against an RSA key with the same name.
    if expected_signing_algorithm is not None and expected_signing_algorithm != signing_algorithm:
        raise ValueError("ALGORITHM_MISMATCH")

    # --- Load the stored public key (no DEK required — public keys are not secret) ---
    public_bytes = base64.b64decode(row["public_key_b64"])
    public_key = serialization.load_pem_public_key(public_bytes)

    # Decode the provided signature
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        # Malformed base64 → the signature can never be valid; return False gracefully.
        return {
            "key_name": key_name,
            "signature_valid": False,
            "signing_algorithm": signing_algorithm
        }

    signature_valid = False
    try:
        if signing_algorithm == "ED25519":
            if message_type == "RAW":
                import hashlib
                # Must hash the message the same way sign() did
                digest = hashlib.sha256(data).digest()
            else:  # DIGEST
                digest = data
                if len(digest) != 32:
                    raise ValueError("INVALID_DIGEST")
            # Ed25519 verify() raises InvalidSignature on failure; success = no exception
            public_key.verify(signature_bytes, digest)
            signature_valid = True

        elif signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
            if message_type == "RAW":
                public_key.verify(
                    signature_bytes,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            else:  # DIGEST
                digest = data
                if len(digest) != 32:
                    raise ValueError("INVALID_DIGEST")
                public_key.verify(
                    signature_bytes,
                    digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256())
                )
            signature_valid = True

    except Exception as e:
        if isinstance(e, ValueError) and str(e) == "INVALID_DIGEST":
            # Re-raise caller-visible errors (bad digest length) as HTTP 400
            raise e
        # All other exceptions (InvalidSignature, etc.) mean the signature did not verify.
        # We do NOT propagate these as errors — instead we set signature_valid=False
        # and return normally (HTTP 200), matching the contract of a verifier API.
        signature_valid = False

    return {
        "key_name": key_name,
        "signature_valid": signature_valid,
        "signing_algorithm": signing_algorithm
    }
