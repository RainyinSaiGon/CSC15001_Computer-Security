import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage import database

def create_key(key_name: str, owner_email: str, dek: bytes | None) -> dict:
    """
    Create a new named key for a user:
    1. Verify vault is unlocked (dek is not None).
    2. Validate key name.
    3. Ensure key name does not already exist for this user.
    4. Generate random 256-bit AES key.
    5. Encrypt the key material with the DEK.
    6. Store in the sqlite database.
    """
    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        raise ValueError("INVALID_KEY_NAME")

    key_name = key_name.strip()

    conn = database.get_connection()
    row = conn.execute(
        "SELECT key_name FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        (owner_email, key_name)
    ).fetchone()
    if row is not None:
        raise ValueError("KEY_ALREADY_EXISTS")

    # Generate AES-256 key
    raw_key = secrets.token_bytes(32)

    # Encrypt raw key with DEK using AES-GCM
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, raw_key, None)

    # Pack nonce and ciphertext together
    encrypted_key_bytes = nonce + ciphertext
    encrypted_key_material_b64 = base64.b64encode(encrypted_key_bytes).decode("utf-8")

    # Save to db
    conn.execute(
        """
        INSERT INTO transit_keys (key_name, owner_email, key_usage, encrypted_key_material_b64)
        VALUES (?, ?, ?, ?)
        """,
        (key_name, owner_email, "ENCRYPT_DECRYPT", encrypted_key_material_b64)
    )
    conn.commit()

    return {
        "key_name": key_name,
        "owner_email": owner_email,
        "key_usage": "ENCRYPT_DECRYPT",
        "encrypted_key_material_b64": encrypted_key_material_b64
    }

def list_keys(owner_email: str) -> list[dict]:
    """
    List names and key_usage of keys created by the user (never plaintext key material).
    """
    conn = database.get_connection()
    rows = conn.execute(
        "SELECT key_name, key_usage FROM transit_keys WHERE owner_email = ?",
        (owner_email,)
    ).fetchall()
    return [{"key_name": r["key_name"], "key_usage": r["key_usage"]} for r in rows]

def revoke_key(key_name: str, owner_email: str) -> None:
    """
    Permanently delete a named key owned by the user.
    """
    if not key_name:
        raise ValueError("KEY_NOT_FOUND")

    conn = database.get_connection()
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


def encrypt(key_name: str, plaintext_b64: str, owner_email: str, dek: bytes | None) -> str:
    """
    Encrypt base64-encoded plaintext using a named key.
    1. Validate vault is unlocked.
    2. Query key.
    3. Check ownership. If not matching, log access denial and raise ValueError("PERMISSION_DENIED").
    4. Check key usage. If not ENCRYPT_DECRYPT, raise ValueError("INVALID_KEY_USAGE").
    5. Decrypt named key using DEK.
    6. Encrypt plaintext using AES-256-GCM.
    7. Return formatted ciphertext.
    """
    from src.storage import disk

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not key_name or not key_name.strip():
        raise ValueError("PERMISSION_DENIED")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # Access control: If key doesn't exist at all, or belongs to another user
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "ENCRYPT_DECRYPT":
        raise ValueError("INVALID_KEY_USAGE")

    # Decrypt the AES key material with the DEK
    encrypted_key_bytes = base64.b64decode(row["encrypted_key_material_b64"])
    key_nonce = encrypted_key_bytes[:12]
    key_ciphertext = encrypted_key_bytes[12:]
    
    aesgcm_dek = AESGCM(dek)
    raw_key = aesgcm_dek.decrypt(key_nonce, key_ciphertext, None)

    # Decode plaintext
    try:
        plaintext = base64.b64decode(plaintext_b64)
    except Exception:
        raise ValueError("INVALID_PLAINTEXT_BASE64")

    # Generate a fresh random nonce for this encryption
    aesgcm_key = AESGCM(raw_key)
    nonce = secrets.token_bytes(12)
    ciphertext_and_tag = aesgcm_key.encrypt(nonce, plaintext, None)

    # Return self-describing ciphertext format: vault:<key_name>:<base64(nonce+ct+tag)>
    payload_b64 = base64.b64encode(nonce + ciphertext_and_tag).decode("utf-8")
    return f"vault:{key_name}:{payload_b64}"


def decrypt(ciphertext: str, owner_email: str, dek: bytes | None) -> str:
    """
    Decrypt the self-describing ciphertext format.
    1. Validate vault is unlocked.
    2. Parse ciphertext format.
    3. Query key and check ownership. If not matching, log access denial and raise ValueError("PERMISSION_DENIED").
    4. Check key usage. If not ENCRYPT_DECRYPT, raise ValueError("INVALID_KEY_USAGE").
    5. Decrypt named key using DEK.
    6. Decrypt payload using AES-256-GCM.
    7. Return base64-encoded plaintext.
    """
    from src.storage import disk

    if dek is None:
        raise ValueError("VAULT_LOCKED")

    if not ciphertext or not ciphertext.startswith("vault:"):
        raise ValueError("INVALID_CIPHERTEXT")

    parts = ciphertext.split(":")
    if len(parts) != 3:
        raise ValueError("INVALID_CIPHERTEXT")

    _, key_name, payload_b64 = parts

    try:
        payload = base64.b64decode(payload_b64)
    except Exception:
        raise ValueError("INVALID_CIPHERTEXT")

    if len(payload) < 12 + 16:  # Nonce is 12 bytes, Tag is 16 bytes minimum
        raise ValueError("INVALID_CIPHERTEXT")

    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE key_name = ?",
        (key_name,)
    ).fetchone()

    # Access control: If key doesn't exist at all, or belongs to another user
    if row is None or row["owner_email"] != owner_email:
        disk.log_denied_access(owner_email, "key", key_name)
        raise ValueError("PERMISSION_DENIED")

    if row["key_usage"] != "ENCRYPT_DECRYPT":
        raise ValueError("INVALID_KEY_USAGE")

    # Decrypt the AES key material with the DEK
    encrypted_key_bytes = base64.b64decode(row["encrypted_key_material_b64"])
    key_nonce = encrypted_key_bytes[:12]
    key_ciphertext = encrypted_key_bytes[12:]
    
    aesgcm_dek = AESGCM(dek)
    raw_key = aesgcm_dek.decrypt(key_nonce, key_ciphertext, None)

    # Decrypt the payload
    nonce = payload[:12]
    ciphertext_and_tag = payload[12:]

    aesgcm_key = AESGCM(raw_key)
    try:
        plaintext = aesgcm_key.decrypt(nonce, ciphertext_and_tag, None)
    except Exception:
        raise ValueError("DECRYPTION_FAILED")

    return base64.b64encode(plaintext).decode("utf-8")

