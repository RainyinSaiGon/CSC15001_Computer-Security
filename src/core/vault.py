import base64
import secrets
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage import disk

# ---------------------------------------------------------------------------
# DEK (Data Encryption Key) — the heart of the envelope encryption scheme.
#
# The vault uses a two-layer key hierarchy:
#   Master passphrase
#       → Argon2id KDF (with salt) → 256-bit derived key (KDK)
#           → KDK encrypts the 256-bit DEK (AES-256-GCM)
#               → DEK encrypts all user data (secrets, transit keys, signing keys)
#
# This means:
#   • Only the DEK needs to be re-encrypted if the passphrase changes,
#     not every piece of user data.
#   • The DEK lives only in RAM. It is NEVER written to disk in plaintext.
#   • Locking the vault = setting _IN_MEMORY_DEK = None → zero-knowledge on disk.
# ---------------------------------------------------------------------------
_IN_MEMORY_DEK: bytes | None = None


def is_strong_passphrase(passphrase: str) -> bool:
    """
    Check if the master passphrase meets NIST SP 800-63B guidelines:
    - Prioritizes length over complexity (e.g. longer passphrases rather than short complex ones)
    - Enforces a minimum length of 14 characters for root/master passphrases
    - Avoids common default/placeholder strings
    """
    if not passphrase or len(passphrase) < 14:
        return False

    # Prevent common defaults or simple placeholders
    defaults = {"master_passphrase", "passwordpassword", "adminadmin12345"}
    if passphrase.strip().lower() in defaults:
        return False

    return True


def get_status() -> str:
    """
    Resolve the current status of the vault:
    - 'uninitialized': no metadata file exists.
    - 'locked': metadata exists but DEK is not in memory.
    - 'unlocked': metadata exists and DEK is in memory.
    """
    metadata = disk.read_vault_metadata()
    if metadata is None:
        return "uninitialized"

    if _IN_MEMORY_DEK is None:
        return "locked"

    return "unlocked"


def get_dek() -> bytes | None:
    """
    Retrieve the in-memory DEK. Returns None if the vault is locked.
    Callers should treat None as 'vault is sealed — refuse the operation'.
    """
    if get_status() != "unlocked":
        return None
    return _IN_MEMORY_DEK


def init_vault(master_passphrase: str) -> dict:
    """
    Initialize the vault with a master passphrase:
    1. Validate passphrase strength.
    2. Generate KDF salt and derive key.
    3. Generate DEK and encrypt it with derived key.
    4. Write metadata to disk.
    5. Load DEK into memory.
    """
    if get_status() != "uninitialized":
        raise ValueError("ALREADY_INITIALIZED")

    if not is_strong_passphrase(master_passphrase):
        raise ValueError("WEAK_PASSPHRASE")

    # --- Step 1: Key Derivation via Argon2id ---
    # We use a fresh 128-bit random salt per vault so that the same passphrase
    # produces a completely different derived key across vaults. This defeats
    # precomputed rainbow-table attacks against the metadata file on disk.
    salt = secrets.token_bytes(16)

    # Argon2id (RFC 9106 preferred variant) is memory-hard:
    #   time_cost=3    → 3 iterations
    #   memory_cost=64 MiB → fills 64 MB of RAM per derivation attempt, making
    #                        GPU/ASIC cracking orders of magnitude more expensive
    #   parallelism=4  → uses 4 parallel lanes; a brute-force attacker must
    #                    allocate 4× the memory per attempt
    #   hash_len=32    → produces a 256-bit key, matching AES-256 key size
    derived_key = low_level.hash_secret_raw(
        secret=master_passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )

    # --- Step 2: Generate the DEK ---
    # The DEK is a 256-bit random key generated via the OS CSPRNG.
    # It is the root key for all user data — all transit keys and secrets
    # are encrypted with this key before being written to disk.
    global _IN_MEMORY_DEK
    dek = secrets.token_bytes(32)

    # --- Step 3: Wrap the DEK under the derived key (AES-256-GCM) ---
    # AES-GCM provides both confidentiality (AES-CTR) and integrity (GHASH tag).
    # The 96-bit (12-byte) nonce is the NIST-recommended size for GCM, giving
    # 2^32 encryptions before nonce-collision risk becomes relevant.
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)
    # encrypt() returns ciphertext || 16-byte authentication tag (GCM appends tag automatically)
    ciphertext = aesgcm.encrypt(nonce, dek, None)

    # Store nonce prepended to ciphertext so unlock_vault can unpack them as a unit.
    encrypted_dek_bytes = nonce + ciphertext
    encrypted_dek_b64 = base64.b64encode(encrypted_dek_bytes).decode("utf-8")
    salt_b64 = base64.b64encode(salt).decode("utf-8")

    # --- Step 4: Persist metadata (all values safe to be on disk) ---
    # Nothing written here is the DEK in plaintext — only its encrypted form
    # and the KDF parameters needed to re-derive the wrapping key.
    metadata = {
        "kdf": "argon2id",
        "kdf_salt_b64": salt_b64,
        "encrypted_dek_b64": encrypted_dek_b64,
        "status": "locked"  # persisted state always reflects locked; in-memory state controls unlock
    }
    disk.write_vault_metadata(metadata)

    # --- Step 5: Transition to unlocked state ---
    # Hold the DEK in process memory only. If the process exits or
    # lock_vault() is called, this value is gone and the vault must
    # be unlocked again with the correct passphrase.
    _IN_MEMORY_DEK = dek
    return {"status": "unlocked"}


def unlock_vault(master_passphrase: str) -> dict:
    """
    Unlock the vault by verifying the master passphrase and loading the DEK into memory.
    """
    status = get_status()
    if status == "uninitialized":
        raise ValueError("UNINITIALIZED")
    if status == "unlocked":
        # Idempotent: already unlocked, nothing to do
        return {"status": "unlocked"}

    metadata = disk.read_vault_metadata()
    if not metadata:
        raise ValueError("UNINITIALIZED")

    try:
        salt = base64.b64decode(metadata["kdf_salt_b64"])
        encrypted_dek_bytes = base64.b64decode(metadata["encrypted_dek_b64"])

        # Unpack: first 12 bytes = nonce, remaining = ciphertext + GCM tag
        nonce = encrypted_dek_bytes[:12]
        ciphertext = encrypted_dek_bytes[12:]

        # Re-derive the same wrapping key using the stored salt + identical KDF params.
        # A wrong passphrase produces a different derived key, which will fail GCM authentication.
        derived_key = low_level.hash_secret_raw(
            secret=master_passphrase.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=low_level.Type.ID
        )

        # AES-GCM decryption verifies the authentication tag before returning plaintext.
        # Any tampering with the encrypted_dek blob, or a wrong passphrase, raises an
        # InvalidTag exception here — we map all such failures to WRONG_PASSPHRASE so
        # callers cannot distinguish between "bad password" and "corrupted metadata".
        aesgcm = AESGCM(derived_key)
        dek = aesgcm.decrypt(nonce, ciphertext, None)

        # Promote to unlocked by holding the DEK in RAM
        global _IN_MEMORY_DEK
        _IN_MEMORY_DEK = dek
        return {"status": "unlocked"}
    except Exception:
        # Catch InvalidTag (wrong passphrase), base64 decode errors, and any other
        # deserialization failures. All map to the same generic error to prevent
        # oracle attacks (attacker must not learn WHICH check failed).
        raise ValueError("WRONG_PASSPHRASE")


def lock_vault() -> dict:
    """
    Lock the vault by clearing the DEK from memory.

    This is the equivalent of 'sealing' the vault: without the DEK, no
    encrypt/decrypt/sign/verify operation is possible, even if an attacker
    has full read access to the disk. The encrypted DEK on disk is useless
    without the master passphrase.
    """
    global _IN_MEMORY_DEK
    _IN_MEMORY_DEK = None
    return {"status": "locked"}
