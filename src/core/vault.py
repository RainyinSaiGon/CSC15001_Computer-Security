import base64
import secrets
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage import disk

# In-memory storage for the decrypted Data Encryption Key (DEK)
# This is wiped when the vault is locked and is never written to disk in plaintext.
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
    
    # 1. Derive key via Argon2id
    salt = secrets.token_bytes(16)
    derived_key = low_level.hash_secret_raw(
        secret=master_passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )
    
    # 2. Generate random 256-bit DEK
    global _IN_MEMORY_DEK
    dek = secrets.token_bytes(32)
    
    # 3. Encrypt DEK using AES-256-GCM
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, dek, None)
    
    # We package nonce + ciphertext + tag into encrypted_dek_b64
    encrypted_dek_bytes = nonce + ciphertext
    encrypted_dek_b64 = base64.b64encode(encrypted_dek_bytes).decode("utf-8")
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    
    # 4. Save metadata to disk
    metadata = {
        "kdf": "argon2id",
        "kdf_salt_b64": salt_b64,
        "encrypted_dek_b64": encrypted_dek_b64,
        "status": "locked"  # stored state defaults to locked
    }
    disk.write_vault_metadata(metadata)
    
    # 5. Transition to unlocked by loading DEK into memory
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
        return {"status": "unlocked"}
    
    metadata = disk.read_vault_metadata()
    if not metadata:
        raise ValueError("UNINITIALIZED")
    
    try:
        salt = base64.b64decode(metadata["kdf_salt_b64"])
        encrypted_dek_bytes = base64.b64decode(metadata["encrypted_dek_b64"])
        
        # Extract nonce (first 12 bytes) and ciphertext
        nonce = encrypted_dek_bytes[:12]
        ciphertext = encrypted_dek_bytes[12:]
        
        # Derive key using Argon2id
        derived_key = low_level.hash_secret_raw(
            secret=master_passphrase.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=low_level.Type.ID
        )
        
        # Decrypt DEK
        aesgcm = AESGCM(derived_key)
        dek = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Store in memory
        global _IN_MEMORY_DEK
        _IN_MEMORY_DEK = dek
        return {"status": "unlocked"}
    except Exception:
        # Catch decryption/gcm-tag errors, base64 decode errors, KDF errors
        raise ValueError("WRONG_PASSPHRASE")

def lock_vault() -> dict:
    """
    Lock the vault by clearing the DEK from memory.
    """
    global _IN_MEMORY_DEK
    _IN_MEMORY_DEK = None
    return {"status": "locked"}
