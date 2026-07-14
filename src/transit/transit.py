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
