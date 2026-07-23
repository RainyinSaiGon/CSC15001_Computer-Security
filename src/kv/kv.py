import json
import time
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage import database

# ---------------------------------------------------------------------------
# Helper: Ownership Validation (Requirement 1.2)
# ---------------------------------------------------------------------------

def _check_ownership(path: str, owner_email: str):
    """
    Ensure the path starts with 'secret/<email>/'.
    Requirement 1.2: Owner-based access control.
    """
    required_prefix = f"secret/{owner_email}/"
    if not path.startswith(required_prefix):
        # Requirement 1.2: Generic error to avoid leaking path existence
        raise ValueError("PERMISSION_DENIED")


# ---------------------------------------------------------------------------
# Feature 1.1: Encrypted-at-Rest Storage
# ---------------------------------------------------------------------------

def write_secret(path: str, data: dict, owner_email: str, dek: bytes) -> dict:
    """
    Encrypt and store a secret (JSON object) at a specific path.
    """
    # 1. Kiểm tra quyền sở hữu (Requirement 1.2)
    _check_ownership(path, owner_email)

    # 2. Chuẩn bị dữ liệu để mã hóa (Chuyển JSON dict thành bytes)
    plaintext_bytes = json.dumps(data).encode("utf-8")

    # 3. Thực hiện mã hóa AEAD (AES-256-GCM) (Requirement 1.1)
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)  # Fresh random nonce for every write
    
    # encrypt trả về ciphertext + tag nối liền nhau
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    # Tách ciphertext và tag (GCM tag mặc định dài 16 bytes cuối)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # 4. Lưu trữ vào Database
    conn = database.get_connection()
    now = time.time()
    
    # Sử dụng REPLACE INTO để ghi đè nếu path đã tồn tại (Requirement 1.1, step 3)
    conn.execute("""
        INSERT OR REPLACE INTO secrets (path, nonce_b64, ciphertext_b64, tag_b64, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        path,
        base64.b64encode(nonce).decode("utf-8"),
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(tag).decode("utf-8"),
        now
    ))
    conn.commit()

    return {"path": path, "status": "stored", "timestamp": now}


def read_secret(path: str, owner_email: str, dek: bytes) -> dict:
    """
    Retrieve and decrypt a secret from a specific path.
    """
    # 1. Kiểm tra quyền sở hữu TRƯỚC KHI chạm vào crypto (Requirement 1.2)
    _check_ownership(path, owner_email)

    # 2. Lấy dữ liệu mã hóa từ Database
    conn = database.get_connection()
    row = conn.execute(
        "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM secrets WHERE path = ?",
        (path,)
    ).fetchone()

    if row is None:
        raise ValueError("NOT_FOUND")

    # 3. Giải mã (Requirement 1.1)
    try:
        nonce = base64.b64decode(row["nonce_b64"])
        ciphertext = base64.b64decode(row["ciphertext_b64"])
        tag = base64.b64decode(row["tag_b64"])

        aesgcm = AESGCM(dek)
        # Nối ciphertext + tag để thư viện tự kiểm tra tính toàn vẹn
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
        
        # Chuyển bytes về lại JSON object
        return json.loads(decrypted_bytes.decode("utf-8"))
        
    except Exception:
        # Nếu Tag không khớp (dữ liệu bị sửa đổi) hoặc sai khóa
        # Requirement 1.1: Refuse outright, do not return garbage data
        raise ValueError("INTEGRITY_FAILURE")


def delete_secret(path: str, owner_email: str) -> dict:
    """
    Permanently delete a secret record.
    """
    # 1. Kiểm tra quyền sở hữu
    _check_ownership(path, owner_email)

    conn = database.get_connection()
    # Kiểm tra xem có tồn tại không trước khi xóa
    row = conn.execute("SELECT path FROM secrets WHERE path = ?", (path,)).fetchone()
    if row is None:
        raise ValueError("NOT_FOUND")

    conn.execute("DELETE FROM secrets WHERE path = ?", (path,))
    conn.commit()

    return {"message": "Secret deleted successfully", "path": path}