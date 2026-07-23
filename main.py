import uvicorn
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel
from src import core
from src.auth import auth
from src.transit import transit
from src.kv import kv  
from fastapi.openapi.utils import get_openapi

app = FastAPI(
    title="Mini Vault",
    description="Secure Storage & Encryption/Signing as a Service",
    version="0.2.0"
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PassphraseRequest(BaseModel):
    master_passphrase: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    confirm_password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class CreateKeyRequest(BaseModel):
    key_name: str

class EncryptRequest(BaseModel):
    plaintext_b64: str

class DecryptRequest(BaseModel):
    ciphertext: str

class CreateSigningKeyRequest(BaseModel):
    key_name: str
    signing_algorithm: str

class SignRequest(BaseModel):
    message_b64: str
    message_type: str

class VerifyRequest(BaseModel):
    message_b64: str
    message_type: str
    signature_b64: str
    signing_algorithm: str | None = None  # Optional: if provided, must match the key's stored algorithm
class WriteSecretRequest(BaseModel):
    path: str
    data: dict


# ---------------------------------------------------------------------------
# Helper: extract and validate session token from Authorization header
# ---------------------------------------------------------------------------

def _require_session(authorization: str | None) -> str:
    """
    Parse 'Bearer <token>' from the Authorization header and validate it.
    Returns the authenticated user's email.
    Raises HTTPException 401 if missing, malformed, invalid, or expired.

    All transit endpoints call this helper first so that:
      1. Unauthenticated requests are rejected before any database query.
      2. The returned email is used as the owner_email for key ownership checks,
         ensuring a token can only operate on its own user's keys.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UNAUTHENTICATED"
        )
    token = authorization[7:]  # strip "Bearer " prefix
    try:
        email = auth.validate_session(token)
        return email
    except ValueError as e:
        err = str(e)
        if err == "SESSION_EXPIRED":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SESSION_EXPIRED"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UNAUTHENTICATED"
        )


# ---------------------------------------------------------------------------
# Vault endpoints (Feature 0.1)
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check():
    """Health check endpoint to verify the service status."""
    return {
        "status": "healthy",
        "vault": core.get_status()
    }

@app.get("/vault/status")
def get_vault_status():
    """Retrieve the current initialization and lock status of the vault."""
    return {"status": core.get_status()}

@app.post("/vault/init")
def initialize_vault(req: PassphraseRequest):
    """Initialize the vault with a strong master passphrase."""
    try:
        res = core.init_vault(req.master_passphrase)
        return res
    except ValueError as e:
        err_msg = str(e)
        if err_msg == "ALREADY_INITIALIZED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ALREADY_INITIALIZED"
            )
        elif err_msg == "WEAK_PASSPHRASE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WEAK_PASSPHRASE"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err_msg
        )

@app.post("/vault/unlock")
def unlock_vault(req: PassphraseRequest):
    """Unlock the vault using the master passphrase."""
    try:
        res = core.unlock_vault(req.master_passphrase)
        return res
    except ValueError as e:
        err_msg = str(e)
        if err_msg == "WRONG_PASSPHRASE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WRONG_PASSPHRASE"
            )
        elif err_msg == "UNINITIALIZED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="UNINITIALIZED"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err_msg
        )

@app.post("/vault/lock")
def lock_vault():
    """Lock the vault (clear the decryption key from memory)."""
    return core.lock_vault()


# ---------------------------------------------------------------------------
# Auth endpoints (Feature 0.2)
# ---------------------------------------------------------------------------

@app.post("/auth/register")
def register_user(req: RegisterRequest):
    """Register a new user with email, password, and password confirmation."""
    try:
        result = auth.register(req.email, req.password, req.confirm_password)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.post("/auth/login")
def login_user(req: LoginRequest):
    """Authenticate a user and issue a session token."""
    try:
        result = auth.login(req.email, req.password)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# ---------------------------------------------------------------------------
# Protected test endpoint (requires both vault unlocked AND valid session)
# ---------------------------------------------------------------------------

@app.get("/vault/protected-test")
def protected_test(authorization: str | None = Header(default=None)):
    """
    A protected test endpoint that simulates operations on Features 1 & 2.
    Requires:
    1. Vault to be unlocked.
    2. A valid session token in the Authorization header.
    """
    # Check vault status first
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    # Then check session token
    _require_session(authorization)
    return {"message": "success"}


# ---------------------------------------------------------------------------
# KV Store endpoints (Feature 1.1 & 1.2)
# ---------------------------------------------------------------------------

@app.post("/kv/write")
def write_secret_endpoint(
    req: WriteSecretRequest,
    authorization: str | None = Header(default=None)
):
    """
    Securely store a secret.
    Requires: Vault unlocked + Valid session token.
    Path must start with 'secret/<your_email>/'.
    """
    # 1. Kiểm tra trạng thái hệ thống (0.1)
    if core.get_status() != "unlocked":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="VAULT_LOCKED")

    # 2. Kiểm tra phiên đăng nhập (0.2)
    owner_email = _require_session(authorization)

    # 3. Lấy khóa DEK từ RAM để thực hiện mã hóa
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="VAULT_LOCKED")

    try:
        # Gọi xuống module kv để thực hiện mã hóa và lưu trữ
        res = kv.write_secret(req.path, req.data, owner_email, dek)
        return res
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PERMISSION_DENIED")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err)


@app.get("/kv/read")
def read_secret_endpoint(
    path: str,  # Nhận path qua query parameter ?path=...
    authorization: str | None = Header(default=None)
):
    """
    Retrieve and decrypt a secret.
    Requires: Vault unlocked + Valid session token + Ownership.
    """
    if core.get_status() != "unlocked":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="VAULT_LOCKED")

    owner_email = _require_session(authorization)
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="VAULT_LOCKED")

    try:
        res = kv.read_secret(path, owner_email, dek)
        return res
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PERMISSION_DENIED")
        elif err == "NOT_FOUND":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT_FOUND")
        elif err == "INTEGRITY_FAILURE":
            # Requirement 1.1: Trả về lỗi nếu tag không khớp (dữ liệu bị sửa đổi)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INTEGRITY_FAILURE")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err)


@app.delete("/kv/delete")
def delete_secret_endpoint(
    path: str,
    authorization: str | None = Header(default=None)
):
    """
    Permanently delete a secret.
    Requires: Vault unlocked + Valid session token + Ownership.
    """
    if core.get_status() != "unlocked":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="VAULT_LOCKED")

    owner_email = _require_session(authorization)

    try:
        res = kv.delete_secret(path, owner_email)
        return res
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PERMISSION_DENIED")
        elif err == "NOT_FOUND":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT_FOUND")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err)


# ---------------------------------------------------------------------------
# Transit Engine endpoints (Feature 2.1)
# ---------------------------------------------------------------------------

@app.post("/transit/keys")
def create_transit_key(
    req: CreateKeyRequest,
    authorization: str | None = Header(default=None)
):
    """Create a new named key for encryption/decryption."""
    # Dual-gate: vault lock check first (fast), then session check (involves DB lookup).
    # If the vault is locked, there is no DEK to wrap new keys — fail early.
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )

    owner_email = _require_session(authorization)
    dek = core.get_dek()
    # Defensive double-check: get_dek() could return None if vault was locked
    # between the status check above and this call (TOCTOU window).
    if dek is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    try:
        res = transit.create_key(req.key_name, owner_email, dek)
        return res
    except ValueError as e:
        err = str(e)
        if err == "KEY_ALREADY_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="KEY_ALREADY_EXISTS"
            )
        elif err == "INVALID_KEY_NAME":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="INVALID_KEY_NAME"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.get("/transit/keys")
def list_transit_keys(
    authorization: str | None = Header(default=None)
):
    """List named keys created by the current user."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    return transit.list_keys(owner_email)

@app.delete("/transit/keys/{key_name}")
def revoke_transit_key(
    key_name: str,
    authorization: str | None = Header(default=None)
):
    """Revoke (permanently delete) a named key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    try:
        transit.revoke_key(key_name, owner_email)
        return {"message": f"Key '{key_name}' has been successfully revoked"}
    except ValueError as e:
        err = str(e)
        if err == "KEY_NOT_FOUND":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="KEY_NOT_FOUND"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.post("/transit/encrypt/{key_name}")
def encrypt_transit_data(
    key_name: str,
    req: EncryptRequest,
    authorization: str | None = Header(default=None)
):
    """Encrypt data using a named key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    try:
        ciphertext = transit.encrypt(key_name, req.plaintext_b64, owner_email, dek)
        return {"ciphertext": ciphertext}
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PERMISSION_DENIED"
            )
        elif err == "INVALID_KEY_USAGE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="INVALID_KEY_USAGE"
            )
        elif err == "INVALID_PLAINTEXT_BASE64":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="INVALID_PLAINTEXT_BASE64"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.post("/transit/decrypt")
def decrypt_transit_data(
    req: DecryptRequest,
    authorization: str | None = Header(default=None)
):
    """Decrypt data using a named key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    try:
        plaintext_b64 = transit.decrypt(req.ciphertext, owner_email, dek)
        return {"plaintext_b64": plaintext_b64}
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PERMISSION_DENIED"
            )
        elif err == "INVALID_KEY_USAGE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="INVALID_KEY_USAGE"
            )
        elif err in ("INVALID_CIPHERTEXT", "DECRYPTION_FAILED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.post("/transit/keys/signing")
def create_transit_signing_key(
    req: CreateSigningKeyRequest,
    authorization: str | None = Header(default=None)
):
    """Create a new named signing key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    try:
        res = transit.create_signing_key(req.key_name, req.signing_algorithm, owner_email, dek)
        return res
    except ValueError as e:
        err = str(e)
        if err in ("INVALID_KEY_NAME", "INVALID_SIGNING_ALGORITHM", "KEY_ALREADY_EXISTS"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.post("/transit/sign/{key_name}")
def sign_transit_data(
    key_name: str,
    req: SignRequest,
    authorization: str | None = Header(default=None)
):
    """Sign data using a named key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    dek = core.get_dek()
    if dek is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    try:
        res = transit.sign(key_name, req.message_b64, req.message_type, owner_email, dek)
        return res
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PERMISSION_DENIED"
            )
        elif err in ("INVALID_KEY_USAGE", "INVALID_MESSAGE_TYPE", "INVALID_MESSAGE_BASE64", "INVALID_DIGEST"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )

@app.post("/transit/verify/{key_name}")
def verify_transit_data(
    key_name: str,
    req: VerifyRequest,
    authorization: str | None = Header(default=None)
):
    """Verify signature using a named key."""
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    
    owner_email = _require_session(authorization)
    try:
        res = transit.verify(
            key_name, req.message_b64, req.message_type,
            req.signature_b64, owner_email,
            expected_signing_algorithm=req.signing_algorithm
        )
        return res
    except ValueError as e:
        err = str(e)
        if err == "PERMISSION_DENIED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PERMISSION_DENIED"
            )
        elif err in ("INVALID_KEY_USAGE", "INVALID_MESSAGE_TYPE", "INVALID_MESSAGE_BASE64",
                     "INVALID_DIGEST", "ALGORITHM_MISMATCH"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err
        )
        
def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Register the BearerAuth scheme
    schema.setdefault("components", {})
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "description": "Paste your session_token from POST /auth/login here."
        }
    }

    # Apply BearerAuth to every endpoint that accepts an authorization header
    for path, methods in schema["paths"].items():
        for method_info in methods.values():
            params = method_info.get("parameters", [])
            has_auth = any(p.get("name") == "authorization" for p in params)
            if has_auth:
                method_info.setdefault("security", [{"BearerAuth": []}])

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
