import uvicorn
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel
from src import core
from src.auth import auth
from src.transit import transit

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


# ---------------------------------------------------------------------------
# Helper: extract and validate session token from Authorization header
# ---------------------------------------------------------------------------

def _require_session(authorization: str | None) -> str:
    """
    Parse 'Bearer <token>' from the Authorization header and validate it.
    Returns the authenticated user's email.
    Raises HTTPException 401 if missing, malformed, invalid, or expired.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UNAUTHENTICATED"
        )
    token = authorization[7:]  # strip "Bearer "
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
# Transit Engine endpoints (Feature 2.1)
# ---------------------------------------------------------------------------

@app.post("/transit/keys")
def create_transit_key(
    req: CreateKeyRequest,
    authorization: str | None = Header(default=None)
):
    """Create a new named key for encryption/decryption."""
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


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
