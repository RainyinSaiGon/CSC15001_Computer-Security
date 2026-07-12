import uvicorn
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from src import core

app = FastAPI(
    title="Mini Vault",
    description="Secure Storage & Encryption/Signing as a Service",
    version="0.1.0"
)

class PassphraseRequest(BaseModel):
    master_passphrase: str

@app.get("/health")
def health_check():
    """
    Health check endpoint to verify the service status.
    """
    return {
        "status": "healthy",
        "vault": core.get_status()
    }

@app.get("/vault/status")
def get_vault_status():
    """
    Retrieve the current initialization and lock status of the vault.
    """
    return {"status": core.get_status()}

@app.post("/vault/init")
def initialize_vault(req: PassphraseRequest):
    """
    Initialize the vault with a strong master passphrase.
    """
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
    """
    Unlock the vault using the master passphrase.
    """
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
    """
    Lock the vault (clear the decryption key from memory).
    """
    return core.lock_vault()

@app.get("/vault/protected-test")
def protected_test():
    """
    A protected test endpoint that simulates operations on Features 1 & 2.
    It returns VAULT_LOCKED if the vault is not unlocked.
    """
    if core.get_status() != "unlocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VAULT_LOCKED"
        )
    return {"message": "success"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
