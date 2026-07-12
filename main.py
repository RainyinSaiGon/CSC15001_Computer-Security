import uvicorn
from fastapi import FastAPI

app = FastAPI(
    title="Mini Vault",
    description="Secure Storage & Encryption/Signing as a Service",
    version="0.1.0"
)

@app.get("/health")
def health_check():
    """
    Health check endpoint to verify the service status.
    In the future, this can report vault lock status (locked/unlocked).
    """
    return {
        "status": "healthy",
        "vault": "locked"
    }

if __name__ == "__main__":
    # Start the FastAPI server using Uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
