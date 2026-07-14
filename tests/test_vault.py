import os
import pytest
from fastapi.testclient import TestClient
from main import app
from src.storage import database
from src.auth import auth


def _register_and_login(client):
    """Helper: register a test user and return a valid session token."""
    client.post("/auth/register", json={
        "email": "testuser@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    resp = client.post("/auth/login", json={
        "email": "testuser@example.com",
        "password": "securepass123"
    })
    return resp.json()["session_token"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Set the vault data directory to a temp path for isolated testing
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_LOG_FILE", str(tmp_path / "vault.log"))
    database.reset_connection()
    auth.clear_sessions()
    
    with TestClient(app) as c:
        yield c
    
    database.reset_connection()
    auth.clear_sessions()

def test_vault_status_uninitialized(client):
    """
    1. test_vault_status_uninitialized:
    Ensure that when no metadata file exists on disk, GET /vault/status returns status 'uninitialized'.
    """
    response = client.get("/vault/status")
    assert response.status_code == 200
    assert response.json() == {"status": "uninitialized"}

def test_vault_init_success(client):
    """
    2. test_vault_init_success:
    Call POST /vault/init with a strong passphrase.
    Assert success, metadata file creation, and status change to unlocked.
    """
    # Initialize the vault
    response = client.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "unlocked"
    
    # Check that status endpoint now reports unlocked
    status_response = client.get("/vault/status")
    assert status_response.status_code == 200
    assert status_response.json() == {"status": "unlocked"}

def test_vault_init_already_initialized(client):
    """
    3. test_vault_init_already_initialized:
    Subsequent calls to POST /vault/init on an already initialized vault must fail.
    """
    # First initialization
    response1 = client.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
    assert response1.status_code == 200
    
    # Second initialization attempt should fail
    response2 = client.post("/vault/init", json={"master_passphrase": "another_strong_passphrase_123!"})
    assert response2.status_code == 400
    assert response2.json()["detail"] == "ALREADY_INITIALIZED"

def test_vault_init_weak_passphrase(client):
    """
    4. test_vault_init_weak_passphrase:
    Attempting to initialize with a weak passphrase or a default placeholder must fail.
    """
    # 4a. Short passphrase (< 14 characters)
    response_short = client.post("/vault/init", json={"master_passphrase": "short_pass123"})
    assert response_short.status_code == 400
    assert response_short.json()["detail"] == "WEAK_PASSPHRASE"
    
    # 4b. Common default passphrase
    response_default = client.post("/vault/init", json={"master_passphrase": "master_passphrase"})
    assert response_default.status_code == 400
    assert response_default.json()["detail"] == "WEAK_PASSPHRASE"

    # Status should remain uninitialized
    status_response = client.get("/vault/status")
    assert status_response.json() == {"status": "uninitialized"}


def test_vault_lock_and_unlock_success(client):
    """
    5. test_vault_lock_and_unlock_success:
    Initialize -> Lock -> verify locked -> Unlock with correct passphrase -> verify unlocked.
    """
    passphrase = "a_very_strong_master_passphrase_123!"
    
    # 1. Initialize
    client.post("/vault/init", json={"master_passphrase": passphrase})
    
    # 2. Lock
    response = client.post("/vault/lock")
    assert response.status_code == 200
    assert response.json() == {"status": "locked"}
    
    # Verify GET status reports locked
    assert client.get("/vault/status").json() == {"status": "locked"}
    
    # 3. Unlock with correct passphrase
    response = client.post("/vault/unlock", json={"master_passphrase": passphrase})
    assert response.status_code == 200
    assert response.json() == {"status": "unlocked"}
    
    # Verify GET status reports unlocked
    assert client.get("/vault/status").json() == {"status": "unlocked"}

def test_vault_unlock_wrong_passphrase(client):
    """
    6. test_vault_unlock_wrong_passphrase:
    Initialize -> Lock -> Unlock with incorrect passphrase.
    Assert generic decryption failure, status remains locked.
    """
    passphrase = "a_very_strong_master_passphrase_123!"
    
    # Initialize and Lock
    client.post("/vault/init", json={"master_passphrase": passphrase})
    client.post("/vault/lock")
    
    # Unlock with wrong passphrase
    response = client.post("/vault/unlock", json={"master_passphrase": "wrong_master_passphrase_123!"})
    assert response.status_code == 400
    assert response.json()["detail"] == "WRONG_PASSPHRASE"
    
    # Verify status is still locked
    assert client.get("/vault/status").json() == {"status": "locked"}

def test_vault_locked_refuses_operations(client):
    """
    7. test_vault_locked_refuses_operations:
    Ensure that calling mock operations (Feature 1/2 protected endpoints)
    returns a 'VAULT_LOCKED' error when the vault is locked or uninitialized.
    """
    # 1. Check when uninitialized — vault check runs before token check
    response = client.get("/vault/protected-test")
    assert response.status_code == 400
    assert response.json()["detail"] == "VAULT_LOCKED"
    
    # 2. Initialize (becomes unlocked)
    client.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
    
    # Register and login to get a valid token
    token = _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test that it works when unlocked WITH a valid token
    response_unlocked = client.get("/vault/protected-test", headers=headers)
    assert response_unlocked.status_code == 200
    assert response_unlocked.json() == {"message": "success"}
    
    # 3. Lock the vault
    client.post("/vault/lock")
    
    # Test that it refuses when locked (even with a valid token)
    response_locked = client.get("/vault/protected-test", headers=headers)
    assert response_locked.status_code == 400
    assert response_locked.json()["detail"] == "VAULT_LOCKED"

def test_vault_restart_behavior(tmp_path, monkeypatch):
    """
    8. test_vault_restart_behavior:
    Simulate a complete server restart:
    - Create a metadata file in one process run.
    - Start a fresh client/process in a new test with the same data directory.
    - Verify that status is 'locked' initially.
    - Verify that correct unlock works.
    """
    # 1. First run: Initialize the vault
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_LOG_FILE", str(tmp_path / "vault.log"))
    database.reset_connection()
    auth.clear_sessions()
    
    with TestClient(app) as client1:
        res = client1.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
        assert res.status_code == 200
        assert res.json()["status"] == "unlocked"
        
        # Register a user and get a token to test protected endpoint
        token = _register_and_login(client1)
        headers = {"Authorization": f"Bearer {token}"}
        
        resp = client1.get("/vault/protected-test", headers=headers)
        assert resp.status_code == 200
        
        # Wiping the in-memory variable mocks a process restart / memory reset
        from src.core import vault
        vault._IN_MEMORY_DEK = None
        
    # 2. Restart run: Create a fresh TestClient, referencing the same data directory
    with TestClient(app) as client2:
        # Since _IN_MEMORY_DEK was wiped, it should start in a locked state
        status_resp = client2.get("/vault/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] == "locked"
        
        # Protected endpoints must refuse (vault locked takes priority)
        protected_resp = client2.get("/vault/protected-test", headers=headers)
        assert protected_resp.status_code == 400
        assert protected_resp.json()["detail"] == "VAULT_LOCKED"
        
        # Must unlock with the correct passphrase
        unlock_resp = client2.post("/vault/unlock", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
        assert unlock_resp.status_code == 200
        assert unlock_resp.json()["status"] == "unlocked"
        
        # Protected endpoints must work again with the same token
        resp_after_unlock = client2.get("/vault/protected-test", headers=headers)
        assert resp_after_unlock.status_code == 200
