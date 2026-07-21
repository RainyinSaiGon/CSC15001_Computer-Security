import base64
import pytest
from fastapi.testclient import TestClient
from main import app
from src.storage import database
from src.auth import auth
from src.core import vault

@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """
    Ensure every test gets a fresh database and clean session store.
    Resets the SQLite connection and clears in-memory sessions.
    """
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_LOG_FILE", str(tmp_path / "vault.log"))
    database.reset_connection()
    auth.clear_sessions()
    yield
    database.reset_connection()
    auth.clear_sessions()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def unlocked_client(client):
    """Return a client with the vault already initialized and unlocked."""
    client.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
    return client

def _register_and_login(client, email, password):
    """Helper to register and login a user, returning the session token."""
    client.post("/auth/register", json={
        "email": email,
        "password": password,
        "confirm_password": password
    })
    resp = client.post("/auth/login", json={
        "email": email,
        "password": password
    })
    return resp.json()["session_token"]

def test_create_key_success(unlocked_client):
    """Create a named key successfully and verify metadata format."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    response = unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["key_name"] == "my-key"
    assert data["owner_email"] == "alice@example.com"
    assert data["key_usage"] == "ENCRYPT_DECRYPT"
    assert "encrypted_key_material_b64" in data
    # Plaintext key should not be in the response at all
    assert "plaintext" not in str(data).lower()
    
    # Check that the database contains the encrypted key
    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        ("alice@example.com", "my-key")
    ).fetchone()
    assert row is not None
    assert row["key_usage"] == "ENCRYPT_DECRYPT"
    assert row["encrypted_key_material_b64"] == data["encrypted_key_material_b64"]

def test_create_key_duplicate(unlocked_client):
    """Creating a key with a name that already exists for the same user must fail."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    response1 = unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)
    assert response1.status_code == 200

    response2 = unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)
    assert response2.status_code == 400
    assert response2.json()["detail"] == "KEY_ALREADY_EXISTS"

def test_create_key_namespacing(unlocked_client):
    """Alice and Bob can both create a key named 'my-key' without conflict."""
    token_alice = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    token_bob = _register_and_login(unlocked_client, "bob@example.com", "securepass456")

    res_alice = unlocked_client.post(
        "/transit/keys", 
        json={"key_name": "my-key"}, 
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    assert res_alice.status_code == 200

    res_bob = unlocked_client.post(
        "/transit/keys", 
        json={"key_name": "my-key"}, 
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert res_bob.status_code == 200

def test_create_key_invalid_name(unlocked_client):
    """Empty or whitespace-only key names must be rejected."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    response = unlocked_client.post("/transit/keys", json={"key_name": ""}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "INVALID_KEY_NAME"

    response = unlocked_client.post("/transit/keys", json={"key_name": "   "}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "INVALID_KEY_NAME"

def test_list_keys(unlocked_client):
    """Listing keys returns key names and usage, but not encrypted/plaintext key materials."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Should be empty initially
    res_empty = unlocked_client.get("/transit/keys", headers=headers)
    assert res_empty.status_code == 200
    assert res_empty.json() == []

    # Create keys
    unlocked_client.post("/transit/keys", json={"key_name": "key-1"}, headers=headers)
    unlocked_client.post("/transit/keys", json={"key_name": "key-2"}, headers=headers)

    res_list = unlocked_client.get("/transit/keys", headers=headers)
    assert res_list.status_code == 200
    keys = res_list.json()
    assert len(keys) == 2
    assert {k["key_name"] for k in keys} == {"key-1", "key-2"}
    assert {k["key_usage"] for k in keys} == {"ENCRYPT_DECRYPT"}
    # Assert that no key material is returned in the list response
    for k in keys:
        assert "encrypted_key_material_b64" not in k
        assert "key_material" not in k

def test_list_keys_namespacing(unlocked_client):
    """Alice and Bob can only see their own keys when listing."""
    token_alice = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    token_bob = _register_and_login(unlocked_client, "bob@example.com", "securepass456")

    unlocked_client.post(
        "/transit/keys", 
        json={"key_name": "alice-key"}, 
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    unlocked_client.post(
        "/transit/keys", 
        json={"key_name": "bob-key"}, 
        headers={"Authorization": f"Bearer {token_bob}"}
    )

    res_alice = unlocked_client.get("/transit/keys", headers={"Authorization": f"Bearer {token_alice}"})
    keys_alice = res_alice.json()
    assert len(keys_alice) == 1
    assert keys_alice[0]["key_name"] == "alice-key"

    res_bob = unlocked_client.get("/transit/keys", headers={"Authorization": f"Bearer {token_bob}"})
    keys_bob = res_bob.json()
    assert len(keys_bob) == 1
    assert keys_bob[0]["key_name"] == "bob-key"

def test_revoke_key_success(unlocked_client):
    """Revoking a key deletes it from both listing and database."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Create a key
    unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)

    # Revoke it
    resp = unlocked_client.delete("/transit/keys/my-key", headers=headers)
    assert resp.status_code == 200
    assert "revoked" in resp.json()["message"]

    # Verify it is gone from listing
    res_list = unlocked_client.get("/transit/keys", headers=headers)
    assert res_list.json() == []

    # Verify it is gone from db
    conn = database.get_connection()
    row = conn.execute(
        "SELECT * FROM transit_keys WHERE owner_email = ? AND key_name = ?",
        ("alice@example.com", "my-key")
    ).fetchone()
    assert row is None

def test_revoke_key_not_found(unlocked_client):
    """Revoking a non-existent key returns 404."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    resp = unlocked_client.delete("/transit/keys/non-existent-key", headers=headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "KEY_NOT_FOUND"

def test_revoke_key_namespacing(unlocked_client):
    """Alice cannot revoke Bob's key."""
    token_alice = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    token_bob = _register_and_login(unlocked_client, "bob@example.com", "securepass456")

    unlocked_client.post(
        "/transit/keys", 
        json={"key_name": "bob-key"}, 
        headers={"Authorization": f"Bearer {token_bob}"}
    )

    # Alice tries to revoke Bob's key
    resp = unlocked_client.delete(
        "/transit/keys/bob-key", 
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "KEY_NOT_FOUND"

    # Bob's key must still exist
    res_bob = unlocked_client.get("/transit/keys", headers={"Authorization": f"Bearer {token_bob}"})
    assert len(res_bob.json()) == 1

def test_vault_locked_refuses_operations(unlocked_client):
    """Transit endpoints must refuse operations when the vault is locked."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Lock vault
    unlocked_client.post("/vault/lock")

    # Create key must fail
    res_create = unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)
    assert res_create.status_code == 400
    assert res_create.json()["detail"] == "VAULT_LOCKED"

    # List keys must fail
    res_list = unlocked_client.get("/transit/keys", headers=headers)
    assert res_list.status_code == 400
    assert res_list.json()["detail"] == "VAULT_LOCKED"

    # Revoke key must fail
    res_revoke = unlocked_client.delete("/transit/keys/my-key", headers=headers)
    assert res_revoke.status_code == 400
    assert res_revoke.json()["detail"] == "VAULT_LOCKED"

def test_key_persistence_across_restarts(tmp_path, monkeypatch):
    """Verify named keys persist and are accessible after vault relocking/restarting."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_LOG_FILE", str(tmp_path / "vault.log"))
    database.reset_connection()
    auth.clear_sessions()

    # Step 1: Initialize vault and create a key
    with TestClient(app) as client1:
        client1.post("/vault/init", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})
        token = _register_and_login(client1, "alice@example.com", "securepass123")
        headers = {"Authorization": f"Bearer {token}"}

        resp = client1.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)
        assert resp.status_code == 200

        # Lock the vault (simulate memory clear / service restart)
        client1.post("/vault/lock")
        vault._IN_MEMORY_DEK = None

    # Step 2: Restart and check access
    with TestClient(app) as client2:
        # Fails while locked
        res_list_locked = client2.get("/transit/keys", headers=headers)
        assert res_list_locked.status_code == 400
        assert res_list_locked.json()["detail"] == "VAULT_LOCKED"

        # Unlock vault
        client2.post("/vault/unlock", json={"master_passphrase": "a_very_strong_master_passphrase_123!"})

        # Succeeds and lists the key
        res_list_unlocked = client2.get("/transit/keys", headers=headers)
        assert res_list_unlocked.status_code == 200
        keys = res_list_unlocked.json()
        assert len(keys) == 1
        assert keys[0]["key_name"] == "my-key"


def test_encrypt_decrypt_success(unlocked_client):
    """Test standard round-trip encryption/decryption."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Create a key
    unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)

    # Plaintexts: string, json-like, binary bytes
    plaintexts = [
        b"Hello world! Cryptography is fun.",
        b'{"key": "value", "secret_token": "abc123xyz"}',
        b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
    ]

    for pt in plaintexts:
        pt_b64 = base64.b64encode(pt).decode("utf-8")
        
        # Encrypt
        enc_resp = unlocked_client.post(
            "/transit/encrypt/my-key",
            json={"plaintext_b64": pt_b64},
            headers=headers
        )
        assert enc_resp.status_code == 200
        ciphertext = enc_resp.json()["ciphertext"]
        assert ciphertext.startswith("vault:my-key:")

        # Decrypt
        dec_resp = unlocked_client.post(
            "/transit/decrypt",
            json={"ciphertext": ciphertext},
            headers=headers
        )
        assert dec_resp.status_code == 200
        decrypted_b64 = dec_resp.json()["plaintext_b64"]
        assert decrypted_b64 == pt_b64
        assert base64.b64decode(decrypted_b64) == pt


def test_encrypt_decrypt_access_control(unlocked_client, tmp_path):
    """Bob cannot encrypt or decrypt with Alice's key, and gets PERMISSION_DENIED (403)."""
    token_alice = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    token_bob = _register_and_login(unlocked_client, "bob@example.com", "securepass456")

    # Alice creates a key
    unlocked_client.post(
        "/transit/keys",
        json={"key_name": "alice-key"},
        headers={"Authorization": f"Bearer {token_alice}"}
    )

    pt_b64 = base64.b64encode(b"secret message").decode("utf-8")

    # Bob tries to encrypt using Alice's key
    bob_enc_resp = unlocked_client.post(
        "/transit/encrypt/alice-key",
        json={"plaintext_b64": pt_b64},
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert bob_enc_resp.status_code == 403
    assert bob_enc_resp.json()["detail"] == "PERMISSION_DENIED"

    # Alice encrypts successfully
    alice_enc_resp = unlocked_client.post(
        "/transit/encrypt/alice-key",
        json={"plaintext_b64": pt_b64},
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    assert alice_enc_resp.status_code == 200
    ciphertext = alice_enc_resp.json()["ciphertext"]

    # Bob tries to decrypt Alice's ciphertext
    bob_dec_resp = unlocked_client.post(
        "/transit/decrypt",
        json={"ciphertext": ciphertext},
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert bob_dec_resp.status_code == 403
    assert bob_dec_resp.json()["detail"] == "PERMISSION_DENIED"

    # Bob tries to encrypt/decrypt with a non-existent key
    bob_nonexistent_enc = unlocked_client.post(
        "/transit/encrypt/no-key",
        json={"plaintext_b64": pt_b64},
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert bob_nonexistent_enc.status_code == 403
    assert bob_nonexistent_enc.json()["detail"] == "PERMISSION_DENIED"

    # Check that denial logs are written
    import os
    log_file = os.getenv("VAULT_LOG_FILE")
    assert log_file is not None
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        log_content = f.read()
    assert "ACCESS_DENIED" in log_content
    assert "email=bob@example.com" in log_content
    assert "id=alice-key" in log_content


def test_decrypt_tampered_ciphertext(unlocked_client):
    """Altering any byte of the ciphertext must cause the decrypt request to fail."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Create a key
    unlocked_client.post("/transit/keys", json={"key_name": "my-key"}, headers=headers)

    pt_b64 = base64.b64encode(b"super secret data").decode("utf-8")

    # Encrypt
    enc_resp = unlocked_client.post(
        "/transit/encrypt/my-key",
        json={"plaintext_b64": pt_b64},
        headers=headers
    )
    ciphertext = enc_resp.json()["ciphertext"]

    # Alter ciphertext
    # Format: vault:my-key:<base64>
    parts = ciphertext.split(":")
    raw_payload = bytearray(base64.b64decode(parts[2]))
    # Corrupt one byte (avoiding out of bound)
    raw_payload[15] ^= 0xFF
    corrupted_payload_b64 = base64.b64encode(raw_payload).decode("utf-8")
    corrupted_ciphertext = f"vault:my-key:{corrupted_payload_b64}"

    # Try decrypt
    dec_resp = unlocked_client.post(
        "/transit/decrypt",
        json={"ciphertext": corrupted_ciphertext},
        headers=headers
    )
    assert dec_resp.status_code == 400
    assert dec_resp.json()["detail"] == "DECRYPTION_FAILED"


def test_decrypt_invalid_ciphertext_format(unlocked_client):
    """Malformed or invalid ciphertexts must be rejected."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    invalid_inputs = [
        "not-vault:key:base64",
        "vault:key",
        "vault:key:notbase64!!!",
        "vault:key:",
        "vault::base64",
    ]

    for val in invalid_inputs:
        resp = unlocked_client.post(
            "/transit/decrypt",
            json={"ciphertext": val},
            headers=headers
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "INVALID_CIPHERTEXT"


def test_decrypt_invalid_key_usage(unlocked_client):
    """If key usage is not ENCRYPT_DECRYPT, reject it."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Manually insert a key with usage SIGN_VERIFY to test
    from src.storage import database
    conn = database.get_connection()
    conn.execute(
        """
        INSERT INTO transit_keys (key_name, owner_email, key_usage, encrypted_key_material_b64)
        VALUES (?, ?, ?, ?)
        """,
        ("signing-key", "alice@example.com", "SIGN_VERIFY", base64.b64encode(b"dummy_encrypted_key_material").decode("utf-8"))
    )
    conn.commit()

    # Try to encrypt using the signing key
    pt_b64 = base64.b64encode(b"data").decode("utf-8")
    enc_resp = unlocked_client.post(
        "/transit/encrypt/signing-key",
        json={"plaintext_b64": pt_b64},
        headers=headers
    )
    assert enc_resp.status_code == 400
    assert enc_resp.json()["detail"] == "INVALID_KEY_USAGE"

    # Try to decrypt using the signing key (fake ciphertext format)
    dummy_payload = base64.b64encode(b"A" * 40).decode("utf-8")
    dec_resp = unlocked_client.post(
        "/transit/decrypt",
        json={"ciphertext": f"vault:signing-key:{dummy_payload}"},
        headers=headers
    )
    assert dec_resp.status_code == 400
    assert dec_resp.json()["detail"] == "INVALID_KEY_USAGE"

