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
        INSERT INTO transit_keys (key_name, owner_email, key_usage, encrypted_key_material_b64, signing_algorithm, public_key_b64)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("signing-key", "alice@example.com", "SIGN_VERIFY",
         base64.b64encode(b"dummy_encrypted_key_material").decode("utf-8"),
         "ED25519", "dummy_public_key_b64")
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


def test_create_signing_key_success(unlocked_client):
    """Creating a signing key successfully registers and returns the correct data contract."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    for algo in ["RSASSA_PKCS1_V1_5_SHA_256", "ED25519"]:
        key_name = f"sign-key-{algo}"
        resp = unlocked_client.post(
            "/transit/keys/signing",
            json={"key_name": key_name, "signing_algorithm": algo},
            headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_name"] == key_name
        assert data["owner_email"] == "alice@example.com"
        assert data["key_usage"] == "SIGN_VERIFY"
        assert data["signing_algorithm"] == algo
        # Neither the public key nor the encrypted/raw private key should be in the response
        assert "public_key_b64" not in data
        assert "encrypted_private_key_b64" not in data
        assert "private_key" not in str(data).lower()

    # Verify keys exist in list response
    list_resp = unlocked_client.get("/transit/keys", headers=headers)
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert len(keys) == 2
    assert {k["key_name"] for k in keys} == {"sign-key-RSASSA_PKCS1_V1_5_SHA_256", "sign-key-ED25519"}
    assert {k["key_usage"] for k in keys} == {"SIGN_VERIFY"}
    assert {k["signing_algorithm"] for k in keys} == {"RSASSA_PKCS1_V1_5_SHA_256", "ED25519"}


def test_sign_verify_success(unlocked_client):
    """Test signing and verification round-trip for both algorithms and message types (RAW, DIGEST)."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    algos = ["RSASSA_PKCS1_V1_5_SHA_256", "ED25519"]
    for algo in algos:
        key_name = f"key-{algo}"
        unlocked_client.post(
            "/transit/keys/signing",
            json={"key_name": key_name, "signing_algorithm": algo},
            headers=headers
        )

        # Message type RAW
        raw_msg = b"Hello world! This is a signed message."
        raw_msg_b64 = base64.b64encode(raw_msg).decode("utf-8")
        
        sign_resp = unlocked_client.post(
            f"/transit/sign/{key_name}",
            json={"message_b64": raw_msg_b64, "message_type": "RAW"},
            headers=headers
        )
        assert sign_resp.status_code == 200
        sig_data = sign_resp.json()
        assert "signature" in sig_data
        assert sig_data["key_name"] == key_name
        assert sig_data["signing_algorithm"] == algo

        # Verify RAW
        verify_resp = unlocked_client.post(
            f"/transit/verify/{key_name}",
            json={
                "message_b64": raw_msg_b64,
                "message_type": "RAW",
                "signature_b64": sig_data["signature"]
            },
            headers=headers
        )
        assert verify_resp.status_code == 200
        ver_data = verify_resp.json()
        assert ver_data["signature_valid"] is True
        assert ver_data["key_name"] == key_name
        assert ver_data["signing_algorithm"] == algo

        # Verify RAW with tampered message
        tampered_msg_b64 = base64.b64encode(b"Hello world! This is a signed message..").decode("utf-8")
        verify_tampered = unlocked_client.post(
            f"/transit/verify/{key_name}",
            json={
                "message_b64": tampered_msg_b64,
                "message_type": "RAW",
                "signature_b64": sig_data["signature"]
            },
            headers=headers
        )
        assert verify_tampered.status_code == 200
        assert verify_tampered.json()["signature_valid"] is False

        # Message type DIGEST (precomputed 32-byte hash)
        import hashlib
        digest = hashlib.sha256(raw_msg).digest()
        digest_b64 = base64.b64encode(digest).decode("utf-8")

        sign_digest_resp = unlocked_client.post(
            f"/transit/sign/{key_name}",
            json={"message_b64": digest_b64, "message_type": "DIGEST"},
            headers=headers
        )
        assert sign_digest_resp.status_code == 200
        sig_digest_data = sign_digest_resp.json()

        # Verify DIGEST
        verify_digest_resp = unlocked_client.post(
            f"/transit/verify/{key_name}",
            json={
                "message_b64": digest_b64,
                "message_type": "DIGEST",
                "signature_b64": sig_digest_data["signature"]
            },
            headers=headers
        )
        assert verify_digest_resp.status_code == 200
        assert verify_digest_resp.json()["signature_valid"] is True


def test_sign_verify_access_control(unlocked_client):
    """Alice's signing key cannot be used by Bob to sign or verify, raising PERMISSION_DENIED."""
    token_alice = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    token_bob = _register_and_login(unlocked_client, "bob@example.com", "securepass456")

    # Alice creates a key
    unlocked_client.post(
        "/transit/keys/signing",
        json={"key_name": "alice-signing-key", "signing_algorithm": "ED25519"},
        headers={"Authorization": f"Bearer {token_alice}"}
    )

    msg_b64 = base64.b64encode(b"hello").decode("utf-8")

    # Bob tries to sign
    sign_resp = unlocked_client.post(
        "/transit/sign/alice-signing-key",
        json={"message_b64": msg_b64, "message_type": "RAW"},
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert sign_resp.status_code == 403
    assert sign_resp.json()["detail"] == "PERMISSION_DENIED"

    # Alice signs successfully
    alice_sign_resp = unlocked_client.post(
        "/transit/sign/alice-signing-key",
        json={"message_b64": msg_b64, "message_type": "RAW"},
        headers={"Authorization": f"Bearer {token_alice}"}
    )
    sig_b64 = alice_sign_resp.json()["signature"]

    # Bob tries to verify
    verify_resp = unlocked_client.post(
        "/transit/verify/alice-signing-key",
        json={
            "message_b64": msg_b64,
            "message_type": "RAW",
            "signature_b64": sig_b64
        },
        headers={"Authorization": f"Bearer {token_bob}"}
    )
    assert verify_resp.status_code == 403
    assert verify_resp.json()["detail"] == "PERMISSION_DENIED"


def test_sign_verify_invalid_usage_and_inputs(unlocked_client):
    """Verify that encrypt keys cannot be used for signing, and invalid formats are handled."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create encrypt key
    unlocked_client.post("/transit/keys", json={"key_name": "enc-key"}, headers=headers)

    # Try to sign with encrypt key
    msg_b64 = base64.b64encode(b"hello").decode("utf-8")
    resp_sign = unlocked_client.post(
        "/transit/sign/enc-key",
        json={"message_b64": msg_b64, "message_type": "RAW"},
        headers=headers
    )
    assert resp_sign.status_code == 400
    assert resp_sign.json()["detail"] == "INVALID_KEY_USAGE"

    # 2. Create signing key
    unlocked_client.post(
        "/transit/keys/signing",
        json={"key_name": "sign-key", "signing_algorithm": "ED25519"},
        headers=headers
    )

    # Invalid digest length (expected 32 bytes)
    short_digest = base64.b64encode(b"too-short").decode("utf-8")
    resp_digest = unlocked_client.post(
        "/transit/sign/sign-key",
        json={"message_b64": short_digest, "message_type": "DIGEST"},
        headers=headers
    )
    assert resp_digest.status_code == 400
    assert resp_digest.json()["detail"] == "INVALID_DIGEST"

    # Malformed signature passed to verify -> return signature_valid: false
    resp_ver_malformed = unlocked_client.post(
        "/transit/verify/sign-key",
        json={
            "message_b64": msg_b64,
            "message_type": "RAW",
            "signature_b64": "not-base64!!!"
        },
        headers=headers
    )
    assert resp_ver_malformed.status_code == 200
    assert resp_ver_malformed.json()["signature_valid"] is False


def test_cross_key_signature_is_invalid(unlocked_client):
    """Acceptance criteria: Signature from key-A must not verify against key-B."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Create two independent ED25519 signing keys
    for kname in ["key-a", "key-b"]:
        unlocked_client.post(
            "/transit/keys/signing",
            json={"key_name": kname, "signing_algorithm": "ED25519"},
            headers=headers
        )

    msg_b64 = base64.b64encode(b"hello cross-key").decode("utf-8")

    # Sign with key-a
    sign_resp = unlocked_client.post(
        "/transit/sign/key-a",
        json={"message_b64": msg_b64, "message_type": "RAW"},
        headers=headers
    )
    sig_a = sign_resp.json()["signature"]

    # Verify against key-a: must be valid
    ver_a = unlocked_client.post(
        "/transit/verify/key-a",
        json={"message_b64": msg_b64, "message_type": "RAW", "signature_b64": sig_a},
        headers=headers
    )
    assert ver_a.status_code == 200
    assert ver_a.json()["signature_valid"] is True

    # Verify against key-b using key-a's signature: must be False
    ver_b = unlocked_client.post(
        "/transit/verify/key-b",
        json={"message_b64": msg_b64, "message_type": "RAW", "signature_b64": sig_a},
        headers=headers
    )
    assert ver_b.status_code == 200
    assert ver_b.json()["signature_valid"] is False


def test_verify_algorithm_mismatch(unlocked_client):
    """verify() with a signing_algorithm that doesn't match the key's must be rejected."""
    token = _register_and_login(unlocked_client, "alice@example.com", "securepass123")
    headers = {"Authorization": f"Bearer {token}"}

    # Create an ED25519 signing key
    unlocked_client.post(
        "/transit/keys/signing",
        json={"key_name": "ed-key", "signing_algorithm": "ED25519"},
        headers=headers
    )

    msg_b64 = base64.b64encode(b"test algo mismatch").decode("utf-8")

    sign_resp = unlocked_client.post(
        "/transit/sign/ed-key",
        json={"message_b64": msg_b64, "message_type": "RAW"},
        headers=headers
    )
    sig_b64 = sign_resp.json()["signature"]

    # Verify with correct algorithm: must succeed
    ver_ok = unlocked_client.post(
        "/transit/verify/ed-key",
        json={
            "message_b64": msg_b64, "message_type": "RAW",
            "signature_b64": sig_b64, "signing_algorithm": "ED25519"
        },
        headers=headers
    )
    assert ver_ok.status_code == 200
    assert ver_ok.json()["signature_valid"] is True

    # Verify with wrong algorithm: must be rejected with ALGORITHM_MISMATCH
    ver_mismatch = unlocked_client.post(
        "/transit/verify/ed-key",
        json={
            "message_b64": msg_b64, "message_type": "RAW",
            "signature_b64": sig_b64, "signing_algorithm": "RSASSA_PKCS1_V1_5_SHA_256"
        },
        headers=headers
    )
    assert ver_mismatch.status_code == 400
    assert ver_mismatch.json()["detail"] == "ALGORITHM_MISMATCH"
