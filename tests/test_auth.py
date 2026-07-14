import pytest
from fastapi.testclient import TestClient
from main import app
from src.storage import database
from src.auth import auth


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


# ═══════════════════════════════════════════════════════════════════════════
# Registration Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_register_success(unlocked_client):
    """1. Register a new user with a valid email and strong password."""
    response = unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_register_duplicate_email(unlocked_client):
    """2. Registering the same email twice must fail."""
    payload = {
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    }
    unlocked_client.post("/auth/register", json=payload)

    response = unlocked_client.post("/auth/register", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "EMAIL_ALREADY_EXISTS"


def test_register_password_mismatch(unlocked_client):
    """3. Password and confirm_password must match."""
    response = unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "differentpass456"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "PASSWORD_MISMATCH"


def test_register_weak_password(unlocked_client):
    """4. Password shorter than 8 characters must fail."""
    response = unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "short",
        "confirm_password": "short"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "WEAK_PASSWORD"


def test_register_invalid_email(unlocked_client):
    """4b. Email without '@' or with invalid format must fail."""
    response = unlocked_client.post("/auth/register", json={
        "email": "not-an-email",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "INVALID_EMAIL"


# ═══════════════════════════════════════════════════════════════════════════
# Login Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_login_success(unlocked_client):
    """5. Login with correct credentials returns a session token."""
    unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })

    response = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "session_token" in data
    assert "expires_at" in data
    assert len(data["session_token"]) == 64  # 32 bytes hex = 64 chars


def test_login_nonexistent_account(unlocked_client):
    """6. Login for an email that was never registered must fail."""
    response = unlocked_client.post("/auth/login", json={
        "email": "nobody@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "ACCOUNT_NOT_FOUND"


def test_login_invalid_password(unlocked_client):
    """7. Login with the wrong password must fail."""
    unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })

    response = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "wrongpassword999"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "INVALID_PASSWORD"


# ═══════════════════════════════════════════════════════════════════════════
# Lockout Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_lockout_enforcement(unlocked_client, monkeypatch):
    """
    8. test_lockout_enforcement (REQUIRED TEST):
    - 5 wrong passwords in a row → account locked for 5 minutes.
    - Correct password still fails during lockout.
    - After 5 minutes, correct password succeeds.
    """
    unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })

    fake_time = 1000000.0
    monkeypatch.setattr("src.auth.auth._get_current_time", lambda: fake_time)

    # Fail 5 times in a row
    for i in range(5):
        response = unlocked_client.post("/auth/login", json={
            "email": "alice@example.com",
            "password": "wrongpassword"
        })
        if i < 4:
            assert response.status_code == 400
            assert response.json()["detail"] == "INVALID_PASSWORD"
        else:
            # 5th failure triggers lockout
            assert response.status_code == 400
            assert response.json()["detail"] == "ACCOUNT_LOCKED"

    # Correct password still fails during lockout
    response = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "ACCOUNT_LOCKED"

    # Fast-forward time by 5 minutes
    fake_time_after_lockout = fake_time + (5 * 60) + 1
    monkeypatch.setattr("src.auth.auth._get_current_time", lambda: fake_time_after_lockout)

    # Correct password succeeds after lockout expires
    response = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 200
    assert "session_token" in response.json()


def test_failed_attempts_reset_on_success(unlocked_client, monkeypatch):
    """
    8b. After 3 failed attempts, a successful login resets the counter.
    Then 4 more failures should NOT trigger lockout (only 4, not 5 total).
    """
    unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })

    fake_time = 1000000.0
    monkeypatch.setattr("src.auth.auth._get_current_time", lambda: fake_time)

    # Fail 3 times
    for _ in range(3):
        unlocked_client.post("/auth/login", json={
            "email": "alice@example.com",
            "password": "wrongpassword"
        })

    # Succeed once — this should reset the counter to 0
    response = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 200

    # Now fail 4 more times — should NOT trigger lockout (need 5 consecutive)
    for i in range(4):
        response = unlocked_client.post("/auth/login", json={
            "email": "alice@example.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 400
        assert response.json()["detail"] == "INVALID_PASSWORD"


# ═══════════════════════════════════════════════════════════════════════════
# Session Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_session_expiry(unlocked_client, monkeypatch):
    """
    9. A session token must expire after 30 minutes.
    """
    unlocked_client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })

    fake_time = 1000000.0
    monkeypatch.setattr("src.auth.auth._get_current_time", lambda: fake_time)

    login_resp = unlocked_client.post("/auth/login", json={
        "email": "alice@example.com",
        "password": "securepass123"
    })
    token = login_resp.json()["session_token"]

    # Token is valid right now
    response = unlocked_client.get("/vault/protected-test", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    # Fast-forward 31 minutes
    monkeypatch.setattr("src.auth.auth._get_current_time", lambda: fake_time + 31 * 60)

    response = unlocked_client.get("/vault/protected-test", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "SESSION_EXPIRED"


def test_protected_endpoint_requires_token(unlocked_client):
    """
    10. Protected endpoints must reject requests without a valid session token.
    """
    # No token at all
    response = unlocked_client.get("/vault/protected-test")
    assert response.status_code == 401
    assert response.json()["detail"] == "UNAUTHENTICATED"

    # Completely invalid token
    response = unlocked_client.get(
        "/vault/protected-test",
        headers={"Authorization": "Bearer totally_fake_token_1234"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "UNAUTHENTICATED"
