import re
import time
import secrets
import bcrypt
from src.storage import database

# ---------------------------------------------------------------------------
# In-memory session store.
#
# Sessions are intentionally kept only in RAM (not the database) so that:
#   • Restarting the server automatically invalidates all active sessions,
#     forcing users to re-authenticate with their passwords.
#   • There is no persistent session record an attacker can steal via SQLi.
#
# Format: { token_hex: {"email": str, "expires_at": unix_timestamp_float} }
# ---------------------------------------------------------------------------
_ACTIVE_SESSIONS: dict[str, dict] = {}

# Session lifetime in seconds (30 minutes)
SESSION_EXPIRY_SECONDS = 30 * 60

# Lockout configuration: after MAX_FAILED_ATTEMPTS wrong passwords,
# the account is frozen for LOCKOUT_DURATION_SECONDS to defeat brute-force.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 5 * 60  # 5 minutes

# Minimum user passphrase length (distinct from the 14-char master passphrase requirement)
MIN_PASSWORD_LENGTH = 8


def _get_current_time() -> float:
    """
    Return the current Unix timestamp.
    Extracted as a helper so tests can monkeypatch it to simulate time travel
    (e.g., advance the clock past SESSION_EXPIRY_SECONDS without sleeping).
    """
    return time.time()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _is_valid_email(email: str) -> bool:
    """Basic email format validation: must contain exactly one '@' with text on both sides."""
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email))


def _is_strong_password(password: str) -> bool:
    """User passphrase must be at least MIN_PASSWORD_LENGTH characters."""
    return bool(password) and len(password) >= MIN_PASSWORD_LENGTH


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(email: str, password: str, confirm_password: str) -> dict:
    """
    Register a new user.
    1. Validate email format.
    2. Validate password strength.
    3. Check password == confirm_password.
    4. Ensure email is unique.
    5. Hash password with bcrypt and store.
    """
    if not _is_valid_email(email):
        raise ValueError("INVALID_EMAIL")

    if not _is_strong_password(password):
        raise ValueError("WEAK_PASSWORD")

    if password != confirm_password:
        raise ValueError("PASSWORD_MISMATCH")

    conn = database.get_connection()
    row = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
    if row is not None:
        raise ValueError("EMAIL_ALREADY_EXISTS")

    # bcrypt automatically generates a unique 128-bit salt per call and embeds it
    # in the resulting hash string. This means two identical passwords produce
    # completely different hashes, defeating precomputed rainbow tables.
    # bcrypt's work factor also makes each comparison deliberately slow (~100ms),
    # making large-scale password cracking economically infeasible.
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    conn.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, hashed.decode("utf-8"))
    )
    conn.commit()

    return {"message": "User registered successfully", "email": email}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login(email: str, password: str) -> dict:
    """
    Authenticate a user and issue a session token.
    1. Check the account exists.
    2. Check lockout status.
    3. Verify password with bcrypt.
    4. On failure: increment failed_attempts, lock if >= MAX_FAILED_ATTEMPTS.
    5. On success: reset failed_attempts, issue token.
    """
    conn = database.get_connection()
    row = conn.execute(
        "SELECT email, password_hash, failed_attempts, lockout_until FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    # Return the same error code for "not found" as for "wrong password"
    # so an attacker cannot enumerate which email addresses are registered.
    if row is None:
        raise ValueError("ACCOUNT_NOT_FOUND")

    now = _get_current_time()

    # Enforce the time-based lockout before attempting bcrypt (even if the
    # password would be correct, a locked account should not proceed).
    if row["lockout_until"] and now < row["lockout_until"]:
        raise ValueError("ACCOUNT_LOCKED")

    # bcrypt.checkpw performs a constant-time comparison to prevent timing
    # side-channel attacks where an attacker infers a matching prefix by
    # measuring response time differences.
    stored_hash = row["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        # Track consecutive failures in the database so the counter survives
        # server restarts (unlike an in-memory counter, which would be bypassed
        # by simply restarting the process).
        new_attempts = row["failed_attempts"] + 1
        lockout_until = 0.0
        if new_attempts >= MAX_FAILED_ATTEMPTS:
            # Set absolute lockout expiry timestamp
            lockout_until = now + LOCKOUT_DURATION_SECONDS
        conn.execute(
            "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE email = ?",
            (new_attempts, lockout_until, email)
        )
        conn.commit()

        if new_attempts >= MAX_FAILED_ATTEMPTS:
            raise ValueError("ACCOUNT_LOCKED")
        raise ValueError("INVALID_PASSWORD")

    # Success — reset the failure counter so the user gets a fresh allowance
    # of MAX_FAILED_ATTEMPTS on the next login attempt.
    conn.execute(
        "UPDATE users SET failed_attempts = 0, lockout_until = 0.0 WHERE email = ?",
        (email,)
    )
    conn.commit()

    # Issue a session token: 32 bytes from the OS CSPRNG encoded as hex → 64-character string.
    # This gives 256 bits of entropy, making brute-force guessing computationally infeasible.
    token = secrets.token_hex(32)
    expires_at = now + SESSION_EXPIRY_SECONDS
    _ACTIVE_SESSIONS[token] = {"email": email, "expires_at": expires_at}

    return {"session_token": token, "expires_at": expires_at}


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------

def validate_session(token: str | None) -> str:
    """
    Validate a session token. Returns the email if valid.
    Raises ValueError with UNAUTHENTICATED if invalid or expired.
    """
    if not token or token not in _ACTIVE_SESSIONS:
        # Use a single generic error so the caller cannot distinguish
        # "token never existed" from "token was revoked" — both look identical.
        raise ValueError("UNAUTHENTICATED")

    session = _ACTIVE_SESSIONS[token]
    now = _get_current_time()

    if now >= session["expires_at"]:
        # Lazily evict the expired token so the session store stays clean.
        # Expired tokens become unreachable anyway, but deleting them immediately
        # prevents unbounded memory growth in long-running deployments.
        del _ACTIVE_SESSIONS[token]
        raise ValueError("SESSION_EXPIRED")

    return session["email"]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def clear_sessions() -> None:
    """Clear all active sessions. Used by test fixtures for isolation."""
    _ACTIVE_SESSIONS.clear()
