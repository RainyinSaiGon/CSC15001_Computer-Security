import os
import sqlite3

# ---------------------------------------------------------------------------
# Single global SQLite connection.
#
# SQLite is used here for simplicity in a single-process deployment.
# check_same_thread=False is safe in this context because FastAPI runs
# request handlers on the same thread pool and our endpoints are synchronous.
# In a multi-threaded or async deployment, each thread/coroutine should own
# its own connection from a connection pool.
# ---------------------------------------------------------------------------
_connection: sqlite3.Connection | None = None


def _get_db_path() -> str:
    """
    Resolve the path to the SQLite database file.

    The VAULT_DATA_DIR environment variable lets tests redirect the database
    to a temporary directory so they never touch the production data file.
    """
    data_dir = os.getenv("VAULT_DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "vault.db")


def get_connection() -> sqlite3.Connection:
    """
    Get or create the shared SQLite connection.
    Initializes the schema on first call (idempotent due to IF NOT EXISTS clauses).
    """
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(_get_db_path(), check_same_thread=False)
        # Row factory returns rows as dict-like objects (accessible by column name),
        # which is safer than index-based access and more readable.
        _connection.row_factory = sqlite3.Row
        _init_tables(_connection)
    return _connection


def reset_connection() -> None:
    """
    Close and discard the current connection. Used by test fixtures for isolation:
    each test gets a fresh database by redirecting VAULT_DATA_DIR to a temp path
    and calling this function to force re-connection.
    """
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None


def _init_tables(conn: sqlite3.Connection) -> None:
    """
    Create all database tables if they do not already exist.

    Schema notes:
    ─────────────────────────────────────────────────────────────
    users
        email               → PRIMARY KEY; enforces uniqueness at DB level
        password_hash       → bcrypt output (includes algorithm + salt + hash)
        failed_attempts     → consecutive wrong-password counter (survives restarts)
        lockout_until       → Unix float timestamp when the lockout expires (0.0 = no lock)

    transit_keys
        (owner_email, key_name) → composite PRIMARY KEY; a key name is scoped to its owner,
                                  so two different users can each have a key named "my-key"
                                  without collision.
        key_usage           → "ENCRYPT_DECRYPT" for AES keys, "SIGN_VERIFY" for asymmetric pairs
        encrypted_key_material_b64 → the raw AES key or PEM private key, encrypted by the DEK
                                     (AES-256-GCM). Never stored in plaintext.
        signing_algorithm   → "RSASSA_PKCS1_V1_5_SHA_256" or "ED25519" (only for SIGN_VERIFY keys)
        public_key_b64      → PEM-encoded public key, stored for server-side verify()
                              (NOT returned through the API; server only)
    ─────────────────────────────────────────────────────────────
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until REAL DEFAULT 0.0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transit_keys (
            key_name TEXT,
            owner_email TEXT,
            key_usage TEXT,
            encrypted_key_material_b64 TEXT NOT NULL,
            signing_algorithm TEXT,
            public_key_b64 TEXT,
            PRIMARY KEY (owner_email, key_name)
        )
    """)

    # Migration guard: add new columns to any database created by an older version
    # of the schema. ALTER TABLE ADD COLUMN raises OperationalError if the column
    # already exists — we suppress that specific error and re-raise anything else.
    try:
        conn.execute("ALTER TABLE transit_keys ADD COLUMN signing_algorithm TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists — nothing to do

    try:
        conn.execute("ALTER TABLE transit_keys ADD COLUMN public_key_b64 TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists — nothing to do

    conn.commit()
