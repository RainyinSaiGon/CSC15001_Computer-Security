import os
import sqlite3

_connection: sqlite3.Connection | None = None

def _get_db_path() -> str:
    """Resolve the path to the SQLite database file."""
    data_dir = os.getenv("VAULT_DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "vault.db")

def get_connection() -> sqlite3.Connection:
    """Get or create a SQLite connection. Creates the users table if needed."""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(_get_db_path(), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _init_tables(_connection)
    return _connection

def reset_connection() -> None:
    """Close and reset the connection. Used by tests for isolation."""
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None

def _init_tables(conn: sqlite3.Connection) -> None:
    """Create the users and transit_keys tables if they do not exist."""
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
            PRIMARY KEY (owner_email, key_name)
        )
    """)
    conn.commit()
