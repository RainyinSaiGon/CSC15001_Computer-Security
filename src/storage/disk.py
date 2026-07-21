import os
import json


def get_metadata_path() -> str:
    """
    Resolve the path to vault_metadata.json based on the VAULT_DATA_DIR environment variable.
    Ensures the parent directory exists before returning the path.

    This file holds the KDF parameters (salt) and the DEK encrypted under the
    derived master key — all values are safe to store on disk (no plaintext secrets).
    """
    data_dir = os.getenv("VAULT_DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "vault_metadata.json")


def write_vault_metadata(metadata: dict) -> None:
    """
    Serialize and write the vault metadata structure to disk as JSON.

    The metadata contains:
      • kdf           — algorithm name ("argon2id")
      • kdf_salt_b64  — base64-encoded 128-bit KDF salt
      • encrypted_dek_b64 — base64-encoded nonce + AES-256-GCM(DEK)
      • status        — informational only ("locked"); in-memory state is authoritative
    """
    path = get_metadata_path()
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


def read_vault_metadata() -> dict | None:
    """
    Read and deserialize the vault metadata from disk.

    Returns None in two cases:
      1. The file does not exist → vault has never been initialized.
      2. The file is present but unreadable JSON → treat as corrupt / uninitialized.
         Callers will surface this as "UNINITIALIZED" to avoid leaking internal errors.
    """
    path = get_metadata_path()
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # A corrupted metadata file is treated the same as a missing one
            # rather than crashing with an unhandled exception.
            return None


def log_denied_access(email: str, resource_type: str, resource_identifier: str) -> None:
    """
    Append a structured line to the access-denial audit log.

    Every time a user attempts to operate on a resource they do not own
    (wrong owner, nonexistent key, etc.) this function is called BEFORE
    the error is raised, ensuring the event is recorded even if the caller
    catches the exception.

    Log format (one line per event):
        [ISO-8601-UTC] ACCESS_DENIED: email=<email>, type=<resource_type>, id=<resource_identifier>

    The log file path is configured via VAULT_LOG_FILE (defaults to data/vault.log).
    Tests redirect this to a temp path via monkeypatch to avoid polluting the repo.
    """
    import datetime
    log_file = os.getenv("VAULT_LOG_FILE", os.path.join("data", "vault.log"))

    # Ensure the log directory exists before opening the file for appending.
    # os.path.dirname returns "" for a bare filename with no path component,
    # so we guard against calling makedirs("").
    parent_dir = os.path.dirname(log_file)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_line = f"[{timestamp}] ACCESS_DENIED: email={email}, type={resource_type}, id={resource_identifier}\n"

    # 'a' (append) mode ensures concurrent writes from multiple requests do not
    # truncate earlier entries — each write adds to the end of the file.
    with open(log_file, "a") as f:
        f.write(log_line)
