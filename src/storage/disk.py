import os
import json

def get_metadata_path() -> str:
    """
    Resolve the path to vault_metadata.json based on the VAULT_DATA_DIR environment variable.
    Ensures the parent directory exists.
    """
    data_dir = os.getenv("VAULT_DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "vault_metadata.json")

def write_vault_metadata(metadata: dict) -> None:
    """
    Write the vault metadata structure to disk.
    """
    path = get_metadata_path()
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)

def read_vault_metadata() -> dict | None:
    """
    Read the vault metadata structure from disk. Returns None if the file does not exist.
    """
    path = get_metadata_path()
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None
