# Core Vault Logic (Master Passphrase, init/unlock, DEK)
from src.core.vault import (
    is_strong_passphrase,
    get_status,
    get_dek,
    init_vault,
    unlock_vault,
    lock_vault
)

__all__ = [
    "is_strong_passphrase",
    "get_status",
    "get_dek",
    "init_vault",
    "unlock_vault",
    "lock_vault"
]
