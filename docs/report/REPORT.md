# Mini Vault Project Report

## Team Information
*   **Team Name:** [Insert Team Name]
*   **Members & Student IDs:**
    *   Student 1: [Name / ID] - Role: [e.g., Cryptographic Engine & Core Logic]
    *   Student 2: [Name / ID] - Role: [e.g., API Development & Authentication]
    *   Student 3: [Name / ID] - Role: [e.g., Integration, Testing, and Documentation]

---

## II. Architecture Overview

```
              Master Passphrase (provided in memory)
                            │
                            ▼
              [ Argon2id Key Derivation ]  <─── Random Salt (data/vault_metadata.json)
                            │
                            ▼
                    Derived Key (256-bit)
                            │
                            ▼
         [ Decrypts DEK using AES-256-GCM ]  <─── Encrypted DEK (data/vault_metadata.json)
                            │
                            ▼
                     Plaintext DEK
                (Stored in memory only)
```

---

## III. Technical Explanations

### Section 0.1 — Vault Initialization & Unlock

#### 1. Key Derivation Function (KDF)
To derive a strong cryptographic key from a user-provided Master Passphrase, Mini Vault employs **Argon2id** (via the `argon2-cffi` library). 
*   **Why Argon2id?** Argon2id is the state-of-the-art key derivation function (winner of the Password Hashing Competition) designed to resist both GPU/ASIC hardware-acceleration attacks (memory-hardness) and side-channel cache-timing attacks.
*   **Parameters used:**
    *   *Salt:* A 16-byte cryptographically secure random value generated using `secrets.token_bytes(16)`.
    *   *Time Cost (Iterations):* `3`
    *   *Memory Cost:* `65536 KB` (64 MB)
    *   *Parallelism:* `4` threads
    *   *Key Length:* `32` bytes (256 bits, suitable for AES-256)

#### 2. Data Encryption Key (DEK) Generation
When the vault is initialized for the first time:
*   A 256-bit (32-byte) Data Encryption Key (DEK) is generated using `secrets.token_bytes(32)`.
*   This key is used as the master key to encrypt all subsequent secrets (Feature 1) and transit keys (Feature 2).

#### 3. DEK Encryption & Storage
The plaintext DEK must **never** be written to disk. Instead:
*   The DEK is encrypted using **AES-256-GCM** (Advanced Encryption Standard in Galois/Counter Mode).
*   **Encryption Key:** The 256-bit key derived from the Master Passphrase.
*   **Nonce (Initialization Vector):** A fresh 96-bit (12-byte) random value generated using `secrets.token_bytes(12)`.
*   **Ciphertext & Authentication Tag:** AES-GCM generates the ciphertext along with a 16-byte authentication tag to guarantee ciphertext integrity.
*   **Serialization:** The salt, encrypted DEK, and encryption details are base64-encoded and persisted to disk in the data contract JSON format:
    ```json
    {
      "kdf": "argon2id",
      "kdf_salt_b64": "<base64 encoded salt>",
      "encrypted_dek_b64": "<base64 encoded encrypted DEK and authentication tag>",
      "status": "locked"
    }
    ```

#### 4. Lifecycle & Lock State Machine
*   **Uninitialized:** The file `data/vault_metadata.json` does not exist. The vault must be initialized before use.
*   **Locked (Default State):** On application startup, the plaintext DEK is not present in memory. If any operation in Feature 1 (KV Engine) or Feature 2 (Transit Engine) is called, the server checks the in-memory state and returns `VAULT_LOCKED`.
*   **Unlocked:** Providing the correct Master Passphrase derives the key, decrypts the DEK, verifies the integrity tag, and populates the plaintext DEK in memory. The status transitions to `unlocked`.
*   **Locking:** Calling the lock API immediately wipes the decrypted DEK from memory and transitions the status to `locked`.

#### 5. Passphrase Complexity Standards (NIST SP 800-63B Guidelines)
To maximize security for the root master passphrase, Mini Vault implements guidelines from NIST SP 800-63B:
*   **Length over Complexity:** Enforces a minimum length of 14 characters, encouraging long multi-word passphrases (e.g. `correct-horse-battery-staple`) which possess high natural entropy over short, complex passwords with forced special characters.
*   **Default Prevention:** Explicitly blocks common default strings (like `master_passphrase`, `passwordpassword`, or `adminadmin12345`) to prevent deployment with placeholder credentials.

