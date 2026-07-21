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
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
   [ Named AES-256 Key ]     [ RSA-2048 / Ed25519 Private Key ]
   (ENCRYPT_DECRYPT keys)        (SIGN_VERIFY keys)
   Encrypted with DEK            Encrypted with DEK
   Stored in vault.db            Stored in vault.db
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

---

### Section 0.2 — User Identity Authentication

#### 1. Password Hashing (bcrypt)
User passphrases are hashed using **bcrypt** (via the `bcrypt` Python library), which is a dedicated password-hashing algorithm designed to be computationally expensive, making brute-force attacks impractical.
*   **Hashing**: `bcrypt.hashpw(password, bcrypt.gensalt())` generates a unique salt and hash per user.
*   **Verification**: `bcrypt.checkpw(password, stored_hash)` performs constant-time comparison, resistant to timing attacks.
*   **Why not SHA?** SHA-256/SHA-512 are general-purpose hash functions optimized for speed — the exact opposite of what password storage needs. bcrypt's configurable work factor makes it deliberately slow.

#### 2. User Registration
*   **Email Validation**: Basic format check ensures the email contains `@` and a domain with a dot (regex: `^[^@\s]+@[^@\s]+\.[^@\s]+$`).
*   **Password Strength**: Minimum 8 characters for user passphrases (distinct from the 14-character requirement for the root master passphrase).
*   **Password Confirmation**: The `confirm_password` field must match `password` exactly.
*   **Uniqueness**: Checked via SQLite `PRIMARY KEY` constraint on the `email` column.

#### 3. Session Token Management
*   **Generation**: 32-byte cryptographically secure random hex token (`secrets.token_hex(32)`), producing a 64-character string.
*   **Storage**: In-memory dictionary mapping `token → {email, expires_at}`. Sessions are intentionally volatile — they are cleared on server restart, forcing re-authentication.
*   **Expiry**: 30 minutes from the time of issue. Every protected API call validates the token and checks expiry.
*   **Authorization Header**: Tokens are passed as `Authorization: Bearer <token>` in HTTP headers, following standard REST conventions.

#### 4. Account Lockout Mechanism
*   **Trigger**: 5 consecutive failed login attempts.
*   **Duration**: 5 minutes (300 seconds), enforced via a `lockout_until` Unix timestamp stored in the SQLite `users` table.
*   **Enforcement**: During the lockout period, **all** login attempts are rejected immediately — even with the correct password — before any password verification occurs. This prevents timing-based attacks from inferring whether a password is correct.
*   **Reset**: A successful login resets the `failed_attempts` counter to 0 and clears `lockout_until`.

#### 5. Database Schema
User accounts are stored in an SQLite database (`data/vault.db`) with the following schema:
```sql
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until REAL DEFAULT 0.0  -- Unix timestamp
);
```

#### 6. Time Abstraction for Testability
All time-dependent logic uses a `_get_current_time()` helper function that wraps `time.time()`. This design allows tests to monkeypatch the function to simulate time travel (e.g., fast-forwarding past a lockout period or session expiry) without relying on `time.sleep()`, which would make tests slow and non-deterministic.

---

### Section 2 — Transit Engine: Encryption & Signing as a Service

The Transit Engine is a server-side cryptography service modelled after HashiCorp Vault's Transit secrets engine. Its central invariant is that **raw key material (AES keys, RSA/Ed25519 private keys) never leaves the server through any API**, under any form — not even to the key's own owner. All cryptographic operations are performed on the server, and only the results (ciphertext, signature, verification outcome) are returned.

All named keys are stored encrypted at rest using the vault's DEK via the same envelope encryption pattern as Feature 0.1: `DEK → AES-256-GCM → named key material → disk`.

#### Database Schema (`transit_keys`)

```sql
CREATE TABLE IF NOT EXISTS transit_keys (
    key_name    TEXT,
    owner_email TEXT,
    key_usage   TEXT,                        -- "ENCRYPT_DECRYPT" or "SIGN_VERIFY"
    encrypted_key_material_b64 TEXT NOT NULL, -- DEK-encrypted key, never plaintext
    signing_algorithm TEXT,                  -- NULL for AES keys; algo name for signing keys
    public_key_b64    TEXT,                  -- PEM public key for signing keys (server-side only)
    PRIMARY KEY (owner_email, key_name)      -- composite PK: key names are scoped per user
);
```

The composite primary key `(owner_email, key_name)` means two different users can each own a key named `my-key` without collision — a key name is always scoped to its owner.

---

#### 2.1 — Named Key Management

**Security guarantee:** The AES-256 key used to encrypt a client's data is **never returned** through any API, under any form — it can only be used indirectly via `encrypt`/`decrypt`.

**Design decision — duplicate key names:** When `create_key` is called with a name that already exists for the same user, the request is **rejected** with `KEY_ALREADY_EXISTS` (HTTP 400). We chose rejection over silent overwrite because overwriting would silently invalidate all previously produced ciphertext that relied on the old key, with no warning to the caller.

**Cryptographic flow:**
1.  **Generation:** A 256-bit random AES key is produced via `secrets.token_bytes(32)` (OS CSPRNG).
2.  **Wrapping:** The raw key is immediately encrypted with the DEK (AES-256-GCM), using a fresh 96-bit nonce per key, before any storage occurs. The raw key exists in plaintext only briefly in process memory during the wrapping step.
3.  **Storage:** Only the base64-encoded `nonce || ciphertext || GCM tag` blob is written to the database.
4.  **Listing:** `list_keys()` queries only `key_name`, `key_usage`, and `signing_algorithm` — the `encrypted_key_material_b64` column is never included in query results returned to the client.
5.  **Revocation:** `revoke_key()` permanently DELETEs the database row. Because only the encrypted form was stored and no backup exists, any ciphertext encrypted with the revoked key is irrecoverable — by design.

**API endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/transit/keys` | Create a new named AES-256 key |
| `GET` | `/transit/keys` | List all keys owned by the caller |
| `DELETE` | `/transit/keys/{key_name}` | Permanently revoke a named key |

---

#### 2.2 — Encryption / Decryption API

**Ciphertext format:** `vault:<key_name>:<base64(nonce + ciphertext + GCM tag)>`

The `vault:` prefix makes the format self-describing: `decrypt()` reads the embedded `key_name` directly from the ciphertext string. The caller never needs to remember which key was used — the ciphertext is self-routing.

**Parsing detail:** The ciphertext string is split with `maxsplit=2` (`ciphertext.split(":", 2)`), so key names that contain colons (e.g. `org:team:key`) are still parsed correctly. A naive `split(":")` would produce too many parts and incorrectly fail validation.

**Cryptographic flow for `encrypt`:**
1.  Vault locked check (dek != None).
2.  Ownership check — run **before** any key material is accessed (see 2.3).
3.  `key_usage` guard — rejects `SIGN_VERIFY` keys with `INVALID_KEY_USAGE`.
4.  Unwrap the named AES key: `AESGCM(dek).decrypt(nonce, blob)`.
5.  Generate a **fresh 96-bit nonce** for this specific encrypt call. Nonce reuse under the same key is catastrophic for AES-GCM — it reveals the XOR of the two plaintexts — so a new nonce is generated unconditionally for every call.
6.  Encrypt: `AESGCM(raw_key).encrypt(nonce, plaintext, None)` → returns `ciphertext || 16-byte GCM tag`.
7.  Encode result as `vault:<key_name>:<base64(nonce||ct||tag)>`.

**Cryptographic flow for `decrypt`:**
1.  Vault locked check.
2.  Parse and validate ciphertext format; check minimum payload length (≥ 28 bytes: 12-byte nonce + 16-byte tag minimum).
3.  Ownership check.
4.  `key_usage` guard.
5.  Unwrap the named AES key.
6.  `AESGCM(raw_key).decrypt(nonce, ct_and_tag, None)` — the GCM authentication tag is verified **atomically** before any plaintext is released. A single-bit change to the ciphertext causes tag verification to fail, and the call raises `DECRYPTION_FAILED` (HTTP 400). Partial plaintext is never returned.

**API endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/transit/encrypt/{key_name}` | Encrypt base64 plaintext, returns vault ciphertext |
| `POST` | `/transit/decrypt` | Decrypt vault ciphertext, returns base64 plaintext |

---

#### 2.3 — Named-Key Access Control

**Security guarantee:** A user cannot operate on another user's named key, even if they know its exact name.

**Implementation:**
*   Every key row stores `owner_email`, set at creation time from the validated session token.
*   Every `encrypt`, `decrypt`, `sign`, and `verify` call performs an ownership check: `row["owner_email"] != caller_email`.
*   If the key does not exist **or** belongs to a different user, both cases return the same generic `PERMISSION_DENIED` error (HTTP 403) — the caller cannot distinguish "key not found" from "access denied". This prevents key-name enumeration attacks.
*   The access denial is **logged before the error is raised** via `disk.log_denied_access(email, "key", key_name)`, writing a structured line to `data/vault.log`. Even if the caller catches the HTTP 403, the audit event is already persisted.

**Audit log format:**
```
[2025-07-21T14:00:00Z] ACCESS_DENIED: email=bob@example.com, type=key, id=alice-key
```

---

#### 2.4 — Sign & Verify as a Service

**Security guarantee:** The private signing key never leaves the server. Verification uses only the stored public key — the DEK is not required for `verify()`.

**Supported algorithms:**

| Algorithm constant | Key type | Key size | Hash | Notes |
|---|---|---|---|---|
| `RSASSA_PKCS1_V1_5_SHA_256` | RSA | 2048-bit | SHA-256 | PKCS#1 v1.5 padding; `public_exponent=65537` |
| `ED25519` | Edwards-curve | 32-byte | SHA-256 (pre-hash) | ~128-bit security; immune to timing side-channels |

**Why Ed25519 over ECDSA?** Ed25519 is deterministic (no random `k` value per signature) and immune to the nonce-reuse vulnerability that breaks ECDSA when the same `k` is used twice. It also produces smaller signatures (64 bytes vs. ~72 bytes for P-256 ECDSA) with faster verification.

**Key creation flow (`create_signing_key`):**
1.  Generate the key pair server-side. The private key is serialized to PKCS#8 PEM format (unencrypted at the Python level — the DEK wrap below is the encryption layer).
2.  Wrap the private key bytes with the DEK (AES-256-GCM, fresh nonce).
3.  Store `encrypted_key_material_b64` (wrapped private key) and `public_key_b64` (plain PEM public key — public keys are not secrets) in `transit_keys`.
4.  **Return only** `{key_name, owner_email, key_usage, signing_algorithm}` — no key material of any kind appears in the API response.

**Signing flow (`sign`):**
*   `message_type = "RAW"`: server computes `SHA-256(message)` then signs the digest.
*   `message_type = "DIGEST"`: caller provides a pre-computed digest; server validates it is exactly 32 bytes (SHA-256 output size), then signs it directly using `Prehashed(SHA256())`.
*   For RSA, the `cryptography` library handles hashing internally when `hashes.SHA256()` is passed. For Ed25519, hashing is done explicitly before calling `private_key.sign(digest)` so both paths produce a consistent 32-byte pre-hash.

**Verification flow (`verify`):**
*   Uses the stored public key — the DEK and private key are **never accessed**.
*   Recomputes the digest using the identical RAW/DIGEST branching logic as `sign()`.
*   Returns `{"key_name": ..., "signature_valid": bool, "signing_algorithm": ...}` — mirroring the AWS KMS Verify API response shape.
*   A bad signature, tampered message, or malformed signature bytes all result in `signature_valid: false` (HTTP 200), **not** an exception. This distinguishes "bad signature" (expected, not an error) from an actual API failure.
*   An **optional** `signing_algorithm` field in the `verify` request lets callers assert which algorithm they expect. If provided and it does not match the key's stored algorithm, `ALGORITHM_MISMATCH` (HTTP 400) is returned immediately, before any crypto work is done.

**API endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/transit/keys/signing` | Create a named signing key pair |
| `POST` | `/transit/sign/{key_name}` | Sign a message/digest, return signature |
| `POST` | `/transit/verify/{key_name}` | Verify a signature, return `signature_valid` |

---

### Testing Summary

All 43 automated tests pass (`pytest -v`). The test suite covers every acceptance criterion from Sections 0 and 2:

| Test file | Tests | What is covered |
|---|---|---|
| `tests/test_vault.py` | 8 | Vault init, lock/unlock, wrong passphrase, weak passphrase, restart persistence |
| `tests/test_auth.py` | 12 | Registration, login, lockout, session expiry, token validation |
| `tests/test_main.py` | 1 | Health check endpoint |
| `tests/test_transit.py` | 22 | Full coverage of features 2.1–2.4 (see table below) |

**Transit test breakdown:**

| Test | Feature | What is verified |
|---|---|---|
| `test_create_key_success` | 2.1 | Key created; `encrypted_key_material_b64` in DB; no raw key in response |
| `test_create_key_duplicate` | 2.1 | Duplicate name rejected with `KEY_ALREADY_EXISTS` |
| `test_create_key_namespacing` | 2.1 | Two users may use the same key name independently |
| `test_create_key_invalid_name` | 2.1 | Blank/whitespace-only name rejected |
| `test_list_keys` | 2.1 | List returns names + usage only; no key material |
| `test_list_keys_namespacing` | 2.1 | User A's `list_keys` does not include User B's keys |
| `test_revoke_key_success` | 2.1 | Key removed from DB; subsequent operations fail |
| `test_revoke_key_not_found` | 2.1 | Revoking nonexistent key → `KEY_NOT_FOUND` |
| `test_revoke_key_namespacing` | 2.3 | User A cannot revoke User B's key |
| `test_vault_locked_refuses_operations` | 2.1 | All transit ops return `VAULT_LOCKED` when sealed |
| `test_key_persistence_across_restarts` | 2.1 | Keys survive simulated server restart (DB persists) |
| `test_encrypt_decrypt_success` | 2.2 | Round-trip: text, JSON, binary — all return exact original |
| `test_encrypt_decrypt_access_control` | 2.3 | User B denied on User A's key; denial logged |
| `test_decrypt_tampered_ciphertext` | 2.2 | Single-byte alteration → `DECRYPTION_FAILED` 100% |
| `test_decrypt_invalid_ciphertext_format` | 2.2 | Malformed format strings rejected |
| `test_decrypt_invalid_key_usage` | 2.2 | `SIGN_VERIFY` key rejected for encrypt/decrypt |
| `test_create_signing_key_success` | 2.4 | Both algorithms created; no key material in response |
| `test_sign_verify_success` | 2.4 | Round-trip sign→verify for RSA and Ed25519, RAW and DIGEST |
| `test_sign_verify_access_control` | 2.4 | Ownership enforced for both sign and verify |
| `test_sign_verify_invalid_usage_and_inputs` | 2.4 | Wrong usage, bad digest length, malformed signature |
| `test_cross_key_signature_is_invalid` | 2.4 | Sig from key-A fails verification against key-B |
| `test_verify_algorithm_mismatch` | 2.4 | Mismatched `signing_algorithm` param → `ALGORITHM_MISMATCH` |
