# Mini Vault — Project Requirements

**Course:** Computer Security
**Assignment:** 1 — Mini Vault (Secure Storage & Encryption/Signing as a Service)
**Team size:** 3 students
**Language:** Python (`cryptography`, `bcrypt`/`argon2-cffi`, `secrets`)

---

## 1. Problem Statement

Secrets (DB passwords, API keys, etc.) are often stored in plaintext or encrypted with hardcoded keys embedded in code. Mini Vault solves two problems:

1. **Storage**: data on disk is *always* ciphertext, and only the rightful owner can read it.
2. **Crypto-as-a-service**: other applications can encrypt/decrypt or digitally sign their own data **without ever holding the key themselves**.

---

## 2. Architecture Overview

```
Master Passphrase (never stored)
      │  Argon2id + salt
      ▼
Derived Key (memory only, exists while unlocked)
      │  AES-256-GCM wrap
      ▼
DEK — Data Encryption Key (random, generated once at init)
   on disk only as: encrypted_dek_b64
      │  AES-256-GCM
      ▼
Everything else: KV secrets, Transit AES keys, Transit private signing keys
```

- **Vault-level lock** (Feature 0.1): one Master Passphrase per deployment. Controls whether the DEK is in memory at all.
- **User-level auth** (Feature 0.2): many registered users, each with their own namespace, independent of vault lock state.
- **KV Engine** (Feature 1): per-user encrypted key-value secret storage.
- **Transit Engine** (Feature 2): per-user named keys usable only via encrypt/decrypt/sign/verify calls — key material never leaves the server.

---

## 3. Required Folder Structure

```
StudentID1_StudentID2_StudentID3/
├── README.md
├── requirements.txt
├── .env.example
├── main.py
├── src/
│   ├── core/       # Master Passphrase, init/unlock, DEK (0.1)
│   ├── auth/       # Register/login, session token (0.2)
│   ├── kv/         # Feature 1: Secure Storage
│   ├── transit/    # Feature 2: Encryption & Signing as a Service
│   └── storage/    # Read/write data to disk
├── tests/
├── data/
│   ├── samples/
│   └── logs/
└── docs/
    └── report/
```

### Submission naming

- Zip the whole folder: `StudentID1_StudentID2_StudentID3.zip`
- Report: `Report_StudentID1_StudentID2_StudentID3.pdf` → placed in `docs/report/`
- Demo video (recommended, 3–5 min): unlisted Drive/YouTube link in `README.md`

---

## 4. Feature Specifications

### 0.1 — Vault Initialization & Unlock

**Goal:** One Master Passphrase per deployment; DEK never touches disk in plaintext; default state after restart is always `locked`.

**Flow:**

1. First run: admin sets Master Passphrase → derive key via KDF (Argon2id or PBKDF2-HMAC-SHA256) with a random salt.
2. Generate random DEK → encrypt with derived key (AES-256-GCM) → persist `encrypted_dek_b64` + `kdf_salt_b64`.
3. Every restart: state defaults to `locked`; Feature 1 & 2 refuse to operate.
4. Correct passphrase re-entered → re-derive key → decrypt DEK → state becomes `unlocked`.

**Data contract:**

```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "<salt>",
  "encrypted_dek_b64": "<encrypted DEK>",
  "status": "locked"
}
```

**Error handling:**

- Wrong passphrase → GCM tag mismatch → generic error (no detail disclosed)
- Any Feature 1/2 call while locked → `VAULT_LOCKED`

**Acceptance criteria:**

- [ ] Plaintext DEK never written to disk
- [ ] State is always `locked` after restart until correct passphrase is entered

---

### 0.2 — User Identity Authentication

**Goal:** Every user is known before touching any secret or key.

**Flow:**

1. Register: email + passphrase + confirm → check strength, check email uniqueness.
2. Hash passphrase with bcrypt or argon2 (never plain SHA).
3. Login: email + passphrase → issue session token with expiry (e.g. 30 min).
4. 5 consecutive failed attempts → lock account for 5 minutes (mandatory).

**Data contract:**

```json
{ "email": "alice@example.com", "password_hash": "<bcrypt/argon2>" }
```

**Error handling:**

- Nonexistent account at login → error
- Expired session token → require re-login

**Acceptance criteria:**

- [ ] Every Feature 1/2 API call requires a valid session token — no exceptions
- [ ] **Required test:** 5 wrong passphrases in a row → account locked exactly 5 minutes; correct passphrase still fails during lockout

---

### 1.1 — KV Engine: Encrypted-at-Rest Storage

**Security guarantee:** Anyone with the raw data file but not the DEK cannot read secret contents.

**Flow:**

1. `write(path, data, token)` — data is any JSON object.
2. Encrypt full payload with AES-256-GCM + DEK, fresh random nonce every write (never reuse nonce+key).
3. Persist ciphertext + nonce + tag; overwrite existing path directly (no version history).
4. `read(path, token)` — decrypt, verify tag before returning; invalid tag → refuse outright.
5. `delete(path, token)` — permanent deletion.

**API:**

| API | Input | Output |
|---|---|---|
| write | path, data (JSON), token | created_at / updated_at |
| read | path, token | decrypted data (only if tag valid) |
| delete | path, token | deletion confirmation |

**Data contract:**

```json
{ "path": "secret/alice@example.com/db", "nonce_b64": "...", "ciphertext_b64": "...", "tag_b64": "..." }
```

**Error handling:**

- Locked vault → `VAULT_LOCKED`
- Tag mismatch (tampered data) → refuse to decrypt
- Nonexistent path → `NOT_FOUND`, no garbage data returned

**Acceptance criteria:**

- [ ] write → read round-trip returns exact original data
- [ ] No plaintext fragment visible when opening the data file directly
- [ ] Manually altering 1 byte of ciphertext/tag on disk → read refuses, never returns corrupted data

---

### 1.2 — KV Engine: Ownership-based Access Control

**Security guarantee:** User A cannot read/write/delete a secret in user B's namespace, even knowing the exact path.

**Flow:**

1. Every secret stored under `secret/<email>/...`.
2. Every request checks token email vs. path's email prefix.
3. Mismatch → refuse **before** any crypto operation; generic error (doesn't distinguish "not found" vs "no permission").
4. Log every denied attempt (requester email + denied path).

**Error handling:**

- Valid token, wrong namespace → `PERMISSION_DENIED` (no existence disclosure)
- Invalid/expired token → `UNAUTHENTICATED`, rejected before permission check

**Acceptance criteria:**

- [ ] **Required test:** User A's valid token reading `secret/<B's email>/...` → denied 100% of the time
- [ ] Missing/invalid token never reaches the path-check step

---

### 2.1 — Transit Engine: Named Key Management

**Security guarantee:** Key material is never returned via any API, under any form, even to its owner.

**Flow:**

1. `create_key(key_name, token)` → generate random AES-256 key, bind to `key_name` + owner email, `key_usage = "ENCRYPT_DECRYPT"`.
2. Encrypt the AES key with the DEK before persisting.
3. `list_keys()` → names + `key_usage` only, never material. `revoke_key(key_name)` → permanent delete.

**Data contract:**

```json
{
  "key_name": "my-key",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "encrypted_key_material_b64": "<AES key encrypted with the DEK>"
}
```

**Error handling:**

- Duplicate key_name (same owner) → overwrite confirmation OR reject (team's choice, document in report)
- Locked vault → `VAULT_LOCKED`

**Acceptance criteria:**

- [ ] No API (including `list_keys`) ever returns real AES key material

---

### 2.2 — Transit Engine: Encrypt / Decrypt as a Service

**Flow:**

1. `encrypt(key_name, plaintext_b64, token)` → verify ownership (2.3) → temporarily decrypt AES key via in-memory DEK → random nonce → AES-256-GCM encrypt.
2. Return self-describing ciphertext: `vault:<key_name>:<base64(nonce+ct+tag)>`.
3. `decrypt(ciphertext, token)` → parse embedded key_name → check permission → decrypt AES key via DEK → decrypt + verify tag → return plaintext.

**API:**

| API | Input | Output |
|---|---|---|
| encrypt | key_name, plaintext (base64), token | `vault:<key_name>:<base64(nonce+ct+tag)>` |
| decrypt | ciphertext, token | plaintext (base64) |

**Error handling:**

- Malformed/truncated ciphertext → refuse
- GCM tag mismatch → refuse with clear reason
- key_name missing/revoked → refuse both operations
- key_name has `key_usage = "SIGN_VERIFY"` → reject (mirrors AWS KMS `InvalidKeyUsageException`)

**Acceptance criteria:**

- [ ] encrypt → decrypt round-trip returns exact plaintext across text/JSON/binary
- [ ] Altering any ciphertext byte → decrypt fails 100% of the time
- [ ] No request ever returns real AES key material

---

### 2.3 — Transit Engine: Named-Key Access Control

**Security guarantee:** User cannot use another user's named key, even knowing its name.

**Flow:**

1. Every named key stores `owner_email`.
2. Every encrypt/decrypt request checks token email vs. `owner_email`.
3. Mismatch → refuse **before** any crypto operation, generic error (no existence disclosure).
4. Log every denied attempt (requester email + denied key_name).

**Acceptance criteria:**

- [ ] **Required test:** User A using User B's key_name → denied 100% of the time

---

### 2.4 — Transit Engine: Sign & Verify as a Service

**Security guarantee:** Private signing key never leaves the server; tampered messages/cross-key signatures always fail verification.

**Flow:**

1. `create_signing_key(key_name, signing_algorithm, token)` → generate RSA-2048 or Ed25519 key pair; private key encrypted with DEK before storage; public key stored for server-side verification.
2. `sign(key_name, message_b64, message_type, token)` — `message_type` is `RAW` (server hashes with SHA-256) or `DIGEST` (client pre-hashed). Check ownership → sign with private key (decrypted temporarily via DEK) → return signature.
3. `verify(key_name, message_b64, message_type, signature_b64, token)` → recompute digest same way as sign → check against public key → return `{key_name, signature_valid, signing_algorithm}`.
4. Same ownership-based access control as 2.1/2.3 applies to both `sign()` and `verify()` (mandatory scope: owner-only for both).

**API:**

| API | Input | Output |
|---|---|---|
| create_signing_key | key_name, signing_algorithm, token | confirmation |
| sign | key_name, message (base64), message_type, token | signature (base64), key_name, signing_algorithm |
| verify | key_name, message (base64), message_type, signature (base64), token | key_name, signature_valid (bool), signing_algorithm |

**Data contract:**

```json
{
  "key_name": "my-signing-key",
  "owner_email": "alice@example.com",
  "key_usage": "SIGN_VERIFY",
  "signing_algorithm": "ED25519",
  "encrypted_private_key_b64": "<private key encrypted with the DEK>",
  "public_key_b64": "<public key>"
}
```

**Error handling:**

- `DIGEST` with wrong digest length → reject
- `verify()` algorithm mismatch vs. key's creation algorithm → reject
- key_name missing/revoked → refuse both sign/verify
- key_name has `key_usage = "ENCRYPT_DECRYPT"` → reject (`InvalidKeyUsageException` pattern)
- Malformed/wrong-length signature → return `signature_valid: false`, never an unhandled exception

**Acceptance criteria:**

- [ ] sign → verify on unmodified message → `signature_valid: true`, 100% of the time
- [ ] Altering 1 byte of message before verify → `signature_valid: false`, 100% of the time
- [ ] Signature from key A verified against key B → `signature_valid: false`
- [ ] No API ever returns the raw private signing key

---

## 5. Optional / Extra Credit (max +1.0 total, only after all 8 required sub-features are stable)

| Feature | Credit |
|---|---|
| Full Policy/ACL system for sharing keys/secrets across users | +0.4 |
| MFA (OTP/TOTP) for login | +0.2 |
| Shamir's Secret Sharing for Master Passphrase (N shares, K threshold) | +0.5 |
| Key rotation for Transit (versioned keys, decrypt old ciphertext) | +0.4 |
| KV versioning (history of overwrites) | +0.3 |
| Tamper-evident audit log (hash-chained) | +0.3 |
| Open `verify()` to any authenticated user via grant model | +0.3 |

---

## 6. Suggested Technology

| Task | Library |
|---|---|
| Storing KV / named keys / users | `sqlite3` or JSON |
| Password hashing | `bcrypt`, `argon2-cffi` |
| KDF for Master Passphrase | `argon2-cffi` or `hashlib.pbkdf2_hmac` |
| AES-256-GCM | `cryptography` (AESGCM) or `pycryptodome` |
| Asymmetric signing (RSA/Ed25519) | `cryptography` (`rsa`, `ed25519`) |
| CSPRNG (nonce, key, salt) | `secrets`, `os.urandom` |
| REST API (optional) | FastAPI or Flask |
| Testing | `pytest`, GitHub Actions |

---

## 7. Submission Checklist

- [ ] Full source code in the required module structure, with README.md
- [ ] Report (PDF): team name, student IDs, task assignment, architecture diagram, technical explanation of 0.1/0.2/1.1/1.2/2.1/2.2/2.3/2.4, demo screenshots, optional features completed
- [ ] Demo video (3–5 min, recommended): unlock → write/read secret → cross-user denial → create named key → encrypt/decrypt → cross-user key denial → sign → verify (valid) → verify (tampered, invalid)
- [ ] Test data files: an encrypted KV data file, sample Transit ciphertext
- [ ] Zipped as `StudentID1_StudentID2_StudentID3.zip`

---

## 8. Grading Rubric (10 pts total)

| # | Category | Criteria | Points |
|---|---|---|---|
| 1 | 0.1 Init & Unlock | Correct KDF, defaults to locked after restart, no plaintext DEK leaked | 1.0 |
| 2 | 0.2 User Authentication | Correct password hashing, session token, 5-fail lockout | 1.0 |
| 3 | 1.1 KV Encrypted-at-Rest | Correct AEAD, detects tampering, no plaintext leaked | 1.25 |
| 4 | 1.2 KV Access Control | Blocks 100% of unauthorized cross-user access | 1.0 |
| 5 | 2.1 Transit Key Management | Named key never returned in plaintext | 1.0 |
| 6 | 2.2 Transit Encrypt/Decrypt | Correct round-trip, detects tampered ciphertext | 1.25 |
| 7 | 2.3 Transit Access Control | Blocks 100% of cross-user key use | 1.0 |
| 8 | 2.4 Sign & Verify | Correct round-trip, rejects tampered/cross-key 100% | 1.0 |
| 9 | Report, README, task assignment | Clear, complete, well-illustrated, run instructions | 0.75 |
| 10 | Product Demo | Clear demo incl. denied-access and sign/verify cases | 0.75 |

---

## 9. Recommended Build Order

Dependency chain — each stage requires the previous to be working and tested:

```
0.1 Init/Unlock → 0.2 Auth → 1.1 KV crypto → 1.2 KV ACL →
2.1 Key mgmt → 2.2 Encrypt/Decrypt → 2.3 Transit ACL → 2.4 Sign/Verify
```

1. `core/` — KDF, AEAD wrapper, vault lock/unlock state machine
2. `auth/` — register, login, session tokens, failed-attempt lockout
3. `kv/` — 1.1 (encrypt/decrypt storage) then 1.2 (ownership check)
4. `transit/` — 2.1 → 2.2 → 2.3 → 2.4, same pattern each time (mechanism → ownership check → usage-type validation)
5. Wrap in CLI or FastAPI routes; write required negative tests (tampered byte, cross-user access, cross-key verify)
