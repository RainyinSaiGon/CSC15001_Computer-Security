# Mini Vault

Mini Vault is a secure storage (KV Engine) and Encryption/Signing as a service (Transit Engine) designed for secure secret custody and server-side cryptographic operations without exposing raw keys to clients.

## Project Structure
```
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
├── tests/          # pytest unit tests
├── data/           # Storage files & logs
└── docs/report/    # PDF report destination
```

---

## Getting Started

### 1. Prerequisites
Ensure you have Python 3.10+ installed.

### 2. Installation
Install the required dependencies using pip:
```bash
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the template `.env.example` to `.env` (optional, default configurations will be used if not present):
```bash
cp .env.example .env
```

---

## Running the Services

Start the FastAPI application by executing the entrypoint:
```bash
python main.py
```
This launches the server at `http://127.0.0.1:8000` with hot-reload enabled.

---

## Running Tests

To run the full suite of automated unit tests:
```bash
python -m pytest
```

---

## API Usage Examples

### 1. Check Vault Status
Returns whether the vault is `uninitialized`, `locked`, or `unlocked`.
```bash
curl http://127.0.0.1:8000/vault/status
```
*Response:*
```json
{
  "status": "uninitialized"
}
```

### 2. Initialize the Vault
Set the root master passphrase. The passphrase must be at least 14 characters long and cannot be a common placeholder.
```bash
curl -X POST http://127.0.0.1:8000/vault/init \
  -H "Content-Type: application/json" \
  -d '{"master_passphrase": "correct-horse-battery-staple-2026!"}'
```
*Response:*
```json
{
  "status": "unlocked"
}
```

### 3. Lock the Vault
Manually lock the vault (wipes the decrypted Data Encryption Key from memory).
```bash
curl -X POST http://127.0.0.1:8000/vault/lock
```
*Response:*
```json
{
  "status": "locked"
}
```

### 4. Unlock the Vault
Unlock the vault using the correct master passphrase.
```bash
curl -X POST http://127.0.0.1:8000/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"master_passphrase": "correct-horse-battery-staple-2026!"}'
```
*Response:*
```json
{
  "status": "unlocked"
}
```
