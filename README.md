# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-79%25-green.svg)](https://github.com/TheRedTower/secure-string-cipher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)

A security-focused AES-256-GCM encryption CLI tool with passphrase vault and modern cryptographic defaults.

## Features

- **AES-256-GCM encryption** for text and files with authenticated encryption
- **Argon2id key derivation** – memory-hard, GPU/ASIC resistant
- **Key commitment scheme** – prevents partitioning oracle attacks
- **Hidden password input** – passwords hidden in interactive terminals, visible for scripts/tests
- **Inline passphrase generation** – type `/gen` at any password prompt
- **Encrypted passphrase vault** with HMAC-SHA256 integrity verification
- **Secure memory handling** via libsodium (PyNaCl) when available
- **Timing-safe operations** – constant-time comparisons prevent side-channel attacks
- Chunked file streaming (256 KiB) for low memory usage
- Automatic vault backups (last 5 kept)

## Quick Start

```bash
# Install from PyPI
pip install secure-string-cipher

# Run interactive CLI
ssc start

# Or use non-interactive CLI
ssc --help
```

## Installation

```bash
# Recommended: install with pipx
pipx install secure-string-cipher

# Or with pip
pip install secure-string-cipher

# Or from source (dev/install with uv)
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --extra dev --locked

# Run tooling with the locked environment
uv run --locked ssc --help
```

> Requires Python 3.12+

## Usage

### Non-Interactive CLI (`ssc`)

For scripting and automation, use the `ssc` command:

```bash
# Encrypt text
ssc encrypt -t "Secret message"

# Encrypt a file
ssc encrypt -f document.pdf

# Decrypt a file (restores original filename by default)
ssc decrypt -f document.pdf.enc

# Decrypt with an explicit output path
ssc decrypt -f document.pdf.enc --output document.pdf

# Decrypt without restoring the stored filename
ssc decrypt -f document.pdf.enc --no-restore-filename

# Decrypt using a vault password
ssc decrypt -f document.pdf.enc --vault my-server

# Store a password in vault
ssc store my-server

# Auto-generate and store a password
ssc store backup-key --generate

# Vault management
ssc vault list
ssc vault delete old-key
ssc vault export backup.json
ssc vault import backup.json  # validates header and integrity before replacing
```

**Exit codes:** 0=success, 1=input error, 2=auth error, 3=vault error, 4=file error

**Security:** Passwords are never passed via command line arguments (prevents shell history exposure). All passwords are prompted interactively or retrieved from the vault.

### Interactive CLI (`ssc start`)

For interactive use, run:

```bash
ssc start
```

You'll see this menu:

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                       AVAILABLE OPERATIONS                     ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                ┃
┃  TEXT & FILE ENCRYPTION                                        ┃
┃                                                                ┃
┃    [1] Encrypt Text      →  Encrypt a message (base64 output)  ┃
┃    [2] Decrypt Text      →  Decrypt an encrypted message       ┃
┃    [3] Encrypt File      →  Encrypt a file (creates .enc)      ┃
┃    [4] Decrypt File      →  Decrypt an encrypted file          ┃
┃                                                                ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  PASSPHRASE VAULT (Optional)                                   ┃
┃                                                                ┃
┃    [5] Generate Passphrase  →  Create secure random password   ┃
┃    [6] Store in Vault       →  Save passphrase securely        ┃
┃    [7] Retrieve from Vault  →  Get stored passphrase           ┃
┃    [8] List Vault Entries   →  View all stored labels          ┃
┃    [9] Manage Vault         →  Update or delete entries        ┃
┃                                                                ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃    [0] Exit                →  Quit application                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

```

Choose an option and follow the prompts.

### Quick Passphrase Generation

When prompted for a password during encryption, you can type `/gen` (or `/generate` or `/g`) to instantly generate a strong passphrase:

```text
Enter passphrase: /gen

🔑 Auto-Generating Secure Passphrase...

✅ Generated Passphrase:
8w@!-@_#M)wF,Qn(ms.Uv+3z

Entropy: 155.0 bits

💾 Store this passphrase in vault? (y/n) [n]: y
Enter a label for this passphrase: backup-2025
Enter master password to encrypt vault: ••••••••••••
✅ Passphrase 'backup-2025' stored in vault!

✅ Using this passphrase for current operation...
```

Generated passphrases have 155+ bits of entropy and can be stored directly in the encrypted vault.

### Passphrase Vault

The vault stores passphrases encrypted with your master password at `~/.secure-cipher/passphrase_vault.enc`:

- **Generate & store** – Option 5 or `/gen` during encryption
- **Manual storage** – Option 6 for existing passphrases
- **Retrieve/manage** – Options 7-9 for lookup, listing, and deletion

All vault operations use HMAC integrity verification and maintain automatic backups.

## Docker

Use the pre-built image (Python 3.14-alpine based):

```bash
# Pull and run
docker pull ghcr.io/theredtower/secure-string-cipher:latest
docker run --rm -it ghcr.io/theredtower/secure-string-cipher:latest

# Or with Docker Compose
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
docker compose up -d
docker compose exec cipher ssc start
```

To encrypt files in your current directory:

```bash
docker run --rm -it \
  -v "$PWD:/data" \
  ghcr.io/theredtower/secure-string-cipher:latest
```

With persistent vault and backups:

```bash
docker run --rm -it \
  -v "$PWD/data:/data" \
  -v "$PWD/vault:/vault" \
  -v "$PWD/backups:/backups" \
  ghcr.io/theredtower/secure-string-cipher:latest
```

**Image details:** ~65MB Alpine-based, runs as non-root (UID 1000), network-isolated.

## Programmatic API

Use secure-string-cipher as a library in your Python projects:

### Text Encryption

```python
from secure_string_cipher import encrypt_text, decrypt_text

# Encrypt a message
ciphertext = encrypt_text("Secret message", "MySecurePass123!")
print(ciphertext)  # Base64-encoded string

# Decrypt it back
plaintext = decrypt_text(ciphertext, "MySecurePass123!")
print(plaintext)  # "Secret message"
```

### File Encryption

```python
from secure_string_cipher import encrypt_file, decrypt_file

# Encrypt a file (explicit output path)
encrypt_file("document.pdf", "document.pdf.enc", "MySecurePass123!")

# Decrypt it (explicit output path)
decrypt_file("document.pdf.enc", "document.pdf", "MySecurePass123!")
```

> File operations refuse symlinked inputs/outputs (except system-managed paths like /var) to prevent path hijacking.

### Passphrase Generation

```python
from secure_string_cipher import generate_passphrase

# Generate a 24-character passphrase (155+ bits entropy)
passphrase = generate_passphrase(length=24)
print(passphrase)
```

### Vault Operations

```python
from secure_string_cipher import PassphraseVault

# Create or open vault
vault = PassphraseVault()

# Store a passphrase
vault.store_passphrase("my-server", "MySecurePass123!", master_password="VaultMaster456!")

# Retrieve it
password = vault.retrieve_passphrase("my-server", master_password="VaultMaster456!")

# List all labels (requires master password)
labels = vault.list_labels(master_password="VaultMaster456!")

# Update an entry
vault.update_passphrase("my-server", "NewPass789!", master_password="VaultMaster456!")

# Delete an entry
vault.delete_passphrase("my-server", master_password="VaultMaster456!")
```

### Security Utilities

```python
from secure_string_cipher import (
    check_password_strength,
    constant_time_compare,
    has_secure_memory,
)

# Validate password strength
is_strong, issues = check_password_strength("weak")
if not is_strong:
    print(f"Password issues: {issues}")

# Constant-time comparison (prevents timing attacks)
if constant_time_compare(user_input, stored_hash):
    print("Match!")

# Check if libsodium secure memory is available
if has_secure_memory():
    print("Using libsodium for secure memory zeroing")
```

## Security

| Component | Implementation | Details |
|-----------|---------------|---------|
| **Encryption** | AES-256-GCM | Authenticated encryption, 128-bit tags |
| **Key Derivation** | Argon2id | 64MB memory, 3 iterations, parallelism 4 |
| **Key Commitment** | HMAC-SHA256 | Prevents partitioning oracle attacks |
| **Vault Integrity** | HMAC-SHA256 | Detects tampering before decryption |
| **Memory Security** | libsodium | `sodium_memzero()` via PyNaCl |
| **Timing Safety** | Constant-time | All password/hash comparisons |
| **Rate Limiting** | Exponential backoff | Active on vault unlock, text decrypt, and file decrypt |
| **Vault Import** | SSCVAULT validation | Header, hex salt, and HMAC separators verified; `0o600` enforced |

**Additional protections:** Path traversal prevention, symlink attack detection, atomic writes, user-only file permissions (600), 12-character minimum password with complexity requirements.

**Password input:** When running interactively, passwords are hidden (using `getpass`). When stdin is piped or redirected (scripts, automation, tests), passwords are visible. This allows both secure interactive use and scriptable automation.

**Python memory limitations:** Even with libsodium, Python strings are immutable and GC may copy objects. Use `has_secure_memory()` to check libsodium availability.

## Development

```bash
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --extra dev --locked

# Run checks with the locked environment
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked mypy src tests
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=xml --cov-fail-under=69
```

See [DEVELOPER.md](DEVELOPER.md) for detailed development workflow and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.
