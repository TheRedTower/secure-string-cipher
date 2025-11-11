# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/downloads/)
[![Compatibility](https://img.shields.io/badge/Backward_Compatible-3.10+-green.svg)](https://www.python.org/downloads/)

A simple, secure AES-256-GCM encryption tool with an interactive menu interface.

**Developed for:** Python 3.14  
**Backward compatible to:** Python 3.10+

## Features

- Encrypt and decrypt text and files with AES-256-GCM
- **Inline passphrase generation** – Type `/gen` at any password prompt to instantly generate a strong passphrase
- Generate strong random passphrases with entropy calculation
- Store passphrases in an encrypted vault (optional)
  - HMAC-SHA256 integrity verification to detect tampering
  - Automatic backup creation (keeps last 5 backups)
  - Atomic writes to prevent corruption
- Stream large files in chunks for low memory usage
- Text output in Base64 for easy copy/paste
- Clipboard integration available

## Installation

> **Note**: This project is developed for **Python 3.14** (latest stable) and is backward compatible to Python 3.10+. We follow Python's official support policy and may drop support for older versions as they reach end-of-life.

```bash
# Recommended: install with pipx
pipx install secure-string-cipher

# Or with pip
pip install secure-string-cipher

# Or from source
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install .
```

## Usage

Run the interactive CLI:

```bash
cipher-start
```

You'll see this menu:

```
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

```
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

This feature:
- Generates alphanumeric passphrases with symbols (155+ bits entropy)
- Optionally stores the passphrase in your encrypted vault
- Skips confirmation since you already saw the generated password
- Works seamlessly without leaving the encryption flow

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
docker compose exec cipher cipher-start
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

**Image details:** ~65MB Alpine-based image, Python 3.14, runs as non-root user (UID 1000), network-isolated, includes HMAC integrity verification and automatic backups (last 5 kept).

## Security

- **Encryption:** AES-256-GCM with authenticated encryption
- **Key derivation:** PBKDF2-HMAC-SHA256 (390,000 iterations)
- **Passphrase vault:** Encrypted with AES-256-GCM using your master password
- **Vault integrity:** HMAC-SHA256 verification detects file tampering
- **Automatic backups:** Last 5 vault backups saved in `~/.secure-cipher/backups/`
- **File permissions:** Vault files are user-only (chmod 600)
- **Password requirements:** Minimum 12 characters with complexity checks

## Development

### Quick Start

```bash
# Clone and install with dev dependencies
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install -e ".[dev]"

# Format code before committing
make format

# Run the full test suite
make ci
```

### Available Commands

```bash
make format      # Auto-format code with Ruff
make lint        # Check formatting, types, and code quality
make test        # Run test suite
make test-cov    # Run tests with coverage report
make clean       # Remove temporary files
make ci          # Run complete CI pipeline locally
```

### Tools

- **Ruff** – Fast linter and formatter (replaces Black, isort, flake8)
- **mypy** – Static type checking
- **pytest** – Testing framework with 150+ tests

Run `make format` before pushing, then `make ci` to verify everything passes.

## License

MIT License. See [LICENSE](LICENSE) for details.
