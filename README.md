# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

A simple, secure AES-256-GCM encryption tool with an interactive menu interface.

**Requirements:** Python 3.10+

## Features

- Encrypt and decrypt text and files with AES-256-GCM
- Generate strong random passphrases with entropy calculation
- Store passphrases in an encrypted vault (optional)
- Stream large files in chunks for low memory usage
- Text output in Base64 for easy copy/paste
- Clipboard integration available

## Installation

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
┃                    ⚡ AVAILABLE OPERATIONS ⚡                     ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                  ┃
┃  📝  TEXT & FILE ENCRYPTION                                      ┃
┃                                                                  ┃
┃    [1] Encrypt Text     →  Encrypt a message (base64 output)    ┃
┃    [2] Decrypt Text     →  Decrypt an encrypted message         ┃
┃    [3] Encrypt File     →  Encrypt a file (creates .enc)        ┃
┃    [4] Decrypt File     →  Decrypt an encrypted file            ┃
┃                                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  🔑  PASSPHRASE VAULT (Optional)                                ┃
┃                                                                  ┃
┃    [5] Generate Passphrase  →  Create secure random password    ┃
┃    [6] Store in Vault       →  Save passphrase securely         ┃
┃    [7] Retrieve from Vault  →  Get stored passphrase            ┃
┃    [8] List Vault Entries   →  View all stored labels           ┃
┃    [9] Manage Vault         →  Update or delete entries         ┃
┃                                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃    [0] Exit               →  Quit application                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Choose an option and follow the prompts.

## Docker

Use the pre-built image:

```bash
# Pull and run
docker pull ghcr.io/theredtower/secure-string-cipher:latest
docker run --rm -it ghcr.io/theredtower/secure-string-cipher:latest

# Or with docker-compose
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
docker-compose run --rm cipher
```

To encrypt files in your current directory:

```bash
docker run --rm -it \
  -v "$PWD:/data" \
  ghcr.io/theredtower/secure-string-cipher:latest
```

With persistent passphrase vault:

```bash
docker run --rm -it \
  -v "$PWD:/data" \
  -v cipher-vault:/home/cipheruser/.secure-cipher \
  ghcr.io/theredtower/secure-string-cipher:latest
```

**Image details:** 78MB Alpine-based image, runs as non-root user, no critical vulnerabilities.

## Security

- **Encryption:** AES-256-GCM with authenticated encryption
- **Key derivation:** PBKDF2-HMAC-SHA256 (390,000 iterations)
- **Passphrase vault:** Encrypted with AES-256-GCM using your master password
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
