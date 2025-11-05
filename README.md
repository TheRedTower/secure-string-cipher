# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

A simple, secure AES-256-GCM encryption tool with an interactive menu interface.

**Requirements:** Python 3.10+

## Features

- **Encrypt/Decrypt** text and files using AES-256-GCM
- **Passphrase Generator** with entropy calculation
- **Encrypted Vault** to store your passphrases
- Streams large files in chunks (low memory usage)
- Text mode outputs Base64 for easy copy/paste
- Optional clipboard integration

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

Just run:

```bash
cipher-start
```

You'll see a menu:

```
Available Operations:
  1. Encrypt text          - Encrypt a message (returns base64 string)
  2. Decrypt text          - Decrypt a base64 encrypted message
  3. Encrypt file          - Encrypt a file (creates .enc file)
  4. Decrypt file          - Decrypt an encrypted file
  5. Generate passphrase   - Create a secure random passphrase
  6. Exit                  - Quit the program
```

Pick an option and follow the prompts.

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

**Image specs:** 78MB, Alpine-based, runs as non-root, 0 critical/high/medium vulnerabilities.

## Security

- **Algorithm:** AES-256-GCM
- **Key derivation:** PBKDF2-HMAC-SHA256 (390,000 iterations)
- **Passphrase vault:** AES-256-GCM encrypted with master password
- **File permissions:** Vault restricted to user-only (600)

## License

MIT License. See [LICENSE](LICENSE) for details.
