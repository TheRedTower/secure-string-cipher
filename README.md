# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

Interactive AES-GCM Encrypt/Decrypt Tool

**Requirements:** Python 3.10 or higher (tested up to Python 3.14)

## Features

- 🔐 Encrypt or decrypt **text** or **files** using a passphrase
- 🛡️ **AES-256-GCM** with PBKDF2-HMAC-SHA256 key derivation (390,000 iterations)
- 🔑 **Passphrase Generator** - Create cryptographically secure passphrases
  - Word-based (e.g., `mountain-tiger-ocean-basket-rocket-palace`)
  - Alphanumeric with symbols (e.g., `xK9$mP2@qL5#vR8&nB3!`)
  - Mixed mode (words + numbers)
  - Shows entropy bits for security assessment
- 💾 **Encrypted Passphrase Vault** - Securely store passphrases with master password
  - Store, retrieve, and manage multiple passphrases
  - Vault encrypted with AES-256-GCM
  - Restricted file permissions for security
- ⚡ Streams file encryption/decryption in 64 KiB chunks (low memory footprint)
- 📋 **Text mode** wraps ciphertext/tag in Base64 for easy copy/paste
- 📎 Optional clipboard copy via **pyperclip** in text mode
- 🎨 **Colourised**, menu-driven interactive wizard with clear operation descriptions
- ✅ Test-friendly CLI with dependency injection support

## Installation

### Via pipx (recommended)

```bash
pipx install secure-string-cipher
```

This installs a globally available `cipher-start` command in an isolated environment.

### From source

```bash
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install .
```

## Usage

Run the interactive wizard:

```bash
cipher-start
```

The CLI will present you with a clear menu of operations:

```
Available Operations:
  1. Encrypt text          - Encrypt a message (returns base64 string)
  2. Decrypt text          - Decrypt a base64 encrypted message
  3. Encrypt file          - Encrypt a file (creates .enc file)
  4. Decrypt file          - Decrypt an encrypted file
  5. Generate passphrase   - Create a secure random passphrase
  6. Exit                  - Quit the program

Select operation [1-6]:
```

Or use flags:

```bash
cipher-start --help
```

### Programmatic use and test-friendly CLI

The CLI entry point is available as a Python function for tests and programmatic usage:

```
from io import StringIO
from secure_string_cipher.cli import main

# Provide input/output streams and disable exiting on completion
mock_in = StringIO("1\nHello, World!\nStrongP@ssw0rd!#\nStrongP@ssw0rd!#\n")
mock_out = StringIO()
main(in_stream=mock_in, out_stream=mock_out, exit_on_completion=False)
print(mock_out.getvalue())
```

- in_stream/out_stream: file-like objects used for input/output (default to sys.stdin/sys.stdout).
- exit_on_completion: when True (default), the CLI exits the process on success or error; when False, it returns 0 (success) or 1 (error).

This design makes the CLI deterministic and easy to unit test without relying on global stdout patches.

### Docker

Alternatively, run via Docker without installing anything locally:

```bash
# Build the image (once)
cd secure-string-cipher
docker build -t yourusername/secure-string-cipher .

# Run interactively
docker run --rm -it yourusername/secure-string-cipher

# Encrypt a file (bind current directory)
docker run --rm -it -v "$PWD":/data yourusername/secure-string-cipher encrypt-file /data/secret.txt
docker run --rm -it -v "$PWD":/data yourusername/secure-string-cipher decrypt-file /data/secret.txt.enc
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
