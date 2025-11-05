# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/secure-string-cipher.svg)](https://pypi.org/project/secure-string-cipher/)

Interactive AES-GCM Encrypt/Decrypt Tool

## Features

- 🔐 Encrypt or decrypt **text** or **files** using a passphrase
- 🛡️ **AES-256-GCM** with PBKDF2-HMAC-SHA256 key derivation (390,000 iterations)
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
  1. Encrypt text
  2. Decrypt text
  3. Encrypt file
  4. Decrypt file
  5. Exit

Select operation [1]:
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
