# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/secure-string-cipher.svg)](https://pypi.org/project/secure-string-cipher/)

Interactive AES-GCM Encrypt/Decrypt Tool

## Features

- Encrypt or decrypt **text** or **files** using a passphrase
- **AES-256-GCM** with PBKDF2-HMAC-SHA256 key derivation (390,000 iterations)
- Streams file encryption/decryption in 64 KiB chunks (low memory footprint)
- **Text mode** wraps ciphertext/tag in Base64 for easy copy/paste
- Optional clipboard copy via **pyperclip** in text mode
- **Colourised**, menu-driven interactive wizard

## Installation

### Via pipx (recommended)

```bash
pipx install string-cipher
```

This installs a globally available `string-cipher` command in an isolated environment.

### From source

```bash
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install .
```

## Usage

Run the interactive wizard:

```bash
string-cipher
```

Or use flags:

```bash
string-cipher --help
```

### Docker

Alternatively, run via Docker without installing anything locally:

```bash
# Build the image (once)
cd string-cipher
docker build -t yourusername/string-cipher .

# Run interactively
docker run --rm -it yourusername/string-cipher

# Encrypt a file (bind current directory)
docker run --rm -it -v "$PWD":/data yourusername/string-cipher encrypt-file /data/secret.txt
docker run --rm -it -v "$PWD":/data yourusername/string-cipher decrypt-file /data/secret.txt.enc
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
