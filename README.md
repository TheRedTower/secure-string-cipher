# secure-string-cipher

[![CI](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheRedTower/secure-string-cipher/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)](https://github.com/TheRedTower/secure-string-cipher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)

A **Beta** AES-256-GCM encryption CLI with a passphrase vault and modern
cryptographic defaults. Beta means the current v4/v5 format is usable and
compatibility-sensitive, but the project is not yet stable or independently
audited.

## Beta Scope

- Regular files are treated as opaque bytes, so any internal file format is
  supported up to the 100 MiB input limit. Directories are not supported.
- The current writer emits metadata version 5. Legacy version 4 files remain
  decryptable, but their unauthenticated stored filenames are never trusted for
  automatic output selection.
- Large framed SSC2 objects, transactional vault import/restore authentication,
  descriptor-level path hardening, secret `.ssckey` files, compatibility
  fixtures, and cross-platform release CI remain future work.

## Features

- **AES-256-GCM encryption** for text and files with authenticated encryption
- **Argon2id key derivation** – memory-hard, GPU/ASIC resistant
- **Key commitment scheme** – prevents partitioning oracle attacks
- **Legacy key-file mode** – hashes any file's bytes into a symmetric passphrase
  (SHA-256 → Argon2id); this is not public-key or recipient encryption
- **OS Keychain integration** – store vault in macOS Keychain, Windows Credential Vault, or Linux Secret Service
- **Hidden password input** – passwords hidden in interactive terminals, visible for scripts/tests
- **Inline passphrase generation** – type `/gen` at any password prompt
- **Encrypted passphrase vault** with HMAC-SHA256 integrity verification
- **Best-effort memory clearing** via mutable buffers and libsodium when available
- **Timing-safe operations** – constant-time comparisons prevent side-channel attacks
- **Local CLI rate limiting** – exponential backoff on failed decrypt/vault attempts;
  it cannot prevent offline password guessing
- **Best-effort shred** – overwrite then unlink; unreliable on SSDs, COW,
  snapshots, and journaled filesystems
- Chunked file streaming (256 KiB) for low memory usage
- Automatic vault backups (last 5 kept)

## Documentation

- [API Reference](docs/API.md) — Complete programmatic API documentation
- [Keychain Backend](docs/KEYCHAIN.md) — OS keychain integration guide
- [Developer Guide](DEVELOPER.md) — Development workflow and tooling
- [Contributing](CONTRIBUTING.md) — Contribution guidelines
- [Security Policy](.github/SECURITY.md) — Supported versions and vulnerability reporting
- [Cryptographic Design](.github/CRYPTOGRAPHY.md) — Design document for security auditors
- [Dependency Audit](AUDITS/DEPENDENCY_AUDIT.md) — Supply-chain security audit report
- [Changelog](CHANGELOG.md) — Release history

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

# Encrypt using a key file
ssc encrypt -f document.pdf --key-file /path/to/key.pem

# Decrypt a file (restores original filename by default)
ssc decrypt -f document.pdf.enc

# Decrypt with an explicit output path
ssc decrypt -f document.pdf.enc --output document.pdf

# Decrypt without restoring the stored filename
ssc decrypt -f document.pdf.enc --no-restore-filename

# Decrypt using a vault password
ssc decrypt -f document.pdf.enc --vault my-server

# Decrypt using a key file
ssc decrypt -f document.pdf.enc --key-file /path/to/key.pem

# Store a password in vault
ssc store my-server

# Auto-generate and store a password
ssc store backup-key --generate

# Vault management
ssc vault list
ssc vault delete old-key
ssc vault export backup.json
ssc vault import backup.json  # structural validation only; see limitations below
```

**Exit codes:** 0=success, 1=input error, 2=auth error, 3=vault error, 4=file error

**Security:** Passwords are never passed via command line arguments (prevents shell history exposure). All passwords are prompted interactively or retrieved from the vault.

`--force` permits final atomic replacement only after encryption completes or
decryption authenticates. It never pre-deletes the existing destination.

### Interactive CLI (`ssc start`)

For interactive use, run:

```bash
ssc start
```

You'll see this menu:

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                       AVAILABLE OPERATIONS                       ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                  ┃
┃  TEXT & FILE ENCRYPTION                                          ┃
┃                                                                  ┃
┃    [1] Encrypt Text       ->  Encrypt a message (base64)         ┃
┃    [2] Decrypt Text       ->  Decrypt an encrypted message       ┃
┃    [3] Encrypt File       ->  Encrypt a file (creates .enc)      ┃
┃    [4] Decrypt File       ->  Decrypt an encrypted file          ┃
┃                                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  PASSPHRASE VAULT (Optional)                                     ┃
┃                                                                  ┃
┃    [5] Generate Passphrase  ->  Create random password           ┃
┃    [6] Store in Vault       ->  Save passphrase securely         ┃
┃    [7] Retrieve from Vault  ->  Get stored passphrase            ┃
┃    [8] List Vault Entries   ->  View all stored labels           ┃
┃    [9] Manage Vault         ->  Update, delete, export           ┃
┃                                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  SECURITY TOOLS                                                  ┃
┃                                                                  ┃
┃   [10] Secure Shred       ->  Permanently delete a file          ┃
┃   [11] Use Key File       ->  Encrypt/decrypt w/ key file        ┃
┃                                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃    [0] Exit                ->  Quit application                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
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

### OS Keychain Integration

Optionally store your vault in the OS keychain for added security:

```bash
# Existing pipx install: add keychain support to the pipx venv
pipx inject secure-string-cipher keyring

# New pipx install with keychain support
pipx install 'secure-string-cipher[keychain]'

# Or for a normal pip/venv install
python -m pip install 'secure-string-cipher[keychain]'

# Migrate existing vault to keychain
ssc vault migrate --to keychain

# Migrate back to file if needed
ssc vault migrate --to file
```

See [docs/KEYCHAIN.md](docs/KEYCHAIN.md) for full setup instructions per platform.

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

# Replace only after complete encryption and sync
encrypt_file("document.pdf", "document.pdf.enc", "MySecurePass123!", overwrite=True)

# Decrypt it (explicit output path)
output_path, metadata = decrypt_file(
    "document.pdf.enc",
    "document.pdf",
    "MySecurePass123!",
    overwrite=True,
)
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
| --------- | -------------- | ------- |
| **Encryption** | AES-256-GCM | Authenticated encryption, 128-bit tags |
| **Key Derivation** | Argon2id | 64MB memory, 3 iterations, parallelism 4 |
| **Key Commitment** | HMAC-SHA256 | Prevents partitioning oracle attacks |
| **Vault Integrity** | HMAC-SHA256 | Detects tampering before decryption |
| **Memory Clearing** | Best effort | Mutable buffers/libsodium where available; Python may retain copies |
| **Timing Safety** | Constant-time | All password/hash comparisons |
| **Rate Limiting** | Local exponential backoff | CLI throttle only; offline guessing remains possible |
| **Vault Import** | Structural SSCVAULT checks | Cryptographic validation before replacement is pending |

**Additional protections:** best-effort symlink preflight checks, atomic final
publication, user-only file permissions (`0o600`), and a 12-character password
policy. Atomic publication protects against ordinary operation failures;
hostile concurrent path races require descriptor-level hardening and are not
claimed to be prevented.

**Password input:** When running interactively, passwords are hidden (using `getpass`). When stdin is piped or redirected (scripts, automation, tests), passwords are visible. This allows both secure interactive use and scriptable automation.

**Python memory limitations:** Memory clearing is best-effort. Even with
libsodium, Python strings are immutable and the runtime may copy objects. Use
`has_secure_memory()` to check libsodium availability.

**Local records and deletion limitations:** The audit/event log is editable
local JSON and is not tamper-evident. Overwrite-based deletion cannot reliably
erase data from SSD wear levelling, copy-on-write storage, snapshots, backups,
or journaled filesystems.

**Legacy key-file limitation:** Anyone with identical key-file bytes can derive
the same symmetric passphrase and decrypt. PEM or public-key-shaped input does
not create RSA, recipient, or public-key encryption. Treat this mode as legacy
pending the secret `.ssckey` design.

## Development

```bash
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --extra dev --locked

# Run checks with the locked environment
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked mypy src
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=xml --cov-fail-under=85
```

See [DEVELOPER.md](DEVELOPER.md) for detailed development workflow and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.
