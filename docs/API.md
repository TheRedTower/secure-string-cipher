# API Reference

Complete API documentation for the current Beta API. The Beta is not a stable
or audited release contract.

## Table of Contents

- [Core Encryption](#core-encryption)
  - [encrypt_text](#encrypt_text)
  - [decrypt_text](#decrypt_text)
  - [encrypt_file](#encrypt_file)
  - [decrypt_file](#decrypt_file)
- [Key Derivation](#key-derivation)
  - [derive_key](#derive_key)
  - [compute_key_commitment / verify_key_commitment](#compute_key_commitment--verify_key_commitment)
  - [derive_key_from_key_file](#derive_key_from_key_file)
  - [generate_key_pair](#generate_key_pair)
- [Passphrase Generation](#passphrase-generation)
  - [generate_passphrase](#generate_passphrase)
- [Passphrase Vault](#passphrase-vault)
  - [PassphraseVault](#passphrasevault)
- [Keychain Backend](#keychain-backend)
  - [KeychainVaultBackend](#keychainvaultbackend)
  - [is_keychain_available](#is_keychain_available)
  - [KeychainError / KeychainUnavailableError](#keychainerror--keychainunavailableerror)
- [Security Utilities](#security-utilities)
  - [check_password_strength](#check_password_strength)
  - [constant_time_compare](#constant_time_compare)
  - [add_timing_jitter](#add_timing_jitter)
- [Secure Memory](#secure-memory)
  - [SecureString / SecureBytes](#securestring--securebytes)
  - [has_secure_memory](#has_secure_memory)
  - [secure_wipe](#secure_wipe)
- [Rate Limiting](#rate-limiting)
  - [RateLimiter](#ratelimiter)
  - [rate_limited](#rate_limited)
- [Audit Logging](#audit-logging)
  - [AuditLogger](#auditlogger)
  - [Convenience Functions](#convenience-functions)
- [Exceptions](#exceptions)
  - [CryptoError](#cryptoerror)
  - [SecurityError](#securityerror)
  - [RateLimitError](#ratelimiterror)
- [Utility Functions](#utility-functions)
  - [colorize](#colorize)
  - [ProgressBar](#progressbar)
  - [secure_overwrite](#secure_overwrite)
- [Configuration Constants](#configuration-constants)

## Core Encryption

File APIs accept whole regular files as opaque bytes. `MAX_FILE_SIZE` is an
inclusive 100 MiB plaintext-payload limit; SSC magic, metadata, salt, nonce, and
tag framing may make an encrypted container larger. Directories and other
special files are rejected. Active/candidate vault representations and legacy
key files separately use the same numeric value as a raw-input cap. Vault text
is measured by strict UTF-8 bytes before storage, so the writer cannot publish a
value that the bounded reader would reject solely for size.

Text and byte-token readers require canonical ASCII Base64: the alphabet and
padding must be strict, and decoding then re-encoding must reproduce the exact
input text.

### encrypt_text

Encrypt a plaintext string using AES-256-GCM.

```python
from secure_string_cipher import encrypt_text

ciphertext = encrypt_text(plaintext: str, passphrase: str) -> str
```

**Parameters:**

- `plaintext` (str): The text to encrypt
- `passphrase` (str): Password for key derivation (min 12 characters recommended)

**Returns:** Base64-encoded ciphertext string containing salt, nonce, tag, and encrypted data.

**Raises:** `CryptoError` if encryption fails.

**Example:**

```python
from secure_string_cipher import encrypt_text

message = "Secret message"
ciphertext = encrypt_text(message, "MySecurePass123!")
print(ciphertext)  # Base64 string like "gAAAAABh..."
```

---

### decrypt_text

Decrypt a ciphertext string encrypted with `encrypt_text`.

```python
from secure_string_cipher import decrypt_text

plaintext = decrypt_text(ciphertext: str, passphrase: str) -> str
```

**Parameters:**

- `ciphertext` (str): Base64-encoded ciphertext from `encrypt_text`
- `passphrase` (str): Same password used for encryption

**Returns:** Original plaintext string.

**Raises:** `CryptoError` if decryption fails (wrong password, corrupted data, or tampering).

**Example:**

```python
from secure_string_cipher import decrypt_text

plaintext = decrypt_text(ciphertext, "MySecurePass123!")
print(plaintext)  # "Secret message"
```

---

### encrypt_file

Encrypt a file using AES-256-GCM with chunked streaming.

```python
from secure_string_cipher import encrypt_file

encrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str,
    *,
    store_filename: bool = True,
    overwrite: bool = False,
) -> None
```

**Parameters:**

- `input_path` (str): Path to the file to encrypt
- `output_path` (str): Destination path for the encrypted file (must be provided)
- `passphrase` (str): Password for key derivation
- `store_filename` (bool, keyword-only): Whether to embed the original basename
  in metadata (default: True)
- `overwrite` (bool, keyword-only): Permit final atomic replacement after
  encryption, flush, and sync succeed (default: False)

**Returns:** None (writes the encrypted file to `output_path`).

**Raises:** `CryptoError` for encryption, file, size, and path-validation
failures.

**Security/IO notes:**

- `_ensure_no_symlink` rejects symlinked inputs/outputs unless in the allowlist (e.g., `/var`).
- Existing outputs are preserved unless `overwrite=True`.
- The opened input descriptor must identify a regular file. Its snapshot size
  is checked before key derivation, and a cumulative counter catches subsequent
  growth beyond the plaintext limit.
- Ciphertext is streamed to a same-directory temporary file and published only
  after GCM finalization, flush, and sync complete.
- This protects against ordinary operation failures. Lexical path checks and a
  later descriptor inspection do not make opening race-free against a hostile
  concurrent path replacement.

**Example:**

```python
from secure_string_cipher import encrypt_file

encrypt_file(
    input_path="document.pdf",
    output_path="document.pdf.enc",
    passphrase="MySecurePass123!",
    store_filename=True,
)
print("Encrypted to document.pdf.enc")
```

---

### decrypt_file

Decrypt a file encrypted with `encrypt_file`.

```python
from secure_string_cipher import decrypt_file

output_path, metadata = decrypt_file(
    input_path: str,
    output_path: str | None,
    passphrase: str,
    *,
    restore_filename: bool = True,
    overwrite: bool = False,
) -> tuple[str, FileMetadata | None]
```

**Parameters:**

- `input_path` (str): Path to the encrypted file
- `output_path` (str | None): Explicit destination, or None for automatic
  selection. Version 5 may restore its authenticated, sanitized filename.
  Version 4 always uses a deterministic `.dec` fallback because its metadata is
  not authenticated.
- `passphrase` (str): Same password used for encryption
- `restore_filename` (bool, keyword-only): Whether version 5 may use its stored
  filename when `output_path` is None (default: True)
- `overwrite` (bool, keyword-only): Permit atomic replacement only after GCM
  authentication succeeds (default: False)

**Returns:** Tuple of `(output_path, metadata)` where `metadata` is a `FileMetadata` instance containing `original_filename` (if stored) and base64-encoded `key_commitment`.

**Raises:** `CryptoError` for decryption, authentication, file, and
path-validation failures. Wrong credentials and damaged ciphertext share the
CLI's generic authentication-failure behavior.

**Security/IO notes:**

- `_ensure_no_symlink` rejects symlinked inputs/outputs unless in the allowlist (e.g., `/var`).
- Decryption derives the plaintext length from the actual parsed header and
  metadata length, so framing overhead is not counted against `MAX_FILE_SIZE`.
  Descriptor and cumulative checks run before any over-limit plaintext is
  published, including both passes used for automatic output selection.
- No final plaintext path is published before authentication succeeds.
- Existing outputs are preserved for wrong passwords, damaged ciphertext, and
  ordinary write/publication failures.

**Example:**

```python
from secure_string_cipher import decrypt_file

output_path, metadata = decrypt_file(
    input_path="document.pdf.enc",
    output_path=None,  # restore stored filename when present
    passphrase="MySecurePass123!",
    restore_filename=True,
)
print(output_path)  # e.g., "document.pdf" or "document.pdf.dec"
print(metadata.original_filename)  # "document.pdf" when stored
print(metadata.key_commitment)     # base64 string
```

`FileMetadata` contains exactly these serialized fields when present:
`version`, `original_filename`, and `key_commitment`. `original_filename` is a
bounded metadata string, not a filesystem path. The current writer emits
version 5 and authenticates the original metadata bytes as AES-GCM additional
authenticated data; only after authentication may an automatic destination use
a sanitized name. Legacy version 4 metadata is readable but unauthenticated, so
its stored name is ignored for destination selection. Explicit output paths are
authoritative for both versions.

---

## Key Derivation

### derive_key

Derive a cryptographic key from a passphrase using Argon2id.

```python
from secure_string_cipher import derive_key

key = derive_key(passphrase: str, salt: bytes) -> bytes
```

**Parameters:**

- `passphrase` (str): Password to derive key from
- `salt` (bytes): 16-byte salt for key derivation

**Returns:** 32-byte key suitable for AES-256

**Example:**

```python
from secure_string_cipher import derive_key
import os

# Generate new key with random salt
salt = os.urandom(16)
key = derive_key("MySecurePass123!", salt)

# Re-derive same key with stored salt
key2 = derive_key("MySecurePass123!", salt)
assert key == key2
```

---

### compute_key_commitment / verify_key_commitment

Compute and verify HMAC-SHA256 key commitment to prevent partitioning oracle attacks.

```python
from secure_string_cipher import compute_key_commitment, verify_key_commitment

commitment = compute_key_commitment(key: bytes, salt: bytes) -> bytes
is_valid = verify_key_commitment(key: bytes, salt: bytes, commitment: bytes) -> bool
```

**Example:**

```python
from secure_string_cipher import derive_key, compute_key_commitment, verify_key_commitment

key, salt = derive_key("password")
commitment = compute_key_commitment(key, salt)

# Later: verify the key matches
assert verify_key_commitment(key, salt, commitment)
```

---

### derive_key_from_key_file

Derive a cryptographic key from a key file using Argon2id.

This legacy mode accepts any regular file. Its bytes are hashed with SHA-256 and
the digest is used as a symmetric passphrase for Argon2id. It is not RSA,
public-key, or recipient encryption: anyone with identical file bytes can
decrypt. Treat it as legacy pending secret `.ssckey` files.

```python
from secure_string_cipher import derive_key_from_key_file

key = derive_key_from_key_file(key_file_path: str | Path, salt: bytes) -> bytes
```

**Parameters:**

- `key_file_path` (str | Path): Path to the key file
- `salt` (bytes): 16-byte salt for key derivation

**Returns:** 32-byte key suitable for AES-256

**Raises:** `CryptoError` if key file cannot be read or is empty

**Security:** The key file is validated - must exist, be a regular file (not a symlink), and be non-empty.

**Example:**

```python
from secure_string_cipher import derive_key_from_key_file
import os

# Derive key from an SSH private key
salt = os.urandom(16)
key = derive_key_from_key_file("/home/user/.ssh/id_rsa", salt)

# Re-derive same key with stored salt
key2 = derive_key_from_key_file("/home/user/.ssh/id_rsa", salt)
assert key == key2
```

---

### generate_key_pair

Generate an RSA key pair. The current encrypt/decrypt APIs do not consume this
pair and do not implement recipient encryption.

```python
from secure_string_cipher import generate_key_pair

generate_key_pair(
    private_key_path: str | Path,
    public_key_path: str | Path | None = None
) -> None
```

**Parameters:**

- `private_key_path` (str | Path): Path where private key will be saved (PEM format)
- `public_key_path` (str | Path, optional): Path where public key will be saved. Defaults to `private_key_path + ".pub"`

**Returns:** None (writes key files to disk)

**Raises:** `CryptoError` if key generation or file operations fail

**Security:** Private key is saved with `0o600` permissions (owner read/write only). Public key is saved with `0o644` permissions.

**Example:**

```python
from secure_string_cipher import generate_key_pair

# Generate RSA key pair
generate_key_pair("/path/to/private_key.pem", "/path/to/public_key.pem")
# Private key: /path/to/private_key.pem (chmod 600)
# Public key:  /path/to/public_key.pem  (chmod 644)

# Or let it auto-generate the public key filename
generate_key_pair("/path/to/private_key.pem")
# Public key will be saved to: /path/to/private_key.pem.pub
```

**Note:** This function requires the `cryptography` library for RSA key generation.

## Passphrase Generation

### generate_passphrase

Generate a cryptographically secure random passphrase.

```python
from secure_string_cipher import generate_passphrase

passphrase = generate_passphrase(
    length: int = 24,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True
) -> str
```

**Parameters:**

- `length` (int): Length of passphrase (default: 24)
- `use_uppercase` (bool): Include A-Z (default: True)
- `use_lowercase` (bool): Include a-z (default: True)
- `use_digits` (bool): Include 0-9 (default: True)
- `use_special` (bool): Include special characters (default: True)

**Returns:** Random passphrase string.

**Example:**

```python
from secure_string_cipher import generate_passphrase

# Default: 24-char with all character types (~155 bits entropy)
passphrase = generate_passphrase()
print(passphrase)  # "8w@!-@_#M)wF,Qn(ms.Uv+3z"

# Alphanumeric only
passphrase = generate_passphrase(length=32, use_special=False)
```

---

## Passphrase Vault

### PassphraseVault

Encrypted storage for passphrases with HMAC integrity verification.

```python
from secure_string_cipher import PassphraseVault

vault = PassphraseVault(
    vault_path: str | None = None,
    backend: str | None = None,
)
```

**Parameters:**

- `vault_path` (str, optional): Custom path for vault file. Default: `~/.secure-cipher/passphrase_vault.enc`
- `backend` (str, optional): `"file"`, `"keychain"`, or `None` to use the
  persisted/environment/default backend selection. A usable keychain is the
  default when no explicit selection exists; otherwise the file backend is used.

#### Methods

##### store_passphrase

Store a passphrase with a label.

```python
vault.store_passphrase(label: str, passphrase: str, master_password: str) -> None
```

##### retrieve_passphrase

Retrieve a stored passphrase.

```python
passphrase = vault.retrieve_passphrase(label: str, master_password: str) -> str
```

**Raises:** `ValueError` if label not found or vault cannot be decrypted.

##### list_labels

List all stored passphrase labels (requires master password to decrypt the vault).

```python
labels = vault.list_labels(master_password: str) -> list[str]
```

##### delete_passphrase

Delete a passphrase entry.

```python
vault.delete_passphrase(label: str, master_password: str) -> None
```

##### update_passphrase

Update an existing passphrase.

```python
vault.update_passphrase(label: str, new_passphrase: str, master_password: str) -> None
```

##### import_raw_vault

Validate and transactionally replace the configured active vault.

```python
backup_identifier = vault.import_raw_vault(
    vault_contents: str | bytes,
    master_password: str,
    *,
    backup_current: bool = True,
) -> str | None
```

Validation (strict six-line framing, HMAC, authenticated decryption, and JSON
schema) completes before active-backend mutation. When an active vault exists,
the default creates an exact encrypted backup first. Publication is read back,
byte-compared, and revalidated. A post-write failure attempts to restore the
prior raw value and raises a generic transaction error reporting whether
rollback succeeded. The returned value is the stable identifier of the
pre-replacement backup, or `None` if none was created.

Filesystem publication uses atomic replacement. Native credential stores do
not expose a multi-record atomic transaction, so rollback for those backends is
best effort. No cross-process lock is implemented.

This API remains byte-exact and does not normalize line endings or surrounding
whitespace. The `ssc vault import` CLI alone accepts exactly one legacy terminal
LF or CRLF, removes it after a bounded raw-byte read, and passes canonical
six-line bytes into this API. Other whitespace and internal CRLF framing remain
invalid.

File-backed active vault reads, backups, migrations, and transaction
read-back/rollback checks use the same opened-descriptor `limit + 1` reader.
Keychain text is incrementally counted by strict UTF-8 bytes before validation,
backup, or publication.

##### list_backup_records / validate_backup / restore_from_backup

```python
records = vault.list_backup_records() -> list[VaultBackup]
vault.validate_backup(backup_identifier: str, master_password: str) -> None
previous_identifier = vault.restore_from_backup(
    backup_identifier: str,
    master_password: str,
) -> str | None
```

`VaultBackup` records expose `identifier`, `created_at`, and `path`. The retained
`created_at` name is a compatibility field containing an mtime-derived UTC
ordering timestamp, not filesystem creation time. Restore requires the exact
identifier, validates the selected record before mutation, uses the same
transaction as import, and never automatically removes the selected restore
source. Five backups are retained; collision-resistant names combine a UTC
microsecond timestamp with a random suffix.

**Example:**

```python
from secure_string_cipher import PassphraseVault

vault = PassphraseVault()

# Store
vault.store_passphrase(
    "production-db", "super-secret-123", master_password="VaultMaster!"  # pragma: allowlist secret
)  # pragma: allowlist secret

# List
print(vault.list_labels(master_password="VaultMaster!"))  # ["production-db"]  # pragma: allowlist secret

# Retrieve
password = vault.retrieve_passphrase(
    "production-db", master_password="VaultMaster!"  # pragma: allowlist secret
)  # pragma: allowlist secret

# Update
vault.update_passphrase(
    "production-db", "even-better-456", master_password="VaultMaster!"  # pragma: allowlist secret
)  # pragma: allowlist secret

# Delete
vault.delete_passphrase("production-db", master_password="VaultMaster!")  # pragma: allowlist secret
```

---

## Keychain Backend

### KeychainVaultBackend

Store vault data in the OS keychain instead of a file.

```python
from secure_string_cipher import KeychainVaultBackend, is_keychain_available

# Check availability
if is_keychain_available():
    backend = KeychainVaultBackend()
    backend.store_vault(vault_contents)
    data = backend.load_vault()
    backend.delete_vault()
```

**Methods:**

| Method | Description |
| ------ | ----------- |
| `store_vault(contents: str)` | Store encrypted vault blob in keychain |
| `load_vault() -> str \| None` | Load vault from keychain (None if not found) |
| `delete_vault()` | Remove vault from keychain |
| `vault_exists() -> bool` | Check if vault exists in keychain |

### is_keychain_available

Check if a usable OS keychain backend is available.

```python
from secure_string_cipher import is_keychain_available

available = is_keychain_available()  # True/False
```

### KeychainError / KeychainUnavailableError

```python
from secure_string_cipher import KeychainError, KeychainUnavailableError

# KeychainError: Base exception for keychain operations
# KeychainUnavailableError: Raised when keyring is not installed or has no backend
```

### PassphraseVault with Keychain

```python
from secure_string_cipher import PassphraseVault, BACKEND_KEYCHAIN, BACKEND_FILE

# Use keychain backend
vault = PassphraseVault(backend=BACKEND_KEYCHAIN)

# Use file backend (default)
vault = PassphraseVault(backend=BACKEND_FILE)

# Migrate between backends
vault.migrate_to_keychain(master_password)
vault.migrate_to_file(master_password)
```

---

## Security Utilities

### check_password_strength

Validate password meets security requirements.

```python
from secure_string_cipher import check_password_strength

is_strong, message = check_password_strength(password: str) -> tuple[bool, str]
```

**Parameters:**

- `password` (str): Password to validate

**Returns:** Tuple of (is_strong: bool, message: str with details)

**Requirements:**

- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

**Example:**

```python
from secure_string_cipher import check_password_strength

is_strong, message = check_password_strength("weak")
if not is_strong:
    print(f"Password problems: {message}")
    # "Too short (minimum 12 characters), missing uppercase, ..."

is_strong, message = check_password_strength("MySecurePass123!")
print(is_strong)  # True
```

---

### constant_time_compare

Compare two byte strings in constant time to prevent timing attacks.

```python
from secure_string_cipher import constant_time_compare

is_equal = constant_time_compare(a: bytes, b: bytes) -> bool
```

**Example:**

```python
from secure_string_cipher import constant_time_compare

# Use this instead of == for security-sensitive comparisons
if constant_time_compare(user_hash, stored_hash):
    print("Authenticated")
```

---

### add_timing_jitter

Add random delay to prevent timing analysis.

```python
from secure_string_cipher import add_timing_jitter

add_timing_jitter() -> None
```

Adds between 0-10ms of random delay.

**Example:**

```python
from secure_string_cipher import add_timing_jitter

# Add random 0-10ms delay
add_timing_jitter()
```

---

## Secure Memory

### SecureString / SecureBytes

Wrappers that automatically zero memory on deletion.

```python
from secure_string_cipher import SecureString, SecureBytes

secure_str = SecureString(value: str)
secure_bytes = SecureBytes(value: bytes)
```

**Methods:**

- `get()`: Retrieve the value
- `clear()`: Explicitly zero and clear the value. Idempotent — safe to call multiple times or concurrently (e.g., from both `__exit__` and `__del__`).

**Example:**

```python
from secure_string_cipher import SecureString, SecureBytes

# Secure password handling
password = SecureString("MySecretPassword")
use_password(password.get())
password.clear()  # Or let it auto-clear on deletion

# Secure key handling
key = SecureBytes(b"\x00" * 32)
```

---

### has_secure_memory

Check if libsodium secure memory is available.

```python
from secure_string_cipher import has_secure_memory

available = has_secure_memory() -> bool
```

**Example:**

```python
from secure_string_cipher import has_secure_memory

if has_secure_memory():
    print("Using libsodium for secure memory wiping")
else:
    print("Falling back to Python-based memory clearing")
```

---

### secure_wipe

Securely wipe a bytearray in memory.

```python
from secure_string_cipher import secure_wipe

secure_wipe(data: bytearray) -> None
```

**Example:**

```python
from secure_string_cipher import secure_wipe

sensitive_data = bytearray(b"secret")
# ... use data ...
secure_wipe(sensitive_data)  # Zeros the memory
```

---

## Rate Limiting

### RateLimiter

Prevent brute-force attacks with rate limiting.

```python
from secure_string_cipher import rate_limited, RateLimitError


@rate_limited("vault_unlock", get_identifier=lambda vault_path, **_: vault_path)
def unlock_vault(vault_path: str, password: str) -> None:
    ...

try:
    unlock_vault("/home/user/.secure-cipher/passphrase_vault.enc", "secret")
except RateLimitError as exc:
    print(f"Too many attempts. Wait {exc.wait_seconds:.1f}s")
```

> **Note:** The rate limiter is a local CLI throttle on vault unlock
> (`ssc vault`), text decryption (`ssc decrypt -t`), and file decryption
> (`ssc decrypt -f`). Repeated failures trigger exponential backoff, but an
> attacker holding ciphertext can perform offline guesses without this limiter.

**Methods:**

- `check(key: str)`: Check if action is allowed
- `record_attempt(key: str)`: Record an attempt
- `record_failure(key: str)`: Record a failed attempt
- `is_locked_out(key: str)`: Check if key is locked out

**Example:**

```python
from secure_string_cipher import RateLimiter, RateLimitError

limiter = RateLimiter(max_attempts=3, window_seconds=60)

try:
    limiter.check("user@example.com")
    # Attempt authentication
    limiter.record_attempt("user@example.com")
except RateLimitError:
    print("Too many attempts, please wait")
```

---

### rate_limited

Decorator for rate-limiting function calls.

```python
from secure_string_cipher import rate_limited

@rate_limited(max_attempts=5, window_seconds=60)
def login(username, password):
    ...
```

---

## Audit Logging

### AuditLogger

Log security events as editable local JSON. Rotation and redaction are provided,
but the log has no cryptographic chain or external append-only storage and is
not tamper-evident.

```python
from secure_string_cipher import AuditLogger, AuditEvent, AuditLevel

logger = AuditLogger(log_path: str | None = None, level: AuditLevel = AuditLevel.STANDARD)
```

**Methods:**

- `log(event: AuditEvent, success: bool = True, details: dict | None = None)`: Log an event with redaction of sensitive keys
- `log_auth_failure(operation: str, reason: str = "invalid_credentials", identifier: str | None = None)`: Convenience for auth failures
- `log_rate_limit(operation: str, wait_seconds: float, identifier: str | None = None)`: Convenience for rate-limit triggers
- `log_encryption(event_type: AuditEvent, success: bool, file_path: str | None = None, error: str | None = None)`: Convenience for encrypt/decrypt
- `log_vault_operation(event_type: AuditEvent, success: bool, vault_path: str | None = None, label: str | None = None, error: str | None = None)`: Convenience for vault CRUD

**Example:**

```python
from secure_string_cipher import AuditEvent, get_audit_logger

logger = get_audit_logger()
logger.log(AuditEvent.ENCRYPT_FILE, success=True, details={"file": "document.pdf"})
```

---

### Convenience Functions

```python
from secure_string_cipher import (
    AuditEvent,
    audit_auth_failure,
    audit_event,
    audit_rate_limit,
)

# Log general event
audit_event(AuditEvent.DECRYPT_FILE, success=True, filename="secret.txt")

# Log authentication failure
audit_auth_failure("vault_unlock", reason="invalid_password", identifier="~/.secure-cipher/passphrase_vault.enc")

# Log rate limit triggered
audit_rate_limit("decrypt_file", wait_seconds=30.0, identifier="secret.enc")
```

---

## Exceptions

### CryptoError

Raised for cryptographic operation failures.

```python
from secure_string_cipher import CryptoError

try:
    decrypt_text(ciphertext, "wrong_password")
except CryptoError as e:
    print(f"Decryption failed: {e}")
```

### SecurityError

Raised for security violations (path traversal, symlink attacks, etc.).

```python
from secure_string_cipher import SecurityError

try:
    encrypt_file("../../../etc/passwd", "password")
except SecurityError as e:
    print(f"Security violation: {e}")
```

### RateLimitError

Raised when rate limit exceeded.

```python
from secure_string_cipher import RateLimitError

try:
    limiter.check("user")
except RateLimitError as e:
    print(f"Rate limited: {e}")
```

---

## Utility Functions

### colorize

Add terminal colors to output.

```python
from secure_string_cipher import colorize

text = colorize(text: str, color: str) -> str
```

**Colors:** `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `bold`

**Example:**

```python
from secure_string_cipher import colorize

print(colorize("Success!", "green"))
print(colorize("Warning!", "yellow"))
print(colorize("Error!", "red"))
```

---

### ProgressBar

Display progress for long operations.

```python
from secure_string_cipher import ProgressBar

progress = ProgressBar(total: int, description: str = "Processing")
progress.update(amount: int = 1)
progress.finish()
```

**Example:**

```python
from secure_string_cipher import ProgressBar

progress = ProgressBar(100, "Encrypting")
for i in range(100):
    # do work
    progress.update()
progress.finish()
```

---

### secure_overwrite

Best-effort delete a file by overwriting it with zero bytes and unlinking it.
This cannot guarantee erasure on SSDs, copy-on-write filesystems, snapshots,
backups, or journaled filesystems.

```python
from secure_string_cipher import secure_overwrite

secure_overwrite(filepath: str) -> None
```

**Example:**

```python
from secure_string_cipher import secure_overwrite

# Best-effort overwrite and unlink
secure_overwrite("plaintext_backup.txt")
```

---

## Configuration Constants

Key parameters defined in `secure_string_cipher.config`:

| Constant | Value | Description |
| -------- | ----- | ----------- |
| `CHUNK_SIZE` | 262144 | File streaming chunk size (256 KiB) |
| `ARGON2_MEMORY` | 65536 | Argon2id memory cost (64MB) |
| `ARGON2_ITERATIONS` | 3 | Argon2id time cost |
| `ARGON2_PARALLELISM` | 4 | Argon2id parallelism |
| `MAX_FILE_SIZE` | 104857600 | Maximum plaintext payload (100 MiB); also the separate raw vault/key-file ingestion cap |
| `MIN_PASSWORD_LENGTH` | 12 | Minimum password length |
| `SALT_SIZE` | 16 | Salt size in bytes |
| `KEY_SIZE` | 32 | AES-256 key size |
| `NONCE_SIZE` | 12 | GCM nonce size |
| `TAG_SIZE` | 16 | GCM authentication tag size |
