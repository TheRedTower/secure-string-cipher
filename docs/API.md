# API Reference

Complete API documentation for secure-string-cipher.

## Core Encryption

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
    store_filename: bool = True,
) -> None
```

**Parameters:**

- `input_path` (str): Path to the file to encrypt
- `output_path` (str): Destination path for the encrypted file (must be provided)
- `passphrase` (str): Password for key derivation
- `store_filename` (bool): Whether to embed the sanitized original filename in metadata (default: True)

**Returns:** None (writes the encrypted file to `output_path`).

**Raises:**

- `CryptoError` if encryption fails
- `SecurityError` if path validation fails (traversal, symlink attacks)
- `FileNotFoundError` if file doesn't exist
- `ValueError` if file exceeds the configured size limit

**Security/IO notes:**

- `_ensure_no_symlink` rejects symlinked inputs/outputs unless in the allowlist (e.g., `/var`).
- `StreamProcessor` raises `CryptoError` if the output file already exists (no interactive prompt).

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
    output_path: str | None = None,
    passphrase: str,
    restore_filename: bool = True,
) -> tuple[str, FileMetadata | None]
```

**Parameters:**

- `input_path` (str): Path to the encrypted file
- `output_path` (str | None): Destination for the decrypted file. If None, the function restores the stored sanitized filename when available; otherwise uses `<input>.dec`.
- `passphrase` (str): Same password used for encryption
- `restore_filename` (bool): Whether to use the stored filename metadata when present (default: True)

**Returns:** Tuple of `(output_path, metadata)` where `metadata` is a `FileMetadata` instance containing `original_filename` (if stored) and base64-encoded `key_commitment`.

**Raises:**

- `CryptoError` if decryption fails
- `SecurityError` if path validation fails or symlinks are detected

**Security/IO notes:**

- `_ensure_no_symlink` rejects symlinked inputs/outputs unless in the allowlist (e.g., `/var`).
- `StreamProcessor` raises `CryptoError` if the output file already exists (no interactive prompt).

**Example:**

```python
from secure_string_cipher import decrypt_file

output_path, metadata = decrypt_file(
    input_path="document.pdf.enc",
    output_path=None,  # restore stored filename when present
    passphrase="MySecurePass123!",
    restore_filename=True,
)
print(output_path)  # e.g., "document.pdf" or "document.pdf.enc.dec" if no name stored
print(metadata.original_filename)  # "document.pdf" when stored
print(metadata.key_commitment)     # base64 string
```

---

## Key Derivation

### derive_key

Derive a cryptographic key from a passphrase using Argon2id.

```python
from secure_string_cipher import derive_key

key, salt = derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]
```

**Parameters:**

- `passphrase` (str): Password to derive key from
- `salt` (bytes, optional): 16-byte salt. If None, generates random salt.

**Returns:** Tuple of (32-byte key, 16-byte salt)

**Example:**

```python
from secure_string_cipher import derive_key

# Generate new key with random salt
key, salt = derive_key("MySecurePass123!")

# Re-derive same key with stored salt
key2, _ = derive_key("MySecurePass123!", salt=salt)
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

vault = PassphraseVault(vault_path: str | None = None)
```

**Parameters:**

- `vault_path` (str, optional): Custom path for vault file. Default: `~/.secure-cipher/passphrase_vault.enc`

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

## Security Utilities

### check_password_strength

Validate password meets security requirements.

```python
from secure_string_cipher import check_password_strength

is_strong, issues = check_password_strength(password: str) -> tuple[bool, list[str]]
```

**Parameters:**

- `password` (str): Password to validate

**Returns:** Tuple of (is_strong: bool, issues: list of problem descriptions)

**Requirements:**

- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

**Example:**

```python
from secure_string_cipher import check_password_strength

is_strong, issues = check_password_strength("weak")
if not is_strong:
    print(f"Password problems: {issues}")
    # ["Too short (minimum 12 characters)", "Missing uppercase", ...]

is_strong, issues = check_password_strength("MySecurePass123!")
print(is_strong)  # True
```

---

### constant_time_compare

Compare two strings in constant time to prevent timing attacks.

```python
from secure_string_cipher import constant_time_compare

is_equal = constant_time_compare(a: str, b: str) -> bool
```

**Example:**

```python
from secure_string_cipher import constant_time_compare

# Use this instead of == for security-sensitive comparisons
if constant_time_compare(user_input, stored_password_hash):
    print("Authenticated")
```

---

### add_timing_jitter

Add random delay to prevent timing analysis.

```python
from secure_string_cipher import add_timing_jitter

add_timing_jitter(min_ms: float = 1.0, max_ms: float = 10.0) -> None
```

**Example:**

```python
from secure_string_cipher import add_timing_jitter

# Add random 1-10ms delay
add_timing_jitter()

# Custom range
add_timing_jitter(min_ms=5.0, max_ms=50.0)
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

> **Note:** The rate limiter is active by default in the CLI on vault unlock (`ssc vault`), text decryption (`ssc decrypt -t`), and file decryption (`ssc decrypt -f`) operations. Repeated failures trigger exponential backoff.

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

Log security events for monitoring and compliance.

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

Securely delete a file by overwriting with random data.

```python
from secure_string_cipher import secure_overwrite

secure_overwrite(filepath: str, passes: int = 3) -> None
```

**Example:**

```python
from secure_string_cipher import secure_overwrite

# Securely delete sensitive file
secure_overwrite("plaintext_backup.txt", passes=3)
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
| `MAX_FILE_SIZE` | 104857600 | Maximum file size (100MB) |
| `MIN_PASSWORD_LENGTH` | 12 | Minimum password length |
| `SALT_SIZE` | 16 | Salt size in bytes |
| `KEY_SIZE` | 32 | AES-256 key size |
| `NONCE_SIZE` | 12 | GCM nonce size |
| `TAG_SIZE` | 16 | GCM authentication tag size |
