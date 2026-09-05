# API Reference

This reference documents every name exported by `secure_string_cipher.__all__`
on the current Beta branch. The API and file formats remain compatibility
sensitive, but the Beta is not yet a stable or independently audited contract.

Import public names from the package root:

```python
from secure_string_cipher import encrypt_text
```

Names available only from submodules are implementation-level interfaces unless
another project document explicitly says otherwise. Never print, log, or place
passphrases in command-line arguments; placeholder credentials below are for
illustration only.

## Public API at a glance

| Area | Package-root exports |
| ---- | -------------------- |
| Encryption | `encrypt_text`, `decrypt_text`, `encrypt_bytes`, `decrypt_bytes`, `encrypt_file`, `decrypt_file`, `StreamProcessor`, `FileMetadata` |
| Key derivation | `derive_key`, `derive_key_from_key_file`, `generate_key_pair`, `compute_key_commitment`, `verify_key_commitment` |
| Errors | `CryptoError`, `SecurityError`, `RateLimitError`, `KeychainError`, `KeychainUnavailableError` |
| Passphrases and vault | `generate_passphrase`, `PassphraseVault`, `BACKEND_FILE`, `BACKEND_KEYCHAIN` |
| Vault configuration | `VaultSettings`, `load_vault_settings`, `save_vault_settings`, `set_vault_backend` |
| Keychain | `KeychainVaultBackend`, `is_keychain_available` |
| Security and memory | `check_password_strength`, `constant_time_compare`, `add_timing_jitter`, `SecureString`, `SecureBytes`, `secure_wipe`, `has_secure_memory` |
| Rate limiting | `RateLimiter`, `PersistentRateLimiter`, `rate_limited`, `get_global_limiter` |
| Audit logging | `AuditLogger`, `AuditEvent`, `AuditLevel`, `get_audit_logger`, `audit_event`, `audit_auth_failure`, `audit_rate_limit` |
| Terminal and CLI | `colorize`, `secure_overwrite`, `ProgressBar`, `main` |

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

```text
encrypt_text(text: str, passphrase: str) -> str
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

```text
decrypt_text(token: str, passphrase: str) -> str
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

### encrypt_bytes / decrypt_bytes

Encrypt arbitrary bytes and return a canonical Base64 token as `bytes`.
`decrypt_bytes` accepts only canonical ASCII Base64 and returns the original
byte sequence.

```text
encrypt_bytes(data: bytes, passphrase: str) -> bytes
decrypt_bytes(token: bytes, passphrase: str) -> bytes
```

Both functions raise `CryptoError` for invalid input, authentication failure,
or cryptographic failure. They operate in memory; use `encrypt_file` and
`decrypt_file` for bounded streaming file operations.

```python
from secure_string_cipher import decrypt_bytes, encrypt_bytes

payload = b"binary\x00payload"
token = encrypt_bytes(payload, "correct horse battery staple")
assert decrypt_bytes(token, "correct horse battery staple") == payload
```

---

### encrypt_file

Encrypt a file using AES-256-GCM with chunked streaming.

```text
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

```text
decrypt_file(
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

### FileMetadata

`FileMetadata` is the parsed metadata returned by `decrypt_file` and the
serializer used by the file-format implementation.

```text
FileMetadata(
    original_filename: str | None = None,
    version: int = 5,
    key_commitment: str | None = None,
) -> FileMetadata
metadata.to_bytes() -> bytes
FileMetadata.from_bytes(data: bytes) -> FileMetadata
```

`from_bytes` strictly accepts supported version 4 or 5 JSON metadata, rejects
unknown or duplicate fields, and validates the canonical Base64 commitment.
Constructing an instance directly does not perform that parser validation;
prefer the high-level file functions unless implementing compatible framing.

### StreamProcessor

`StreamProcessor` is the exported low-level context manager used for regular
file reads and progress tracking.

```text
StreamProcessor(path: str, mode: str) -> StreamProcessor
stream.read(size: int = -1) -> bytes
stream.write(data: bytes) -> int
```

Supported modes are the binary modes used by SSC (`"rb"` and `"wb"`). Reads
from filesystem paths enforce the plaintext size bound. Direct writes through
this helper are not the authenticated, atomic publication workflow provided by
`encrypt_file` and `decrypt_file`; application code should normally use those
high-level functions.

---

## Key Derivation

### derive_key

Derive a cryptographic key from a passphrase using Argon2id.

```text
derive_key(passphrase: str, salt: bytes) -> bytes
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

Compute and verify the HMAC-SHA256 commitment that binds ciphertext to the
derived key and rejects a non-matching key before plaintext processing.

```text
compute_key_commitment(key: bytes) -> bytes
verify_key_commitment(key: bytes, expected_commitment: bytes) -> bool
```

**Example:**

```python
import os

from secure_string_cipher import (
    compute_key_commitment,
    derive_key,
    verify_key_commitment,
)

salt = os.urandom(16)
key = derive_key("application-passphrase", salt)
commitment = compute_key_commitment(key)

# Later: verify the key matches
assert verify_key_commitment(key, commitment)
```

The commitment is HMAC-SHA256 over SSC's fixed commitment context using an
already-derived key. It does not accept a salt; callers pass the same key bytes
to `verify_key_commitment` with the expected commitment.

---

### derive_key_from_key_file

Derive a cryptographic key from a key file using Argon2id.

This legacy mode accepts any regular file. Its bytes are hashed with SHA-256 and
the digest is used as a symmetric passphrase for Argon2id. It is not RSA,
public-key, or recipient encryption: anyone with identical file bytes can
decrypt. Treat it as legacy pending secret `.ssckey` files.

```text
derive_key_from_key_file(key_file_path: str | Path, salt: bytes) -> bytes
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

```text
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

**Security:** Both files are written with owner-only `0o600` permissions. The
private key is unencrypted PKCS#8 PEM and must be protected independently. If
you need to share the public key, copy it or deliberately broaden that file's
permissions. These files are not a sender/recipient key pair for SSC's current
symmetric encryption APIs.

**Example:**

```python
from secure_string_cipher import generate_key_pair

# Generate RSA key pair
generate_key_pair("/path/to/private_key.pem", "/path/to/public_key.pem")
# Private key: /path/to/private_key.pem (chmod 600)
# Public key:  /path/to/public_key.pem  (chmod 600)

# Or let it auto-generate the public key filename
generate_key_pair("/path/to/private_key.pem")
# Public key will be saved to: /path/to/private_key.pem.pub
```

**Note:** This function requires the `cryptography` library for RSA key generation.

## Passphrase Generation

### generate_passphrase

Generate a passphrase with Python's `secrets` module and return both the secret
and the generator's entropy estimate.

```text
generate_passphrase(
    strategy: str = "word",
    word_count: int = 6,
    length: int = 24,
    include_symbols: bool = True,
    number_count: int = 4,
) -> tuple[str, float]
```

**Parameters:**

- `strategy`: `"word"` (default), `"alphanumeric"`, or `"mixed"`.
- `word_count`: Number of words for `word` or `mixed`. The minimum is 4 for
  `word` and 3 for `mixed`.
- `length`: Character count for `alphanumeric` (default 24, minimum 16).
- `include_symbols`: Include the generator's symbol alphabet in an
  `alphanumeric` result (default `True`). Letters and digits are always used.
- `number_count`: Number of trailing digits for `mixed` (default 4, minimum 3).

**Returns:** `(passphrase, entropy_bits)`. The numeric value is the generator's
selection-space estimate, not a strength verdict for arbitrary user passwords.

**Raises:** `ValueError` for an unknown strategy or a strategy-specific count
below its minimum.

**Example:**

```python
from secure_string_cipher import generate_passphrase

# Default: six words separated by hyphens.
word_passphrase, word_entropy = generate_passphrase()

# 32 letters and digits, without symbols.
token, token_entropy = generate_passphrase(
    "alphanumeric", length=32, include_symbols=False
)

# Four words followed by four digits.
mixed, mixed_entropy = generate_passphrase(
    "mixed", word_count=4, number_count=4
)
```

All returned passphrases are plaintext secrets. Store or consume them without
printing or logging them.

---

## Passphrase Vault

### PassphraseVault

Encrypted storage for passphrases with HMAC integrity verification.

```text
PassphraseVault(
    vault_path: str | None = None,
    backend: str | None = None,
)
```

**Parameters:**

- `vault_path` (str, optional): Custom path for vault file. Default: `~/.secure-cipher/passphrase_vault.enc`
- `backend` (str, optional): `"file"`, `"keychain"`, or `None` to use the
  persisted/environment/default backend selection. A usable keychain is the
  default when no explicit selection exists; otherwise the file backend is used.

`BACKEND_FILE` and `BACKEND_KEYCHAIN` are the package-root string constants
`"file"` and `"keychain"`. The `backend` property exposes the selected value.

#### Methods

| Method | Result |
| ------ | ------ |
| `store_passphrase(label, passphrase, master_password)` | Add a uniquely labelled secret |
| `retrieve_passphrase(label, master_password)` | Return a stored secret |
| `list_labels(master_password)` | Return sorted labels |
| `update_passphrase(label, new_passphrase, master_password)` | Replace an existing secret |
| `delete_passphrase(label, master_password)` | Remove an existing secret |
| `vault_exists()` | Report whether active backend storage exists |
| `get_vault_path()` | Return a file path or `"OS Keychain"` |
| `read_raw_vault()` | Return exact encrypted vault text, or `None` |
| `write_raw_vault(vault_contents)` | Write size-bounded raw encrypted text without authenticating it |
| `delete_vault_storage()` | Delete active backend storage |
| `import_raw_vault(vault_contents, master_password, *, backup_current=True)` | Validate and transactionally publish a candidate |
| `migrate_to_keychain(master_password)` | Validate and copy the file vault to the keychain |
| `migrate_to_file(master_password)` | Validate and copy the keychain vault to the file path |
| `list_backup_records()` | Return structured backup records, newest first |
| `list_backups()` | Return backup path strings, newest first |
| `validate_backup(backup_identifier, master_password)` | Authenticate a selected backup without mutation |
| `restore_from_backup(backup_identifier, master_password)` | Transactionally restore a selected backup |

Prefer `import_raw_vault` over `write_raw_vault` for untrusted or transported
data. `delete_vault_storage` is destructive and does not create a backup.

##### store_passphrase

Store a passphrase with a label.

```text
vault.store_passphrase(label: str, passphrase: str, master_password: str) -> None
```

##### retrieve_passphrase

Retrieve a stored passphrase.

```text
vault.retrieve_passphrase(label: str, master_password: str) -> str
```

**Raises:** `ValueError` if label not found or vault cannot be decrypted.

##### list_labels

List all stored passphrase labels (requires master password to decrypt the vault).

```text
vault.list_labels(master_password: str) -> list[str]
```

##### delete_passphrase

Delete a passphrase entry.

```text
vault.delete_passphrase(label: str, master_password: str) -> None
```

##### update_passphrase

Update an existing passphrase.

```text
vault.update_passphrase(label: str, new_passphrase: str, master_password: str) -> None
```

##### import_raw_vault

Validate and transactionally replace the configured active vault.

```text
vault.import_raw_vault(
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

```text
vault.list_backup_records() -> list[VaultBackup]
vault.validate_backup(backup_identifier: str, master_password: str) -> None
vault.restore_from_backup(
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

## Vault Configuration

### VaultSettings

```text
VaultSettings(
    vault_backend: str = "file",
    vault_path: str | None = None,
    backup_dir: str | None = None,
)
```

`VaultSettings` is a mutable dataclass. A directly constructed instance has the
field defaults above; `load_vault_settings` resolves usable paths and the
effective backend.

### load_vault_settings / save_vault_settings / set_vault_backend

```text
load_vault_settings(*, apply_env: bool = True) -> VaultSettings
save_vault_settings(settings: VaultSettings) -> None
set_vault_backend(backend: str) -> VaultSettings
```

Settings are persisted in `~/.secure-cipher/config.json`. When `apply_env=True`,
`CIPHER_VAULT_BACKEND`, `CIPHER_VAULT_PATH`, and `CIPHER_BACKUP_DIR` override
persisted values. `set_vault_backend` accepts `BACKEND_FILE` or
`BACKEND_KEYCHAIN`, persists that choice, and returns the effective settings;
an environment override may therefore affect the returned backend.

---

## Keychain Backend

### KeychainVaultBackend

Store vault data in a usable OS keychain through the optional `keyring`
dependency.

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
| `store_vault(vault_contents: str) -> None` | Store the encrypted vault blob |
| `load_vault() -> str \| None` | Load vault from keychain (None if not found) |
| `delete_vault() -> None` | Remove vault from keychain |
| `vault_exists() -> bool` | Check if vault exists in keychain |
| `store_metadata(metadata: dict[str, Any]) -> None` | Best-effort metadata write |
| `load_metadata() -> dict[str, Any]` | Best-effort metadata read; returns `{}` on failure |

The constructor accepts `service_name: str = "secure-string-cipher"` and raises
`KeychainUnavailableError` when no usable keyring backend is available.

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

# Select a backend explicitly
vault = PassphraseVault(backend=BACKEND_KEYCHAIN)
file_vault = PassphraseVault(backend=BACKEND_FILE)

# Migrate between backends
file_vault.migrate_to_keychain(master_password)
vault.migrate_to_file(master_password)
```

When `backend=None`, `PassphraseVault` uses environment, persisted, and default
selection rather than always choosing the file backend. See
[Vault Configuration](#vault-configuration).

---

## Security Utilities

### check_password_strength

Validate password meets security requirements.

```text
check_password_strength(password: str) -> tuple[bool, str]
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
- No substring from the built-in common-password set

**Example:**

```python
from secure_string_cipher import check_password_strength

is_strong, message = check_password_strength("weak")
if not is_strong:
    print(f"Password problems: {message}")
    # "Password must be at least 12 characters"

is_strong, message = check_password_strength("MySecurePass123!")
print(is_strong)  # True
```

---

### constant_time_compare

Compare two byte strings with `hmac.compare_digest` to avoid ordinary
early-exit equality timing behaviour.

```text
constant_time_compare(a: bytes, b: bytes) -> bool
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

Sleep for a random interval from 0 up to (but not including) 10 milliseconds.

```text
add_timing_jitter() -> None
```

This is one small timing-obfuscation measure used by password-strength checks;
it is not a substitute for constant-time comparison or rate limiting.

**Example:**

```python
from secure_string_cipher import add_timing_jitter

# Add random 0-10ms delay
add_timing_jitter()
```

---

## Secure Memory

### SecureString / SecureBytes

Context-manageable wrappers that wipe their mutable internal buffers.

```text
SecureString(string: str) -> SecureString
SecureBytes(data: bytes) -> SecureBytes
```

**Access and cleanup:**

- `SecureString.string` returns a newly decoded immutable `str`.
- `SecureBytes.data` returns a `memoryview` over the mutable internal buffer.
- `wipe()` clears the internal buffer and is idempotent.
- Context-manager exit calls `wipe()`.

**Example:**

```python
from secure_string_cipher import SecureBytes, SecureString

with SecureString("application-passphrase") as password:
    use_password(password.string)

with SecureBytes(b"\x00" * 32) as key:
    use_key(bytes(key.data))
```

Python may retain immutable originals or copies created while accessing either
wrapper. These classes reduce lifetime of the mutable internal copy; they do
not guarantee that every copy of a secret is removed from process memory.

---

### has_secure_memory

Check whether the libsodium-backed wiping path is available.

```text
has_secure_memory() -> bool
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

Wipe a mutable buffer with libsodium when available, otherwise with SSC's
best-effort Python fallback.

```text
secure_wipe(data: bytes | bytearray | memoryview | array.array) -> None
```

**Example:**

```python
from secure_string_cipher import secure_wipe

sensitive_data = bytearray(b"secret")
# ... use data ...
secure_wipe(sensitive_data)  # Zeros the memory
```

Despite the compatibility annotation, immutable `bytes` cannot be wiped and
raise `TypeError`. Pass a `bytearray`, writable contiguous `memoryview`, or
`array.array`; multi-byte element buffers are wiped across their full byte
length. The function releases a supplied `memoryview` on return, including when
it rejects the view; read-only and non-C-contiguous views are rejected before
any bytes are overwritten.

---

## Rate Limiting

### RateLimiter

In-memory, thread-safe attempt tracking with a time window and exponential
lockout backoff.

```text
RateLimiter(
    max_attempts: int = 5,
    window_seconds: float = 60.0,
    lockout_seconds: float = 30.0,
    backoff_multiplier: float = 2.0,
)
```

**Methods:**

- `check_rate_limit(operation, identifier="") -> tuple[bool, float]`
- `record_attempt(operation, identifier="", success=False) -> None`
- `get_remaining_attempts(operation, identifier="") -> int`
- `reset(operation, identifier="") -> None`
- `reset_all() -> None`

**Example:**

```python
from secure_string_cipher import RateLimiter

limiter = RateLimiter(max_attempts=3, window_seconds=60)
allowed, wait_seconds = limiter.check_rate_limit("vault_unlock", "local-vault")
if allowed:
    try:
        unlock_vault()
    except AuthenticationError:
        limiter.record_attempt("vault_unlock", "local-vault", success=False)
        raise
    else:
        limiter.record_attempt("vault_unlock", "local-vault", success=True)
```

### PersistentRateLimiter

`PersistentRateLimiter` has the same methods and policy parameters as
`RateLimiter`, plus `state_path: str | None = None`. It reloads and atomically
updates JSON state around mutating/check operations; the default path is
`~/.secure-cipher/rate_limits.json`.

```python
from secure_string_cipher import PersistentRateLimiter

limiter = PersistentRateLimiter(state_path="/private/app/rate_limits.json")
```

During construction, a missing or malformed JSON file leaves the initial state
empty; schema-invalid records are ignored. A later transient load failure keeps
the process's existing in-memory records. This is local process/host throttling,
not protection against offline guesses by an attacker who has ciphertext.

### rate_limited / get_global_limiter

```text
get_global_limiter() -> RateLimiter
rate_limited(
    operation: str,
    limiter: RateLimiter | None = None,
    get_identifier: Callable[..., str] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]
```

The decorator checks before calling the wrapped function, records success when
it returns, records failure when it raises an `Exception`, and raises
`RateLimitError` with a `wait_seconds` attribute when blocked. If `limiter` is
omitted it uses the process-local object returned by `get_global_limiter()`.

```python
from secure_string_cipher import RateLimitError, rate_limited


@rate_limited("vault_unlock", get_identifier=lambda vault_id, **_: vault_id)
def unlock(vault_id: str, supplied_passphrase: str) -> None:
    authenticate(vault_id, supplied_passphrase)

try:
    unlock("local-vault", supplied_passphrase)
except RateLimitError as exc:
    print(f"Retry after {exc.wait_seconds:.1f} seconds")
```

The SSC command-line interface applies local rate limiting to vault unlock,
text decryption, and file decryption. It cannot prevent offline password
guessing.

---

## Audit Logging

### AuditLogger

Log security events as editable local JSON. Rotation and redaction are provided,
but the log has no cryptographic chain or external append-only storage and is
not tamper-evident.

```text
AuditLogger(
    log_path: str | Path | None = None,
    level: AuditLevel = AuditLevel.STANDARD,
    enabled: bool | None = None,
    max_size: int | None = None,
    backup_count: int | None = None,
)
```

`AuditLogger` is a process singleton; constructor settings apply only on its
first initialization. `get_audit_logger()` returns that same instance.

`AuditLevel` values are `OFF`, `CRITICAL`, `STANDARD`, and `VERBOSE`.
`AuditEvent` covers text/file encryption and decryption, vault operations,
authentication, rate limiting, key derivation, integrity failures, startup,
shutdown, and configuration change events.

**Methods:**

- `log(event: AuditEvent, success: bool = True, details: dict | None = None)`: Log an event with redaction of sensitive keys
- `log_auth_failure(operation: str, reason: str = "invalid_credentials", identifier: str | None = None)`: Convenience for auth failures
- `log_rate_limit(operation: str, wait_seconds: float, identifier: str | None = None)`: Convenience for rate-limit triggers
- `log_encryption(event_type: AuditEvent, success: bool, file_path: str | None = None, error: str | None = None)`: Convenience for encrypt/decrypt
- `log_vault_operation(event_type: AuditEvent, success: bool, vault_path: str | None = None, label: str | None = None, error: str | None = None)`: Convenience for vault CRUD
- `set_level(level: AuditLevel)`, `enable()`, and `disable()`: Change runtime logging behavior

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

The exact package-root signatures are:

```text
get_audit_logger() -> AuditLogger
audit_event(event: AuditEvent, success: bool = True, **details) -> None
audit_auth_failure(operation: str, reason: str = "invalid_credentials", **kwargs) -> None
audit_rate_limit(operation: str, wait_seconds: float, **kwargs) -> None
```

---

## Exceptions

### CryptoError

Raised for cryptographic operation failures.

```python
from secure_string_cipher import CryptoError, decrypt_text, encrypt_text

token = encrypt_text("message", "correct horse battery staple")

try:
    decrypt_text(token, "different horse battery staple")
except CryptoError:
    print("Decryption failed")
```

### SecurityError

Raised by the policy helpers in `secure_string_cipher.security` for path,
symlink, execution-context, and secure-publication violations. The exception is
exported at the package root; the helpers themselves are submodule APIs.

```python
from secure_string_cipher import SecurityError
from secure_string_cipher.security import validate_safe_path

try:
    validate_safe_path("../outside.txt", ".")
except SecurityError:
    print("Path rejected")
```

### RateLimitError

Raised by `rate_limited` when an operation is blocked. It carries the remaining
delay in `wait_seconds`.

```python
from secure_string_cipher import RateLimitError, RateLimiter

limiter = RateLimiter(max_attempts=1)
limiter.record_attempt("example", success=False)
allowed, wait_seconds = limiter.check_rate_limit("example")

try:
    if not allowed:
        raise RateLimitError(wait_seconds)
except RateLimitError as exc:
    print(f"Retry after {exc.wait_seconds:.1f} seconds")
```

---

## Utility Functions

### colorize

Add terminal colors to output.

```text
colorize(text: str, color: str = "cyan") -> str
```

**Configured colors:** `red`, `green`, `blue`, and `cyan`. An unknown color
falls back to cyan on a likely dark terminal or blue on a likely light one.

**Example:**

```python
from secure_string_cipher import colorize

print(colorize("Success!", "green"))
print(colorize("Information", "cyan"))
print(colorize("Error!", "red"))
```

---

### ProgressBar

Display progress for long operations.

```text
ProgressBar(total_bytes: int, width: int = 40) -> ProgressBar
progress.update(current: int) -> None
```

**Example:**

```python
from secure_string_cipher import ProgressBar

progress = ProgressBar(total_bytes=100)
for completed in range(1, 101):
    # do work
    progress.update(completed)
```

---

### secure_overwrite

Best-effort delete a file by overwriting it with zero bytes and unlinking it.
This cannot guarantee erasure on SSDs, copy-on-write filesystems, snapshots,
backups, or journaled filesystems.

```text
secure_overwrite(path: str) -> None
```

**Example:**

```python
from secure_string_cipher import secure_overwrite

# Best-effort overwrite and unlink
secure_overwrite("plaintext_backup.txt")
```

---

### main

Run the package-root interactive menu with optional input/output streams. This
is distinct from the installed `ssc` console script, which uses the argparse
entry point in `secure_string_cipher.cli_args`.

```text
main(
    in_stream: TextIO | None = None,
    out_stream: TextIO | None = None,
    exit_on_completion: bool = True,
) -> int | None
```

Supplying streams supports embedding and tests. With
`exit_on_completion=False`, the function returns instead of terminating after
a completed operation.

---

## Configuration Constants

Key parameters defined in `secure_string_cipher.config`:

| Constant | Value | Description |
| -------- | ----- | ----------- |
| `CHUNK_SIZE` | 262144 | File streaming chunk size (256 KiB) |
| `ARGON2_MEMORY_COST` | 65536 | Argon2id memory cost in KiB (64 MiB) |
| `ARGON2_TIME_COST` | 3 | Argon2id time cost |
| `ARGON2_PARALLELISM` | 4 | Argon2id parallelism |
| `ARGON2_HASH_LENGTH` | 32 | Derived-key length in bytes |
| `MAX_FILE_SIZE` | 104857600 | Maximum plaintext payload (100 MiB); also the separate raw vault/key-file ingestion cap |
| `MIN_PASSWORD_LENGTH` | 12 | Minimum password length |
| `SALT_SIZE` | 16 | Salt size in bytes |
| `KEY_COMMITMENT_SIZE` | 32 | HMAC-SHA256 commitment size in bytes |
| `NONCE_SIZE` | 12 | GCM nonce size |
| `TAG_SIZE` | 16 | GCM authentication tag size |
| `METADATA_VERSION` | 5 | Current authenticated file-metadata version |
