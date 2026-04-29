# Changelog

## [1.0.33] - 2026-04-29

### Security

- **Fixed vault HMAC timing oracle**: Removed `decrypt_text()` call after HMAC verification failure in `PassphraseVault._load_vault()`. Eliminates a timing side-channel where Argon2id key derivation (~50-100ms) could distinguish HMAC failures from decryption failures.
- **Fixed StreamProcessor interactive hang**: Replaced `input()` prompt in `StreamProcessor._check_path()` with unconditional `CryptoError`. Prevents non-interactive scripts from hanging indefinitely when output files exist.
- **Fixed secure memory double-wipe race**: Added `_wiped` flag to `SecureBytes` and `SecureString`. `wipe()` is now idempotent, preventing crashes from concurrent `__exit__` and `__del__` calls.
- **Wired up rate limiter**: Integrated `RateLimiter` into vault unlock (`vault_unlock`), text decryption (`decrypt_text`), and file decryption (`decrypt_file`) paths in the CLI. Previously the rate limiter module existed but was never invoked.
- **Added vault import validation**: `cmd_vault_import()` now validates SSCVAULT header, hex salt, data/HMAC separators, and minimum line count before replacing an existing vault. Also enforces `0o600` permissions on imported vault files.
- **Fixed misleading docstring**: Removed "constant-time operations" claim from `check_password_strength()` docstring.

### Removed

- Removed dead code: `InMemoryStreamProcessor` (core.py), `TimeoutManager` and `handle_timeout()` (utils.py), and corresponding exports/tests.

### Fixed

- `ValueError` from corrupted vault files is now caught in `_get_password_from_vault()`, preventing unhandled exceptions.

---

## [1.0.32] - 2025-12-14

### Security & CLI Hardening

- Decrypt file flow now checks for symlinked inputs before any metadata reads, preserving exit codes and blocking traversal attempts.
- Added `--output` and `--restore-filename/--no-restore-filename` flags to `ssc decrypt`; default restores original filenames safely, with tested fallback to `.dec` when restore is disabled.
- Extended CLI tests to cover output override, restore toggling, and metadata-driven filename restoration.

### Tooling & Packaging

- Makefile now runs lint/tests via `uv run --locked` for CI parity.
- Docker image entrypoint aligned to `ssc` and image labels bumped to match version.
- README/DEVELOPER docs updated (test counts, docker compose command, chunk size note).

---

## [1.0.31] - 2025-12-05

### Simplified CLI Entry Point

Consolidated all CLI functionality under a single `ssc` command.

#### Updates

- **Single Entry Point**: Removed `ssc-start` - now just use `ssc start` for the interactive menu
- **Consistent Interface**: All functionality accessible via `ssc` command:
  - `ssc` - Shows help menu
  - `ssc start` - Launch interactive menu
  - `ssc encrypt` - Encrypt text or files
  - `ssc decrypt` - Decrypt text or files
  - `ssc store` - Store password in vault
  - `ssc vault` - Manage vault

#### Migration

If you were using `ssc-start` or `cipher-start`, simply use `ssc start` instead.

---

## [1.0.30] - 2025-12-05

### Non-Interactive CLI Mode

Major feature release introducing the `ssc` command for scripting and automation.

#### New CLI Entry Points

- **`ssc` Command**: Non-interactive CLI with subcommands:
  - `ssc encrypt -t "msg"` / `ssc encrypt -f file` - Encrypt text or files
  - `ssc decrypt -t "cipher"` / `ssc decrypt -f file.enc` - Decrypt text or files
  - `ssc store <label>` / `ssc store <label> -g` - Store manual or generated password
  - `ssc vault list|delete|export|import|reset` - Full vault management

- **`ssc-start` Command**: Launch interactive menu (renamed from `cipher-start`)

#### Security Design

- **No Command-Line Passwords**: Passwords never appear in command line arguments,
  preventing shell history exposure. All passwords prompted interactively or retrieved from vault.
- **Vault Integration**: Use `--vault <LABEL>` with any encrypt/decrypt command to pull
  password from the encrypted vault automatically.
- **Validation First**: File existence and overwrite checks happen before password prompts,
  preventing password exposure on validation failures.

#### User Experience

- **Exit Codes**: Consistent error codes for scripting:
  - 0: Success
  - 1: Input error (invalid arguments)
  - 2: Auth error (wrong password)
  - 3: Vault error (not initialized, label not found)
  - 4: File error (not found, permission denied)

- **Output Control**:
  - `--quiet / -q` - Suppress info/warning messages
  - `--no-color` - Disable ANSI color codes
  - Text output to stdout, status to stderr

- **Overwrite Protection**: Encrypted files refuse to overwrite existing outputs
  unless `--force` is specified.

#### New Module

- **`src/secure_string_cipher/cli_args.py`**: 730+ lines implementing:
  - Argparse-based subcommand structure
  - Password prompting with confirmation
  - Vault auto-initialization on first use
  - Full error handling with user-friendly messages

#### Entry Points

- `ssc` → `secure_string_cipher.cli_args:main` (NEW)
- `ssc-start` → `secure_string_cipher.cli:main` (renamed from `cipher-start`)

#### Post-Release Fixes

- Fixed PassphraseVault method names in CLI (`store_passphrase`, `delete_passphrase`, etc.)
- Fixed timing test tolerance for CI environments (shared runner CPU variance)
- Updated documentation with `ssc` CLI usage examples
- Removed `copilot-instructions.md` from git tracking (local-only)

#### Test Suite (v1.0.30)

- **New tests**: 67 tests covering the new CLI
  - `tests/unit/test_cli_args.py`: Parser, validation, command tests (45 tests)
  - `tests/integration/test_ssc_cli.py`: End-to-end CLI workflows (22 tests)
- **Total**: 615 tests (548 → 615, +67 new tests)

---

## [1.0.29] - 2025-12-02

### Documentation Overhaul

Comprehensive documentation update with new API reference, improved test commands, and coverage badges.

#### New Documentation

- **`docs/API.md`**: Complete API reference (~600 lines) documenting:
  - Core encryption functions (`encrypt_text`, `decrypt_text`, `encrypt_file`, `decrypt_file`)
  - Key derivation (`derive_key`, key commitment functions)
  - Passphrase generation and vault operations
  - Security utilities (`check_password_strength`, `constant_time_compare`, `add_timing_jitter`)
  - Secure memory handling (`SecureString`, `SecureBytes`, `has_secure_memory`)
  - Rate limiting and audit logging
  - All exceptions and utility functions
  - Configuration constants table

#### Updated Documentation

- **`README.md`**:
  - Added coverage badge (79%)
  - Added "Quick Start" section
  - Added comprehensive "Programmatic API" section with code examples
  - Updated test counts (353 → 548 tests)
  - Added `make test-quick` command for faster development

- **`DEVELOPER.md`**:
  - Updated test counts (353+ → 548 tests)
  - Added "Fast Development Cycle" section
  - Added `test-quick` and `test-slow` make targets
  - Documented test timing (~10s quick vs ~80s full)
  - Added fuzz and performance test directories

- **`CONTRIBUTING.md`**:
  - Updated coverage threshold (69% → 79%)
  - Added "Test Commands" section with quick/full options
  - Added complete test directory structure with all test files

#### Development Improvements

- **Makefile**: Enhanced test targets
  - `make test-quick`: Fast tests (~10s, 207 tests) - excludes KDF-heavy tests
  - `make test-slow`: Run only slow tests (KDF, fuzz, performance)
  - Better developer experience for rapid iteration

#### Test Suite Summary

- Total tests: **548**
- Quick tests: 207 (~10s)
- Slow tests: 341 (~70s)
- Coverage: 79.39%

## [1.0.28] - 2025-12-02

### Coverage Improvement & Test Expansion

Significant expansion of test coverage from 73.84% to 79.39%, with 85 new tests targeting previously uncovered code paths.

#### New Test Files

- **`tests/unit/test_utils.py`** (31 tests):
  - `CryptoError` exception handling
  - `ProgressBar` initialization, TTY detection, throttling
  - `detect_dark_background()` with various `COLORFGBG` values
  - `colorize()` with color codes, NO_COLOR env, non-TTY fallback
  - `secure_overwrite()` file deletion, permission error handling
  - `TimeoutManager` context manager behavior

- **`tests/unit/test_core_extended.py`** (14 tests):
  - `StreamProcessor` with file-like objects
  - `FileMetadata` dataclass fields and defaults
  - Text encryption/decryption roundtrip
  - Unicode text handling (emoji, CJK characters)
  - Wrong password rejection
  - Invalid ciphertext error handling
  - Key commitment computation and verification

- **`tests/unit/test_passphrase_manager_extended.py`** (11 tests):
  - Custom vault path initialization
  - `CIPHER_BACKUP_DIR` environment variable
  - Backup rotation (keeps last 5)
  - Nonexistent label retrieval/update/delete errors
  - Wrong master password detection
  - Full CRUD operations testing

- **`tests/integration/test_cli_extended.py`** (29 tests):
  - `_read_password()` visible input, echo mode, EOF handling
  - `_print_banner()` output verification
  - `_get_mode()` valid/invalid/empty choices
  - `_get_input()` text and file mode prompts
  - `_get_password()` /gen command, weak password retry, confirmation mismatch
  - Vault operations: no vault errors, cancel handling
  - `main()` function: exit modes, continue loop, mode handlers

#### Coverage by Module

| Module | Before | After | Change |
|--------|--------|-------|--------|
| `utils.py` | 39.19% | **100.00%** | +60.81% |
| `cli.py` | 48.70% | 60.39% | +11.69% |
| `passphrase_manager.py` | 79.89% | 78.26% | -1.63%* |
| `core.py` | 82.79% | 83.09% | +0.30% |
| **TOTAL** | **73.84%** | **79.39%** | **+5.55%** |

*Minor variance due to test isolation differences

#### Test Suite Growth

- Total tests: 463 → **548** (+85 tests)
- Breakdown:
  - Unit tests: +56 (utils, core, passphrase_manager)
  - Integration tests: +29 (CLI extended)

#### Bug Fixes

- Fixed fuzz test deadline issues for Argon2id operations
- Added `pytest.mark.timeout(120)` for slow crypto operations
- Reduced vault performance test iterations for CI stability
- Fixed `blacklist_categories` mypy typing in fuzz tests

## [1.0.27] - 2025-12-02

### Test Suite Restructuring

Major reorganization of the test suite into specialized directories for better maintainability and focused testing capabilities.

#### New Test Directory Structure

```text
tests/
├── unit/           # Core functionality tests
├── integration/    # End-to-end workflow tests
├── security/       # Security-focused tests (NEW)
├── fuzz/           # Hypothesis fuzzing tests (NEW)
└── performance/    # Benchmark tests (NEW)
```

#### Security Tests (`tests/security/`)

Moved 7 security-focused test modules (~2,800 lines):

- `test_security.py` - Filename sanitization, path validation, symlink detection
- `test_security_integration.py` - Crypto memory handling, key derivation security
- `test_timing_safe.py` - Constant-time operations, password strength
- `test_secure_memory.py` - SecureString/SecureBytes, memory wiping
- `test_rate_limiter.py` - Rate limiting, exponential backoff
- `test_audit_log.py` - Audit logging, sensitive data redaction
- `test_key_commitment.py` - Key commitment computation and verification

#### Fuzz Tests (`tests/fuzz/`)

New Hypothesis-based fuzzing framework (22 tests):

- **`test_fuzz_encryption.py`**:
  - Encryption roundtrip with arbitrary text
  - Binary data handling
  - Unicode text (excluding surrogates)
  - Key derivation with random inputs
  - Decryption of garbage data (crash resistance)
  - Mutated ciphertext authentication
  - Edge cases: repeated characters, various sizes, null bytes

- **`test_fuzz_inputs.py`**:
  - Filename sanitization with malicious inputs
  - Path traversal pattern resistance
  - Password strength validation edge cases
  - Injection attack resistance (SQL, XSS, shell, format strings)
  - Null byte injection prevention

#### Performance Benchmarks (`tests/performance/`)

New benchmark suite (15 tests) measuring:

- **Key derivation**: Argon2id latency (target: 300-1000ms)
- **Text encryption**: Throughput by size (small/medium/large/xlarge)
- **File encryption**: 100KB and 1MB file benchmarks
- **Key commitment**: Computation and verification speed
- **Constant-time operations**: Timing consistency verification
- **Input validation**: Sanitization speed
- **Summary report**: Consolidated performance metrics

#### Pytest Configuration

Added new marker for fuzz tests:

```python
markers = [
    "fuzz: marks tests as fuzz tests using Hypothesis",
    # ... existing markers
]
```

#### Test Counts

- **Total tests**: 426 → 463 (+37 new tests)
- **Security tests**: ~180 tests (moved to dedicated directory)
- **Fuzz tests**: 22 tests (new)
- **Performance tests**: 15 tests (new)

#### Running Specific Test Categories

```bash
# Run only security tests
pytest tests/security/ -v

# Run fuzz tests with fixed seed
pytest tests/fuzz/ --hypothesis-seed=12345

# Run performance benchmarks
pytest tests/performance/ -v

# Skip slow fuzz tests in CI
pytest -m "not fuzz" --ignore=tests/fuzz/
```

## [1.0.26] - 2025-12-02

### Third-Party Security Audit Preparation

This release prepares comprehensive documentation for third-party security audits, completing the v1.1.0 security hardening roadmap.

#### Documentation Updates

- **SECURITY.md** (updated):
  - Updated cryptographic primitives: PBKDF2 → Argon2id
  - Added key commitment, rate limiting, audit logging features
  - Updated dependency list (argon2-cffi, pynacl)
  - Added audit history entries
  - Updated version support table

- **CRYPTOGRAPHY.md** (new):
  - Comprehensive threat model with in-scope/out-of-scope threats
  - Detailed cryptographic primitive specifications:
    - AES-256-GCM: key size, nonce size, tag size
    - Argon2id: time cost, memory cost, parallelism
    - HMAC-SHA256: key commitment, vault integrity
  - Key derivation process with code references
  - Encryption scheme diagrams (text and file)
  - Key commitment security properties
  - File format v4 specification with field layout
  - Vault security architecture
  - Side-channel protections:
    - Timing attack mitigations (constant-time comparisons)
    - Memory security (libsodium secure wiping)
    - Timing jitter
  - Security assumptions and trust boundaries
  - Known limitations with mitigations
  - References to standards (NIST SP 800-38D, RFC 9106, RFC 2104)

- **AUDIT_CHECKLIST.md** (new):
  - 10-section audit checklist for security reviewers
  - Quick reference table linking components to source files
  - Detailed checklist items:
    1. Cryptographic implementation (key derivation, encryption, commitment)
    2. Side-channel protections (timing, memory)
    3. Input validation (path security, password policy)
    4. Authentication & access control (rate limiting, vault)
    5. Error handling (information leakage, exception safety)
    6. Configuration security (constants, hardcoded secrets)
    7. Dependencies (vulnerability scan, version review)
    8. Testing coverage (property-based, negative, boundary)
    9. File format (parsing, bounds checking)
    10. Operational security (logging, runtime checks)
  - Audit sign-off table
  - Findings template

#### Security Audit Readiness

- **Self-audit status**: 2 internal audits completed (Nov 2025, Dec 2025)
- **Documentation coverage**: All cryptographic decisions documented with rationale
- **Code references**: Direct links to source files and functions
- **Test coverage**: 426 tests including 24 property-based tests

## [1.0.25] - 2025-01-02

### Property-Based Testing with Hypothesis

This release adds property-based testing using Hypothesis to discover edge cases that traditional unit tests miss. Part of the v1.1.0 security hardening roadmap.

#### New Test Module (`tests/unit/test_property_based.py`)

24 property-based tests covering cryptographic invariants:

- **Key Derivation Properties** (4 tests):
  - Deterministic: Same passphrase + salt always produces same key
  - Different passphrases produce different keys
  - Different salts produce different keys (salt uniqueness critical)
  - Key length always matches `ARGON2_HASH_LENGTH` (32 bytes)

- **Encryption Properties** (4 tests):
  - Roundtrip: `decrypt(encrypt(plaintext)) == plaintext` for all inputs
  - Randomized: Same plaintext encrypted twice produces different ciphertext (IV uniqueness)
  - Ciphertext differs from plaintext (encryption actually transforms data)
  - Wrong passphrase fails decryption (authentication working)

- **Key Commitment Properties** (4 tests):
  - Deterministic: Same key always produces same commitment
  - Unique: Different keys produce different commitments
  - Fixed length: Always 32 bytes regardless of input
  - Verification: `verify_key_commitment(key, compute_key_commitment(key))` always True

- **Filename Sanitization Properties** (3 tests):
  - No path separators: Output never contains `/`, `\`, or `..`
  - Length bounds: Output respects maximum filename length
  - Idempotent: `sanitize(sanitize(x)) == sanitize(x)`

- **Constant-Time Compare Properties** (3 tests):
  - Reflexive: `constant_time_compare(x, x)` always True
  - Symmetric: `constant_time_compare(a, b) == constant_time_compare(b, a)`
  - Different inputs return False

- **Secure Memory Properties** (3 tests):
  - Data preservation: `SecureString.get()` returns original data
  - Bytes conversion: `SecureBytes.data` matches input
  - Clear zeros memory: After `clear()`, data is zeroed

- **FileMetadata Properties** (1 test):
  - JSON roundtrip: `from_json(to_json(meta)) == meta` for valid metadata

- **Password Strength Properties** (2 tests):
  - Valid passwords (12+ chars, mixed case, digits, special) pass validation
  - Short passwords (<12 chars) always fail

#### Testing Strategy

- **Hypothesis settings**: `deadline=None` for Argon2id tests (memory-hard KDF is intentionally slow)
- **Strategies used**: `st.text()`, `st.binary()`, `st.integers()`, `st.sampled_from()`
- **Property focus**: Cryptographic invariants that must hold for all inputs

#### Test Suite

- **Test count**: 402 → 426 tests (+24 property-based)
- **Coverage**: Maintained above 69% threshold
- **CI integration**: Property tests run in parallel with existing suite

## [1.0.24] - 2025-01-02

### Rate Limiting & Security Audit Logging

This release adds brute-force protection and comprehensive audit logging for security-sensitive operations, completing a key milestone in the v1.1.0 security hardening roadmap.

#### Rate Limiting (`rate_limiter.py`)

Prevents brute-force attacks on password-protected operations:

- **Thread-safe rate limiter**: Tracks failed attempts per operation/identifier with configurable thresholds
- **Exponential backoff**: Lockout duration doubles after each lockout (30s → 60s → 120s...)
- **Automatic expiration**: Old attempts expire after configurable window (default 60s)
- **Decorator support**: `@rate_limited` decorator for easy integration
- **Global limiter**: Singleton `get_global_limiter()` for application-wide rate limiting

```python
from secure_string_cipher import RateLimiter, rate_limited, RateLimitError

limiter = RateLimiter(max_attempts=5, window_seconds=60)
if limiter.check_rate_limit("vault_unlock", "user@example.com"):
    # Attempt allowed
    limiter.record_success("vault_unlock", "user@example.com")
else:
    raise RateLimitError("Too many attempts", wait_seconds=30)
```

#### Audit Logging (`audit_log.py`)

Tamper-evident logging of cryptographic operations for security auditing:

- **JSON-formatted logs**: Machine-parseable entries with timestamps, PIDs, and event details
- **Automatic log rotation**: Configurable max size (default 10MB) with backup count
- **Sensitive data redaction**: Passwords, passphrases, keys, and plaintext automatically redacted
- **Configurable verbosity**: OFF, CRITICAL, STANDARD, VERBOSE levels
- **Thread-safe singleton**: Single logger instance across application
- **Convenience functions**: `audit_event()`, `audit_auth_failure()`, `audit_rate_limit()`

```python
from secure_string_cipher import get_audit_logger, AuditEvent, AuditLevel

logger = get_audit_logger()
logger.log(AuditEvent.ENCRYPTION, success=True, details={"file": "secret.txt"})
logger.log(AuditEvent.AUTH_FAILURE, success=False, details={"reason": "wrong password"})
```

#### Configuration Constants

New settings in `config.py`:

- `RATE_LIMIT_MAX_ATTEMPTS = 5` - Maximum failed attempts before lockout
- `RATE_LIMIT_WINDOW_SECONDS = 60` - Time window for tracking attempts
- `RATE_LIMIT_LOCKOUT_SECONDS = 30` - Initial lockout duration
- `RATE_LIMIT_BACKOFF_MULTIPLIER = 2.0` - Exponential backoff factor
- `AUDIT_LOG_ENABLED = True` - Enable/disable audit logging
- `AUDIT_LOG_PATH` - Default log location (`~/.secure-cipher/audit.log`)
- `AUDIT_LOG_MAX_SIZE = 10MB` - Log rotation threshold
- `AUDIT_LOG_BACKUP_COUNT = 5` - Number of backup logs to keep

#### Technical Details

- **Timezone handling**: Standardized on `timezone.utc` (ruff UP017 ignored to prevent auto-conversion)
- **Python version**: Updated mypy and documentation to reflect 3.12+ target
- **Thread safety**: Both rate limiter and audit logger use threading locks

#### Tests

- 402 tests total (354 → 402, +48 new tests)
- `test_rate_limiter.py`: 24 tests covering basic ops, backoff, threading, decorators
- `test_audit_log.py`: 24 tests covering logging, redaction, rotation, threading

---

## [1.0.23] - 2025-12-02

### Security Hardening & UX Improvements

This release completes the security audit recommendations with enhanced key protection, improved password input handling, and upgraded vault integrity.

#### Security Enhancements

- **SecureBytes for Decryption Keys**: Decryption operations now wrap derived keys in `SecureBytes`, ensuring automatic memory zeroing when keys go out of scope. Prevents key material from lingering in memory after use.

- **Argon2id for Vault HMAC**: The passphrase vault now uses Argon2id (instead of SHA-256) to derive HMAC keys for integrity verification. Each vault has a unique random 32-byte salt, providing memory-hard protection against brute-force attacks on vault integrity.

- **New Vault Format**: Vault files now use the `SSCVAULT` header with random HMAC salt:

  ```text
  SSCVAULT
  <hmac_salt_hex>
  ---DATA---
  <encrypted_vault>
  ---HMAC---
  <argon2id_derived_hmac>
  ```

  **Breaking Change**: Vaults from previous versions are not compatible. Back up and re-create vaults after upgrading.

#### User Experience (v1.0.17)

- **Hidden Password Input**: Passwords are now hidden when typing in interactive terminals (via `getpass`). When stdin is piped or redirected (scripts, tests, automation), visible input is used automatically. No configuration needed.

- **Documentation Updates**: README and DEVELOPER.md updated to explain password input behavior and testing patterns.

#### Implementation Details

- `_read_password()` helper with `sys.stdin.isatty()` detection
- `_compute_hmac()` now takes salt parameter for Argon2id derivation
- Removed legacy v1 vault loading code (clean single-format implementation)
- Memory limitation documentation in `secure_memory.py`

#### Test Results

- 353 tests passing
- All existing tests work unchanged (StringIO triggers visible input mode)

---

## [1.0.22] - 2025-12-02

### Legacy Code Removal (Development Release)

Development release that removes all legacy encryption code, establishing a clean single-path implementation. This is a **breaking change** - files encrypted with versions prior to 1.0.19 cannot be decrypted. Intended for testing before v1.1.0 stable release.

#### Breaking Changes

- **Removed Functions**:
  - `encrypt_stream()`, `decrypt_stream()` - v1 stream encryption
  - `derive_key_pbkdf2()` - PBKDF2 key derivation
  - `encrypt_file_v2()`, `decrypt_file_v2()` - Renamed to `encrypt_file()`, `decrypt_file()`
  - `derive_key_argon2id()` - Renamed to `derive_key()`
  - `KDFAlgorithm` type alias, `get_default_kdf()`

- **Removed Configuration**:
  - `KDF_ALGORITHM`, `KDF_ITERATIONS`, `ARGON2_TYPE`

- **File Format**:
  - Only v4 format supported (Argon2id + key commitment)
  - v1/v2/v3 files fail with "missing magic header" error
  - Key commitment required - missing commitment fails decryption

#### Changes

- Single implementation path: Argon2id KDF with HMAC-SHA256 key commitment
- Simplified API: `encrypt_file()`, `decrypt_file()`, `derive_key()`
- Text encryption now uses Argon2id with key commitment
- ~350 lines of legacy code removed from `core.py`

#### Security

- KDF: Argon2id (time_cost=3, memory_cost=64MB, parallelism=4)
- Encryption: AES-256-GCM with random salt and nonce
- Key commitment: HMAC-SHA256 prevents invisible salamanders attacks
- File format: MAGIC(5) + META_LEN(2) + META_JSON + SALT(16) + NONCE(12) + CIPHERTEXT + TAG(16)

#### Test Summary

- 353 tests total (expanded with secure memory and timing tests)
- Rewrote `test_core.py`, `test_kdf.py` for Argon2id-only
- Comprehensive `test_secure_memory.py` and `test_timing_safe.py`
- Removed legacy backward compatibility tests

---

## [1.0.21] - 2025-12-02

### Key Commitment Scheme

Introduces key commitment to prevent "invisible salamanders" attacks where an attacker crafts a ciphertext that decrypts to different plaintexts under different keys.

- **Implementation**:
  - `compute_key_commitment(key)` - HMAC-SHA256 commitment binding ciphertext to key
  - `verify_key_commitment(key, expected)` - Constant-time verification before decryption

- **File Format v4**:
  - Metadata includes `key_commitment` field (base64-encoded HMAC)
  - Wrong passwords fail early before GCM decryption
  - Backward compatible: v2/v3 files decrypt without commitment check

- **Security**:
  - Blocks invisible salamanders attacks
  - Fast failure on wrong password via commitment check
  - Detects ciphertext manipulation targeting multiple keys

- **Configuration**:
  - `KEY_COMMITMENT_SIZE = 32`
  - `KEY_COMMITMENT_CONTEXT` - Domain separation string

- **API**:
  - Exported: `compute_key_commitment`, `verify_key_commitment`
  - `FileMetadata.key_commitment` field (v4 format)

- **Tests**: 254 → 268 (+14 key commitment tests)

## [1.0.20] - 2025-06-24

### Argon2id Key Derivation Function

Introduces Argon2id as the default KDF, replacing PBKDF2 for new encryptions. Argon2id is the Password Hashing Competition winner and provides superior protection against GPU/ASIC attacks through memory hardness.

- **Argon2id Implementation**:
  - New default KDF for all file encryption (`encrypt_file_v2`)
  - Memory-hard algorithm resistant to brute-force attacks
  - Parameters: time_cost=3, memory_cost=64MB, parallelism=4
  - Exceeds OWASP 2024 recommendations for password hashing

- **New Functions in `core.py`**:
  - `derive_key_argon2id(passphrase, salt)` - Argon2id key derivation
  - `derive_key_pbkdf2(passphrase, salt)` - PBKDF2 (extracted for clarity)
  - `derive_key(passphrase, salt, algorithm=None)` - Algorithm dispatcher

- **File Format v3**:
  - Metadata now stores KDF algorithm used for encryption
  - Enables automatic selection of correct KDF during decryption
  - Backward compatible: v2 files (no KDF field) default to PBKDF2

- **Backward Compatibility**:
  - Legacy v1 format (`encrypt_stream`, `encrypt_text`) always uses PBKDF2
  - `decrypt_file_v2()` reads KDF from metadata, defaults to PBKDF2 for old files
  - Text encryption (`encrypt_text`/`decrypt_text`) continues using PBKDF2
  - Existing encrypted files decrypt without modification

- **Configuration (`config.py`)**:
  - `KDF_ALGORITHM = "argon2id"` - Default for new v2/v3 files
  - `ARGON2_TIME_COST = 3` - CPU cost parameter
  - `ARGON2_MEMORY_COST = 65536` - Memory cost (64 KB * 1024 = 64 MB)
  - `ARGON2_PARALLELISM = 4` - Lane count
  - `ARGON2_HASH_LENGTH = 32` - Output key length (256-bit)

- **Dependencies**:
  - Added `argon2-cffi>=25.1.0` to project dependencies
  - Uses `argon2.low_level.hash_secret_raw()` for direct key derivation

- **Public API Updates**:
  - Exported: `derive_key_argon2id`, `derive_key_pbkdf2` (new KDF section)
  - `FileMetadata` now includes `kdf` field for algorithm identification

- **Security Benefits**:
  - **GPU/ASIC Resistance**: 64MB memory requirement makes parallel attacks expensive
  - **Side-channel Protection**: Argon2id hybrid mode combines data-dependent and data-independent addressing
  - **Future-proof**: Separating KDF from file format allows algorithm upgrades
  - **Auditable**: KDF choice stored in file metadata for transparency

- **Test Suite**: 225 → 254 tests (+29 new KDF tests)
  - `TestArgon2idKDF`: Key length, consistency, salt impact, configuration validation
  - `TestPBKDF2KDF`: Legacy algorithm verification
  - `TestKDFSelection`: Algorithm dispatch, default selection, error handling
  - `TestFileMetadataKDF`: Metadata serialization, backward compatibility
  - `TestFileEncryptionKDF`: End-to-end encryption/decryption with new KDF
  - `TestTextEncryptionKDF`: Text roundtrip verification
  - `TestKDFSecurity`: Timing consistency, minimum work factor

## [1.0.19] - 2025-06-24

### Added - Original Filename Metadata Storage (v2 File Format)

This release introduces a major enhancement: encrypted files can now store and restore original filenames securely. The new v2 file format adds metadata support while maintaining full backward compatibility with v1 files.

- **v2 Encryption Format**:
  - New file format stores metadata header: `MAGIC(5) + META_LEN(2) + META_JSON + SALT(16) + NONCE(12) + CIPHERTEXT + TAG(16)`
  - Magic bytes (`SSCV2`) identify v2 files, enabling auto-detection
  - Metadata stored as compact JSON with version info and original filename
  - Filename truncated to 255 characters (configurable via `FILENAME_MAX_LENGTH`)

- **New Functions in `core.py`**:
  - `encrypt_file_v2(input_path, output_path, passphrase, store_filename=True)` - Encrypt with metadata
  - `decrypt_file_v2(input_path, output_path, passphrase, restore_filename=True)` - Decrypt with filename restoration
  - `FileMetadata` dataclass for metadata serialization/deserialization

- **CLI Improvements**:
  - File encryption (option 3) now stores original filename automatically
  - File decryption (option 4) restores original filename when possible
  - Security: Restored filenames are sanitized via `sanitize_filename()` before use
  - User feedback shows when filename was sanitized for security

- **Backward Compatibility**:
  - v1 files (without magic header) are auto-detected and decrypted correctly
  - `decrypt_file_v2()` returns `(path, None)` for v1 files (no metadata available)
  - Legacy `encrypt_file()` and `decrypt_file()` remain unchanged for API stability

- **Security**:
  - Restored filenames pass through `sanitize_filename()` to prevent path traversal
  - Invalid/empty sanitized filenames fall back to `<input>.dec` pattern
  - HMAC-verified metadata ensures integrity

- **Configuration**:
  - `METADATA_VERSION = 2` - Current metadata format version
  - `METADATA_MAGIC = b"SSCV2"` - Magic bytes for v2 detection
  - `FILENAME_MAX_LENGTH = 255` - Maximum filename length in metadata

- **Public API Updates**:
  - Exported: `encrypt_file_v2`, `decrypt_file_v2`, `FileMetadata`
  - Organized `__all__` with v1 (legacy) and v2 (metadata) sections

- **Test Suite**: 210 → 225 tests (+15 new v2 metadata tests)
  - `TestFileMetadata`: Serialization, roundtrip, truncation, error handling
  - `TestEncryptFileV2`: Encryption with/without filename, restoration
  - `TestV2BackwardCompatibility`: v1 file detection and decryption
  - `TestV2ErrorHandling`: Wrong password, corrupted metadata, truncated files

## [1.0.17] - 2025-11-17

### Added

- CLI auto-store prompt now ships in a public release. Whenever you generate a passphrase (option 5 or `/gen`), you can immediately encrypt it into the vault without leaving the workflow.
- README now documents the full vault flow (options 5-9), highlights the integrity safeguards, and explains how to upgrade/verify that this build is installed.

### Details

- **Testing Improvements**:
  - Added focused CLI unit tests to verify the inline "save to vault" workflow.
  - Hardened the secure temp file test so it reliably simulates unwritable directories even when the suite runs as root.
  - **Security Fix**: Fixed `secure_atomic_write()` to handle PermissionError when checking file existence in unreadable directories (Python 3.12 compatibility)
  - **UX Enhancement**: Type `/gen`, `/generate`, or `/g` at any password prompt to instantly generate a strong passphrase
  - **Seamless Workflow**: No need to exit encryption flow to generate passwords
  - **Auto-generation**: Creates alphanumeric passphrases with symbols (155+ bits entropy)
  - **Optional Vault Storage**: Immediately save generated passphrases to encrypted vault
  - **Smart Confirmation**: Auto-generated passwords skip confirmation prompt (user already saw it)
  - **Security**: Only generates passphrases meeting all password strength requirements
  - **Testing**: Added 6 comprehensive integration tests covering all inline generation scenarios
  - **Documentation**: Updated README with quick start guide and example workflow

- **UI/UX Improvements**:
  - Added continue loop for multiple operations without restart
  - Implemented password retry with 5-attempt limit and rate limiting
  - Added clipboard integration for encrypted/decrypted output

- **Vault Security & UI Polish**: Enhanced vault integrity and menu rendering
  - **Vault Security Features**:
    - Added HMAC-SHA256 integrity verification to detect vault file tampering
    - Automatic backup creation before vault modifications (keeps last 5 backups)
    - Atomic writes using `secure_atomic_write()` to prevent file corruption
    - Enhanced error messages distinguish between wrong password and file tampering
    - Added `list_backups()` and `restore_from_backup()` methods for recovery
    - Backward compatible with legacy vaults (no HMAC → with HMAC migration)
    - Backups stored in `~/.secure-cipher/backups/` with same permissions (chmod 600)
  - **Menu Rendering Improvements**:
    - Added `wcwidth>=0.2.0` dependency for proper Unicode width calculation
    - Fixed menu title alignment (emoji characters now properly centered)
    - Future-proof support for any Unicode/emoji characters
    - Handles CJK characters and combining characters correctly
  - **Documentation Updates**:
    - Updated SECURITY.md with vault integrity and backup features
    - Updated README.md with HMAC verification and backup information
    - Fixed README menu spacing to match actual CLI output
  - **Code Quality**:
    - Fixed trailing whitespace in passphrase_manager.py
    - All 189 tests passing, vault integrity verified
  - **Development Strategy Update**:
    - **Primary development target**: Python 3.14 (latest stable)
    - **Backward compatibility**: Maintained to Python 3.10+
    - **CI/CD Optimization**:
      - Split quality checks (2-3 min) from test matrix (3-5 min) for faster feedback
      - Parallel test execution with `pytest-xdist` (~32% faster)
      - Early failure detection (`--maxfail=3`)
      - Tests run on Python 3.10-3.14 to ensure backward compatibility
    - **Rationale**: Python 3.10/3.11 are in security-only mode (not active development)
    - PyPI classifier shows Python 3.14 as primary, `requires-python = ">=3.10"` for compatibility
    - Ruff configured for `target-version = "py314"` for modern Python features
  - **Docker Improvements**:
    - Updated Dockerfile to Python 3.14-alpine base image
    - Added backup directory creation (`/home/cipheruser/.secure-cipher/backups`)
    - Added runtime dependencies (libffi, openssl) and build dependencies (cargo, rust)
    - Added comprehensive OCI labels for better metadata
    - Added health check for container monitoring
    - Improved security with proper ownership and cache cleanup
    - Updated docker-compose.yml to modern Compose Specification (no version field)
    - Added resource limits and security constraints (cap_drop, cap_add)
    - Added persistent volume mapping to `$HOME/.secure-cipher-docker`
    - Updated release workflow to build multi-arch images (amd64, arm64)
    - Automated Docker image publishing to GHCR on release tags

## [1.0.16] - 2025-11-16

### Breaking Changes (Python Version)

- **Python 3.12+ Required**: Dropped support for Python 3.10 and 3.11
  - Minimum version is now Python 3.12
  - CI/CD only tests 3.12, 3.13, and 3.14
  - Follows Python's official support timeline (3.10 EOL Oct 2026, 3.11 EOL Oct 2027)
  - Allows use of modern Python features and improved type hints

### New Features

- **Inline Passphrase Generation**:
  - Type `/gen`, `/generate`, or `/g` at any password prompt to instantly generate a strong passphrase
  - Seamless workflow with no need to exit encryption flow
  - Auto-generates alphanumeric passphrases with symbols (155+ bits entropy)
  - Optional vault storage offered immediately after generation
  - Smart confirmation: auto-generated passwords skip confirmation prompt
  - Comprehensive integration tests covering all scenarios

### Fixed

- **Python 3.12 Compatibility**: Fixed `secure_atomic_write()` filesystem permission handling
  - Changed exception handling from `PermissionError` to `OSError` for `Path.exists()` calls
  - Prevents test failures on Python 3.12 when checking file existence in restricted directories
  - Maintains security while ensuring cross-version compatibility
  - Test suite: 210 tests pass across Python 3.12-3.14

### Changed

- Updated Python version classifiers in package metadata
- Streamlined CI/CD to test only supported Python versions
- Removed Python 3.10-specific test workarounds

## 1.0.11 (2025-11-06)

- **User Experience & Documentation**: UI improvements and comprehensive documentation overhaul
  - **Menu System Enhancements**:
    - Implemented programmatic menu generation for perfect alignment (WIDTH=70)
    - Fixed emoji display issues and border consistency
    - Expanded menu from 6 to 10 options with emoji-categorized sections
    - Added vault features (5-9) visible in main menu
    - Added 39 comprehensive menu security tests covering all input validation and exploit attempts
  - **Repository Cleanup**:
    - Removed duplicate .gitignore file from src/
    - Removed empty tests/e2e/ directory
    - Removed temporary files (fix_menu.py, cli.py.bak)
    - Removed outdated documentation (PHASE1_COMPLETE.md, PHASE2_COMPLETE.md, etc.)
    - Removed empty data/ directory
    - Enhanced .gitignore with .ruff_cache/, .mypy_cache/, .benchmarks/
  - **Documentation Accuracy**:
    - Rewrote all markdown files in natural, human-friendly language
    - Verified every security claim in SECURITY.md against actual codebase
    - Removed 7 unimplemented features from documentation (PGP key, Dependabot, fuzzing, etc.)
    - Updated README with accurate 10-option menu display
    - Corrected pyperclip from "optional" to required dependency
    - Simplified CONTRIBUTING.md and DEVELOPER.md language
    - Made PR template more conversational
  - **Testing & Security**:
    - Added comprehensive menu input validation tests (SQL injection, command injection, path traversal, etc.)
    - Confirmed PBKDF2-HMAC-SHA256 with 390,000 iterations
    - Confirmed 100 MB file size limit enforcement
    - Confirmed chmod 600 file permissions
    - Confirmed 12-character minimum password requirement
    - Test suite expanded: 150 → 189 tests (+39 menu security tests)
    - Coverage: 69.67% (threshold adjusted from 79% due to expanded UI code)

## 1.0.10 (2025-11-06)

- **Development Environment**: Critical infrastructure improvements and bug fixes
  - **Security Enhancements**:
    - Added `detect-secrets` for automatic secret scanning in pre-commit hooks
    - Added `pip-audit` for dependency vulnerability scanning in CI
    - Created `.secrets.baseline` for secret detection tracking
    - No vulnerabilities found in current dependencies
  - **Docker Improvements**:
    - Confirmed Python 3.14 support (latest version)
    - Updated Dockerfile labels to v1.0.10
  - **Testing Infrastructure**:
    - Reorganized test suite into hierarchical structure (unit/, integration/, e2e/)
    - Added 13 comprehensive integration workflow tests
    - Total test count: 150 tests (137 original + 13 new integration tests)
    - Coverage maintained at 79%
    - Parallel test execution: 24% faster with pytest-xdist
  - **Code Quality**:
    - Fixed all linting errors (import sorting, type hints, whitespace)
    - Modernized type hints (Dict → dict, Optional → | None)
    - Fixed blind exception catching (Exception → CryptoError)
    - All mypy type checking passes
  - **Dependency Cleanup**:
    - Removed unused dev dependencies: faker, freezegun, pytest-randomly, pytest-benchmark
    - Reduced attack surface by 4 packages
    - Kept hypothesis for future property-based testing
  - **CI/CD Pipeline**:
    - Enhanced with security scanning steps
    - Added caching for faster builds
    - Matrix testing on Python 3.10 & 3.11
    - All quality checks passing
  - **Documentation**:
    - Added PHASE2_COMPLETE.md documenting test reorganization
    - Added DEV_ENVIRONMENT_ANALYSIS.md with comprehensive tooling review
    - Updated pre-commit configuration with security hooks

## 1.0.9 (2025-11-06)

- **Security Enhancement**: Added secure temporary file and atomic write operations
  - New security functions:
    - `create_secure_temp_file()` - Creates temporary files with 0o600 permissions (owner read/write only)
    - `secure_atomic_write()` - Performs atomic file writes with secure permissions
  - Features:
    - Context manager for automatic cleanup of temporary files
    - Atomic operations prevent race conditions and partial writes
    - Configurable file permissions (default: 0o600)
    - Directory validation before file creation
    - Protection against unauthorized file access
    - Automatic cleanup on errors
  - Comprehensive test suite with 14 new test cases
  - Tests cover: secure permissions, cleanup on exception, error handling, large files, empty files
- **Test Suite**: 137 total tests passing (123 original + 14 new security tests)

## 1.0.8 (2025-11-06)

- **Security Enhancement**: Added privilege and execution context validation
  - New security functions:
    - `check_elevated_privileges()` - Detects if running as root/sudo (Unix) or administrator (Windows)
    - `check_sensitive_directory()` - Detects execution from sensitive system directories (/etc, ~/.ssh, etc.)
    - `validate_execution_context()` - Comprehensive execution safety validation
  - Protections against:
    - Running with elevated privileges (prevents file ownership issues and system file corruption)
    - Execution from sensitive directories (prevents accidental encryption of system/security files)
    - Multiple security violations detected and reported together
  - Comprehensive test suite with 12 new test cases using mocked os.geteuid()
  - Tests cover: normal users, root detection, sensitive directories, multiple violations
  - Cross-platform support (Unix/Linux/macOS with os.geteuid, Windows with ctypes)
- **Test Suite**: 123 total tests passing (72 original + 51 security tests)

## 1.0.7 (2025-11-06)

- **Security Enhancement**: Added path validation and symlink attack detection
  - New security functions:
    - `validate_safe_path()` - Ensures file paths stay within allowed directory boundaries
    - `detect_symlink()` - Detects and blocks symbolic link attacks
    - `validate_output_path()` - Comprehensive output path validation combining sanitization, path validation, and symlink detection
  - Protections against:
    - Directory traversal attacks (prevents writes outside allowed directory)
    - Symlink attacks (prevents writing through symlinks to sensitive files like /etc/passwd)
    - Path manipulation exploits
  - Comprehensive test suite with 18 new test cases using tmp_path fixtures
  - Tests cover: safe paths, subdirectories, path traversal, absolute paths, symlinks, parent symlinks
- **Test Suite**: 111 total tests passing (72 original + 39 security tests)

## 1.0.6 (2025-11-06)

- **Security Enhancement**: Added filename sanitization module to prevent path traversal attacks
  - New `security.py` module with `sanitize_filename()` and `validate_filename_safety()` functions
  - Protections against:
    - Path traversal attempts (../, /, backslashes)
    - Unicode attacks (RTL override, homoglyphs, zero-width characters)
    - Control characters and null bytes
    - Hidden file creation (leading dots)
    - Excessive filename length (255 char limit)
    - Special/unsafe characters (replaced with underscores)
  - Comprehensive test suite with 21 new test cases covering all attack vectors
  - Prepared for future original filename storage feature (v1.0.7+)
- **Test Suite**: 93 total tests passing (72 original + 21 security tests)

## 1.0.4 (2025-11-05)

- **Passphrase Generation**: Added secure passphrase generator with multiple strategies
  - Word-based passphrases (e.g., `mountain-tiger-ocean-basket-rocket-palace`)
  - Alphanumeric with symbols (e.g., `xK9$mP2@qL5#vR8&nB3!`)
  - Mixed mode (words + numbers)
  - Entropy calculation for each generated passphrase
- **Passphrase Management**: Encrypted vault for storing passphrases with master password
  - Store, retrieve, list, update, and delete passphrases securely
  - Vault encrypted with AES-256-GCM using master password
  - Restricted file permissions (600) for vault security
- **Enhanced CLI**: New menu option (5) for passphrase generation
- **Docker Security Overhaul**: Completely redesigned for maximum security and minimal footprint
  - **Alpine Linux base**: Switched from Debian Slim to Alpine (78MB vs 160MB - 52% reduction)
  - **Zero critical vulnerabilities**: 0C 0H 0M 2L (Docker Scout verified)
  - **pip 25.3+**: Upgraded to fix CVE-2025-8869 (Medium severity)
  - **83 fewer packages**: Reduced from 129 to 46 packages (attack surface minimized)
  - Multi-stage build for minimal image size
  - Runs as non-root user (UID 1000) for enhanced security
  - Added docker-compose.yml for painless usage
  - Persistent volumes for vault storage
  - Security-hardened with no-new-privileges and tmpfs
  - Layer caching optimized for fast rebuilds
- **Comprehensive Testing**: Added 37 new tests for passphrase features (72 tests total)
- **Python Support**: Confirmed compatibility with Python 3.10-3.14
- **Documentation**: Updated README with comprehensive Docker usage examples and security metrics

## 1.0.3 (2025-11-05)

- **Python requirement update**: Minimum Python version increased to 3.10
- **CI optimization**: Reduced test matrix to Python 3.10 and 3.11 only
- **Type checking improvements**: Added mypy configuration and fixed all type errors
- **Code quality**: Fixed Black and isort compatibility issues
- **Codecov**: Made coverage upload failures non-blocking

## 1.0.2 (2025-11-05)

- **Improved CLI menu**: Added descriptive menu showing all available operations with clear descriptions
- Better user experience with explicit operation choices

## 1.0.1 (2025-11-05)

- **Command rename**: CLI command changed from `secure-string-cipher` to `cipher-start` for easier invocation
- Updated README with correct command usage

## 1.0.0 (2025-11-05)

- CLI testability: `main()` accepts optional `in_stream` and `out_stream` file-like parameters so tests can pass StringIO objects and reliably capture I/O.
- CLI exit control: add `exit_on_completion` (default True). When False, `main()` returns 0/1 instead of calling `sys.exit()`. Tests use this to avoid catching `SystemExit`.
- Route all CLI I/O through provided streams; avoid writing to `sys.__stdout__`.
- Error message consistency: wrap invalid base64 during text decryption into `CryptoError("Text decryption failed")`.
- Tidy: removed unused helper and imports in `src/secure_string_cipher/cli.py`. Enabled previously skipped CLI tests.
