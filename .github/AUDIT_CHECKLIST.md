# Security Audit Checklist

This checklist is designed for third-party security auditors reviewing secure-string-cipher.

## Quick Reference

| Component | File | Lines |
|-----------|------|-------|
| Key derivation | `src/secure_string_cipher/core.py` | `derive_key()` |
| Encryption | `src/secure_string_cipher/core.py` | `encrypt_file()`, `encrypt_text()` |
| Key commitment | `src/secure_string_cipher/core.py` | `compute_key_commitment()`, `verify_key_commitment()` |
| Vault security | `src/secure_string_cipher/passphrase_manager.py` | `PassphraseVault` |
| Secure memory | `src/secure_string_cipher/secure_memory.py` | `SecureString`, `SecureBytes` |
| Timing safety | `src/secure_string_cipher/timing_safe.py` | `constant_time_compare()` |
| Input validation | `src/secure_string_cipher/security.py` | `sanitize_filename()`, `validate_safe_path()` |
| Rate limiting | `src/secure_string_cipher/rate_limiter.py` | `RateLimiter` |
| Audit logging | `src/secure_string_cipher/audit_log.py` | `AuditLogger` |
| Configuration | `src/secure_string_cipher/config.py` | Constants |

---

## 1. Cryptographic Implementation

### 1.1 Key Derivation (CRITICAL)

- [ ] **Argon2id parameters are correct**
  - File: `config.py`
  - Expected: `time_cost=3`, `memory_cost=65536`, `parallelism=4`, `hash_len=32`
  - Verify parameters meet/exceed OWASP 2024 recommendations

- [ ] **Salt generation is cryptographically secure**
  - File: `core.py`
  - Expected: `secrets.token_bytes(16)` for each encryption
  - Verify no salt reuse

- [ ] **Key derivation uses correct algorithm**
  - File: `core.py`, function `derive_key()`
  - Expected: `argon2.low_level.hash_secret_raw()` with `Type.ID`

### 1.2 Encryption (CRITICAL)

- [ ] **AES-256-GCM is used correctly**
  - File: `core.py`
  - Expected: `AESGCM(key)` where key is 32 bytes
  - Verify nonce is 12 bytes, generated fresh per encryption

- [ ] **Nonce is never reused**
  - File: `core.py`
  - Expected: `secrets.token_bytes(12)` for each encryption
  - Check: No nonce reuse with same key

- [ ] **Authentication tag is verified**
  - File: `core.py`
  - Expected: `AESGCM.decrypt()` raises `InvalidTag` on tampering
  - Verify tag is not stripped or ignored

### 1.3 Key Commitment (HIGH)

- [ ] **Key commitment is computed correctly**
  - File: `core.py`, function `compute_key_commitment()`
  - Expected: `HMAC(key, KEY_COMMITMENT_CONTEXT)` using SHA-256

- [ ] **Key commitment is verified before decryption**
  - File: `core.py`, function `decrypt_file()`
  - Expected: `verify_key_commitment()` called before `AESGCM.decrypt()`

- [ ] **Commitment verification is constant-time**
  - File: `core.py`, function `verify_key_commitment()`
  - Expected: Uses `hmac.compare_digest()`

---

## 2. Side-Channel Protections

### 2.1 Timing Attacks (HIGH)

- [ ] **Password comparison is constant-time**
  - File: `timing_safe.py`, function `constant_time_compare()`
  - Expected: Uses `hmac.compare_digest()` or equivalent

- [ ] **All security-critical comparisons are constant-time**
  - Files: `core.py`, `passphrase_manager.py`, `timing_safe.py`
  - Check: HMAC verification, password verification, key commitment

- [ ] **Timing jitter is added to sensitive operations**
  - File: `timing_safe.py`, function `add_timing_jitter()`
  - Verify: Used in authentication paths

### 2.2 Memory Security (MEDIUM)

- [ ] **Secure memory wiping is implemented**
  - File: `secure_memory.py`
  - Expected: Uses `sodium_memzero()` via PyNaCl when available

- [ ] **SecureString/SecureBytes auto-clear on deletion**
  - File: `secure_memory.py`
  - Check: `__del__` method zeros memory

- [ ] **Fallback behavior is documented**
  - When libsodium unavailable, document limitations
  - Check: `has_secure_memory()` function exists

---

## 3. Input Validation

### 3.1 Path Security (HIGH)

- [ ] **Path traversal is prevented**
  - File: `security.py`, function `validate_safe_path()`
  - Test: `../`, `..\\`, absolute paths outside allowed directory

- [ ] **Symlink attacks are detected**
  - File: `security.py`, function `detect_symlink()`
  - Expected: Rejects or warns on symlinks

- [ ] **Filename sanitization removes dangerous characters**
  - File: `security.py`, function `sanitize_filename()`
  - Test: Null bytes, path separators, Unicode normalization

### 3.2 Password Policy (MEDIUM)

- [ ] **Minimum length enforced**
  - File: `config.py`, constant `MIN_PASSWORD_LENGTH`
  - Expected: 12 characters minimum

- [ ] **Complexity requirements enforced**
  - File: `timing_safe.py`, function `check_password_strength()`
  - Expected: Mixed case, digits, symbols required

- [ ] **Common passwords rejected**
  - File: `config.py`, constant `COMMON_PASSWORDS`
  - Verify: List includes common weak passwords

---

## 4. Authentication & Access Control

### 4.1 Rate Limiting (HIGH)

- [ ] **Rate limiter tracks failed attempts**
  - File: `rate_limiter.py`, class `RateLimiter`
  - Expected: Per-operation, per-identifier tracking

- [ ] **Exponential backoff implemented**
  - File: `rate_limiter.py`
  - Expected: Lockout duration increases with repeated failures

- [ ] **Thread safety**
  - File: `rate_limiter.py`
  - Expected: Uses threading locks for concurrent access

### 4.2 Vault Security (HIGH)

- [ ] **Vault HMAC prevents tampering**
  - File: `passphrase_manager.py`
  - Expected: HMAC verified before decryption

- [ ] **Vault file permissions are restrictive**
  - File: `passphrase_manager.py`
  - Expected: `chmod 600` (owner-only)

- [ ] **Backups are created before modifications**
  - File: `passphrase_manager.py`, method `_create_backup()`
  - Expected: Backup created before any write

---

## 5. Error Handling

### 5.1 Information Leakage (MEDIUM)

- [ ] **Error messages don't reveal sensitive data**
  - All files
  - Check: No passwords, keys, or plaintexts in error messages

- [ ] **Decryption failures are generic**
  - File: `core.py`
  - Expected: Same error for wrong password vs. corrupted file

- [ ] **Audit logs redact sensitive fields**
  - File: `audit_log.py`
  - Check: `password`, `passphrase`, `key`, `plaintext` redacted

### 5.2 Exception Safety (MEDIUM)

- [ ] **Atomic file writes prevent corruption**
  - File: `security.py`, function `secure_atomic_write()`
  - Expected: Write to temp file, then atomic rename

- [ ] **Resources are cleaned up on error**
  - All files
  - Check: Context managers, try/finally blocks

---

## 6. Configuration Security

### 6.1 Constants Review (HIGH)

- [ ] **Cryptographic constants are correct**
  - File: `config.py`
  - Review:
    - `SALT_SIZE = 16`
    - `NONCE_SIZE = 12`
    - `TAG_SIZE = 16`
    - `ARGON2_HASH_LENGTH = 32`
    - `KEY_COMMITMENT_SIZE = 32`

- [ ] **Security limits are reasonable**
  - File: `config.py`
  - Review:
    - `MAX_FILE_SIZE = 100 * 1024 * 1024` (100 MiB plaintext payload;
      separately the raw vault/key-file ingestion cap)
    - `MIN_PASSWORD_LENGTH = 12`

### 6.2 Hardcoded Secrets (CRITICAL)

- [ ] **No hardcoded keys or passwords**
  - All files
  - Run: `detect-secrets scan`

- [ ] **No backdoors or debug code**
  - All files
  - Check: No bypass mechanisms

---

## 7. Dependencies

### 7.1 Dependency Security (HIGH)

- [ ] **Run vulnerability scan**

  ```bash
  pip-audit
  ```

- [ ] **Review dependency versions**
  - File: `pyproject.toml`
  - Check: `cryptography>=41.0.0`, `argon2-cffi>=25.1.0`, `pynacl>=1.5.0`

- [ ] **No unnecessary dependencies**
  - Review: Each dependency is required for functionality

---

## 8. Testing Coverage

### 8.1 Security Tests (HIGH)

- [ ] **Property-based tests exist**
  - File: `tests/unit/test_property_based.py`
  - Check: Cryptographic invariants tested with Hypothesis

- [ ] **Negative tests exist**
  - Check: Wrong password, corrupted files, invalid input

- [ ] **Boundary tests exist**
  - Check: Empty files, max size files, edge cases

### 8.2 Coverage Report

```bash
make test-cov
```

- [ ] **Coverage meets threshold (69%)**
- [ ] **Critical paths are covered**

---

## 9. File Format

### 9.1 Format Parsing (HIGH)

- [ ] **Magic bytes validated**
  - File: `core.py`
  - Expected: `SSCV2` at file start

- [ ] **Metadata length bounds checked**
  - File: `core.py`
  - Check: Integer overflow, excessive length

- [ ] **JSON parsing is safe**
  - File: `core.py`
  - Check: No arbitrary code execution

---

## 10. Operational Security

### 10.1 Audit Logging (MEDIUM)

- [ ] **Security events are logged**
  - File: `audit_log.py`
  - Check: Auth failures, rate limits, encryption/decryption

- [ ] **Log rotation is configured**
  - File: `audit_log.py`
  - Expected: Max size limit, backup count

### 10.2 Runtime Checks (MEDIUM)

- [ ] **Elevated privilege check**
  - File: `security.py`, function `check_elevated_privileges()`
  - Expected: Warns/exits when running as root

---

## Audit Sign-Off

| Section | Auditor | Date | Status |
|---------|---------|------|--------|
| 1. Cryptographic Implementation | | | ☐ |
| 2. Side-Channel Protections | | | ☐ |
| 3. Input Validation | | | ☐ |
| 4. Authentication & Access Control | | | ☐ |
| 5. Error Handling | | | ☐ |
| 6. Configuration Security | | | ☐ |
| 7. Dependencies | | | ☐ |
| 8. Testing Coverage | | | ☐ |
| 9. File Format | | | ☐ |
| 10. Operational Security | | | ☐ |

**Overall Assessment:** ☐ Pass ☐ Pass with findings ☐ Fail

**Auditor Signature:** _________________________

**Date:** _________________________

---

## Findings Template

### Finding #X: [Title]

**Severity:** Critical / High / Medium / Low / Informational

**Location:** `file.py`, line X

**Description:**

**Impact:**

**Recommendation:**

**Status:** Open / Fixed / Won't Fix

---

**Document version:** 1.0
**Last updated:** December 2, 2025
