# Cryptographic Design Document

This document describes the current Beta cryptographic design for review. It is
not a claim that secure-string-cipher has completed an independent audit or is
stable.

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Key Derivation](#key-derivation)
5. [Encryption Scheme](#encryption-scheme)
6. [Key Commitment](#key-commitment)
7. [File Format](#file-format)
8. [Vault Security](#vault-security)
9. [Side-Channel Protections](#side-channel-protections)
10. [Security Assumptions](#security-assumptions)
11. [Known Limitations](#known-limitations)

---

## Overview

secure-string-cipher is a password-based encryption tool using:

- **AES-256-GCM** for authenticated encryption
- **Argon2id** for password-based key derivation
- **HMAC-SHA256** for key commitment and vault integrity

The design prioritizes:

1. Resistance to offline brute-force attacks (Argon2id)
2. Authenticated encryption (GCM tags)
3. Resistance to partitioning oracle attacks (key commitment)
4. Side-channel resistance (constant-time operations)

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| **Offline password cracking** | Argon2id with 64MB memory, 3 iterations |
| **Ciphertext tampering** | AES-GCM authentication tags |
| **Partitioning oracle attacks** | HMAC-SHA256 key commitment |
| **Timing attacks on password comparison** | Constant-time comparison |
| **Vault file tampering** | HMAC-SHA256 integrity verification |
| **Online CLI password guessing** | Local rate limiting with exponential backoff |
| **Accidental path misuse** | Best-effort lexical validation and symlink preflight |
| **Some mutable-buffer residue** | Best-effort clearing via libsodium where available |

### Out of Scope

| Threat | Reason |
|--------|--------|
| **Malware on the system** | Cannot defend against compromised OS |
| **Physical access attacks** | Cold boot, hardware keyloggers |
| **Social engineering** | User education, not technical control |
| **Quantum computing** | AES-256 provides ~128-bit post-quantum security for symmetric encryption; Argon2id output is vulnerable to Grover's algorithm but 256-bit keys maintain adequate security margins |
| **Traffic analysis** | File sizes visible in encrypted output |
| **Offline password guessing** | Local CLI rate limiting cannot affect copied ciphertext |
| **Hostile path races** | Descriptor-level opening is not yet implemented |

### Assumptions

1. The underlying cryptographic libraries (`cryptography`, `argon2-cffi`, `pynacl`) are correctly implemented
2. The operating system's CSPRNG (`secrets` module) is secure
3. The user's system is not compromised
4. The user chooses a strong passphrase (enforced by password policy)

---

## Cryptographic Primitives

### AES-256-GCM

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Key size | 256 bits | Maximum AES security level |
| Nonce size | 96 bits | GCM recommended size |
| Tag size | 128 bits | Full authentication security |
| Mode | GCM | AEAD with wide hardware support |

**Implementation:** the streaming `Cipher(..., modes.GCM(...))` interface from
`cryptography`.

**Nonce generation:** Fresh random nonce for each encryption via `secrets.token_bytes(12)`

**Security note:** With 96-bit random nonces, collision probability reaches 2^-32 after ~2^32 encryptions with the same key. Our use case (file encryption with unique passphrases) stays well below this threshold.

### Argon2id

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Time cost | 3 iterations | OWASP 2024 recommendation |
| Memory cost | 64 MiB | Exceeds OWASP minimum (19 MiB) |
| Parallelism | 4 threads | Typical desktop CPU |
| Output length | 32 bytes | 256-bit key for AES |
| Salt size | 16 bytes | 128-bit unique salt |

**Implementation:** `argon2-cffi` library (reference implementation bindings)

**Why Argon2id:** Combines Argon2i (side-channel resistant) and Argon2d (GPU-resistant) for hybrid protection. Winner of the Password Hashing Competition (2015).

**Salt generation:** Fresh random salt for each encryption via `secrets.token_bytes(16)`

### HMAC-SHA256

Used for:

1. **Key commitment** - Binds ciphertext to specific key
2. **Vault integrity** - Detects tampering before decryption

| Parameter | Value |
|-----------|-------|
| Hash function | SHA-256 |
| Output size | 256 bits |
| Key size | 256 bits (derived key) |

**Implementation:** `cryptography.hazmat.primitives.hmac.HMAC`

---

## Key Derivation

### Process

```text
passphrase (UTF-8 bytes)
        │
        ▼
┌───────────────────┐
│     Argon2id      │◄── salt (16 random bytes)
│  time=3, mem=64MB │
│  parallelism=4    │
└───────────────────┘
        │
        ▼
   key (32 bytes)
```

### Key Derivation Code

```python
# src/secure_string_cipher/core.py
def derive_key(passphrase: str, salt: bytes) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,      # 3
        memory_cost=ARGON2_MEMORY_COST,  # 65536 KiB
        parallelism=ARGON2_PARALLELISM,  # 4
        hash_len=ARGON2_HASH_LENGTH,     # 32
        type=argon2.low_level.Type.ID,
    )
```

### Security Analysis

- **Memory hardness:** 64 MiB prevents GPU/ASIC attacks (GPUs have limited per-core memory)
- **Time hardness:** 3 iterations provide ~0.5-1.0 second derivation on modern CPUs
- **Salt uniqueness:** Random 128-bit salt prevents rainbow tables
- **Parallelism:** Matches typical desktop CPUs; attackers gain no advantage from more cores

---

## Encryption Scheme

### Text Encryption

```text
plaintext
    │
    ▼
┌────────────────┐
│  UTF-8 encode  │
└────────────────┘
    │
    ▼
┌────────────────┐
│  Generate salt │──► salt (16 bytes)
└────────────────┘
    │
    ▼
┌────────────────┐
│  Derive key    │◄── passphrase
└────────────────┘
    │
    ▼
┌────────────────┐
│ Generate nonce │──► nonce (12 bytes)
└────────────────┘
    │
    ▼
┌────────────────┐
│  AES-256-GCM   │
│   encrypt      │
└────────────────┘
    │
    ▼
salt ║ nonce ║ ciphertext ║ tag
    │
    ▼
┌────────────────┐
│  Base64 encode │
└────────────────┘
    │
    ▼
  output string
```

### File Encryption

File encryption uses a structured format with metadata:

```text
┌─────────────────────────────────────────────────────────────┐
│ MAGIC (5 bytes): "SSCV2"                                    │
├─────────────────────────────────────────────────────────────┤
│ METADATA_LENGTH (2 bytes): Big-endian uint16                │
├─────────────────────────────────────────────────────────────┤
│ METADATA (JSON): version, original_filename,                │
│                  key_commitment                             │
├─────────────────────────────────────────────────────────────┤
│ SALT (16 bytes)                                             │
├─────────────────────────────────────────────────────────────┤
│ NONCE (12 bytes)                                            │
├─────────────────────────────────────────────────────────────┤
│ CIPHERTEXT (variable)                                       │
├─────────────────────────────────────────────────────────────┤
│ TAG (16 bytes)                                              │
└─────────────────────────────────────────────────────────────┘
```

### Decryption Process

1. Parse magic bytes, verify format
2. Read metadata length and metadata JSON
3. Read salt, derive key from passphrase
4. **Verify key commitment** (fast-fail on wrong password)
5. Read nonce
6. Decrypt ciphertext with AES-GCM (verifies tag)
7. Return plaintext

---

## Key Commitment

### Problem: Partitioning Oracle Attacks

Without key commitment, an attacker can craft a ciphertext that decrypts to different valid plaintexts under different keys. This enables:

- **Invisible salamanders attack:** Same ciphertext, different plaintext per recipient
- **Partitioning oracles:** Learn which key was used by observing decryption success/failure

### Solution: HMAC-SHA256 Key Commitment

Before encryption, compute a commitment value:

```python
commitment = HMAC-SHA256(key, KEY_COMMITMENT_CONTEXT)
```

Where `KEY_COMMITMENT_CONTEXT = b"secure-string-cipher-v1-key-commitment"`

Store the commitment in metadata. During decryption:

1. Derive key from passphrase
2. Compute commitment
3. Compare with stored commitment (constant-time)
4. If mismatch, reject immediately (before GCM decryption)

### Security Properties

- **Binding:** Ciphertext is bound to exactly one key
- **Fast rejection:** Wrong passwords fail at commitment check, not GCM tag
- **Constant-time:** Comparison uses `hmac.compare_digest()`

### Key Commitment Code

```python
# src/secure_string_cipher/core.py
def compute_key_commitment(key: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(KEY_COMMITMENT_CONTEXT)
    return h.finalize()

def verify_key_commitment(key: bytes, expected: bytes) -> bool:
    computed = compute_key_commitment(key)
    return hmac.compare_digest(computed, expected)
```

---

## File Format

### Versions 5 and 4

> **Note:** The magic bytes `SSCV2` identify the file format structure (with metadata header).
> The current writer emits metadata version 5. Version 4 remains readable.

| Field | Size | Description |
|-------|------|-------------|
| Magic | 5 bytes | `SSCV2` (identifies file format structure) |
| Meta length | 2 bytes | Big-endian uint16 |
| Metadata | Variable | JSON with version, original_filename, key_commitment |
| Salt | 16 bytes | Argon2id salt |
| Nonce | 12 bytes | AES-GCM nonce |
| Ciphertext | Variable | Encrypted file content |
| Tag | 16 bytes | GCM authentication tag |

### Metadata Schema

```json
{
  "version": 5,
  "original_filename": "document.pdf",
  "key_commitment": "base64-encoded-hmac"
}
```

### Format Evolution

| Version | KDF | Key Commitment | Notes |
|---------|-----|----------------|-------|
| 1 | PBKDF2 | No | Legacy, unsupported |
| 2 | PBKDF2 | No | Legacy, unsupported |
| 3 | Argon2id | No | Transitional |
| 4 | Argon2id | Yes | Legacy; metadata is not GCM-authenticated and its filename is never trusted for output selection |
| 5 | Argon2id | Yes | Current writer; metadata is AES-GCM additional authenticated data |

The v4/v5 salt, nonce, tag, KDF parameters, AES-GCM behavior, header ordering,
and tag placement are otherwise unchanged by the atomic-publication hardening.

Authentic immutable compatibility fixtures are stored under
`tests/fixtures/legacy/`. Version 4 was produced by tag `v1.2.10` at commit
`f7e3fc797e737ddfdd2a27d28cafec6dc5d710cb`; version 5 was produced by tag
`v1.3.0` at commit `f7ff04c4d5a0adc0cbdc3cb841d5048f2f14dcac`.
The manifest records producer environments and SHA-256 hashes. Their shared
1,094,205-byte binary payload crosses four 256 KiB streaming chunks.

---

## Vault Security

The passphrase vault stores encrypted passphrases for user convenience.

### Vault Structure

```text
SSCVAULT
<32-byte HMAC salt as 64 lowercase hex characters>
---DATA---
<strict Base64 encrypted-text token>
---HMAC---
<32-byte HMAC as 64 lowercase hex characters>
```

The decrypted encrypted-text payload must be one JSON object with unique string
keys and string values. The released six-line format has no version, size, or
entry-count field; readers do not invent limits that would reject an authentic
released vault. Import file buffering is separately limited to 100 MiB.

### Integrity Verification and Recovery

Candidate validation is side-effect free and completes before active storage is
read or written:

1. Parse exactly six lines with strict separators, lowercase hex, and Base64.
2. Derive the HMAC key with Argon2id and compare HMACs in constant time.
3. Authenticate/decrypt the encrypted-text token.
4. Strictly decode the JSON object and reject duplicates or non-string entries.
5. Retain and back up the current raw active vault.
6. Publish through the configured backend, read back exact contents, and run the
   same validation again.
7. On any post-write failure, restore the retained raw value (or prior absence)
   and report whether rollback succeeded.

### Backup Strategy

- Collision-resistant identifiers combine UTC microseconds with a random suffix.
- The newest five records are retained; the selected restore source and newly
  published pre-replacement snapshot are protected during rotation.
- Backups contain the exact raw encrypted vault representation, use atomic
  no-overwrite publication, and use mode `0600` on POSIX.
- File-backend active writes are atomically replaced. Native credential stores
  provide no multi-record transaction, so rollback there is best effort.
- No cross-process vault lock exists; simultaneous processes can still race.

---

## Side-Channel Protections

### Timing Attacks

| Operation | Protection |
|-----------|------------|
| Password comparison | `hmac.compare_digest()` |
| Key commitment verification | `hmac.compare_digest()` |
| HMAC verification | `hmac.compare_digest()` |

All sensitive comparisons use constant-time functions that don't leak information through timing.

### Memory Protection

When PyNaCl (libsodium) is available, mutable managed buffers are cleared on a
best-effort basis:

- `SecureString`: Auto-zeros memory on deletion
- `SecureBytes`: Auto-zeros memory on deletion
- Uses `sodium_memzero()` for secure wiping

**Limitation:** Python strings are immutable and the interpreter or libraries
may create copies. Clearing cannot guarantee removal of every secret copy.

### Timing Jitter

Security-critical operations add random microsecond delays to obscure timing patterns:

```python
def add_timing_jitter(max_microseconds: int = 1000) -> None:
    time.sleep(secrets.randbelow(max_microseconds) / 1_000_000)
```

---

## Security Assumptions

### Cryptographic Assumptions

1. **AES-256 is secure:** No practical attacks on AES with 256-bit keys
2. **GCM mode is secure:** Polynomial hash + CTR provides AEAD
3. **Argon2id is secure:** Memory-hard, resistant to TMTO attacks
4. **HMAC-SHA256 is a PRF:** Secure for key commitment and integrity
5. **SHA-256 is collision-resistant:** Used for content hashing

### Environmental Assumptions

1. **CSPRNG is secure:** `secrets.token_bytes()` uses OS entropy
2. **Libraries are correct:** `cryptography`, `argon2-cffi`, `pynacl`
3. **No malware:** System is not compromised
4. **Strong passphrase:** User follows password policy (12+ chars, complexity)

### Trust Boundaries

```text
┌─────────────────────────────────────────────────────────┐
│                    TRUSTED                              │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │ OS CSPRNG     │  │ Crypto libs   │  │ Python      │  │
│  │ (secrets)     │  │ (cryptography)│  │ runtime     │  │
│  └───────────────┘  └───────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              secure-string-cipher                       │
│  • Key derivation logic                                 │
│  • Encryption/decryption orchestration                  │
│  • Input validation                                     │
│  • File format handling                                 │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    UNTRUSTED                            │
│  • User input (passphrase, filenames)                   │
│  • Encrypted files (may be tampered)                    │
│  • Network (not used, but files may traverse)           │
└─────────────────────────────────────────────────────────┘
```

---

## Known Limitations

### 1. Python Memory Model

Python strings are immutable; the garbage collector may copy sensitive data. Mitigations:

- Use `SecureBytes`/`SecureString` with libsodium when available
- Minimize passphrase lifetime in memory
- Check `has_secure_memory()` for libsodium availability

### 2. No Forward Secrecy

If a passphrase is compromised, all files encrypted with it can be decrypted. Mitigation:

- Use unique passphrases per file when security is critical
- Rotate passphrases periodically

### 3. Metadata Leakage

Encrypted file metadata is visible before authentication. The optional original
filename is visible, and total object length leaks approximate plaintext size.
Mitigations:

- Content is fully encrypted
- Filename can be randomized before encryption
- Size padding not implemented (would increase storage)

### 4. Single-User Design

No support for:

- Multiple recipients
- Public key encryption
- Key escrow

This is intentional for simplicity. Use GPG/age for multi-recipient scenarios.

### 5. No Hardware Security Module Support

Keys exist only in software memory. For HSM requirements, consider:

- PKCS#11 integration (not implemented)
- Hardware tokens (not implemented)

### 6. Beta File and Filesystem Scope

Whole regular files of any internal format are encrypted as opaque bytes up to
100 MiB. Directories and large framed SSC2 objects are not supported. Final
outputs are atomically replaced only after successful encryption or
authenticated decryption, which protects against ordinary operation failures.
Temporary files are synced before replacement. Parent-directory sync after
replacement is best effort. Hostile concurrent path races remain under
hardening.

### 7. Legacy Key Files and Local Controls

Legacy key-file mode hashes file bytes into a symmetric passphrase. It is not
RSA, recipient, or public-key encryption; identical bytes grant decryption.
Local rate limiting does not stop offline guessing. Audit events are editable
local JSON rather than a tamper-evident log.

### 8. Vault Concurrency and Native Backends

Vault import/restore verifies before and after publication and attempts rollback
after post-write failure. File writes use same-directory atomic replacement;
keychain/native credential-store rollback is best effort. There is no
cross-process vault lock, and CI does not exercise real OS credential services.

---

## References

1. **AES-GCM:** NIST SP 800-38D
2. **Argon2:** RFC 9106
3. **HMAC:** RFC 2104
4. **Password Storage:** OWASP Password Storage Cheat Sheet 2024
5. **Key Commitment:** "Partitioning Oracle Attacks" (Len, Grubbs, Ristenpart 2021)

---

**Document version:** 1.1
**Last updated:** December 5, 2025
