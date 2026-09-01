# Security Policy

secure-string-cipher is currently **Beta**. It has not completed an independent
security audit and is not a stable release contract.

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          | Python Requirements |
| ------- | ------------------ | ------------------- |
| 1.3.x   | :white_check_mark: | 3.12+              |
| 1.2.x   | :white_check_mark: | 3.12+              |
| 1.1.x   | :white_check_mark: | 3.12+              |
| < 1.1.0 | :x:                | 3.10+              |

**Note**: Version 1.1.0+ uses Argon2id KDF and key commitment. Files encrypted with older versions are not compatible.

## Python Version Support Policy

We follow Python's official support timeline and drop support for versions that have reached end-of-life or are in security-only mode:

- **Python 3.10**: EOL October 2026 (no longer supported by this project)
- **Python 3.11**: EOL October 2027 (no longer supported by this project)
- **Python 3.12**: EOL October 2028 ✅
- **Python 3.13**: EOL October 2029 ✅
- **Python 3.14**: EOL October 2030 ✅

## Reporting a Vulnerability

We take security bugs seriously. Thanks for helping us keep this project secure.

### How to Report

**Choose one of these methods:**

1. **GitHub Security Advisories** (preferred)
   - Go to [Security Advisories](https://github.com/TheRedTower/secure-string-cipher/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the private form

2. **Email**
   - Send to: **<security@avondenecloud.uk>**
   - Don't create a public GitHub issue for vulnerabilities

### What to Include

- What's vulnerable and how it works
- Steps to reproduce the issue
- Potential impact
- Ideas for a fix (if you have them)

### What to Expect

1. **Initial response:** Within 24 hours
2. **Status updates:** At least every 72 hours
3. **Fix timeline:**
   - We'll publish a security advisory within 72 hours
   - Develop and test a fix within 1-2 weeks
   - Public disclosure after the fix is released (typically within 90 days)

## Security Features

This project implements multiple layers of security:

### 1. Cryptography

| Component | Implementation | Configuration |
|-----------|---------------|---------------|
| **Encryption** | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag |
| **Key Derivation** | Argon2id | 64MB memory, 3 iterations, parallelism 4 |
| **Key Commitment** | HMAC-SHA256 | Prevents partitioning oracle attacks |
| **Random Generation** | `secrets` module | OS-level CSPRNG |

**Argon2id parameters exceed OWASP 2024 recommendations** (minimum: 19MB memory, 2 iterations).

### 2. Password Protection

- **Minimum length**: 12 characters
- **Complexity requirements**: Mixed case, numbers, symbols
- **Common password detection**: Blocks known weak passwords
- **Constant-time comparison**: Prevents timing attacks
- **Local rate limiting**: CLI exponential backoff after failed attempts; copied
  ciphertext remains available for offline guessing

### 3. File Security

- **100 MiB plaintext limit** - Whole regular files are treated as opaque bytes;
  SSC framing overhead is additional. Active/candidate vault representations
  and legacy key files separately use the same value as their raw-input cap.
  Directories and other special files are unsupported
- **Opened-input enforcement** - Descriptor type/size checks happen before key
  derivation, and cumulative stream counters reject subsequent growth
- **Atomic final publication** - Existing outputs survive ordinary operation and
  authentication failures; `--force` never pre-deletes them. Same-directory
  temporary files are synced before replacement; parent-directory sync after
  replacement is best effort
- **Secure permissions** - `chmod 600` (owner-only read/write)
- **Path validation** - Best-effort lexical symlink preflight; hostile races
  remain pending descriptor-level hardening
- **Filename policy** - Stored names are bounded metadata, not paths. Version 5
  authenticates before automatic destination sanitization; version 4 names are
  ignored. Sanitization removes traversal components, separators, controls, and
  unsupported characters; it does not prevent Unicode homoglyphs

### 4. Vault Integrity

- **HMAC-SHA256 verification** - Detects tampering before decryption
- **Authenticated import/restore** - Strict framing, HMAC, encrypted payload,
  and decrypted JSON schema are validated before active-backend mutation
- **Transport boundary** - Core vault APIs require canonical six-line bytes.
  The CLI importer alone recovers exactly one legacy terminal LF or CRLF after a
  bounded read; no broad whitespace normalization is performed
- **Bound-consistent storage** - File active/backup/migration reads use opened
  regular descriptors and `limit + 1`; keychain text is incrementally counted
  in UTF-8 bytes, and oversize active values are never backed up or replaced
- **Transactional verification** - Current raw state is retained and backed up,
  replacement is read back and revalidated, and post-write failures attempt
  rollback
- **Automatic backups** - Five collision-resistant, stable identifiers are
  retained; a selected restore source and the new pre-replacement snapshot are
  protected from the same operation's rotation
- **Backend scope** - File publication is atomic. Native credential stores do
  not expose a multi-record transaction, so rollback there is best effort

### 5. Runtime Protection

- **Best-effort memory clearing** - Mutable managed buffers use libsodium when
  available, but Python may retain copied immutable values
- **Timing jitter** - Adds random delay to security operations
- **Input sanitization** - All user input validated
- **Audit logging** - Security events logged with timestamps

### 6. Audit Logging

Security-sensitive operations are logged to `~/.secure-cipher/audit.log`:

- Authentication successes/failures
- Rate limit triggers
- Encryption/decryption operations
- Vault access events
- Sensitive data automatically redacted

The log is editable local JSON with rotation. It is not cryptographically
chained, append-only, or tamper-evident.

### 7. Current Limitations

- Writer metadata version 5 authenticates `version`, `original_filename`, and
  `key_commitment`. `original_filename` is retained as bounded metadata and is
  sanitized only after authentication when choosing an automatic destination.
  Legacy version 4 metadata is unauthenticated, so its stored filename is never
  used to select an output path.
- Legacy key-file mode hashes file bytes into a symmetric passphrase. It is not
  public-key or recipient encryption; anyone with identical bytes can decrypt.
- Vault import and restore authenticate before mutation and verify after
  publication. Two simultaneous vault processes can still race because no
  cross-process lock exists.
- Overwrite-based deletion is best-effort and unreliable on SSD wear levelling,
  copy-on-write filesystems, snapshots, backups, and journals.

### 8. Tested Platform Boundary

The main CI workflow runs the general suite on Ubuntu with Python 3.12, 3.13,
and 3.14, and defines a focused safety matrix on Ubuntu, macOS, and Windows with
Python 3.12. The focused gate covers atomic publication, bounded regular-file
processing, failure cleanup, wrong-password preservation, empty/binary files,
metadata restoration, authentic v4/v5 fixtures, strict vault candidates, CLI
vault transport, and backend-independent vault transaction/rollback behavior.
A workflow definition is not evidence of a successful remote run; the
stabilization handoff records that status separately. Real OS keychain services
are not exercised by these isolated CI tests.

## For Contributors

When contributing:

1. **Dependencies**
   - Use latest stable versions
   - Check for security updates regularly
   - Run `pip-audit` for vulnerability scanning

2. **Code Review**
   - Security-focused reviews
   - Static analysis with Ruff and mypy
   - Test security edge cases

3. **Testing**
   - Write tests for security-critical code
   - Property-based tests with Hypothesis
   - Test edge cases and error conditions
   - Verify input validation

4. **Documentation**
   - Document security considerations
   - Include usage warnings where appropriate
   - Follow best practices

## User Security Guide

### Installing Safely

1. **Install from the official source**

   ```bash
   pip install secure-string-cipher
   ```

2. **Verify the package**
   - Official PyPI: <https://pypi.org/project/secure-string-cipher/>
   - Maintainer: TheRedTower
   - Source code: <https://github.com/TheRedTower/secure-string-cipher>

3. **Check dependencies**

   ```bash
   pip show secure-string-cipher
   ```

### Using it Securely

1. **Passphrases**
   - Use strong, unique passphrases (12+ characters, mixed case, numbers, symbols)
   - Use `/gen` at password prompts to generate secure passphrases
   - Don't reuse passphrases across different files
   - Store passphrases in a password manager or the built-in vault
   - Never share passphrases over insecure channels

2. **File Handling**
   - Store encrypted files in secure locations
   - Keep backups of encrypted files (but not with their passphrases)
   - Test decryption before deleting original files
   - Original files aren't automatically deleted after encryption

3. **Environment**
   - Use the tool on trusted, malware-free systems
   - Avoid shared or public computers
   - Clear your terminal history if it contains sensitive commands
   - Keep the software updated

## Supply Chain

### Dependencies

1. **What we depend on**
   - `cryptography` - Industry-standard cryptographic library (AES-GCM)
   - `argon2-cffi` - Argon2 implementation for key derivation
   - `pynacl` - libsodium bindings for secure memory
   - `pyperclip` - Clipboard support
   - `wcwidth` - Unicode width calculation
   - All from trusted, well-maintained sources

2. **How we vet dependencies**
   - Review dependencies for security issues
   - Run `pip-audit` for vulnerability scanning
   - Update promptly to address vulnerabilities

3. **Automated checks**
   - Pre-commit hooks with `detect-secrets` (prevents credential leaks)
   - CI/CD pipeline runs security checks on every commit
   - `pip-audit` scans for known vulnerabilities

### Software Bill of Materials

Generate an SBOM:

```bash
pip install cyclonedx-bom
cyclonedx-py -r --format json -o sbom.json
```

Or view the dependency tree:

```bash
pip install pipdeptree
pipdeptree -p secure-string-cipher
```

## Review Materials

No independent third-party audit has been completed. The project maintains
materials intended to support future review:

- **[CRYPTOGRAPHY.md](.github/CRYPTOGRAPHY.md)** - Detailed cryptographic design and threat model
- **[AUDIT_CHECKLIST.md](.github/AUDIT_CHECKLIST.md)** - Review checklist

## Contact

- **Security issues:** <security@avondenecloud.uk>
- **GitHub Security Advisories:** <https://github.com/TheRedTower/secure-string-cipher/security/advisories>
- **General support:** Open a GitHub issue (non-security only)

---

**Last updated:** August 29, 2026
**Version:** 2.3 Beta
