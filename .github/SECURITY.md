# Security Policy

## Supported Versions

We provide security patches for these versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Reporting a Vulnerability

We take security bugs seriously. Thanks for helping us keep this project secure.

### How to Report

**Choose one of these methods:**

1. **GitHub Security Advisories** (preferred)
   - Go to [Security Advisories](https://github.com/TheRedTower/secure-string-cipher/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the private form

2. **Email**
   - Send to: **security@avondenecloud.uk**
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

This project implements several security measures:

1. **Cryptography**
   - AES-256-GCM for encryption (authenticated encryption mode)
   - PBKDF2-HMAC-SHA256 for key derivation (390,000 iterations)
   - Cryptographically secure random number generation

2. **Password Protection**
   - Minimum 12 characters required
   - Complexity requirements (mixed case, numbers, symbols)
   - Common password pattern detection
   - Constant-time password comparison to prevent timing attacks

3. **File Security**
   - 100 MB file size limit
   - Atomic file writes (no partial writes on failure)
   - Overwrite confirmation prompts
   - Secure file permissions (chmod 600 for vault files)
   - HMAC-SHA256 integrity verification (detects tampering)
   - Automatic backups before vault modifications (last 5 kept in `~/.secure-cipher/backups/`)

4. **Runtime Protection**
   - Input sanitization and validation
   - Secure memory wiping for sensitive data
   - Error messages don't leak sensitive information

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
   - Official PyPI: https://pypi.org/project/secure-string-cipher/
   - Maintainer: TheRedTower
   - Source code: https://github.com/TheRedTower/secure-string-cipher

3. **Check dependencies**
   ```bash
   pip show secure-string-cipher
   ```

### Using it Securely

1. **Passphrases**
   - Use strong, unique passphrases (12+ characters, mixed case, numbers, symbols)
   - Don't reuse passphrases across different files
   - Store passphrases in a password manager
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
   - `cryptography` - Industry-standard cryptographic library
   - `pyperclip` - Clipboard support
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

## Audit History

| Date       | Type       | Auditor  | Status    | Notes                   |
|------------|------------|----------|-----------|-------------------------|
| 2025-11-06 | Self-Audit | Internal | Completed | Initial security review |

## Contact

- **Security issues:** security@avondenecloud.uk
- **GitHub Security Advisories:** https://github.com/TheRedTower/secure-string-cipher/security/advisories
- **General support:** Open a GitHub issue (non-security only)

---

**Last updated:** November 6, 2025  
**Version:** 1.0
