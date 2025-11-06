# Security Policy

## Supported Versions

We release security patches for the following versions:

| Version | Supported          |
| ------- | ----------------- |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report a Security Vulnerability

**Please use one of these secure reporting methods:**

1. **GitHub Security Advisories** (Preferred)
   - Navigate to [Security Advisories](https://github.com/TheRedTower/secure-string-cipher/security/advisories)
   - Click "Report a vulnerability"
   - Fill in the private advisory form

2. **Email Disclosure**
   - Send your findings to: **security@avondenecloud.uk**
   - **DO NOT** create a public GitHub issue for the vulnerability

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if possible)

### What to Expect

1. **Acknowledgment**: We aim to acknowledge receipt within 24 hours.
2. **Updates**: We'll provide updates at least every 72 hours.
3. **Timeline**: 
   - Initial response: 24 hours
   - Security advisory: 72 hours
   - Fix development: 1-2 weeks
   - Public disclosure: After fix is validated and released (typically 90 days from initial report or when fix is deployed, whichever is sooner)

## Security Measures

This project implements several security measures:

1. **Cryptographic Operations**
   - AES-256-GCM for encryption
   - PBKDF2-HMAC-SHA256 for key derivation
   - Secure random number generation
   - Authenticated encryption

2. **Password Security**
   - Minimum length requirements
   - Complexity validation
   - Common password checking
   - Secure password input

3. **File Security**
   - File size limits (100 MB default)
   - Safe file operations with atomic writes
   - Overwrite protection (prompts before overwriting)
   - Secure file permissions (0o600)

4. **Runtime Security**
   - Input validation and sanitization
   - Memory wiping for sensitive data
   - Error handling without information leakage

## Development Security

When contributing:

1. **Dependencies**
   - Use latest stable versions
   - Regular security updates
   - Vulnerability scanning

2. **Code Review**
   - Security-focused review
   - Static analysis
   - Dynamic testing

3. **Testing**
   - Security test cases
   - Edge cases
   - Error conditions

4. **Documentation**
   - Security considerations
   - Usage warnings
   - Best practices

## Security Best Practices for Users

### Package Verification

1. **Install from Official Source**
   ```bash
   # Install from PyPI
   pip install secure-string-cipher
   ```

2. **Check Package Source**
   - Always install from official PyPI: https://pypi.org/project/secure-string-cipher/
   - Verify the package author: TheRedTower
   - Check the GitHub repository: https://github.com/TheRedTower/secure-string-cipher

3. **Review Dependencies**
   ```bash
   pip show secure-string-cipher
   ```

### Safe Usage Practices

1. **Passphrase Management**
   - Use strong, unique passphrases (12+ characters, mixed case, numbers, symbols)
   - Never reuse passphrases across different encrypted files
   - Store passphrases securely (use a password manager)
   - Never share passphrases via insecure channels

2. **File Handling**
   - Store encrypted files in secure locations
   - Maintain backups of encrypted files (but never store passphrases with them)
   - Test decryption before deleting original files
   - Be aware that original files are not automatically securely deleted

3. **Environment Security**
   - Use the tool on trusted, malware-free systems
   - Avoid using on shared or public computers
   - Clear terminal history after use if it contains sensitive data
   - Keep the software updated to the latest version

## Supply Chain Security

### Dependency Management

1. **Dependency Vetting**
   - All dependencies are reviewed for security issues
   - We use `pip-audit` for vulnerability scanning
   - Regular updates to address known vulnerabilities

2. **Minimal Dependencies**
   - Core dependencies: 
     - `cryptography` (industry-standard cryptographic library)
     - `pyperclip` (clipboard support)
   - All dependencies are from trusted, well-maintained sources

3. **Automated Scanning**
   - Pre-commit hooks with `detect-secrets` to prevent credential leaks
   - CI/CD pipeline includes security checks on every commit
   - `pip-audit` for vulnerability scanning in dependencies

### Software Bill of Materials (SBOM)

To generate an SBOM for this project:

```bash
pip install cyclonedx-bom
cyclonedx-py -r --format json -o sbom.json
```

Or view dependencies:

```bash
pip install pipdeptree
pipdeptree -p secure-string-cipher
```

## Security Audit History

| Date       | Type          | Auditor   | Status    | Notes                  |
|------------|---------------|-----------|-----------|------------------------|
| 2025-11-06 | Self-Audit    | Internal  | Completed | Initial security review|

_This table will be updated as security audits are performed._

## Contact

- **Security Issues**: security@avondenecloud.uk
- **GitHub Security Advisories**: https://github.com/TheRedTower/secure-string-cipher/security/advisories
- **General Support**: Open a GitHub issue (non-security related only)

---

**Last Updated**: November 6, 2025  
**Version**: 1.0
