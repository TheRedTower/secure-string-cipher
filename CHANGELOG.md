# Changelog

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

