# Changelog

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

