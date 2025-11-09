# Copilot Instructions for secure-string-cipher

## Project Overview
A **security-focused** AES-256-GCM encryption CLI tool with passphrase vault. Developed for Python 3.14, backward compatible to 3.10+. Uses modern cryptography with strict security practices.

## Architecture & Key Components

### Core Modules (src/secure_string_cipher/)
- **core.py**: AES-256-GCM encryption/decryption for text and files. Uses `StreamProcessor` for chunked file I/O (64KB chunks). All operations derive keys via PBKDF2-HMAC-SHA256 (390k iterations)
- **security.py**: Filename sanitization, path validation, atomic writes with `secure_atomic_write()`. Prevents path traversal, Unicode attacks, symlink attacks
- **passphrase_manager.py**: `PassphraseVault` encrypts passphrases with HMAC-SHA256 integrity verification. Auto-creates backups (keeps last 5) in `~/.secure-cipher/backups/`
- **timing_safe.py**: Constant-time password comparison, timing jitter, password strength validation (min 12 chars, complexity rules)
- **secure_memory.py**: `SecureString` and `SecureBytes` classes with automatic zeroing on deletion
- **cli.py**: Interactive menu-driven interface. Uses custom stdio streams for testability (avoids `getpass`)

### Config Constants (config.py)
- `CHUNK_SIZE = 64 * 1024` - File streaming chunks
- `KDF_ITERATIONS = 390_000` - PBKDF2 iterations
- `MAX_FILE_SIZE = 100MB` - File size limit
- `MIN_PASSWORD_LENGTH = 12` - Password policy

## Development Workflow

### Essential Commands (via Makefile)
```bash
make format    # Auto-format with Ruff (replaces Black + isort)
make lint      # Check quality (Ruff + mypy)
make test      # Run pytest suite (150+ tests)
make ci        # Full pipeline (format → lint → test)
```

**Always run `make format` before commits, then `make ci` to verify CI will pass.**

### Testing Architecture
- **Unit tests** (`tests/unit/`): Test individual components, marked with `@pytest.mark.unit`
- **Integration tests** (`tests/integration/`): Test CLI workflows, file operations, vault workflows
- **Fixtures**: Use `tests/conftest.py` for shared fixtures (`temp_dir`, `temp_file`)
- **Factories**: `tests/factories.py` provides `PassphraseFactory` and `FileFactory` for test data
- **Helpers**: `tests/helpers.py` has utilities like `create_test_files()`, `create_nested_structure()`
- **Parallel execution**: Tests run with `pytest -n auto` (pytest-xdist)
- **Coverage**: Minimum 69% (`--cov-fail-under=69` in pyproject.toml)
- **Test count tracking**: Always note test count changes in CHANGELOG (e.g., "150 → 189 tests")

### CLI Testing Pattern
Tests use custom stdio streams to avoid `getpass`. Example:
```python
from io import StringIO
from secure_string_cipher.cli import run_menu

in_stream = StringIO("1\nmy message\nMySecurePass123!\n0\n")
out_stream = StringIO()
run_menu(in_stream, out_stream)
```

## Code Quality Standards

### Tooling (All configured in pyproject.toml)
- **Ruff**: Linter + formatter (10-100x faster than Black). Target: Python 3.14
  - Replaces: Black, isort, flake8, pyupgrade, bugbear
  - Config: `[tool.ruff]` and `[tool.ruff.lint]`
- **mypy**: Type checker (`python_version = "3.10"` for compatibility)
- **pytest**: Testing with markers: `unit`, `integration`, `security`, `slow`, `benchmark`

### Security Practices
1. **Password handling**: Use `SecureString` for sensitive data, zero memory on deletion
2. **File operations**: Always use `secure_atomic_write()` (creates temp file, atomic rename)
3. **Filename sanitization**: Run all user filenames through `sanitize_filename()`
4. **Path validation**: Use `validate_safe_path()` and `detect_symlink()` to prevent traversal/symlink attacks
5. **Timing attacks**: Use `constant_time_compare()` for password/hash comparisons
6. **Validation**: Check password strength with `check_password_strength()` before crypto ops
7. **Privilege checking**: Never run as root - check execution context
8. **HMAC verification**: All vault operations verify integrity with HMAC-SHA256

### Conventions
- **Type hints**: Use modern syntax (`str | None` not `Optional[str]`)
- **Docstrings**: Google style with Args/Returns/Raises sections
- **Error handling**: Raise `CryptoError` for crypto failures, `SecurityError` for security violations
- **Constants**: Define in `config.py`, import where needed
- **File permissions**: Set vault files to `0o600` (user-only)

## Common Patterns

### Encryption Flow
```python
# Text: salt → derive_key → encrypt → base64
# Files: salt → derive_key → chunk-based streaming (CHUNK_SIZE)
```

### Vault Operations (passphrase_manager.py)
- Always create backup before write (`_create_backup()`)
- Verify HMAC on read (`_compute_hmac()`)
- Use master password to encrypt vault entries
- Store in `~/.secure-cipher/` with 0o600 permissions

### Stream Processing
```python
with StreamProcessor(path, "rb") as reader:
    encrypt_stream(reader, writer, passphrase)
```

### Error Handling
```python
# Raise specific exceptions
raise CryptoError("Encryption failed")  # Crypto operations
raise SecurityError("Path traversal detected")  # Security violations

# Never catch bare Exception - use specific types
try:
    operation()
except CryptoError as e:
    # Handle crypto failure
```

## CI/CD Pipeline (.github/workflows/ci.yml)

**Two-stage pipeline**:
1. **Quality checks** (Python 3.14 only): Ruff lint → Ruff format → mypy → secret scanning
2. **Test matrix** (parallel): Python 3.10-3.14, coverage on 3.14 only

**Secret scanning**: Uses `detect-secrets` with `.secrets.baseline`
**Dependency security**: `pip-audit` for vulnerability scanning

## Docker
- Alpine-based (~65MB), Python 3.14, runs as non-root (UID 1000)
- Build: `make docker-build` or `DOCKER_BUILDKIT=1 docker build`
- Mount volumes for persistent vault: `-v $PWD/vault:/vault`

## Key Files to Reference
- `src/secure_string_cipher/core.py` - Encryption implementation
- `src/secure_string_cipher/security.py` - All security validation functions
- `src/secure_string_cipher/passphrase_manager.py` - Vault implementation with HMAC
- `tests/integration/test_cli_workflows.py` - End-to-end workflow examples
- `tests/conftest.py` - Shared test fixtures
- `tests/factories.py` - Test data generation
- `tests/helpers.py` - Test utility functions
- `pyproject.toml` - All tool configuration (Ruff, pytest, mypy)
- `Makefile` - Developer commands reference
- `CHANGELOG.md` - Narrative-style versioning guide

## When Adding Features
1. Add security validation (sanitization, constant-time ops)
2. Write unit tests first (`tests/unit/`)
3. Add integration tests for workflows (`tests/integration/`)
4. Update type hints and docstrings
5. Run `make format` then `make ci` before committing
6. Ensure coverage doesn't drop below 69%
7. Update CHANGELOG.md in narrative style (see existing entries for format)
8. Consider security implications and document in PR

## Changelog Convention

Follow the **narrative-driven** style seen in CHANGELOG.md:

**Structure for each version:**
```markdown
## X.Y.Z (YYYY-MM-DD)

- **Thematic Title**: Brief description of release focus
  - **Category Name**:
    - Specific change with context and impact
    - Include metrics (test counts, performance improvements)
    - Explain security protections (what attacks are prevented)
    - Reference code elements in backticks (`function_name()`, `ClassName`)
  - **Test Suite**: Total count (X original + Y new category tests)
```

**Key principles:**
- **Context over brevity**: Explain *why* changes matter, not just *what* changed
- **Security transparency**: Detail what threats each security feature prevents
- **Metrics included**: Test counts, coverage %, performance improvements, size reductions
- **Progressive narrative**: Each version builds on previous security/feature improvements
- **User + Developer audience**: Accessible to both users and contributors

**Examples from codebase:**
- ✅ "Added HMAC-SHA256 integrity verification to detect vault file tampering"
- ✅ "Protections against: Path traversal attempts (../, /, backslashes)"
- ✅ "Test suite expanded: 150 → 189 tests (+39 menu security tests)"
- ❌ "Fixed bugs" (too vague)
- ❌ "Updated tests" (no context or metrics)

## Virtual Environment Setup

**Critical:** This project requires a virtual environment (recommended for all Python projects).

**Initial setup:**
```bash
cd <project-root>
python3.14 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
pip install -e ".[dev]"
```

**VS Code integration:**
- VS Code auto-detects `.venv/` in project root
- If not detected: Cmd/Ctrl+Shift+P → "Python: Select Interpreter" → Choose `.venv/bin/python`

**Always activate before development:**
```bash
source .venv/bin/activate  # macOS/Linux
.venv\Scripts\activate     # Windows
```

**Why virtual environments:**
- Isolates project dependencies from system Python
- Prevents conflicts between projects
- Required for externally-managed Python distributions (Homebrew, system Python)
- Standard Python development practice (PEP 405)
