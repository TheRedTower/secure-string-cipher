# Developer Guide

## Quick Start

```bash
# Clone and install with locked dev dependencies
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --extra dev --locked
```

## Workflow

### Before Committing

```bash
make format    # Fix formatting automatically
make ci        # Run full CI pipeline locally
```

### Commands

```bash
make help         # List all commands
make format       # Auto-format with Ruff
make lint         # Check style, types, and code quality
make test         # Run full test suite (826 tests, ~80s)
make test-quick   # Run fast tests only (207 tests, ~10s)
make test-slow    # Run KDF/fuzz/performance tests
make test-cov     # Run tests with coverage
make clean        # Remove temporary files
make ci           # Run complete CI checks
```

### Fast Development Cycle

For rapid iteration, use `test-quick` which skips crypto-heavy tests:

```bash
# Quick feedback loop (~10s vs ~80s)
make test-quick

# Run full suite before commit
make ci
```

## Tools

### Ruff (Linter + Formatter)

- Replaces Black, isort, flake8, and more
- 10-100x faster than Black
- Formats code, sorts imports, catches bugs
- Config in `pyproject.toml` under `[tool.ruff]`

### mypy (Type Checker)

- Catches type errors before runtime
- Checks arguments, return types, None handling
- Config in `pyproject.toml` under `[tool.mypy]`

### pytest (Testing)

- Runs automated tests (826 tests)
- Unit tests in `tests/unit/`, integration tests in `tests/integration/`
- Security tests in `tests/security/`, fuzz tests in `tests/fuzz/`
- Performance benchmarks in `tests/performance/`
- Markers: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.security`, `@pytest.mark.fuzz`, `@pytest.mark.benchmark`, `@pytest.mark.e2e`
- Run with `pytest tests/` or `make test`

## CI/CD

GitHub Actions uses uv-locked installs and runs a two-stage pipeline:

1. **Quality checks** (Python 3.14 only):
   - uv sync --extra dev --locked
   - Ruff lint + format check (uv run --locked)
   - mypy type checking (uv run --locked)
   - Secret scan (uv run --locked detect-secrets --baseline .secrets.baseline)
   - Vulnerability scan (uv run --locked pip-audit --desc)
   - Inline passphrase strength verification (uv run --locked python -c "...")

2. **Test matrix** (Python 3.12, 3.13, 3.14 in parallel):
   - uv sync --extra dev --locked
   - Full pytest suite (uv run --locked pytest)
   - Coverage reporting and 75% gate on 3.14

## Common Tasks

### Adding a Feature

```bash
# Create a branch
git checkout -b feature/my-feature

# Make changes, then test
make format
make ci

# Commit and push
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

### Fix Formatting

```bash
# Auto-fix everything
make format

# Check without modifying
ruff format --check src tests
```

### Run Specific Tests

```bash
# One test file
pytest tests/unit/test_security.py

# One test class
pytest tests/unit/test_security.py::TestFilenameSanitization

# One test function
pytest tests/unit/test_security.py::TestFilenameSanitization::test_safe_filename_unchanged

# By marker
pytest -m security
pytest -m "unit and not slow"

# Quick vs full
make test-quick   # Fast tests only (~10s)
make test         # Full suite (~80s)
```

### Testing Password Input

The CLI uses automatic mode detection for password input via `_read_password()`:

- **Interactive terminal** (`sys.stdin.isatty()` = True): Hidden input via `getpass.getpass()`
- **Piped/redirected stdin** (tests, scripts): Visible input via `sys.stdin.readline()`

Tests use `StringIO` which triggers visible mode, so they work without modification:

```python
from io import StringIO
from secure_string_cipher.cli import run_menu

# Passwords flow through StringIO - no getpass called
in_stream = StringIO("1\nmy message\nMySecurePass123!\nMySecurePass123!\n0\n")
out_stream = StringIO()
run_menu(in_stream, out_stream)
```

### Testing the Non-Interactive CLI (`ssc`)

The `ssc` command is designed for scripting and automation. Test with subprocess:

```python
import subprocess

# Test encryption with password prompt
result = subprocess.run(
    ["ssc", "encrypt", "-t", "secret message"],
    input="MySecurePass123!\nMySecurePass123!\n",
    capture_output=True,
    text=True
)
assert result.returncode == 0

# Test with vault password
result = subprocess.run(
    ["ssc", "decrypt", "-f", "file.enc", "--vault", "my-label"],
    input="VaultMaster456!\n",
    capture_output=True,
    text=True
)
```

Exit codes: 0=success, 1=input error, 2=auth error, 3=vault error, 4=file error

### Debug CI Failures

```bash
# Run what CI runs
make ci

# If formatting fails
make format

# If linting fails
ruff check --fix src tests

# If tests fail
pytest tests/ -v
```

## Releases

### Version Bump

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit: `git commit -m "chore: bump version to X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main --tags`

### Publishing to PyPI

Publishing is automated via GitHub Actions (`release.yml`). When a `v*` tag is pushed:

1. Builds sdist + wheel with `python -m build`
2. Creates a GitHub Release with changelog and artifacts
3. Publishes to PyPI via trusted publisher (`pypa/gh-action-pypi-publish`)
4. Builds and pushes multi-arch Docker image to GHCR

## Tips

- Run `make format` before committing - saves CI time
- Run `make ci` locally - catches issues early
- Use `make help` to see all commands
- Check `.github/workflows/ci.yml` to see exact CI steps

## Troubleshooting

### Ruff Errors

```bash
# See problems
ruff check src tests

# Auto-fix
ruff check --fix src tests

# Include unsafe fixes (review manually)
ruff check --fix --unsafe-fixes src tests
```

### Test Failures

```bash
# Verbose output
pytest tests/ -v

# Extra verbose
pytest tests/ -vv

# Stop at first failure
pytest tests/ -x
```

### Type Errors

```bash
# Check types
mypy src tests

# Ignore specific errors (add to code)
# type: ignore[error-code]
```
