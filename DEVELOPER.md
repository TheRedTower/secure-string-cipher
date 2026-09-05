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
make secret-scan  # Scan tracked files against the secrets baseline
make dependency-audit  # Scan the locked production dependency set
make build        # Build with hash-checked, locked build dependencies
make test         # Run the complete test suite
make test-quick   # Run a focused unit/integration subset
make test-slow    # Run KDF/fuzz/performance tests
make test-cov     # Run tests with coverage
make clean        # Remove temporary files
make ci           # Run the non-mutating local CI gate
```

`make clean` removes generated caches and build/test outputs. It leaves
encrypted and decrypted data files (`*.enc`, `*.dec`) in place.

### Fast Development Cycle

For rapid iteration, use `test-quick`, which skips selected crypto-heavy tests.
Test counts and timings are intentionally not fixed in this guide because they
change as regressions are added and vary by machine.

```bash
# Focused feedback loop
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

- Runs the automated test suite
- Unit tests in `tests/unit/`, integration tests in `tests/integration/`
- Security tests in `tests/security/`, fuzz tests in `tests/fuzz/`
- Performance benchmarks in `tests/performance/`
- Markers: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.security`, `@pytest.mark.fuzz`, `@pytest.mark.benchmark`, `@pytest.mark.e2e`
- Run with `pytest tests/` or `make test`

## CI/CD

GitHub Actions uses uv-locked installs and runs these protected CI stages:

The workflows pin uv to the locally tested version, `0.9.17`. Package builds use
the separate `build` dependency group in `uv.lock`; update that group together
with `[build-system].requires` when changing Hatchling.

1. **Quality checks** (Python 3.14 only):
   - uv sync --extra dev --locked
   - Ruff lint + format check (uv run --locked)
   - mypy type checking (uv run --locked)
   - Sensitive-output guard
   - Enforcing tracked-file secret scan against `.secrets.baseline`
   - Exact locked production dependency export and vulnerability scan
   - Inline passphrase strength verification (uv run --locked python -c "...")

2. **Test matrix** (Python 3.12, 3.13, 3.14 in parallel):
   - uv sync --extra dev --locked
   - Full pytest suite (uv run --locked pytest)
   - Branch-coverage reporting and an 85% gate on Python 3.14

3. **Platform safety matrix** (Python 3.12):
   - Focused file, fixture, vault, and transaction tests on Ubuntu, macOS, and
     Windows

CodeQL runs in its own workflow. Workflow configuration defines the intended
boundary; the result for a particular change must be verified on that exact
commit in GitHub.

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

# Focused vs full
make test-quick
make test
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
# Run the local CI-parity gate
make ci

# If formatting fails
make format

# If linting fails
uv run --locked ruff check --fix src tests tools

# If tests fail
uv run --locked pytest tests/ -v
```

## Releases

See [RELEASE.md](RELEASE.md) for the complete release preparation, artifact
inspection, protected-branch, and post-publication checklist. Preparing a
version change does not itself authorize tagging or publication.

### Publishing to PyPI

Publishing is automated via GitHub Actions (`release.yml`) after an explicitly
authorized `v*` tag is pushed. The workflow:

1. Builds a source distribution and wheel
2. Verifies tag, project, wheel, and source-distribution versions match
3. Creates a GitHub Release with generated notes and selected artifacts
4. Publishes to PyPI via trusted publisher (`pypa/gh-action-pypi-publish`)
5. Builds and pushes a multi-architecture Docker image to GHCR

## Tips

- Run `make format` before committing; `make ci` is deliberately check-only
- Run `make ci` locally to catch issues early
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
