# Developer Guide

## Quick Start

```bash
# Clone and install with dev dependencies
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install -e ".[dev]"
```

## Workflow

### Before Committing

```bash
make format    # Fix formatting automatically
make ci        # Run full CI pipeline locally
```

### Commands

```bash
make help      # List all commands
make format    # Auto-format with Ruff
make lint      # Check style, types, and code quality
make test      # Run test suite
make test-cov  # Run tests with coverage
make clean     # Remove temporary files
make ci        # Run complete CI checks
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
- Runs automated tests (150+ tests)
- Fixtures, parametrization, coverage reports
- Run with `pytest tests/` or `make test`

## CI/CD

The GitHub Actions workflow runs:
1. Install dependencies (with caching)
2. Check code quality (Ruff lint)
3. Check formatting (Ruff format)
4. Type check (mypy)
5. Run tests (pytest + coverage)
6. Upload coverage (Codecov)

All in one job, takes 1-2 minutes.

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
pytest tests/test_security.py

# One test class
pytest tests/test_security.py::TestFilenameSanitization

# One test function
pytest tests/test_security.py::TestFilenameSanitization::test_safe_filename_unchanged
```

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
```bash
# Build
python -m build

# Upload
python -m twine upload dist/*
```

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