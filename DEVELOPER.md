# Developer Guide

## Quick Start

```bash
# Clone and install
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
pip install -e ".[dev]"
```

## Development Workflow

### Before Every Commit

```bash
make format    # Auto-fix all formatting issues
make ci        # Run full CI pipeline (format check + lint + tests)
```

### Available Commands

```bash
make help      # Show all available commands
make format    # Auto-format code with Ruff
make lint      # Check code quality (Ruff + mypy)
make test      # Run tests
make test-cov  # Run tests with coverage report
make clean     # Remove temporary files
make ci        # Full CI check (format + lint + test)
```

## Tools Explained

### Ruff (All-in-One Tool)
- **Replaces**: Black (formatter), isort (import sorter), flake8 (linter), and more
- **Speed**: 10-100x faster than Black
- **What it does**: Formats code, sorts imports, catches bugs
- **Configuration**: `pyproject.toml` → `[tool.ruff]`

### mypy (Type Checker)
- **Purpose**: Catches type-related bugs before runtime
- **What it checks**: Function arguments, return types, None checks
- **Configuration**: `pyproject.toml` → `[tool.mypy]`

### pytest (Test Framework)
- **Purpose**: Runs automated tests
- **Features**: Fixtures, parametrization, coverage reports
- **Run tests**: `pytest tests/` or `make test`

## CI/CD Pipeline

### GitHub Actions Workflow
```yaml
Single job: quality
├── Install dependencies (with pip cache)
├── Check code quality (Ruff lint)
├── Check formatting (Ruff format)
├── Type check (mypy)
├── Run tests (pytest + coverage)
└── Upload coverage (Codecov)
```

**Smart caching**: Dependencies are cached between runs for faster CI

### Why This is Better
- **Before**: 2 jobs (test + lint), ~3 minutes
- **After**: 1 job with caching, ~1-2 minutes
- **Simpler**: One tool (Ruff) instead of three (Black + isort + flake8)
- **Faster**: Ruff is orders of magnitude faster than Black

## Common Tasks

### Add a New Feature
```bash
# 1. Create a feature branch
git checkout -b feature/my-feature

# 2. Make your changes
# Edit files...

# 3. Format and test
make format
make ci

# 4. Commit and push
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

### Fix Formatting Issues
```bash
# Auto-fix everything
make format

# Check what would change (without modifying)
ruff format --check src tests
```

### Run Specific Tests
```bash
# Run one test file
pytest tests/test_security.py

# Run one test class
pytest tests/test_security.py::TestFilenameSanitization

# Run one test function
pytest tests/test_security.py::TestFilenameSanitization::test_safe_filename_unchanged
```

### Debug Failing CI
```bash
# Run exactly what CI runs
make ci

# If formatting fails:
make format

# If linting fails:
ruff check --fix src tests

# If tests fail:
pytest tests/ -v
```

## Release Process

### Version Bumping
1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit: `git commit -m "chore: bump version to X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main --tags`

### Publishing to PyPI
```bash
# Build package
python -m build

# Upload to PyPI
python -m twine upload dist/*
```

## Tips

- **Run `make format` before every commit** - saves CI time
- **Run `make ci` locally** - catches issues before pushing
- **Use `make help`** - see all available commands
- **Check `.github/workflows/ci.yml`** - see exact CI steps

## Troubleshooting

### Ruff Errors
```bash
# See what's wrong
ruff check src tests

# Auto-fix
ruff check --fix src tests

# Some fixes are unsafe (require manual review)
ruff check --fix --unsafe-fixes src tests
```

### Test Failures
```bash
# Run with verbose output
pytest tests/ -v

# Run with detailed traceback
pytest tests/ -vv

# Stop at first failure
pytest tests/ -x
```

### Type Errors (mypy)
```bash
# Check types
mypy src tests

# Ignore specific errors (add to code)
# type: ignore[error-code]
```
