# Contributing

Thanks for considering contributing to Secure String Cipher! We appreciate any help making this encryption tool better.

## Security First

Since this is a security tool, we have a few special requirements:

1. **Security reviews** - Changes to cryptographic operations need review from at least two maintainers
2. **No security through obscurity** - All security measures must be well-documented and based on proven principles
3. **Dependency changes** - Updates to crypto dependencies must include a security impact analysis

## Code of Conduct

This project follows a Code of Conduct adapted from the Contributor Covenant. By participating, you agree to uphold it.

## How to Contribute

### Reporting Bugs

* **Security issues** - Please report these privately to <security@avondenecloud.uk>
* **Regular bugs** - Use the GitHub issue tracker
* Include steps to reproduce, your OS, Python version, and any relevant logs

### Suggesting Features

* Use the GitHub issue tracker
* Explain your use case
* Consider backward compatibility and security implications

### Pull Requests

1. Fork the repo and create a branch from `main`
2. If you add code:
   * Write tests
   * Update docs
   * Follow the style guide
3. Make sure all tests pass
4. Keep commits clear and focused

## Development Setup

**Python 3.12+ required** (3.14 recommended for development).

```bash
# Install dependencies from the lockfile (keeps parity with CI)
uv sync --extra dev --locked

# Run tools through the locked environment
uv run --locked ruff check src tests
uv run --locked mypy src tests
uv run --locked pytest tests/ --maxfail=3 -n auto

# Optional: Make targets wrap the same commands
make format  # Auto-fix formatting
make ci      # Run full CI pipeline
```

See [DEVELOPER.md](DEVELOPER.md) for detailed workflow, troubleshooting, and release process.

## Style Guide

* Follow PEP 8
* Use type hints
* Document all public functions and classes
* Keep functions small and focused
* Use descriptive names
* Comment complex algorithms

## Testing

* Write tests for new features
* CI coverage gate: 75% (current: ~79%)
* Include positive and negative test cases
* Test edge cases and error conditions
* Use parameterized tests when appropriate

### Test Commands

```bash
# Direct (CI-parity)
uv run --locked ruff check src tests
uv run --locked mypy src tests
uv run --locked pytest tests/ --maxfail=3 -n auto

# Optional make wrappers
make test-quick   # Fast tests (~10s) - for development iteration
make test         # Full suite (826 tests, ~80s)
make test-cov     # Full suite with coverage report
```

### Test Structure

```text
tests/
├── conftest.py          # Shared fixtures
├── factories.py         # Test data factories
├── helpers.py           # Test utilities
├── unit/                # Unit tests (fast, isolated)
│   ├── test_cli_args.py
│   ├── test_cli_args_coverage.py
│   ├── test_cli_coverage.py
│   ├── test_cli_menu.py
│   ├── test_core.py
│   ├── test_core_coverage.py
│   ├── test_core_extended.py
│   ├── test_kdf.py
│   ├── test_keychain_backend.py
│   ├── test_package_init.py
│   ├── test_passphrase_generator.py
│   ├── test_passphrase_manager_extended.py
│   ├── test_property_based.py
│   └── test_utils.py
├── integration/         # Integration tests (CLI workflows)
│   ├── test_cli.py
│   ├── test_cli_extended.py
│   ├── test_cli_workflows.py
│   ├── test_inline_passphrase_gen.py
│   ├── test_passphrase_manager.py
│   └── test_ssc_cli.py
├── security/            # Security-focused tests
│   ├── test_audit_log.py
│   ├── test_key_commitment.py
│   ├── test_rate_limiter.py
│   ├── test_secure_memory.py
│   ├── test_security.py
│   ├── test_security_integration.py
│   └── test_timing_safe.py
├── fuzz/                # Hypothesis fuzzing tests
│   ├── test_fuzz_encryption.py
│   └── test_fuzz_inputs.py
└── performance/         # Benchmark tests
    └── test_benchmarks.py
```

## Documentation

* Update README.md if needed
* Document security considerations
* Keep docstrings current

## Git Practices

* Write clear commit messages following [Conventional Commits](https://conventionalcommits.org)
* One feature or fix per commit
* Reference issues in commits (e.g., "Fixes #123")

## Questions?

* GitHub Issues
* Project Discussions

## Project Structure

```text
secure-string-cipher/
├── src/
│   └── secure_string_cipher/
│       ├── __init__.py           # Public API exports
│       ├── audit_log.py          # Security event logging
│       ├── cli.py                # Interactive menu interface
│       ├── cli_args.py           # Non-interactive argparse CLI (`ssc`)
│       ├── config.py             # Constants (iterations, chunk size, etc.)
│       ├── core.py               # AES-256-GCM + Argon2id + key commitment
│       ├── keychain_backend.py   # OS keychain integration (macOS/Windows/Linux)
│       ├── passphrase_generator.py  # Random passphrase generation
│       ├── passphrase_manager.py # Encrypted vault with HMAC integrity
│       ├── rate_limiter.py       # Brute-force rate limiting
│       ├── secure_memory.py      # SecureBytes/SecureString with libsodium
│       ├── security.py           # Path validation, filename sanitization
│       ├── timing_safe.py        # Constant-time comparison, password strength
│       └── utils.py              # Progress bar, colors, helpers
├── tests/
│   ├── conftest.py               # Shared fixtures
│   ├── factories.py              # Test data factories
│   ├── helpers.py                # Test utilities
│   ├── unit/                     # Unit tests (fast, isolated)
│   ├── integration/              # Integration tests (CLI workflows)
│   ├── security/                 # Security-focused tests
│   ├── fuzz/                     # Hypothesis fuzzing tests
│   └── performance/              # Benchmark tests
```

Thank you for contributing!
