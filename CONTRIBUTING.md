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

* **Security issues** - Please report these privately to security@avondenecloud.uk
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

**Python Version**: We develop on **Python 3.14** (latest stable) with backward compatibility to Python 3.10+. Please use Python 3.14 for development to ensure you're using modern Python features.

1. **Create your environment**
   ```bash
   python3.14 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

2. **Run tests**
   ```bash
   pytest
   # Or with coverage and parallel execution
   pytest --cov=secure_string_cipher -n auto
   ```

3. **Check code quality**
   ```bash
   make format  # Auto-fix formatting
   make lint    # Check types and style
   make ci      # Run everything
   ```

## Style Guide

* Follow PEP 8
* Use type hints
* Document all public functions and classes
* Keep functions small and focused
* Use descriptive names
* Comment complex algorithms

## Testing

* Write tests for new features
* Maintain 90%+ coverage
* Include positive and negative test cases
* Test edge cases and error conditions
* Use parameterized tests when appropriate

## Documentation

* Update README.md if needed
* Document security considerations
* Keep docstrings current
* Comment complex logic

## Git Practices

* Write clear commit messages
* One feature or fix per commit
* Reference issues in commits (e.g., "Fixes #123")
* Keep commits focused

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Run full test suite (`make ci`)
4. Create tagged release
5. Publish to PyPI (automated via GitHub Actions)

## Questions?

Ask in:
* GitHub Issues
* Project Discussions

## Project Structure

```
secure-string-cipher/
├── src/
│   └── secure_string_cipher/
│       ├── __init__.py
│       ├── cli.py
│       ├── core.py
│       ├── security.py
│       ├── passphrase_generator.py
│       └── passphrase_manager.py
├── tests/
│   ├── unit/
│   └── integration/
````

Thank you for contributing!