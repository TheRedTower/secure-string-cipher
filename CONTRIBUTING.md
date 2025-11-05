# Contributing to Secure String Cipher

First off, thank you for considering contributing to Secure String Cipher! This project aims to provide a secure, user-friendly encryption utility, and we value any contributions that help achieve this goal.

## Security First

Since this is a security-focused project, we have some special considerations:

1. **Security Reviews**: All changes that affect cryptographic operations must be reviewed by at least two maintainers
2. **No Security Through Obscurity**: All security measures must be well-documented and based on proven cryptographic principles
3. **Dependencies**: Changes to cryptographic dependencies must include a security impact analysis

## Code of Conduct

This project adheres to a Code of Conduct adapted from the Contributor Covenant. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

* **Security Vulnerabilities**: Please report security issues privately to [security contact]
* **Regular Bugs**: Use the GitHub issue tracker
* Include detailed steps to reproduce
* Mention your operating system and Python version
* Attach relevant logs or screenshots

### Suggesting Enhancements

* Use the GitHub issue tracker
* Explain the use case
* Consider backward compatibility
* Think about security implications

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code:
   * Add tests
   * Update documentation
   * Follow the style guide
3. Ensure all tests pass
4. Make sure your commits are clear and focused

## Development Process

1. **Setup Development Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   pip install -e ".[dev]"
   ```

2. **Run Tests**
   ```bash
   pytest
   ```

3. **Check Code Style**
   ```bash
   black .
   isort .
   flake8
   ```

## Style Guide

* Follow PEP 8
* Use type hints
* Document all functions and classes
* Keep functions focused and small
* Use descriptive variable names
* Comment complex algorithms

## Test Guidelines

* Write tests for all new features
* Maintain 90%+ code coverage
* Include both positive and negative test cases
* Test edge cases and error conditions
* Use parameterized tests for multiple scenarios

## Documentation

* Keep README.md up to date
* Document security considerations
* Update docstrings
* Add inline comments for complex logic

## Version Control Practices

* Use meaningful commit messages
* One feature/fix per commit
* Reference issues in commits
* Keep commits small and focused

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Run full test suite
4. Create tagged release
5. Build and publish to PyPI

## Questions?

Feel free to ask in:
* GitHub Issues
* Project Discussions
* Development Chat

## Project Structure

```
secure-string-cipher/
├── src/
│   └── secure_string_cipher/
│       ├── __init__.py
│       ├── cli.py
│       └── core.py
├── tests/
│   ├── __init__.py
│   ├── test_cli.py
│   └── test_core.py
├── docs/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
└── pyproject.toml
```

Thank you for contributing!