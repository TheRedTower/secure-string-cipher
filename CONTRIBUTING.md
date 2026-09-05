# Contributing to Secure String Cipher

Thank you for contributing. Secure String Cipher is a security-sensitive Beta
project maintained by one person, so focused changes with clear evidence are
the easiest to review safely.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening an issue

- Search the existing issues and [roadmap](ROADMAP.md).
- Use the bug or feature form so the report contains the details needed for
  triage.
- Never post passwords, keys, plaintext, vault contents, private paths, or
  other sensitive data.
- Report suspected vulnerabilities privately as described in the
  [security policy](.github/SECURITY.md), not through a public issue.

General questions and non-security support requests may use the
[issue tracker](https://github.com/TheRedTower/secure-string-cipher/issues).
GitHub Discussions is not currently used by this project.

## Development setup

Python 3.12 or later and [uv](https://docs.astral.sh/uv/) are required.

```bash
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --extra dev --locked
```

Run commands through the locked environment to match CI:

```bash
uv run --locked ruff format --check src tests tools
uv run --locked ruff check src tests tools
uv run --locked mypy src
uv run --locked python tools/check_sensitive_output.py
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-fail-under=85
```

The [developer guide](DEVELOPER.md) documents focused test targets and the
cross-platform CI boundary.

## Proposing a change

1. Fork the repository and branch from the latest `main`.
2. Keep the pull request limited to one coherent purpose.
3. Add or update tests for behaviour changes, including negative and boundary
   cases where relevant.
4. Update public documentation when a command, API, security property, file
   format, or limitation changes.
5. Run the relevant focused tests and the complete protected check set.
6. Explain the user-visible effect, security impact, compatibility impact, and
   validation performed in the pull request.

Use clear commit messages. The project follows
[Conventional Commits](https://www.conventionalcommits.org/) where practical.

## Security-sensitive changes

Changes involving cryptography, key derivation, authentication, file formats,
vault state, secret handling, filesystem publication, or dependency trust need
extra evidence:

- state the threat or failure mode being addressed;
- preserve released-format compatibility unless a migration is explicitly
  designed and tested;
- include adversarial, failure-path, and regression tests;
- document any guarantee that remains best effort; and
- include a security-impact analysis for cryptographic or security-critical
  dependency changes.

This is a sole-maintainer project. The maintainer records a deliberate
self-review and relies on protected status checks for every accepted change.
External specialist review is sought for high-risk changes when practical, but
it must not be represented as an independent audit unless one actually occurs.

## Coding and testing expectations

- Target Python 3.12 or later and follow the configured Ruff rules.
- Use type annotations for production code and keep mypy clean.
- Keep public interfaces and security boundaries documented.
- Prefer small functions, descriptive names, and comments that explain why a
  non-obvious security decision exists.
- Cover successful, rejected, boundary, and cleanup behaviour.
- Do not weaken the 85% branch-coverage gate to make a change pass.
- Do not regenerate or silently replace immutable compatibility fixtures.

Tests are organized under `tests/unit`, `tests/integration`, `tests/security`,
`tests/fuzz`, and `tests/performance`. Useful wrappers include:

```bash
make test-quick
make test-unit
make test-integration
make test-security
make test
make test-cov
```

## Pull-request review

The maintainer evaluates scope, correctness, compatibility, security impact,
tests, documentation, and protected CI results. Review comments must be
resolved with code or a documented technical rationale. A green workflow is
necessary but is not, by itself, proof that a security claim is correct.

Contributions may be declined or deferred when their scope cannot be reviewed
safely, they conflict with the documented Beta boundary, or the maintenance
cost is not sustainable for the project.
