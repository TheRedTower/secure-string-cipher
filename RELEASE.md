# Release guide

This guide is the maintainer checklist for a future Secure String Cipher
release. It does not authorize a release, tag, upload, or publication by
itself. Historical one-off checklists are kept in the
[documentation archive](docs/archive/README.md).

## Release principles

- Release only from the protected `main` branch after its required checks pass.
- Treat the version tag, project metadata, built metadata, changelog entry, and
  user-facing documentation as one versioned contract.
- Never move or silently replace a published tag.
- Build into a clean output directory and publish only the expected wheel and
  source archive.
- Preserve compatibility fixtures and test supported legacy decryption before
  publication.
- Record limitations accurately; a Beta release is not an independent security
  audit or a stability guarantee.

## 1. Prepare a release pull request

1. Choose the version according to the user-visible and compatibility impact.
2. Update `pyproject.toml` and the matching section of `CHANGELOG.md`.
3. Review `README.md`, `docs/`, `.github/SECURITY.md`, and package metadata for
   claims affected by the release.
4. Confirm dependency and lockfile changes are intentional.
5. Keep release preparation separate from unrelated feature work.

## 2. Run the local acceptance gate

Use the locked environment:

```bash
uv sync --extra dev --locked
uv run --locked ruff format --check src tests tools
uv run --locked ruff check src tests tools
uv run --locked mypy src
uv run --locked python tools/check_sensitive_output.py
git ls-files -z -- ':!:package.lock.json' | \
  xargs -0 uv run --locked detect-secrets-hook --baseline .secrets.baseline
make dependency-audit
uv run --locked pytest tests/ \
  --cov=secure_string_cipher \
  --cov-report=term-missing \
  --cov-fail-under=85 \
  -n 0
```

Also verify empty and binary file round trips, wrong-password destination
preservation, released v4/v5 fixtures, and any migration affected by the
release.

## 3. Build and inspect artifacts

Build from a clean checkout of the accepted commit:

```bash
make build
```

Before publication, verify all of the following:

- exactly one expected `.whl` and one `.tar.gz` exist in `dist/`;
- tag version, `pyproject.toml`, wheel metadata, and sdist metadata match;
- the wheel and sdist contain the intended licence, documentation, modules,
  and data files, with no temporary or unrelated artifacts;
- each artifact installs in an isolated environment; and
- import/version, `ssc --help`, and the release smoke tests pass from both
  installed artifacts.

Record artifact names, sizes, SHA-256 hashes, Python and uv versions, test
results, and the exact source commit in the release evidence.

## 4. Remote acceptance

After the release pull request is merged, confirm the exact protected `main`
commit and all required Linux, macOS, Windows, static-analysis, secret, and
dependency checks. Review unresolved security findings and verify that the
release workflow still publishes only explicitly selected package formats.

The tag must point to the current `main` commit when validation runs. If `main`
has advanced, investigate and prepare a new accepted release commit; do not move
an existing tag. Validation and building run with read-only repository access;
PyPI publishing alone receives OIDC permission, followed by GitHub Release and
container jobs with their respective write permissions. Existing release assets
are not overwritten, and PyPI publication does not skip existing versions.

Before the next release, verify the repository's PyPI trusted-publisher binding.
No `pypi` environment is assumed by this workflow. Adding one requires matching
GitHub deployment rules and a corresponding PyPI publisher configuration;
creating an unprotected environment alone would not supply an approval gate.

Tagging and publishing require a separate, explicit maintainer decision after
these checks. Follow the current automation in `.github/workflows/release.yml`;
do not infer its behaviour from an older release record.

## 5. Post-publication verification

- Confirm the GitHub and package-index versions and artifact hashes.
- Install from the public package index in a clean environment and repeat the
  smoke tests.
- Confirm release notes contain only the intended release section and link to
  the full changelog.
- Confirm container tags and metadata match when a container is part of the
  release.
- Open a focused follow-up issue for any discrepancy; do not rewrite published
  history to hide it.
