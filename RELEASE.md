# Release v1.2.0

## Branch Cleanup Summary

The following branches have been reviewed and are confirmed as already merged
into `main` (via squash-merge PRs or identical commits):

| Branch | Status | Action |
|--------|--------|--------|
| `copilot/fix-security-issues-codeql` | Squash-merged via PR #2 | Delete |
| `copilot/implement-passphrase-vault-storage` | Squash-merged via PR #3 | Delete |
| `copilot/secure-string-cipher-analysis` | Identical to main | Delete |
| `fix/security-quality-cli` | All commits in main | Delete |
| `patch-1` | LICENSE already identical to main; CI workflows reference enterprise-specific secrets (JFrog/Artifactory) incompatible with this repo's CI setup | Delete |

## Pre-Release Verification

- [x] All lint checks pass (Ruff format, Ruff lint)
- [x] Type checking passes (mypy — 43 source files, no issues)
- [x] All 313 tests pass (unit + integration)
- [x] Version set to `1.2.0` in `pyproject.toml`
- [x] CHANGELOG updated with v1.2.0 entry
- [x] Runtime `__version__` reports `1.2.0`
- [x] Release workflow (`release.yml`) configured for `v*` tag trigger

## Release Steps

After this PR is merged to `main`, complete the v1.2.0 release:

    # 0. Ensure you're releasing the latest main commit
    git checkout main
    git pull --ff-only

    # 1. Delete stale branches
    git push origin --delete copilot/fix-security-issues-codeql
    git push origin --delete copilot/implement-passphrase-vault-storage
    git push origin --delete copilot/secure-string-cipher-analysis
    git push origin --delete fix/security-quality-cli
    git push origin --delete patch-1

    # 2. Create and push the release tag (from main)
    git tag -a v1.2.0 -m "Release v1.2.0 - Keychain backend, interactive feature parity"
    git push origin v1.2.0

This will trigger the GitHub Actions release workflow which:
1. Builds the Python package (sdist + wheel)
2. Creates a GitHub Release with changelog and artifacts
3. Publishes to PyPI
4. Builds and pushes multi-arch Docker image to GHCR

## What's New in v1.2.0

- **OS Keychain backend** — macOS Keychain, Windows Credential Vault, Linux Secret Service
- **Interactive mode feature parity** — shred, key-file encrypt/decrypt, expanded vault management
- **Documentation** — `docs/KEYCHAIN.md` keychain setup guide
- **Security** — Rate limiting in both interactive and non-interactive modes
- **313 tests passing** (up from 288 in v1.1.0)
