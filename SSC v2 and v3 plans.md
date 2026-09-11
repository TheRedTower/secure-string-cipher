> Implement the plan:

# Repository Analysis: secure-string-cipher

## Overview

A well-structured Python 3.12+ AES-256-GCM encryption CLI tool and library with passphrase vault, keychain integration, rate limiting, audit logging, and comprehensive security features. Currently at v1.2.10 with 826 tests and ~79% coverage.

## To-Do List: Improvements, Refinements & Extensions

### 🔒 Security Hardening

1. **Stricter mypy configuration** — `disallow_untyped_defs = false` and `warn_return_any = false` are loose; tighten gradually to catch type-level bugs in crypto code.
2. **Remove `ignore_missing_imports = true`** — Add explicit type stubs or per-module overrides instead of a blanket ignore.
3. **Pin urllib3 justification** — `urllib3==2.6.3` is listed as a dependency but no HTTP functionality is visible in the codebase. Audit if it's actually needed; remove if not (reduces attack surface).
4. **Vault master-password rotation** — Currently no mechanism to re-encrypt the vault under a new master password without export/import. Add a `ssc vault rotate-master` command.
5. **Memory-locked allocations** — Beyond `sodium_memzero`, consider `mlock()` on sensitive buffers to prevent them from being swapped to disk.
6. **AEAD nonce counter/HKDF-expand per chunk** — The file encryption uses a single nonce for the entire stream. For multi-chunk streaming, derive per-chunk nonces (nonce-misuse resistance).
7. **Canary/tripwire for vault tampering** — Add an optional TOTP or challenge token so the user knows the vault hasn't been silently replaced by an attacker.

### 🧪 Testing & Quality

8. **Raise coverage to ≥90%** — Currently ~79%; set a roadmap to 85% then 90% with incremental `--cov-fail-under` bumps.
9. **Add mutation testing** (e.g., `mutmut` or `cosmic-ray`) — Validates that tests actually catch regressions, not just exercise code paths.
10. **Property-based tests for vault round-trip** — Hypothesis tests exist for encryption but vault store→retrieve→delete round-trips aren't fuzz-tested.
11. **Negative/adversarial test coverage** — Explicitly test truncated ciphertexts, bit-flipped HMAC bytes, oversized payloads, and race conditions on vault files.
12. **E2E tests for Docker image** — The `e2e` marker exists but no `tests/e2e/` directory; add container-based end-to-end tests.
13. **CI matrix: add macOS and Windows runners** — Keychain backend is cross-platform but only tested on `ubuntu-latest`.

### 📦 Packaging & Distribution

14. **Publish to PyPI with Trusted Publishers** — `release.yml` exists but verify it uses OIDC-based trusted publishing (no long-lived tokens).
15. **SBOM generation** — Add a step to emit a CycloneDX or SPDX SBOM on each release for supply-chain transparency.
16. **Reproducible builds** — Pin the hatchling build backend version and verify wheel reproducibility.
17. **`py.typed` marker file** — Ship a `py.typed` in the package so downstream consumers get type information.

### 🏗️ Architecture & Code Quality

18. **Extract a `CryptoEngine` protocol/interface** — Decouple KDF, AEAD, and commitment logic behind an interface for future algorithm agility (e.g., XChaCha20-Poly1305 backend).
19. **Replace global mutable state in CLI** — `_quiet_mode` and `_no_color` are module-level globals; refactor into a CLI context dataclass passed through the call stack.
20. **Async file I/O option** — For large files, offer asyncio-compatible encryption that doesn't block the event loop (useful when used as a library).
21. **Structured logging in audit module** — Currently JSON-ish; adopt a formal structured-logging library or Python logging with JSON formatter for SIEM ingestion.
22. **Error hierarchy cleanup** — `CryptoError` and `SecurityError` are separate hierarchies; create a common `SSCError` base for easier blanket catches by consumers.

### 🚀 Feature Extensions

23. **Directory/recursive encryption** — `ssc encrypt -d ./folder` to recursively encrypt all files in a directory tree (with include/exclude globs).
24. **Streaming stdin/stdout encryption** — `echo "secret" | ssc encrypt --stdin | ssc decrypt --stdin` pipe-friendly mode for Unix workflows.
25. **Public-key (asymmetric) mode** — Support X25519 + HKDF → AES-256-GCM for encrypting to a recipient's public key (share without pre-shared secret).
26. **Multi-recipient encryption** — Wrap the symmetric key for N recipients (age-style).
27. **Vault sync/merge** — Allow merging two vault files (conflict resolution), useful for multi-device workflows.
28. **TOTP / 2FA unlock for vault** — Require a TOTP code in addition to master password for vault access.
29. **YubiKey / FIDO2 hardware key support** — Use a hardware authenticator as a KDF input for the vault master key.
30. **Configurable Argon2 parameters via CLI flag** — Let advanced users increase time/memory cost without editing config.
31. **Expiry / TTL on vault entries** — Auto-warn or auto-delete entries after a configured time period.
32. **Vault entry metadata** — Store notes, creation date, last-used timestamp per entry.
33. **Shell completions** — Generate Bash/Zsh/Fish completion scripts (`ssc --completions bash`).

### 📖 Documentation & DX

34. **Man page generation** — Auto-generate a man page from argparse for Unix installs.
35. **Interactive tutorial / `ssc demo`** — A guided walkthrough for first-time users.
36. **Threat model document** — Expand `.github/CRYPTOGRAPHY.md` into a formal threat model (assets, adversaries, mitigations).
37. **Architecture decision records (ADRs)** — Document why Argon2id over bcrypt, why AES-GCM over XChaCha20, etc.
38. **Version badge is static** — README coverage badge says 79% as a static shield; hook up Codecov or Coveralls for a dynamic badge.

### 🐳 Docker & Deployment

39. **Multi-arch image (amd64 + arm64)** — Build for both architectures to support Apple Silicon and ARM servers.
40. **Distroless or scratch final stage** — Alpine is small but a distroless Python image is even more minimal (fewer CVE surfaces).
41. **Docker image version label is stale** — Dockerfile `LABEL version="1.1.0"` but project is at 1.2.10; automate label injection from `pyproject.toml`.
42. **Add `--read-only` Docker Compose flag** — Enforce immutable rootfs to further harden the container.

### ⚙️ CI/CD Improvements

43. **Dependency update automation** — Add Dependabot or Renovate config for `pyproject.toml` and GitHub Actions.
44. **Enforce conventional commits** — Add a CI check so changelogs can be auto-generated.
45. **Separate security-scan job** — `pip-audit` and `detect-secrets` use `continue-on-error: true`; make them fail the build (or at least post a PR comment).
46. **Cache Docker layers in CI** — Use GitHub Actions cache for Docker BuildKit layers to speed up image builds.
47. **Release-please or similar** — Automate changelog + version bumps + GitHub Release creation.

### 🧹 Housekeeping

48. **Remove unused urllib3 dependency** — No HTTP calls are made in the source; likely a leftover.
49. **Consolidate duplicate `colorize` references** — Exported from both `utils` and `__init__`; ensure a single canonical location.
50. **Dockerfile `pip install` in final stage runs as root** — The `pip install` happens before `USER cipheruser` but could be further isolated.
51. **`pyperclip` graceful degradation** — If clipboard is unavailable (headless server, Docker), ensure no import errors or unhandled exceptions at module load.

## Priority Tiers

| Priority | Items |
| --- | --- |
| **P0 — Do now** | #48 (remove urllib3), #41 (fix Docker labels), #8 (coverage roadmap), #17 (py.typed) |
| **P1 — Next sprint** | #1-2 (mypy strictness), #4 (vault rotate), #13 (CI matrix), #43 (Dependabot) |
| **P2 — Near-term** | #18 (CryptoEngine interface), #23-24 (dir/stdin encryption), #33 (shell completions), #38 (dynamic badge) |
| **P3 — Future** | #25-29 (asymmetric/multi-recipient/hardware key), #9 (mutation testing), #39 (multi-arch) |
