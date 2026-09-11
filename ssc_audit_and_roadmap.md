# Secure String Cipher — Senior Maintainer Audit & Roadmap Brief

**Repository:** [TheRedTower/secure-string-cipher](https://github.com/TheRedTower/secure-string-cipher)
**Current Version:** 1.3.0 (Beta) - Latest tag: `v1.3.0`
**Date:** September 8, 2026
**Audience:** Gemini 3.1 Pro (or equivalent LLM acting as a senior engineering advisor)

---

## 1. Repository Inventory

### Codebase Metrics

| Metric | Value |
|--------|-------|
| **Source Lines (Python)** | ~10,810 across 17 modules |
| **Test Files** | 43 files across 5 categories |
| **CI Workflows** | 4 (ci, release, codeql, cleanup-caches) |
| **Git Tags** | 28 releases (v1.0.0 to v1.3.0) |
| **Dependencies (prod)** | 5 pinned (`cryptography`, `argon2-cffi`, `pynacl`, `pyperclip`, `wcwidth`) |
| **Python Support** | 3.12, 3.13, 3.14 |
| **Coverage Gate** | 85% on Python 3.14 |

### Source Module Breakdown

| Module | Purpose | Size |
|--------|---------|------|
| [cli.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/cli.py) | Interactive menu (`ssc start`) | ~47 KiB |
| [cli_args.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/cli_args.py) | Non-interactive CLI (`ssc`) | ~47 KiB |
| [core.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/core.py) | Encryption/decryption engine | ~42 KiB |
| [passphrase_generator.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/passphrase_generator.py) | Passphrase generation | ~46 KiB |
| [passphrase_manager.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/passphrase_manager.py) | Vault CRUD + transactions | ~31 KiB |
| [security.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/security.py) | Path/filename validation | ~17 KiB |
| [rate_limiter.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/rate_limiter.py) | Exponential backoff rate limiter | ~14 KiB |
| [audit_log.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/audit_log.py) | JSON audit logging | ~13 KiB |
| [config.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/config.py) | Constants + vault settings | ~9 KiB |
| [secure_memory.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/secure_memory.py) | SecureBytes/SecureString + libsodium | ~9 KiB |
| [keychain_backend.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/keychain_backend.py) | OS keychain via `keyring` | ~6 KiB |
| [atomic_io.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/atomic_io.py) | Atomic file writes | ~4 KiB |
| [utils.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/utils.py) | Progress bar, color, shred | ~3 KiB |
| [timing_safe.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/timing_safe.py) | Constant-time compare + strength check | ~2 KiB |
| [vault_transport.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/vault_transport.py) | Vault transport constants | <1 KiB |
| [__init__.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/__init__.py) | Public API exports (56 symbols) | ~3 KiB |

### Test Structure

```
tests/
  conftest.py, factories.py, helpers.py
  fixtures/           # Immutable v4/v5 compatibility fixtures
  unit/               # 21 files - core, CLI, vault, config, metadata, etc.
  integration/        # 7 files - CLI workflows, legacy fixtures, platform safety
  security/           # 7 files - audit log, key commitment, rate limiter, memory, timing
  fuzz/               # 2 files - Hypothesis property-based tests
  performance/        # 1 file - benchmark suite
```

### Documentation

| Document | Location | Status |
|----------|----------|--------|
| README | [README.md](file:///Users/adi/VScode/SSC/README.md) | Comprehensive, accurate |
| API Reference | [docs/API.md](file:///Users/adi/VScode/SSC/docs/API.md) | ~39 KiB, thorough |
| Roadmap | [ROADMAP.md](file:///Users/adi/VScode/SSC/ROADMAP.md) | v2/v3 vision documented |
| Changelog | [CHANGELOG.md](file:///Users/adi/VScode/SSC/CHANGELOG.md) | Detailed, 1250+ lines |
| Security Policy | [SECURITY.md](file:///Users/adi/VScode/SSC/.github/SECURITY.md) | Updated Sep 2026 |
| Cryptography Design | [CRYPTOGRAPHY.md](file:///Users/adi/VScode/SSC/.github/CRYPTOGRAPHY.md) | Threat model + specs |
| Audit Checklist | [AUDIT_CHECKLIST.md](file:///Users/adi/VScode/SSC/.github/AUDIT_CHECKLIST.md) | 10-section review guide |
| V2 Architecture | [V2_MANAGED_KEYS_ARCHITECTURE.md](file:///Users/adi/VScode/SSC/docs/V2_MANAGED_KEYS_ARCHITECTURE.md) | 33 KiB approved design |
| Developer Guide | [DEVELOPER.md](file:///Users/adi/VScode/SSC/DEVELOPER.md) | Accurate to current CI |
| Release Guide | [RELEASE.md](file:///Users/adi/VScode/SSC/RELEASE.md) | Checklist-based |
| Keychain Guide | [KEYCHAIN.md](file:///Users/adi/VScode/SSC/docs/KEYCHAIN.md) | Per-platform |
| Historical Archive | [docs/archive/](file:///Users/adi/VScode/SSC/docs/archive) | Dated records |

---

## 2. Claim Verification - What's Claimed vs. What's Implemented

### Claims That Are Fully Implemented and Verified

| Claim | Evidence |
|-------|----------|
| AES-256-GCM encryption for text and files | [core.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/core.py) uses `cryptography` AESGCM with 256-bit keys |
| Argon2id key derivation (64 MiB, 3 iter, p=4) | [core.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/core.py) `derive_key()` + [config.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/config.py) constants |
| Key commitment scheme (HMAC-SHA256) | `compute_key_commitment()` / `verify_key_commitment()` in core + 7 dedicated tests |
| Legacy key-file mode (SHA-256 then Argon2id) | `derive_key_from_key_file()` in core, `--key-file` CLI arg, symlink rejection |
| OS Keychain integration (macOS/Win/Linux) | [keychain_backend.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/keychain_backend.py) + `keyring` optional dep + migration CLI |
| Hidden password input / visible for scripts | `_read_password()` with `isatty()` detection in both CLI modules |
| Inline passphrase generation (`/gen`) | Implemented in `cli.py` interactive menu, 200-rep CI strength check |
| Encrypted vault with HMAC-SHA256 integrity | SSCVAULT format in [passphrase_manager.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/passphrase_manager.py) |
| Best-effort memory clearing (libsodium) | [secure_memory.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/secure_memory.py) SecureBytes/SecureString + `has_secure_memory()` |
| Constant-time comparisons | [timing_safe.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/timing_safe.py) `constant_time_compare()` |
| Local CLI rate limiting (exponential backoff) | [rate_limiter.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/rate_limiter.py) + `PersistentRateLimiter` + wired into CLI |
| Best-effort shred (overwrite + unlink) | `secure_overwrite()` in utils.py, option 10 in interactive menu |
| Chunked file streaming (256 KiB) | `StreamProcessor` in core.py |
| Automatic vault backups (last 5 kept) | Collision-resistant backup IDs, retention logic in passphrase_manager |
| Atomic final publication (never pre-delete) | [atomic_io.py](file:///Users/adi/VScode/SSC/src/secure_string_cipher/atomic_io.py) + `--force` semantics verified in tests |
| 100 MiB plaintext limit | `MAX_FILE_SIZE` in config, descriptor checks, cumulative streaming limits |
| v4/v5 metadata format (v5 authenticated) | Writer emits v5, reader handles v4+v5, immutable fixtures in `tests/fixtures/` |
| Transactional vault import/restore | Snapshot, backup, write, readback, revalidate, rollback-on-failure |
| Canonical vault export (six-line bytes) | `vault_transport.py` constants, CLI import LF/CRLF recovery |
| Exit codes (0/1/2/3/4) | Defined and tested in `cli_args.py` |
| Docker (Python 3.14-alpine, non-root, --network none) | [Dockerfile](file:///Users/adi/VScode/SSC/Dockerfile) + [docker-compose.yml](file:///Users/adi/VScode/SSC/docker-compose.yml) |
| PyPI publishing (trusted publisher) | [release.yml](file:///Users/adi/VScode/SSC/.github/workflows/release.yml) OIDC, tag verification, artifact validation |
| CI: 85% coverage gate on 3.14 | [ci.yml](file:///Users/adi/VScode/SSC/.github/workflows/ci.yml) line 120: `--cov-fail-under=85` |
| CI: platform safety on Ubuntu/macOS/Windows | `platform-safety` job in ci.yml, Python 3.12 |
| Beta status honestly declared | README line 7, `pyproject.toml` classifier, SECURITY.md |

### Claims That Are Honestly Qualified (Documented Limitations)

These are features the project claims with explicit caveats - not bugs, but noted boundaries:

| Claim with Caveat | Verification |
|----|-----|
| "Memory clearing is best-effort" | Documented: Python strings immutable, libsodium optional |
| "Rate limiting cannot prevent offline guessing" | Documented in README + SECURITY.md |
| "Shred is unreliable on SSDs, COW, snapshots" | Documented in README + SECURITY.md |
| "Audit log is local JSON, not tamper-evident" | Documented in SECURITY.md section 6 |
| "No cross-process vault lock" | Documented in README, ROADMAP, SECURITY.md |
| "Symlink preflight is best-effort, hostile races remain" | Documented; descriptor-level opening is on roadmap |
| "Key-file is legacy, not public-key encryption" | Documented in README + SECURITY.md section 7 |
| "No independent third-party security audit" | Documented in README, SECURITY.md |

> [!TIP]
> The project is unusually honest about its limitations. Every feature claim in the README is either verified in code or explicitly qualified with a caveat. This is rare and commendable for a solo-maintainer project.

### Gaps Between Claims/Roadmap and Implementation

| Gap | Severity | Details |
|-----|----------|---------|
| **v2 module is empty** | Low (roadmap) | `src/secure_string_cipher/v2/` directory exists but contains only `__pycache__` - no `__init__.py`, no source files on `main`. PR #40 ("feat: add V2 managed-key value types") is open on the `codex/v2-module-skeleton` branch with actual code, but it hasn't been merged. |
| **`generate_key_pair()` still exported** | Medium | README does not mention RSA key-pair generation, but it's still exported from `__init__.py` and present in `core.py`. The SECURITY.md describes key-file as "legacy." This function feels orphaned - neither promoted nor deprecated. |
| **Audit stubs are thin** | Low | `AUDITS/CODEQL_ALERTS_FIX_PLAN.md` (349 bytes) and `AUDITS/DEPENDENCY_AUDIT.md` (377 bytes) are placeholders/stubs pointing elsewhere. |
| **`cryptography` 50.0.0 pinned; 50.0.1 pending** | Medium | PR #72 bumps to 50.0.1 but is unmerged. Pinned exact versions in prod deps means manual merge is required for every security patch. |
| **No separate `ssc start` entry point** | Clarification | `pyproject.toml` defines only `ssc = secure_string_cipher.cli_args:main`. The `ssc start` subcommand works, but the old `ssc-start` / `cipher-start` entries were removed. This is documented but some CHANGELOG entries still reference them. |
| **FAST_TRACK and STABILIZATION docs are stubs** | Low | 246 and 294 bytes respectively - these are pointers to archive, not standalone docs. |

---

## 3. GitHub State - Open PRs and Branch Health

### Open PRs (8 total, plus 1 feature PR)

| PR | Type | Priority | Action Needed |
|----|------|----------|---------------|
| #78 | Chore: copyright year 2025 to 2026 | Low | Merge after CI passes |
| #77 | CI: bump setup-uv 8.3.0 to 10.0.1 | Medium | **Major version bump** - review cache security changes |
| #76 | CI: bump docker/login-action 4.4.0 to 4.6.0 | Low | Merge |
| #75 | CI: bump pypi-publish 1.14.0 to 1.14.2 | Medium | Fixes upload timeout bug - merge promptly |
| #74 | CI: bump build-push-action 7.2.0 to 7.3.0 | Low | Merge |
| #73 | CI: routine GH Actions group bump | Low | Merge |
| #72 | Deps: cryptography 50.0.0 to 50.0.1 | **High** | Security dependency - merge and validate |
| #71 | Deps: routine Python deps bump (5 pkgs) | Medium | Review + merge |
| #40 | Feat: v2 managed-key value types | Low (future) | In-progress on `codex/v2-module-skeleton` branch |

### Branches

| Branch | Status |
|--------|--------|
| `main` | Protected, active, up-to-date |
| `codex/v2-module-skeleton` | Active feature branch - v2 managed-key work |
| `dependabot/*` (7 branches) | Pending dependency updates |

---

## 4. Coherence Assessment

### What's Working Well

1. **Honest documentation culture.** Every claim is either verified or explicitly caveated. The project doesn't overstate its security posture.
2. **Professional CI/CD pipeline.** Quality then test matrix then platform safety then coverage gate then secret scan then vulnerability scan. Release workflow verifies tag/artifact version match, rejects leaked private files, and uses trusted publisher OIDC.
3. **Immutable compatibility fixtures.** v4 and v5 fixtures with known binary payloads prevent regressions.
4. **Transactional vault operations.** The import/restore/backup pipeline with snapshot/readback/rollback is well-designed.
5. **Consistent formatting and tooling.** Ruff, mypy, pre-commit, detect-secrets, pip-audit - all pinned and locked.
6. **Dependabot is active.** Automated dependency PRs with labels and grouping.
7. **Clean public API.** `__init__.py` exports 56 well-organized symbols with `__all__`.

### What Needs Attention

1. **Dependency PR backlog.** 8 open PRs (6 Dependabot + 2 manual). The `cryptography` 50.0.1 bump should be prioritized - it's a security-critical dependency.
2. **v2 module is a ghost directory.** The empty `v2/` package on `main` with only `__pycache__` is confusing. Either merge PR #40 or remove the empty directory until v2 work is ready.
3. **Bloated CLI modules.** Both `cli.py` (~47 KiB) and `cli_args.py` (~47 KiB) are very large single files. They'd benefit from decomposition.
4. **`passphrase_generator.py` is 46 KiB.** This is surprisingly large for a passphrase generator and warrants inspection for dead weight.
5. **Test count discrepancy.** The CHANGELOG tracks test counts by version (from 353 to 826+), but no single document states the current test count. The count isn't in README or DEVELOPER.md by design ("Test counts are intentionally not fixed").
6. **`generate_key_pair()` is in limbo.** Exported but undocumented in README - should either be deprecated with a warning or properly documented.

---

## 5. Actionable Roadmap - What Needs to Be Done

### P0 - Do Immediately

| Task | Rationale |
|------|-----------|
| **Merge PR #72** (cryptography 50.0.1) | Security-critical dependency update. Validate v4/v5 fixtures pass, then merge. |
| **Merge PR #75** (pypi-publish 1.14.2) | Fixes upload timeout bug that blocks future releases. |
| **Clear Dependabot backlog** (#71, #73, #74, #76, #77, #78) | 6 non-controversial updates. Batch-merge after CI passes. For #77 (setup-uv major bump to v10), review cache security policy change before merging. |

### P1 - Before Next Release (v1.4.0 or v1.3.1)

| Task | Rationale |
|------|-----------|
| **Clean up empty `v2/` directory** on main | Remove the ghost `__pycache__`-only directory. v2 work lives on `codex/v2-module-skeleton` branch - the empty package on main is confusing and ships in the wheel. |
| **Resolve `generate_key_pair()` status** | Either (a) deprecate with `warnings.warn()` and remove from `__all__`, or (b) document it properly in README and API.md. Currently it's exported but invisible. |
| **Tag and release the [Unreleased] CHANGELOG work** | The `[Unreleased]` section in CHANGELOG.md contains massive security, compatibility, and documentation work (atomic writer, v5 metadata auth, strict parsing, transactional vault, etc.) that has been merged to `main` but never released. This is significant value sitting unshipped. |
| **Upgrade audit stubs** | `AUDITS/CODEQL_ALERTS_FIX_PLAN.md` and `AUDITS/DEPENDENCY_AUDIT.md` are under 400 bytes each. Either flesh them out or consolidate into the archive with redirect pointers. |
| **Update SECURITY.md support table** | SECURITY.md says "< 1.3: No" but the [Unreleased] work is substantially hardened beyond 1.3.0. When released, update the table. |

### P2 - Medium-Term (v2.0.0 Preparation)

| Task | Rationale |
|------|-----------|
| **Land PR #40** (v2 managed-key value types) | First concrete v2 code. Review the `codex/v2-module-skeleton` branch, which has ~20 commits of real implementation work. |
| **Implement the 9-step v2 PR sequence** from ROADMAP.md | The sequence is well-defined: (1) docs, (2) skeleton + dataclasses, (3) `.ssckey` format, (4) vault schema, (5) HKDF + DEK wrapping, (6) envelope + header auth, (7) payload + chunk frames, (8) CLI `--with` syntax, (9) migration guide. |
| **Decompose `cli.py` and `cli_args.py`** | Both are ~47 KiB monoliths. Extract shared utilities, vault operations, and file operations into focused submodules. This becomes more important as v2 CLI features are added. |
| **Add descriptor-level path opening** | Roadmap item. Replace lexical symlink preflight with `O_NOFOLLOW` / `openat()` for race-resistant path security. |
| **Design cross-process vault locking** | Roadmap item. Currently documented limitation. Need `fcntl.flock()` / Windows lock equivalent. |
| **Investigate `passphrase_generator.py` size** | At 46 KiB, it's the second-largest module. Likely contains embedded word lists. Verify whether they should be external data files. |

### P3 - Long-Term (v3.0.0 Vision)

| Task | Rationale |
|------|-----------|
| Multiple grants per encrypted object | ROADMAP.md v3 item |
| X25519 / HPKE public-key recipient grants | ROADMAP.md v3 item |
| Hardware-backed key grants | ROADMAP.md v3 item |
| SQLite encrypted-record vault backend | ROADMAP.md v3 item |
| Tamper-evident audit logging | ROADMAP.md v3 item |
| Independent third-party security audit | Stated as future work in README, SECURITY.md, and ROADMAP.md |

---

## 6. Summary for Gemini 3.1 Pro

> [!IMPORTANT]
> **Bottom line:** This is a well-engineered, honestly-documented solo-maintainer Python cryptography CLI at Beta stage. The codebase and its claims are coherent - what's claimed is implemented, and what's not yet done is honestly flagged as future work. The main risks are:
>
> 1. **Stale dependency PRs** - the `cryptography` 50.0.1 bump (PR #72) should be merged immediately.
> 2. **Unshipped hardening work** - the `[Unreleased]` CHANGELOG section contains substantial security improvements that have been merged to `main` but not tagged/released.
> 3. **v2 is design-only on main** - the architecture doc is approved and detailed, a feature branch has code, but `main` has an empty ghost module.
> 4. **Module size** - `cli.py`, `cli_args.py`, and `passphrase_generator.py` are all over 40 KiB single-file monoliths that will impede v2 development.
>
> The project needs a **v1.4.0 release** to ship the merged hardening work, a **dependency hygiene pass**, and then focused execution on the v2 roadmap.

### Key Numbers

- **17** production source modules, **~10,800** lines
- **43** test files across 5 categories (unit, integration, security, fuzz, performance)
- **85%** CI coverage gate (Python 3.14)
- **3** platform CI targets (Ubuntu, macOS, Windows)
- **28** published tags, **5** prod dependencies
- **8** open PRs (mostly Dependabot), **0** open Issues (all tracked as PRs)
- **1** active feature branch (`codex/v2-module-skeleton` for v2 managed keys)
