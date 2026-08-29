# SSC Stabilization Tranche 2

Status: local implementation and audit handoff for a Beta candidate. This is
not a release announcement, stable contract, or third-party audit report.

## Scope and Integration

The tranche began from the completed fast-track integration commit `2981e99`
and repository baseline `94f0587cda87038f440f8e4b90a17751e7cda26d`.
The local documentation branch integrates these reviewed packets:

| Packet | Commit | Result |
| --- | --- | --- |
| ST2-01 cryptography 50 | `7de8b7b` | Locked upgrade from 49.0.0 to 50.0.0; no format change |
| ST2-02 released fixtures | `f3d2e61` | Authentic v4/v5 immutable fixtures |
| ST2-03 platform matrix | `9c9ea80` | Focused Ubuntu/macOS/Windows Python 3.12 workflow |
| ST2-04 strict parser | `15c5835` | Strict v4/v5 read-side metadata validation |
| ST2-05 vault validator | `b9c1ef7` | Side-effect-free six-line vault validation |
| ST2-06 vault recovery | `8175588` | Transactional import/restore and safe backup retention |

No release tag was created, no package version was changed, and no remote
branch, pull request, protection rule, or release was mutated by this local run.

## Claims to Evidence

| Claim | Implementation evidence | Regression evidence |
| --- | --- | --- |
| Failed file encryption never publishes a partial destination | `atomic_binary_writer()` and `encrypt_file()` | Atomic writer, core, CLI, and platform-safety failure injection |
| Plaintext is not published before authentication | `decrypt_file()` finalizes GCM inside the atomic writer | Wrong-password, corrupt-tag, hostile-metadata, and destination-preservation tests |
| `--force` never pre-deletes | CLI passes keyword-only `overwrite`; core performs final replacement | Encryption/decryption force failure tests |
| v4 filename is untrusted; v5 filename is authenticated | Strict metadata parser and authenticated destination selection | Authentic v4/v5 fixtures plus hostile filename tests |
| Legacy wire compatibility is exercised across chunk boundaries | Immutable released-writer fixtures over a 1,094,205-byte payload | `tests/integration/test_legacy_fixtures.py` |
| Vault candidates authenticate before mutation | `validate_raw_vault()` and transaction service ordering | Wrong password, corrupt framing/HMAC/body/tag/JSON/schema, and truncation matrix |
| Vault publication is verified and failures roll back | Exact read-back comparison, revalidation, retained prior raw state | Write, read-back, post-validation, rollback success/failure tests |
| Backups use collision-resistant identifiers, refuse observed existing entries, and preserve restore sources during rotation | Best-effort no-overwrite preflights; timestamp plus random suffix; protected retention set; hostile concurrent-create races remain out of scope | Collision, same-timestamp, five-record, failure, and future-mtime tests |
| Secret material does not reach public errors/logs | Generic transaction errors and fixed audit categories | Sensitive-output guard and secret-free exception/log test |

## Vault Transaction Contract

Import and restore use the currently configured `PassphraseVault` backend.
They do not construct a file-only vault in CLI handlers.

1. Read the candidate through the 100 MiB bounded file reader when applicable.
2. Parse exactly six raw lines; enforce strict UTF-8, separators, lowercase hex,
   strict Base64, HMAC length, and decrypted JSON schema.
3. Verify HMAC, authenticate/decrypt, reject duplicate or non-string entries.
4. Retain the current raw active value or its absence.
5. Publish an exact encrypted backup with a collision-resistant identifier.
6. Write the already validated candidate through the configured backend.
7. Read back exact raw contents, compare, and run the same validator again.
8. On steps 6-7 failure, restore the retained prior value or prior absence.
9. Report success only after read-back validation; otherwise report whether
   rollback succeeded without including secrets.

Restore resolves an exact identifier, validates the selected record before
confirmation/mutation, uses the same transaction path, and never automatically
deletes its selected source. Retention protects both that source and the newly
created pre-replacement snapshot, even if mtimes are future-dated or the system
clock moves backward.

### Failure categories

| Stage | Public category | Active-state guarantee |
| --- | --- | --- |
| Candidate bound/read | `candidate_too_large` / `candidate_read_failed` | No backend mutation |
| Candidate authentication/schema | `candidate_validation_failed` | No backend mutation |
| Initial active read | `active_read_failed` | No write attempted |
| Backup publication | `backup_failed` | Active raw value unchanged |
| Active write/read-back/revalidation | `publication_failed` | Rollback completed and prior state verified |
| Rollback operation/read-back | `rollback_failed` | High-severity warning; active state may be inconsistent |

## Backend Guarantees

- File vault and backup publication uses same-directory atomic replacement,
  restrictive POSIX file mode, temporary-file sync, and failure cleanup.
- Parent-directory sync after replacement is best effort where supported. A
  failure there is not reported as if the already-published destination were
  still replaceable.
- Native credential stores do not expose a multi-record atomic transaction.
  Their rollback is best effort and crash atomicity is not claimed.
- There is no cross-process vault lock. Concurrent processes can still race.

## Compatibility Fixtures

The fixture credential is public test data and the payload is deterministic,
synthetic, and non-sensitive.

| Fixture | Producer | Commit | SHA-256 |
| --- | --- | --- | --- |
| `payload.bin` | deterministic test generator | n/a | `eb201352e0a8bfe4c333ca7ad4580932d6803164ca824ecf43a7f7f28ef84a68` |
| `file-v4.ssc` | release `v1.2.10` | `f7e3fc797e737ddfdd2a27d28cafec6dc5d710cb` | `5e506bc990439ae8249aeae04e88a71fb1aa21c6e9fa8a7d9f9545fe0519551d` |
| `file-v5.ssc` | release `v1.3.0` | `f7ff04c4d5a0adc0cbdc3cb841d5048f2f14dcac` | `df1f06b8f8c4861bbd950f4db8863fae18422a33aa9276295c2b68069bee9c97` |

Both released writers ran under CPython 3.14.7 on macOS 26.5.1 arm64 in
disposable detached worktrees using their locked environments. Tests verify
hashes, metadata behavior, decryption, wrong-password preservation, and
corruption rejection; they never regenerate fixture bytes.

## Dependency and Format Result

The only locked production dependency change since `2981e99` is
`cryptography==49.0.0` to `cryptography==50.0.0`. The package was imported and
its version checked in the locked environment; the full local suite and fixture
suite passed. `pip-audit . --desc` reported no known vulnerabilities.

The SSCV2 v4/v5 magic, metadata serialization written by the current writer,
salt, nonce, tag, Argon2 parameters, AES-GCM behavior, AAD, chunk size, header
ordering, and tag placement did not change. The six-line vault writer format,
Argon2/HMAC construction, and encrypted-text format also did not change.

## Local Validation Record

Environment used for the final local gate:

- Host: macOS 26.5.1 arm64
- Python: 3.14.7
- Dependency manager: uv version recorded in the final artifact section
- Minimum package Python: 3.12 (`requires-python = ">=3.12"`)

Results recorded before final packaging:

- Ruff check: passed
- Ruff format check: passed
- mypy `src`: passed
- detect-secrets baseline scan: passed
- pip-audit: no known vulnerabilities
- Integrated focused parser/fixture/platform/vault set: 164 passed
- ST2-06 final full gate before integration: 996 passed, 89.46% coverage

The final integrated full-suite count and coverage are recorded in the external
maintainer handoff produced after the final commit.

## Platform CI Status

The workflow defines:

- Ubuntu general tests on Python 3.12, 3.13, and 3.14, with the enforced 85%
  coverage gate on 3.14.
- Focused platform-safety tests on `ubuntu-latest`, `macos-latest`, and
  `windows-latest` using Python 3.12.

This local run did not push a branch, so there are no remote Linux/macOS/Windows
job results to claim. The required branch-protection check name and successful
remote matrix runs remain maintainer gates. Local macOS evidence alone does not
satisfy that external acceptance item.

## Package Artifact Record

The final build produces `secure_string_cipher-1.3.0-py3-none-any.whl` and
`secure_string_cipher-1.3.0.tar.gz`. Exact artifact SHA-256 hashes and isolated
wheel/sdist smoke results are recorded in the external maintainer handoff. They
cannot be embedded in this source-distribution input without changing the
source distribution and therefore invalidating its own recorded hash.

The smoke contract is: import/version, CLI help, empty and binary file
round-trips, authentic v4/v5 decryption, and wrong-password destination
preservation. Repository-only fixture files are copied into the isolated smoke
workspace as external test inputs; package runtime must not import them.

## Independent Review Record

- ST2-01: approved; dependency upgrade did not change cryptographic source or
  formats.
- ST2-02: approved after replacing the initial undersized payload with a true
  multi-chunk fixture.
- ST2-03: workflow reviewed locally; remote OS execution remains pending.
- ST2-04: approved; strict reader-only parser, no writer/format change.
- ST2-05: approved after rejecting unauthenticated surrounding whitespace and
  preserving the exact released-writer fixture representation.
- ST2-06: approved at `8175588` after fixing selected-source retention and
  protecting the newly published snapshot from clock/mtime anomalies.

## Deferred Risks

1. No descriptor-level path opening or hostile race-free no-replace primitive.
2. No cross-process vault locking; concurrent operations can race.
3. Native credential-store rollback is best effort and real OS keychains are
   not exercised by the focused CI job.
4. No independent third-party security audit has been completed.
5. No real secret `.ssckey` design is implemented; legacy key-file mode hashes
   identical file bytes into the same symmetric passphrase.
6. No SSC2 large-object/directory format is implemented.
7. Local rate limiting does not prevent offline guessing; Python memory clearing
   is best effort; audit JSON is editable; overwrite-based deletion is
   unreliable on SSD/COW/snapshot/journaled storage.
8. Remote platform jobs and branch-protection configuration are not locally
   verifiable until a maintainer pushes the branch.

## Beta Go/No-Go

Local code and artifact readiness can receive a **conditional Beta go** only if
the final integrated gates and both isolated artifact smoke suites pass.
Repository merge or release is **no-go** until the required protected-branch
checks are configured and the remote Ubuntu/macOS/Windows focused matrix passes.
No stable release label should be applied.
