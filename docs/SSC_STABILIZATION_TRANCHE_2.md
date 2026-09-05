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

## PR #67 Post-Review Repair Addendum

Independent review of exact PR head
`4998426a0b1d2d73073d4425b5cd50cb0b2632fc` found bounded defects despite green
checks. The local repair remains four serial packets: metadata compatibility and
canonical Base64; vault transport and recovery reporting; bounded regular-file
processing and temporary cleanup; then CI/documentation/acceptance closure.

The repaired contract is:

- stored filenames are bounded metadata. Version 5 authenticates the exact
  original bytes before sanitizing a name for automatic destination use;
  version 4 names are ignored, and explicit destinations remain authoritative;
- vault core APIs require canonical six-line bytes. Only CLI import removes
  exactly one terminal LF or CRLF from a bounded raw candidate for compatibility
  with older redirected exports;
- `MAX_FILE_SIZE` is the maximum plaintext payload for file encryption and
  decryption. SSC framing overhead is additional. Active/candidate vault
  representations and legacy key files separately use the same value as a
  raw-byte cap, and vault writes enforce the same read-back bound; and
- opened inputs must be regular files, descriptor snapshots are checked before
  key derivation, and cumulative counters reject later growth.

The historical validation records below remain evidence for their stated
commits only. They are not presented as validation of the post-review repair.

## Claims to Evidence

| Claim | Implementation evidence | Regression evidence |
| --- | --- | --- |
| Failed file encryption never publishes a partial destination | `atomic_binary_writer()` and `encrypt_file()` | Atomic writer, core, CLI, and platform-safety failure injection |
| Plaintext is not published before authentication | `decrypt_file()` finalizes GCM inside the atomic writer | Wrong-password, corrupt-tag, hostile-metadata, and destination-preservation tests |
| The 100 MiB limit denotes plaintext rather than container size | Descriptor size plus parsed SSC framing; cumulative encrypt/decrypt counters | Exact-limit container-overhead, limit-plus-one, underreported-growth, and platform regressions |
| `--force` never pre-deletes | CLI passes keyword-only `overwrite`; core performs final replacement | Encryption/decryption force failure tests |
| Stored names remain compatible without becoming paths | Bounded metadata parser; authenticated v5 destination sanitization; v4 fallback | POSIX path-shaped writer/reader closure, hostile-name, and authentic v4/v5 fixture tests |
| Legacy wire compatibility is exercised across chunk boundaries | Immutable released-writer fixtures over a 1,094,205-byte payload | `tests/integration/test_legacy_fixtures.py` |
| Vault candidates authenticate before mutation | `validate_raw_vault()` and transaction service ordering | Wrong password, corrupt framing/HMAC/body/tag/JSON/schema, and truncation matrix |
| Active vault data cannot bypass or contradict the raw cap | Shared descriptor reader, incremental UTF-8 counting, and bounded writes/backups/migrations | Exact/plus-one, multibyte, growth, nonregular, CRUD, transaction-no-write, export, and migration tests |
| Exported vault bytes round-trip across OS text conventions | Binary stdout export; one-ending CLI compatibility boundary; strict core validator | Exact export/import, LF/CRLF legacy, other-whitespace rejection, and Windows translation tests |
| Vault publication is verified and failures roll back | Exact read-back comparison, revalidation, retained prior raw state | Write, read-back, post-validation, rollback success/failure tests |
| Backups use collision-resistant identifiers, refuse observed existing entries, and preserve restore sources during rotation | Best-effort no-overwrite preflights; timestamp plus random suffix; protected retention set; hostile concurrent-create races remain out of scope | Collision, same-timestamp, five-record, failure, and future-mtime tests |
| Secret material does not reach public errors/logs | Generic transaction errors and fixed audit categories | Sensitive-output guard and secret-free exception/log test |

## Vault Transaction Contract

Import and restore use the currently configured `PassphraseVault` backend.
They do not construct a file-only vault in CLI handlers.

1. Read file candidates from an opened regular descriptor with a 100 MiB raw
   cap and a `limit + 1` growth check.
2. At the CLI import boundary only, remove exactly one terminal LF or CRLF left
   by an older redirected export. Direct API callers receive no normalization.
3. Parse exactly six raw lines; enforce strict UTF-8, separators, lowercase hex,
   strict Base64, HMAC length, and decrypted JSON schema.
4. Verify HMAC, authenticate/decrypt, reject duplicate or non-string entries.
5. Retain the current raw active value or its absence.
6. Publish an exact encrypted backup with a collision-resistant identifier.
7. Write the already validated candidate through the configured backend.
8. Read back exact raw contents, compare, and run the same validator again.
9. On steps 7-8 failure, restore the retained prior value or prior absence.
10. Report success only after read-back validation; otherwise report whether
   rollback succeeded without including secrets.

Active file-vault CRUD, export, backup, migration, transaction snapshot,
read-back, and rollback verification use the same bounded descriptor reader.
Keychain strings are counted incrementally by UTF-8 byte length before they are
validated, backed up, or stored.

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
- Sensitive temporary paths remain available for a final cleanup retry after
  handles close if an earlier unlink fails transiently.
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

Historical results recorded before the original tranche's final packaging:

- Ruff check: passed
- Ruff format check: passed
- mypy `src`: passed
- detect-secrets baseline scan: passed
- pip-audit: no known vulnerabilities
- Integrated focused parser/fixture/platform/vault set: 164 passed
- ST2-06 final full gate before integration: 996 passed, 89.46% coverage

These counts predate the PR #67 post-review repairs and are not used as current
acceptance evidence.

### PR #67 post-review local acceptance

The four planned repair commits and subsequent remote-acceptance follow-ups were
validated locally on 2026-09-01. The follow-ups made the Windows active-vault
fixture use the real byte-exact writer, restricted temporary-removal suppression
to filesystem errors, and excluded symlinks/non-files from backup rotation:

- Ruff check and format check: passed
- mypy `src`: passed
- sensitive-output guard: passed
- enforcing `detect-secrets-hook` invocation over tracked files: passed
- `pip-audit . --desc`: no known vulnerabilities
- Integrated focused safety set: 627 passed
- Focused final atomic/transaction set: 64 passed
- Full serial suite: 1,174 passed in 107.70 seconds
- Branch coverage: 90.01%, above the enforced 85% floor

Immutable fixture verification also passed:

- `payload.bin` (1,094,205 bytes):
  `eb201352e0a8bfe4c333ca7ad4580932d6803164ca824ecf43a7f7f28ef84a68`
- `file-v4.ssc` (1,094,374 bytes):
  `5e506bc990439ae8249aeae04e88a71fb1aa21c6e9fa8a7d9f9545fe0519551d`
- `file-v5.ssc` (1,094,374 bytes):
  `df1f06b8f8c4861bbd950f4db8863fae18422a33aa9276295c2b68069bee9c97`
- Decoded current-vault fixture (405 bytes):
  `7da09b6852e28060ee416d03a44d8df3c59bcad57b6e10e82d10edb44f81e16d`

This is local macOS evidence for the repaired commit series. It does not claim
the required remote protected checks, cross-platform jobs, review-thread
resolution, approval, merge authorization, or release acceptance.

## Platform CI Status

The workflow defines:

- Ubuntu general tests on Python 3.12, 3.13, and 3.14, with the enforced 85%
  coverage gate on 3.14.
- Focused platform-safety tests on `ubuntu-latest`, `macos-latest`, and
  `windows-latest` using Python 3.12. The selection includes released fixtures,
  file/transport boundaries, strict vault candidates, and backend-independent
  vault transaction/rollback tests.

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

1. No descriptor-relative no-follow path opening or hostile race-free
   no-replace primitive. Post-open descriptor checks do not close those races.
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
