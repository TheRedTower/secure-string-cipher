# Local V2 fixes and validation

Reviewed baseline: local `codex/v2-module-skeleton`, commit
`002aacc22380dd0f4bafd8f01afdd28b724a4fb8`.

These are local, uncommitted repairs to the defects identified in the preceding
review. The four supplied planning documents were preserved. No Git remote was
accessed, and no merge, rebase, push, version change, or release was performed.
The branch still has its original baseline; reconciliation with newer local
`main` remains separate work.

## Changes, in implementation order

1. **Vault document transactions.** Migration, managed-key mutations, password
   rotation, and passphrase mutations retain the exact original storage snapshot.
   Saves validate the intended document and encoded candidate, enforce the raw
   size limit before encryption, back up, reject stale snapshots, publish, and
   authenticate an exact read-back. Failed publication, verification, or
   cancellation restores and verifies the original bytes or absence. Rollback
   failure reports possible active-state inconsistency and a backup identifier.
   First-key creation no longer publishes an intermediate schema migration.

2. **Legacy and structured validation.** `validate_raw_vault` again rejects
   structured documents. V2-aware passphrase operations use the complete-document
   validator and preserve every managed-key record. V2 migration rejects existing
   empty/malformed storage. The legacy passphrase API's existing empty-file
   initialization behavior remains supported. Vault serialization retains the
   shared canonical encoding and depth limit without applying the protected
   header's 1,024-node cap to the passphrase namespace.

3. **Inner secrets and backend copies.** Import and restore verify usable inner
   secrets before publication. Password rotation reuses one old and one new root;
   it verifies rewrapped records and preserves old-password backups. Exact raw
   read-back equality carries the candidate's inner-secret verification to the
   published object without another inner-root derivation. Backend copies acquire
   both locks in deterministic order, preserve the source, and use destination
   verification and rollback. Oversized source files fail before constructing a
   keychain adapter.

4. **Lock ownership.** Reentrancy is limited to the owning thread. Forked children
   clear inherited ownership and close inherited lock descriptors. Raw writes,
   reset, import, restore, and backend copies cooperate with the shared locks.
   Lock files reject symlinks, nonregular files, and multiple hard links; POSIX
   locks require current-user ownership and owner-only permissions.

5. **Keyfile safety.** Secret bytes are excluded from dataclass representations.
   Publication writes and syncs a complete temporary file, then uses a hard link
   that refuses an existing or concurrently created destination. Parent symlinks
   are rejected on reads and writes. Filesystems without hard-link support fail
   before publication. Keyfile parsing bounds input, validates exact dates and
   version spelling, checks secret/fingerprint consistency, and accepts omission
   of the single final transport newline as specified.

6. **Derivation and immutable inputs.** Vault roots pass Argon2 version 19
   explicitly. Direct Argon2 entrypoints reject unsupported version values before
   calling the KDF. V2 password bounds apply before derivation. Mapping proxies
   are copied recursively rather than retained, and grant projections reject
   non-string keys instead of coercing them.

## Regression evidence

48 new regression cases cover publication corruption/failure/cancellation,
snapshot changes, failed backups and rollbacks, absent and malformed storage,
large passphrase collections, unusable imported secrets, password rotation and
old-backup recovery, simulated keychain failures, competing process updates,
thread/fork ownership, process-death release, keyfile overwrite races and secret
representations, canonical dates, immutable mappings, and KDF rejection.

Existing tamper tests now construct hostile raw storage directly because normal
saves reject unusable inner records. Existing transaction doubles inject failures
at the publication boundary after the new pre-publication snapshot read. Their
rollback and compatibility assertions remain intact.

## Verification

- Environment synchronized with `uv sync --extra dev --locked`.
- `make lint`: passed (format, Ruff, mypy, sensitive-output guard).
- Secret hook on changed tracked files and new source/test files: passed; the
  secret baseline was unchanged.
- Focused tests passed after each step. The first full run exposed a source-size
  preflight regression; it was repaired, and the affected 73 tests passed.
- Final full suite with branch coverage: 1,364 passed in 136.34s; 88.99% total coverage.
- Offline wheel and sdist build: passed using `uv build --offline`.
- Both packages include the new path helper and V2 modules plus `py.typed`.

Final test command:

```text
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=term-missing --cov-fail-under=85 -n 0 --maxfail=10
```

Build artifacts are local to `/tmp/ssc-v2-local-fixes-dist/`.

## Remaining acceptance boundaries

This is implementation and local validation evidence, not the independent
Gemini/Claude security-review evidence required by the supplied implementation
guide. That review is still outstanding. The prior local review did not establish
whether such reviews had occurred elsewhere.

Validation is on macOS with Python 3.14.7. Windows/Linux behavior, real credential
stores, and their capacity/ACL behavior were not verified. Advisory locks do not
protect against hostile same-user processes or older noncooperating clients.
Path checks do not establish protection against every hostile concurrent parent
directory substitution. Python immutable secret bytes have no guaranteed wipe.

These repairs do not complete the later payload, envelope-parser, CLI, or release
stages, nor constitute a fresh exhaustive audit of every V2 protocol requirement.
