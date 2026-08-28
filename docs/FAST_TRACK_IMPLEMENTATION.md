# Fast-Track Safety Sprint Runbook

Baseline: `main` at `94f0587cda87038f440f8e4b90a17751e7cda26d`

Purpose: provide tightly bounded, independently reviewable packets that deliver
the highest-value safety improvements in approximately five working days.

## Outcome and Boundary

At completion, failed encryption and failed/authentication-rejected decryption
never replace or expose a partial final output. `--force` permits replacement
only after successful encryption or authenticated decryption. The destructive
fixed `.write_test` probe is removed; empty progress, strict text decoding,
strict base64, and relative-symlink inspection are corrected; existing vault
writes use the streaming atomic writer; and documentation states the Beta's
actual guarantees and limitations.

The legacy SSCV2 v4/v5 wire layout, metadata serialization, AES-GCM behavior,
Argon2 parameters, salt, nonce, and tag sizes do not change.

This sprint does not make the project stable. Transactional vault
import/restore authentication, descriptor-level path hardening, immutable
compatibility fixtures, cross-platform release CI, secret `.ssckey` files, and
SSC2 remain later work.

## Rules for Every Packet

1. Never delete or truncate an existing destination before a successful
   replacement.
2. Never publish decrypted plaintext before authentication succeeds.
3. Do not change v4/v5 cryptographic parameters or serialization.
4. Do not log secrets, plaintext, key material, vault data, or ciphertext.
5. Preserve generic public behavior for wrong credentials and damaged data.
6. Preserve public APIs except for the specified keyword-only `overwrite`
   parameters.
7. Add no dependencies and perform no unrelated refactoring.
8. Add regression tests before or with implementation.
9. Stop rather than widening a packet beyond its allowed files.
10. Before editing, verify the dependency commit, inspect status, preserve
    unrelated changes, and read the scoped production functions and tests.

Every packet report must list changed files, behavior, checks run, platform
limitations, unverified assumptions, and confirmation that the encrypted-data
format did not change.

## Dependency Order

```text
FT-01 atomic writer ─────┐
                         ├─> FT-03 atomic encryption
FT-02 isolated fixes ────┘          │
                                    v
                          FT-04 safe decryption/force
                                    │
                         ┌──────────┴──────────┐
                         v                     v
                   FT-05 truthful docs    FT-06 CI cleanup
```

Use one branch, one PR, and one security-focused commit per packet. FT-01 and
FT-02 may proceed independently. Do not mix Dependabot work into these branches.

## FT-01: Streaming Atomic Writer

Branch: `hardening/atomic-writer`. Allowed files: new `atomic_io.py`, new atomic
unit tests, `security.py`, and existing atomic-write security tests.

Required API:

```python
@contextmanager
def atomic_binary_writer(
    destination: str | Path,
    *,
    overwrite: bool = False,
    mode: int = 0o600,
) -> Iterator[BinaryIO]: ...
```

Use a unique `mkstemp` file in the existing destination directory, set mode
before writing, yield a buffered descriptor-backed binary stream, then flush,
file-`fsync`, close, recheck no-overwrite, and publish with `os.replace`. Sync
the parent on a best-effort basis where supported. Any caller, temporary-file
sync, or replace failure removes the temporary file without masking the
original exception and preserves the old destination. A directory-sync error
after `os.replace` is not reported as an operation failure because publication
is already irreversible. The no-overwrite check is best-effort and does not
claim hostile race resistance.

Route `secure_atomic_write()` through this API with `overwrite=True`, preserving
its signature and `0o600` policy. Tests cover create/refuse/replace, caller and
publication failures, cleanup, permissions, invalid parents, large payloads,
and existing byte-writer behavior.

## FT-02: Isolated Correctness and Safety

Branch: `hardening/isolated-correctness`. Allowed production files: `core.py`
and `utils.py`, plus directly relevant tests. Do not change CLI behavior.

- Remove `.write_test`; require an existing directory parent and let real output
  creation determine writability. Prove a legitimate `.write_test` is untouched.
- Build relative paths lexically from `Path.cwd() / path` before inspecting the
  final component and parents for symlinks. Preserve `/var` compatibility and
  document that this is preflight, not descriptor hardening.
- Decode text tokens with strict base64 and authenticated plaintext with strict
  UTF-8. Invalid UTF-8 raises `CryptoError`; byte APIs remain binary-safe.
- Render an empty completed TTY operation as 100% without division by zero and
  preserve non-TTY behavior.

## FT-03: Atomic Encryption and Safe Force

Branch: `hardening/atomic-encryption`, after FT-01 and FT-02.

```python
def encrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str,
    *,
    store_filename: bool = True,
    overwrite: bool = False,
) -> None: ...
```

Stream existing v5 header and ciphertext bytes into `atomic_binary_writer`.
Finalization and tag writing occur before publication. `cmd_encrypt()` never
unlinks; it forwards `overwrite=args.force`. Preserve header ordering, metadata,
AAD, chunking, salt/nonce placement, and tag placement. Tests inject midstream,
sync, and replace failures with and without old outputs, verify cleanup and
empty files, and prove forced CLI output is decryptable.

## FT-04: Authenticated Decryption Destination

Branch: `hardening/atomic-decryption`, after FT-03.

```python
def decrypt_file(
    input_path: str,
    output_path: str | None,
    passphrase: str,
    *,
    restore_filename: bool = True,
    overwrite: bool = False,
) -> tuple[str, FileMetadata | None]: ...
```

Replace local temporary publication with the atomic writer and finalize GCM
before context exit. Explicit output paths remain authoritative. With no output,
v5 may use only an authenticated, sanitized stored filename; v4 ignores its
unauthenticated stored filename and uses a deterministic `.dec` fallback.

Remove CLI metadata pre-parsing and all force-path unlinking. Pass explicit
`--output` or `None`, forward `overwrite=args.force`, and report the committed
path only after success. Adversarial tests cover malicious filename metadata,
wrong credentials, damaged tags, v4 hostile names, authenticated v5 restore,
existing destinations, cleanup, and absence of a visible final plaintext prefix.

## FT-05: Truthful Beta Documentation

Branch: `docs/truthful-beta-contract`, after FT-04. Production code is out of
scope. Update README, security/cryptography documents, API reference, changelog,
and roadmap.

State Beta status; opaque regular-file support up to 100 MiB; no directories or
large SSC2 objects; current v5 and legacy v4; actual metadata fields
`version`/`original_filename`/`key_commitment`; v5 metadata authentication and
v4 non-authentication; exact keyword-only overwrite APIs; atomic `--force`
semantics; and hostile path-race limitations.

State that legacy key-file mode hashes bytes into a symmetric passphrase rather
than providing public-key encryption; rate limiting is local; Python clearing is
best-effort; local JSON logs are editable; overwrite deletion is unreliable on
SSDs/COW/snapshots/journals; and vault import is structurally, not
cryptographically, validated before replacement. Do not claim homoglyph
prevention, SSC2 availability, independent audit, or stability. Add an
Unreleased section without changing package version.

## FT-06: CI Coverage Reporting

Branch: `ci/coverage-reporting-cleanup`, after FT-04 and parallel with FT-05.
Keep `--cov-fail-under=85`; remove the non-enforcing Codecov upload unless a
verified token exists; replace hard-coded coverage badges with CI status or
plain enforced-threshold text. Do not weaken tests, dependency audit, secret
scan, Ruff, mypy, or CodeQL, and do not add OS jobs in this packet.

## Five-Day Schedule

1. Create the runbook, enable branch protection manually, and review FT-01/02.
2. Merge prerequisites, implement/review FT-03, and run encryption regressions.
3. Implement FT-04 and give malicious-metadata and preservation tests special
   review; merge only after confirming no early delete/truncate remains.
4. Implement FT-05/06 from FT-04 and reconcile claims against source.
5. Run the complete suite and manual Linux/macOS/Windows smoke tests.

## Final Automated Verification

```bash
uv sync --extra dev --locked
uv run --locked ruff check src tests tools
uv run --locked ruff format --check src tests tools
uv run --locked mypy src
uv run --locked detect-secrets scan --baseline .secrets.baseline
uv run --locked pip-audit . --desc
uv run --locked pytest tests/ \
  --cov=secure_string_cipher \
  --cov-report=term-missing \
  --cov-report=json:coverage.json \
  --cov-report=xml \
  --cov-fail-under=85
```

Manual smoke tests cover empty and all-byte files, forced ciphertext
replacement, wrong-password hash preservation, corrupted-tag non-publication,
temporary-file cleanup, POSIX permissions, and existing v4/v5 samples on Linux,
macOS, and Windows.

## Review and Definition of Done

Review blocking destination deletion/truncation/exposure first, then format or
parameter drift, cleanup/preservation, unauthenticated metadata filesystem
influence, missing adversarial tests, secret leakage, and packet scope. A green
CI result alone is insufficient. FT-03 and FT-04 require a different model or
human reviewer.

The sprint is done only after all packets are merged in dependency order, full
checks and v4/v5 round trips pass, injected failures preserve outputs, no force
path pre-deletes, documentation says Beta, FT-03/04 receive separate approval,
and no stable label is applied.
