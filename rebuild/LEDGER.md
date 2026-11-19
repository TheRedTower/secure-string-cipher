# Rebuild ledger

This file records where everything on the `v3` branch came from, so the owner's
pre-3.0 work, the rebuild brief, and new 3.0 work stay distinct. Every step in
[the game plan](GAME_PLAN.md) lands as a pull request and adds rows here: one row per
commit, grouped by PR. Merge commits and the "Merge branch 'v3' into …" commits
that keep a PR up to date add no content and are not listed.

## Where things live

| Path | What it is | Who wrote it |
| --- | --- | --- |
| `rebuild/GAME_PLAN.md` | The rebuild brief, unchanged | Project owner |
| `legacy/` | Every pre-3.0 file, moved unchanged. Reference only; deleted in Phase 5, step 2 | Project owner |
| `LICENSE`, `.gitignore` | Kept at the root, unchanged | Project owner |
| Everything else | New 3.0 work, done step by step from the brief | Claude, under the owner's direction |

Nothing under `legacy/` is built, linted, type-checked or run by CI. Code is
not copied out of `legacy/`; where 3.0 reuses an idea from it, the ledger
entry says which one.

## Gates

| Gate | Status |
| --- | --- |
| Phase 0: CI green on all three platforms for the empty package | Met on 2026-11-18 (#159) |
| Phase 1: review comments answered and vectors frozen | Vectors frozen (#166). Community review (Discussion #168) is still open. On 2026-11-19 the owner chose to start Phase 2 without waiting for it, and to answer those comments afterwards. Any spec change they cause is made through a PR that regenerates the vectors, restoring the generator from history (`git show becaf73~1:tools/vectors/generate.py`) |
| Phase 2: every vector passes and fuzzing is clean | Met with #176. Every valid vector opens and is reproduced byte for byte, every rejection vector fails for its named reason, the vault vector opens, and `test_vector_coverage.py` allows no exceptions. The fuzz suite is clean in CI and in a 140,000-example local run. The throwaway generator is deleted |

## Steps

### Phase 0: set up

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| #159 | Before Phase 0 | `14aa22e` docs: add the SSC 3.0 rebuild game plan, verbatim | `rebuild/GAME_PLAN.md` |
| #159 | Before Phase 0 | `4134401` chore: move every pre-3.0 file under legacy/, unchanged | 180 files renamed into `legacy/`, with no content edits |
| #159 | Step 1 | `0cf0eaa` docs: write the 3.0 charter | `docs/CHARTER.md` and this ledger |
| #160, merged through #159 | Step 2 | `2799083` build: empty 3.0 package with three-platform CI | `pyproject.toml`, `uv.lock`, `src/secure_string_cipher/`, `tests/test_package.py`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml` and `README.md`. The three-platform CI matrix is the idea carried over from `legacy/.github/workflows/ci.yml`, as section 8 of the brief suggests, and the action pins are reused from it |
| #161, on `main` | Step 3 | `446fc74` docs: freeze 2.x while 3.0 is rebuilt on the v3 branch, and `f218900` chore: stop Dependabot version updates for frozen 2.x | A README note on `main` and the removal of `main`'s Dependabot config. Merged by the owner on 2026-11-18 |

### Phase 1: design on paper

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| #162 | Step 1 | `8f112fe` docs(spec): draft the 3.0 file format | `docs/spec/FORMAT.md`. The payload rules (a strict final chunk, no trailing data, limits checked before allocation) are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` sections 3 and 6. The separation of header and payload follows age, as section 9 of the brief says |
| #162 | Step 1, fix | `e1733d4` docs(spec): require a fresh payload nonce for every payload written | FORMAT.md sections 4.3 and 7.4. Fixes a nonce-reuse flaw in the first draft, found while designing the vault |
| #163 | Step 2 | `0862556` docs(spec): draft the 3.0 access spec | `docs/spec/ACCESS.md`. Two things are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` sections 4.2 and 4.3: the exact Argon2id tuple (64 MiB, t=3, p=4), and the caveat that "all of" is not independent two-factor. The n-factor HKDF derivation generalises SSC2's two-factor combined grant, as section 5 of the brief says |
| #163 | Step 2, Codex fix | `395ab52` docs(spec): key the password-secret cache on the password too | ACCESS.md section 4 |
| #163 | Step 2, Codex fix | `5aaea95` docs(spec): drop the undefined "key folder" from the access spec | ACCESS.md sections 2.2 and 4 |
| #164 | Step 3 | `b0a76a0` docs(spec): draft the 3.0 vault spec | `docs/spec/VAULT.md`. The `.ssckey` rules (recompute and check the key ID, bounded reads, refuse symlinks, owner-only writes) and the label pattern are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` section 9. The lock file is the idea behind 2.x's cross-process vault locking |
| #164 | Step 3, Codex fix | `6cd0c6a` docs(spec): give trimmed history an explicit chain anchor | VAULT.md section 5 |
| #164 | Step 3, Codex fix | `7e1d69b` docs(spec): say how a password change is recorded when history is on | VAULT.md section 2 |
| #165 | Step 4 | `98c8df8` docs(spec): draft the 3.0 CLI contract and interactive flows | `docs/spec/CLI.md`. Two things are carried over from `legacy/src/secure_string_cipher/cli_args.py` and `legacy/README.md`: the exit-code taxonomy, and the rules for credentials without a prompt (the flag beats the variable, no symlinks, no group- or world-readable files). The sensitive-output check comes from `legacy/tools/check_sensitive_output.py`, as section 8 of the brief says |
| #165 | Step 4, Codex fix | `979a8e7` docs(spec): let scripts supply key files, and keep key files out of profiles | CLI.md sections 1, 3.1 and 3.4 |
| #165 | Step 4, Codex fix | `6ceeb60` docs(spec): define which recovery entry the recovery token picks | CLI.md sections 2 and 3.4 |
| #165 | Step 4, Codex fix | `663c9fa` docs(spec): add a new-master-password source, and hold stdout until authenticated | CLI.md section 1. The split between setting and using a master password is carried over from `legacy/README.md` |
| #165 | Step 4, Codex fix | `402600f` docs(spec): separate opening and new passwords, and avoid recovery-label clashes | CLI.md sections 1 and 2 |
| #165 | Step 4, Codex fix | `baa26fc` docs(spec): accept several opening passwords, and a scripted vault password entry | CLI.md section 1 |
| #166 | Step 5 | `482a9bc` test: generate and freeze the 3.0 test vectors | Adds `tools/vectors/generate.py` (throwaway: **delete at the Phase 2 gate**), `tests/vectors/` (14 valid vectors, 23 rejection vectors, a vault and a key file), `tests/test_vectors_frozen.py` and `.gitattributes`. The golden-vector approach and the manifest of hashes are the idea carried over from `legacy/tests/fixtures/`, as section 8 of the brief says |
| #166 | Step 5, Codex fix | `481e99a` test: include the key-file vector in the frozen hash checks | `tests/vectors/manifest.json` and `tests/test_vectors_frozen.py` |
| #166 | Step 5, Codex fix | `0f04e6b` test: record the unknown grant's bytes in the vector manifest | `tests/vectors/manifest.json` |
| #166 | Housekeeping | `04dae92` docs: keep the ledger's review-fix row in order | This ledger |
| #167 | Steps 1 to 4, decisions | `d4d6697` docs(spec): record the owner's decisions on every open question | Each spec's "Open questions" section becomes "Decisions". The owner accepted all twelve proposals on 2026-11-18 |
| Discussion #168 | Step 6 | (not a commit) | The access spec was posted for community review, and Discussions were turned on for the repository. Forum posts are left to the owner |
| #169 | Step 6 | `3827694` docs: record Phase 1, step 6 and the gate status in the ledger | This ledger |
| #170 | Housekeeping | `b1da387` docs: rebuild the ledger from git history | This ledger, now listing every commit grouped by PR |

### Phase 2: the engine

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| #171 | Step 1 | `5635852` feat(engine): the payload layer, passing its vectors | `src/secure_string_cipher/errors.py`, `engine/header.py` (the fixed header), `engine/payload.py` (64 KiB AES-256-GCM chunks with counter-and-flag nonces), `tests/vectorkit.py`, `tests/engine/`, and the `cryptography==50.0.2` dependency. The manifest now records `file_key` and `payload_nonce` for the rejection vectors too, with every vector file unchanged |
| #171 | Step 1, Codex fix | `d7ccc73` fix(engine): finish short writes to the sink | `engine/payload.py` gains `write_all`, and `read_exactly` is made public for the container |
| #172 | Step 2 | `6ec5108` feat(engine): the access layer, armour and container | `engine/access.py` (password and vault password factors, grants, the access-body parser, the access MAC, opening), `engine/armor.py`, `engine/container.py`, new reasons and `CannotOpen` in `errors.py`, and tests including `tests/engine/test_vector_coverage.py`. Adds `argon2-cffi==25.1.0`, with `argon2-cffi-bindings` held at 26.1.0. Vectors needing the key or recovery factor are listed as pending |
| #172 | Step 2, carried fix | `f65b1e1` fix(engine): finish short writes in the container and armour | `engine/container.py` and `engine/armor.py` |
| #172 | Housekeeping | docs: record Phase 2, step 2 in the ledger | This ledger, and the #170 row now names its commit |
| #173 | Step 3 | `4c8c44b` feat(engine): the managed-key factor and .ssckey files | The key factor in `engine/access.py` (`key_id`, `new_key`, keys in `Credentials`, matched by ID), `engine/keyfile.py` (VAULT.md section 6), `armor.split_lines` shared with key files, and new reasons `keyfile` and `keyfile-key-id`. Every vector passes except the three that need a recovery code |
| #173 | Housekeeping | docs: record Phase 2, step 3 in the ledger | This ledger |
| #173 | Step 3, Codex fix | `d5939fc` fix(engine): refuse symlinked parents and FIFOs when reading a key file | `engine/keyfile.py`: a no-follow walk from the root, and `O_NONBLOCK` |
| #173 | Step 3, Codex fix | `750948f` fix(engine): check every path component of a key file, ".." included | `engine/keyfile.py`: the path is made absolute without being normalised |
| #173 | Step 3, Codex fix | `7b793d9` fix(engine): walk a key file's parents with search-only descriptors | `engine/keyfile.py`: `O_PATH` or `O_SEARCH` for directories |
| #173 | Step 3, Codex fix | `2a3efb9` fix(engine): publish a new key file only once it is fully written | `engine/keyfile.py`: temporary file, fsync, then a no-replace link or rename |
| #174 | Step 4 | `7b1aed6` feat(engine): change access: add, remove and rotate | `engine/container.py` (`unlock`, `add_grant`, `remove_grant`, `rotate`), and `payload.chunks` and `payload.ChunkReader` so a payload streams straight into re-encryption, plus `tests/engine/test_change.py` |
| #174 | Housekeeping | docs: record Phase 2, step 4 in the ledger | This ledger, and the review fixes to #173 |
| #175 | Step 5 | `70decd4` build: add hypothesis 6.170.14 for fuzzing | `pyproject.toml` and `uv.lock` (dev group). 6.170.15 was under two weeks old |
| #175 | Step 5 | `7f93828` test: fuzz the header, access-block, armour and key-file parsers | `tests/fuzz/test_parsers.py`: 400 derandomised examples per property in CI. `SSC_FUZZ_EXAMPLES` runs a deeper random pass, and 20,000 per property ran clean |
| #175 | Housekeeping | docs: record Phase 2, step 5 in the ledger | This ledger |
| #176 | Gate | `da9fbe6` feat(engine): the recovery code factor, so every vector passes | `engine/access.py` (`new_recovery`, `recovery_secret`, `Credentials.recovery_codes`) and the remaining vector tests. The printed form stays with Phase 3, step 4 |
| #176 | Gate | `becaf73` chore: delete the throwaway vector generator at the Phase 2 gate | Deletes `tools/vectors/generate.py`; the spec notes on the vectors say so |
| #176 | Gate | `58299e6` test: unit tests for the recovery code factor | `tests/engine/test_access.py` |
| #176 | Housekeeping | docs: record the Phase 2 gate in the ledger | This ledger |


### Phase 3: the vault

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| #177 | Step 1 | `1597cf5` refactor: share safe owner-only writes and add a writer lock | `src/secure_string_cipher/fs.py`: the temporary-file-then-rename write from `engine/keyfile.py`, now with a replacing mode and a folder sync, plus `locked()` (`flock` on POSIX, `msvcrt.locking` on Windows). Key files use it unchanged in behaviour. Windows ACLs: SSC sets none and relies on what the per-user data folder grants; this is the Phase 3 decision VAULT.md section 1 asks for, to be confirmed at the gate |
| #177 | Step 1 | `bb56259` feat(engine): replace a payload under the same file key | `engine/container.py`: `replace_payload` (FORMAT.md section 7.4, always a fresh payload nonce), and `rewrite_access` made public for the vault |
| #177 | Step 1 | `f94a935` build: add platformdirs 4.14.5 for the vault location | `pyproject.toml` and `uv.lock`. 4.14.6 and 4.14.7 were under two weeks old |
| #177 | Step 1 | `fd2ee23` feat(vault): the vault object with its master-password grant | `vault/document.py` (the canonical JSON document of VAULT.md section 3, parsed strictly in full, with history's chain left to step 5), `vault/store.py` (`create`, `load`, `edit`, `change_master_password`, the lock and the 16 MiB limit), new `vault-document` and `vault` reasons and `VaultError` in `errors.py`, `tests/vault/`, and a fuzz property for the document parser |
| #177 | Housekeeping | docs: record Phase 3, step 1 in the ledger | This ledger |
| #177 | Step 1, Codex fix | `86917a4` fix: treat the rename as the commit point of a safe write | `fs.py`: a failed folder sync after the rename raises `fs.NotDurable` instead of looking like an aborted write, and a folder that cannot be synced is skipped. `tests/test_fs.py` |
| #177 | Step 1, Codex fix | `c592b0b` fix(vault): bound the vault file before reading it | `vault/store.py`: `max_file_size()`, the largest armoured CRLF file a 16 MiB document can make |
| #177 | Step 1, Codex fix | `22777f1` fix(vault): report an over-long JSON integer as a FormatError | `vault/document.py` |
| #178 | Step 2 | `3a58826` feat(vault): password and key entries, and the vault-entry factor | `vault/entries.py`: adding password and key entries (passwords stored NFC-normalised), importing and exporting key files with the key unchanged, archiving and revoking, `factor()` for `vault:<label>` (active entries only), and `credentials()` for opening (every entry not revoked). `tests/vault/test_entries.py` opens the vault-password and key vectors through vault entries |
| #178 | Housekeeping | docs: record Phase 3, step 2 in the ledger | This ledger |
