# Rebuild ledger

This file records where everything on the `v3` branch came from, so the owner's
pre-3.0 work, the rebuild brief, and new 3.0 work stay distinct. Every step in
[the game plan](GAME_PLAN.md) adds a line here.

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
| Phase 0: CI green on all three platforms for the empty package | Met on 2026-11-18 (#159 and #160) |
| Phase 1: review comments answered and vectors frozen | Vectors frozen (#166). Waiting on community review in Discussion #168 |

## Steps

| Brief step | Commit subject | What was added or changed |
| --- | --- | --- |
| Before Phase 0 | docs: add the SSC 3.0 rebuild game plan, verbatim | `rebuild/GAME_PLAN.md` |
| Before Phase 0 | chore: move every pre-3.0 file under legacy/, unchanged | 180 files renamed into `legacy/`, no content edits |
| Phase 0, step 1 | docs: write the 3.0 charter | `docs/CHARTER.md`, this ledger |
| Phase 0, step 2 | build: empty 3.0 package with three-platform CI | `pyproject.toml`, `uv.lock`, `src/secure_string_cipher/`, `tests/test_package.py`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `README.md`. The three-platform CI matrix is the idea carried over from `legacy/.github/workflows/ci.yml`, as section 8 of the brief suggests; the action pins are reused from it |
| Phase 0, step 3 | docs: freeze 2.x while 3.0 is rebuilt on the v3 branch | A README note on `main` (PR #161), outside this branch, approved by the owner |
| Phase 1, step 1 | docs(spec): draft the 3.0 file format | `docs/spec/FORMAT.md`. The payload rules (strict final chunk, no trailing data, limits checked before allocation) are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` sections 3 and 6. The separation of header and payload follows age, as section 9 of the brief says |
| Phase 1, step 2 | docs(spec): draft the 3.0 access spec | `docs/spec/ACCESS.md`. The exact Argon2id tuple (64 MiB, t=3, p=4) and the caveat that "all of" is not independent two-factor are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` sections 4.2 and 4.3. The n-factor HKDF derivation generalises SSC2's two-factor combined grant, as section 5 of the brief says |
| Phase 1, step 1 (fix) | docs(spec): require a fresh payload nonce for every payload written | `docs/spec/FORMAT.md` sections 4.3 and 7.4. A nonce-reuse flaw in the first draft, found while designing the vault |
| Phase 1, step 3 | docs(spec): draft the 3.0 vault spec | `docs/spec/VAULT.md`. The `.ssckey` rules (recompute and check the key ID, bounded read, refuse symlinks, owner-only writes) and the label pattern are carried over from `legacy/docs/SSC2_PROTOCOL_SPECIFICATION.md` section 9. The lock file is the idea behind 2.x's cross-process vault locking |
| Phase 1, step 4 | docs(spec): draft the 3.0 CLI contract and interactive flows | `docs/spec/CLI.md`. The exit-code taxonomy and the rules for credentials without a prompt (flag beats variable, no symlinks, no group or world-readable files) are carried over from `legacy/src/secure_string_cipher/cli_args.py` and `legacy/README.md`. The sensitive-output check comes from `legacy/tools/check_sensitive_output.py`, as section 8 of the brief says |
| Phase 1, step 2 (fix) | docs(spec): key the password-secret cache on the password too | `docs/spec/ACCESS.md` section 4, from Codex's review of #163 |
| Phase 1, step 3 (fix) | docs(spec): give trimmed history an explicit chain anchor | `docs/spec/VAULT.md` section 5, from Codex's review of #164 |
| Phase 1, step 5 | test: generate and freeze the 3.0 test vectors | `tools/vectors/generate.py` (throwaway: **delete at the Phase 2 gate**), `tests/vectors/` (14 valid, 23 rejection, a vault and a key file), `tests/test_vectors_frozen.py`, `.gitattributes`. The golden-vector approach and the manifest of hashes are the idea carried over from `legacy/tests/fixtures/`, as section 8 of the brief says |
| Phase 1, steps 2 to 5 (fixes) | Four commits, one per finding | From Codex's reviews of #164, #165 and #166: drop the undefined key folder (ACCESS.md); record a password change in history (VAULT.md); add `--key-file` and keep key files out of profiles (CLI.md); hash the key-file vector |
| Phase 1, steps 1 to 4 (decisions) | docs(spec): record the owner's decisions on every open question | Each spec's "Open questions" section becomes "Decisions": the owner accepted all twelve proposals on 2026-11-18 |
| Phase 1, step 6 | Discussion #168 (not a commit) | The access spec was posted for community review as GitHub Discussion #168, with Discussions turned on for the repository. Forum posts are made by the owner. The Phase 1 gate waits on those review comments being answered |
