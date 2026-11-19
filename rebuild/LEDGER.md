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
| Phase 1: review comments answered and vectors frozen | Vectors frozen (#166). Community review (Discussion #168) is still open. On 2026-11-19 the owner chose to start Phase 2 without waiting for it, and to answer those comments afterwards. Any spec change they cause is made through a PR that regenerates the vectors |

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
| This PR | Housekeeping | docs: rebuild the ledger from git history | This ledger, now listing every commit grouped by PR |

### Phase 2: the engine

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| This PR | Step 1 | feat(engine): the payload layer, passing its vectors | `src/secure_string_cipher/errors.py`, `engine/header.py` (the fixed header), `engine/payload.py` (64 KiB AES-256-GCM chunks with counter-and-flag nonces), `tests/vectorkit.py`, `tests/engine/`, and the `cryptography==50.0.2` dependency. The manifest now records `file_key` and `payload_nonce` for the rejection vectors too, with every vector file unchanged |

