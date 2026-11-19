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
| Phase 3: changing the master password rewraps one grant, and the vault works on all three platforms | Met with #182. `test_changing_the_master_password_rewraps_one_grant` runs on the frozen vault with history off (payload untouched) and on (one appended `vault-access-change` event). `test_the_real_os_keychain` unlocks a vault through macOS Keychain, Windows Credential Manager and Secret Service in CI, and `test_the_vault_is_owner_only_on_windows` checks the Windows ACLs by SID |

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
| #179 | Step 3 | `1b233e8` build: add keyring 25.7.0 for the device unlock key | `pyproject.toml` and `uv.lock`, with its dependencies `jaraco.*`, `more-itertools`, and `SecretStorage` and `jeepney` on Linux and `pywin32-ctypes` on Windows. All are over two weeks old |
| #179 | Step 3 | `0c8cb22` feat(vault): unlock the vault with a device key in the OS keychain | `vault/keychain.py`: the `ssc` / `vault-unlock:<key_id>` item, accepting only the macOS, Windows and Secret Service backends (never a plain file), `credentials()` read from the vault header, `add_device` and `remove_device`. `vault/store.py`: `Session.add_grant`, `remove_grant` (the master grant always stays), and `after_write` and `on_abort` actions, so a keychain item never outlives a vault write that failed. `container.binary_stream` made public |
| #179 | Step 3 | `948160a` ci: test the real OS keychain on all three platforms | `.github/workflows/ci.yml`: `SSC_KEYCHAIN_TESTS=1`, and an unlocked gnome-keyring under `dbus-run-session` on Linux |
| #179 | Housekeeping | docs: record Phase 3, step 3 in the ledger | This ledger |
| #179 | Step 3, CI fix | `f4980fb` ci: unlock gnome-keyring with a password so no prompt is needed | `.github/workflows/ci.yml`: an empty password left no login collection, and creating one needed a prompt |
| #179 | Step 3, Codex fix | `9bc3d4f` fix(vault): treat any keychain backend failure as no device key, and bound the header read | `vault/keychain.py`: Secret Service errors that are not a `KeyringError` now fall back to the master password. `vault/store.py`: `read_file`, the size-bounded read now shared with `keychain.credentials` |
| #180 | Step 4 | `3ffc97c` feat(engine): the printed form of a recovery code, passing its vectors | `engine/recovery.py`: Crockford Base32 of `R` and its 2-byte check in 8 groups of 4, read ignoring case, spaces and hyphens, with O, I and L read as digits. New reasons `recovery-code` and `recovery-check`, and `RecoveryCodeError` (an input error). `tests/engine/test_recovery.py` covers every `recovery_codes` vector |
| #180 | Step 4 | `2159d55` feat(vault): recovery entries, and a recovery code for the vault itself | `vault/entries.py`: `add_recovery`, and `choose_recovery` for the `recovery` token (CLI.md section 2). `vault/store.py`: `Session.add_recovery_grant`, and `reset_master_password`, which needs the vault's own recovery code |
| #180 | Step 4 | `9727abc` feat(vault): profiles | `vault/profiles.py`: create, replace, delete and apply. A profile must name active entries; one naming an archived, revoked or missing entry is refused until edited. `tests/vault/test_recovery_and_profiles.py` |
| #180 | Housekeeping | docs: record Phase 3, step 4 in the ledger | This ledger |
| #180 | Step 4, Codex fix | `5e2b80e` fix(vault): refuse a profile grant that repeats a factor on the wire | `vault/profiles.py`: two recovery entries, or two key entries holding the same key, in one grant would encode the same factor, which `new_grant` refuses |
| #181 | Step 5 | `87d7272` feat(vault): check the history chain when reading the vault | `vault/document.py`: `GENESIS`, `event_hash`, and the chain checks of VAULT.md section 5 in `History`, so `parse` rejects a broken chain, and an empty history that was trimmed or has a moved anchor |
| #181 | Step 5 | `c96e777` feat(vault): opt-in history | `vault/history.py` (`turn_on`, `turn_off`, `record`, trimming to the newest 1,000 events by moving the anchor). Entries record `entry-create`, `entry-archive` and `entry-revoke`; profiles record `profile-change`; `Session.record` is there for `vault-unlock`, `encrypt` and `decrypt`; a write that changes the grants records `vault-access-change`, which with history on replaces the payload. `tests/vault/test_history.py`, and the gate test now covers history both off and on |
| #181 | Housekeeping | docs: record Phase 3, step 5 in the ledger | This ledger |
| #182 | Gate | `ec859b2` test: check the vault is owner-only on Windows by its ACL | `tests/vault/test_store.py`: no Everyone, Authenticated Users, Users or Guests entry on the vault, its lock file or the default data folder |
| #182 | Gate | `a7fe356` docs(spec): record how SSC keeps files owner-only on Windows | `docs/spec/VAULT.md` section 1, which left this to Phase 3 |
| #182 | Housekeeping | docs: record the Phase 3 gate in the ledger | This ledger |
| #182 | Gate, CI fix | `a348917` test: read Windows ACLs through the Win32 API, not PowerShell | `tests/vault/test_store.py`: Windows PowerShell on the runners could not load `Get-Acl` |

### Phase 4: CLI and interactive mode

| PR | Brief step | Commit | What it added or changed |
| --- | --- | --- | --- |
| #183 | Step 1 | `9cc87d1` build: add zxcvbn 4.5.0 and the EFF large wordlist | `pyproject.toml`, `uv.lock` and `service/eff_large_wordlist.txt` (the EFF's list, CC BY 3.0 US, for `ssc generate`). zxcvbn is pure Python with no dependencies, which CLI.md decision 2 asks for. The pre-3.0 generator in `legacy/` used the EFF short list; 3.0 uses the large one, as CLI.md says |
| #183 | Step 1 | `be941a6` feat(engine): report which grant opened a file | `engine/access.py`: `open_grant`, so history can name the vault entry a decryption used |
| #183 | Step 1 | `762a942` feat(service): the service layer shared by the CLI and interactive mode | `service/`: `context` (the `Prompter` that the CLI and interactive mode each implement), `grants` (grant specs), `files` (encrypt and decrypt, asking only for what is missing, holding stream output until authenticated), `access_ops`, `vaults`, `keys`, `profile_ops`, `settings` (the default profile), `passwords` (length and zxcvbn checks, passphrases) and `shred`. `InputError` in `errors.py` |
| #183 | Step 1 | `b787c9f` test: the service layer, end to end | `tests/service/`, with a scripted prompter that fails on any unexpected question |
| #183 | Housekeeping | docs: record Phase 4, step 1 in the ledger | This ledger |
| #183 | Review fix | `ccd8add` fix(engine): open a grant with one exact assignment of secrets to factors | `engine/access.py`: `open_assigned`, for Codex's finding that rotation could swap two password factors |
| #183 | Review fix | `7ac676b` fix(service): Codex findings on the service layer | `service/files.py` and `access_ops.py`: exact assignments in rotate, a late `NotDurable` raised only after the vault commits, a wrong master password no longer blocks other ways in, and `decrypt` history for recovery entries |
| #183 | Review fix | `e0aa117` fix(engine): search rotation assignments with one Argon2id cache | `engine/access.py`: `find_assignment` replaces `open_assigned`, for Codex's finding that each assignment re-ran Argon2id |
| #183 | Review fix | `d56910f` fix(service): save a new recovery entry before publishing what it opens | `service/files.py` (`Builder.save_new_entries`) and `access_ops.add`, for Codex's finding that a failed vault write could leave an output only a lost recovery code opens |
| #183 | Review fix | `e8c40b7` fix(service): risks found in a full review of the service layer | `service/` (with `Prompter.can_show`), `vault/store.py` (`locked` made public) and `vault/keychain.py` (`remove_device(forget=)`): from Claude's own review of the PR, not Codex. Covers recovery codes nobody could see, the vault lock held while streaming, fallbacks when the vault cannot be read, revoke scans, labels and entry password checks |
| #183 | Review fix | `1cc1a9e` fix(service): an unreadable vault does not stop another way in | `service/files.py` and `access_ops.py`, for Codex's finding that an OS error from the optional vault read escaped |
| #183 | Review fix | `23b9294` fix(service): keep the vault snapshot only after its session closes | `service/files.py`, for Codex's finding that a failed `vault-unlock` write left a half-read vault |
| #183 | Review fix | `4ca6858` fix(service): record each vault entry an all-of grant used to decrypt | `service/files.py` (`_entries_in`), for Codex's finding that only the first entry was recorded |
| #184 | Step 2 | `ce6502a` refactor(fs): one reader for credential files | `fs.py`: `read_private`, moved from `engine/keyfile.py` so key files and password files share one set of rules |
| #184 | Step 2 | `a33f3e8` fix(service): wrong supplied credentials are CannotOpen, not a prompt | `service/files.py`: `Opener.supplied`, so a wrong supplied credential with no terminal is exit 2, not exit 1 |
| #184 | Step 2 | `101f390` feat(cli): the ssc command line, as CLI.md says | `cli/` (`parser`, `commands`, `prompter`, `sources`, `main`), `__main__.py` and the `ssc` console script. Three readings of the contract are Claude's, for the owner to confirm: `vault change-password` takes the vault's recovery code in place of the master password; `vault revoke --scan <folder>` names the folder that decision 3 asks for; a wrong supplied credential is exit 2 and a missing one exit 1 |
| #184 | Step 2 | `5dea3d4` test(cli): every command end to end, in-process | `tests/cli/`, with a scripted terminal and an in-memory keychain |
| #184 | Housekeeping | docs: record Phase 4, step 2 in the ledger | This ledger |
| #184 | Review fix | `2fb1d78` fix(cli): rotating after a revoke drops every grant the entry is in | `service/access_ops.py` (`rotate(without=)`) and `vaults.grant_uses`, for Codex's finding that a supplied copy of a revoked key survived the offered rotation |
| #185 | Step 3 | `5b1484e` build: add questionary 2.1.1 for the interactive mode | `pyproject.toml` and `uv.lock`: `questionary==2.1.1`, with `prompt-toolkit==3.0.53` and `wcwidth==0.9.4` as constraints |
| #185 | Step 3 | `c33d9c5` feat(service): what the interactive mode needs from the service layer | `service/files.py` (`open_file`, `write_plaintext`, `Opening`), `passwords.py` (`is_weak`, `WEAK`), `vaults.py` (`peek`, moved from `access_ops`, and `this_device`) |
| #185 | Step 3 | `19ea6d0` feat(interactive): the guided flow, as CLI.md section 4 says | `interactive/` (`ui` with the `Ui` protocol and `QuestionaryUi`, `prompter`, `flow`) and `cli/main.py`, which opens the flow for `ssc` with no arguments in a terminal |
| #185 | Step 3 | `bcac053` test(interactive): every screen end to end, and questionary's Ui | `tests/interactive/`: every screen with a scripted Ui, and `QuestionaryUi` through a prompt_toolkit pipe |
| #185 | Step 3 | `8306ae2` docs(spec): confirm questionary for the interactive mode | `docs/spec/CLI.md` section 4: questionary confirmed |
| #185 | Housekeeping | docs: record Phase 4, step 3 in the ledger | This ledger |
| #185 | Review fix | `c4a62c3` fix(interactive): unlock for saved profiles; revoke archived entries | `interactive/flow.py`, for Codex's two findings: profiles hidden behind a locked vault, and archived entries missing from the revoke picker |
| #185 | Review fix | `dfa4704` fix(interactive): ask for a key file a file needs when decrypting | `service/context.py` (`ask_key_file`), `service/files.py` (`Opener.missing_keys`, `ask_key`) and the guided flow, for Codex's finding that a standalone-key file could not be opened in the flow |
