# Phase 4 gate

**Gate (GAME_PLAN.md section 11):** every flow in the contract works end to
end in CI on all three platforms.

CI runs the whole suite on Linux, macOS and Windows, each on Python 3.13,
3.14 and 3.15. The suite includes `tests/e2e`, which runs the installed
`ssc` command as a separate process, with its own vault and real stdin,
stdout and exit codes. The Docker job adds `tests/docker`.

| CLI.md | What | End to end (`tests/e2e/test_installed.py`) | Also covered by |
| --- | --- | --- | --- |
| 1 | Positional files, default output names, `--force`, stdin and stdout, armour | `test_files_streams_and_exit_codes` | `tests/cli` `test_streams_and_armour` |
| 1 | `decrypt -o -` writes nothing before the file authenticates | `test_nothing_reaches_stdout_before_the_whole_file_authenticates` | `tests/service/test_files.py` (the 64 MiB spool) |
| 1 | Secrets never reach output; one sentence, no traceback | checked on every call (`Ssc.__call__`) | `tests/cli` `test_no_secret_reaches_output`, `test_errors_are_one_sentence_unless_debug` |
| 1 | Exit codes 0, 1, 2, 3 and 4 | `test_files_streams_and_exit_codes` | `tests/cli` `test_exit_codes` |
| 1 | Credentials: password files (up to 5), `SSC_*` variables, key files, private credential files | `test_password_files_environment_and_key_files` | `tests/cli` `test_environment_variables`, `test_credential_files_must_be_private` |
| 1 | No TTY: a missing credential is exit 1, never a hang | `test_files_streams_and_exit_codes`, `test_the_vault_commands` | `tests/docker` |
| 2 | Grant specs, limits, and `recovery` without a TTY | `test_grant_spec_limits`, `test_grants_profiles_and_the_vault_in_files` | `tests/service/test_grants_and_passwords.py`, `tests/cli` `test_recovery_codes_need_a_terminal` |
| 3.1 | `encrypt` with `--profile`, `--vault`, `--grant`, `--recovery-code` or the default profile; `decrypt` | `test_grants_profiles_and_the_vault_in_files` | `tests/cli` `test_vault_entries_open_files_without_asking` |
| 3.2 | `access show`, `add`, `remove`, `rotate`, `apply`, and their wording | `test_access_show_add_remove_rotate_apply`, `test_rotate_drops_what_it_cannot_rebuild_only_with_force` | `tests/cli` `test_access_commands`, `tests/service/test_access_ops.py` |
| 3.3 | `vault init`, `status`, `add`, `list`, `archive`, `revoke [--scan]`, `change-password`, `backup`, `remove-device` | `test_the_vault_commands` | `tests/cli` `test_change_password_and_reset_with_the_vault_recovery_code`, `test_revoke_scans_and_offers_to_rotate` |
| 3.3 | `vault add-device`, and keychain unlock | not run end to end, since it would write to the real keychain | `tests/cli` `test_history_and_devices`, and `tests/vault/test_keychain.py` against the real OS keychain on all three platforms |
| 3.3 | New recovery codes, shown once and typed back | only the no-TTY refusal | `tests/cli` `test_recovery_codes_need_a_terminal`, `tests/interactive` |
| 3.3 | `vault history on`, `off`, `show`; no paths recorded | `test_history_on_show_off` | `tests/cli` `test_history_and_devices` |
| 3.4 | `key new`, `import`, `export`; `profile create`, `list`, `show`, `delete`, `default`; `generate`; `shred` | `test_keys_profiles_generate_and_shred` | `tests/cli` `test_keys_profiles_generate_and_shred` |
| 4 | The guided interactive mode | `test_no_arguments_without_a_terminal_prints_help` | `tests/interactive` (every screen, on the real service layer), and `tests/docker` (in a real pseudo-terminal) |

## What is not end to end, and why

- **Keychain writes** (`vault add-device`, `vault init` with a device key):
  running them would add items to the keychain of whoever runs the tests.
  The real-keychain test covers them in CI on every OS.
- **Showing a new recovery code** needs a TTY. Windows has no pseudo-terminal
  for a test to drive, so it is tested in-process. The refusal without a
  TTY is tested end to end.
