# CodeQL Alerts Fix Plan

**Date:** 2026-06-06
**Repository:** TheRedTower/secure-string-cipher
**GitHub alert source:** `gh api repos/TheRedTower/secure-string-cipher/code-scanning/alerts`
**Local checkout:** `main` at `c8e0090`, ahead of `origin/main` by 2 commits
**GitHub baseline inspected:** `origin/main` at `60440a3`

## Executive Summary

GitHub CodeQL currently reports 15 open alerts. All open alerts are the same high-severity rule:

- `py/clear-text-logging-sensitive-data`
- Rule description: clear-text logging of sensitive information
- Affected files: `src/secure_string_cipher/cli.py` and `src/secure_string_cipher/cli_args.py`

The highest-impact findings are real secret-disclosure risks in the GitHub-visible `origin/main` code: generated passphrases and retrieved vault passphrases are printed to the terminal. The local checkout already contains two unpublished commits that remove those direct displays and keep generated/retrieved passphrases hidden. Those commits have not been reflected in GitHub CodeQL yet because the local branch is ahead of `origin/main`.

The remaining findings are clustered around password validation and retry output. They appear to be CodeQL taint-flow alerts caused by printing messages derived from password-strength checks or by writing static status text inside password-tainted control flow. They should still be addressed in code where practical, because terminal output can be captured by shells, CI, logs, issue reports, or screen recordings.

## Implementation Progress

### Already addressed by local unpublished commits

The local commits `368c19d` and `c8e0090` already address the direct passphrase-display alerts:

- `_handle_generate_passphrase_inline()` no longer prints generated passphrases.
- `_handle_generate_passphrase()` no longer prints generated passphrases.
- `_handle_retrieve_passphrase()` no longer prints retrieved vault passphrases.
- Key-file passphrase derivation is centralized in `derive_passphrase_from_key_file()`.

These changes should be retained and pushed or incorporated into the final fix branch before relying on GitHub CodeQL results.

### Addressed in the current implementation pass

The remaining started work focuses on password-validation and retry output:

- `src/secure_string_cipher/cli.py` now prints static password policy guidance instead of `msg` returned by `check_password_strength(pw)`.
- `src/secure_string_cipher/cli.py` now routes retry and max-attempt output through helpers that only accept non-sensitive counters.
- `src/secure_string_cipher/cli.py` now avoids printing raw exception text in generated-passphrase, vault-store, vault-open, vault-retrieve, and direct passphrase-store failure paths.
- `src/secure_string_cipher/cli_args.py` now prints static password policy guidance instead of iterating over `issues` returned by `check_password_strength(password)`.
- `src/secure_string_cipher/cli_args.py` now avoids printing or auditing raw exception text for unexpected `store` command vault failures.
- Tests now use explicit sentinel secrets to assert generated, retrieved, and rejected passwords do not appear in CLI output.

Verified locally with:

```bash
uv run --locked ruff check src/secure_string_cipher/cli.py src/secure_string_cipher/cli_args.py tests/unit/test_cli_menu.py tests/unit/test_cli_coverage.py tests/unit/test_cli_args_coverage.py
uv run --locked pytest tests/unit/test_cli_menu.py tests/unit/test_cli_coverage.py tests/unit/test_cli_args_coverage.py
uv run --locked mypy src
```

## Alert Inventory

| Alert | State | File | GitHub line | Local area | Initial classification |
| --- | --- | --- | ---: | --- | --- |
| [#1](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/1) | Open | `src/secure_string_cipher/cli.py` | 322 | Inline generated passphrase display | Real direct leak on `origin/main`; locally mitigated |
| [#2](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/2) | Open | `src/secure_string_cipher/cli.py` | 323 | Inline passphrase-generation output | Same flow as #1; locally mitigated |
| [#12](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/12) | Open | `src/secure_string_cipher/cli.py` | 520 | Menu generated passphrase display | Real direct leak on `origin/main`; locally mitigated |
| [#13](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/13) | Open | `src/secure_string_cipher/cli.py` | 521 | Menu passphrase-generation output | Same flow as #12; locally mitigated |
| [#14](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/14) | Open | `src/secure_string_cipher/cli.py` | 617 | Vault passphrase retrieval output | Real direct leak on `origin/main`; locally mitigated |
| [#15](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/15) | Open | `src/secure_string_cipher/cli_args.py` | 177 | Strength-validation issue printing | Sensitive-derived validation output |
| [#16](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/16) | Open | `src/secure_string_cipher/cli.py` | 469 | Password retry failure output | Likely taint/control-flow alert |
| [#17](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/17) | Open | `src/secure_string_cipher/cli.py` | 409 | Password retry failure output | Likely taint/control-flow alert |
| [#18](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/18) | Open | `src/secure_string_cipher/cli.py` | 407 | Password-strength message output | Sensitive-derived validation output |
| [#19](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/19) | Open | `src/secure_string_cipher/cli.py` | 417 | Password retry failure output | Likely taint/control-flow alert |
| [#20](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/20) | Open | `src/secure_string_cipher/cli.py` | 415 | Password-strength message output | Sensitive-derived validation output |
| [#21](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/21) | Open | `src/secure_string_cipher/cli.py` | 441 | Confirmation retry output | Likely taint/control-flow alert |
| [#22](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/22) | Open | `src/secure_string_cipher/cli.py` | 459 | Confirmation retry output | Likely taint/control-flow alert |
| [#23](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/23) | Open | `src/secure_string_cipher/cli.py` | 433 | Confirmation retry output | Likely taint/control-flow alert |
| [#24](https://github.com/TheRedTower/secure-string-cipher/security/code-scanning/24) | Open | `src/secure_string_cipher/cli.py` | 451 | Confirmation retry output | Likely taint/control-flow alert |

Nine older alerts are already marked fixed in GitHub: #3 through #11.

## Scope Analysis

### Affected user surfaces

The alerts are limited to CLI presentation paths:

- Interactive menu implementation in `src/secure_string_cipher/cli.py`.
- Non-interactive `ssc` CLI password validation in `src/secure_string_cipher/cli_args.py`.

No current CodeQL alerts were reported in cryptographic primitives, vault storage, key derivation, file handling, or audit-log formatting.

### Real direct leaks on GitHub `origin/main`

The following `origin/main` behaviors expose passphrase material directly to terminal output:

1. `_handle_generate_passphrase_inline()` prints the generated passphrase immediately after generation.
2. `_handle_generate_passphrase()` prints the generated passphrase from the menu generation path.
3. `_handle_retrieve_passphrase()` prints the retrieved vault passphrase.

These are high-priority because terminal output is commonly persisted in shell logs, CI logs, troubleshooting screenshots, clipboard managers, or support tickets.

### Local unpublished mitigation already present

The local commits `368c19d` and `c8e0090` change the direct leak behavior:

- Generated passphrases are described as hidden instead of printed.
- Generated passphrases must be stored before use in the inline flow.
- Vault retrieval returns the secret for the current operation or confirms it is hidden, rather than displaying it.
- Key-file passphrase derivation has been centralized in `derive_passphrase_from_key_file()`.

Because the local branch is ahead of `origin/main`, GitHub CodeQL still reports alerts against code that may already be changed locally. These commits should be reviewed and either pushed or folded into the final fix branch before re-running CodeQL.

### Sensitive-derived output still needs cleanup

Two validation paths still print data derived from password checking:

- `src/secure_string_cipher/cli.py`: `_get_password()` prints `msg` from `check_password_strength(pw)`.
- `src/secure_string_cipher/cli_args.py`: `_prompt_password_with_validation()` prints each item in `issues` from `check_password_strength(password)`.

The messages are policy feedback rather than the password itself, but they are derived from the password. A stricter remediation is to avoid printing password-derived details and instead print static policy guidance.

### Likely false-positive/control-flow alerts

Several alerts point to static retry or failure text such as attempt counts, "passwords do not match", or maximum retry messages. These messages do not contain the secret value. CodeQL appears to flag them because the output occurs in branches controlled by password input or confirmation comparison.

The implementation should first remove actual and password-derived output. If CodeQL still flags purely static output after that, those specific remaining alerts should be reviewed as false positives and dismissed in GitHub with a clear rationale.

## Fix Plan

### Step 1: Establish the branch baseline

1. Confirm whether the implementation will continue from local `main` at `c8e0090` or from `origin/main` at `60440a3`.
2. Preserve the local unpublished fixes unless there is a product decision to restore visible passphrase display.
3. Re-run the CodeQL alert query before coding to ensure the alert count has not changed.

Recommended command:

```bash
gh api 'repos/TheRedTower/secure-string-cipher/code-scanning/alerts?state=open&per_page=100' \
  --paginate \
  --jq '.[] | {number, rule: .rule.id, path: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line, message: .most_recent_instance.message.text}'
```

### Step 2: Keep generated passphrases non-displayable by default

Target: `src/secure_string_cipher/cli.py`

Implementation requirements:

1. Keep `_handle_generate_passphrase_inline()` from writing the generated passphrase to `out_stream`.
2. Keep `_handle_generate_passphrase()` from writing the generated passphrase to `out_stream`.
3. Require generated passphrases to be stored or otherwise explicitly discarded.
4. Do not add a convenience fallback that prints the generated secret.

Expected closed alerts: #1, #2, #12, #13.

### Step 3: Keep vault retrieval hidden

Target: `src/secure_string_cipher/cli.py`

Implementation requirements:

1. Keep `_handle_retrieve_passphrase()` from printing the retrieved passphrase.
2. Keep `_load_passphrase_from_vault()` returning the secret only to the caller that needs it for encryption/decryption.
3. Display only labels and generic status messages.
4. Treat labels as user-controlled identifiers, not secret passphrase values.

Expected closed alert: #14.

### Step 4: Replace password-derived validation output with static policy output

Targets:

- `src/secure_string_cipher/cli.py`
- `src/secure_string_cipher/cli_args.py`

Implementation requirements:

1. Continue using `check_password_strength()` for enforcement.
2. Do not print the returned `msg` or `issues` values directly.
3. Add a static helper such as `_password_policy_message()` or `_write_password_policy()` that prints fixed requirements:
   - minimum length
   - uppercase and lowercase letters
   - digits
   - symbols
4. In `_get_password()`, replace `ostream.write(f"... {msg}")` with a fixed failure message plus the static policy text.
5. In `_prompt_password_with_validation()`, replace the loop over `issues` with the same static policy text.

Expected affected alerts: #15, #18, #20.

### Step 5: Reduce password-tainted control flow around output

Target: `src/secure_string_cipher/cli.py`

Implementation requirements:

1. Keep all output in password retry branches static and generic.
2. Move retry-message formatting into helpers that accept only non-sensitive integers, for example `attempts` and `remaining`.
3. Avoid passing `pw`, `confirm_pw`, `password`, `passphrase`, or validation messages into any display/logging helper.
4. Avoid printing exception messages from code paths that may include sensitive values. Prefer generic text for password/vault failures and record sanitized audit details only where required.

Expected affected alerts: #16, #17, #19, #21, #22, #23, #24.

### Step 6: Add regression tests for no secret output

Targets:

- `tests/unit/test_cli_menu.py`
- `tests/unit/test_cli_args.py`
- optionally `tests/security/test_security_integration.py`

Required test cases:

1. Inline generated passphrase flow does not include the generated passphrase in `out_stream`.
2. Menu passphrase generation does not include the generated passphrase in `out_stream`.
3. Vault retrieval does not include the retrieved passphrase in `out_stream`.
4. `_get_password()` validation failure does not include the submitted password.
5. `_prompt_password_with_validation()` validation failure does not include the submitted password.
6. Wrong-password decrypt failures remain generic and do not include the attempted password, plaintext, or ciphertext internals.

Use sentinel secrets that are easy to assert against, for example `DO_NOT_PRINT_THIS_SECRET_123!`. <!-- pragma: allowlist secret -->

### Step 7: Run local verification

Recommended commands:

```bash
uv run --locked ruff check src tests
uv run --locked mypy src
uv run --locked pytest tests/unit/test_cli_menu.py tests/unit/test_cli_args.py tests/security/test_audit_log.py
uv run --locked pytest tests/security/test_security_integration.py
```

If the CodeQL CLI is available locally, run a local Python analysis before pushing. Otherwise, push the fix branch and let GitHub CodeQL analyze it.

### Step 8: Reconcile GitHub CodeQL alerts after CI

1. Wait for GitHub CodeQL to finish on the pushed branch or `main`.
2. Query open alerts again.
3. Confirm direct leak alerts #1, #2, #12, #13, and #14 are closed.
4. Confirm validation-derived alerts #15, #18, and #20 are closed after static policy output changes.
5. For any remaining alerts that point only to static retry text, inspect the exact sink and dataflow. If no sensitive value can reach output, dismiss as false positive in GitHub with rationale:
   - output is static retry/status text
   - no password/passphrase value or derived validation detail reaches stdout/stderr
   - regression tests assert sentinel secrets are absent from output

## Acceptance Criteria

The fix work is complete when:

1. No generated passphrase is printed in the interactive or non-interactive flows.
2. No retrieved vault passphrase is printed.
3. Password validation output uses static policy text, not password-derived result strings.
4. Password retry and confirmation output cannot include password/passphrase values.
5. Tests assert representative secrets are absent from stdout/stderr.
6. CodeQL reports zero actionable `py/clear-text-logging-sensitive-data` alerts, or any residual static-output findings are dismissed with documented false-positive rationale.

## Implementation Notes

- Do not weaken password-strength enforcement to silence alerts.
- Do not route secrets through logging helpers, even if the helper redacts.
- Do not rely on variable renaming alone. The important fix is preventing sensitive values and sensitive-derived messages from reaching output sinks.
- Prefer static, user-friendly policy guidance over detailed per-password feedback.
- Keep audit logging sanitized. The existing audit logger already redacts keys containing `password`, `passphrase`, `key`, `secret`, `token`, and `plaintext`; do not bypass that path. <!-- pragma: allowlist secret -->
