Title: Make CLI testable via stream injection and improve error messaging

Commit: cli: make CLI testable via stream injection; route IO through in_stream/out_stream; tidy unused helper; add CHANGELOG

Description
-----------
This patch makes the command-line interface (CLI) deterministic and unit-test-friendly by:

- Adding optional `in_stream` and `out_stream` parameters to `main()` (defaults to `sys.stdin`/`sys.stdout`).
- Routing all CLI input/output through the provided streams and updating helper functions (`_get_mode`, `_get_input`, `_get_password`, `_print_banner`) to accept streams.
- Avoiding writes to `sys.__stdout__` and removing an unused helper to prevent test capture issues.
- Wrapping base64 decode errors during text decryption into a `CryptoError("Text decryption failed")` to give a consistent error message used in tests.
- Adding a `CHANGELOG.md` entry describing the change.

Why
---
Pytest's stdout capture can wrap or replace `sys.stdout`, causing tests that patch `sys.stdout` to receive no output while pytest shows the captured output. Injecting streams avoids this race and makes tests deterministic.

Notes
-----
- The branch is `feature/cli-testability`. Changes are committed locally. To push and open a PR:

  git push -u origin feature/cli-testability

  # Using GitHub CLI to create a PR:
  gh pr create --title "Make CLI testable via stream injection" --body-file PR_DRAFT.md --base main

Or push and create a PR via the GitHub web UI.

Testing
-------
All tests pass locally:

  .venv/bin/python -m pytest -q

Result: 32 passed, 3 skipped
