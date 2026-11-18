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

## Steps

| Brief step | Commit subject | What was added or changed |
| --- | --- | --- |
| Before Phase 0 | docs: add the SSC 3.0 rebuild game plan, verbatim | `rebuild/GAME_PLAN.md` |
| Before Phase 0 | chore: move every pre-3.0 file under legacy/, unchanged | 180 files renamed into `legacy/`, no content edits |
| Phase 0, step 1 | docs: write the 3.0 charter | `docs/CHARTER.md`, this ledger |
| Phase 0, step 2 | build: empty 3.0 package with three-platform CI | `pyproject.toml`, `uv.lock`, `src/secure_string_cipher/`, `tests/test_package.py`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `README.md`. The three-platform CI matrix is the idea carried over from `legacy/.github/workflows/ci.yml`, as section 8 of the brief suggests; the action pins are reused from it |
| Phase 0, step 3 | Not done on `v3` | The README note freezing 2.x belongs on `main`, outside this branch; it waits for the owner's go-ahead |
