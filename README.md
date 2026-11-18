# secure-string-cipher 3.0 (in progress)

This branch is a ground-up rebuild of SSC: local file encryption where every
file carries its own access rules. It is not usable yet; it replaces `main`
when 3.0 ships.

- [Charter](docs/CHARTER.md): what SSC 3.0 is for, its threat model and non-goals.
- [Game plan](rebuild/GAME_PLAN.md): the rebuild brief, step by step.
- [Ledger](rebuild/LEDGER.md): where each file on this branch came from.

The pre-3.0 code and docs are kept under `legacy/` as reference only, and are
deleted before 3.0 is released.

## Development

Requires [uv](https://docs.astral.sh/uv/) 0.9.17 or newer and Python 3.13 or newer.

```sh
uv sync --locked
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
```

Licensed under the [MIT licence](LICENSE).
