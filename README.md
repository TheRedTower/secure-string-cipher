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

## Docker

```sh
docker build -t ssc .
mkdir -m 700 -p ~/.ssc-docker
docker run --rm -it --network=none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v ~/.ssc-docker:/ssc ssc
```

- With no arguments in a terminal, that runs the guided flow. Give a
  command after `ssc` to run it instead, such as `ssc encrypt report.pdf`.
- `/work` is the folder files are read from and written to. `/ssc` holds the
  vault and settings, so they outlive each container.
- A container has no OS keychain, so SSC asks for the master password.
  Scripts can pass credentials with `--env SSC_MASTER_PASSWORD` and the
  other variables in [CLI.md](docs/spec/CLI.md) section 1.
- `--user` makes the files it writes yours.
- `docker run --rm -i` with no terminal works too: a credential that is
  needed but not supplied is then an error, never a hang.

The image installs exactly the hash-locked versions in `uv.lock`, from
wheels only, and has no compiler. The Docker job in CI builds it and runs
[`tests/docker`](tests/docker/test_image.py) against it:

```sh
SSC_DOCKER_IMAGE=ssc uv run pytest tests/docker
```

Licensed under the [MIT licence](LICENSE).
