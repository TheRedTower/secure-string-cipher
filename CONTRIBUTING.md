# Contributing to SSC

Thank you for helping. SSC is security-sensitive and maintained by one
person, so small, focused changes with tests are the easiest to review.

- **Vulnerabilities:** report them privately, as the
  [security policy](SECURITY.md) says, never in a public issue.
- **Issues:** never post real passwords, keys, recovery codes, plaintext or
  vault contents. Use made-up examples.

## The specs come first

SSC's behaviour is written down before it is built:

- [FORMAT.md](docs/spec/FORMAT.md): the `.ssc` file format.
- [ACCESS.md](docs/spec/ACCESS.md): grants and factors.
- [VAULT.md](docs/spec/VAULT.md): the vault, the keychain and key files.
- [CLI.md](docs/spec/CLI.md): every command, flag, message and exit code.

A change to what SSC does starts as a change to the spec. Anything not in
CLI.md is not part of SSC. A change to the format or the access rules also
changes the test vectors in `tests/vectors`, and has to keep files written
by earlier 3.x versions readable.

## Setting up

You need [uv](https://docs.astral.sh/uv/) 0.9.17 or newer and Python 3.13 or
newer.

```sh
git clone https://github.com/TheRedTower/secure-string-cipher.git
cd secure-string-cipher
uv sync --locked
uv run pre-commit install
```

## The checks CI runs

```sh
uv run --locked ruff check
uv run --locked ruff format --check
uv run --locked mypy
uv run --locked pytest
```

- **mypy** runs in strict mode. CI runs it on Linux, macOS and Windows, since
  each evaluates platform checks differently. To check another platform
  locally, use `uv run mypy --platform win32` (or `linux`, `darwin`).
- **pytest** runs on all three platforms with Python 3.13, 3.14 and 3.15.
  - `tests/e2e` runs the installed `ssc` command as a separate process.
  - `tests/vault/test_keychain.py` writes to the real OS keychain, so it
    runs only with `SSC_KEYCHAIN_TESTS=1`.
  - `tests/docker` runs only with `SSC_DOCKER_IMAGE` set to an image built
    from the `Dockerfile`.
  - No other test may touch the OS keychain or your real vault.

## Making a change

1. Branch from `main`.
2. Make the change, with tests that fail without it.
3. Before you push, review your own diff, in particular:
   - failure paths: a locked, damaged or busy vault, no keychain, no TTY;
   - anything held for a session that can go stale;
   - input that ends up inside a parsed syntax;
   - loops and retries that must end.
4. Open a pull request that says what changed, why, and how it was tested.

## Rules the code keeps

- **No secret in output:** no password, key or recovery code goes to stdout,
  stderr, logs or error messages. The only exceptions are a new recovery
  code and `vault add --generate --show`, each shown once.
- **No silent fallback:** if the OS keychain is unavailable, SSC asks for
  the master password. It never keeps a key in a plain file.
- **Dependencies:** each one is pinned to an exact version, at least two
  weeks old when it is added, and locked with hashes in `uv.lock`.
- **Writing:** the docs, messages and comments use plain English, and
  describe only what exists.

By contributing, you agree that your contribution is licensed under the
[MIT licence](LICENSE).
