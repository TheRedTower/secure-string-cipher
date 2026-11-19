"""Credentials without a prompt (CLI.md section 1): flags that name files,
and environment variables, for scripts and Docker.

A flag beats its variable, except that `SSC_PASSWORD` is one more opening
password on top of up to five `--password-file`s. A credential file is held
to the same rules as a key file: a regular file, not reached through a
symlink, and on POSIX not readable by group or others.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from secure_string_cipher import fs
from secure_string_cipher.errors import InputError

MAX_PASSWORD_FILES = 5
# The bound 2.x applied to a password file: an oversized one is refused, not
# fed to Argon2id.
MAX_SECRET_FILE = 65536


@dataclass(frozen=True)
class Sources:
    passwords: Sequence[str] = ()
    new_password: str | None = None
    master_password: str | None = None
    new_master_password: str | None = None
    recovery_code: str | None = None
    key_files: Sequence[Path] = field(default_factory=tuple)


def read_secret(path: Path, what: str) -> str:
    """A password or recovery code from a file, with one trailing newline
    removed."""
    try:
        data = fs.read_private(path, MAX_SECRET_FILE + 1, what)
    except FileNotFoundError:
        raise InputError(f"The {what} file {path} does not exist.") from None
    except PermissionError as error:
        raise InputError(str(error)) from None
    if len(data) > MAX_SECRET_FILE:
        raise InputError(f"The {what} file {path} is too long.")
    for ending in (b"\r\n", b"\n"):
        if data.endswith(ending):
            data = data[: -len(ending)]
            break
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError(f"The {what} file {path} is not UTF-8 text.") from None
    if not text:
        raise InputError(f"The {what} file {path} is empty.")
    return text


def _one(flag: Path | None, env: Mapping[str, str], name: str, what: str) -> str | None:
    if flag is not None:
        return read_secret(flag, what)
    return env.get(name) or None


def gather(
    *,
    password_files: Sequence[Path] = (),
    new_password_file: Path | None = None,
    master_password_file: Path | None = None,
    new_master_password_file: Path | None = None,
    recovery_code_file: Path | None = None,
    key_files: Sequence[Path] = (),
    env: Mapping[str, str] | None = None,
) -> Sources:
    env = os.environ if env is None else env
    if len(password_files) > MAX_PASSWORD_FILES:
        raise InputError(
            f"--password-file can be given at most {MAX_PASSWORD_FILES} times."
        )
    passwords = [read_secret(p, "password") for p in password_files]
    if env.get("SSC_PASSWORD"):
        passwords.append(env["SSC_PASSWORD"])
    keys = list(key_files)
    if not keys and env.get("SSC_KEY_FILES"):
        keys = [Path(p) for p in env["SSC_KEY_FILES"].split(os.pathsep) if p]
    return Sources(
        passwords=passwords,
        new_password=_one(new_password_file, env, "SSC_NEW_PASSWORD", "new password"),
        master_password=_one(
            master_password_file, env, "SSC_MASTER_PASSWORD", "master password"
        ),
        new_master_password=_one(
            new_master_password_file,
            env,
            "SSC_NEW_MASTER_PASSWORD",
            "new master password",
        ),
        recovery_code=_one(
            recovery_code_file, env, "SSC_RECOVERY_CODE", "recovery code"
        ),
        key_files=keys,
    )
