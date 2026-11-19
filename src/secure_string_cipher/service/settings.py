"""Settings (VAULT.md section 1): the OS's standard config folder, holding no
secrets. 3.0 has one setting: the default profile."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from secure_string_cipher import fs
from secure_string_cipher.engine.keyfile import LABEL
from secure_string_cipher.errors import InputError

NAME = "settings.json"


def default_path() -> Path:
    return Path(platformdirs.user_config_dir("ssc", appauthor=False)) / NAME


@dataclass(frozen=True)
class Settings:
    default_profile: str | None = None


def load(path: Path | None = None) -> Settings:
    path = default_path() if path is None else path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Settings()
    except (ValueError, OSError) as error:
        raise InputError(f"The settings file {path} cannot be read: {error}") from None
    if not isinstance(value, dict) or set(value) != {"default_profile"}:
        raise InputError(f"The settings file {path} is not valid.")
    name = value["default_profile"]
    if name is not None and not (isinstance(name, str) and LABEL.fullmatch(name)):
        raise InputError(f"The settings file {path} names an invalid profile.")
    return Settings(name)


def save(settings: Settings, path: Path | None = None) -> None:
    path = default_path() if path is None else path
    fs.private_dir(path.parent)
    data = json.dumps({"default_profile": settings.default_profile}).encode()
    fs.write_atomic(path, lambda out: out.write(data), replace=True)
