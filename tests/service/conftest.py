from __future__ import annotations

from pathlib import Path

import pytest

from secure_string_cipher.service.context import Context
from tests.service.fakes import Keychain, Prompter


@pytest.fixture
def prompter() -> Prompter:
    return Prompter()


@pytest.fixture
def chain() -> Keychain:
    return Keychain()


@pytest.fixture
def ctx(tmp_path: Path, prompter: Prompter, chain: Keychain) -> Context:
    return Context(prompter, vault_path=tmp_path / "data" / "vault.ssc", keychain=chain)


@pytest.fixture
def settings_path(tmp_path: Path) -> Path:
    return tmp_path / "config" / "settings.json"


@pytest.fixture(autouse=True)
def _no_real_folders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No service test reads or writes the real settings or vault."""
    from secure_string_cipher.service import settings
    from secure_string_cipher.vault import store

    monkeypatch.setattr(
        settings, "default_path", lambda: tmp_path / "real-settings.json"
    )
    monkeypatch.setattr(store, "default_path", lambda: tmp_path / "real-vault.ssc")
