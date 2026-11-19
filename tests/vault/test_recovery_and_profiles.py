"""Recovery codes and profiles in the vault (VAULT.md sections 2, 3.1 and
3.2; CLI.md section 2)."""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from secure_string_cipher.engine import access, container, recovery
from secure_string_cipher.errors import CannotOpen, VaultError
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, profiles, store
from tests import vectorkit

VAULT = vectorkit.manifest()["vault"]
MASTER = access.Credentials(passwords=[VAULT["master_password"]])
EMPTY = doc.Document()


def seal(policy: list[list[access.NewFactor]]) -> bytes:
    out = io.BytesIO()
    container.encrypt(io.BytesIO(b"secret"), out, policy)
    return out.getvalue()


def opens(data: bytes, creds: access.Credentials) -> bool:
    try:
        container.decrypt(io.BytesIO(data), io.BytesIO(), creds)
    except CannotOpen:
        return False
    return True


@pytest.fixture
def vector_vault(tmp_path: Path) -> Path:
    path = tmp_path / "vault.ssc"
    shutil.copyfile(vectorkit.VECTORS / VAULT["file"], path)
    return path


# --- recovery entries ------------------------------------------------------------


def test_a_recovery_entry_opens_files_from_its_printed_code() -> None:
    d, entry = entries.add_recovery(EMPTY, "paper")
    assert isinstance(entry.secret, bytes)
    printed = recovery.encode(entry.secret)
    data = seal([[entries.factor(d, "paper")]])
    assert opens(data, entries.credentials(d))
    typed = access.Credentials(recovery_codes=[recovery.decode(printed.lower())])
    assert opens(data, typed)


def test_the_recovery_token_uses_the_one_active_entry() -> None:
    d, paper = entries.add_recovery(EMPTY, "paper")
    assert entries.choose_recovery(d) == (d, paper, False)


def test_the_recovery_token_creates_one_when_there_is_none() -> None:
    d, _ = entries.add_recovery(EMPTY, "recovery")
    d = entries.archive(d, "recovery")
    d, _ = entries.add_password(d, "recovery-2", "taken by a password")
    d, made, created = entries.choose_recovery(d)
    assert created and made.label == "recovery-3" and made.kind == "recovery"
    assert entries.find(d, "recovery-3") == made


def test_the_recovery_token_refuses_to_guess_between_several() -> None:
    d, _ = entries.add_recovery(EMPTY, "a")
    d, _ = entries.add_recovery(d, "b")
    with pytest.raises(VaultError, match="a, b"):
        entries.choose_recovery(d)


def test_the_vector_vaults_archived_code_is_not_chosen() -> None:
    d = doc.parse(doc.canonical(VAULT["document"]))
    d, made, created = entries.choose_recovery(d)
    assert created and made.label == "recovery"


# --- the vault's own recovery grant -------------------------------------------------


def test_a_recovery_code_resets_a_forgotten_master_password(vector_vault: Path) -> None:
    r = recovery.new()
    with store.edit(MASTER, vector_vault) as session:
        assert session.add_recovery_grant(r) == 2
    printed = recovery.encode(r)

    code = access.Credentials(recovery_codes=[recovery.decode(printed)])
    with store.edit(code, vector_vault) as session:
        session.reset_master_password(recovery.decode(printed), "remembered now")
    with pytest.raises(CannotOpen):
        store.load(MASTER, vector_vault)
    new = access.Credentials(passwords=["remembered now"])
    assert store.load(new, vector_vault).to_json() == VAULT["document"]
    assert store.load(code, vector_vault).to_json() == VAULT["document"]


def test_a_reset_needs_the_vaults_own_code(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        with pytest.raises(VaultError):  # no recovery grant yet
            session.reset_master_password(recovery.new(), "x")
        session.add_recovery_grant(recovery.new())
    with store.edit(MASTER, vector_vault) as session, pytest.raises(CannotOpen):
        session.reset_master_password(recovery.new(), "x")


# --- profiles ----------------------------------------------------------------------


def _vault_with_entries() -> tuple[doc.Document, doc.Entry, doc.Entry]:
    d, key = entries.add_key(EMPTY, "laptop")
    d, code = entries.add_recovery(d, "paper")
    return d, key, code


def test_applying_a_profile_builds_its_grants() -> None:
    d, key, code = _vault_with_entries()
    d, _ = profiles.create(
        d,
        "backup",
        [[doc.Ref(key.id)], [doc.ASK_PASSWORD, doc.Ref(code.id)]],
    )
    asked: list[str] = []

    def ask() -> str:
        asked.append("typed")
        return "typed"

    data = seal(profiles.apply(d, "backup", ask))
    assert asked == ["typed"]
    assert isinstance(key.secret, bytes) and isinstance(code.secret, bytes)
    assert opens(data, access.Credentials(keys=[key.secret]))
    assert opens(
        data, access.Credentials(passwords=["typed"], recovery_codes=[code.secret])
    )
    assert not opens(data, access.Credentials(passwords=["typed"]))
    assert doc.parse(doc.encode(d)) == d


def test_a_profile_must_name_active_entries_when_created() -> None:
    d, key, _ = _vault_with_entries()
    with pytest.raises(VaultError):
        profiles.create(d, "p", [[doc.Ref(bytes(16))]])
    with pytest.raises(VaultError):
        profiles.create(entries.archive(d, "laptop"), "p", [[doc.Ref(key.id)]])
    d, _ = profiles.create(d, "p", [[doc.Ref(key.id)]])
    with pytest.raises(VaultError):
        profiles.create(d, "p", [[doc.ASK_PASSWORD]])


def test_a_profile_naming_a_revoked_entry_cannot_be_applied() -> None:
    d, key, _ = _vault_with_entries()
    d, _ = profiles.create(d, "p", [[doc.Ref(key.id)]])
    d = entries.revoke(d, "laptop")
    with pytest.raises(VaultError):
        profiles.apply(d, "p", lambda: "x")


def test_the_vector_vaults_profile_needs_editing_first() -> None:
    """Its second grant names the archived recovery entry "paper"."""
    d = doc.parse(doc.canonical(VAULT["document"]))
    with pytest.raises(VaultError, match="archived"):
        profiles.apply(d, "backup", lambda: "x")
    laptop = entries.find(d, "laptop")
    d, _ = profiles.replace(d, "backup", [[doc.Ref(laptop.id)]])
    policy = profiles.apply(d, "backup", lambda: "x")
    assert len(policy) == 1 and policy[0][0].factor.kind == access.KEY


def test_delete_and_missing_profiles() -> None:
    d, _ = profiles.create(EMPTY, "p", [[doc.ASK_PASSWORD]])
    d = profiles.delete(d, "p")
    assert d.profiles == ()
    for call in (profiles.find, profiles.delete):
        with pytest.raises(VaultError):
            call(d, "p")


def test_profiles_persist_through_the_vault(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        session.document = profiles.delete(session.document, "backup")
        session.document, _ = profiles.create(
            session.document, "typed", [[doc.ASK_PASSWORD]]
        )
    loaded = store.load(MASTER, vector_vault)
    assert [p.name for p in loaded.profiles] == ["typed"]
