"""Opt-in history and its hash chain (VAULT.md section 5)."""

from __future__ import annotations

import dataclasses
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.engine import access
from secure_string_cipher.errors import FormatError, Reason
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, history, profiles, store
from tests import vectorkit

VAULT = vectorkit.manifest()["vault"]
MASTER = access.Credentials(passwords=[VAULT["master_password"]])
WHEN = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
ON = history.turn_on(doc.Document())


def vector_json() -> dict[str, Any]:
    copy: dict[str, Any] = json.loads(json.dumps(VAULT["document"]))
    return copy


def rejects(value: dict[str, Any]) -> None:
    with pytest.raises(FormatError) as caught:
        doc.parse(doc.canonical(value))
    assert caught.value.reason == Reason.VAULT_DOCUMENT


def events(document: doc.Document) -> list[str]:
    assert document.history is not None
    return [e.action for e in document.history.events]


def test_the_vector_chain_verifies() -> None:
    parsed = doc.parse(doc.canonical(VAULT["document"]))
    assert parsed.history is not None
    assert parsed.history.anchor == doc.GENESIS
    assert parsed.history.events[1].prev == doc.event_hash(parsed.history.events[0])


@pytest.mark.parametrize(
    ("path", "new"),
    [
        (["events", 0, "at"], "2026-11-18T09:30:01Z"),
        (["events", 1, "prev"], "9_OeG73WB381bfqx4w9ynX4Onw5Qfau486M5c_q5SMs"),
        (["anchor"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        (["trimmed"], 3),  # allowed: trimming does not change the chain
    ],
)
def test_a_tampered_chain_is_rejected(path: list[Any], new: Any) -> None:
    value = vector_json()
    target = value["history"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = new
    if path == ["trimmed"]:
        assert doc.parse(doc.canonical(value)).history is not None
    else:
        rejects(value)


def test_an_event_inserted_into_the_chain_is_caught() -> None:
    value = vector_json()
    event = value["history"]["events"][1]
    value["history"]["events"].insert(1, dict(event, action="decrypt"))
    rejects(value)


def test_an_empty_history_must_be_fresh() -> None:
    value = vector_json()
    value["history"]["events"] = []
    assert doc.parse(doc.canonical(value)).history == doc.History()
    value["history"]["trimmed"] = 1
    rejects(value)
    value["history"]["trimmed"] = 0
    value["history"]["anchor"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    rejects(value)


def test_turning_history_on_and_off() -> None:
    assert ON.history == doc.History(doc.GENESIS, (), 0)
    assert history.turn_on(ON) is ON
    with_event = history.record(ON, "vault-unlock", when=WHEN)
    assert history.turn_on(with_event) is with_event
    assert history.turn_off(with_event).history is None
    assert doc.encode(history.turn_off(with_event)).count(b'"history":null') == 1


def test_record_does_nothing_while_history_is_off() -> None:
    off = doc.Document()
    assert history.record(off, "vault-unlock") is off


def test_record_extends_the_chain() -> None:
    d = history.record(ON, "vault-unlock", when=WHEN)
    entry_id = bytes(range(16))
    d = history.record(d, "decrypt", entry_id, when=WHEN)
    assert d.history is not None
    first, second = d.history.events
    assert first.prev == doc.GENESIS and first.entry is None
    assert second.prev == doc.event_hash(first) and second.entry == entry_id
    assert first.at == "2026-11-19T12:00:00Z"
    assert doc.parse(doc.encode(d)) == d


def test_history_keeps_the_newest_1000_events() -> None:
    chain: list[doc.Event] = []
    prev = doc.GENESIS
    for _ in range(doc.MAX_EVENTS):
        event = doc.Event("decrypt", "2026-11-19T12:00:00Z", None, prev)
        chain.append(event)
        prev = doc.event_hash(event)
    full = dataclasses.replace(ON, history=doc.History(doc.GENESIS, tuple(chain)))
    d = history.record(full, "vault-unlock", when=WHEN)
    assert d.history is not None
    assert len(d.history.events) == doc.MAX_EVENTS
    assert d.history.trimmed == 1
    assert d.history.anchor == doc.event_hash(chain[0]) == chain[1].prev
    assert d.history.events[-1].action == "vault-unlock"
    d = history.record(d, "vault-unlock", when=WHEN)
    assert d.history is not None and d.history.trimmed == 2
    assert doc.parse(doc.encode(d)) == d


def test_entries_and_profiles_record_what_they_do() -> None:
    d, key = entries.add_key(ON, "laptop")
    d = entries.archive(d, "laptop")
    d = entries.revoke(d, "laptop")
    d, _ = profiles.create(d, "p", [[doc.ASK_PASSWORD]])
    d = profiles.delete(d, "p")
    assert events(d) == [
        "entry-create",
        "entry-archive",
        "entry-revoke",
        "profile-change",
        "profile-change",
    ]
    assert d.history is not None
    assert [e.entry for e in d.history.events[:3]] == [key.id] * 3


def test_no_secrets_or_paths_are_recorded() -> None:
    d, _ = entries.add_password(ON, "work", "hunter2 is the password")
    assert d.history is not None
    recorded = doc.canonical([doc.event_json(e) for e in d.history.events])
    assert b"hunter2" not in recorded and b"work" not in recorded


@pytest.fixture
def vector_vault(tmp_path: Path) -> Path:
    path = tmp_path / "vault.ssc"
    shutil.copyfile(vectorkit.VECTORS / VAULT["file"], path)
    return path


def test_a_session_records_unlocks_and_access_changes(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        session.record("vault-unlock")
    with store.edit(MASTER, vector_vault) as session:
        session.add_grant([access.new_key(bytes(32))])
    assert events(store.load(MASTER, vector_vault)) == [
        "vault-unlock",
        "encrypt",
        "vault-unlock",
        "vault-access-change",
    ]


def test_history_survives_a_round_trip_through_the_vault(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        session.document = history.turn_off(session.document)
    assert store.load(MASTER, vector_vault).history is None
    with store.edit(MASTER, vector_vault) as session:
        session.document = history.turn_on(session.document)
        session.record("vault-unlock")
    assert events(store.load(MASTER, vector_vault)) == ["vault-unlock"]
