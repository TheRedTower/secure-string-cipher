"""The vault document (VAULT.md section 3): canonical JSON, parsed strictly."""

from __future__ import annotations

import json
from typing import Any

import pytest

from secure_string_cipher.errors import FormatError, Reason
from secure_string_cipher.vault import document as doc
from tests import vectorkit

VAULT = vectorkit.manifest()["vault"]
WHEN = "2026-11-18T09:30:00Z"
SIX_FACTORS = [{"ask": "password"}] + [{"entry": f"{c}" + "A" * 21} for c in "ABCDE"]


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def rejects(data: bytes) -> None:
    with pytest.raises(FormatError) as caught:
        doc.parse(data)
    assert caught.value.reason == Reason.VAULT_DOCUMENT


def vector_json() -> dict[str, Any]:
    copy: dict[str, Any] = json.loads(json.dumps(VAULT["document"]))
    return copy


def test_the_vector_document_round_trips() -> None:
    data = canonical(VAULT["document"])
    parsed = doc.parse(data)
    assert doc.encode(parsed) == data
    assert [e.label for e in parsed.entries] == ["work", "laptop", "paper"]
    laptop = parsed.entries[1]
    assert laptop.kind == "key" and isinstance(laptop.secret, bytes)
    assert len(laptop.secret) == 32
    assert parsed.profiles[0].grants[1][0] == doc.ASK_PASSWORD
    assert parsed.history is not None and len(parsed.history.events) == 2


def test_an_empty_vault() -> None:
    data = b'{"entries":[],"format":1,"history":null,"profiles":[]}'
    assert doc.parse(data) == doc.Document()
    assert doc.encode(doc.Document()) == data


@pytest.mark.parametrize(
    "data",
    [
        b'{"entries": [],"format":1,"history":null,"profiles":[]}',
        b'{"format":1,"entries":[],"history":null,"profiles":[]}',
        b'{"entries":[],"format":1,"history":null,"profiles":[]}\n',
        b'{"entries":[],"format":1,"format":1,"history":null,"profiles":[]}',
        b'{"entries":[],"format":1.0,"history":null,"profiles":[]}',
        b'{"entries":[],"format":true,"history":null,"profiles":[]}',
        b'{"entries":[],"format":2,"history":null,"profiles":[]}',
        b'{"entries":[],"format":NaN,"history":null,"profiles":[]}',
        b'{"entries":[],"format":1,"history":null}',
        b'{"entries":[],"extra":0,"format":1,"history":null,"profiles":[]}',
        b'{"entries":{},"format":1,"history":null,"profiles":[]}',
        b"\xff",
        b"[]",
        b"",
        b"[" * 100_000,
    ],
    ids=lambda d: repr(d[:40]),
)
def test_rejects_a_bad_document(data: bytes) -> None:
    rejects(data)


def test_rejects_escapes_json_does_not_require() -> None:
    value = vector_json()
    data = canonical(value).replace(b'"work"', b'"\\u0077ork"')
    rejects(data)


def test_rejects_an_integer_too_long_to_convert() -> None:
    """Python refuses ints over 4,300 digits with a plain ValueError."""
    rejects(
        b'{"entries":[],"format":' + b"1" * 5000 + b',"history":null,"profiles":[]}'
    )


def test_rejects_a_document_over_16_mib() -> None:
    rejects(b" " * (doc.MAX_SIZE + 1))


def _with(path: list[Any], new: Any) -> bytes:
    value = vector_json()
    target = value
    for part in path[:-1]:
        target = target[part]
    if new is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = new
    return canonical(value)


@pytest.mark.parametrize(
    ("path", "new"),
    [
        (["entries", 0, "label"], "Work"),
        (["entries", 0, "label"], "laptop"),
        (["entries", 0, "id"], "vN2ivz-LsPnrkku4jwdO7A"),
        (["entries", 0, "id"], "RfPUou6ytB4C2dwI_FF1tg=="),
        (["entries", 0, "id"], "RfPUou6ytB4C2dwI_FF1th"),
        (["entries", 0, "id"], "AAAA"),
        (["entries", 0, "kind"], "note"),
        (["entries", 0, "status"], "deleted"),
        (["entries", 0, "created"], "2026-02-30T09:30:00Z"),
        (["entries", 0, "created"], "2026-11-18 09:30:00"),
        (["entries", 0, "secret"], ""),
        (["entries", 0, "secret"], "café"),
        (["entries", 0, "secret"], 7),
        (["entries", 1, "secret"], "AAAA"),
        (["entries", 2, "secret"], "1LpPijnrIWeM5MdezYypmTcdSuUu0iMZMo0OU7lBAis"),
        (["entries", 0, "status"], KeyError),
        (["entries", 0, "note"], "x"),
        (["profiles", 0, "name"], "Backup"),
        (["profiles", 0, "grants"], []),
        (["profiles", 0, "grants", 0], []),
        (["profiles", 0, "grants", 0, 0], {"ask": "key"}),
        (["profiles", 0, "grants", 0, 0], {"entry": "x", "ask": "password"}),
        (["profiles", 0, "grants", 1, 1], {"ask": "password"}),
        (["profiles", 0, "grants", 1, 0], {"entry": "GQR9ACXL-LyrznyWeifRTQ"}),
        (["profiles", 0, "grants", 0], SIX_FACTORS),
        (["history", "anchor"], "AAAA"),
        (["history", "trimmed"], -1),
        (["history", "trimmed"], "0"),
        (["history", "events", 0, "action"], "export"),
        (["history", "events", 0, "entry"], "AAAA"),
        (["history", "events", 0, "at"], "yesterday"),
    ],
)
def test_rejects_a_broken_field(path: list[Any], new: Any) -> None:
    rejects(_with(path, new))


def test_a_profile_may_name_a_missing_entry() -> None:
    """VAULT.md section 3.2: it just cannot be applied until edited."""
    data = _with(["profiles", 0, "grants", 0, 0], {"entry": "AAAAAAAAAAAAAAAAAAAAAA"})
    assert doc.encode(doc.parse(data)) == data


def test_rejects_too_many_profile_grants() -> None:
    ask = [{"ask": "password"}]
    rejects(_with(["profiles", 0, "grants"], [ask] * 17))
    assert doc.parse(_with(["profiles", 0, "grants"], [ask] * 16))


def test_rejects_too_many_events() -> None:
    event = vector_json()["history"]["events"][0]
    rejects(_with(["history", "events"], [event] * 1001))


def test_the_model_refuses_what_parse_refuses() -> None:
    with pytest.raises(ValueError):
        doc.Entry(bytes(16), "Bad", "password", "x", WHEN)
    with pytest.raises(ValueError):
        doc.Entry(bytes(16), "ok", "key", "not bytes", WHEN)
    entry = doc.Entry(bytes(16), "ok", "password", "x", WHEN)
    with pytest.raises(ValueError):
        doc.Document(entries=(entry, entry))
    with pytest.raises(ValueError):
        doc.Profile("p", ((doc.ASK_PASSWORD, doc.ASK_PASSWORD),))
