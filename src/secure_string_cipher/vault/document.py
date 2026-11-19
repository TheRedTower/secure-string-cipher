"""The vault document (VAULT.md section 3): the canonical JSON inside the
vault's payload.

Every rule lives in the dataclasses, which raise ValueError when broken.
`parse` adds the JSON rules (exact fields, exact types, canonical bytes) and
reports any broken rule as a FormatError.
"""

from __future__ import annotations

import base64
import json
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, NoReturn

from secure_string_cipher.engine import access
from secure_string_cipher.engine.keyfile import LABEL, valid_timestamp
from secure_string_cipher.errors import FormatError, Reason

FORMAT = 1
MAX_SIZE = 16 * 1024 * 1024
MAX_EVENTS = 1000
MAX_GRANTS = access.MAX_GRANTS
ID_SIZE = access.ENTRY_ID_SIZE
HASH_SIZE = 32

KINDS = ("password", "key", "recovery")
STATUSES = ("active", "archived", "revoked")
ACTIONS = (
    "vault-unlock",
    "vault-access-change",
    "entry-create",
    "entry-archive",
    "entry-revoke",
    "profile-change",
    "encrypt",
    "decrypt",
)
_SECRET_SIZES = {"key": access.KEY_SIZE, "recovery": access.RECOVERY_SIZE}
_B64 = re.compile(r"[A-Za-z0-9_-]*")


def b64(data: bytes) -> str:
    """Base64url without padding, the document's form for byte strings."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _check_label(label: str, what: str) -> None:
    if not LABEL.fullmatch(label):
        raise ValueError(f"Not a valid {what}: {label!r}")


def _check_timestamp(text: str) -> None:
    if not valid_timestamp(text):
        raise ValueError(f"Not a valid timestamp: {text!r}")


def _check_size(data: bytes | None, size: int, what: str) -> None:
    if data is not None and len(data) != size:
        raise ValueError(f"{what} must be {size} bytes.")


# --- the model -------------------------------------------------------------------


@dataclass(frozen=True)
class Entry:
    """A named secret (VAULT.md section 3.1). A `password` entry's secret is
    its text; a `key` or `recovery` entry's is its bytes."""

    id: bytes
    label: str
    kind: str
    secret: str | bytes = field(repr=False)
    created: str
    status: str = "active"

    def __post_init__(self) -> None:
        _check_size(self.id, ID_SIZE, "An entry ID")
        _check_label(self.label, "label")
        _check_timestamp(self.created)
        if self.kind not in KINDS:
            raise ValueError(f"Not an entry kind: {self.kind!r}")
        if self.status not in STATUSES:
            raise ValueError(f"Not an entry status: {self.status!r}")
        if self.kind == "password":
            if not isinstance(self.secret, str) or not self.secret:
                raise ValueError("A password entry needs a non-empty password.")
            if unicodedata.normalize("NFC", self.secret) != self.secret:
                raise ValueError("A password entry is stored NFC-normalised.")
        elif not isinstance(self.secret, bytes):
            raise ValueError(f"A {self.kind} entry's secret is bytes.")
        else:
            _check_size(self.secret, _SECRET_SIZES[self.kind], f"A {self.kind}")


@dataclass(frozen=True)
class Ref:
    """A factor reference in a profile: a vault entry, or, with `entry`
    None, a password typed at encrypt time."""

    entry: bytes | None = None

    def __post_init__(self) -> None:
        _check_size(self.entry, ID_SIZE, "An entry ID")


ASK_PASSWORD = Ref()


@dataclass(frozen=True)
class Profile:
    """A named policy (VAULT.md section 3.2). It may name entries that are
    missing or revoked; such a profile cannot be applied until edited."""

    name: str
    grants: tuple[tuple[Ref, ...], ...]

    def __post_init__(self) -> None:
        _check_label(self.name, "profile name")
        if not 1 <= len(self.grants) <= MAX_GRANTS:
            raise ValueError(f"A profile needs 1 to {MAX_GRANTS} grants.")
        for grant in self.grants:
            if not 1 <= len(grant) <= access.MAX_FACTORS:
                raise ValueError(f"A grant needs 1 to {access.MAX_FACTORS} factors.")
            entries = [ref.entry for ref in grant if ref.entry is not None]
            if len(set(entries)) != len(entries):
                raise ValueError("A grant cannot name the same entry twice.")
            if len(grant) - len(entries) > 1:
                raise ValueError("A grant holds at most one typed password.")


@dataclass(frozen=True)
class Event:
    """One history event (VAULT.md section 5)."""

    action: str
    at: str
    entry: bytes | None
    prev: bytes

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"Not a history action: {self.action!r}")
        _check_timestamp(self.at)
        _check_size(self.entry, ID_SIZE, "An entry ID")
        _check_size(self.prev, HASH_SIZE, "An event's prev")


@dataclass(frozen=True)
class History:
    """The opt-in history. Its chain is checked by the history step
    (Phase 3, step 5); here only its shape is."""

    anchor: bytes
    events: tuple[Event, ...]
    trimmed: int = 0

    def __post_init__(self) -> None:
        _check_size(self.anchor, HASH_SIZE, "The history anchor")
        if len(self.events) > MAX_EVENTS:
            raise ValueError(f"History keeps at most {MAX_EVENTS} events.")
        if self.trimmed < 0:
            raise ValueError("The trimmed count cannot be negative.")


@dataclass(frozen=True)
class Document:
    entries: tuple[Entry, ...] = ()
    profiles: tuple[Profile, ...] = ()
    history: History | None = None

    def __post_init__(self) -> None:
        for what, values in (
            ("entry ID", [e.id for e in self.entries]),
            ("entry label", [e.label for e in self.entries]),
            ("profile name", [p.name for p in self.profiles]),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"Each {what} must be unique in the vault.")

    def to_json(self) -> dict[str, Any]:
        return {
            "entries": [_entry_json(e) for e in self.entries],
            "format": FORMAT,
            "history": None if self.history is None else _history_json(self.history),
            "profiles": [_profile_json(p) for p in self.profiles],
        }


# --- encoding ----------------------------------------------------------------------


def _entry_json(entry: Entry) -> dict[str, Any]:
    secret = entry.secret if isinstance(entry.secret, str) else b64(entry.secret)
    return {
        "created": entry.created,
        "id": b64(entry.id),
        "kind": entry.kind,
        "label": entry.label,
        "secret": secret,
        "status": entry.status,
    }


def _ref_json(ref: Ref) -> dict[str, str]:
    return {"ask": "password"} if ref.entry is None else {"entry": b64(ref.entry)}


def _profile_json(profile: Profile) -> dict[str, Any]:
    return {
        "grants": [[_ref_json(r) for r in grant] for grant in profile.grants],
        "name": profile.name,
    }


def event_json(event: Event) -> dict[str, Any]:
    return {
        "action": event.action,
        "at": event.at,
        "entry": None if event.entry is None else b64(event.entry),
        "prev": b64(event.prev),
    }


def _history_json(history: History) -> dict[str, Any]:
    return {
        "anchor": b64(history.anchor),
        "events": [event_json(e) for e in history.events],
        "trimmed": history.trimmed,
    }


def canonical(value: Any) -> bytes:
    """Canonical JSON (VAULT.md section 3): sorted keys, no insignificant
    whitespace, UTF-8, and escapes only where JSON requires them."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def encode(document: Document) -> bytes:
    data = canonical(document.to_json())
    if len(data) > MAX_SIZE:
        raise ValueError("The vault document would be over 16 MiB.")
    return data


# --- parsing -----------------------------------------------------------------------


def _bad(message: str) -> NoReturn:
    raise FormatError(Reason.VAULT_DOCUMENT, message)


def _object(value: Any, fields: Sequence[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or sorted(value) != sorted(fields):
        _bad(f"{where} must have exactly the fields {', '.join(sorted(fields))}.")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        _bad(f"{where} must be a list.")
    return value


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        _bad(f"{where} must be a string.")
    return value


def _int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _bad(f"{where} must be an integer.")
    return value


def _bytes(value: Any, where: str) -> bytes:
    text = _str(value, where)
    if not _B64.fullmatch(text) or len(text) % 4 == 1:
        _bad(f"{where} is not Base64url without padding.")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(data) != text:
        _bad(f"{where} is not canonical Base64url.")
    return data


def _entry(value: Any) -> Entry:
    obj = _object(
        value, ("created", "id", "kind", "label", "secret", "status"), "An entry"
    )
    kind = _str(obj["kind"], "An entry's kind")
    secret: str | bytes = _str(obj["secret"], "An entry's secret")
    if kind != "password":
        secret = _bytes(secret, "An entry's secret")
    return Entry(
        id=_bytes(obj["id"], "An entry ID"),
        label=_str(obj["label"], "An entry label"),
        kind=kind,
        secret=secret,
        created=_str(obj["created"], "An entry's created time"),
        status=_str(obj["status"], "An entry's status"),
    )


def _ref(value: Any) -> Ref:
    if isinstance(value, dict) and list(value) == ["ask"]:
        if value["ask"] != "password":
            _bad('A typed factor must be {"ask": "password"}.')
        return ASK_PASSWORD
    obj = _object(value, ("entry",), "A factor reference")
    return Ref(_bytes(obj["entry"], "A factor reference"))


def _profile(value: Any) -> Profile:
    obj = _object(value, ("grants", "name"), "A profile")
    grants = tuple(
        tuple(_ref(r) for r in _list(g, "A grant"))
        for g in _list(obj["grants"], "A profile's grants")
    )
    return Profile(_str(obj["name"], "A profile name"), grants)


def _event(value: Any) -> Event:
    obj = _object(value, ("action", "at", "entry", "prev"), "A history event")
    entry = None if obj["entry"] is None else _bytes(obj["entry"], "An event's entry")
    return Event(
        action=_str(obj["action"], "An event's action"),
        at=_str(obj["at"], "An event's time"),
        entry=entry,
        prev=_bytes(obj["prev"], "An event's prev"),
    )


def _history(value: Any) -> History | None:
    if value is None:
        return None
    obj = _object(value, ("anchor", "events", "trimmed"), "The history")
    events = _list(obj["events"], "The history's events")
    if len(events) > MAX_EVENTS:
        _bad(f"History keeps at most {MAX_EVENTS} events.")
    return History(
        anchor=_bytes(obj["anchor"], "The history anchor"),
        events=tuple(_event(e) for e in events),
        trimmed=_int(obj["trimmed"], "The trimmed count"),
    )


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        _bad("The vault document repeats a field.")
    return dict(pairs)


def _no_floats(text: str) -> NoReturn:
    _bad("The vault document holds a number that is not an integer.")


def parse(data: bytes) -> Document:
    """Parse an authenticated vault payload strictly. Anything but a
    canonical document of this format is a FormatError."""
    if len(data) > MAX_SIZE:
        _bad("The vault document is over 16 MiB.")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_no_floats,
            parse_constant=_no_floats,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _bad("The vault document is not valid UTF-8 JSON.")
    obj = _object(value, ("entries", "format", "history", "profiles"), "The vault")
    if _int(obj["format"], "The vault's format") != FORMAT:
        _bad("The vault document uses a format this SSC cannot read.")
    try:
        document = Document(
            entries=tuple(_entry(e) for e in _list(obj["entries"], "entries")),
            profiles=tuple(_profile(p) for p in _list(obj["profiles"], "profiles")),
            history=_history(obj["history"]),
        )
        canonical_bytes = encode(document)
    except (ValueError, UnicodeEncodeError) as error:
        _bad(str(error))
    if canonical_bytes != data:
        _bad("The vault document is not in canonical form.")
    return document
