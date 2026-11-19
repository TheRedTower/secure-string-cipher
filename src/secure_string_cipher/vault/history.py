"""Opt-in history (VAULT.md section 5): a hash-chained log of what the
vault was used for. Never file names or paths, and never secrets.

Every function takes a document and returns a new one. With history off,
`record` changes nothing, so callers record unconditionally.

The chain is tamper evidence against edits by someone who can unlock the
vault, such as a script holding the device key. It cannot stop that person
from rewriting the whole chain, or from trimming events and moving the
anchor forward.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime

from secure_string_cipher.engine import keyfile
from secure_string_cipher.vault.document import (
    MAX_EVENTS,
    Document,
    Event,
    History,
    event_hash,
)


def turn_on(document: Document) -> Document:
    """Start an empty history anchored at the genesis hash. Already on, the
    history is kept as it is."""
    if document.history is not None:
        return document
    return dataclasses.replace(document, history=History())


def turn_off(document: Document) -> Document:
    """Delete the history: `history` becomes null."""
    return dataclasses.replace(document, history=None)


def record(
    document: Document,
    action: str,
    entry: bytes | None = None,
    *,
    when: datetime | None = None,
) -> Document:
    """Append an event if history is on, keeping the newest MAX_EVENTS. The
    oldest event is trimmed by moving the anchor to its hash, which the next
    event's `prev` already holds, and counting it in `trimmed`."""
    history = document.history
    if history is None:
        return document
    event = Event(action, keyfile.timestamp(when), entry, history.head)
    events = (*history.events, event)
    anchor, trimmed = history.anchor, history.trimmed
    while len(events) > MAX_EVENTS:
        anchor = event_hash(events[0])
        events = events[1:]
        trimmed += 1
    return dataclasses.replace(document, history=History(anchor, events, trimmed))
