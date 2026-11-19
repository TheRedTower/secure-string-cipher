"""Profiles (VAULT.md section 3.2): named policies of vault entries and
typed passwords.

Applying a profile builds exactly its grants. Changing a profile does not
change files already written.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence

from secure_string_cipher.engine import access
from secure_string_cipher.errors import VaultError
from secure_string_cipher.vault import entries
from secure_string_cipher.vault.document import Document, Entry, Profile, Ref


def find(document: Document, name: str) -> Profile:
    for profile in document.profiles:
        if profile.name == name:
            return profile
    raise VaultError(f'There is no profile "{name}".')


def _wire_identity(entry: Entry) -> bytes:
    """What the entry's factor looks like in a grant, minus random salts.
    Two factors that look the same cannot share a grant (ACCESS.md section
    3.4): every recovery factor has an empty body, and keys are named by
    their `key_id`."""
    if entry.kind == "recovery":
        return bytes([access.RECOVERY])
    if isinstance(entry.secret, bytes):
        return bytes([access.KEY]) + access.key_id(entry.secret)
    return bytes([access.VAULT_PASSWORD]) + entry.id


def _check_entries(document: Document, profile: Profile) -> None:
    """A profile can only refer to what the vault holds, only to entries
    that would be offered for new files, and only to grants a file can
    hold."""
    for grant in profile.grants:
        seen: set[bytes] = set()
        for ref in grant:
            if ref.entry is None:
                continue
            entry = entries.by_id(document, ref.entry)
            if entry is None:
                raise VaultError(f'The profile "{profile.name}" names a missing entry.')
            if entry.status != "active":
                raise VaultError(
                    f'The profile "{profile.name}" names the {entry.status} entry '
                    f'"{entry.label}"; edit the profile first.'
                )
            identity = _wire_identity(entry)
            if identity in seen:
                raise VaultError(
                    f'A grant in the profile "{profile.name}" holds the same factor '
                    "twice: a grant can have only one recovery code, and only "
                    "one use of each key."
                )
            seen.add(identity)


def create(
    document: Document, name: str, grants: Sequence[Sequence[Ref]]
) -> tuple[Document, Profile]:
    """Add a profile. Every entry it names must exist and be active now."""
    profile = Profile(name, tuple(tuple(g) for g in grants))
    if any(p.name == name for p in document.profiles):
        raise VaultError(f'There is already a profile "{name}".')
    _check_entries(document, profile)
    return dataclasses.replace(
        document, profiles=(*document.profiles, profile)
    ), profile


def replace(
    document: Document, name: str, grants: Sequence[Sequence[Ref]]
) -> tuple[Document, Profile]:
    """Edit a profile's grants in place, keeping its position."""
    old = find(document, name)
    profile = Profile(name, tuple(tuple(g) for g in grants))
    _check_entries(document, profile)
    profiles = tuple(profile if p is old else p for p in document.profiles)
    return dataclasses.replace(document, profiles=profiles), profile


def delete(document: Document, name: str) -> Document:
    old = find(document, name)
    return dataclasses.replace(
        document, profiles=tuple(p for p in document.profiles if p is not old)
    )


def apply(
    document: Document, name: str, ask_password: Callable[[], str]
) -> list[list[access.NewFactor]]:
    """The grants a new file gets from the profile, as the factors each
    needs. `ask_password` is called once for each typed password in it.
    A profile naming a missing, archived or revoked entry is refused until
    it is edited."""
    profile = find(document, name)
    _check_entries(document, profile)
    policy = []
    for grant in profile.grants:
        factors = []
        for ref in grant:
            if ref.entry is None:
                factors.append(access.new_password(ask_password()))
                continue
            entry = entries.by_id(document, ref.entry)
            assert entry is not None  # checked above
            factors.append(entries.factor(document, entry.label))
        policy.append(factors)
    return policy
