"""Profiles (CLI.md section 3.4): `ssc profile create`, `list`, `show`,
`delete` and `default`. Profile grant specs use `--grant` syntax, except
that `keyfile:` is refused."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from secure_string_cipher.errors import InputError
from secure_string_cipher.service import grants as specs
from secure_string_cipher.service import settings, vaults
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, profiles, store


def _refs(
    ctx: Context, session: store.Session, grant: Sequence[specs.Token]
) -> list[doc.Ref]:
    refs = []
    for token in grant:
        if token.kind == "password":
            refs.append(doc.ASK_PASSWORD)
        elif token.kind == "vault":
            refs.append(doc.Ref(entries.find(session.document, token.value).id))
        elif token.kind == "recovery":
            # Resolved now, so later recovery entries do not change it.
            refs.append(doc.Ref(vaults.choose_recovery(ctx, session)[0].id))
        else:
            raise InputError(
                "A profile can only refer to what the vault holds: run "
                f"ssc key import {token.value} first, then use vault:<label>."
            )
    return refs


def create(ctx: Context, name: str, grant_specs: Sequence[str]) -> None:
    vaults.check_label(name, "profile name")
    parsed = specs.parse_grants(grant_specs)
    with vaults.edit(ctx) as session:
        refs = [_refs(ctx, session, g) for g in parsed]
        session.document, _ = profiles.create(session.document, name, refs)


def list_(ctx: Context) -> tuple[doc.Profile, ...]:
    with vaults.edit(ctx) as session:
        return session.document.profiles


def show(ctx: Context, name: str) -> list[str]:
    """Each grant in plain words, such as `g1: vault entry "laptop"`."""
    with vaults.edit(ctx) as session:
        return describe(session.document, name)


def describe(document: doc.Document, name: str) -> list[str]:
    """`show`, from a vault already read: no unlock, no Argon2id run."""
    profile = profiles.find(document, name)
    lines = []
    for i, grant in enumerate(profile.grants, 1):
        words = []
        for ref in grant:
            if ref.entry is None:
                words.append("a password typed at encrypt time")
                continue
            entry = entries.by_id(document, ref.entry)
            words.append(f'vault entry "{entry.label}"' if entry else "a missing entry")
        lines.append(f"g{i}: " + " + ".join(words))
    return lines


def delete(ctx: Context, name: str, settings_path: Path | None = None) -> None:
    with vaults.edit(ctx) as session:
        session.document = profiles.delete(session.document, name)
    current = settings.load(settings_path)
    if current.default_profile == name:
        settings.save(settings.Settings(None), settings_path)


def set_default(
    ctx: Context, name: str | None, settings_path: Path | None = None
) -> None:
    """`ssc profile default <name>`, or `--none` with `name` None."""
    if name is not None:
        with vaults.edit(ctx) as session:
            profiles.find(session.document, name)
    settings.save(settings.Settings(name), settings_path)
