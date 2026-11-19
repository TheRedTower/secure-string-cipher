"""Changing who can open a file (CLI.md section 3.2): `ssc access show`,
`add`, `remove`, `rotate` and `apply`.

Each change rewrites the file through a temporary file renamed into place.
The file is read inside that write, so it is closed before the rename, which
Windows needs.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher import fs
from secure_string_cipher.engine import access, container, payload
from secure_string_cipher.errors import CannotOpen, InputError, SSCError
from secure_string_cipher.service import files, vaults
from secure_string_cipher.service import grants as specs
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import document as doc


def _read_header(path: Path) -> container.Header:
    with path.open("rb") as handle:
        stream, _ = container.binary_stream(handle)
        return container.read_header(stream)


# --- show ------------------------------------------------------------------------


def _vault_document(ctx: Context) -> doc.Document | None:
    """The vault, if this device can open it without asking."""
    if not vaults.exists(ctx):
        return None
    try:
        with vaults.edit(ctx, ask=False) as session:
            return session.document
    except SSCError:  # locked, damaged or in use: show what the file says
        return None


def describe(factor: access.Factor, document: doc.Document | None) -> str:
    entries = document.entries if document else ()
    if factor.kind == access.PASSWORD:
        return "password"
    if factor.kind == access.VAULT_PASSWORD:
        for entry in entries:
            if entry.id == factor.entry_id:
                return f'vault entry "{entry.label}"'
        return f"vault password entry {factor.entry_id.hex()}"
    if factor.kind == access.KEY:
        for entry in entries:
            if (
                isinstance(entry.secret, bytes)
                and entry.kind == "key"
                and access.key_id(entry.secret) == factor.body
            ):
                return f'key "{entry.label}"'
        return f"key {factor.body.hex()}"
    return "recovery code"


def show(ctx: Context, path: Path) -> list[str]:
    """Each grant in plain words, such as `g1: password + key "laptop"`. It
    needs no credentials; labels come from the vault if this device can
    open it."""
    header = _read_header(path)
    document = _vault_document(ctx)
    lines = []
    for i, grant in enumerate(header.grants, 1):
        if grant.factors is None:
            lines.append(f"g{i}: a kind of grant this version of SSC cannot read")
        else:
            lines.append(
                f"g{i}: " + " + ".join(describe(f, document) for f in grant.factors)
            )
    return lines


# --- changes that keep the file key ------------------------------------------------


def _open(ctx: Context, handle: BinaryIO) -> tuple[container.Opened, files.Opener]:
    stream, armored = container.binary_stream(handle)
    header = container.read_header(stream)
    opener = files.Opener(ctx, header)
    file_key, index = opener.open()
    opener.record(index)
    return container.Opened(header, file_key, stream, armored), opener


def _only_passwords(factors: Sequence[access.Factor]) -> bool:
    return all(f.kind in (access.PASSWORD, access.VAULT_PASSWORD) for f in factors)


def add(ctx: Context, path: Path, spec: str) -> None:
    """`ssc access add <file> --grant <spec>`. Only someone who can open the
    file can add a way in."""
    tokens = specs.parse_grant(spec)
    saved: fs.NotDurable | None = None
    with ExitStack() as stack:

        def write(out: BinaryIO) -> None:
            with path.open("rb") as handle:
                opened, opener = _open(ctx, handle)
                grants = list(opened.header.grants)
                if len(grants) >= access.MAX_GRANTS:
                    raise InputError(f"A file has at most {access.MAX_GRANTS} grants.")
                build = opener.builder(stack)
                factors = build.policy([tokens])[0]
                files.check_policy([factors])
                new = access.new_grant(opened.file_key, factors)
                assert new.factors is not None
                if _only_passwords(new.factors) and any(
                    g.factors and not _only_passwords(g.factors) for g in grants
                ):
                    ctx.prompter.notice(
                        "Adding a password-only way in makes this file only as "
                        "strong as that password."
                    )
                nonlocal saved
                saved = build.save()  # before the file is published
                container.rewrite_access(opened, [*grants, new], out)

        late = files.durably(lambda: fs.write_atomic(path, write, replace=True))
    failure = late or saved
    if failure is not None:
        raise failure


def remove(ctx: Context, path: Path, grant: str) -> None:
    """`ssc access remove <file> --grant <gN>`. Removal, not revocation."""
    index = vaults.grant_index(grant)

    def write(out: BinaryIO) -> None:
        with path.open("rb") as handle:
            opened, _ = _open(ctx, handle)
            grants = list(opened.header.grants)
            if index >= len(grants):
                raise InputError(f"This file has no grant {grant}.")
            if len(grants) == 1:
                raise InputError("A file must keep at least one grant.")
            del grants[index]
            container.rewrite_access(opened, grants, out)

    late = files.durably(lambda: fs.write_atomic(path, write, replace=True))
    ctx.prompter.notice(
        f"Removed {grant}. Anyone who already opened this file, or has an old "
        "copy, can still open that copy. To lock them out of this file's future "
        "contents, use ssc access rotate."
    )
    if late is not None:
        raise late


def apply(ctx: Context, path: Path, profile: str) -> None:
    """`ssc access apply <file> --profile <name>`: replace the file's grants
    with the profile's, under the same file key."""
    saved: fs.NotDurable | None = None
    with ExitStack() as stack:

        def write(out: BinaryIO) -> None:
            with path.open("rb") as handle:
                opened, opener = _open(ctx, handle)
                build = opener.builder(stack)
                policy = build.profile(profile)
                files.check_policy(policy)
                grants = [access.new_grant(opened.file_key, f) for f in policy]
                nonlocal saved
                saved = build.save()  # before the file is published
                container.rewrite_access(opened, grants, out)

        late = files.durably(lambda: fs.write_atomic(path, write, replace=True))
    failure = late or saved
    if failure is not None:
        raise failure


# --- rotate ------------------------------------------------------------------------


Rebuild = Callable[[], access.NewFactor]


def _candidates(
    factor: access.Factor, creds: access.Credentials
) -> list[tuple[access.Credentials, Rebuild]]:
    """Each way to supply `factor`: credentials holding just that, and how
    to rebuild the factor from it. Rebuilding is lazy, since a password
    costs an Argon2id run."""
    out: list[tuple[access.Credentials, Rebuild]] = []
    if factor.kind == access.PASSWORD:
        for p in creds.passwords:
            out.append(
                (access.Credentials(passwords=[p]), partial(access.new_password, p))
            )
    elif factor.kind == access.VAULT_PASSWORD:
        entry_id = factor.entry_id
        stored = creds.entry_passwords.get(entry_id)
        sources = (
            [access.Credentials(entry_passwords={entry_id: stored})] if stored else []
        )
        found = [stored] if stored else []
        for p in creds.passwords:
            sources.append(access.Credentials(passwords=[p]))
            found.append(p)
        for source, password in zip(sources, found, strict=True):
            out.append((source, partial(access.new_vault_password, entry_id, password)))
    elif factor.kind == access.KEY:
        for k in creds.keys:
            if access.key_id(k) == factor.body:
                out.append((access.Credentials(keys=[k]), partial(access.new_key, k)))
    elif factor.kind == access.RECOVERY:
        for r in creds.recovery_codes:
            out.append(
                (
                    access.Credentials(recovery_codes=[r]),
                    partial(access.new_recovery, r),
                )
            )
    return out


def _rebuild(
    opened: container.Opened, grant: access.Grant, creds: access.Credentials
) -> list[access.NewFactor] | None:
    """The factors that rebuild `grant`, found by testing each assignment of
    what was supplied, factor by factor, against the grant itself (ACCESS.md
    section 5). Testing the exact assignment matters: two password factors
    must each be rebuilt with the password that filled that factor."""
    if grant.factors is None:
        return None
    header = opened.header
    options = [_candidates(f, creds) for f in grant.factors]
    try:
        picked = access.find_assignment(
            grant,
            [[source for source, _ in o] for o in options],
            header.fixed.to_bytes(),
            header.access_body,
            header.access_mac,
        )
    except CannotOpen:
        return None
    return [o[k][1]() for o, k in zip(options, picked, strict=True)]


def rotate(ctx: Context, path: Path, *, force: bool = False) -> None:
    """`ssc access rotate <file>`: a new file key and payload nonce, with
    every grant rebuilt that can be. A grant that cannot is listed, and
    dropped only after asking, or with `force`."""

    def write(out: BinaryIO) -> None:
        with path.open("rb") as handle:
            opened, opener = _open(ctx, handle)
            creds = opener.credentials()
            policy, dropped = [], []
            for i, grant in enumerate(opened.header.grants, 1):
                rebuilt = _rebuild(opened, grant, creds)
                if rebuilt is None:
                    dropped.append(f"g{i}")
                else:
                    policy.append(rebuilt)
            if (
                dropped
                and not force
                and not ctx.prompter.confirm(
                    f"SSC cannot rebuild {', '.join(dropped)}, so rotating "
                    "drops it. Continue?",
                    default=False,
                )
            ):
                raise InputError("Not rotated.")
            if not policy:
                raise CannotOpen()
            old = payload.payload_key(opened.file_key, opened.header.fixed)
            plaintext = payload.ChunkReader(payload.chunks(old, opened.payload))
            container.encrypt(plaintext, out, policy, armored=opened.armored)

    late = files.durably(lambda: fs.write_atomic(path, write, replace=True))
    ctx.prompter.notice("Rotated. Old copies of this file still open as they did.")
    if late is not None:
        raise late
