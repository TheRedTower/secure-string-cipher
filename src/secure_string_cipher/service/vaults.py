"""Vault operations (CLI.md section 3.3) and unlocking the vault for any
other operation: this device's key first, then the master password.

Every use of an unlocked vault goes through `edit`, so a `vault-unlock`
event is recorded when history is on, and the lock is held throughout.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from secure_string_cipher import fs
from secure_string_cipher.engine import access, container, recovery
from secure_string_cipher.errors import CannotOpen, InputError, SSCError, VaultError
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, history, keychain, store


def exists(ctx: Context) -> bool:
    return ctx.vault_path.exists()


def _require(ctx: Context) -> None:
    if not exists(ctx):
        raise VaultError(
            f"There is no vault at {ctx.vault_path}. Create one with ssc vault init."
        )


def _device(ctx: Context) -> access.Credentials:
    chain = ctx.chain()
    if chain is None:
        return access.Credentials()
    return keychain.credentials(ctx.vault_path, chain)


def _master(ctx: Context) -> str:
    if ctx.master_password is not None:
        return ctx.master_password
    return ctx.prompter.secret("Vault master password")


@contextmanager
def edit(ctx: Context, *, ask: bool = True) -> Iterator[store.Session]:
    """The vault, unlocked with this device's key if it can be, and
    otherwise with the master password. With `ask` False, a vault this
    device cannot unlock is a VaultError instead of a prompt."""
    _require(ctx)
    with ExitStack() as stack:
        session: store.Session | None = None
        device = _device(ctx)
        if device.keys:
            try:
                session = stack.enter_context(store.edit(device, ctx.vault_path))
            except CannotOpen:
                session = None  # a stale keychain item; fall back
        if session is None:
            if not ask and ctx.master_password is None:
                raise VaultError("The vault is locked.")
            creds = access.Credentials(passwords=[_master(ctx)])
            session = stack.enter_context(store.edit(creds, ctx.vault_path))
        session.record("vault-unlock")
        yield session


# --- init and status -----------------------------------------------------------


def init(ctx: Context, *, device_key: bool = True, recovery_code: bool = False) -> None:
    """`ssc vault init`: create the vault with a new master password, add
    this device's key unless there is no keychain or it is not wanted, and
    optionally a recovery code for the vault itself, shown once."""
    if exists(ctx):
        raise VaultError(f"There is already a vault at {ctx.vault_path}.")
    master = ctx.prompter.new_master_password()
    store.create(master, ctx.vault_path)
    chain = ctx.chain() if device_key else None
    if not device_key and not recovery_code:
        return
    with store.edit(access.Credentials(passwords=[master]), ctx.vault_path) as session:
        if chain is not None:
            keychain.add_device(session, chain)
        elif device_key:
            ctx.prompter.notice(
                "No OS keychain is available, so this device will ask for the "
                "master password each time."
            )
        if recovery_code:
            r = recovery.new()
            session.add_recovery_grant(r)
            session.after_write.append(
                lambda: ctx.prompter.show_once(
                    "Vault recovery code", recovery.encode(r)
                )
            )


class State(StrEnum):
    NONE = "no vault yet"
    LOCKED = "locked"
    DEVICE = "unlocked with this device"


@dataclass(frozen=True)
class Status:
    state: State
    entries: int | None = None
    profiles: int | None = None
    history: bool | None = None


def status(ctx: Context) -> Status:
    """`ssc vault status`: what can be told without asking for anything."""
    if not exists(ctx):
        return Status(State.NONE)
    device = _device(ctx)
    if not device.keys:
        return Status(State.LOCKED)
    try:
        document = store.load(device, ctx.vault_path)
    except CannotOpen:
        return Status(State.LOCKED)
    return Status(
        State.DEVICE,
        len(document.entries),
        len(document.profiles),
        document.history is not None,
    )


# --- entries -------------------------------------------------------------------


def add_password(ctx: Context, label: str, password: str | None = None) -> doc.Entry:
    """`ssc vault add <label> --password`. `password` is given when it was
    generated; otherwise the person sets one."""
    if password is None:
        password = ctx.prompter.new_password(f'Password for vault entry "{label}"')
    with edit(ctx) as session:
        session.document, entry = entries.add_password(
            session.document, label, password
        )
    return entry


def add_key(ctx: Context, label: str) -> doc.Entry:
    """`ssc vault add <label> --key`. A key entry has no other way back if
    the vault is lost, so a recovery code is offered in the same step."""
    with edit(ctx) as session:
        session.document, entry = entries.add_key(session.document, label)
        if ctx.prompter.confirm(
            "This key has no other way back if the vault is lost. "
            "Add a recovery code now?",
            default=True,
        ):
            taken = {e.label for e in session.document.entries}
            _add_recovery(ctx, session, _free(f"{label[:55]}-recovery", taken))
    return entry


def _free(base: str, taken: set[str]) -> str:
    label, n = base, 2
    while label in taken:
        label, n = f"{base}-{n}", n + 1
    return label


def show_recovery_after_write(
    ctx: Context, session: store.Session, entry: doc.Entry
) -> None:
    """Show a new recovery entry's code once, after the vault holding it
    has been written, so a code is never shown that the vault then lost."""
    assert isinstance(entry.secret, bytes)
    code = recovery.encode(entry.secret)
    session.after_write.append(
        lambda: ctx.prompter.show_once(f'Recovery code "{entry.label}"', code)
    )


def _add_recovery(ctx: Context, session: store.Session, label: str) -> doc.Entry:
    session.document, entry = entries.add_recovery(session.document, label)
    show_recovery_after_write(ctx, session, entry)
    return entry


def add_recovery(ctx: Context, label: str) -> doc.Entry:
    """`ssc vault add <label> --recovery-code`: shown once, once the vault
    has been written."""
    with edit(ctx) as session:
        return _add_recovery(ctx, session, label)


def list_entries(ctx: Context) -> tuple[doc.Entry, ...]:
    with edit(ctx) as session:
        return session.document.entries


def archive(ctx: Context, label: str) -> None:
    with edit(ctx) as session:
        session.document = entries.archive(session.document, label)


def revoke(ctx: Context, label: str, scan: Path | None = None) -> list[Path]:
    """`ssc vault revoke`: mark the entry revoked, and list the SSC files
    under `scan` that it opens, so the caller can offer to rotate them. A
    copy of the secret still opens them until they are rotated."""
    with edit(ctx) as session:
        entry = entries.find(session.document, label)
        creds = entries.credentials(doc.Document(entries=(entry,)))
        session.document = entries.revoke(session.document, label)
    ctx.prompter.notice(
        f'Revoked "{label}". SSC will refuse it, but anyone with a copy of the '
        "secret can still open the files it opens until they are rotated."
    )
    return [] if scan is None else _opens(scan, creds)


def _opens(folder: Path, creds: access.Credentials) -> list[Path]:
    found = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                container.unlock(handle, creds)
        except (OSError, SSCError, ValueError):
            continue  # unreadable, not an SSC file, damaged, or not this entry's
        found.append(path)
    return found


# --- access to the vault itself --------------------------------------------------


def change_password(ctx: Context) -> None:
    """`ssc vault change-password`: needs the current master password and a
    new one, and rewraps one grant (VAULT.md section 2)."""
    current = _master(ctx)
    new = ctx.prompter.new_master_password()
    with store.edit(access.Credentials(passwords=[current]), ctx.vault_path) as session:
        session.record("vault-unlock")
        session.change_master_password(current, new)


def reset_password(ctx: Context, code: str) -> None:
    """Set a new master password with the vault's own recovery code."""
    r = recovery.decode(code)
    new = ctx.prompter.new_master_password()
    _require(ctx)
    with store.edit(access.Credentials(recovery_codes=[r]), ctx.vault_path) as session:
        session.record("vault-unlock")
        session.reset_master_password(r, new)


def add_device(ctx: Context) -> int:
    chain = ctx.chain()
    if chain is None:
        raise VaultError("No OS keychain is available here.")
    with edit(ctx) as session:
        return keychain.add_device(session, chain)


def remove_device(ctx: Context, grant: str) -> None:
    """`ssc vault remove-device <gN>`."""
    index = grant_index(grant)
    with edit(ctx) as session:
        keychain.remove_device(session, index, ctx.chain())
    ctx.prompter.notice(
        f"Removed {grant}. That device has already seen the vault's key; to "
        "lock a lost device out, rotate the vault."
    )


def grant_index(grant: str) -> int:
    if not (grant.startswith("g") and grant[1:].isdigit() and int(grant[1:]) >= 1):
        raise InputError(f'"{grant}" is not a grant: use g1, g2 and so on.')
    return int(grant[1:]) - 1


def backup(ctx: Context, path: Path) -> None:
    """`ssc vault backup <path>`: a copy of the encrypted vault, which opens
    with the grants it has now."""
    _require(ctx)
    if path.exists():
        raise FileExistsError(f"{path} already exists.")
    with fs.locked(store.lock_path(ctx.vault_path)):
        data = store.read_file(ctx.vault_path)
    fs.write_atomic(path, lambda out: out.write(data), replace=False)
    ctx.prompter.notice(
        "The backup opens with the master password and recovery code the vault "
        "has now. A device key works only while that device's keychain item "
        "exists."
    )


# --- history -------------------------------------------------------------------


def history_on(ctx: Context) -> None:
    with edit(ctx) as session:
        session.document = history.turn_on(session.document)


def history_off(ctx: Context) -> None:
    with edit(ctx) as session:
        session.document = history.turn_off(session.document)


def history_show(ctx: Context) -> doc.History | None:
    with edit(ctx) as session:
        return session.document.history
