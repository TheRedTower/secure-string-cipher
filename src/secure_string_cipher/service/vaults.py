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
from secure_string_cipher.engine import access, container, keyfile, recovery
from secure_string_cipher.errors import CannotOpen, InputError, SSCError, VaultError
from secure_string_cipher.service import passwords
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, history, keychain, store


class Locked(VaultError):
    """This device cannot unlock the vault without asking."""


def check_label(label: str, what: str = "label") -> str:
    """Labels and profile names: a lowercase letter, then up to 63 of
    lowercase letters, digits, `.`, `_` and `-` (VAULT.md section 3)."""
    if not keyfile.LABEL.fullmatch(label):
        raise InputError(
            f'"{label}" is not a valid {what}: use a lowercase letter, then up '
            "to 63 lowercase letters, digits, dots, underscores or hyphens."
        )
    return label


def require_show(ctx: Context) -> None:
    """A new recovery code must be shown to someone (CLI.md section 2)."""
    if not ctx.prompter.can_show():
        raise InputError(
            "A new recovery code can only be shown on a terminal, so it cannot "
            "be created here."
        )


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
                raise Locked("The vault is locked.")
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
    if recovery_code:
        require_show(ctx)
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
    generated; otherwise the person sets one, and it is checked like any
    password set for encryption (CLI.md section 3.4)."""
    check_label(label)
    if password is None:
        password = passwords.new_password(ctx, f'Password for vault entry "{label}"')
    with edit(ctx) as session:
        session.document, entry = entries.add_password(
            session.document, label, password
        )
    return entry


def add_key(ctx: Context, label: str) -> doc.Entry:
    """`ssc vault add <label> --key`. A key entry has no other way back if
    the vault is lost, so a recovery code is offered in the same step, where
    one can be shown."""
    check_label(label)
    with edit(ctx) as session:
        session.document, entry = entries.add_key(session.document, label)
        if ctx.prompter.can_show() and ctx.prompter.confirm(
            "This key has no other way back if the vault is lost. "
            "Add a recovery code now?",
            default=True,
        ):
            taken = {e.label for e in session.document.entries}
            _add_recovery(ctx, session, _free(f"{label[:45]}-recovery", taken))
    return entry


def _free(base: str, taken: set[str]) -> str:
    """`base`, or `base-2` and so on: `base` is at most 54 characters, so a
    suffix of up to 9 digits keeps the label within 64."""
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


def choose_recovery(ctx: Context, session: store.Session) -> tuple[doc.Entry, bool]:
    """The entry the `recovery` token means (CLI.md section 2), and whether
    it was just created. A new one is refused where its code cannot be
    shown, and is shown once the vault holding it is written."""
    if not any(
        e.kind == "recovery" and e.status == "active" for e in session.document.entries
    ):
        require_show(ctx)
    session.document, entry, created = entries.choose_recovery(session.document)
    if created:
        show_recovery_after_write(ctx, session, entry)
    return entry, created


def _add_recovery(ctx: Context, session: store.Session, label: str) -> doc.Entry:
    require_show(ctx)
    session.document, entry = entries.add_recovery(session.document, label)
    show_recovery_after_write(ctx, session, entry)
    return entry


def add_recovery(ctx: Context, label: str) -> doc.Entry:
    """`ssc vault add <label> --recovery-code`: shown once, once the vault
    has been written."""
    check_label(label)
    require_show(ctx)
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
        others = entries.credentials(session.document)
        session.document = entries.revoke(session.document, label)
    ctx.prompter.notice(
        f'Revoked "{label}". SSC will refuse it, but anyone with a copy of the '
        "secret can still open the files it opens until they are rotated."
    )
    return [] if scan is None else _uses(scan, entry, others)


def _uses(folder: Path, entry: doc.Entry, others: access.Credentials) -> list[Path]:
    """The SSC files under `folder` with a grant that uses `entry`, alone or
    with other factors, since each of them needs rotating."""
    found = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                stream, _ = container.binary_stream(handle)
                header = container.read_header(stream)
            if any(grant_uses(header, g, entry, others) for g in header.grants):
                found.append(path)
        except (OSError, SSCError, ValueError):
            continue  # unreadable, not an SSC file, or damaged
    return found


def grant_uses(
    header: container.Header,
    grant: access.Grant,
    entry: doc.Entry,
    others: access.Credentials,
) -> bool:
    """Password and key entries are named in the grant itself. A recovery
    factor names nothing, so the grant is opened with this entry's code and
    whatever the vault holds for its other factors; a grant that also needs
    a typed password cannot be told apart, and is not listed."""
    factors = grant.factors or ()
    if entry.kind == "password":
        return any(
            f.kind == access.VAULT_PASSWORD and f.entry_id == entry.id for f in factors
        )
    assert isinstance(entry.secret, bytes)
    if entry.kind == "key":
        mine = access.key_id(entry.secret)
        return any(f.kind == access.KEY and f.body == mine for f in factors)
    if not any(f.kind == access.RECOVERY for f in factors):
        return False
    code = [access.Credentials(recovery_codes=[entry.secret])]
    try:
        access.find_assignment(
            grant,
            [code if f.kind == access.RECOVERY else [others] for f in factors],
            header.fixed.to_bytes(),
            header.access_body,
            header.access_mac,
        )
    except CannotOpen:
        return False
    return True


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


def peek(ctx: Context) -> doc.Document | None:
    """The vault, if this device can read it without asking; None if there
    is none, or it is locked, damaged, in use or unreadable."""
    if not exists(ctx):
        return None
    try:
        with edit(ctx, ask=False) as session:
            return session.document
    except (SSCError, OSError):
        return None


def this_device(ctx: Context) -> int | None:
    """The index of this device's grant, without asking for anything: None
    if the vault is locked here or there is no keychain."""
    chain = ctx.chain()
    if chain is None or not exists(ctx):
        return None
    try:
        with edit(ctx, ask=False) as session:
            return keychain.this_device(session, chain)
    except (Locked, CannotOpen):
        return None


def remove_device(ctx: Context, grant: str) -> None:
    """`ssc vault remove-device <gN>`."""
    index = grant_index(grant)
    chain = ctx.chain()
    with edit(ctx) as session:
        keychain.remove_device(session, index, chain, forget=chain is not None)
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
    with store.locked(ctx.vault_path):
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
