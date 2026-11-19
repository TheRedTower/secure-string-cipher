"""Encrypting and decrypting files (CLI.md sections 1 and 3.1).

Output always goes through a temporary file renamed into place, and an
existing output is refused unless `force` is given. Decrypting to a stream
holds the plaintext until the whole file has authenticated: in memory up to
64 MiB, then in an owner-only temporary file that is deleted when done.
"""

from __future__ import annotations

import dataclasses
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher import fs
from secure_string_cipher.engine import access, container, keyfile, payload, recovery
from secure_string_cipher.engine.payload import Readable
from secure_string_cipher.errors import CannotOpen, InputError, SSCError
from secure_string_cipher.service import grants as specs
from secure_string_cipher.service import passwords, settings, vaults
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, profiles, store

HOLD_IN_MEMORY = 64 * 1024 * 1024
Output = Path | BinaryIO


# --- output --------------------------------------------------------------------


def _refuse_existing(output: Output, force: bool) -> None:
    """Checked before anything is asked, and again just before writing."""
    if isinstance(output, Path) and not force and output.exists():
        raise FileExistsError(f"{output} already exists. Use --force to replace it.")


def _write(
    output: Output, force: bool, write: Callable[[BinaryIO], object]
) -> fs.NotDurable | None:
    """Write the output. A folder sync that failed after the rename is
    returned, not raised: the file is in place, so the vault session around
    the write must still commit, and the caller raises it afterwards."""
    if isinstance(output, Path):
        _refuse_existing(output, force)
        return durably(lambda: fs.write_atomic(output, write, replace=force))
    write(output)
    return None


def durably(commit: Callable[[], object]) -> fs.NotDurable | None:
    """Run a write whose rename is its commit point, returning the
    `NotDurable` it raised, if any, for the caller to raise once the vault
    has been saved too."""
    try:
        commit()
    except fs.NotDurable as late:
        return late
    return None


def _release(held: tempfile.SpooledTemporaryFile[bytes], sink: BinaryIO) -> None:
    held.seek(0)
    for part in iter(lambda: held.read(1 << 16), b""):
        payload.write_all(sink, part)
    sink.flush()


# --- building a policy -----------------------------------------------------------


@dataclass
class Builder:
    """Turns grant specs into factors, opening the vault only if a spec
    needs it, and once. `save` writes and releases it before any output is
    published, so no output depends on a vault entry that was then lost,
    and the vault's lock is not held while a payload streams."""

    ctx: Context
    stack: ExitStack
    session: store.Session | None = None

    def vault(self) -> store.Session:
        if self.session is None:
            self.session = self.stack.enter_context(vaults.edit(self.ctx))
        return self.session

    def factor(self, token: specs.Token) -> access.NewFactor:
        if token.kind == "password":
            return access.new_password(
                passwords.new_password(self.ctx, "New password for this file")
            )
        if token.kind == "keyfile":
            return access.new_key(keyfile.read(Path(token.value)).key)
        session = self.vault()
        if token.kind == "recovery":
            entry, _ = vaults.choose_recovery(self.ctx, session)
        else:
            entry = entries.find(session.document, token.value)
        session.record("encrypt", entry.id)
        return entries.factor(session.document, entry.label)

    def save(self) -> fs.NotDurable | None:
        """Write the vault, if it was opened, and release it. Called before
        the output is published: an unused entry, or an `encrypt` event for
        an output that then failed, is safe, but an output that only a lost
        entry opens is not. Nothing more is recorded after this."""
        if self.session is None:
            return None
        return durably(self.stack.close)

    def policy(
        self, grants: Sequence[Sequence[specs.Token]]
    ) -> list[list[access.NewFactor]]:
        return [[self.factor(t) for t in grant] for grant in grants]

    def profile(self, name: str) -> list[list[access.NewFactor]]:
        session = self.vault()
        policy = profiles.apply(
            session.document,
            name,
            lambda: passwords.new_password(self.ctx, "New password for this file"),
        )
        for grant in profiles.find(session.document, name).grants:
            for ref in grant:
                if ref.entry is not None:
                    session.record("encrypt", ref.entry)
        return policy


@dataclass(frozen=True)
class Choice:
    """How a new file unlocks (CLI.md section 3.1): one of a profile, a
    vault entry or grant specs, plus `--recovery-code`. With none of them,
    the default profile, or else a typed password."""

    grant_specs: Sequence[str] = ()
    vault_label: str | None = None
    profile: str | None = None
    recovery_code: bool = False


@contextmanager
def policy(
    ctx: Context, choice: Choice, settings_path: Path | None = None
) -> Iterator[list[list[access.NewFactor]]]:
    """The grants a new file gets. The vault, if used, is written, and a new
    recovery code shown, before the block runs (see `Builder.save`)."""
    picked = [x for x in (choice.grant_specs, choice.vault_label, choice.profile) if x]
    if len(picked) > 1:
        raise InputError("Use only one of --profile, --vault and --grant.")
    with ExitStack() as stack:
        build = Builder(ctx, stack)
        tokens: list[tuple[specs.Token, ...]] = []
        result: list[list[access.NewFactor]] = []
        if choice.grant_specs:
            tokens = specs.parse_grants(choice.grant_specs)
        elif choice.vault_label:
            tokens = [(specs.Token("vault", choice.vault_label),)]
        else:
            name = choice.profile or settings.load(settings_path).default_profile
            if name:
                result = build.profile(name)
            else:
                tokens = [(specs.Token("password"),)]
        if choice.recovery_code:
            tokens.append((specs.Token("recovery"),))
        if len(result) + len(tokens) > access.MAX_GRANTS:
            raise InputError(f"A file has at most {access.MAX_GRANTS} grants.")
        result += build.policy(tokens)
        check_policy(result)
        late = build.save()
        yield result
        if late is not None:
            raise late


def check_policy(policy: Sequence[Sequence[access.NewFactor]]) -> None:
    for grant in policy:
        encodings = [f.factor.encoding for f in grant]
        if len(set(encodings)) != len(encodings):
            raise InputError(
                "A grant names the same factor twice, such as two key files "
                "holding the same key."
            )


# --- encrypt -----------------------------------------------------------------------


def encrypt(
    ctx: Context,
    source: Readable,
    output: Output,
    choice: Choice | None = None,
    *,
    armored: bool = False,
    force: bool = False,
    settings_path: Path | None = None,
) -> int:
    """`ssc encrypt`. Returns the plaintext size."""
    _refuse_existing(output, force)
    with policy(ctx, choice or Choice(), settings_path) as chosen:
        size = 0

        def write(out: BinaryIO) -> None:
            nonlocal size
            size = container.encrypt(source, out, chosen, armored=armored)

        late = _write(output, force, write)
    if late is not None:
        raise late
    return size


# --- decrypt -----------------------------------------------------------------------


def _kinds(header: container.Header) -> set[int]:
    return {f.kind for g in header.grants if g.factors for f in g.factors}


def _max_passwords(header: container.Header) -> int:
    counts = [
        sum(f.kind in (access.PASSWORD, access.VAULT_PASSWORD) for f in g.factors)
        for g in header.grants
        if g.factors
    ]
    return max(counts, default=0)


@dataclass
class Opener:
    """Gathers what can open a file, asking only for what is still missing
    (CLI.md section 3.1).

    The vault is read and released at once, so its lock is not held while
    a payload streams; `record` opens it again briefly, the same way, to
    record history."""

    ctx: Context
    header: container.Header
    document: doc.Document | None = None  # what the vault held when read
    vault_ctx: Context | None = None  # how it was unlocked, to open it again
    asked_master: bool = False
    asked_recovery: bool = False
    asked_passwords: int = 0
    asked_keys: int = 0

    def __post_init__(self) -> None:
        self.passwords = list(self.ctx.passwords)
        self.codes = [recovery.decode(c) for c in self.ctx.recovery_codes]
        self.keys = [keyfile.read(p).key for p in self.ctx.key_files]
        kinds = _kinds(self.header)
        self.vault_may_help = vaults.exists(self.ctx) and bool(
            kinds & {access.VAULT_PASSWORD, access.KEY, access.RECOVERY}
        )
        if self.vault_may_help:
            self._read_vault(self.ctx)

    def _read_vault(self, ctx: Context) -> None:
        """Read the vault without asking. If it cannot be read, say why and
        go on: the file may open another way."""
        try:
            with vaults.edit(ctx, ask=False) as session:
                document = session.document
        except vaults.Locked:
            return  # the master password stays an option
        except CannotOpen:
            self.ctx.prompter.notice("That master password did not open the vault.")
            return
        except SSCError as error:  # damaged, or in use by another ssc
            self.ctx.prompter.notice(f"{error} Trying without the vault.")
            return
        except OSError as error:  # unreadable vault, keychain or lock file
            reason = error.strerror or type(error).__name__
            self.ctx.prompter.notice(
                f"The vault could not be read ({reason}). Trying without it."
            )
            return
        # Kept only once the session has closed cleanly, its own history
        # write included, so a failed read leaves no half-opened vault.
        self.document, self.vault_ctx = document, ctx

    def credentials(self) -> access.Credentials:
        vault = (
            entries.credentials(self.document)
            if self.document
            else access.Credentials()
        )
        return access.Credentials(
            passwords=self.passwords,
            entry_passwords=vault.entry_passwords,
            keys=[*self.keys, *vault.keys],
            recovery_codes=[*self.codes, *vault.recovery_codes],
        )

    def attempt(self) -> tuple[bytes, int] | None:
        header = self.header
        try:
            return access.open_grant(
                header.grants,
                header.fixed.to_bytes(),
                header.access_body,
                header.access_mac,
                self.credentials(),
            )
        except CannotOpen:
            return None

    def options(self) -> list[tuple[str, Callable[[], None]]]:
        kinds = _kinds(self.header)
        found: list[tuple[str, Callable[[], None]]] = []
        if self.vault_may_help and self.document is None and not self.asked_master:
            found.append(("your vault's master password", self.unlock_vault))
        if kinds & {
            access.PASSWORD,
            access.VAULT_PASSWORD,
        } and self.asked_passwords < _max_passwords(self.header):
            found.append(("your password", self.ask_password))
        if access.RECOVERY in kinds and not self.asked_recovery:
            found.append(("a recovery code", self.ask_recovery))
        named = self.named_keys()
        # Asked at most once per key the file names, a fixed bound, and only
        # while one is still missing: an all-of grant may need several.
        if (
            self.ctx.ask_key_file is not None
            and self.asked_keys < len(named)
            and named - self.keys_held()
        ):
            found.append(("a key file", self.ask_key))
        return found

    def named_keys(self) -> set[bytes]:
        """The key_ids of the file's key factors."""
        return {
            f.body
            for g in self.header.grants
            for f in g.factors or ()
            if f.kind == access.KEY
        }

    def keys_held(self) -> set[bytes]:
        return {access.key_id(k) for k in self.credentials().keys}

    def ask_key(self) -> None:
        assert self.ctx.ask_key_file is not None
        self.asked_keys += 1
        self.keys.append(keyfile.read(self.ctx.ask_key_file()).key)

    def unlock_vault(self) -> None:
        """Always asks: a supplied master password has already failed."""
        self.asked_master = True
        typed = self.ctx.prompter.secret("Vault master password")
        self._read_vault(dataclasses.replace(self.ctx, master_password=typed))

    def ask_password(self) -> None:
        self.asked_passwords += 1
        self.passwords.append(self.ctx.prompter.secret("Password for this file"))

    def ask_recovery(self) -> None:
        self.asked_recovery = True
        self.codes.append(recovery.decode(self.ctx.prompter.secret("Recovery code")))

    def open(self) -> tuple[bytes, int]:
        while (opened := self.attempt()) is None:
            options = self.options()
            if not options:
                raise CannotOpen()
            try:
                pick = (
                    0
                    if len(options) == 1
                    else self.ctx.prompter.choose(
                        "How do you want to open it?", [o[0] for o in options]
                    )
                )
                options[pick][1]()
            except InputError:
                # Nothing more can be asked. If the caller supplied
                # credentials, they were wrong (exit 2); if not, the error
                # says what to supply (exit 1). CLI.md section 1.
                if self.supplied():
                    raise CannotOpen() from None
                raise
        return opened

    def supplied(self) -> bool:
        ctx = self.ctx
        return bool(
            ctx.passwords or ctx.recovery_codes or ctx.key_files or ctx.master_password
        )

    def builder(self, stack: ExitStack) -> Builder:
        """A Builder that unlocks the vault the way this opener did."""
        return Builder(self.vault_ctx or self.ctx, stack)

    def record(self, index: int) -> None:
        """Record `decrypt` with each vault entry the opening grant used,
        as encrypting does, in a short session of its own. Only with
        history on."""
        if self.document is None or self.document.history is None:
            return
        assert self.vault_ctx is not None
        grant = self.header.grants[index]
        used = _entries_in(self.document, grant)
        if (code := self._recovery_in(grant)) is not None:
            used.append(code)
        if used:
            with vaults.edit(self.vault_ctx, ask=False) as session:
                for entry in used:
                    session.record("decrypt", entry.id)

    def _recovery_in(self, grant: access.Grant) -> doc.Entry | None:
        """The vault recovery entry that filled `grant`'s recovery factor:
        one search, sharing Argon2id work, with each entry's code tried for
        that factor alone."""
        assert self.document is not None
        factors = grant.factors or ()
        held = [
            (e, e.secret)
            for e in self.document.entries
            if e.kind == "recovery"
            and e.status != "revoked"
            and isinstance(e.secret, bytes)
        ]
        if not held or not any(f.kind == access.RECOVERY for f in factors):
            return None
        each = [access.Credentials(recovery_codes=[r]) for _, r in held]
        rest = [self.credentials()]
        header = self.header
        try:
            picked = access.find_assignment(
                grant,
                [each if f.kind == access.RECOVERY else rest for f in factors],
                header.fixed.to_bytes(),
                header.access_body,
                header.access_mac,
            )
        except CannotOpen:
            return None
        first = next(
            k for f, k in zip(factors, picked, strict=True) if f.kind == access.RECOVERY
        )
        return held[first][0]


def _entries_in(document: doc.Document, grant: access.Grant) -> list[doc.Entry]:
    """The vault password and key entries `grant` names, in factor order.
    Recovery entries name nothing, so `Opener._recovery_in` finds those."""
    found: list[doc.Entry] = []
    for factor in grant.factors or ():
        for entry in document.entries:
            if entry.status == "revoked" or entry in found:
                continue
            if (
                factor.kind == access.VAULT_PASSWORD and entry.id == factor.entry_id
            ) or (
                factor.kind == access.KEY
                and isinstance(entry.secret, bytes)
                and entry.kind == "key"
                and access.key_id(entry.secret) == factor.body
            ):
                found.append(entry)
                break
    return found


@dataclass
class Opening:
    """A file whose key has been found, before any plaintext is written:
    the interactive mode says how it opened, then asks where to write."""

    header: container.Header
    stream: Readable
    file_key: bytes
    index: int
    opener: Opener

    @property
    def grant(self) -> access.Grant:
        return self.header.grants[self.index]

    def asked(self) -> bool:
        """Whether anything was typed to open it."""
        o = self.opener
        return bool(
            o.asked_master or o.asked_recovery or o.asked_passwords or o.asked_keys
        )


def open_file(ctx: Context, source: Readable) -> Opening:
    """Find the file key, asking only for what is missing."""
    stream, _ = container.binary_stream(source)
    header = container.read_header(stream)
    opener = Opener(ctx, header)
    file_key, index = opener.open()
    return Opening(header, stream, file_key, index, opener)


def write_plaintext(opening: Opening, output: Output, *, force: bool = False) -> int:
    """Decrypt an opened file. Returns the plaintext size. To a path, the
    output appears only once the file has fully authenticated; to a stream,
    nothing is written until then."""
    _refuse_existing(output, force)
    key = payload.payload_key(opening.file_key, opening.header.fixed)
    stream = opening.stream
    size = 0
    late = None
    if isinstance(output, Path):

        def write(out: BinaryIO) -> None:
            nonlocal size
            size = payload.decrypt(key, stream, out)

        late = _write(output, force, write)
    else:
        # Held back until authenticated: in memory up to 64 MiB, then in an
        # owner-only temporary file the OS deletes when it is closed.
        with tempfile.SpooledTemporaryFile(max_size=HOLD_IN_MEMORY) as held:
            size = payload.decrypt(key, stream, held)
            _release(held, output)
    opening.opener.record(opening.index)
    if late is not None:
        raise late
    return size


def decrypt(
    ctx: Context, source: Readable, output: Output, *, force: bool = False
) -> int:
    """`ssc decrypt`: `open_file`, then `write_plaintext`. An existing output
    is refused before anything is asked."""
    _refuse_existing(output, force)
    return write_plaintext(open_file(ctx, source), output, force=force)
