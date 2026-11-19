"""The vault file (VAULT.md sections 1 and 2): an SSC file whose payload is
the vault document, opened by its own grants.

Every access holds `vault.ssc.lock` for the whole read, modify and write, so
two `ssc` processes cannot lose each other's changes. Writes go through a
temporary file renamed into place (FORMAT.md section 7.5).
"""

from __future__ import annotations

import dataclasses
import io
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import platformdirs

from secure_string_cipher import fs
from secure_string_cipher.engine import access, armor, container, payload
from secure_string_cipher.engine.header import SIZE as FIXED_HEADER_SIZE
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import FormatError, Reason, VaultError
from secure_string_cipher.vault import document as doc

NAME = "vault.ssc"
LOCK_TIMEOUT = 10.0


def max_file_size() -> int:
    """The largest file a vault document of at most MAX_SIZE can be: the
    header, the largest access block and the sealed chunks, then the same in
    armoured form with CRLF line endings."""
    chunks = doc.MAX_SIZE // payload.CHUNK_SIZE + 1
    binary = (
        FIXED_HEADER_SIZE
        + 4
        + access.MAX_ACCESS_BODY
        + container.MAC_SIZE
        + doc.MAX_SIZE
        + chunks * payload.TAG_SIZE
    )
    lines = -(-binary // 48)
    return (lines + 2) * (armor.LINE + 2) + len(armor.BEGIN) + len(armor.END)


def default_path() -> Path:
    """`vault.ssc` in the OS's standard user data folder."""
    return Path(platformdirs.user_data_dir("ssc", appauthor=False)) / NAME


def lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def _require(path: Path) -> None:
    if not path.exists():
        raise VaultError(f"There is no vault at {path}.")


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    try:
        with fs.locked(lock_path(path), timeout=LOCK_TIMEOUT):
            yield
    except fs.LockTimeout:
        raise VaultError("The vault is in use by another ssc process.") from None


def _is_master(grant: access.Grant) -> bool:
    """The master-password grant is the vault's one grant made of a single
    password factor (VAULT.md section 2)."""
    factors = grant.factors
    return (
        factors is not None and len(factors) == 1 and factors[0].kind == access.PASSWORD
    )


def _master_grant(file_key: bytes, password: str) -> access.Grant:
    return access.new_grant(file_key, [access.new_password(password)])


class _Bounded:
    """A sink that refuses more than the vault document's size limit."""

    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes, /) -> int:
        if len(self.data) + len(data) > doc.MAX_SIZE:
            raise FormatError(
                Reason.VAULT_DOCUMENT, "The vault document is over 16 MiB."
            )
        self.data += data
        return len(data)


def create(
    master_password: str,
    path: Path | None = None,
    document: doc.Document | None = None,
) -> None:
    """Create a vault opened by `master_password`. Refuses to replace one."""
    path = default_path() if path is None else path
    if not master_password:
        raise ValueError("A master password cannot be empty.")
    contents = doc.encode(doc.Document() if document is None else document)
    file_key = secrets.token_bytes(payload.FILE_KEY_SIZE)
    grants = [_master_grant(file_key, master_password)]
    fs.private_dir(path.parent)
    with _locked(path):
        if os.path.lexists(path):
            raise VaultError(f"There is already a vault at {path}.")
        fs.write_atomic(
            path,
            lambda out: container.seal(
                file_key, FixedHeader.new(), grants, io.BytesIO(contents), out
            ),
            replace=False,
        )


class Session:
    """An unlocked vault, held under the lock for one read, modify and write.

    Change `document` or the grants; leaving the `edit` block writes the
    vault once, and only if something changed.
    """

    def __init__(
        self,
        path: Path,
        opened: container.Opened,
        old_payload: bytes,
        document: doc.Document,
    ) -> None:
        self.path = path
        self.document = document
        self._opened = opened
        self._old_payload = old_payload
        self._old_document = document
        self.grants: list[access.Grant] = list(opened.header.grants)

    def _master_index(self) -> int:
        found = [i for i, g in enumerate(self.grants) if _is_master(g)]
        if len(found) != 1:
            raise VaultError("This vault does not have exactly one master password.")
        return found[0]

    def change_master_password(self, current: str, new: str) -> None:
        """Rewrap the master-password grant for `new` (VAULT.md section 2).
        The file key and every other grant stay byte for byte the same.
        `current` must open the master grant itself, even when the vault was
        unlocked some other way, such as with this device's key."""
        if not new:
            raise ValueError("A master password cannot be empty.")
        index = self._master_index()
        header = self._opened.header
        access.open_file_key(
            [self.grants[index]],
            header.fixed.to_bytes(),
            header.access_body,
            header.access_mac,
            access.Credentials(passwords=[current]),
        )
        self.grants[index] = _master_grant(self._opened.file_key, new)

    def _write(self) -> None:
        document_changed = self.document != self._old_document
        if not document_changed and self.grants == list(self._opened.header.grants):
            return
        if document_changed:
            # FORMAT.md section 7.4: same file key, fresh payload nonce.
            contents = doc.encode(self.document)

            def write(out: payload.Writable) -> None:
                container.replace_payload(
                    self._opened, io.BytesIO(contents), out, self.grants
                )

        else:
            # Only the access block changes; the payload bytes are kept.
            kept = dataclasses.replace(
                self._opened, payload=io.BytesIO(self._old_payload)
            )

            def write(out: payload.Writable) -> None:
                container.rewrite_access(kept, self.grants, out)

        fs.write_atomic(self.path, write, replace=True)


def _read(path: Path, credentials: access.Credentials) -> Session:
    limit = max_file_size()
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except FileNotFoundError:
        raise VaultError(f"There is no vault at {path}.") from None
    if len(data) > limit:
        raise FormatError(
            Reason.VAULT_DOCUMENT, "The vault file is larger than any vault can be."
        )
    opened = container.unlock(io.BytesIO(data), credentials)
    old_payload = b"".join(iter(lambda: opened.payload.read(1 << 16), b""))
    sink = _Bounded()
    key = payload.payload_key(opened.file_key, opened.header.fixed)
    payload.decrypt(key, io.BytesIO(old_payload), sink)
    return Session(path, opened, old_payload, doc.parse(bytes(sink.data)))


def load(credentials: access.Credentials, path: Path | None = None) -> doc.Document:
    """Open the vault and return its document."""
    path = default_path() if path is None else path
    _require(path)
    with _locked(path):
        return _read(path, credentials).document


@contextmanager
def edit(
    credentials: access.Credentials, path: Path | None = None
) -> Iterator[Session]:
    """Open the vault for one change. The vault is written when the block
    ends without an error, and left untouched if it raises."""
    path = default_path() if path is None else path
    _require(path)
    with _locked(path):
        session = _read(path, credentials)
        yield session
        session._write()
