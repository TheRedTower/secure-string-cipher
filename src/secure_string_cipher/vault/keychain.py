"""Unlocking the vault with this device's key, held in the OS keychain
(VAULT.md section 2).

The keychain holds only the 32-byte device key, never the vault. Its item
has service `ssc` and account `vault-unlock:<key_id hex>`; a reader finds it
from the key factors it sees in the vault file, so the vault needs no ID of
its own. Where there is no OS keychain (headless Linux, Docker), SSC asks for
the master password, and never keeps the key in a plain file instead.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import io
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

import keyring
from keyring.backend import KeyringBackend
from keyring.backends.chainer import ChainerBackend

from secure_string_cipher.engine import access, container
from secure_string_cipher.errors import VaultError
from secure_string_cipher.vault import store
from secure_string_cipher.vault.document import b64

SERVICE = "ssc"
ACCOUNT_PREFIX = "vault-unlock:"
# Only the OS keychains VAULT.md section 1 names: macOS Keychain, Windows
# Credential Manager and Linux Secret Service. Never a plain-file backend.
OS_BACKENDS = (
    "keyring.backends.macOS",
    "keyring.backends.Windows",
    "keyring.backends.SecretService",
)


# Keychain backends do not always wrap their own failures in KeyringError:
# Secret Service can raise SecretStorageException or a D-Bus error directly.
# At this boundary, any failure from the backend counts as the keychain
# being unavailable for that operation.
_BACKEND_ERRORS = (Exception,)


class Keychain(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...
    def delete_password(self, service: str, username: str) -> None: ...


def account(key_id: bytes) -> str:
    return ACCOUNT_PREFIX + key_id.hex()


def os_keychain() -> Keychain | None:
    """The OS keychain, or None where there is none."""
    try:
        backend: KeyringBackend = keyring.get_keyring()
    except Exception:
        return None
    candidates = backend.backends if isinstance(backend, ChainerBackend) else [backend]
    for candidate in candidates:
        if type(candidate).__module__ in OS_BACKENDS:
            return candidate
    return None


def _required(chain: Keychain | None) -> Keychain:
    chain = os_keychain() if chain is None else chain
    if chain is None:
        raise VaultError(
            "No OS keychain is available here, so this device cannot hold a "
            "vault key. Use the master password instead."
        )
    return chain


def device_key_id(grant: access.Grant) -> bytes | None:
    """The `key_id` of a device-key grant (a single key factor), else None."""
    factors = grant.factors
    if factors is not None and len(factors) == 1 and factors[0].kind == access.KEY:
        return factors[0].body
    return None


def _lookup(chain: Keychain, key_id: bytes) -> bytes | None:
    """The device key stored for `key_id`, if this keychain has a sound one."""
    try:
        text = chain.get_password(SERVICE, account(key_id))
    except _BACKEND_ERRORS:
        return None
    if text is None:
        return None
    try:
        key = base64.urlsafe_b64decode(text + "=")
    except (binascii.Error, ValueError):
        return None
    if len(key) != access.KEY_SIZE or access.key_id(key) != key_id:
        return None
    return key


def device_keys(
    grants: Sequence[access.Grant], chain: Keychain | None = None
) -> list[bytes]:
    """The keys this device's keychain holds for the vault's device grants.
    Empty where there is no keychain, so the caller asks for the master
    password."""
    chain = os_keychain() if chain is None else chain
    if chain is None:
        return []
    found = []
    for grant in grants:
        key_id = device_key_id(grant)
        key = None if key_id is None else _lookup(chain, key_id)
        if key is not None:
            found.append(key)
    return found


def credentials(
    path: Path | None = None, chain: Keychain | None = None
) -> access.Credentials:
    """Credentials that unlock the vault at `path` with this device, read
    from the grants in its header. Reading the header needs no secret."""
    path = store.default_path() if path is None else path
    stream, _ = container.binary_stream(io.BytesIO(store.read_file(path)))
    grants = container.read_header(stream).grants
    return access.Credentials(keys=device_keys(grants, chain))


def this_device(session: store.Session, chain: Keychain | None = None) -> int | None:
    """The index of this device's grant, if it has one."""
    chain = os_keychain() if chain is None else chain
    if chain is None:
        return None
    for index, grant in enumerate(session.grants):
        key_id = device_key_id(grant)
        if key_id is not None and _lookup(chain, key_id) is not None:
            return index
    return None


def add_device(session: store.Session, chain: Keychain | None = None) -> int:
    """Add a device-key grant for this device and store its key in the
    keychain. If the vault is then not written, the keychain item is
    removed again. Returns the new grant's index."""
    chain = _required(chain)
    if this_device(session, chain) is not None:
        raise VaultError("This device can already unlock the vault.")
    key = secrets.token_bytes(access.KEY_SIZE)
    name = account(access.key_id(key))
    index = session.add_grant([access.new_key(key)])
    try:
        chain.set_password(SERVICE, name, b64(key))
    except _BACKEND_ERRORS as error:
        session.grants.pop(index)
        raise VaultError(f"The keychain refused the vault key: {error}") from None

    def forget() -> None:
        with contextlib.suppress(*_BACKEND_ERRORS):
            chain.delete_password(SERVICE, name)

    session.on_abort.append(forget)
    return index


def remove_device(
    session: store.Session,
    index: int,
    chain: Keychain | None = None,
    *,
    forget: bool = True,
) -> None:
    """Remove the device grant at `index` (0-based). This is removal, not
    revocation: to lock a lost device out, rotate the vault. Once the vault
    is written, this keychain's item for that key is deleted if it has one,
    unless `forget` is False (the keychain is turned off)."""
    key_id = (
        device_key_id(session.grants[index])
        if 0 <= index < len(session.grants)
        else None
    )
    if key_id is None:
        raise VaultError(f"g{index + 1} is not a device key grant.")
    session.remove_grant(index)
    if not forget:
        return
    name = account(key_id)
    chain = os_keychain() if chain is None else chain
    if chain is None:
        return
    keychain = chain

    def delete() -> None:
        with contextlib.suppress(*_BACKEND_ERRORS):
            keychain.delete_password(SERVICE, name)

    session.after_write.append(delete)
