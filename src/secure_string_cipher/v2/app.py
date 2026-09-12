"""Reusable application logic for v2 credentials and managed-key policy.

This layer exists so that more than one interface can perform v2
encrypt/decrypt correctly. The same logic previously lived in
``cli_args.py`` as private helpers that called ``sys.exit`` and ``getpass``
directly, which made it unusable from anywhere else: a second surface
calling the key-status check would have terminated the process instead of
reporting an error, and would have blocked on a terminal prompt.

Nothing here performs interactive input or exits the process. Callers supply
credentials and receive either a value or a typed exception, and decide for
themselves how to prompt, render and exit.

Deliberately *not* included: obtaining a password. Where a password comes
from — a prompt, a vault entry, a file, an environment variable — is an
interface concern, so it stays with the caller. This module only says which
credential an object requires and assembles one from parts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from secure_string_cipher.v2.encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    V2Credential,
)
from secure_string_cipher.v2.envelope import GrantType, V2Header
from secure_string_cipher.v2.key_identity import KeyStatus
from secure_string_cipher.v2.keyfile import KeyFileData, load_keyfile
from secure_string_cipher.v2.vault_service import V2VaultService

__all__ = [
    "CredentialRequirement",
    "GrantRequirement",
    "KeyDirectoryUnreadable",
    "KeyResolver",
    "KeyStatusPolicy",
    "KeyFileNotFound",
    "KeyFileUnreadable",
    "KeyStatusRejected",
    "MalformedContainer",
    "NoUsableGrant",
    "V2AppError",
    "VaultUnlockFailed",
    "build_credential",
    "default_keys_dir",
    "header_from_armour",
    "required_credential",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class V2AppError(Exception):
    """Base class for a v2 application-layer failure."""


class KeyFileNotFound(V2AppError):
    """No `.ssckey` matched the supplied reference."""

    def __init__(self, key_ref: str, keys_dir: Path):
        self.key_ref = key_ref
        self.keys_dir = keys_dir
        super().__init__(
            f"Key not found: provide a .ssckey path or a fingerprint/key-id "
            f"present in {keys_dir}."
        )


class KeyFileUnreadable(V2AppError):
    """A `.ssckey` was located but could not be loaded or validated."""

    def __init__(self, path: Path, cause: BaseException):
        self.path = path
        self.cause = cause
        super().__init__(f"Could not load key file: {path}")


class KeyDirectoryUnreadable(V2AppError):
    """The keys directory exists but could not be searched.

    Distinct from `KeyFileNotFound`: the reference may well have matched, but
    the directory could not be read to find out. Reporting "not found" for an
    unreadable directory would send the caller looking for the wrong problem.
    """

    def __init__(self, keys_dir: Path, cause: BaseException):
        self.keys_dir = keys_dir
        self.cause = cause
        super().__init__(f"Could not search the keys directory: {keys_dir}")


class KeyStatusRejected(V2AppError):
    """The vault tracks this key and marks it unusable."""

    def __init__(self, key_id: str, status: KeyStatus):
        self.key_id = key_id
        self.status = status
        verb = (
            "is revoked in" if status == KeyStatus.REVOKED else "has been destroyed in"
        )
        super().__init__(f"Key '{key_id}' {verb} this vault; refusing to use it.")


class VaultUnlockFailed(V2AppError):
    """The vault could not be opened to read key status."""

    def __init__(self, cause: BaseException | None = None):
        self.cause = cause
        super().__init__("Could not unlock vault to check key status.")


class NoUsableGrant(V2AppError):
    """The header carries no grant this implementation can satisfy."""

    def __init__(self) -> None:
        super().__init__("No usable access grant found in V2 header.")


class MalformedContainer(V2AppError):
    """The input is not a well-formed v2 container."""

    def __init__(self, cause: BaseException | None = None):
        self.cause = cause
        super().__init__("Not a valid V2 container.")


# ---------------------------------------------------------------------------
# What a container requires
# ---------------------------------------------------------------------------


class CredentialRequirement(Enum):
    """The credential an object's single grant requires."""

    PASSWORD = "password"  # pragma: allowlist secret - grant type name
    MANAGED_KEY = "managed-key"
    COMBINED = "combined-password-managed-key"


@dataclass(frozen=True)
class GrantRequirement:
    """What a caller must supply to open a particular object.

    `key_fingerprint` is the fingerprint the grant names, present whenever a
    managed key is involved. A caller may resolve a different keyfile than
    the named one (the CLI's `--key-file` does this), but the fingerprint
    recorded in the grant is what the DEK was wrapped against.
    """

    requirement: CredentialRequirement
    key_fingerprint: str | None = None

    @property
    def needs_password(self) -> bool:
        return self.requirement in (
            CredentialRequirement.PASSWORD,
            CredentialRequirement.COMBINED,
        )

    @property
    def needs_managed_key(self) -> bool:
        return self.requirement in (
            CredentialRequirement.MANAGED_KEY,
            CredentialRequirement.COMBINED,
        )


def header_from_armour(armoured_text: str) -> V2Header:
    """Extract and validate the protected header from an armoured message.

    An armoured message carries its header as Base64'd canonical JSON rather
    than the binary `SSC2` framing that `parse_header_stream` reads, so a
    caller inspecting a text container before choosing a credential needs
    this rather than the file path. Raises `MalformedContainer`, deliberately
    without detail: the caller is about to decide whether to attempt
    decryption, and a parse failure should not describe the input back.
    """
    import base64
    import json

    from secure_string_cipher.v2.header_parser import validate_v2_header
    from secure_string_cipher.v2.message import unarmor_message
    from secure_string_cipher.v2.vault_schema import _reject_duplicate_object_hook

    try:
        parsed = unarmor_message(armoured_text)
        raw_bytes = base64.b64decode(parsed.header_b64, validate=True)
        header_dict = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_hook,
        )
        return validate_v2_header(header_dict, raw_bytes)
    except Exception as error:
        raise MalformedContainer(error) from error


def required_credential(header: V2Header) -> GrantRequirement:
    """Report what the header's grant requires. Pure; performs no I/O.

    Raises `NoUsableGrant` when the grant type is not one this version can
    satisfy. A v2 object always carries exactly one grant
    (`AccessPolicy.SINGLE_GRANT`, enforced in envelope.py), so this inspects
    that grant rather than searching for a satisfiable one among several.
    """
    grants = header.access.grants
    if not grants:
        raise NoUsableGrant
    grant = grants[0]

    if grant.type == GrantType.PASSWORD:
        return GrantRequirement(CredentialRequirement.PASSWORD)

    if grant.type == GrantType.MANAGED_KEY:
        if not grant.key_fingerprint:
            raise NoUsableGrant
        return GrantRequirement(
            CredentialRequirement.MANAGED_KEY, grant.key_fingerprint
        )

    if grant.type == GrantType.COMBINED_PASSWORD_MANAGED_KEY:
        if not grant.key_fingerprint:
            raise NoUsableGrant
        return GrantRequirement(CredentialRequirement.COMBINED, grant.key_fingerprint)

    raise NoUsableGrant


# ---------------------------------------------------------------------------
# Locating a managed key
# ---------------------------------------------------------------------------


def default_keys_dir() -> Path:
    """The conventional location for managed keyfiles.

    Resolved on each call rather than captured at import time, so that a
    caller (or a test) which redirects the home directory is honoured.
    """
    return Path.home() / ".ssc" / "keys"


class KeyResolver:
    """Turns a key reference into validated keyfile data.

    A reference is either a path to a `.ssckey` file or a fingerprint/key-id
    belonging to a keyfile in `keys_dir`. Both encryption (`key:ID` sources)
    and decryption (a grant's recorded fingerprint) use this, so the two
    sides cannot drift apart in how they interpret a reference.
    """

    def __init__(self, keys_dir: Path | None = None):
        self._keys_dir = keys_dir

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir if self._keys_dir is not None else default_keys_dir()

    def resolve(self, key_ref: str) -> KeyFileData:
        """Locate and load the keyfile `key_ref` names.

        Raises `KeyFileUnreadable` if a path was clearly intended but could
        not be loaded, and `KeyFileNotFound` if nothing matched.
        """
        candidate = Path(key_ref).expanduser()
        if candidate.suffix == ".ssckey" or candidate.is_file():
            try:
                return load_keyfile(candidate)
            except Exception as error:
                raise KeyFileUnreadable(candidate, error) from error

        keys_dir = self.keys_dir
        if keys_dir.is_dir():
            try:
                children = sorted(keys_dir.iterdir())
            except OSError as error:
                # An unreadable directory, or one removed between the is_dir
                # check and the listing, would otherwise raise a bare
                # PermissionError/OSError straight past the V2AppError
                # hierarchy this module advertises.
                raise KeyDirectoryUnreadable(keys_dir, error) from error

            for child in children:
                if child.suffix != ".ssckey":
                    continue
                try:
                    key_data = load_keyfile(child)
                except Exception:
                    # A single unreadable or malformed keyfile in the
                    # directory must not stop the search; the reference may
                    # well name one of the others.
                    continue
                if key_ref in (key_data.fingerprint, key_data.key_id):
                    return key_data

        raise KeyFileNotFound(key_ref, keys_dir)


# ---------------------------------------------------------------------------
# Lifecycle policy
# ---------------------------------------------------------------------------


class KeyStatusPolicy:
    """Refuses a managed key this vault marks revoked or destroyed.

    Holding a `.ssckey` file is sufficient to use the key it contains, so
    ordinary encrypt/decrypt reads the file straight off disk and never
    consults the vault. That is inherent to a bearer secret, not a defect.
    This check exists for the case where a caller *is* willing to open the
    vault: it then refuses a key that vault records as revoked or destroyed.

    A key the vault does not track cannot be checked and is allowed through.
    `ARCHIVED` is bookkeeping only and never blocks use.
    """

    def __init__(self, service: V2VaultService):
        self._service = service

    def check(self, fingerprint: str, *, master_password: str) -> None:
        """Raise if the vault marks `fingerprint` unusable.

        Raises `VaultUnlockFailed` if the vault cannot be read, and
        `KeyStatusRejected` if it records the key as revoked or destroyed.
        """
        try:
            records = self._service.list_keys(master_password)
        except Exception as error:
            raise VaultUnlockFailed(error) from error

        for record in records:
            if record.fingerprint != fingerprint:
                continue
            if record.status in (KeyStatus.REVOKED, KeyStatus.DESTROYED):
                raise KeyStatusRejected(record.id, record.status)
            return


# ---------------------------------------------------------------------------
# Assembling a credential
# ---------------------------------------------------------------------------


def build_credential(
    requirement: GrantRequirement,
    *,
    password: str | None = None,
    key_data: KeyFileData | None = None,
) -> V2Credential:
    """Assemble the credential `requirement` describes from supplied parts.

    The fingerprint recorded in the grant is used rather than the resolved
    keyfile's own, so that a caller who pointed at a different file still
    produces a credential naming what the DEK was wrapped against — and the
    resulting mismatch surfaces as an authentication failure rather than
    silently succeeding against the wrong identity.
    """
    if requirement.needs_password and password is None:
        raise ValueError("this grant requires a password")
    if requirement.needs_managed_key and key_data is None:
        raise ValueError("this grant requires a managed key")

    if requirement.requirement == CredentialRequirement.PASSWORD:
        assert password is not None
        return PasswordCredential(passphrase=password)

    fingerprint = requirement.key_fingerprint
    if not fingerprint:
        raise NoUsableGrant
    assert key_data is not None

    if requirement.requirement == CredentialRequirement.MANAGED_KEY:
        return KeyCredential(
            key_fingerprint=fingerprint, managed_secret=key_data.secret_bytes
        )

    assert password is not None
    return CombinedCredential(
        passphrase=password,
        key_fingerprint=fingerprint,
        managed_secret=key_data.secret_bytes,
    )
