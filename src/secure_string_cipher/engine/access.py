"""The access layer (ACCESS.md): factors, grants and the access body.

Each grant is an all-of set of factors that wraps the file key once. A
file's grants together are any-of: any one grant opens it. The access MAC
(FORMAT.md section 4.4) confirms that a key recovered from a grant really is
this file's key, before any payload is decrypted.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import secrets
import struct
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_string_cipher.errors import CannotOpen, FormatError, Reason

PASSWORD = 0x01
VAULT_PASSWORD = 0x02
KEY = 0x03
RECOVERY = 0x04
BODY_SIZES = {PASSWORD: 25, VAULT_PASSWORD: 41, KEY: 16, RECOVERY: 0}

ARGON2_MEMORY_KIB = 65536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
ARGON2_PARAMS = struct.pack(">II", ARGON2_MEMORY_KIB, ARGON2_TIME_COST) + bytes(
    [ARGON2_PARALLELISM]
)

SALT_SIZE = 16
ENTRY_ID_SIZE = 16
KEY_SIZE = 32
KEY_ID_SIZE = 16
RECOVERY_SIZE = 18
SECRET_SIZE = 32
WRAPPED_SIZE = 48
MAX_FACTORS = 5
MAX_GRANTS = 16
MAX_ACCESS_BODY = 65536
_ZERO_NONCE = bytes(12)
# The smallest grant: salt, factor count, one empty-bodied factor, wrapped key.
_MIN_GRANT = SALT_SIZE + 1 + 1 + WRAPPED_SIZE


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt or None, info).derive(ikm)


def access_mac(file_key: bytes, fixed_header: bytes, access_body: bytes) -> bytes:
    """HMAC(mac_key, fixed_header || access_length || access_body)."""
    mac_key = _hkdf(file_key, b"", b"ssc3/access-mac")
    message = fixed_header + struct.pack(">I", len(access_body)) + access_body
    return hmac.digest(mac_key, message, "sha256")


# --- factors ---------------------------------------------------------------


@dataclass(frozen=True)
class Factor:
    """A factor as written in a grant: its type byte and its body."""

    kind: int
    body: bytes

    @property
    def encoding(self) -> bytes:
        return bytes([self.kind]) + self.body

    @property
    def salt(self) -> bytes:
        """The Argon2id salt of a password or vault password factor."""
        return self.body[-25:-9]

    @property
    def entry_id(self) -> bytes:
        """The vault entry a vault password factor names."""
        return self.body[:ENTRY_ID_SIZE]


@dataclass(frozen=True)
class NewFactor:
    """A factor being written, with its 32-byte factor secret."""

    factor: Factor
    secret: bytes = field(repr=False)


def password_secret(password: str, salt: bytes) -> bytes:
    """Argon2id over the NFC-normalised password (ACCESS.md section 2.1)."""
    if not password:
        raise ValueError("A password cannot be empty.")
    return hash_secret_raw(
        unicodedata.normalize("NFC", password).encode("utf-8"),
        salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=SECRET_SIZE,
        type=Type.ID,
        version=19,
    )


def new_password(password: str, *, salt: bytes | None = None) -> NewFactor:
    """A password factor. `salt` is for reproducing test vectors only."""
    salt = secrets.token_bytes(SALT_SIZE) if salt is None else salt
    factor = Factor(PASSWORD, salt + ARGON2_PARAMS)
    return NewFactor(factor, password_secret(password, salt))


def new_vault_password(
    entry_id: bytes, password: str, *, salt: bytes | None = None
) -> NewFactor:
    """A vault password entry factor (ACCESS.md section 2.1)."""
    if len(entry_id) != ENTRY_ID_SIZE:
        raise ValueError(f"entry_id must be {ENTRY_ID_SIZE} bytes")
    salt = secrets.token_bytes(SALT_SIZE) if salt is None else salt
    factor = Factor(VAULT_PASSWORD, entry_id + salt + ARGON2_PARAMS)
    return NewFactor(factor, password_secret(password, salt))


def key_id(key: bytes) -> bytes:
    """SHA-256("ssc3/key-id" || key)[0..16] (ACCESS.md section 2.2)."""
    return hashlib.sha256(b"ssc3/key-id" + key).digest()[:KEY_ID_SIZE]


def key_secret(key: bytes) -> bytes:
    return _hkdf(key, b"", b"ssc3/factor/key")


def new_key(key: bytes) -> NewFactor:
    """A key factor (ACCESS.md section 2.2)."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"A key must be {KEY_SIZE} bytes.")
    return NewFactor(Factor(KEY, key_id(key)), key_secret(key))


def recovery_secret(r: bytes) -> bytes:
    return _hkdf(r, b"", b"ssc3/factor/recovery-code")


def new_recovery(r: bytes) -> NewFactor:
    """A recovery code factor (ACCESS.md section 2.3) from its 18 random
    bytes. Its printed form belongs to the vault (Phase 3, step 4)."""
    if len(r) != RECOVERY_SIZE:
        raise ValueError(f"A recovery code is {RECOVERY_SIZE} bytes.")
    return NewFactor(Factor(RECOVERY, b""), recovery_secret(r))


# --- grants ----------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    """One grant: everything after its `grant_length` field.

    `factors` is None for a grant that holds a factor type this version does
    not know. Such a grant is kept byte for byte and never tried.
    """

    encoded: bytes
    factors: tuple[Factor, ...] | None

    @property
    def salt(self) -> bytes:
        return self.encoded[:SALT_SIZE]

    @property
    def descriptor(self) -> bytes:
        return self.encoded[:-WRAPPED_SIZE]

    @property
    def wrapped_key(self) -> bytes:
        return self.encoded[-WRAPPED_SIZE:]

    def to_bytes(self) -> bytes:
        return struct.pack(">H", len(self.encoded)) + self.encoded


def _kek(secrets_in_order: Sequence[bytes], salt: bytes, descriptor: bytes) -> bytes:
    return _hkdf(b"".join(secrets_in_order), salt, b"ssc3/grant-kek" + descriptor)


def new_grant(
    file_key: bytes, factors: Sequence[NewFactor], *, salt: bytes | None = None
) -> Grant:
    """Wrap `file_key` under a grant needing all of `factors`.

    A fresh `grant_salt` makes every grant key unique, which the all-zero
    wrapping nonce depends on (ACCESS.md section 3.3). `salt` is for
    reproducing test vectors only.
    """
    if not 1 <= len(factors) <= MAX_FACTORS:
        raise ValueError(f"A grant needs 1 to {MAX_FACTORS} factors.")
    ordered = sorted(factors, key=lambda f: f.factor.encoding)
    encodings = [f.factor.encoding for f in ordered]
    if len(set(encodings)) != len(encodings):
        raise ValueError("A grant cannot hold the same factor twice.")
    salt = secrets.token_bytes(SALT_SIZE) if salt is None else salt
    descriptor = salt + bytes([len(ordered)]) + b"".join(encodings)
    kek = _kek([f.secret for f in ordered], salt, descriptor)
    wrapped = AESGCM(kek).encrypt(_ZERO_NONCE, file_key, None)
    return Grant(descriptor + wrapped, tuple(f.factor for f in ordered))


def _parse_grant(encoded: bytes) -> Grant:
    end = len(encoded) - WRAPPED_SIZE
    count = encoded[SALT_SIZE]
    if not 1 <= count <= MAX_FACTORS:
        raise FormatError(Reason.FACTOR_COUNT, "A grant has too many or no factors.")
    pos = SALT_SIZE + 1
    factors: list[Factor] = []
    for _ in range(count):
        if pos >= end:
            raise FormatError(Reason.GRANT_LENGTH, "A grant's length is wrong.")
        kind = encoded[pos]
        size = BODY_SIZES.get(kind)
        if size is None:
            return Grant(encoded, None)
        if pos + 1 + size > end:
            raise FormatError(Reason.GRANT_LENGTH, "A grant's length is wrong.")
        body = encoded[pos + 1 : pos + 1 + size]
        if kind in (PASSWORD, VAULT_PASSWORD) and body[-9:] != ARGON2_PARAMS:
            raise FormatError(
                Reason.ARGON_PARAMS, "A password uses settings this SSC refuses."
            )
        factors.append(Factor(kind, body))
        pos += 1 + size
    if pos != end:
        raise FormatError(Reason.GRANT_LENGTH, "A grant's length is wrong.")
    encodings = [f.encoding for f in factors]
    if any(a >= b for a, b in itertools.pairwise(encodings)):
        raise FormatError(Reason.FACTOR_ORDER, "A grant's factors are not canonical.")
    return Grant(encoded, tuple(factors))


def parse_access_body(body: bytes) -> list[Grant]:
    """Parse the whole access body strictly (ACCESS.md sections 3.4 and 4)."""
    if not 1 <= len(body) <= MAX_ACCESS_BODY:
        raise FormatError(Reason.ACCESS_LENGTH, "The access block has a bad length.")
    count = body[0]
    if not 1 <= count <= MAX_GRANTS:
        raise FormatError(Reason.GRANT_COUNT, "A file must have 1 to 16 grants.")
    pos, grants = 1, []
    for _ in range(count):
        if pos + 2 > len(body):
            raise FormatError(
                Reason.ACCESS_BODY_LENGTH, "The access block ends too soon."
            )
        (length,) = struct.unpack(">H", body[pos : pos + 2])
        encoded = body[pos + 2 : pos + 2 + length]
        if len(encoded) != length or length < _MIN_GRANT:
            raise FormatError(Reason.GRANT_LENGTH, "A grant's length is wrong.")
        grants.append(_parse_grant(encoded))
        pos += 2 + length
    if pos != len(body):
        raise FormatError(
            Reason.ACCESS_BODY_LENGTH, "The access block has bytes after its grants."
        )
    return grants


def encode_access_body(grants: Sequence[Grant]) -> bytes:
    if not 1 <= len(grants) <= MAX_GRANTS:
        raise ValueError(f"A file must have 1 to {MAX_GRANTS} grants.")
    body = bytes([len(grants)]) + b"".join(g.to_bytes() for g in grants)
    if len(body) > MAX_ACCESS_BODY:
        raise ValueError("The access block would be too large.")
    return body


# --- opening ---------------------------------------------------------------


@dataclass(frozen=True)
class Credentials:
    """What the caller can supply to open a file.

    `passwords` are typed or supplied passwords. Each is tried against every
    password factor the vault cannot fill (CLI.md section 1).
    `entry_passwords` maps a vault entry ID to its stored password.
    `keys` are 32-byte keys, from the vault or from key files; each is used
    only for a factor whose `key_id` matches it.
    `recovery_codes` are the 18 random bytes of each recovery code; a
    recovery factor names no code, so each is tried (ACCESS.md section 2.3).
    """

    passwords: Sequence[str] = ()
    entry_passwords: Mapping[bytes, str] = field(default_factory=dict)
    keys: Sequence[bytes] = ()
    recovery_codes: Sequence[bytes] = ()


class _SecretCache:
    """Argon2id results for one open attempt, keyed on the password too
    (ACCESS.md section 4), so a corrected password is never served the
    secret of a mistyped one."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, bytes], bytes] = {}

    def password(self, password: str, salt: bytes) -> bytes:
        key = (password, salt)
        if key not in self._cache:
            self._cache[key] = password_secret(password, salt)
        return self._cache[key]


def _candidate_passwords(factor: Factor, credentials: Credentials) -> list[str]:
    if factor.kind == PASSWORD:
        return list(dict.fromkeys(credentials.passwords))
    stored = credentials.entry_passwords.get(factor.entry_id)
    first = [stored] if stored else []
    return list(dict.fromkeys([*first, *credentials.passwords]))


def _options(
    factor: Factor, credentials: Credentials, cache: _SecretCache
) -> list[Callable[[], bytes]]:
    """Ways to supply one factor's secret, each derived only when tried."""
    if factor.kind in (PASSWORD, VAULT_PASSWORD):
        return [
            partial(cache.password, pw, factor.salt)
            for pw in _candidate_passwords(factor, credentials)
        ]
    if factor.kind == KEY:
        matching = dict.fromkeys(
            k for k in credentials.keys if key_id(k) == factor.body
        )
        return [partial(key_secret, k) for k in matching]
    if factor.kind == RECOVERY:
        codes = dict.fromkeys(credentials.recovery_codes)
        return [partial(recovery_secret, r) for r in codes]
    return []


def _combinations(
    factors: Sequence[Factor], credentials: Credentials, cache: _SecretCache
) -> Iterator[list[bytes]]:
    options = [_options(f, credentials, cache) for f in factors]
    if not all(options):
        return  # some factor cannot be supplied: no work at all
    for choice in itertools.product(*options):
        yield [derive() for derive in choice]


def open_grant(
    grants: Sequence[Grant],
    fixed_header: bytes,
    access_body: bytes,
    mac: bytes,
    credentials: Credentials,
) -> tuple[bytes, int]:
    """Recover the file key from the first grant that the credentials open
    and that the access MAC confirms (ACCESS.md section 4), and that grant's
    index. The index is for the caller's own bookkeeping, such as history;
    a failure still says nothing about which grant or factor was wrong."""
    cache = _SecretCache()
    for index, grant in enumerate(grants):
        if grant.factors is None:
            continue
        for factor_secrets in _combinations(grant.factors, credentials, cache):
            kek = _kek(factor_secrets, grant.salt, grant.descriptor)
            try:
                candidate = AESGCM(kek).decrypt(_ZERO_NONCE, grant.wrapped_key, None)
            except InvalidTag:
                continue
            expected = access_mac(candidate, fixed_header, access_body)
            if hmac.compare_digest(expected, mac):
                return candidate, index
    raise CannotOpen()


def open_assigned(
    grant: Grant,
    assignment: Sequence[Credentials],
    fixed_header: bytes,
    access_body: bytes,
    mac: bytes,
) -> bytes:
    """Open one grant with `assignment[i]` supplying only factor `i`, and
    confirm the result against the access MAC.

    Unlike `open_grant`, which tries every supplied password against every
    password factor, this proves which secret fills which factor, so a
    caller can rebuild the grant faithfully (rotation).
    """
    if grant.factors is None or len(assignment) != len(grant.factors):
        raise CannotOpen()
    cache = _SecretCache()
    options = [
        _options(f, c, cache) for f, c in zip(grant.factors, assignment, strict=True)
    ]
    for choice in itertools.product(*options):
        kek = _kek([derive() for derive in choice], grant.salt, grant.descriptor)
        try:
            candidate = AESGCM(kek).decrypt(_ZERO_NONCE, grant.wrapped_key, None)
        except InvalidTag:
            continue
        if hmac.compare_digest(access_mac(candidate, fixed_header, access_body), mac):
            return candidate
    raise CannotOpen()


def open_file_key(
    grants: Sequence[Grant],
    fixed_header: bytes,
    access_body: bytes,
    mac: bytes,
    credentials: Credentials,
) -> bytes:
    """`open_grant`, for callers that need only the file key."""
    return open_grant(grants, fixed_header, access_body, mac, credentials)[0]
