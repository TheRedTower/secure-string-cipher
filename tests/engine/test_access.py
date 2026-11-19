"""Unit tests for the access layer, the armoured form and the container."""

from __future__ import annotations

import io
import secrets
import unicodedata

import pytest

from secure_string_cipher.engine import access, armor, container
from secure_string_cipher.errors import CannotOpen, FormatError, Reason

FILE_KEY = bytes(range(32))
HEADER = bytes(25)


@pytest.fixture(scope="module")
def pw() -> access.NewFactor:
    return access.new_password("hunter2")


@pytest.fixture(scope="module")
def pw2() -> access.NewFactor:
    return access.new_password("second")


def body_and_mac(*grants: access.Grant) -> tuple[bytes, bytes]:
    body = access.encode_access_body(grants)
    return body, access.access_mac(FILE_KEY, HEADER, body)


def open_with(grants: list[access.Grant], **creds: object) -> bytes:
    body, mac = body_and_mac(*grants)
    parsed = access.parse_access_body(body)
    return access.open_file_key(
        parsed,
        HEADER,
        body,
        mac,
        access.Credentials(**creds),  # type: ignore[arg-type]
    )


# --- factors and grants ------------------------------------------------------


def test_empty_password_is_refused() -> None:
    with pytest.raises(ValueError):
        access.new_password("")


def test_password_is_nfc_normalised() -> None:
    salt = bytes(16)
    nfd = unicodedata.normalize("NFD", "pássword")
    assert access.password_secret(nfd, salt) == access.password_secret("pássword", salt)


def test_vault_password_needs_a_16_byte_entry_id() -> None:
    with pytest.raises(ValueError):
        access.new_vault_password(b"short", "x")


def test_grant_sorts_its_factors(pw: access.NewFactor, pw2: access.NewFactor) -> None:
    a = access.new_grant(FILE_KEY, [pw, pw2], salt=bytes(16))
    b = access.new_grant(FILE_KEY, [pw2, pw], salt=bytes(16))
    assert a == b
    assert a.factors is not None
    encodings = [f.encoding for f in a.factors]
    assert encodings == sorted(encodings)


def test_grant_refuses_duplicates_and_bad_counts(pw: access.NewFactor) -> None:
    with pytest.raises(ValueError):
        access.new_grant(FILE_KEY, [pw, pw])
    with pytest.raises(ValueError):
        access.new_grant(FILE_KEY, [])
    with pytest.raises(ValueError):
        access.new_grant(FILE_KEY, [pw] * 6)


def test_access_body_round_trips(pw: access.NewFactor, pw2: access.NewFactor) -> None:
    grants = [access.new_grant(FILE_KEY, [pw]), access.new_grant(FILE_KEY, [pw, pw2])]
    body = access.encode_access_body(grants)
    assert access.parse_access_body(body) == grants


def test_access_body_limits(pw: access.NewFactor) -> None:
    with pytest.raises(ValueError):
        access.encode_access_body([])
    grant = access.new_grant(FILE_KEY, [pw])
    with pytest.raises(ValueError):
        access.encode_access_body([grant] * 17)


def test_unknown_factor_type_is_kept_but_never_tried(pw: access.NewFactor) -> None:
    unknown = bytes(16) + b"\x01" + b"\x7f" + bytes(48)
    known = access.new_grant(FILE_KEY, [pw])
    body = access.encode_access_body([access.Grant(unknown, None), known])
    parsed = access.parse_access_body(body)
    assert parsed[0] == access.Grant(unknown, None)
    assert access.encode_access_body(parsed) == body


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda b: b[:1] + b"\x00\x10" + b[3:], Reason.GRANT_LENGTH),  # too short
        (lambda b: b + b"\x00", Reason.ACCESS_BODY_LENGTH),
        (lambda b: b"\x02" + b[1:], Reason.ACCESS_BODY_LENGTH),
        (lambda b: b[:19] + b"\x00" + b[20:], Reason.FACTOR_COUNT),
        (lambda b: b[:20] + b"\x02" + b[21:], Reason.GRANT_LENGTH),
        (lambda b: b[:-49] + b"\x05" + b[-48:], Reason.ARGON_PARAMS),
    ],
)
def test_parse_rejects(pw: access.NewFactor, mutate: object, reason: Reason) -> None:
    body = access.encode_access_body([access.new_grant(FILE_KEY, [pw])])
    with pytest.raises(FormatError) as caught:
        access.parse_access_body(mutate(body))  # type: ignore[operator]
    assert caught.value.reason == reason


# --- opening -------------------------------------------------------------------


def test_opens_with_the_password(pw: access.NewFactor) -> None:
    grant = access.new_grant(FILE_KEY, [pw])
    assert open_with([grant], passwords=["hunter2"]) == FILE_KEY


def test_two_factor_grant_needs_both(
    pw: access.NewFactor, pw2: access.NewFactor
) -> None:
    grant = access.new_grant(FILE_KEY, [pw, pw2])
    assert open_with([grant], passwords=["second", "hunter2"]) == FILE_KEY
    with pytest.raises(CannotOpen):
        open_with([grant], passwords=["hunter2"])


def test_mistyped_then_correct_password(pw: access.NewFactor) -> None:
    grant = access.new_grant(FILE_KEY, [pw])
    assert open_with([grant], passwords=["hunter3", "hunter2"]) == FILE_KEY


def test_skips_a_grant_it_cannot_satisfy(pw: access.NewFactor) -> None:
    entry = access.new_vault_password(bytes(16), "stored")
    grants = [access.new_grant(FILE_KEY, [pw]), access.new_grant(FILE_KEY, [entry])]
    assert open_with(grants, entry_passwords={bytes(16): "stored"}) == FILE_KEY


def test_nothing_supplied_cannot_open(pw: access.NewFactor) -> None:
    with pytest.raises(CannotOpen) as caught:
        open_with([access.new_grant(FILE_KEY, [pw])])
    assert caught.value.reason == Reason.CANNOT_OPEN


def test_a_grant_for_another_key_fails_the_mac(pw: access.NewFactor) -> None:
    """Key commitment: a grant that opens must also match the access MAC."""
    other = access.new_grant(bytes(32), [pw])
    with pytest.raises(CannotOpen):
        open_with([other], passwords=["hunter2"])


def test_argon2_runs_once_per_password_and_salt(
    pw: access.NewFactor, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = access.password_secret

    def counting(password: str, salt: bytes) -> bytes:
        calls.append(password)
        return real(password, salt)

    monkeypatch.setattr(access, "password_secret", counting)
    wrong = access.new_grant(bytes(32), [pw])  # opens, but fails the MAC
    right = access.new_grant(FILE_KEY, [pw])
    assert open_with([wrong, right], passwords=["hunter2"]) == FILE_KEY
    assert calls == ["hunter2"]


# --- armour ----------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 47, 48, 49, 96, 1000])
def test_armour_round_trips(size: int) -> None:
    data = secrets.token_bytes(size)
    text = armor.encode(data)
    if size == 0:
        with pytest.raises(FormatError):
            armor.decode(text)
        return
    assert armor.decode(text) == data
    assert armor.decode(text.rstrip(b"\n")) == data


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (b"x" + armor.encode(b"abc"), Reason.ARMOR_FRAME),
        (armor.encode(b"abc") * 2, Reason.ARMOR_FRAME),
        (armor.encode(b"abc") + b"\n", Reason.ARMOR_FRAME),
        (armor.encode(b"abc").replace(b"\n", b"\r"), Reason.ARMOR_LINE_ENDINGS),
        (armor.BEGIN + b"\n\n" + armor.END, Reason.ARMOR_LINE_LENGTH),
        (armor.BEGIN + b"\nYW Jj\n" + armor.END, Reason.ARMOR_BASE64),
        (armor.BEGIN + b"\nYWJ\n" + armor.END, Reason.ARMOR_BASE64),
    ],
)
def test_armour_rejects(text: bytes, reason: Reason) -> None:
    with pytest.raises(FormatError) as caught:
        armor.decode(text)
    assert caught.value.reason == reason


# --- the container -----------------------------------------------------------------


@pytest.mark.parametrize("armored", [False, True])
@pytest.mark.parametrize("size", [0, 5, 65536, 65537])
def test_container_round_trips(pw: access.NewFactor, armored: bool, size: int) -> None:
    plain = secrets.token_bytes(size)
    sealed = io.BytesIO()
    assert container.encrypt(io.BytesIO(plain), sealed, [[pw]], armored=armored) == size
    assert sealed.getvalue().startswith(armor.BEGIN) == armored
    out = io.BytesIO()
    creds = access.Credentials(passwords=["hunter2"])
    assert container.decrypt(io.BytesIO(sealed.getvalue()), out, creds) == size
    assert out.getvalue() == plain


def test_container_detects_neither_form() -> None:
    with pytest.raises(FormatError) as caught:
        container.decrypt(io.BytesIO(b"hello"), io.BytesIO(), access.Credentials())
    assert caught.value.reason == Reason.MAGIC


def test_container_rejects_a_truncated_access_block(pw: access.NewFactor) -> None:
    sealed = io.BytesIO()
    container.encrypt(io.BytesIO(b"x"), sealed, [[pw]])
    for cut in (25, 28, 40, 29 + 94 + 31):
        with pytest.raises(FormatError) as caught:
            container.read_header(io.BytesIO(sealed.getvalue()[:cut]))
        assert caught.value.reason == Reason.TRUNCATED


def test_container_tampered_header_cannot_open(pw: access.NewFactor) -> None:
    sealed = io.BytesIO()
    container.encrypt(io.BytesIO(b"x"), sealed, [[pw]])
    data = bytearray(sealed.getvalue())
    data[9] ^= 1  # the payload nonce, covered by the access MAC
    with pytest.raises(CannotOpen):
        container.decrypt(
            io.BytesIO(bytes(data)),
            io.BytesIO(),
            access.Credentials(passwords=["hunter2"]),
        )


class ShortWriter:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes, /) -> int:
        self.data += data[:5]
        return min(len(data), 5)


@pytest.mark.parametrize("armored", [False, True])
def test_container_completes_short_writes(pw: access.NewFactor, armored: bool) -> None:
    sealed = ShortWriter()
    container.encrypt(io.BytesIO(b"short"), sealed, [[pw]], armored=armored)
    out = io.BytesIO()
    creds = access.Credentials(passwords=["hunter2"])
    container.decrypt(io.BytesIO(bytes(sealed.data)), out, creds)
    assert out.getvalue() == b"short"
