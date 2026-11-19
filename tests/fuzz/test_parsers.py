"""Fuzzing of the header, access-block, armour and key-file parsers
(Phase 2, step 5).

Each parser must, for any input, either accept it or raise FormatError,
never anything else. What a parser accepts must also be canonical: encoding
it again gives back the same bytes. Whole files, mutated, must open to their
original plaintext or fail with an SSCError.

CI runs a fixed, derandomised set of examples. For a deeper random run:

    SSC_FUZZ_EXAMPLES=200000 uv run pytest tests/fuzz
"""

from __future__ import annotations

import io
import os
import struct

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secure_string_cipher.engine import access, armor, container, keyfile, payload
from secure_string_cipher.engine.header import MAGIC, VERSION, FixedHeader
from secure_string_cipher.errors import FormatError, SSCError
from tests import vectorkit

_DEEP = int(os.environ.get("SSC_FUZZ_EXAMPLES", "0"))
fuzz = settings(
    max_examples=_DEEP or 400,
    derandomize=not _DEEP,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

KEY_A = bytes.fromhex(vectorkit.manifest()["credentials"]["key_a"])
KEY_VECTORS = [
    "format-1-bytes",
    "format-65537-bytes",
    "access-key",
    "access-unknown-grant-skipped",
]
FILES = {name: vectorkit.read(vectorkit.valid(name)["file"]) for name in KEY_VECTORS}


# --- strategies ------------------------------------------------------------------


@st.composite
def factor_bytes(draw: st.DrawFn) -> bytes:
    """A factor encoding: usually well-formed, sometimes not."""
    kind = draw(st.sampled_from([0x01, 0x02, 0x03, 0x04, 0x00, 0x7F, 0xFF]))
    size = access.BODY_SIZES.get(kind, draw(st.integers(0, 40)))
    if kind in (access.PASSWORD, access.VAULT_PASSWORD) and draw(st.booleans()):
        body = draw(st.binary(min_size=size - 9, max_size=size - 9))
        body += access.ARGON2_PARAMS
    else:
        body = draw(st.binary(min_size=size, max_size=size))
    if draw(st.integers(0, 9)) == 0:
        body = body[: draw(st.integers(0, len(body)))]
    return bytes([kind]) + body


@st.composite
def grant_bytes(draw: st.DrawFn) -> bytes:
    """A grant with its length prefix, mostly well-formed."""
    factors = draw(st.lists(factor_bytes(), min_size=1, max_size=6))
    if draw(st.booleans()):
        factors.sort()
    count = len(factors) if draw(st.integers(0, 9)) else draw(st.integers(0, 255))
    encoded = (
        draw(st.binary(min_size=16, max_size=16))
        + bytes([count])
        + b"".join(factors)
        + draw(st.binary(min_size=48, max_size=48))
    )
    length = len(encoded) + (0 if draw(st.integers(0, 9)) else draw(st.integers(-3, 3)))
    return struct.pack(">H", max(0, min(length, 0xFFFF))) + encoded


@st.composite
def access_bodies(draw: st.DrawFn) -> bytes:
    grants = draw(st.lists(grant_bytes(), min_size=0, max_size=17))
    count = len(grants) if draw(st.integers(0, 9)) else draw(st.integers(0, 255))
    tail = b"" if draw(st.integers(0, 9)) else draw(st.binary(max_size=4))
    return bytes([count]) + b"".join(grants) + tail


@st.composite
def mutated(draw: st.DrawFn, data: bytes) -> bytes:
    """`data` with a few flips, cuts, insertions or deletions."""
    out = bytearray(data)
    for _ in range(draw(st.integers(1, 4))):
        op = draw(st.sampled_from(["flip", "set", "cut", "insert", "delete"]))
        where = draw(st.integers(0, max(len(out) - 1, 0)))
        if op == "flip" and out:
            out[where] ^= 1 << draw(st.integers(0, 7))
        elif op == "set" and out:
            out[where] = draw(st.integers(0, 255))
        elif op == "cut":
            del out[where:]
        elif op == "insert":
            out[where:where] = draw(st.binary(min_size=1, max_size=8))
        elif op == "delete":
            del out[where : where + draw(st.integers(1, 8))]
    return bytes(out)


header_inputs = st.one_of(
    st.binary(max_size=40),
    st.builds(
        lambda version, rest: MAGIC + bytes([version]) + rest,
        st.sampled_from([VERSION, 0, 2, 255]),
        st.binary(max_size=24),
    ),
)


# --- parsers -----------------------------------------------------------------------


@fuzz
@given(header_inputs)
def test_fixed_header(data: bytes) -> None:
    try:
        header = FixedHeader.parse(data)
    except FormatError:
        return
    assert header.to_bytes() == data[: len(header.to_bytes())]


@fuzz
@given(st.one_of(access_bodies(), st.binary(max_size=300)))
def test_access_body(body: bytes) -> None:
    try:
        grants = access.parse_access_body(body)
    except FormatError:
        return
    assert access.encode_access_body(grants) == body
    for grant in grants:
        if grant.factors is not None:
            encodings = [f.encoding for f in grant.factors]
            assert encodings == sorted(set(encodings))
            assert 1 <= len(grant.factors) <= access.MAX_FACTORS


@fuzz
@given(st.one_of(access_bodies(), st.binary(max_size=300)))
def test_opening_a_fuzzed_access_body(body: bytes) -> None:
    """Parsing then opening never raises anything but SSCError, and never
    opens a body whose MAC was not made with the file key."""
    try:
        grants = access.parse_access_body(body)
    except FormatError:
        return
    creds = access.Credentials(keys=[KEY_A])
    try:
        access.open_file_key(grants, bytes(25), body, bytes(32), creds)
    except SSCError:
        return
    raise AssertionError("a fuzzed access body opened")


@fuzz
@given(st.sampled_from(KEY_VECTORS), st.data())
def test_mutated_files(name: str, data: st.DataObject) -> None:
    original = FILES[name]
    changed = data.draw(mutated(original))
    creds = access.Credentials(keys=[KEY_A])
    out = io.BytesIO()
    try:
        container.decrypt(io.BytesIO(changed), out, creds)
    except SSCError:
        return
    expected = io.BytesIO()
    container.decrypt(io.BytesIO(original), expected, creds)
    assert out.getvalue() == expected.getvalue()


@fuzz
@given(st.binary(min_size=32, max_size=32), st.binary(max_size=200))
def test_payload_chunks(key: bytes, data: bytes) -> None:
    try:
        list(payload.chunks(key, io.BytesIO(data)))
    except FormatError:
        return
    raise AssertionError("random bytes authenticated")


_ARMORED = vectorkit.read(vectorkit.valid("format-armored")["file"])


@fuzz
@given(st.one_of(mutated(_ARMORED), st.binary(max_size=200)))
def test_armor(text: bytes) -> None:
    try:
        decoded = armor.decode(text)
    except FormatError:
        return
    canonical = text.replace(b"\r\n", b"\n")
    if not canonical.endswith(b"\n"):
        canonical += b"\n"
    assert armor.encode(decoded) == canonical


_KEYFILE = vectorkit.read(vectorkit.manifest()["keyfiles"][0]["file"])


@fuzz
@given(st.one_of(mutated(_KEYFILE), st.binary(max_size=300)))
def test_keyfile(text: bytes) -> None:
    try:
        parsed = keyfile.parse(text)
    except FormatError:
        return
    canonical = text.replace(b"\r\n", b"\n")
    if not canonical.endswith(b"\n"):
        canonical += b"\n"
    assert parsed.to_bytes() == canonical
