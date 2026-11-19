"""Unit tests for the key factor and key files."""

from __future__ import annotations

import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secure_string_cipher.engine import access, keyfile
from secure_string_cipher.errors import CannotOpen, FormatError, Reason

FILE_KEY = bytes(range(32))
HEADER = bytes(25)
KEY = bytes(range(100, 132))
GOOD = keyfile.KeyFile("laptop", "2026-11-18T09:30:00Z", KEY)


def open_with(grant: access.Grant, **creds: object) -> bytes:
    body = access.encode_access_body([grant])
    mac = access.access_mac(FILE_KEY, HEADER, body)
    return access.open_file_key(
        access.parse_access_body(body),
        HEADER,
        body,
        mac,
        access.Credentials(**creds),  # type: ignore[arg-type]
    )


# --- the key factor -----------------------------------------------------------


def test_key_factor_names_the_key_by_its_id() -> None:
    factor = access.new_key(KEY)
    assert factor.factor == access.Factor(access.KEY, access.key_id(KEY))


def test_key_must_be_32_bytes() -> None:
    with pytest.raises(ValueError):
        access.new_key(b"short")


def test_opens_with_the_matching_key_among_several() -> None:
    grant = access.new_grant(FILE_KEY, [access.new_key(KEY)])
    others = [secrets.token_bytes(32) for _ in range(3)]
    assert open_with(grant, keys=[*others, KEY]) == FILE_KEY
    with pytest.raises(CannotOpen):
        open_with(grant, keys=others)


def test_a_key_is_only_tried_where_its_id_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = access.new_grant(FILE_KEY, [access.new_key(KEY)])
    calls: list[bytes] = []
    real = access.key_secret

    def counting(key: bytes) -> bytes:
        calls.append(key)
        return real(key)

    monkeypatch.setattr(access, "key_secret", counting)
    open_with(grant, keys=[secrets.token_bytes(32), KEY])
    assert calls == [KEY]


def test_password_and_key_grant() -> None:
    factors = [access.new_password("hunter2"), access.new_key(KEY)]
    grant = access.new_grant(FILE_KEY, factors)
    assert open_with(grant, passwords=["hunter2"], keys=[KEY]) == FILE_KEY
    with pytest.raises(CannotOpen):
        open_with(grant, keys=[KEY])


# --- key files ----------------------------------------------------------------


def test_round_trip() -> None:
    assert keyfile.parse(GOOD.to_bytes()) == GOOD
    assert keyfile.is_keyfile(GOOD.to_bytes())
    assert not keyfile.is_keyfile(b"\x89SSC")


def test_timestamp_form() -> None:
    when = datetime(2026, 11, 18, 9, 30, 0, 123, tzinfo=UTC)
    assert keyfile.timestamp(when) == "2026-11-18T09:30:00Z"


@pytest.mark.parametrize(
    "fields",
    [
        {"label": "Laptop"},
        {"label": "9lives"},
        {"label": "a" * 65},
        {"created": "2026-11-18 09:30:00Z"},
        {"created": "2026-13-18T09:30:00Z"},
        {"key": b"short"},
    ],
)
def test_keyfile_fields_are_checked(fields: dict[str, object]) -> None:
    args: dict[str, object] = {"label": GOOD.label, "created": GOOD.created, "key": KEY}
    with pytest.raises(ValueError):
        keyfile.KeyFile(**(args | fields))  # type: ignore[arg-type]


def _lines() -> list[bytes]:
    return GOOD.to_bytes().split(b"\n")


def _swap(index: int, line: bytes) -> bytes:
    lines = _lines()
    lines[index] = line
    return b"\n".join(lines)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"x" + GOOD.to_bytes(), Reason.KEYFILE),
        (GOOD.to_bytes() + b"x", Reason.KEYFILE),
        (GOOD.to_bytes() + b"\n", Reason.KEYFILE),
        (GOOD.to_bytes() * 2, Reason.KEYFILE),
        (GOOD.to_bytes().replace(b"\n", b"\r\n", 1), Reason.ARMOR_LINE_ENDINGS),
        (_swap(1, b"label: laptop"), Reason.KEYFILE),
        (_swap(1, b"Label: Laptop"), Reason.KEYFILE),
        (_swap(2, b"Created: yesterday"), Reason.KEYFILE),
        (_swap(3, b"Key-ID: " + b"A" * 32), Reason.KEYFILE),
        (_swap(3, b"Key-ID: " + b"0" * 32), Reason.KEYFILE_KEY_ID),
        (_swap(4, _lines()[4][:-1]), Reason.KEYFILE),
        (_swap(4, _lines()[4] + b"="), Reason.KEYFILE),
        (_swap(4, _lines()[4][:-1] + b"+"), Reason.KEYFILE),
        (_swap(1, "Label: läptop".encode()), Reason.KEYFILE),
        (
            b"\n".join([_lines()[0], _lines()[2], _lines()[1], *_lines()[3:]]),
            Reason.KEYFILE,
        ),
        (GOOD.to_bytes() + b" " * 1024, Reason.KEYFILE),
    ],
)
def test_parse_rejects(data: bytes, reason: Reason) -> None:
    with pytest.raises(FormatError) as caught:
        keyfile.parse(data)
    assert caught.value.reason == reason


def test_noncanonical_key_text_is_rejected() -> None:
    line = _lines()[4]
    # The last of 43 characters carries 2 unused bits; set one.
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(line[-1:])
    tweaked = line[:-1] + alphabet[last | 1 : (last | 1) + 1]
    if tweaked == line:
        tweaked = line[:-1] + alphabet[last ^ 1 : (last ^ 1) + 1]
    with pytest.raises(FormatError) as caught:
        keyfile.parse(_swap(4, tweaked))
    assert caught.value.reason in (Reason.KEYFILE, Reason.KEYFILE_KEY_ID)


def test_write_then_read(tmp_path: Path) -> None:
    path = tmp_path / "laptop.ssckey"
    keyfile.write(path, GOOD)
    assert keyfile.read(path) == GOOD
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_write_never_replaces(tmp_path: Path) -> None:
    path = tmp_path / "laptop.ssckey"
    keyfile.write(path, GOOD)
    with pytest.raises(FileExistsError):
        keyfile.write(path, GOOD)


def test_read_refuses_a_symlink(tmp_path: Path) -> None:
    path = tmp_path / "real.ssckey"
    keyfile.write(path, GOOD)
    link = tmp_path / "link.ssckey"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlinks are not available here")
    with pytest.raises(PermissionError):
        keyfile.read(link)


def test_read_refuses_a_directory(tmp_path: Path) -> None:
    with pytest.raises(PermissionError):
        keyfile.read(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_read_refuses_a_file_others_can_read(tmp_path: Path) -> None:
    path = tmp_path / "laptop.ssckey"
    keyfile.write(path, GOOD)
    path.chmod(0o640)
    with pytest.raises(PermissionError):
        keyfile.read(path)


def test_read_stops_at_1_kib(tmp_path: Path) -> None:
    path = tmp_path / "big.ssckey"
    keyfile.write(path, GOOD)
    with path.open("ab") as handle:
        handle.write(b"\n" * 2000)
    with pytest.raises(FormatError):
        keyfile.read(path)


def test_read_refuses_a_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    keyfile.write(real / "laptop.ssckey", GOOD)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available here")
    assert keyfile.read(real / "laptop.ssckey") == GOOD
    with pytest.raises(PermissionError):
        keyfile.read(alias / "laptop.ssckey")


def test_read_reaches_a_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keyfile.write(tmp_path / "laptop.ssckey", GOOD)
    monkeypatch.chdir(tmp_path)
    assert keyfile.read("laptop.ssckey") == GOOD


def test_read_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX FIFOs")
    fifo = tmp_path / "key.ssckey"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(PermissionError):
        keyfile.read(fifo)


def test_read_refuses_a_symlink_hidden_by_dot_dot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "other" / "child").mkdir(parents=True)
    keyfile.write(tmp_path / "other" / "laptop.ssckey", GOOD)
    keyfile.write(tmp_path / "laptop.ssckey", GOOD)
    try:
        (tmp_path / "alias").symlink_to(
            tmp_path / "other" / "child", target_is_directory=True
        )
    except OSError:
        pytest.skip("symlinks are not available here")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(PermissionError):
        keyfile.read(Path("alias") / ".." / "laptop.ssckey")
    with pytest.raises(PermissionError):
        keyfile.read(tmp_path / "alias" / ".." / "laptop.ssckey")
    assert keyfile.read(Path("other") / "child" / ".." / "laptop.ssckey") == GOOD


def test_read_through_a_search_only_parent(tmp_path: Path) -> None:
    if sys.platform == "win32" or os.geteuid() == 0:
        pytest.skip("POSIX permissions, as a user they apply to")
    parent = tmp_path / "locked"
    parent.mkdir()
    keyfile.write(parent / "laptop.ssckey", GOOD)
    parent.chmod(0o300)  # search and write, but no listing
    try:
        assert keyfile.read(parent / "laptop.ssckey") == GOOD
    finally:
        parent.chmod(0o700)
