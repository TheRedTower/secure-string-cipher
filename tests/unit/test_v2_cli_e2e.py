"""End-to-end CLI tests for the V2 encrypt/decrypt code paths.

Unlike test_v2_cli_routing.py (which mocks the V2 layer away), these tests run
the real ``cmd_encrypt``/``cmd_decrypt`` implementation with real crypto and
real keyfiles. Only the password prompt, the vault backend, and ``HOME`` (for
``~/.ssc/keys`` lookup) are mocked.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import secure_string_cipher.cli_args as cli_args
from secure_string_cipher.rate_limiter import PersistentRateLimiter
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.key_identity import compute_fingerprint
from secure_string_cipher.v2.keyfile import KeyFileData, save_keyfile

PASSWORD = "correct horse battery staple"
_SECRET = b"\x5a" * 32
_FINGERPRINT = compute_fingerprint(_SECRET)
_KEY_ID = "e2e-key"

_BEGIN = "-----BEGIN SSC MESSAGE-----"
_END = "-----END SSC MESSAGE-----"


@pytest.fixture(autouse=True)
def _hermetic_cli_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate every test in this file from the real ~/.secure-cipher state.

    The V2 CLI code paths hit two module-level singletons that would otherwise
    read/write the developer's real home directory:

    - ``cli_args._cli_limiter`` (PersistentRateLimiter) persists attempt state
      to ``~/.secure-cipher/rate_limits.json``.
    - ``cli_args.get_audit_logger`` returns a singleton that appends to
      ``~/.secure-cipher/logs/audit.log``.

    This fixture redirects HOME to a per-test tmp dir (no XDG_* vars are used
    by this codebase; get_config_dir() keys off HOME) and replaces both
    singletons so no real audit file writes or global rate-limit side effects
    can occur. Existing per-test helpers keep working on top of this.
    """
    home = tmp_path / "hermetic-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        cli_args,
        "_cli_limiter",
        PersistentRateLimiter(state_path=str(tmp_path / "rate_limits.json")),
    )
    monkeypatch.setattr(cli_args, "get_audit_logger", MagicMock())


def _encrypt_args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "text": None,
        "file": None,
        "positional_path": None,
        "vault": None,
        "key_file": None,
        "force": False,
        "with_sources": None,
        "require": "any",
        "output": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _decrypt_args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "text": None,
        "file": None,
        "output": None,
        "restore_filename": True,
        "vault": None,
        "key_file": None,
        "force": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _make_keyfile(path: Path, key_id: str = _KEY_ID) -> KeyFileData:
    data = KeyFileData(
        version=1,
        key_id=key_id,
        key_type="symmetric-key",
        kdf="hkdf-sha256",
        fingerprint=_FINGERPRINT,
        created_at="2026-09-09T00:00:00Z",
        secret_bytes=_SECRET,
    )
    save_keyfile(data, path)
    return data


def _mock_password_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_args, "_prompt_password", lambda *a, **k: PASSWORD)


def _extract_armored(stdout: str) -> str:
    start = stdout.index(_BEGIN)
    end = stdout.index(_END) + len(_END)
    return stdout[start:end] + "\n"


def _use_hermetic_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> Path:
    """Point HOME at a temp dir and register the test key in ~/.ssc/keys/."""
    keys_dir = home / ".ssc" / "keys"
    keys_dir.mkdir(parents=True)
    _make_keyfile(keys_dir / f"{_KEY_ID}.ssckey")
    monkeypatch.setenv("HOME", str(home))
    return keys_dir


# =============================================================================
# Password credential: text and file round-trips through the real CLI
# =============================================================================


def test_v2_cli_password_text_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="attack at dawn", with_sources=["password"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)
    assert armored.startswith(_BEGIN)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "attack at dawn"


def test_v2_cli_password_file_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)
    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"file contents \x00\x01\x02")

    rc = cli_args.cmd_encrypt(
        _encrypt_args(file=str(plaintext), with_sources=["password"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    container = tmp_path / "secret.txt.ssc"
    assert container.exists()

    # Explicit -o destination (also covers the output/force passthrough).
    restored = tmp_path / "restored.txt"
    rc = cli_args.cmd_decrypt(_decrypt_args(file=str(container), output=str(restored)))
    assert rc == cli_args.EXIT_SUCCESS
    assert restored.read_bytes() == b"file contents \x00\x01\x02"

    # Default path: restores the original filename next to the container.
    plaintext.unlink()
    rc = cli_args.cmd_decrypt(_decrypt_args(file=str(container)))
    assert rc == cli_args.EXIT_SUCCESS
    assert plaintext.read_bytes() == b"file contents \x00\x01\x02"


# =============================================================================
# Managed-key credential, referenced by .ssckey path
# =============================================================================


def test_v2_cli_key_by_path_text_roundtrip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_path = tmp_path / "mykey.ssckey"
    _make_keyfile(key_path)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="key text", with_sources=[f"key:{key_path}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored, key_file=str(key_path)))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "key text"


def test_v2_cli_key_by_path_file_roundtrip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_path = tmp_path / "mykey.ssckey"
    _make_keyfile(key_path)
    plaintext = tmp_path / "doc.bin"
    plaintext.write_bytes(b"\x89PNG binary-ish")

    rc = cli_args.cmd_encrypt(
        _encrypt_args(file=str(plaintext), with_sources=[f"key:{key_path}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    container = tmp_path / "doc.bin.ssc"
    assert container.exists()

    restored = tmp_path / "doc.out"
    rc = cli_args.cmd_decrypt(
        _decrypt_args(file=str(container), output=str(restored), key_file=str(key_path))
    )
    assert rc == cli_args.EXIT_SUCCESS
    assert restored.read_bytes() == b"\x89PNG binary-ish"


# =============================================================================
# Managed-key credential, referenced by fingerprint / key-id via ~/.ssc/keys
# =============================================================================


def test_v2_cli_key_by_fingerprint_text_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_hermetic_home(monkeypatch, tmp_path / "home")

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="fingerprint text", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    # Decrypt with no key flags: the grant fingerprint is resolved via
    # ~/.ssc/keys/ under the hermetic HOME.
    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "fingerprint text"


def test_v2_cli_key_by_fingerprint_file_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_hermetic_home(monkeypatch, tmp_path / "home")
    plaintext = tmp_path / "fp.txt"
    plaintext.write_text("fingerprint file")

    rc = cli_args.cmd_encrypt(
        _encrypt_args(file=str(plaintext), with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    container = tmp_path / "fp.txt.ssc"
    assert container.exists()

    restored = tmp_path / "fp.out"
    rc = cli_args.cmd_decrypt(_decrypt_args(file=str(container), output=str(restored)))
    assert rc == cli_args.EXIT_SUCCESS
    assert restored.read_text() == "fingerprint file"


def test_v2_cli_key_by_key_id_text_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_hermetic_home(monkeypatch, tmp_path / "home")

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="key-id text", with_sources=[f"key:{_KEY_ID}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "key-id text"


# =============================================================================
# Combined password + managed-key credential
# =============================================================================


def test_v2_cli_combined_text_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)
    key_path = tmp_path / "combo.ssckey"
    _make_keyfile(key_path)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="combined secret",
            with_sources=["password", f"key:{key_path}"],
            require="all",
        )
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored, key_file=str(key_path)))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "combined secret"


# =============================================================================
# Exit-code contract and error-message leakage
# =============================================================================


def test_v2_cli_encrypt_missing_keyfile_exits_4(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(
            _encrypt_args(text="x", with_sources=[f"key:{tmp_path / 'nope.ssckey'}"])
        )
    assert excinfo.value.code == cli_args.EXIT_FILE_ERROR
    assert "Could not load key file." in capsys.readouterr().err


def test_v2_cli_encrypt_unresolvable_fingerprint_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_hermetic_home(monkeypatch, tmp_path / "home")
    missing = compute_fingerprint(b"\x01" * 32)
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(_encrypt_args(text="x", with_sources=[f"key:{missing}"]))
    assert excinfo.value.code == cli_args.EXIT_FILE_ERROR
    assert "Key not found" in capsys.readouterr().err


def test_v2_cli_decrypt_missing_keyfile_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Encrypt with a resolvable key first (real home has no such key either).
    key_path = tmp_path / "mykey.ssckey"
    _make_keyfile(key_path)
    rc = cli_args.cmd_encrypt(_encrypt_args(text="x", with_sources=[f"key:{key_path}"]))
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    # Hermetic HOME without the key registered: grant fingerprint lookup fails.
    home = tmp_path / "empty-home"
    (home / ".ssc" / "keys").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert excinfo.value.code == cli_args.EXIT_FILE_ERROR
    assert "Key not found" in capsys.readouterr().err


def test_v2_cli_decrypt_wrong_password_exits_2_generic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)
    rc = cli_args.cmd_encrypt(_encrypt_args(text="secret", with_sources=["password"]))
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    monkeypatch.setattr(cli_args, "_prompt_password", lambda *a, **k: "wrong password")
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    err = capsys.readouterr().err
    assert "Decryption failed. Wrong password/key or corrupted data." in err
    # No exception internals may leak into the user-facing message.
    for leaked in ("GrantCommitmentError", "commitment", "unwrap", "AEAD"):
        assert leaked not in err


def test_v2_cli_decrypt_malformed_message_exits_2_generic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    malformed = (
        "-----BEGIN SSC MESSAGE-----\n"
        "Version: 2\n"
        "Type: text\n"
        "Header: !!!not-base64!!!\n"
        "\n"
        "Zm9v\n"
        "-----END SSC MESSAGE-----\n"
    )
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=malformed))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    err = capsys.readouterr().err
    assert "Decryption failed. Wrong password/key or corrupted data." in err
    assert "Failed to parse" not in err


def test_v2_cli_decrypt_corrupt_container_exits_2_generic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    container = tmp_path / "broken.ssc"
    container.write_bytes(b"SSC2" + b"\xff\xff\xff\xff" + b"garbage")
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(file=str(container)))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    err = capsys.readouterr().err
    assert "Decryption failed. Wrong password/key or corrupted data." in err


def test_v2_cli_encrypt_internal_failure_exits_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)

    def _boom(*args: object, **kwargs: object) -> str:
        raise CryptoError("internal failure")

    monkeypatch.setattr(cli_args, "encrypt_v2_text", _boom)
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(_encrypt_args(text="secret", with_sources=["password"]))
    assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR
    assert "Encryption failed." in capsys.readouterr().err


def test_v2_cli_decrypt_key_file_flag_rejected_for_password_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mock_password_prompt(monkeypatch)
    rc = cli_args.cmd_encrypt(_encrypt_args(text="secret", with_sources=["password"]))
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    key_path = tmp_path / "mykey.ssckey"
    _make_keyfile(key_path)
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored, key_file=str(key_path)))
    assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR
