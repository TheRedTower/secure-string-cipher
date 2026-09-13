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
from secure_string_cipher.passphrase_manager import PassphraseVault
from secure_string_cipher.rate_limiter import PersistentRateLimiter
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.key_identity import KeyStorageMode, compute_fingerprint
from secure_string_cipher.v2.keyfile import KeyFileData, load_keyfile, save_keyfile
from secure_string_cipher.v2.vault_service import V2VaultService

PASSWORD = "correct horse battery staple"
MASTER = "vault-master-password-2026!"  # pragma: allowlist secret
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

    # --no-restore-filename must be honored for V2, not silently ignored:
    # the CLI flag threads through to decrypt_v2_file's restore_filename.
    plaintext.unlink()
    rc = cli_args.cmd_decrypt(
        _decrypt_args(file=str(container), restore_filename=False)
    )
    assert rc == cli_args.EXIT_SUCCESS
    assert not plaintext.exists()
    fallback = tmp_path / "secret.txt.dec"
    assert fallback.exists()
    assert fallback.read_bytes() == b"file contents \x00\x01\x02"


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


# =============================================================================
# Key-status enforcement: opt-in via --vault, closes the gap where a revoked
# or destroyed managed key still works because encrypt/decrypt normally
# resolve .ssckey files straight off disk without ever consulting the vault.
# =============================================================================


def _register_key_in_vault(
    home: Path, *, status: str | None = None, key_id: str = _KEY_ID
) -> None:
    """Register the standard test key (same fingerprint/secret _use_hermetic_home
    writes to ~/.ssc/keys/) in this HOME's vault, and optionally set its status.
    HOME must already be set to `home` before calling this.
    """
    vault = PassphraseVault()
    service = V2VaultService(vault)
    keyfile_path = home / "for-import.ssckey"
    _make_keyfile(keyfile_path, key_id=key_id)
    key_data = load_keyfile(keyfile_path)
    service.import_key(key_data, KeyStorageMode.EXTERNAL_ONLY, master_password=MASTER)
    if status == "revoked":
        service.revoke_key(key_id, MASTER)
    elif status == "destroyed":
        service.destroy_key(key_id, MASTER)
    elif status == "archived":
        service.archive_key(key_id, MASTER)


def _mock_master_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_args, "_prompt_master_password", lambda: MASTER)


def test_v2_cli_encrypt_with_vault_rejects_revoked_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status="revoked")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(
            _encrypt_args(
                text="secret", with_sources=[f"key:{_FINGERPRINT}"], vault="anything"
            )
        )
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "revoked" in capsys.readouterr().err.lower()


def test_v2_cli_encrypt_with_vault_rejects_destroyed_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status="destroyed")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(
            _encrypt_args(
                text="secret", with_sources=[f"key:{_FINGERPRINT}"], vault="anything"
            )
        )
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "destroyed" in capsys.readouterr().err.lower()


def test_v2_cli_encrypt_with_vault_allows_active_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status=None)
    _mock_master_password(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="secret", with_sources=[f"key:{_FINGERPRINT}"], vault="anything"
        )
    )
    assert rc == cli_args.EXIT_SUCCESS


def test_v2_cli_encrypt_with_vault_allows_archived_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Archived is a "not primary" status, not a block — only revoke/destroy
    are enforced."""
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status="archived")
    _mock_master_password(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="secret", with_sources=[f"key:{_FINGERPRINT}"], vault="anything"
        )
    )
    assert rc == cli_args.EXIT_SUCCESS


def test_v2_cli_encrypt_rejects_revoked_status_without_the_vault_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Enforcement no longer needs --vault to opt in.

    Revocation that a physically-held .ssckey could simply ignore was
    revocation in name only, so the check now runs whenever a vault is
    present, whether or not --vault was passed.
    """
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status="revoked")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(
            _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
        )
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "revoked" in capsys.readouterr().err.lower()


def test_v2_cli_encrypt_ignores_revoked_status_when_enforcement_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--no-enforce-key-status restores the offline-friendly behaviour.

    The holder of a .ssckey can always use the key it contains — that is
    inherent to a bearer secret. The flag exists so that an operator who
    knows the vault is unreachable can proceed deliberately rather than
    being blocked by a check that cannot complete.
    """
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _register_key_in_vault(home, status="revoked")
    monkeypatch.setattr(cli_args, "_enforce_key_status", False)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS


def test_v2_cli_encrypt_with_vault_and_unregistered_key_still_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bare .ssckey file that was never imported into this vault has
    nothing to check against --vault should not block it."""
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    # Initialize an empty vault (no key registered) so vault_exists() is True
    # and the enforcement path actually runs its lookup instead of short-
    # circuiting on a missing vault file.
    vault = PassphraseVault()
    vault.store_passphrase("__init__", "init", MASTER)
    _mock_master_password(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="secret", with_sources=[f"key:{_FINGERPRINT}"], vault="anything"
        )
    )
    assert rc == cli_args.EXIT_SUCCESS


def test_v2_cli_decrypt_with_vault_rejects_revoked_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status="revoked")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored, vault="anything"))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "revoked" in capsys.readouterr().err.lower()


def test_v2_cli_decrypt_with_vault_allows_active_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status=None)
    _mock_master_password(monkeypatch)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored, vault="anything"))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "secret"


# =============================================================================
# Key-status enforcement on a combined grant, and the two remaining branches
# of _enforce_v2_key_status itself (no-vault early return; vault-unlock
# failure). Every other enforcement site (encrypt+revoked, encrypt+destroyed,
# decrypt(key-only)+revoked/destroyed) has coverage above; combined-grant
# decrypt did not.
# =============================================================================


def test_v2_cli_decrypt_combined_grant_rejects_revoked_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _mock_password_prompt(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="combined secret",
            with_sources=["password", f"key:{_FINGERPRINT}"],
            require="all",
        )
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status="revoked")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "revoked" in capsys.readouterr().err.lower()


def test_v2_cli_decrypt_combined_grant_rejects_destroyed_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _mock_password_prompt(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="combined secret",
            with_sources=["password", f"key:{_FINGERPRINT}"],
            require="all",
        )
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status="destroyed")
    _mock_master_password(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "destroyed" in capsys.readouterr().err.lower()


def test_v2_cli_decrypt_combined_grant_allows_active_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sanity check alongside the two rejections above: the combined-grant
    decrypt path must still succeed for a key the vault tracks as active,
    proving the new coverage isn't merely testing a code path that always
    fails."""
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)
    _mock_password_prompt(monkeypatch)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="combined secret",
            with_sources=["password", f"key:{_FINGERPRINT}"],
            require="all",
        )
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status=None)
    _mock_master_password(monkeypatch)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert rc == cli_args.EXIT_SUCCESS
    assert capsys.readouterr().out.strip() == "combined secret"


def test_enforce_key_status_fails_closed_when_the_vault_cannot_be_unlocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The `VaultUnlockFailed` branch: a vault exists and is consulted, but
    the supplied master password does not open it. Must fail closed rather
    than silently letting the key through unchecked -- proceeding here would
    report a status check that never actually happened."""
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status=None)
    monkeypatch.setattr(
        cli_args, "_prompt_master_password", lambda: "definitely-the-wrong-password"
    )

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    err = capsys.readouterr().err.lower()
    assert "could not unlock the vault" in err
    assert "--no-enforce-key-status" in err


def test_enforce_key_status_skips_the_prompt_hint_when_a_source_was_supplied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """When the master password already came from --master-password-file /
    SSC_MASTER_PASSWORD, there is no interactive prompt about to surprise the
    operator, so the explanatory info line must not print."""
    home = tmp_path / "home"
    _use_hermetic_home(monkeypatch, home)

    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=[f"key:{_FINGERPRINT}"])
    )
    assert rc == cli_args.EXIT_SUCCESS
    armored = _extract_armored(capsys.readouterr().out)

    _register_key_in_vault(home, status=None)
    monkeypatch.setattr(cli_args, "_master_password_source", MASTER)

    rc = cli_args.cmd_decrypt(_decrypt_args(text=armored))
    assert rc == cli_args.EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "Checking the key's status against the vault" not in captured.err
    assert "Checking the key's status against the vault" not in captured.out
