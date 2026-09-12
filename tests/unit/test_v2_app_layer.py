"""Tests for the reusable v2 application layer.

The defining property of this layer is what it does *not* do: no prompting,
no process exit. Everything here therefore runs with no TTY attached and
asserts on returned values or raised exceptions. If a future change
reintroduces `getpass` or `sys.exit` into this module, the tests that drive
it headlessly are what will notice.
"""

import secrets
from pathlib import Path

import pytest

from secure_string_cipher.v2.app import (
    CredentialRequirement,
    GrantRequirement,
    KeyFileNotFound,
    KeyFileUnreadable,
    KeyResolver,
    KeyStatusPolicy,
    KeyStatusRejected,
    NoUsableGrant,
    V2AppError,
    VaultUnlockFailed,
    build_credential,
    default_keys_dir,
    header_from_armour,
    required_credential,
)
from secure_string_cipher.v2.encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    encrypt_v2_text,
)
from secure_string_cipher.v2.envelope import V2Header
from secure_string_cipher.v2.key_identity import KeyStatus, compute_fingerprint
from secure_string_cipher.v2.keyfile import KeyFileData, save_keyfile

PASSWORD = "Str0ngPassphrase!2026"  # pragma: allowlist secret
# Stub master passwords. Named constants rather than inline literals so the
# allowlist pragma cannot be detached from them by the formatter.
MASTER = "stub-master"  # pragma: allowlist secret
WRONG_MASTER = "stub-wrong"  # pragma: allowlist secret


def _write_keyfile(directory: Path, key_id: str) -> tuple[Path, KeyFileData]:
    secret = secrets.token_bytes(32)
    data = KeyFileData(
        version=1,
        key_id=key_id,
        key_type="symmetric-key",
        kdf="hkdf-sha256",
        fingerprint=compute_fingerprint(secret),
        created_at="2026-09-12T00:00:00Z",
        secret_bytes=secret,
    )
    path = directory / f"{key_id}.ssckey"
    save_keyfile(data, path)
    return path, data


def _header_for(credential) -> V2Header:
    """Seal a real object and hand back its parsed header."""
    return header_from_armour(encrypt_v2_text("probe", credential))


class TestRequiredCredential:
    """`required_credential` is pure: it inspects a header and nothing else."""

    def test_password_grant(self) -> None:
        header = _header_for(PasswordCredential(PASSWORD))
        req = required_credential(header)
        assert req.requirement is CredentialRequirement.PASSWORD
        assert req.needs_password and not req.needs_managed_key
        assert req.key_fingerprint is None

    def test_managed_key_grant(self, tmp_path: Path) -> None:
        _, data = _write_keyfile(tmp_path, "probe-key")
        header = _header_for(KeyCredential(data.fingerprint, data.secret_bytes))
        req = required_credential(header)
        assert req.requirement is CredentialRequirement.MANAGED_KEY
        assert req.needs_managed_key and not req.needs_password
        assert req.key_fingerprint == data.fingerprint

    def test_combined_grant(self, tmp_path: Path) -> None:
        _, data = _write_keyfile(tmp_path, "probe-key")
        header = _header_for(
            CombinedCredential(PASSWORD, data.fingerprint, data.secret_bytes)
        )
        req = required_credential(header)
        assert req.requirement is CredentialRequirement.COMBINED
        assert req.needs_password and req.needs_managed_key
        assert req.key_fingerprint == data.fingerprint


class TestKeyResolver:
    def test_resolves_an_explicit_path(self, tmp_path: Path) -> None:
        path, data = _write_keyfile(tmp_path, "by-path")
        assert KeyResolver().resolve(str(path)).fingerprint == data.fingerprint

    def test_resolves_by_key_id_from_the_keys_directory(self, tmp_path: Path) -> None:
        _, data = _write_keyfile(tmp_path, "by-id")
        assert KeyResolver(tmp_path).resolve("by-id").fingerprint == data.fingerprint

    def test_resolves_by_fingerprint_from_the_keys_directory(
        self, tmp_path: Path
    ) -> None:
        _, data = _write_keyfile(tmp_path, "by-fingerprint")
        resolved = KeyResolver(tmp_path).resolve(data.fingerprint)
        assert resolved.key_id == "by-fingerprint"

    def test_unknown_reference_raises_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(KeyFileNotFound) as excinfo:
            KeyResolver(tmp_path).resolve("no-such-key")
        assert excinfo.value.key_ref == "no-such-key"
        assert str(tmp_path) in str(excinfo.value)

    def test_corrupt_keyfile_at_an_explicit_path_raises_unreadable(
        self, tmp_path: Path
    ) -> None:
        bad = tmp_path / "broken.ssckey"
        bad.write_text("not a keyfile at all\n")
        with pytest.raises(KeyFileUnreadable) as excinfo:
            KeyResolver(tmp_path).resolve(str(bad))
        assert excinfo.value.path == bad
        assert excinfo.value.cause is not None

    def test_one_corrupt_keyfile_does_not_hide_the_others(self, tmp_path: Path) -> None:
        """A malformed neighbour must not abort the directory search."""
        (tmp_path / "broken.ssckey").write_text("garbage\n")
        _, good = _write_keyfile(tmp_path, "good-key")
        assert KeyResolver(tmp_path).resolve("good-key").fingerprint == good.fingerprint

    def test_missing_keys_directory_is_not_an_error_in_itself(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(KeyFileNotFound):
            KeyResolver(tmp_path / "absent").resolve("anything")

    def test_default_keys_directory_follows_the_current_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Resolved per call, not captured at import time."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        assert default_keys_dir() == tmp_path / ".ssc" / "keys"
        assert KeyResolver().keys_dir == tmp_path / ".ssc" / "keys"


class _StubService:
    """Stands in for V2VaultService without needing a real vault."""

    def __init__(self, records=None, error: Exception | None = None):
        self._records = records or []
        self._error = error
        self.seen_password: str | None = None

    def list_keys(self, master_password: str):
        self.seen_password = master_password
        if self._error is not None:
            raise self._error
        return self._records


class _Record:
    def __init__(self, key_id: str, fingerprint: str, status: KeyStatus):
        self.id = key_id
        self.fingerprint = fingerprint
        self.status = status


class TestKeyStatusPolicy:
    FP = "ssc-k1-" + "A" * 52

    def test_active_key_passes(self) -> None:
        service = _StubService([_Record("k", self.FP, KeyStatus.ACTIVE)])
        KeyStatusPolicy(service).check(self.FP, master_password=MASTER)
        assert service.seen_password == MASTER, (
            "the password must be injected, not read"
        )

    def test_archived_key_passes(self) -> None:
        """Archive is bookkeeping only; it never blocks use."""
        service = _StubService([_Record("k", self.FP, KeyStatus.ARCHIVED)])
        KeyStatusPolicy(service).check(self.FP, master_password=MASTER)

    @pytest.mark.parametrize("status", [KeyStatus.REVOKED, KeyStatus.DESTROYED])
    def test_revoked_or_destroyed_key_is_rejected(self, status: KeyStatus) -> None:
        service = _StubService([_Record("laptop", self.FP, status)])
        with pytest.raises(KeyStatusRejected) as excinfo:
            KeyStatusPolicy(service).check(self.FP, master_password=MASTER)
        assert excinfo.value.key_id == "laptop"
        assert excinfo.value.status is status
        assert "laptop" in str(excinfo.value)

    def test_untracked_key_is_allowed_through(self) -> None:
        """A bare .ssckey this vault never registered cannot be judged."""
        other = "ssc-k1-" + "B" * 52
        service = _StubService([_Record("k", other, KeyStatus.REVOKED)])
        KeyStatusPolicy(service).check(self.FP, master_password=MASTER)

    def test_unopenable_vault_raises_rather_than_silently_allowing(self) -> None:
        service = _StubService(error=RuntimeError("bad master password"))
        with pytest.raises(VaultUnlockFailed) as excinfo:
            KeyStatusPolicy(service).check(self.FP, master_password=WRONG_MASTER)
        assert isinstance(excinfo.value.cause, RuntimeError)


class TestBuildCredential:
    FP = "ssc-k1-" + "C" * 52

    def _key_data(self) -> KeyFileData:
        secret = secrets.token_bytes(32)
        return KeyFileData(
            version=1,
            key_id="k",
            key_type="symmetric-key",
            kdf="hkdf-sha256",
            fingerprint=compute_fingerprint(secret),
            created_at="2026-09-12T00:00:00Z",
            secret_bytes=secret,
        )

    def test_builds_each_credential_type(self) -> None:
        data = self._key_data()
        password_only = build_credential(
            GrantRequirement(CredentialRequirement.PASSWORD), password=PASSWORD
        )
        assert isinstance(password_only, PasswordCredential)

        key_only = build_credential(
            GrantRequirement(CredentialRequirement.MANAGED_KEY, self.FP), key_data=data
        )
        assert isinstance(key_only, KeyCredential)

        combined = build_credential(
            GrantRequirement(CredentialRequirement.COMBINED, self.FP),
            password=PASSWORD,
            key_data=data,
        )
        assert isinstance(combined, CombinedCredential)

    def test_uses_the_grant_fingerprint_not_the_keyfile_one(self) -> None:
        """A caller may point at a different file; the grant still names the
        identity the DEK was wrapped against, so a mismatch must surface as an
        authentication failure rather than silently succeeding."""
        data = self._key_data()
        credential = build_credential(
            GrantRequirement(CredentialRequirement.MANAGED_KEY, self.FP), key_data=data
        )
        assert credential.key_fingerprint == self.FP != data.fingerprint

    def test_missing_parts_are_refused(self) -> None:
        with pytest.raises(ValueError, match="requires a password"):
            build_credential(GrantRequirement(CredentialRequirement.PASSWORD))
        with pytest.raises(ValueError, match="requires a managed key"):
            build_credential(
                GrantRequirement(CredentialRequirement.MANAGED_KEY, self.FP)
            )


class TestLayerIsHeadless:
    def test_every_app_error_is_catchable_as_one_type(self) -> None:
        """A caller can handle the whole layer without enumerating classes."""
        for error in (
            KeyFileNotFound("x", Path("/k")),
            KeyFileUnreadable(Path("/k/x.ssckey"), OSError("boom")),
            KeyStatusRejected("k", KeyStatus.REVOKED),
            VaultUnlockFailed(),
            NoUsableGrant(),
        ):
            assert isinstance(error, V2AppError)
            assert str(error), "each error must carry a renderable message"

    def test_a_full_headless_round_trip(self, tmp_path: Path) -> None:
        """Resolve, check status and build a credential with no TTY involved.

        This is the path a TUI or library caller would take, and the one that
        previously could not exist because the equivalent CLI helpers called
        sys.exit and getpass.
        """
        _, data = _write_keyfile(tmp_path, "headless")
        header = _header_for(KeyCredential(data.fingerprint, data.secret_bytes))

        requirement = required_credential(header)
        resolved = KeyResolver(tmp_path).resolve(requirement.key_fingerprint or "")
        KeyStatusPolicy(
            _StubService([_Record("headless", data.fingerprint, KeyStatus.ACTIVE)])
        ).check(data.fingerprint, master_password=MASTER)
        credential = build_credential(requirement, key_data=resolved)

        assert isinstance(credential, KeyCredential)
        assert credential.key_fingerprint == data.fingerprint
