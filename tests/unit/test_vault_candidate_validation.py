"""Side-effect-free current vault candidate validation tests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_string_cipher.core import encrypt_text
from secure_string_cipher.passphrase_manager import (
    PassphraseVault,
    _compute_vault_hmac,
    validate_raw_vault,
)

TEST_MASTER = "Public-Test-Only-Vault-Master-2026!"  # pragma: allowlist secret
WRONG_MASTER = "Wrong-Test-Only-Vault-Master-2026!"  # pragma: allowlist secret
GENERIC_FAILURE = (
    "Failed to decrypt vault. Wrong master password or corrupted vault file."
)
EXPECTED_ENTRIES = {
    "fixture-alpha": "synthetic-river-copper-planet",
    "fixture-beta": "synthetic-lantern-maple-orbit",
}
FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "vault"
FIXTURE_MANIFEST = json.loads(
    (FIXTURE_DIRECTORY / "manifest.json").read_text(encoding="utf-8")
)


def _build_raw(decrypted_json: str, master: str = TEST_MASTER) -> str:
    encrypted = encrypt_text(decrypted_json, master)
    salt = b"\xab" * 32
    digest = _compute_vault_hmac(encrypted, master, salt)
    return f"SSCVAULT\n{salt.hex()}\n---DATA---\n{encrypted}\n---HMAC---\n{digest}"


def _with_nonzero_base64_pad_bits(token: str) -> str:
    """Return an alternate Base64 spelling that decodes to the same bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padding = len(token) - len(token.rstrip("="))
    assert padding in {1, 2}
    index = len(token) - padding - 1
    canonical_value = alphabet.index(token[index])
    alternate = token[:index] + alphabet[canonical_value ^ 1] + token[index + 1 :]
    assert base64.b64decode(alternate, validate=True) == base64.b64decode(token)
    return alternate


@pytest.fixture(scope="module")
def valid_raw() -> str:
    return _build_raw(json.dumps(EXPECTED_ENTRIES))


def _assert_generic_failure(raw: str | bytes, master: str = TEST_MASTER) -> None:
    with pytest.raises(ValueError) as caught:
        validate_raw_vault(raw, master)
    assert str(caught.value) == GENERIC_FAILURE


def test_valid_candidate_returns_fresh_exact_mapping(valid_raw: str) -> None:
    first = validate_raw_vault(valid_raw, TEST_MASTER)
    second = validate_raw_vault(valid_raw.encode("utf-8"), TEST_MASTER)

    assert first == EXPECTED_ENTRIES
    assert second == EXPECTED_ENTRIES
    assert first is not second
    first["fixture-alpha"] = "changed"
    assert second == EXPECTED_ENTRIES


def test_released_writer_fixture_matches_manifest_and_validates() -> None:
    fixture = FIXTURE_DIRECTORY / FIXTURE_MANIFEST["fixture"]["filename"]
    encoded = fixture.read_text(encoding="ascii").strip()
    raw = base64.b64decode(encoded, validate=True)

    assert len(raw) == FIXTURE_MANIFEST["fixture"]["decoded_byte_length"]
    assert (
        f"sha256:{hashlib.sha256(raw).hexdigest()}"
        == FIXTURE_MANIFEST["fixture"]["decoded_sha256"]
    )
    assert (
        validate_raw_vault(raw, FIXTURE_MANIFEST["public_test_credential"])
        == FIXTURE_MANIFEST["expected_entries"]
    )


def test_wrong_master_password_fails_generically(valid_raw: str) -> None:
    _assert_generic_failure(valid_raw, WRONG_MASTER)


@pytest.mark.parametrize("line_index", range(6))
def test_one_bit_corruption_in_each_framed_component_fails(
    valid_raw: str, line_index: int
) -> None:
    lines = valid_raw.split("\n")
    first = lines[line_index][0]
    lines[line_index] = chr(ord(first) ^ 1) + lines[line_index][1:]

    _assert_generic_failure("\n".join(lines))


def _truncated_candidates(raw: str) -> list[object]:
    lines = raw.split("\n")
    boundaries = []
    offset = 0
    for line in lines:
        offset += len(line)
        boundaries.append(offset)
        offset += 1
    candidates = [
        pytest.param(raw[:boundary], id=f"boundary-{index}")
        for index, boundary in enumerate(boundaries[:-1])
    ]
    candidates.append(pytest.param(raw[:-1], id="hmac-truncated"))
    return candidates


@pytest.mark.parametrize("candidate", _truncated_candidates(_build_raw("{}")))
def test_truncation_at_each_framing_boundary_fails(candidate: str) -> None:
    _assert_generic_failure(candidate)


@pytest.mark.parametrize("plaintext", ["not-json", "[1,2]", "42", "null"])
def test_invalid_or_non_object_decrypted_json_fails(plaintext: str) -> None:
    _assert_generic_failure(_build_raw(plaintext))


@pytest.mark.parametrize(
    "plaintext",
    [
        '{1:"value"}',
        '{"label":1}',
        '{"label":true}',
        '{"label":null}',
        '{"label":[]}',
        '{"label":{}}',
    ],
)
def test_non_string_entry_names_or_values_fail(plaintext: str) -> None:
    _assert_generic_failure(_build_raw(plaintext))


def test_duplicate_entry_names_fail() -> None:
    _assert_generic_failure(_build_raw('{"same":"first","same":"second"}'))


def test_invalid_utf8_and_noncanonical_outer_encodings_fail(valid_raw: str) -> None:
    _assert_generic_failure(b"\xff" + valid_raw.encode())

    lines = valid_raw.split("\n")
    lines[1] = lines[1].upper()
    _assert_generic_failure("\n".join(lines))

    lines = valid_raw.split("\n")
    lines[3] += "\n"
    _assert_generic_failure("\n".join(lines))


def test_noncanonical_encrypted_token_pad_bits_fail_with_valid_hmac() -> None:
    raw = _build_raw('{"a":"b"}')
    lines = raw.split("\n")
    lines[3] = _with_nonzero_base64_pad_bits(lines[3])
    salt = bytes.fromhex(lines[1])
    lines[5] = _compute_vault_hmac(lines[3], TEST_MASTER, salt)

    _assert_generic_failure("\n".join(lines))


@pytest.mark.parametrize(
    "whitespace", ["\n", "\r\n", "\n\n", " ", "\t", "\r", "\u2003"]
)
@pytest.mark.parametrize("position", ["prefix", "suffix"])
def test_surrounding_unauthenticated_whitespace_is_rejected(
    valid_raw: str, whitespace: str, position: str
) -> None:
    candidate = (
        whitespace + valid_raw if position == "prefix" else valid_raw + whitespace
    )
    _assert_generic_failure(candidate)


def test_pure_validation_never_calls_backend_io(valid_raw: str) -> None:
    with (
        patch.object(PassphraseVault, "read_raw_vault") as read_backend,
        patch.object(PassphraseVault, "write_raw_vault") as write_backend,
        patch.object(PassphraseVault, "delete_vault_storage") as delete_backend,
    ):
        assert validate_raw_vault(valid_raw, TEST_MASTER) == EXPECTED_ENTRIES

    read_backend.assert_not_called()
    write_backend.assert_not_called()
    delete_backend.assert_not_called()


def test_validation_does_not_change_active_vault(
    tmp_path: Path, valid_raw: str
) -> None:
    active = PassphraseVault(vault_path=str(tmp_path / "active.enc"))
    active.store_passphrase("active-label", "active-value", TEST_MASTER)
    before = active.read_raw_vault()

    candidate = validate_raw_vault(valid_raw, TEST_MASTER)
    candidate["fixture-alpha"] = "locally changed"

    assert active.read_raw_vault() == before
    assert active.retrieve_passphrase("active-label", TEST_MASTER) == "active-value"


def test_active_load_reuses_pure_validator(tmp_path: Path, valid_raw: str) -> None:
    vault = PassphraseVault(vault_path=str(tmp_path / "active.enc"))
    vault.vault_path.write_text(valid_raw, encoding="utf-8")

    with patch(
        "secure_string_cipher.passphrase_manager.validate_raw_vault",
        wraps=validate_raw_vault,
    ) as validator:
        assert vault.list_labels(TEST_MASTER) == sorted(EXPECTED_ENTRIES)

    validator.assert_called_once_with(valid_raw, TEST_MASTER)


def test_errors_and_logs_do_not_expose_candidate_secrets(
    valid_raw: str, caplog: pytest.LogCaptureFixture
) -> None:
    secret_label = "do-not-expose-label"  # pragma: allowlist secret
    secret_value = "do-not-expose-value"  # pragma: allowlist secret
    candidate = _build_raw(json.dumps({secret_label: secret_value}))

    with pytest.raises(ValueError) as caught:
        validate_raw_vault(candidate, WRONG_MASTER)

    exposed = f"{caught.value}\n{caplog.text}"
    assert secret_label not in exposed
    assert secret_value not in exposed
    assert TEST_MASTER not in exposed
    assert WRONG_MASTER not in exposed
    assert valid_raw not in exposed
