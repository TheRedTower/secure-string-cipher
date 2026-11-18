"""Tests for V2 vault migration golden fixtures."""

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from secure_string_cipher.v2.vault_service import V2VaultService

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "v2"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
PRE_MIGRATION_PATH = FIXTURES_DIR / "legacy_vault_pre_migration.json"
POST_MIGRATION_PATH = FIXTURES_DIR / "v2_vault_post_migration.json"


def b64_decode(data: str) -> bytes:
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed != 4:
        data += "=" * padding_needed
    return base64.urlsafe_b64decode(data.encode("ascii"))


@patch("secrets.token_bytes")
def test_migration_golden_fixture(mock_token_bytes: MagicMock, tmp_path: Path) -> None:
    """Verify migration produces the expected canonical output and preserves reserved labels."""
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    vector = manifest["migration"]["flat_to_v2"]
    vault_id_bytes = b64_decode(vector["vault_id"])
    kdf_salt = b64_decode(vector["argon2_salt"])

    # Mock token_bytes to return fixed values for vault_id and kdf_salt
    mock_token_bytes.side_effect = [vault_id_bytes, kdf_salt]

    with open(PRE_MIGRATION_PATH) as f:
        legacy_data = json.load(f)

    with open(POST_MIGRATION_PATH) as f:
        expected_v2_data = json.load(f)

    # Mock vault backend. lock_target must be a real Path/str: migrate_schema
    # takes the real cross-process vault lock around the mutation, and an
    # unconfigured mock attribute here previously derived a bogus lock path
    # from the mock's repr instead of raising (see v2/vault_lock.py).
    mock_vault = MagicMock()
    mock_vault.lock_target = tmp_path / "vault.enc"
    mock_vault._read_document_snapshot.return_value = (
        1,
        legacy_data,
        json.dumps(legacy_data),
    )

    # Instantiate service
    service = V2VaultService(mock_vault)

    # Perform migration
    v2_document = service.migrate_schema("master")

    # Assert save was called
    mock_vault._save_document.assert_called_once()

    # Dump to canonical dict
    actual_v2_data = v2_document.to_dict()

    # Assert
    assert actual_v2_data == expected_v2_data

    # Verify reserved-looking labels survived as passphrase entries
    items_data = actual_v2_data["items"]
    assert isinstance(items_data, dict)
    passphrases_data = items_data["passphrases"]
    assert isinstance(passphrases_data, dict)

    assert "schema_version" in passphrases_data
    assert passphrases_data["schema_version"] == "this-is-a-password"

    assert "vault_meta" in passphrases_data
    assert passphrases_data["vault_meta"] == "also-a-password"

    assert "items" in passphrases_data
    assert passphrases_data["items"] == "yet-another-password"
