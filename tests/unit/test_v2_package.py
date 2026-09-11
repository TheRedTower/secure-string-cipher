"""Tests for the v2 package skeleton."""

import importlib.resources

import secure_string_cipher.v2 as v2

INTENDED_V2_EXPORTS = {
    "decrypt_v2_file",
    "decrypt_v2_text",
    "encrypt_v2_file",
    "encrypt_v2_text",
    "CombinedCredential",
    "KeyCredential",
    "PasswordCredential",
    "V2Credential",
    "V2Header",
    "V2VaultService",
}


def test_v2_package_imports_without_public_api():
    """The v2 package should export exactly its intended public surface."""
    assert set(v2.__all__) == INTENDED_V2_EXPORTS


def test_v2_package_exists_in_source_tree():
    """The v2 package should live under secure_string_cipher."""
    package_init = importlib.resources.files("secure_string_cipher.v2").joinpath(
        "__init__.py"
    )
    assert package_init.is_file()
