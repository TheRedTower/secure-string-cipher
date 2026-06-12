"""Tests for the v2 package skeleton."""

import importlib.resources

import secure_string_cipher.v2 as v2


def test_v2_package_imports_without_public_api():
    """The v2 package should import before implementation modules are added."""
    assert v2.__all__ == []


def test_v2_package_exists_in_source_tree():
    """The v2 package should live under secure_string_cipher."""
    package_init = importlib.resources.files("secure_string_cipher.v2").joinpath(
        "__init__.py"
    )
    assert package_init.is_file()
