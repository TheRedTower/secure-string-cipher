"""Tests for the v2 package's declared public surface.

`secure_string_cipher.v2` is public, semver-covered API, so its `__all__` is
a promise rather than a convenience. These tests make a change to that promise
deliberate: adding or removing a name fails here first.
"""

import importlib.resources
import warnings

import pytest

import secure_string_cipher
import secure_string_cipher.v2 as v2
import secure_string_cipher.v2.app as v2_app

INTENDED_V2_EXPORTS = {
    "decrypt_v2_file",
    "decrypt_v2_text",
    "encrypt_v2_file",
    "encrypt_v2_text",
    "CombinedCredential",
    "KeyCredential",
    "PasswordCredential",
    "V2Credential",
    "KeyFileData",
    "KeyStatus",
    "KeyStorageMode",
    "compute_fingerprint",
    "load_keyfile",
    "save_keyfile",
    "GrantType",
    "V2Header",
    "V2VaultService",
    "app",
}

DEPRECATED_ROOT_EXPORTS = {"colorize", "ProgressBar", "main"}


def test_v2_exports_exactly_its_intended_surface():
    assert set(v2.__all__) == INTENDED_V2_EXPORTS


def test_every_declared_export_actually_resolves():
    """A name in `__all__` that does not import is a broken promise."""
    for name in (*v2.__all__, *v2_app.__all__):
        source = v2_app if name in v2_app.__all__ else v2
        assert hasattr(source, name), f"{name} is declared but missing"


def test_v2_is_reachable_from_the_package_root():
    """Documented as `from secure_string_cipher import v2`, so that must work."""
    assert secure_string_cipher.v2 is v2
    assert "v2" in secure_string_cipher.__all__


def test_the_fingerprint_helper_needs_no_third_level_import():
    """docs/API.md's example imports it from `v2` directly.

    It previously reached into `v2.key_identity`, which told readers that a
    private module was part of the API.
    """
    assert v2.compute_fingerprint(b"\x01" * 32).startswith("ssc-k1-")


def test_v2_package_exists_in_source_tree():
    package_init = importlib.resources.files("secure_string_cipher.v2").joinpath(
        "__init__.py"
    )
    assert package_init.is_file()


class TestDeprecatedRootExports:
    def test_each_one_warns_but_still_works(self):
        for name in DEPRECATED_ROOT_EXPORTS:
            with pytest.warns(DeprecationWarning, match=name):
                assert getattr(secure_string_cipher, name) is not None

    def test_they_stay_in_all_until_the_major_bump(self):
        """Removing them from `__all__` would break `import *` silently.

        The warning is the deprecation signal; the removal is 3.0.0's.
        """
        assert set(secure_string_cipher.__all__) >= DEPRECATED_ROOT_EXPORTS

    def test_importing_the_package_no_longer_loads_the_interactive_cli(self):
        """`main` was the only reason the root imported `cli`.

        Asserted on a subprocess, because this process has almost certainly
        imported `cli` already through some other test.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys, secure_string_cipher; "
                "print('secure_string_cipher.cli' in sys.modules)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "False"

    def test_an_unknown_attribute_still_raises_attribute_error(self):
        """The lazy loader must not turn typos into something else."""
        with pytest.raises(AttributeError, match="no attribute"):
            _ = secure_string_cipher.definitely_not_exported

    def test_a_live_export_does_not_warn(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            assert secure_string_cipher.encrypt_text is not None
            assert secure_string_cipher.secure_overwrite is not None
