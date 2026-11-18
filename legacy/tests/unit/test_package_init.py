"""Tests for secure_string_cipher package metadata initialization."""

import importlib
import importlib.metadata
import importlib.resources
from unittest.mock import patch

import secure_string_cipher


def test_version_falls_back_when_package_metadata_missing():
    """Test that __version__ falls back to "0.0.0" when metadata is unavailable."""
    try:
        with patch(
            "importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError,
        ) as mocked_version:
            importlib.reload(secure_string_cipher)
            mocked_version.assert_called_once_with("secure-string-cipher")
            assert secure_string_cipher.__version__ == "0.0.0"
    finally:
        importlib.reload(secure_string_cipher)


def test_package_exposes_py_typed_marker():
    """Test that the package ships its PEP 561 marker."""
    marker = importlib.resources.files("secure_string_cipher").joinpath("py.typed")
    assert marker.is_file()
