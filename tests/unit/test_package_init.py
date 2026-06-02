"""Tests for secure_string_cipher package metadata initialization."""

import importlib
import importlib.metadata
from unittest.mock import patch

import secure_string_cipher


def test_version_falls_back_when_package_metadata_missing():
    """Falls back to a safe default when package metadata is unavailable."""
    with patch(
        "importlib.metadata.version",
        side_effect=importlib.metadata.PackageNotFoundError("secure-string-cipher"),
    ):
        reloaded = importlib.reload(secure_string_cipher)
        assert reloaded.__version__ == "0.0.0"

    importlib.reload(secure_string_cipher)
