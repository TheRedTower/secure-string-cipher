"""Tests for V2 keyfile golden fixtures."""

import hashlib
import json
from pathlib import Path

from secure_string_cipher.v2.key_identity import compute_fingerprint
from secure_string_cipher.v2.keyfile import (
    parse_keyfile_content,
    serialize_keyfile_content,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "v2"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
KEYFILE_PATH = FIXTURES_DIR / "test-key.ssckey"


def test_keyfile_golden_roundtrip():
    """Verify keyfile parses correctly and round-trips to byte-identical output."""
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    vector = manifest["keyfile"]["round_trip"]
    expected_content = vector["content"]
    expected_fingerprint = vector["fingerprint"]
    expected_sha256 = vector["sha256"]

    # Verify file matches manifest
    actual_content = KEYFILE_PATH.read_text(encoding="utf-8")
    assert actual_content == expected_content

    # Verify SHA-256
    actual_sha256 = hashlib.sha256(actual_content.encode("utf-8")).hexdigest()
    assert actual_sha256 == expected_sha256

    # Parse keyfile
    parsed = parse_keyfile_content(actual_content)

    # Verify fingerprint computation
    computed_fingerprint = compute_fingerprint(parsed.secret_bytes)
    assert computed_fingerprint == expected_fingerprint
    assert parsed.fingerprint == expected_fingerprint

    # Verify serialization
    serialized = serialize_keyfile_content(parsed)
    assert serialized == actual_content
