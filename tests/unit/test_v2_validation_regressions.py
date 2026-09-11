"""Validation at the mutable-input and expensive-derivation boundaries."""

from types import MappingProxyType
from unittest.mock import patch

import pytest

from secure_string_cipher.v2.envelope import CommitmentDescriptor, canonical_json
from secure_string_cipher.v2.kdf import derive_argon2id
from secure_string_cipher.v2.keywrap import build_projection_w


def test_mapping_proxy_is_copied_before_authentication():
    nested = {"salt": "before"}
    backing = {"alg": "hkdf-sha256", "nested": nested}
    descriptor = CommitmentDescriptor("hmac-sha256", MappingProxyType(backing), "value")
    before = canonical_json(descriptor)
    nested["salt"] = "after"
    backing["alg"] = "changed"
    assert canonical_json(descriptor) == before


@pytest.mark.parametrize("version", [16, 18, True, 19.0, "19"])
def test_unsupported_argon_version_rejected_before_kdf(version):
    with patch("secure_string_cipher.v2.kdf.hash_secret_raw") as kdf:
        with pytest.raises((ValueError, TypeError)):
            derive_argon2id("synthetic", b"s" * 16, version=version)
        kdf.assert_not_called()


def test_projection_rejects_non_string_keys():
    with pytest.raises(TypeError, match="keys must be strings"):
        build_projection_w({1: "must not become a string"})
