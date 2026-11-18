"""Unit tests for SSC v2 Key Derivation Functions (kdf.py)."""

from __future__ import annotations

import os
from typing import Any

import pytest

from secure_string_cipher.v2.envelope import PayloadType
from secure_string_cipher.v2.kdf import (
    INFO_COMBINED_GRANT_KEK,
    INFO_COMBINED_MANAGED_KEY_COMPONENT,
    INFO_COMBINED_ROOT,
    INFO_GRANT_KEY_COMMITMENT,
    INFO_MANAGED_KEY_GRANT_KEK,
    INFO_METADATA_SUBKEY,
    INFO_PASSWORD_GRANT_KEK,
    INFO_PAYLOAD_FILE_SUBKEY,
    INFO_PAYLOAD_TEXT_SUBKEY,
    MAX_PASSWORD_BYTES,
    derive_argon2id,
    derive_combined_grant_keys,
    derive_managed_key_grant_keys,
    derive_metadata_key,
    derive_password_grant_keys,
    derive_payload_key,
    hkdf_sha256,
    validate_argon2_params,
)
from secure_string_cipher.v2.vault_schema import b64url_encode


class TestHkdfSha256:
    """Tests for RFC 5869 HKDF-SHA256."""

    def test_rfc5869_test_case_1(self) -> None:
        """RFC 5869 Test Case 1."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"  # pragma: allowlist secret
        )
        okm = hkdf_sha256(ikm, salt, info, length=42)
        assert okm == expected_okm

    def test_rfc5869_test_case_2(self) -> None:
        """RFC 5869 Test Case 2 (longer inputs/outputs)."""
        ikm = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        )
        salt = bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )
        info = bytes.fromhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )
        expected_okm = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"  # pragma: allowlist secret
            "4f012eda2d4efad8a050cc4c19afa97c"  # pragma: allowlist secret
            "59045a99cac7827271cb41c65e590e09"  # pragma: allowlist secret
            "da3275600c2f09b8367793a9aca3db71"  # pragma: allowlist secret
            "cc30c58179ec3e87c14c01d5c1f3434f"  # pragma: allowlist secret
            "1d87"
        )
        okm = hkdf_sha256(ikm, salt, info, length=82)
        assert okm == expected_okm

    def test_invalid_types_and_bounds(self) -> None:
        """Reject invalid types and lengths."""
        with pytest.raises(TypeError, match="ikm must be bytes"):
            hkdf_sha256("string", b"salt", b"info")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="salt must be bytes"):
            hkdf_sha256(b"ikm", "salt", b"info")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="info must be bytes"):
            hkdf_sha256(b"ikm", b"salt", "info")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="length must be an integer"):
            hkdf_sha256(b"ikm", b"salt", b"info", length="32")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="length must be an integer"):
            hkdf_sha256(b"ikm", b"salt", b"info", length=True)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="length must be between 1 and"):
            hkdf_sha256(b"ikm", b"salt", b"info", length=0)
        with pytest.raises(ValueError, match="length must be between 1 and"):
            hkdf_sha256(b"ikm", b"salt", b"info", length=255 * 32 + 1)


class TestArgon2Validation:
    """Tests for validate_argon2_params."""

    def test_valid_strict_profile(self) -> None:
        """Accept exact V2.0.0 descriptor."""
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }
        validate_argon2_params(desc, strict_profile=True)

    def test_reject_wrong_alg(self) -> None:
        desc = {
            "alg": "argon2i",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }
        with pytest.raises(ValueError, match="Argon2 alg must be 'argon2id'"):
            validate_argon2_params(desc)

    def test_reject_wrong_version(self) -> None:
        desc = {
            "alg": "argon2id",
            "version": 18,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }
        with pytest.raises(ValueError, match="Argon2 version must be 19"):
            validate_argon2_params(desc)

    def test_reject_boolean_parameters(self) -> None:
        """Reject boolean parameters pretending to be integers."""
        for field in ["version", "memory_kib", "time_cost", "parallelism", "hash_len"]:
            desc: dict[str, Any] = {
                "alg": "argon2id",
                "version": 19,
                "memory_kib": 65536,
                "time_cost": 3,
                "parallelism": 4,
                "hash_len": 32,
                "salt": b64url_encode(os.urandom(16)),
            }
            desc[field] = True
            with pytest.raises(TypeError, match="must be an integer"):
                validate_argon2_params(desc)

    def test_strict_profile_deviations(self) -> None:
        """Strict profile rejects non-default values."""
        base = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }
        for k, v in [
            ("memory_kib", 32768),
            ("time_cost", 2),
            ("parallelism", 2),
            ("hash_len", 64),
        ]:
            bad = dict(base, **{k: v})
            with pytest.raises(ValueError):
                validate_argon2_params(bad, strict_profile=True)

    def test_invalid_salt_length(self) -> None:
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(32)),  # 32 bytes instead of 16
        }
        with pytest.raises(ValueError, match="Argon2 salt length must be 16 bytes"):
            validate_argon2_params(desc)

    def test_non_strict_bounds(self) -> None:
        """Non-strict mode validates allowable range."""
        validate_argon2_params(
            descriptor_or_memory=8192,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            salt_len=16,
            strict_profile=False,
        )
        validate_argon2_params(
            descriptor_or_memory=1048576,
            time_cost=100,
            parallelism=16,
            hash_len=32,
            salt_len=16,
            strict_profile=False,
        )
        with pytest.raises(ValueError, match="memory_kib must be between"):
            validate_argon2_params(
                descriptor_or_memory=4096,
                time_cost=3,
                parallelism=4,
                hash_len=32,
                salt_len=16,
                strict_profile=False,
            )
        with pytest.raises(ValueError, match="time_cost must be between"):
            validate_argon2_params(
                descriptor_or_memory=65536,
                time_cost=0,
                parallelism=4,
                hash_len=32,
                salt_len=16,
                strict_profile=False,
            )
        with pytest.raises(ValueError, match="parallelism must be between"):
            validate_argon2_params(
                descriptor_or_memory=65536,
                time_cost=3,
                parallelism=0,
                hash_len=32,
                salt_len=16,
                strict_profile=False,
            )


class TestDeriveArgon2id:
    """Tests for derive_argon2id."""

    def test_derive_argon2id_success(self) -> None:
        salt = os.urandom(16)
        # Use low-cost non-strict profile for fast test execution
        out = derive_argon2id(
            password="test-password",  # pragma: allowlist secret
            salt=salt,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        assert isinstance(out, bytes)
        assert len(out) == 32

        # Deterministic
        out2 = derive_argon2id(
            password="test-password",  # pragma: allowlist secret
            salt=salt,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        assert out == out2

        # Different password produces different key
        out3 = derive_argon2id(
            password="other-password",  # pragma: allowlist secret
            salt=salt,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        assert out != out3

    def test_derive_argon2id_password_bytes(self) -> None:
        salt = os.urandom(16)
        out1 = derive_argon2id(
            password="utf8-password-🔑",  # pragma: allowlist secret
            salt=salt,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        out2 = derive_argon2id(
            password="utf8-password-🔑".encode(),  # pragma: allowlist secret
            salt=salt,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        assert out1 == out2

    def test_derive_argon2id_max_password_length(self) -> None:
        salt = os.urandom(16)
        too_long = "a" * (MAX_PASSWORD_BYTES + 1)
        with pytest.raises(ValueError, match="Password exceeds maximum length"):
            derive_argon2id(
                password=too_long,  # pragma: allowlist secret
                salt=salt,
                memory_kib=8192,
                time_cost=1,
                parallelism=1,
                strict_profile=False,
            )

    def test_derive_argon2id_invalid_types(self) -> None:
        salt = os.urandom(16)
        with pytest.raises(TypeError, match="Password must be str or bytes"):
            derive_argon2id(
                password=12345,  # type: ignore[arg-type]  # pragma: allowlist secret
                salt=salt,
                memory_kib=8192,
                time_cost=1,
                parallelism=1,
                strict_profile=False,
            )
        with pytest.raises(TypeError, match="salt must be bytes"):
            derive_argon2id(
                password="pw",  # pragma: allowlist secret
                salt="string-salt",  # type: ignore[arg-type]
                memory_kib=8192,
                time_cost=1,
                parallelism=1,
                strict_profile=False,
            )


class TestGrantKeyDerivations:
    """Tests for password, managed-key, and combined grant key derivations."""

    def test_password_grant_derivation(self) -> None:
        salt_argon2 = os.urandom(16)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)

        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": b64url_encode(salt_argon2),
        }

        r, kek, k_commit = derive_password_grant_keys(
            password="correct-horse-battery-staple",  # pragma: allowlist secret
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )

        assert len(r) == 32
        assert len(kek) == 32
        assert len(k_commit) == 32
        assert len({r, kek, k_commit}) == 3

        # Invalid salt sizes
        with pytest.raises(ValueError, match="salt_kek must be 32 bytes"):
            derive_password_grant_keys(
                password="pw",  # pragma: allowlist secret
                salt_kek=os.urandom(16),
                salt_commit=salt_commit,
                password_kdf=desc,
                strict_profile=False,
            )
        with pytest.raises(ValueError, match="salt_commit must be 32 bytes"):
            derive_password_grant_keys(
                password="pw",  # pragma: allowlist secret
                salt_kek=salt_kek,
                salt_commit=os.urandom(16),
                password_kdf=desc,
                strict_profile=False,
            )

    def test_managed_key_grant_derivation(self) -> None:
        secret = os.urandom(32)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)

        r, kek, k_commit = derive_managed_key_grant_keys(
            managed_secret=secret,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
        )

        # In managed-key grant, R is exactly K
        assert r == secret
        assert len(kek) == 32
        assert len(k_commit) == 32
        assert len({r, kek, k_commit}) == 3

        with pytest.raises(ValueError, match="managed_secret must be 32 bytes"):
            derive_managed_key_grant_keys(
                managed_secret=os.urandom(16),
                salt_kek=salt_kek,
                salt_commit=salt_commit,
            )

    def test_combined_grant_derivation(self) -> None:
        salt_argon2 = os.urandom(16)
        managed_secret = os.urandom(32)
        salt_managed_key = os.urandom(32)
        salt_root = os.urandom(32)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)

        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": b64url_encode(salt_argon2),
        }

        r, kek, k_commit = derive_combined_grant_keys(
            password="my-strong-password",  # pragma: allowlist secret
            managed_secret=managed_secret,
            salt_managed_key=salt_managed_key,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )

        assert len(r) == 32
        assert len(kek) == 32
        assert len(k_commit) == 32
        assert len({r, kek, k_commit}) == 3

    def test_combined_grant_order_invariant(self) -> None:
        """Verify that P || M order is strictly enforced and changing it alters R."""
        salt_argon2 = os.urandom(16)
        managed_secret = os.urandom(32)
        salt_managed_key = os.urandom(32)
        salt_root = os.urandom(32)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)

        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": b64url_encode(salt_argon2),
        }

        r, _, _ = derive_combined_grant_keys(
            password="password",  # pragma: allowlist secret
            managed_secret=managed_secret,
            salt_managed_key=salt_managed_key,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )

        # Manually compute reversed M || P
        p_bytes = derive_argon2id(
            "password",  # pragma: allowlist secret
            salt=salt_argon2,
            memory_kib=8192,
            time_cost=1,
            parallelism=1,
            strict_profile=False,
        )
        m_bytes = hkdf_sha256(
            managed_secret,
            salt=salt_managed_key,
            info=INFO_COMBINED_MANAGED_KEY_COMPONENT,
            length=32,
        )
        mp = m_bytes + p_bytes
        r_reversed = hkdf_sha256(mp, salt=salt_root, info=INFO_COMBINED_ROOT, length=32)
        assert r != r_reversed

    def test_combined_secrecy(self) -> None:
        """Neither password alone nor key alone can derive combined keys."""
        salt_argon2 = os.urandom(16)
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        salt_mk = os.urandom(32)
        salt_root = os.urandom(32)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)

        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": b64url_encode(salt_argon2),
        }

        r1, kek1, _ = derive_combined_grant_keys(
            password="pass1",  # pragma: allowlist secret
            managed_secret=key1,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )

        # Same key, different password
        r2, kek2, _ = derive_combined_grant_keys(
            password="pass2",  # pragma: allowlist secret
            managed_secret=key1,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )
        assert r1 != r2
        assert kek1 != kek2

        # Same password, different key
        r3, kek3, _ = derive_combined_grant_keys(
            password="pass1",  # pragma: allowlist secret
            managed_secret=key2,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )
        assert r1 != r3
        assert kek1 != kek3


class TestPayloadAndMetadataDerivations:
    """Tests for payload and metadata subkey derivations."""

    def test_payload_derivations(self) -> None:
        dek = os.urandom(32)
        salt = os.urandom(32)

        k_file = derive_payload_key(dek, salt, PayloadType.FILE)
        k_text = derive_payload_key(dek, salt, PayloadType.TEXT)

        assert len(k_file) == 32
        assert len(k_text) == 32
        # File and text keys must be strictly domain separated
        assert k_file != k_text

        # Accepts string payload types
        assert derive_payload_key(dek, salt, "file") == k_file
        assert derive_payload_key(dek, salt, "text") == k_text

        with pytest.raises(ValueError, match="Unsupported payload type"):
            derive_payload_key(dek, salt, "unknown")
        with pytest.raises(TypeError, match="payload_type must be"):
            derive_payload_key(dek, salt, 123)  # type: ignore[arg-type]

    def test_metadata_derivation(self) -> None:
        dek = os.urandom(32)
        salt = os.urandom(32)

        k_meta = derive_metadata_key(dek, salt)
        assert len(k_meta) == 32

        # Domain separation against payload keys
        k_file = derive_payload_key(dek, salt, "file")
        k_text = derive_payload_key(dek, salt, "text")
        assert len({k_meta, k_file, k_text}) == 3

    def test_invalid_sizes(self) -> None:
        salt = os.urandom(32)
        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            derive_payload_key(os.urandom(16), salt, "file")
        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            derive_metadata_key(os.urandom(16), salt)
        with pytest.raises(ValueError, match="salt must be 32 bytes"):
            derive_payload_key(os.urandom(32), os.urandom(16), "file")
        with pytest.raises(ValueError, match="salt must be 32 bytes"):
            derive_metadata_key(os.urandom(32), os.urandom(16))


class TestDomainSeparation:
    """Verify that all protocol info strings are distinct and keys never collide."""

    def test_all_info_strings_unique(self) -> None:
        infos = [
            INFO_PASSWORD_GRANT_KEK,
            INFO_MANAGED_KEY_GRANT_KEK,
            INFO_COMBINED_MANAGED_KEY_COMPONENT,
            INFO_COMBINED_ROOT,
            INFO_COMBINED_GRANT_KEK,
            INFO_GRANT_KEY_COMMITMENT,
            INFO_PAYLOAD_FILE_SUBKEY,
            INFO_PAYLOAD_TEXT_SUBKEY,
            INFO_METADATA_SUBKEY,
        ]
        assert len(infos) == len(set(infos))
        for info in infos:
            assert info.startswith(b"secure-string-cipher/v2/")

    def test_identical_input_produces_different_keks(self) -> None:
        """Even if identical root secret R and salt are used, different grant types yield different KEKs."""
        r = os.urandom(32)
        salt = os.urandom(32)

        kek_pw = hkdf_sha256(r, salt, INFO_PASSWORD_GRANT_KEK)
        kek_mk = hkdf_sha256(r, salt, INFO_MANAGED_KEY_GRANT_KEK)
        kek_cb = hkdf_sha256(r, salt, INFO_COMBINED_GRANT_KEK)
        k_commit = hkdf_sha256(r, salt, INFO_GRANT_KEY_COMMITMENT)

        assert len({kek_pw, kek_mk, kek_cb, k_commit}) == 4


class TestBranchCoverageEdges:
    """Target remaining branch conditions in kdf.py."""

    def test_argon2_salt_bytes_in_descriptor(self) -> None:
        salt = os.urandom(16)
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": salt,
        }
        validate_argon2_params(desc, strict_profile=True)

    def test_argon2_invalid_salt_type_in_descriptor(self) -> None:
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": 12345,
        }
        with pytest.raises(
            TypeError, match="Argon2 salt must be a base64url string or bytes"
        ):
            validate_argon2_params(desc)

    def test_argon2_invalid_version_type(self) -> None:
        desc = {
            "alg": "argon2id",
            "version": "19",
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }
        with pytest.raises(TypeError, match="Argon2 version must be an integer"):
            validate_argon2_params(desc)

    def test_password_grant_with_salt_argon2_and_none(self) -> None:
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)
        salt_argon2 = os.urandom(16)

        # Passing salt_argon2 directly (no password_kdf)
        r, kek, k_commit = derive_password_grant_keys(
            password="pwd",  # pragma: allowlist secret
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            salt_argon2=salt_argon2,
            strict_profile=False,
        )
        assert len(r) == 32

        # Passing neither raises ValueError
        with pytest.raises(
            ValueError, match="Either password_kdf or salt_argon2 must be provided"
        ):
            derive_password_grant_keys(
                password="pwd",  # pragma: allowlist secret
                salt_kek=salt_kek,
                salt_commit=salt_commit,
                strict_profile=False,
            )

    def test_password_grant_with_bytes_salt_in_desc(self) -> None:
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": os.urandom(16),
        }
        r, kek, k_commit = derive_password_grant_keys(
            password="pwd",  # pragma: allowlist secret
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )
        assert len(r) == 32

    def test_combined_grant_edges(self) -> None:
        mk = os.urandom(32)
        salt_mk = os.urandom(32)
        salt_root = os.urandom(32)
        salt_kek = os.urandom(32)
        salt_commit = os.urandom(32)
        salt_argon2 = os.urandom(16)

        # Direct salt_argon2
        r, kek, k_commit = derive_combined_grant_keys(
            password="pwd",  # pragma: allowlist secret
            managed_secret=mk,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            salt_argon2=salt_argon2,
            strict_profile=False,
        )
        assert len(r) == 32

        # Neither password_kdf nor salt_argon2
        with pytest.raises(
            ValueError, match="Either password_kdf or salt_argon2 must be provided"
        ):
            derive_combined_grant_keys(
                password="pwd",  # pragma: allowlist secret
                managed_secret=mk,
                salt_managed_key=salt_mk,
                salt_root=salt_root,
                salt_kek=salt_kek,
                salt_commit=salt_commit,
                strict_profile=False,
            )

        # Invalid salt_managed_key length
        with pytest.raises(ValueError, match="salt_managed_key must be 32 bytes"):
            derive_combined_grant_keys(
                password="pwd",  # pragma: allowlist secret
                managed_secret=mk,
                salt_managed_key=os.urandom(16),
                salt_root=salt_root,
                salt_kek=salt_kek,
                salt_commit=salt_commit,
                salt_argon2=salt_argon2,
                strict_profile=False,
            )

        # Invalid salt_root length
        with pytest.raises(ValueError, match="salt_root must be 32 bytes"):
            derive_combined_grant_keys(
                password="pwd",  # pragma: allowlist secret
                managed_secret=mk,
                salt_managed_key=salt_mk,
                salt_root=os.urandom(16),
                salt_kek=salt_kek,
                salt_commit=salt_commit,
                salt_argon2=salt_argon2,
                strict_profile=False,
            )

        # Combined with bytes salt in password_kdf
        desc = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": os.urandom(16),
        }
        r, _, _ = derive_combined_grant_keys(
            password="pwd",  # pragma: allowlist secret
            managed_secret=mk,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=desc,
            strict_profile=False,
        )
        assert len(r) == 32
