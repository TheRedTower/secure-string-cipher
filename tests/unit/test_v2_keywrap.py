"""Unit and adversarial tests for SSC v2 AEAD DEK wrapping and keywrap.py."""

from __future__ import annotations

import os
from typing import Any

import pytest

from secure_string_cipher.v2.envelope import (
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    CommitmentDescriptor,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
)
from secure_string_cipher.v2.keywrap import (
    DekUnwrapError,
    GrantCommitmentError,
    build_projection_m_context,
    build_projection_q,
    build_projection_w,
    compute_commitment_transcript,
    compute_grant_commitment,
    compute_metadata_aad,
    compute_payload_header_digest,
    compute_wrap_aad,
    unwrap_dek_aead,
    unwrap_dek_from_grant,
    verify_grant_commitment,
    wrap_dek_aead,
    wrap_dek_for_grant,
)
from secure_string_cipher.v2.vault_schema import b64url_decode, b64url_encode


def _create_sample_header_dict(
    grant_type: str = "password",
    include_wrapped: bool = False,
    include_commitment_value: bool = False,
) -> dict[str, Any]:
    """Helper to create a valid v2 header dictionary for testing."""
    grant: dict[str, Any] = {
        "grant_id": "grant-0",
        "type": grant_type,
        "wrap_alg": "aes-256-gcm",
        "wrap_nonce": b64url_encode(os.urandom(12)),
        "kek_derivation": {
            "alg": "hkdf-sha256",
            "salt": b64url_encode(os.urandom(32)),
        },
        "commitment": {
            "alg": "hmac-sha256",
            "kdf": {
                "alg": "hkdf-sha256",
                "salt": b64url_encode(os.urandom(32)),
            },
        },
    }

    if grant_type in ("password", "combined-password-managed-key"):
        grant["password_kdf"] = {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 8192,
            "time_cost": 1,
            "parallelism": 1,
            "hash_len": 32,
            "salt": b64url_encode(os.urandom(16)),
        }

    if grant_type in ("managed-key", "combined-password-managed-key"):
        grant["key_fingerprint"] = "ssc-k1-" + "a" * 52

    if grant_type == "combined-password-managed-key":
        grant["combined_kdf"] = {
            "alg": "hkdf-sha256",
            "salt": b64url_encode(os.urandom(32)),
            "managed_key_salt": b64url_encode(os.urandom(32)),
        }

    if include_wrapped:
        grant["wrapped_dek"] = b64url_encode(os.urandom(32))
        grant["tag"] = b64url_encode(os.urandom(16))

    if include_commitment_value:
        grant["commitment"]["value"] = b64url_encode(os.urandom(32))

    return {
        "format": "SSC2",
        "version": 2,
        "object_id": b64url_encode(os.urandom(16)),
        "object_type": "file",
        "payload": {
            "type": "file",
            "alg": "aes-256-gcm",
            "kdf": {
                "alg": "hkdf-sha256",
                "salt": b64url_encode(os.urandom(32)),
            },
            "metadata_policy": "hidden",
            "chunk_size": 262144,
            "nonce_prefix": b64url_encode(os.urandom(4)),
        },
        "access": {
            "version": 1,
            "policy": "single-grant",
            "grants": [grant],
        },
        "metadata": {
            "policy": "hidden",
        },
    }


class TestHeaderProjections:
    """Tests for projections W, Q, and M_context."""

    def test_projection_w_omissions(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=True
        )
        w = build_projection_w(header)

        g = w["access"]["grants"][0]
        assert "wrapped_dek" not in g
        assert "tag" not in g
        assert "value" not in g["commitment"]

        # Ensure all other fields remain intact
        assert w["format"] == "SSC2"
        assert w["object_id"] == header["object_id"]
        assert g["wrap_nonce"] == header["access"]["grants"][0]["wrap_nonce"]
        assert g["commitment"]["alg"] == "hmac-sha256"

    def test_projection_q_omissions(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=True
        )
        q = build_projection_q(header)

        g = q["access"]["grants"][0]
        # Q MUST retain wrapped_dek and tag
        assert "wrapped_dek" in g
        assert "tag" in g
        assert g["wrapped_dek"] == header["access"]["grants"][0]["wrapped_dek"]
        assert g["tag"] == header["access"]["grants"][0]["tag"]
        # Q MUST omit commitment.value
        assert "value" not in g["commitment"]

    def test_projection_q_requires_wrapped_dek_and_tag(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=False, include_commitment_value=False
        )
        with pytest.raises(
            ValueError, match="Projection Q requires wrapped_dek and tag"
        ):
            build_projection_q(header)

    def test_projection_m_context_omissions(self) -> None:
        header = _create_sample_header_dict()
        header["metadata"] = {
            "policy": "encrypted",
            "alg": "aes-256-gcm",
            "nonce": b64url_encode(os.urandom(12)),
            "ciphertext": b64url_encode(os.urandom(64)),
            "tag": b64url_encode(os.urandom(16)),
        }
        m_ctx = build_projection_m_context(header)

        assert "access" not in m_ctx
        assert m_ctx["metadata"]["policy"] == "encrypted"
        assert m_ctx["metadata"]["nonce"] == header["metadata"]["nonce"]
        assert "ciphertext" not in m_ctx["metadata"]
        assert "tag" not in m_ctx["metadata"]

    def test_aad_transcript_prefixes_and_lengths(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=True
        )
        meta_aad = compute_metadata_aad(header)
        assert meta_aad.startswith(b"SSC2/metadata/v1\0")
        assert len(meta_aad) == len(b"SSC2/metadata/v1\0") + 32

        wrap_aad = compute_wrap_aad(header)
        assert wrap_aad.startswith(b"SSC2/wrap/v1\0")
        assert len(wrap_aad) == len(b"SSC2/wrap/v1\0") + 32

        commit_transcript = compute_commitment_transcript(header)
        assert commit_transcript.startswith(b"SSC2/commit/v1\0")
        assert len(commit_transcript) == len(b"SSC2/commit/v1\0") + 32

        digest = compute_payload_header_digest(header)
        assert len(digest) == 32


class TestDirectAeadWrapUnwrap:
    """Tests for wrap_dek_aead and unwrap_dek_aead."""

    def test_wrap_unwrap_success(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"sample-aad-string"

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        assert len(wrapped) == 32
        assert len(tag) == 16
        assert wrapped != dek

        unwrapped = unwrap_dek_aead(wrapped, tag, kek, nonce, aad)
        assert unwrapped == dek

    def test_tamper_wrapped_dek(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"sample-aad"

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        tampered_wrapped = bytearray(wrapped)
        tampered_wrapped[0] ^= 0x01

        with pytest.raises(
            DekUnwrapError, match="DEK AEAD authentication/unwrapping failed"
        ):
            unwrap_dek_aead(bytes(tampered_wrapped), tag, kek, nonce, aad)

    def test_tamper_tag(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"sample-aad"

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01

        with pytest.raises(DekUnwrapError):
            unwrap_dek_aead(wrapped, bytes(tampered_tag), kek, nonce, aad)

    def test_tamper_nonce(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"sample-aad"

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0x01

        with pytest.raises(DekUnwrapError):
            unwrap_dek_aead(wrapped, tag, kek, bytes(tampered_nonce), aad)

    def test_tamper_aad(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"sample-aad"

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        with pytest.raises(DekUnwrapError):
            unwrap_dek_aead(wrapped, tag, kek, nonce, b"tampered-aad")

    def test_invalid_lengths(self) -> None:
        dek = os.urandom(32)
        kek = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"aad"

        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            wrap_dek_aead(os.urandom(16), kek, nonce, aad)
        with pytest.raises(ValueError, match="KEK must be 32 bytes"):
            wrap_dek_aead(dek, os.urandom(16), nonce, aad)
        with pytest.raises(ValueError, match="wrap_nonce must be 12 bytes"):
            wrap_dek_aead(dek, kek, os.urandom(16), aad)

        wrapped, tag = wrap_dek_aead(dek, kek, nonce, aad)
        with pytest.raises(ValueError, match="wrapped_dek must be 32 bytes"):
            unwrap_dek_aead(os.urandom(16), tag, kek, nonce, aad)
        with pytest.raises(ValueError, match="tag must be 16 bytes"):
            unwrap_dek_aead(wrapped, os.urandom(12), kek, nonce, aad)


class TestDirectGrantCommitment:
    """Tests for compute_grant_commitment and verify_grant_commitment."""

    def test_commitment_success(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=False
        )
        k_commit = os.urandom(32)

        comm = compute_grant_commitment(k_commit, header)
        assert isinstance(comm, str)
        assert len(comm) == 43  # 32 bytes base64url unpadded

        assert verify_grant_commitment(k_commit, header, comm) is True

    def test_commitment_fails_on_wrong_key(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=False
        )
        k_commit1 = os.urandom(32)
        k_commit2 = os.urandom(32)

        comm = compute_grant_commitment(k_commit1, header)
        assert verify_grant_commitment(k_commit2, header, comm) is False

    def test_commitment_fails_on_tampered_transcript(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=False
        )
        k_commit = os.urandom(32)
        comm = compute_grant_commitment(k_commit, header)

        # Tamper header field covered by Q
        tampered_header = dict(header)
        tampered_header["object_id"] = b64url_encode(os.urandom(16))
        assert verify_grant_commitment(k_commit, tampered_header, comm) is False

    def test_commitment_fails_on_invalid_format(self) -> None:
        header = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=False
        )
        k_commit = os.urandom(32)
        assert verify_grant_commitment(k_commit, header, "not-valid-b64!@#$") is False
        assert verify_grant_commitment(k_commit, header, 12345) is False  # type: ignore[arg-type]


class TestHighLevelGrantWrapAndUnwrap:
    """End-to-end grant wrap and unwrap tests across all three grant types."""

    def test_password_grant_roundtrip(self) -> None:
        header = _create_sample_header_dict(grant_type="password")
        dek = os.urandom(32)
        password = "super-secret-password-🔒"  # pragma: allowlist secret

        wrapped_header = wrap_dek_for_grant(
            header,
            dek=dek,
            password=password,  # pragma: allowlist secret
            strict_profile=False,
        )

        grant = wrapped_header["access"]["grants"][0]
        assert "wrapped_dek" in grant
        assert "tag" in grant
        assert "value" in grant["commitment"]

        # Unwrap
        unwrapped_dek = unwrap_dek_from_grant(
            wrapped_header,
            password=password,  # pragma: allowlist secret
            strict_profile=False,
        )
        assert unwrapped_dek == dek

    def test_managed_key_grant_roundtrip(self) -> None:
        header = _create_sample_header_dict(grant_type="managed-key")
        dek = os.urandom(32)
        secret = os.urandom(32)

        wrapped_header = wrap_dek_for_grant(
            header,
            dek=dek,
            managed_secret=secret,
            strict_profile=False,
        )

        unwrapped_dek = unwrap_dek_from_grant(
            wrapped_header,
            managed_secret=secret,
            strict_profile=False,
        )
        assert unwrapped_dek == dek

    def test_combined_grant_roundtrip(self) -> None:
        header = _create_sample_header_dict(grant_type="combined-password-managed-key")
        dek = os.urandom(32)
        password = "combined-password-123"  # pragma: allowlist secret
        secret = os.urandom(32)

        wrapped_header = wrap_dek_for_grant(
            header,
            dek=dek,
            password=password,  # pragma: allowlist secret
            managed_secret=secret,
            strict_profile=False,
        )

        unwrapped_dek = unwrap_dek_from_grant(
            wrapped_header,
            password=password,  # pragma: allowlist secret
            managed_secret=secret,
            strict_profile=False,
        )
        assert unwrapped_dek == dek

    def test_v2header_dataclass_input(self) -> None:
        """Verify that wrap_dek_for_grant works when input is a V2Header dataclass."""
        salt_pw = b64url_encode(os.urandom(16))
        salt_kek = b64url_encode(os.urandom(32))
        salt_commit = b64url_encode(os.urandom(32))
        nonce = b64url_encode(os.urandom(12))

        grant = AccessGrant(
            grant_id="grant-0",
            type=GrantType.PASSWORD,
            kek_derivation={"alg": "hkdf-sha256", "salt": salt_kek},
            wrap_alg="aes-256-gcm",
            wrap_nonce=nonce,
            wrapped_dek=b64url_encode(os.urandom(32)),
            tag=b64url_encode(os.urandom(16)),
            commitment=CommitmentDescriptor(
                alg="hmac-sha256",
                kdf={"alg": "hkdf-sha256", "salt": salt_commit},
                value="",
            ),
            password_kdf={
                "alg": "argon2id",
                "version": 19,
                "memory_kib": 8192,
                "time_cost": 1,
                "parallelism": 1,
                "hash_len": 32,
                "salt": salt_pw,
            },
        )

        v2_header = V2Header(
            format="SSC2",
            version=2,
            object_id=b64url_encode(os.urandom(16)),
            object_type="file",
            payload=PayloadDescriptor(
                type=PayloadType.FILE,
                alg="aes-256-gcm",
                kdf={"alg": "hkdf-sha256", "salt": b64url_encode(os.urandom(32))},
                metadata_policy=MetadataPolicy.HIDDEN,
                chunk_size=262144,
                nonce_prefix=b64url_encode(os.urandom(4)),
            ),
            access=AccessBlock(
                version=1,
                policy=AccessPolicy.SINGLE_GRANT,
                grants=(grant,),
            ),
            metadata={"policy": "hidden"},
        )

        dek = os.urandom(32)
        wrapped_dict = wrap_dek_for_grant(
            v2_header,
            dek=dek,
            password="my-password",  # pragma: allowlist secret
            strict_profile=False,
        )

        unwrapped = unwrap_dek_from_grant(
            wrapped_dict,
            password="my-password",  # pragma: allowlist secret
            strict_profile=False,
        )
        assert unwrapped == dek


class TestAdversarialAndTamperCases:
    """Security and negative tests: modifying transcript, commitment, or credentials."""

    def test_wrong_password_fails_at_commitment(self) -> None:
        header = _create_sample_header_dict(grant_type="password")
        dek = os.urandom(32)
        wrapped = wrap_dek_for_grant(
            header,
            dek=dek,
            password="correct-password",  # pragma: allowlist secret
            strict_profile=False,
        )

        # Verification must fail with GrantCommitmentError before unwrapping
        with pytest.raises(
            GrantCommitmentError, match="Grant commitment verification failed"
        ):
            unwrap_dek_from_grant(
                wrapped,
                password="wrong-password",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_wrong_managed_secret_fails_at_commitment(self) -> None:
        header = _create_sample_header_dict(grant_type="managed-key")
        dek = os.urandom(32)
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        wrapped = wrap_dek_for_grant(
            header, dek=dek, managed_secret=key1, strict_profile=False
        )

        with pytest.raises(
            GrantCommitmentError, match="Grant commitment verification failed"
        ):
            unwrap_dek_from_grant(wrapped, managed_secret=key2, strict_profile=False)

    def test_combined_wrong_password_fails_at_commitment(self) -> None:
        header = _create_sample_header_dict(grant_type="combined-password-managed-key")
        dek = os.urandom(32)
        key = os.urandom(32)
        wrapped = wrap_dek_for_grant(
            header,
            dek=dek,
            password="pw",  # pragma: allowlist secret
            managed_secret=key,
            strict_profile=False,
        )

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="bad-pw",  # pragma: allowlist secret
                managed_secret=key,
                strict_profile=False,
            )

    def test_combined_wrong_key_fails_at_commitment(self) -> None:
        header = _create_sample_header_dict(grant_type="combined-password-managed-key")
        dek = os.urandom(32)
        key = os.urandom(32)
        wrapped = wrap_dek_for_grant(
            header,
            dek=dek,
            password="pw",  # pragma: allowlist secret
            managed_secret=key,
            strict_profile=False,
        )

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="pw",  # pragma: allowlist secret
                managed_secret=os.urandom(32),
                strict_profile=False,
            )

    def test_modified_wrapped_dek_in_header(self) -> None:
        """Modifying wrapped_dek invalidates commitment because Q covers wrapped_dek."""
        header = _create_sample_header_dict(grant_type="password")
        wrapped = wrap_dek_for_grant(
            header,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            strict_profile=False,
        )

        # Tamper wrapped_dek
        orig = b64url_decode(wrapped["access"]["grants"][0]["wrapped_dek"])
        tampered = bytearray(orig)
        tampered[0] ^= 0x01
        wrapped["access"]["grants"][0]["wrapped_dek"] = b64url_encode(bytes(tampered))

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_modified_tag_in_header(self) -> None:
        """Modifying tag invalidates commitment because Q covers tag."""
        header = _create_sample_header_dict(grant_type="password")
        wrapped = wrap_dek_for_grant(
            header,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            strict_profile=False,
        )

        orig = b64url_decode(wrapped["access"]["grants"][0]["tag"])
        tampered = bytearray(orig)
        tampered[0] ^= 0x01
        wrapped["access"]["grants"][0]["tag"] = b64url_encode(bytes(tampered))

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_modified_object_id_in_header(self) -> None:
        header = _create_sample_header_dict(grant_type="password")
        wrapped = wrap_dek_for_grant(
            header,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            strict_profile=False,
        )

        wrapped["object_id"] = b64url_encode(os.urandom(16))

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_modified_commitment_value(self) -> None:
        header = _create_sample_header_dict(grant_type="password")
        wrapped = wrap_dek_for_grant(
            header,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            strict_profile=False,
        )

        wrapped["access"]["grants"][0]["commitment"]["value"] = b64url_encode(
            os.urandom(32)
        )

        with pytest.raises(GrantCommitmentError):
            unwrap_dek_from_grant(
                wrapped,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_missing_credentials(self) -> None:
        header = _create_sample_header_dict(grant_type="password")
        with pytest.raises(ValueError, match="password is required"):
            wrap_dek_for_grant(header, dek=os.urandom(32), strict_profile=False)

        header_mk = _create_sample_header_dict(grant_type="managed-key")
        with pytest.raises(ValueError, match="managed_secret is required"):
            wrap_dek_for_grant(header_mk, dek=os.urandom(32), strict_profile=False)

        header_cb = _create_sample_header_dict(
            grant_type="combined-password-managed-key"
        )
        with pytest.raises(ValueError, match="Both password and managed_secret"):
            wrap_dek_for_grant(header_cb, dek=os.urandom(32), strict_profile=False)


class TestKeywrapEdgeCoverage:
    """Target remaining validation and error branches in keywrap.py."""

    def test_build_projection_m_context_invalid_meta(self) -> None:
        header = _create_sample_header_dict()
        header["metadata"] = "not-a-dict"
        with pytest.raises(TypeError, match="header metadata must be a dictionary"):
            build_projection_m_context(header)

    def test_build_projection_w_malformed_header(self) -> None:
        with pytest.raises(
            ValueError, match="Malformed header structure for projection W"
        ):
            build_projection_w({})
        with pytest.raises(
            ValueError, match="access.grants must contain at least one grant"
        ):
            build_projection_w({"access": {"grants": []}})

    def test_build_projection_q_malformed_header(self) -> None:
        with pytest.raises(
            ValueError, match="Malformed header structure for projection Q"
        ):
            build_projection_q({})
        with pytest.raises(
            ValueError, match="access.grants must contain at least one grant"
        ):
            build_projection_q({"access": {"grants": []}})

    def test_aead_unwrap_invalid_kek_and_nonce_lengths(self) -> None:
        with pytest.raises(ValueError, match="KEK must be 32 bytes"):
            unwrap_dek_aead(
                os.urandom(32), os.urandom(16), os.urandom(16), os.urandom(12), b"aad"
            )
        with pytest.raises(ValueError, match="wrap_nonce must be 12 bytes"):
            unwrap_dek_aead(
                os.urandom(32), os.urandom(16), os.urandom(32), os.urandom(16), b"aad"
            )

    def test_commitment_key_lengths(self) -> None:
        header = _create_sample_header_dict(include_wrapped=True)
        with pytest.raises(ValueError, match="k_commit must be 32 bytes"):
            compute_grant_commitment(os.urandom(16), header)
        with pytest.raises(ValueError, match="k_commit must be 32 bytes"):
            verify_grant_commitment(os.urandom(16), header, "abc")

    def test_wrap_dek_for_grant_validation_errors(self) -> None:
        # Invalid DEK length
        header = _create_sample_header_dict()
        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            wrap_dek_for_grant(
                header,
                dek=os.urandom(16),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Invalid grants count
        with pytest.raises(ValueError, match="Header must contain exactly one grant"):
            wrap_dek_for_grant(
                {"access": {"grants": []}},
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Explicit invalid wrap_nonce length
        with pytest.raises(ValueError, match="wrap_nonce must be 12 bytes"):
            wrap_dek_for_grant(
                header,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                wrap_nonce=os.urandom(16),
                strict_profile=False,
            )

        # Explicit valid wrap_nonce bytes
        custom_nonce = os.urandom(12)
        res_custom = wrap_dek_for_grant(
            header,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            wrap_nonce=custom_nonce,
            strict_profile=False,
        )
        assert res_custom["access"]["grants"][0]["wrap_nonce"] == b64url_encode(
            custom_nonce
        )

        # Existing wrap_nonce in grant used when wrap_nonce argument is None
        h_with_nonce = _create_sample_header_dict()
        pre_nonce = b64url_encode(os.urandom(12))
        h_with_nonce["access"]["grants"][0]["wrap_nonce"] = pre_nonce
        res_h = wrap_dek_for_grant(
            h_with_nonce,
            dek=os.urandom(32),
            password="pw",  # pragma: allowlist secret
            strict_profile=False,
        )
        assert res_h["access"]["grants"][0]["wrap_nonce"] == pre_nonce

        # Missing wrap_nonce
        h_no_nonce = _create_sample_header_dict()
        h_no_nonce["access"]["grants"][0]["wrap_nonce"] = ""
        with pytest.raises(ValueError, match="wrap_nonce must be present in grant"):
            wrap_dek_for_grant(
                h_no_nonce,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Missing kek_derivation salt
        h_no_kek_salt = _create_sample_header_dict()
        del h_no_kek_salt["access"]["grants"][0]["kek_derivation"]["salt"]
        with pytest.raises(ValueError, match="grant kek_derivation.salt is required"):
            wrap_dek_for_grant(
                h_no_kek_salt,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Missing commitment salt
        h_no_commit_salt = _create_sample_header_dict()
        del h_no_commit_salt["access"]["grants"][0]["commitment"]["kdf"]["salt"]
        with pytest.raises(ValueError, match="grant commitment.kdf.salt is required"):
            wrap_dek_for_grant(
                h_no_commit_salt,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Password grant missing password_kdf
        h_no_pw_kdf = _create_sample_header_dict(grant_type="password")
        del h_no_pw_kdf["access"]["grants"][0]["password_kdf"]
        with pytest.raises(
            ValueError, match="password_kdf is required for password grant"
        ):
            wrap_dek_for_grant(
                h_no_pw_kdf,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Combined grant missing combined_kdf
        h_no_cb_kdf = _create_sample_header_dict(
            grant_type="combined-password-managed-key"
        )
        del h_no_cb_kdf["access"]["grants"][0]["combined_kdf"]
        with pytest.raises(
            ValueError, match="combined_kdf is required for combined grant"
        ):
            wrap_dek_for_grant(
                h_no_cb_kdf,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                managed_secret=os.urandom(32),
                strict_profile=False,
            )

        # Combined grant missing password_kdf
        h_no_cb_pw_kdf = _create_sample_header_dict(
            grant_type="combined-password-managed-key"
        )
        del h_no_cb_pw_kdf["access"]["grants"][0]["password_kdf"]
        with pytest.raises(
            ValueError, match="password_kdf is required for combined grant"
        ):
            wrap_dek_for_grant(
                h_no_cb_pw_kdf,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                managed_secret=os.urandom(32),
                strict_profile=False,
            )

        # Unsupported grant type
        h_bad_grant = _create_sample_header_dict()
        h_bad_grant["access"]["grants"][0]["type"] = "quantum-grant"
        with pytest.raises(ValueError, match="Unsupported grant type"):
            wrap_dek_for_grant(
                h_bad_grant,
                dek=os.urandom(32),
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

    def test_unwrap_dek_from_grant_validation_errors(self) -> None:
        # Invalid grants count
        with pytest.raises(ValueError, match="Header must contain exactly one grant"):
            unwrap_dek_from_grant(
                {"access": {"grants": []}},
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Missing kek_derivation salt
        h_no_kek_salt = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=True
        )
        del h_no_kek_salt["access"]["grants"][0]["kek_derivation"]["salt"]
        with pytest.raises(ValueError, match="grant kek_derivation.salt is required"):
            unwrap_dek_from_grant(
                h_no_kek_salt,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Missing commitment descriptor/value
        h_no_commit = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=False
        )
        with pytest.raises(
            ValueError, match="grant commitment descriptor with value is required"
        ):
            unwrap_dek_from_grant(
                h_no_commit,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Password grant missing password or password_kdf
        h_pw = _create_sample_header_dict(
            grant_type="password", include_wrapped=True, include_commitment_value=True
        )
        with pytest.raises(ValueError, match="password is required"):
            unwrap_dek_from_grant(h_pw, strict_profile=False)
        del h_pw["access"]["grants"][0]["password_kdf"]
        with pytest.raises(ValueError, match="password_kdf is required"):
            unwrap_dek_from_grant(
                h_pw,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )

        # Managed-key grant missing managed_secret
        h_mk = _create_sample_header_dict(
            grant_type="managed-key",
            include_wrapped=True,
            include_commitment_value=True,
        )
        with pytest.raises(ValueError, match="managed_secret is required"):
            unwrap_dek_from_grant(h_mk, strict_profile=False)

        # Combined grant missing credentials or descriptors
        h_cb = _create_sample_header_dict(
            grant_type="combined-password-managed-key",
            include_wrapped=True,
            include_commitment_value=True,
        )
        with pytest.raises(ValueError, match="Both password and managed_secret"):
            unwrap_dek_from_grant(
                h_cb,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )
        del h_cb["access"]["grants"][0]["combined_kdf"]
        with pytest.raises(ValueError, match="combined_kdf is required"):
            unwrap_dek_from_grant(
                h_cb,
                password="pw",  # pragma: allowlist secret
                managed_secret=os.urandom(32),
                strict_profile=False,
            )
        h_cb2 = _create_sample_header_dict(
            grant_type="combined-password-managed-key",
            include_wrapped=True,
            include_commitment_value=True,
        )
        del h_cb2["access"]["grants"][0]["password_kdf"]
        with pytest.raises(ValueError, match="password_kdf is required"):
            unwrap_dek_from_grant(
                h_cb2,
                password="pw",  # pragma: allowlist secret
                managed_secret=os.urandom(32),
                strict_profile=False,
            )

        # Unsupported grant type
        h_bad_grant = _create_sample_header_dict(
            include_wrapped=True, include_commitment_value=True
        )
        h_bad_grant["access"]["grants"][0]["type"] = "quantum-grant"
        with pytest.raises(ValueError, match="Unsupported grant type"):
            unwrap_dek_from_grant(
                h_bad_grant,
                password="pw",  # pragma: allowlist secret
                strict_profile=False,
            )
