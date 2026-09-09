"""AEAD DEK wrapping, grant key commitment, and header projections for SSC v2.

Implements exact projections W, Q, and M_context, transcript computation,
constant-time grant commitment verification, and AEAD DEK wrapping
as specified in SSC v2 Refined Implementation Spec (Section 8).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

from secure_string_cipher.v2.envelope import V2Header, canonical_json
from secure_string_cipher.v2.kdf import (
    derive_combined_grant_keys,
    derive_managed_key_grant_keys,
    derive_password_grant_keys,
)
from secure_string_cipher.v2.vault_schema import b64url_decode, b64url_encode

__all__ = [
    "DekUnwrapError",
    "GrantCommitmentError",
    "KeyWrapError",
    "build_projection_m_context",
    "build_projection_q",
    "build_projection_w",
    "compute_commitment_transcript",
    "compute_grant_commitment",
    "compute_metadata_aad",
    "compute_payload_header_digest",
    "compute_wrap_aad",
    "unwrap_dek_aead",
    "unwrap_dek_from_grant",
    "verify_grant_commitment",
    "wrap_dek_aead",
    "wrap_dek_for_grant",
]


class KeyWrapError(ValueError):
    """Base exception for v2 key wrapping and unwrapping failures."""


class GrantCommitmentError(KeyWrapError):
    """Raised when grant key commitment verification fails."""


class DekUnwrapError(KeyWrapError):
    """Raised when AEAD DEK decryption or authentication fails."""


def _deep_copy_json(value: Any) -> Any:
    """Recursively convert and copy dataclasses and mappings to plain json containers."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        res: dict[str, Any] = {}
        for f in fields(value):
            v = getattr(value, f.name)
            if v is not None:
                res[f.name] = _deep_copy_json(v)
        return res
    if isinstance(value, Mapping):
        if any(not isinstance(k, str) for k in value):
            raise TypeError("Dictionary keys must be strings")
        return {k: _deep_copy_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_deep_copy_json(x) for x in value]
    return value


def build_projection_m_context(header: Mapping[str, Any] | V2Header) -> dict[str, Any]:
    """Construct M_context projection (Section 8.2).

    M_context = {
      format, version, object_id, object_type, payload,
      metadata: metadata container with only ciphertext and tag omitted
    }
    """
    h = _deep_copy_json(header)
    raw_meta = h.get("metadata", {})
    if not isinstance(raw_meta, dict):
        raise TypeError("header metadata must be a dictionary")

    meta = dict(raw_meta)
    meta.pop("ciphertext", None)
    meta.pop("tag", None)

    return {
        "format": h["format"],
        "version": h["version"],
        "object_id": h["object_id"],
        "object_type": h["object_type"],
        "payload": h["payload"],
        "metadata": meta,
    }


def compute_metadata_aad(header: Mapping[str, Any] | V2Header) -> bytes:
    """Compute metadata_aad = b"SSC2/metadata/v1\0" || H(C(M_context))."""
    m_ctx = build_projection_m_context(header)
    h_m = hashlib.sha256(canonical_json(m_ctx)).digest()
    return b"SSC2/metadata/v1\0" + h_m


def build_projection_w(header: Mapping[str, Any] | V2Header) -> dict[str, Any]:
    """Construct projection W (Section 8.2).

    W = complete header with only these fields omitted:
      access.grants[0].wrapped_dek
      access.grants[0].tag
      access.grants[0].commitment.value
    """
    w = _deep_copy_json(header)
    try:
        grants = w["access"]["grants"]
        if not isinstance(grants, list) or len(grants) == 0:
            raise ValueError("access.grants must contain at least one grant")
        grant = grants[0]
        grant.pop("wrapped_dek", None)
        grant.pop("tag", None)
        commitment = grant.get("commitment")
        if isinstance(commitment, dict):
            commitment.pop("value", None)
    except (KeyError, TypeError, IndexError) as e:
        raise ValueError(f"Malformed header structure for projection W: {e}") from e

    assert isinstance(w, dict)
    return w


def compute_wrap_aad(header_or_w: Mapping[str, Any] | V2Header) -> bytes:
    """Compute wrap_aad = b"SSC2/wrap/v1\0" || H(C(W))."""
    if (
        isinstance(header_or_w, Mapping)
        and "access" in header_or_w
        and "grants" in header_or_w["access"]  # type: ignore[index]
        and isinstance(header_or_w["access"]["grants"], list)  # type: ignore[index]
        and len(header_or_w["access"]["grants"]) > 0  # type: ignore[index]
        and "wrapped_dek" not in header_or_w["access"]["grants"][0]  # type: ignore[index]
        and "tag" not in header_or_w["access"]["grants"][0]  # type: ignore[index]
        and (
            "commitment" not in header_or_w["access"]["grants"][0]  # type: ignore[index]
            or "value" not in header_or_w["access"]["grants"][0].get("commitment", {})  # type: ignore[index]
        )
    ):
        w = _deep_copy_json(header_or_w)
    else:
        w = build_projection_w(header_or_w)

    h_w = hashlib.sha256(canonical_json(w)).digest()
    return b"SSC2/wrap/v1\0" + h_w


def build_projection_q(header: Mapping[str, Any] | V2Header) -> dict[str, Any]:
    """Construct projection Q (Section 8.2).

    Q = complete header after DEK wrapping, with only this field omitted:
      access.grants[0].commitment.value
    """
    q = _deep_copy_json(header)
    try:
        grants = q["access"]["grants"]
        if not isinstance(grants, list) or len(grants) == 0:
            raise ValueError("access.grants must contain at least one grant")
        grant = grants[0]
        if "wrapped_dek" not in grant or "tag" not in grant:
            raise ValueError(
                "Projection Q requires wrapped_dek and tag to be populated"
            )
        commitment = grant.get("commitment")
        if isinstance(commitment, dict):
            commitment.pop("value", None)
    except (KeyError, TypeError, IndexError) as e:
        raise ValueError(f"Malformed header structure for projection Q: {e}") from e

    assert isinstance(q, dict)
    return q


def compute_commitment_transcript(header_or_q: Mapping[str, Any] | V2Header) -> bytes:
    """Compute commitment transcript = b"SSC2/commit/v1\0" || H(C(Q))."""
    if (
        isinstance(header_or_q, Mapping)
        and "access" in header_or_q
        and "grants" in header_or_q["access"]  # type: ignore[index]
        and isinstance(header_or_q["access"]["grants"], list)  # type: ignore[index]
        and len(header_or_q["access"]["grants"]) > 0  # type: ignore[index]
        and "wrapped_dek" in header_or_q["access"]["grants"][0]  # type: ignore[index]
        and (
            "commitment" not in header_or_q["access"]["grants"][0]  # type: ignore[index]
            or "value" not in header_or_q["access"]["grants"][0].get("commitment", {})  # type: ignore[index]
        )
    ):
        q = _deep_copy_json(header_or_q)
    else:
        q = build_projection_q(header_or_q)

    h_q = hashlib.sha256(canonical_json(q)).digest()
    return b"SSC2/commit/v1\0" + h_q


def compute_payload_header_digest(header: Mapping[str, Any] | V2Header) -> bytes:
    """Compute payload_header_digest = H(C(complete_header))."""
    return hashlib.sha256(canonical_json(header)).digest()


def wrap_dek_aead(
    dek: bytes,
    kek: bytes,
    wrap_nonce: bytes,
    wrap_aad: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt 32-byte DEK with AES-256-GCM under KEK, wrap_nonce, and wrap_aad.

    Returns:
        tuple of (wrapped_dek_bytes, tag_bytes) (32 bytes, 16 bytes).
    """
    if len(dek) != 32:
        raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    if len(wrap_nonce) != 12:
        raise ValueError(f"wrap_nonce must be 12 bytes, got {len(wrap_nonce)}")

    aesgcm = AESGCM(kek)
    ciphertext_and_tag = aesgcm.encrypt(wrap_nonce, dek, wrap_aad)
    if len(ciphertext_and_tag) != 48:
        raise RuntimeError(
            f"Expected 48 bytes from AESGCM encrypt, got {len(ciphertext_and_tag)}"
        )
    return ciphertext_and_tag[:32], ciphertext_and_tag[32:]


def unwrap_dek_aead(
    wrapped_dek: bytes,
    tag: bytes,
    kek: bytes,
    wrap_nonce: bytes,
    wrap_aad: bytes,
) -> bytes:
    """Decrypt 32-byte DEK with AES-256-GCM and verify tag under wrap_aad."""
    if len(wrapped_dek) != 32:
        raise ValueError(f"wrapped_dek must be 32 bytes, got {len(wrapped_dek)}")
    if len(tag) != 16:
        raise ValueError(f"tag must be 16 bytes, got {len(tag)}")
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    if len(wrap_nonce) != 12:
        raise ValueError(f"wrap_nonce must be 12 bytes, got {len(wrap_nonce)}")

    aesgcm = AESGCM(kek)
    try:
        dek = aesgcm.decrypt(wrap_nonce, wrapped_dek + tag, wrap_aad)
    except Exception as e:
        raise DekUnwrapError("DEK AEAD authentication/unwrapping failed") from e

    if len(dek) != 32:
        raise DekUnwrapError(f"Unwrapped DEK length is {len(dek)}, expected 32")
    return dek


def compute_grant_commitment(
    k_commit: bytes,
    header_or_q: Mapping[str, Any] | V2Header,
) -> str:
    """Compute base64url HMAC-SHA256 grant commitment over transcript Q."""
    if len(k_commit) != 32:
        raise ValueError(f"k_commit must be 32 bytes, got {len(k_commit)}")

    transcript = compute_commitment_transcript(header_or_q)
    h = HMAC(k_commit, hashes.SHA256())
    h.update(transcript)
    return b64url_encode(h.finalize())


def verify_grant_commitment(
    k_commit: bytes,
    header_or_q: Mapping[str, Any] | V2Header,
    expected_commitment_b64: str,
) -> bool:
    """Verify grant commitment using constant-time comparison."""
    if len(k_commit) != 32:
        raise ValueError(f"k_commit must be 32 bytes, got {len(k_commit)}")
    if not isinstance(expected_commitment_b64, str):
        return False

    try:
        expected_bytes = b64url_decode(expected_commitment_b64, expected_length=32)
    except Exception:
        return False

    transcript = compute_commitment_transcript(header_or_q)
    h = HMAC(k_commit, hashes.SHA256())
    h.update(transcript)
    actual_bytes = h.finalize()
    return hmac.compare_digest(actual_bytes, expected_bytes)


def wrap_dek_for_grant(
    header: Mapping[str, Any] | V2Header,
    dek: bytes,
    *,
    password: str | bytes | None = None,
    managed_secret: bytes | None = None,
    wrap_nonce: bytes | None = None,
    strict_profile: bool = True,
) -> dict[str, Any]:
    """Derive keys, wrap DEK, compute commitment, and return updated header dictionary."""
    if len(dek) != 32:
        raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")

    h = _deep_copy_json(header)
    grants = h.get("access", {}).get("grants", [])
    if not isinstance(grants, list) or len(grants) != 1:
        raise ValueError("Header must contain exactly one grant in access.grants")
    grant = grants[0]

    raw_grant_type = grant.get("type")
    grant_type = (
        raw_grant_type.value
        if isinstance(raw_grant_type, Enum)
        else str(raw_grant_type)
    )

    # 1. Nonce handling
    if wrap_nonce is not None:
        if len(wrap_nonce) != 12:
            raise ValueError(f"wrap_nonce must be 12 bytes, got {len(wrap_nonce)}")
        nonce_bytes = wrap_nonce
        grant["wrap_nonce"] = b64url_encode(nonce_bytes)
    elif grant.get("wrap_nonce"):
        nonce_bytes = b64url_decode(grant["wrap_nonce"], expected_length=12)
    else:
        raise ValueError("wrap_nonce must be present in grant or passed explicitly")

    # 2. Extract salts
    kek_desc = grant.get("kek_derivation")
    if not isinstance(kek_desc, dict) or "salt" not in kek_desc:
        raise ValueError("grant kek_derivation.salt is required")
    salt_kek = b64url_decode(kek_desc["salt"], expected_length=32)

    commit_desc = grant.get("commitment")
    if (
        not isinstance(commit_desc, dict)
        or "kdf" not in commit_desc
        or "salt" not in commit_desc["kdf"]
    ):
        raise ValueError("grant commitment.kdf.salt is required")
    salt_commit = b64url_decode(commit_desc["kdf"]["salt"], expected_length=32)

    # 3. Derive keys
    if grant_type == "password":
        if password is None:
            raise ValueError("password is required for password grant")
        if "password_kdf" not in grant:
            raise ValueError("password_kdf is required for password grant")
        r, kek, k_commit = derive_password_grant_keys(
            password=password,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=grant["password_kdf"],
            strict_profile=strict_profile,
        )
    elif grant_type == "managed-key":
        if managed_secret is None:
            raise ValueError("managed_secret is required for managed-key grant")
        r, kek, k_commit = derive_managed_key_grant_keys(
            managed_secret=managed_secret,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
        )
    elif grant_type == "combined-password-managed-key":
        if password is None or managed_secret is None:
            raise ValueError(
                "Both password and managed_secret are required for combined grant"
            )
        if "combined_kdf" not in grant:
            raise ValueError("combined_kdf is required for combined grant")
        if "password_kdf" not in grant:
            raise ValueError("password_kdf is required for combined grant")
        cb_kdf = grant["combined_kdf"]
        salt_mk = b64url_decode(cb_kdf["managed_key_salt"], expected_length=32)
        salt_root = b64url_decode(cb_kdf["salt"], expected_length=32)
        r, kek, k_commit = derive_combined_grant_keys(
            password=password,
            managed_secret=managed_secret,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=grant["password_kdf"],
            strict_profile=strict_profile,
        )
    else:
        raise ValueError(f"Unsupported grant type: {grant_type!r}")

    # 4. Construct W, wrap AAD, encrypt DEK
    w = build_projection_w(h)
    wrap_aad = compute_wrap_aad(w)
    wrapped_dek_bytes, tag_bytes = wrap_dek_aead(
        dek=dek, kek=kek, wrap_nonce=nonce_bytes, wrap_aad=wrap_aad
    )
    grant["wrapped_dek"] = b64url_encode(wrapped_dek_bytes)
    grant["tag"] = b64url_encode(tag_bytes)

    # 5. Construct Q, compute commitment
    q = build_projection_q(h)
    commitment_value = compute_grant_commitment(k_commit=k_commit, header_or_q=q)
    grant["commitment"]["value"] = commitment_value

    assert isinstance(h, dict)
    return h


def unwrap_dek_from_grant(
    header: Mapping[str, Any] | V2Header,
    *,
    password: str | bytes | None = None,
    managed_secret: bytes | None = None,
    strict_profile: bool = True,
) -> bytes:
    """Verify grant commitment and unwrap the 32-byte object DEK.

    Raises:
        GrantCommitmentError: If constant-time commitment verification fails.
        DekUnwrapError: If AEAD decryption or authentication fails.
        ValueError: If parameters or inputs are invalid.
    """
    h = _deep_copy_json(header)
    grants = h.get("access", {}).get("grants", [])
    if not isinstance(grants, list) or len(grants) != 1:
        raise ValueError("Header must contain exactly one grant in access.grants")
    grant = grants[0]

    raw_grant_type = grant.get("type")
    grant_type = (
        raw_grant_type.value
        if isinstance(raw_grant_type, Enum)
        else str(raw_grant_type)
    )

    # 1. Extract salts
    kek_desc = grant.get("kek_derivation")
    if not isinstance(kek_desc, dict) or "salt" not in kek_desc:
        raise ValueError("grant kek_derivation.salt is required")
    salt_kek = b64url_decode(kek_desc["salt"], expected_length=32)

    commit_desc = grant.get("commitment")
    if (
        not isinstance(commit_desc, dict)
        or "kdf" not in commit_desc
        or "salt" not in commit_desc["kdf"]
        or "value" not in commit_desc
    ):
        raise ValueError("grant commitment descriptor with value is required")
    salt_commit = b64url_decode(commit_desc["kdf"]["salt"], expected_length=32)
    expected_commitment = commit_desc["value"]

    # 2. Derive keys
    if grant_type == "password":
        if password is None:
            raise ValueError("password is required for password grant")
        if "password_kdf" not in grant:
            raise ValueError("password_kdf is required for password grant")
        r, kek, k_commit = derive_password_grant_keys(
            password=password,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=grant["password_kdf"],
            strict_profile=strict_profile,
        )
    elif grant_type == "managed-key":
        if managed_secret is None:
            raise ValueError("managed_secret is required for managed-key grant")
        r, kek, k_commit = derive_managed_key_grant_keys(
            managed_secret=managed_secret,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
        )
    elif grant_type == "combined-password-managed-key":
        if password is None or managed_secret is None:
            raise ValueError(
                "Both password and managed_secret are required for combined grant"
            )
        if "combined_kdf" not in grant:
            raise ValueError("combined_kdf is required for combined grant")
        if "password_kdf" not in grant:
            raise ValueError("password_kdf is required for combined grant")
        cb_kdf = grant["combined_kdf"]
        salt_mk = b64url_decode(cb_kdf["managed_key_salt"], expected_length=32)
        salt_root = b64url_decode(cb_kdf["salt"], expected_length=32)
        r, kek, k_commit = derive_combined_grant_keys(
            password=password,
            managed_secret=managed_secret,
            salt_managed_key=salt_mk,
            salt_root=salt_root,
            salt_kek=salt_kek,
            salt_commit=salt_commit,
            password_kdf=grant["password_kdf"],
            strict_profile=strict_profile,
        )
    else:
        raise ValueError(f"Unsupported grant type: {grant_type!r}")

    # 3. Verify commitment BEFORE unwrap (Section 7.4 & 8.2)
    q = build_projection_q(h)
    if not verify_grant_commitment(k_commit, q, expected_commitment):
        raise GrantCommitmentError("Grant commitment verification failed")

    # 4. Unwrap DEK using projection W
    w = build_projection_w(h)
    wrap_aad = compute_wrap_aad(w)

    nonce_bytes = b64url_decode(grant["wrap_nonce"], expected_length=12)
    wrapped_dek_bytes = b64url_decode(grant["wrapped_dek"], expected_length=32)
    tag_bytes = b64url_decode(grant["tag"], expected_length=16)

    return unwrap_dek_aead(
        wrapped_dek=wrapped_dek_bytes,
        tag=tag_bytes,
        kek=kek,
        wrap_nonce=nonce_bytes,
        wrap_aad=wrap_aad,
    )
