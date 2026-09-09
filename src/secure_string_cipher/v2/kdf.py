"""Cryptographic key derivation functions for SSC v2.

Implements RFC 5869 HKDF-SHA256, Argon2id with strict profile boundaries,
and domain-separated derivation for password, managed-key, and combined grants
as specified in SSC v2 Refined Implementation Spec (Section 7).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_string_cipher.v2.envelope import PayloadType
from secure_string_cipher.v2.vault_schema import b64url_decode

__all__ = [
    "ARGON2_DEFAULT_HASH_LEN",
    "ARGON2_DEFAULT_MEMORY_KIB",
    "ARGON2_DEFAULT_PARALLELISM",
    "ARGON2_DEFAULT_SALT_LEN",
    "ARGON2_DEFAULT_TIME_COST",
    "ARGON2_VERSION",
    "INFO_COMBINED_GRANT_KEK",
    "INFO_COMBINED_MANAGED_KEY_COMPONENT",
    "INFO_COMBINED_ROOT",
    "INFO_GRANT_KEY_COMMITMENT",
    "INFO_MANAGED_KEY_GRANT_KEK",
    "INFO_METADATA_SUBKEY",
    "INFO_PASSWORD_GRANT_KEK",
    "INFO_PAYLOAD_FILE_SUBKEY",
    "INFO_PAYLOAD_TEXT_SUBKEY",
    "MAX_PASSWORD_BYTES",
    "derive_argon2id",
    "derive_combined_grant_keys",
    "derive_managed_key_grant_keys",
    "derive_metadata_key",
    "derive_password_grant_keys",
    "derive_payload_key",
    "hkdf_sha256",
    "validate_argon2_params",
]

# Section 7.2 & 5: Resource and Profile Constants
ARGON2_VERSION: int = 19
ARGON2_DEFAULT_MEMORY_KIB: int = 65536
ARGON2_DEFAULT_TIME_COST: int = 3
ARGON2_DEFAULT_PARALLELISM: int = 4
ARGON2_DEFAULT_HASH_LEN: int = 32
ARGON2_DEFAULT_SALT_LEN: int = 16
MAX_PASSWORD_BYTES: int = 65536

# Section 7.3: Protocol Constants for HKDF Info Strings
INFO_PASSWORD_GRANT_KEK: bytes = (
    b"secure-string-cipher/v2/password/dek-wrap/aes-256-gcm"
)
INFO_MANAGED_KEY_GRANT_KEK: bytes = (
    b"secure-string-cipher/v2/managed-key/dek-wrap/aes-256-gcm"
)
INFO_COMBINED_MANAGED_KEY_COMPONENT: bytes = (
    b"secure-string-cipher/v2/combined/managed-key-component"
)
INFO_COMBINED_ROOT: bytes = (
    b"secure-string-cipher/v2/combined/password+managed-key/root"
)
INFO_COMBINED_GRANT_KEK: bytes = (
    b"secure-string-cipher/v2/combined/password+managed-key/dek-wrap/aes-256-gcm"
)
INFO_GRANT_KEY_COMMITMENT: bytes = (
    b"secure-string-cipher/v2/grant/key-commitment/hmac-sha256"
)
INFO_PAYLOAD_FILE_SUBKEY: bytes = b"secure-string-cipher/v2/payload/aes-256-gcm/chunked"
INFO_PAYLOAD_TEXT_SUBKEY: bytes = b"secure-string-cipher/v2/payload/aes-256-gcm/text"
INFO_METADATA_SUBKEY: bytes = b"secure-string-cipher/v2/metadata/aes-256-gcm"


def hkdf_sha256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """Derive bytes using RFC 5869 HKDF-SHA256 (Extract-and-Expand)."""
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError(f"ikm must be bytes or bytearray, got {type(ikm).__name__}")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes or bytearray, got {type(salt).__name__}")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError(f"info must be bytes or bytearray, got {type(info).__name__}")
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError(f"length must be an integer, got {type(length).__name__}")
    if length <= 0 or length > 255 * 32:
        raise ValueError(f"length must be between 1 and {255 * 32}, got {length}")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def validate_argon2_params(
    descriptor_or_memory: Mapping[str, Any] | int,
    time_cost: int | None = None,
    parallelism: int | None = None,
    hash_len: int | None = None,
    salt_len: int | None = None,
    version: int | None = None,
    *,
    strict_profile: bool = True,
) -> None:
    """Validate Argon2id parameters against spec and safety boundaries."""
    if isinstance(descriptor_or_memory, Mapping):
        desc = descriptor_or_memory
        alg = desc.get("alg")
        if alg != "argon2id":
            raise ValueError(f"Argon2 alg must be 'argon2id', got {alg!r}")

        v = desc.get("version")
        if isinstance(v, bool) or not isinstance(v, int):
            raise TypeError("Argon2 version must be an integer")
        if v != ARGON2_VERSION:
            raise ValueError(f"Argon2 version must be {ARGON2_VERSION}, got {v}")

        mem: object = desc.get("memory_kib")
        tc: object = desc.get("time_cost")
        p: object = desc.get("parallelism")
        hl: object = desc.get("hash_len")
        raw_salt = desc.get("salt")

        if isinstance(raw_salt, str):
            salt_b = b64url_decode(raw_salt)
            sl: object = len(salt_b)
        elif isinstance(raw_salt, (bytes, bytearray)):
            sl = len(raw_salt)
        else:
            raise TypeError(
                f"Argon2 salt must be a base64url string or bytes, got {type(raw_salt).__name__}"
            )
    else:
        mem = descriptor_or_memory
        tc = time_cost
        p = parallelism
        hl = hash_len
        sl = salt_len
        v = version if version is not None else ARGON2_VERSION

    # Type checks (strictly int, no bool)
    for name, val in [
        ("memory_kib", mem),
        ("time_cost", tc),
        ("parallelism", p),
        ("hash_len", hl),
        ("salt_len", sl),
    ]:
        if isinstance(val, bool) or not isinstance(val, int):
            raise TypeError(
                f"Argon2 {name} must be an integer, got {type(val).__name__}"
            )

    assert isinstance(mem, int)
    assert isinstance(tc, int)
    assert isinstance(p, int)
    assert isinstance(hl, int)
    assert isinstance(sl, int)

    if strict_profile:
        if mem != ARGON2_DEFAULT_MEMORY_KIB:
            raise ValueError(
                f"Argon2 memory_kib must be {ARGON2_DEFAULT_MEMORY_KIB}, got {mem}"
            )
        if tc != ARGON2_DEFAULT_TIME_COST:
            raise ValueError(
                f"Argon2 time_cost must be {ARGON2_DEFAULT_TIME_COST}, got {tc}"
            )
        if p != ARGON2_DEFAULT_PARALLELISM:
            raise ValueError(
                f"Argon2 parallelism must be {ARGON2_DEFAULT_PARALLELISM}, got {p}"
            )
        if hl != ARGON2_DEFAULT_HASH_LEN:
            raise ValueError(
                f"Argon2 hash_len must be {ARGON2_DEFAULT_HASH_LEN}, got {hl}"
            )
        if sl != ARGON2_DEFAULT_SALT_LEN:
            raise ValueError(
                f"Argon2 salt length must be {ARGON2_DEFAULT_SALT_LEN} bytes, got {sl}"
            )
    else:
        # Broad bounds check for parameter exploration / allowlist testing
        if mem < 8192 or mem > 1048576:
            raise ValueError(
                f"Argon2 memory_kib must be between 8192 and 1048576, got {mem}"
            )
        if tc < 1 or tc > 100:
            raise ValueError(f"Argon2 time_cost must be between 1 and 100, got {tc}")
        if p < 1 or p > 16:
            raise ValueError(f"Argon2 parallelism must be between 1 and 16, got {p}")
        if hl != ARGON2_DEFAULT_HASH_LEN:
            raise ValueError(
                f"Argon2 hash_len must be {ARGON2_DEFAULT_HASH_LEN}, got {hl}"
            )
        if sl != ARGON2_DEFAULT_SALT_LEN:
            raise ValueError(
                f"Argon2 salt length must be {ARGON2_DEFAULT_SALT_LEN} bytes, got {sl}"
            )


def derive_argon2id(
    password: str | bytes,
    salt: bytes,
    *,
    memory_kib: int = ARGON2_DEFAULT_MEMORY_KIB,
    time_cost: int = ARGON2_DEFAULT_TIME_COST,
    parallelism: int = ARGON2_DEFAULT_PARALLELISM,
    hash_len: int = ARGON2_DEFAULT_HASH_LEN,
    version: int = ARGON2_VERSION,
    strict_profile: bool = True,
) -> bytes:
    """Derive key material using Argon2id with Type.ID and version 19."""
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        password_bytes = password
    else:
        raise TypeError(f"Password must be str or bytes, got {type(password).__name__}")

    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password exceeds maximum length of {MAX_PASSWORD_BYTES} bytes"
        )

    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes, got {type(salt).__name__}")

    validate_argon2_params(
        descriptor_or_memory=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=len(salt),
        version=version,
        strict_profile=strict_profile,
    )

    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
        version=version,
    )


def derive_password_grant_keys(
    password: str | bytes,
    salt_kek: bytes,
    salt_commit: bytes,
    password_kdf: Mapping[str, Any] | None = None,
    *,
    salt_argon2: bytes | None = None,
    strict_profile: bool = True,
) -> tuple[bytes, bytes, bytes]:
    """Derive R, KEK, and K_commit for a Password Grant.

    Returns:
        tuple of (R, KEK, K_commit), each 32 bytes.
    """
    if len(salt_kek) != 32:
        raise ValueError(f"salt_kek must be 32 bytes, got {len(salt_kek)}")
    if len(salt_commit) != 32:
        raise ValueError(f"salt_commit must be 32 bytes, got {len(salt_commit)}")

    if password_kdf is not None:
        validate_argon2_params(password_kdf, strict_profile=strict_profile)
        salt_raw = password_kdf["salt"]
        if isinstance(salt_raw, str):
            argon2_salt = b64url_decode(salt_raw, expected_length=16)
        else:
            argon2_salt = bytes(salt_raw)
        mem = int(password_kdf.get("memory_kib", ARGON2_DEFAULT_MEMORY_KIB))  # type: ignore[arg-type]
        tc = int(password_kdf.get("time_cost", ARGON2_DEFAULT_TIME_COST))  # type: ignore[arg-type]
        p = int(password_kdf.get("parallelism", ARGON2_DEFAULT_PARALLELISM))  # type: ignore[arg-type]
        hl = int(password_kdf.get("hash_len", ARGON2_DEFAULT_HASH_LEN))  # type: ignore[arg-type]
        ver = int(password_kdf.get("version", ARGON2_VERSION))  # type: ignore[arg-type]
    elif salt_argon2 is not None:
        argon2_salt = salt_argon2
        mem = ARGON2_DEFAULT_MEMORY_KIB
        tc = ARGON2_DEFAULT_TIME_COST
        p = ARGON2_DEFAULT_PARALLELISM
        hl = ARGON2_DEFAULT_HASH_LEN
        ver = ARGON2_VERSION
    else:
        raise ValueError("Either password_kdf or salt_argon2 must be provided")

    r = derive_argon2id(
        password=password,
        salt=argon2_salt,
        memory_kib=mem,
        time_cost=tc,
        parallelism=p,
        hash_len=hl,
        version=ver,
        strict_profile=strict_profile,
    )
    kek = hkdf_sha256(r, salt=salt_kek, info=INFO_PASSWORD_GRANT_KEK, length=32)
    k_commit = hkdf_sha256(
        r, salt=salt_commit, info=INFO_GRANT_KEY_COMMITMENT, length=32
    )
    return r, kek, k_commit


def derive_managed_key_grant_keys(
    managed_secret: bytes,
    salt_kek: bytes,
    salt_commit: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Derive R, KEK, and K_commit for a Managed-Key Grant.

    Returns:
        tuple of (R, KEK, K_commit), each 32 bytes.
    """
    if len(managed_secret) != 32:
        raise ValueError(f"managed_secret must be 32 bytes, got {len(managed_secret)}")
    if len(salt_kek) != 32:
        raise ValueError(f"salt_kek must be 32 bytes, got {len(salt_kek)}")
    if len(salt_commit) != 32:
        raise ValueError(f"salt_commit must be 32 bytes, got {len(salt_commit)}")

    r = managed_secret
    kek = hkdf_sha256(r, salt=salt_kek, info=INFO_MANAGED_KEY_GRANT_KEK, length=32)
    k_commit = hkdf_sha256(
        r, salt=salt_commit, info=INFO_GRANT_KEY_COMMITMENT, length=32
    )
    return r, kek, k_commit


def derive_combined_grant_keys(
    password: str | bytes,
    managed_secret: bytes,
    salt_managed_key: bytes,
    salt_root: bytes,
    salt_kek: bytes,
    salt_commit: bytes,
    password_kdf: Mapping[str, Any] | None = None,
    *,
    salt_argon2: bytes | None = None,
    strict_profile: bool = True,
) -> tuple[bytes, bytes, bytes]:
    """Derive R, KEK, and K_commit for a Combined Grant.

    M = HKDF(K, managed_key_salt, INFO_COMBINED_MANAGED_KEY_COMPONENT)
    P = Argon2id(password, password_kdf)
    R = HKDF(P || M, combined_kdf.salt, INFO_COMBINED_ROOT)
    KEK = HKDF(R, kek_derivation.salt, INFO_COMBINED_GRANT_KEK)
    K_commit = HKDF(R, commitment.kdf.salt, INFO_GRANT_KEY_COMMITMENT)

    Returns:
        tuple of (R, KEK, K_commit), each 32 bytes.
    """
    if len(managed_secret) != 32:
        raise ValueError(f"managed_secret must be 32 bytes, got {len(managed_secret)}")
    if len(salt_managed_key) != 32:
        raise ValueError(
            f"salt_managed_key must be 32 bytes, got {len(salt_managed_key)}"
        )
    if len(salt_root) != 32:
        raise ValueError(f"salt_root must be 32 bytes, got {len(salt_root)}")
    if len(salt_kek) != 32:
        raise ValueError(f"salt_kek must be 32 bytes, got {len(salt_kek)}")
    if len(salt_commit) != 32:
        raise ValueError(f"salt_commit must be 32 bytes, got {len(salt_commit)}")

    if password_kdf is not None:
        validate_argon2_params(password_kdf, strict_profile=strict_profile)
        salt_raw = password_kdf["salt"]
        if isinstance(salt_raw, str):
            argon2_salt = b64url_decode(salt_raw, expected_length=16)
        else:
            argon2_salt = bytes(salt_raw)
        mem = int(password_kdf.get("memory_kib", ARGON2_DEFAULT_MEMORY_KIB))  # type: ignore[arg-type]
        tc = int(password_kdf.get("time_cost", ARGON2_DEFAULT_TIME_COST))  # type: ignore[arg-type]
        p = int(password_kdf.get("parallelism", ARGON2_DEFAULT_PARALLELISM))  # type: ignore[arg-type]
        hl = int(password_kdf.get("hash_len", ARGON2_DEFAULT_HASH_LEN))  # type: ignore[arg-type]
        ver = int(password_kdf.get("version", ARGON2_VERSION))  # type: ignore[arg-type]
    elif salt_argon2 is not None:
        argon2_salt = salt_argon2
        mem = ARGON2_DEFAULT_MEMORY_KIB
        tc = ARGON2_DEFAULT_TIME_COST
        p = ARGON2_DEFAULT_PARALLELISM
        hl = ARGON2_DEFAULT_HASH_LEN
        ver = ARGON2_VERSION
    else:
        raise ValueError("Either password_kdf or salt_argon2 must be provided")

    p_bytes = derive_argon2id(
        password=password,
        salt=argon2_salt,
        memory_kib=mem,
        time_cost=tc,
        parallelism=p,
        hash_len=hl,
        version=ver,
        strict_profile=strict_profile,
    )
    m_bytes = hkdf_sha256(
        managed_secret,
        salt=salt_managed_key,
        info=INFO_COMBINED_MANAGED_KEY_COMPONENT,
        length=32,
    )

    if len(p_bytes) != 32 or len(m_bytes) != 32:
        raise RuntimeError("Internal derivation length invariant violated")

    pm = p_bytes + m_bytes
    if len(pm) != 64:
        raise RuntimeError("P || M must be exactly 64 bytes")

    r = hkdf_sha256(pm, salt=salt_root, info=INFO_COMBINED_ROOT, length=32)
    kek = hkdf_sha256(r, salt=salt_kek, info=INFO_COMBINED_GRANT_KEK, length=32)
    k_commit = hkdf_sha256(
        r, salt=salt_commit, info=INFO_GRANT_KEY_COMMITMENT, length=32
    )
    return r, kek, k_commit


def derive_payload_key(
    dek: bytes,
    salt: bytes,
    payload_type: PayloadType | str,
) -> bytes:
    """Derive the payload subkey K_payload from the object DEK."""
    if len(dek) != 32:
        raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")
    if len(salt) != 32:
        raise ValueError(f"payload KDF salt must be 32 bytes, got {len(salt)}")

    if isinstance(payload_type, PayloadType):
        pt_str = payload_type.value
    elif isinstance(payload_type, str):
        pt_str = payload_type
    else:
        raise TypeError(
            f"payload_type must be PayloadType or str, got {type(payload_type).__name__}"
        )

    if pt_str == "file":
        info = INFO_PAYLOAD_FILE_SUBKEY
    elif pt_str == "text":
        info = INFO_PAYLOAD_TEXT_SUBKEY
    else:
        raise ValueError(f"Unsupported payload type: {pt_str!r}")

    return hkdf_sha256(dek, salt=salt, info=info, length=32)


def derive_metadata_key(
    dek: bytes,
    salt: bytes,
) -> bytes:
    """Derive the metadata subkey K_metadata from the object DEK."""
    if len(dek) != 32:
        raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")
    if len(salt) != 32:
        raise ValueError(f"metadata KDF salt must be 32 bytes, got {len(salt)}")

    return hkdf_sha256(dek, salt=salt, info=INFO_METADATA_SUBKEY, length=32)
