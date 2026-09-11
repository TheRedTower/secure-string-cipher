"""V2 encrypt orchestrator — wires together writer order from spec §8.2.

Public API:
    encrypt_v2_file(input_path, output_path, credential, ...)
    encrypt_v2_text(plaintext, credential) -> str

Credential types:
    PasswordCredential, KeyCredential, CombinedCredential
"""

from __future__ import annotations

import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secure_string_cipher.secure_memory import SecureBytes
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.envelope import (
    MAX_PLAINTEXT_FILE_SIZE,
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    CommitmentDescriptor,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
    canonical_json,
)
from secure_string_cipher.v2.keywrap import (
    wrap_dek_for_grant,
)
from secure_string_cipher.v2.message import encrypt_message
from secure_string_cipher.v2.metadata import encrypt_metadata
from secure_string_cipher.v2.output import safe_atomic_output, validate_path_safety
from secure_string_cipher.v2.payload import FrameWriter
from secure_string_cipher.v2.vault_schema import b64url_encode

__all__ = [
    "CombinedCredential",
    "KeyCredential",
    "PasswordCredential",
    "V2Credential",
    "encrypt_v2_file",
    "encrypt_v2_text",
]


# ---------------------------------------------------------------------------
# Credential types (Decision G18)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PasswordCredential:
    """Password-only grant credential."""

    passphrase: str | SecureBytes


@dataclass(frozen=True, slots=True)
class KeyCredential:
    """Managed-key-only grant credential."""

    key_fingerprint: str
    managed_secret: bytes | SecureBytes


@dataclass(frozen=True, slots=True)
class CombinedCredential:
    """Combined password + managed-key grant credential."""

    passphrase: str | SecureBytes
    key_fingerprint: str
    managed_secret: bytes | SecureBytes


V2Credential = PasswordCredential | KeyCredential | CombinedCredential


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CHUNK_SIZE = 65536
_MAX_TEXT_SIZE = 1048576  # 1 MiB — spec §8.1 text limit
_ARGON2_DEFAULTS: dict[str, object] = {
    "alg": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "time_cost": 3,
    "parallelism": 4,
    "hash_len": 32,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_salts() -> dict[str, bytes]:
    """Generate all per-object cryptographic salts."""
    return {
        "payload_kdf_salt": secrets.token_bytes(32),
        "metadata_kdf_salt": secrets.token_bytes(32),
        "kek_salt": secrets.token_bytes(32),
        "commitment_salt": secrets.token_bytes(32),
        "argon2_salt": secrets.token_bytes(16),
        "combined_managed_key_salt": secrets.token_bytes(32),
        "combined_root_salt": secrets.token_bytes(32),
    }


def _build_grant_skeleton(
    credential: V2Credential,
    salts: dict[str, bytes],
) -> AccessGrant:
    """Build an AccessGrant skeleton with placeholder wrapped_dek/tag/commitment."""
    kek_derivation: dict[str, object] = {
        "alg": "hkdf-sha256",
        "salt": b64url_encode(salts["kek_salt"]),
    }

    commitment_kdf: dict[str, object] = {
        "alg": "hkdf-sha256",
        "salt": b64url_encode(salts["commitment_salt"]),
    }

    commitment = CommitmentDescriptor(
        alg="hmac-sha256",
        kdf=commitment_kdf,
        value="",  # placeholder — filled by wrap_dek_for_grant
    )

    wrap_nonce = secrets.token_bytes(12)

    if isinstance(credential, PasswordCredential):
        password_kdf: dict[str, object] = {
            **_ARGON2_DEFAULTS,
            "salt": b64url_encode(salts["argon2_salt"]),
        }
        return AccessGrant(
            grant_id="grant-0",
            type=GrantType.PASSWORD,
            kek_derivation=kek_derivation,
            wrap_alg="aes-256-gcm",
            wrap_nonce=b64url_encode(wrap_nonce),
            wrapped_dek="",  # placeholder
            tag="",  # placeholder
            commitment=commitment,
            password_kdf=password_kdf,
        )

    if isinstance(credential, KeyCredential):
        return AccessGrant(
            grant_id="grant-0",
            type=GrantType.MANAGED_KEY,
            kek_derivation=kek_derivation,
            wrap_alg="aes-256-gcm",
            wrap_nonce=b64url_encode(wrap_nonce),
            wrapped_dek="",  # placeholder
            tag="",  # placeholder
            commitment=commitment,
            key_fingerprint=credential.key_fingerprint,
        )

    if isinstance(credential, CombinedCredential):
        password_kdf_combined: dict[str, object] = {
            **_ARGON2_DEFAULTS,
            "salt": b64url_encode(salts["argon2_salt"]),
        }
        combined_kdf: dict[str, object] = {
            "alg": "hkdf-sha256",
            "salt": b64url_encode(salts["combined_root_salt"]),
            "managed_key_salt": b64url_encode(salts["combined_managed_key_salt"]),
        }
        return AccessGrant(
            grant_id="grant-0",
            type=GrantType.COMBINED_PASSWORD_MANAGED_KEY,
            kek_derivation=kek_derivation,
            wrap_alg="aes-256-gcm",
            wrap_nonce=b64url_encode(wrap_nonce),
            wrapped_dek="",  # placeholder
            tag="",  # placeholder
            commitment=commitment,
            key_fingerprint=credential.key_fingerprint,
            password_kdf=password_kdf_combined,
            combined_kdf=combined_kdf,
        )

    raise TypeError(f"Unsupported credential type: {type(credential).__name__}")


def _credential_to_wrap_kwargs(credential: V2Credential) -> dict[str, Any]:
    """Extract wrap_dek_for_grant keyword arguments from a typed credential."""

    def _extract(val: Any) -> bytes | str:
        return bytes(val.data) if isinstance(val, SecureBytes) else val

    if isinstance(credential, PasswordCredential):
        return {"password": _extract(credential.passphrase)}
    if isinstance(credential, KeyCredential):
        return {"managed_secret": _extract(credential.managed_secret)}
    if isinstance(credential, CombinedCredential):
        return {
            "password": _extract(credential.passphrase),
            "managed_secret": _extract(credential.managed_secret),
        }
    raise TypeError(f"Unsupported credential type: {type(credential).__name__}")


def _build_v2_header(
    credential: V2Credential,
    dek: bytes,
    payload_descriptor: PayloadDescriptor,
    metadata_block: dict[str, object],
    object_id_b64: str,
) -> V2Header:
    """Build a complete V2Header with wrapped DEK and commitment.

    Steps (spec §8.2):
    1. Build skeleton header with placeholder grant fields.
    2. If metadata is encrypted, encrypt it and fill ciphertext/tag.
    3. Call wrap_dek_for_grant to derive keys, wrap DEK, compute commitment.
    4. Reconstruct the final frozen V2Header.
    """
    salts = _generate_salts()

    # Build grant skeleton
    grant = _build_grant_skeleton(credential, salts)
    access = AccessBlock(
        version=1,
        policy=AccessPolicy.SINGLE_GRANT,
        grants=[grant],
    )

    # Build initial header (with placeholder grant fields)
    header = V2Header(
        format="SSC2",
        version=2,
        object_id=object_id_b64,
        object_type=payload_descriptor.type.value,
        payload=payload_descriptor,
        access=access,
        metadata=metadata_block,
    )

    # Step 2: Encrypt metadata if policy is encrypted
    if metadata_block.get("policy") == MetadataPolicy.ENCRYPTED.value:
        original_filename = metadata_block.get("_original_filename")
        original_size = metadata_block.get("_original_size")

        # Strip internal-only keys before building the actual metadata block
        clean_meta: dict[str, object] = {
            k: v for k, v in metadata_block.items() if not k.startswith("_")
        }

        # Re-create header with clean metadata for M_context computation
        header = V2Header(
            format="SSC2",
            version=2,
            object_id=object_id_b64,
            object_type=payload_descriptor.type.value,
            payload=payload_descriptor,
            access=access,
            metadata=clean_meta,
        )

        orig_size_val: int | None = None
        if original_size is not None:
            if not isinstance(original_size, (int, str, float)):
                raise TypeError("_original_size must be castable to int")
            orig_size_val = int(original_size)

        ct, tag = encrypt_metadata(
            header,
            dek,
            original_filename=str(original_filename) if original_filename else None,
            original_size=orig_size_val,
        )

        # Update metadata with ciphertext and tag
        clean_meta["ciphertext"] = b64url_encode(ct)
        clean_meta["tag"] = b64url_encode(tag)

        header = V2Header(
            format="SSC2",
            version=2,
            object_id=object_id_b64,
            object_type=payload_descriptor.type.value,
            payload=payload_descriptor,
            access=access,
            metadata=clean_meta,
        )

    # Steps 3–5: Wrap DEK and compute commitment via keywrap
    wrap_kwargs = _credential_to_wrap_kwargs(credential)
    wrapped_header_dict = wrap_dek_for_grant(header, dek, **wrap_kwargs)

    # Step 6: Reconstruct frozen V2Header from the wrapped dictionary
    from secure_string_cipher.v2.header_parser import validate_v2_header

    final_header = validate_v2_header(wrapped_header_dict)
    return final_header


def _build_file_payload_descriptor(
    chunk_size: int,
    payload_kdf_salt: bytes,
    metadata_policy: MetadataPolicy,
) -> PayloadDescriptor:
    """Build a PayloadDescriptor for file encryption."""
    nonce_prefix = secrets.token_bytes(4)
    kdf: dict[str, object] = {
        "alg": "hkdf-sha256",
        "salt": b64url_encode(payload_kdf_salt),
    }
    return PayloadDescriptor(
        type=PayloadType.FILE,
        alg="aes-256-gcm",
        kdf=kdf,
        metadata_policy=metadata_policy,
        chunk_size=chunk_size,
        nonce_prefix=b64url_encode(nonce_prefix),
    )


def _build_text_payload_descriptor(
    plaintext_length: int,
    payload_kdf_salt: bytes,
) -> PayloadDescriptor:
    """Build a PayloadDescriptor for text encryption."""
    nonce = secrets.token_bytes(12)
    kdf: dict[str, object] = {
        "alg": "hkdf-sha256",
        "salt": b64url_encode(payload_kdf_salt),
    }
    return PayloadDescriptor(
        type=PayloadType.TEXT,
        alg="aes-256-gcm",
        kdf=kdf,
        metadata_policy=MetadataPolicy.HIDDEN,
        nonce=b64url_encode(nonce),
        plaintext_length=plaintext_length,
    )


def _build_encrypted_metadata_block(
    metadata_kdf_salt: bytes,
) -> dict[str, object]:
    """Build the metadata container for encrypted file metadata."""
    nonce = secrets.token_bytes(12)
    return {
        "policy": MetadataPolicy.ENCRYPTED.value,
        "alg": "aes-256-gcm",
        "kdf": {
            "alg": "hkdf-sha256",
            "salt": b64url_encode(metadata_kdf_salt),
        },
        "nonce": b64url_encode(nonce),
        # ciphertext and tag are populated after encryption
    }


def _build_hidden_metadata_block() -> dict[str, object]:
    """Build the metadata container for hidden metadata."""
    return {"policy": MetadataPolicy.HIDDEN.value}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encrypt_v2_file(
    input_path: Path,
    output_path: Path,
    credential: V2Credential,
    *,
    store_filename: bool = True,
    overwrite: bool = False,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> None:
    """Encrypt a file into a V2 binary container.

    Args:
        input_path: Path to the plaintext file to encrypt.
        output_path: Path for the encrypted output file.
        credential: Typed credential (password, key, or combined).
        store_filename: Whether to store the original filename in encrypted metadata.
        overwrite: Whether to overwrite an existing output file.
        chunk_size: Frame chunk size in bytes (default 64 KiB).

    Raises:
        CryptoError: On any encryption failure.
    """
    # Validate paths (G15: orchestrator controls open/stat/stream)
    input_p = validate_path_safety(input_path)
    if not input_p.exists():
        raise CryptoError(f"Input file does not exist: {input_p}")
    if not input_p.is_file():
        raise CryptoError(f"Input path is not a regular file: {input_p}")

    # Stat the input for snapshot-size verification (spec §9.2)
    input_stat = input_p.stat()
    file_size = input_stat.st_size

    if file_size > MAX_PLAINTEXT_FILE_SIZE:
        raise CryptoError(
            f"Input file size ({file_size} bytes) exceeds maximum "
            f"({MAX_PLAINTEXT_FILE_SIZE} bytes)"
        )

    # Generate DEK and object ID
    dek_raw = secrets.token_bytes(32)
    object_id = secrets.token_bytes(16)
    object_id_b64 = b64url_encode(object_id)
    salts = _generate_salts()

    with SecureBytes(dek_raw) as secure_dek:
        dek = bytes(secure_dek.data)

        # Build payload descriptor
        metadata_policy = (
            MetadataPolicy.ENCRYPTED if store_filename else MetadataPolicy.HIDDEN
        )
        payload_desc = _build_file_payload_descriptor(
            chunk_size=chunk_size,
            payload_kdf_salt=salts["payload_kdf_salt"],
            metadata_policy=metadata_policy,
        )

        # Build metadata block
        if store_filename:
            metadata_block = _build_encrypted_metadata_block(salts["metadata_kdf_salt"])
            # Pass internal keys for encrypt_metadata to consume
            metadata_block["_original_filename"] = os.path.basename(str(input_p))
            metadata_block["_original_size"] = file_size
        else:
            metadata_block = _build_hidden_metadata_block()

        # Build complete header (steps 1–6)
        header = _build_v2_header(
            credential=credential,
            dek=dek,
            payload_descriptor=payload_desc,
            metadata_block=metadata_block,
            object_id_b64=object_id_b64,
        )

        # Step 7: Encrypt payload — write binary container
        header_bytes = canonical_json(header)

        with safe_atomic_output(output_path, overwrite=overwrite) as out:
            # Write magic
            out.write(b"SSC2")
            # Write header length (U32)
            out.write(struct.pack("<I", len(header_bytes)))
            # Write header
            out.write(header_bytes)

            # Stream-encrypt frames
            writer = FrameWriter(header, dek, out)

            with open(input_p, "rb") as in_file:
                bytes_read = 0
                buffer = in_file.read(chunk_size)

                while True:
                    next_buffer = in_file.read(chunk_size)
                    is_final = len(next_buffer) == 0

                    if is_final:
                        # This is the last chunk
                        bytes_read += len(buffer)
                        writer.write_frame(buffer, is_final=True)
                        break

                    # Non-final chunk must be exactly chunk_size
                    if len(buffer) != chunk_size:
                        raise CryptoError(
                            f"Non-final chunk is {len(buffer)} bytes, "
                            f"expected {chunk_size}"
                        )
                    bytes_read += len(buffer)
                    writer.write_frame(buffer, is_final=False)
                    buffer = next_buffer

                # Snapshot-size verification (spec §9.2)
                if bytes_read != file_size:
                    raise CryptoError(
                        f"File size changed during encryption: expected "
                        f"{file_size} bytes, read {bytes_read} bytes"
                    )

    # DEK is zeroed by SecureBytes context manager (G19)


def encrypt_v2_text(
    plaintext: str,
    credential: V2Credential,
) -> str:
    """Encrypt a text string into a V2 armored message.

    Args:
        plaintext: The text to encrypt (must be valid UTF-8).
        credential: Typed credential (password, key, or combined).

    Returns:
        ASCII-armored V2 encrypted message.

    Raises:
        CryptoError: On any encryption failure.
    """
    # Validate plaintext
    try:
        pt_bytes = plaintext.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        raise CryptoError("Plaintext is not valid UTF-8") from e

    if len(pt_bytes) > _MAX_TEXT_SIZE:
        raise CryptoError(
            f"Plaintext size ({len(pt_bytes)} bytes) exceeds maximum "
            f"({_MAX_TEXT_SIZE} bytes)"
        )

    # Generate DEK and object ID
    dek_raw = secrets.token_bytes(32)
    object_id = secrets.token_bytes(16)
    object_id_b64 = b64url_encode(object_id)
    salts = _generate_salts()

    with SecureBytes(dek_raw) as secure_dek:
        dek = bytes(secure_dek.data)

        # Build text payload descriptor
        payload_desc = _build_text_payload_descriptor(
            plaintext_length=len(pt_bytes),
            payload_kdf_salt=salts["payload_kdf_salt"],
        )

        # Text metadata is always hidden (spec §8.1)
        metadata_block = _build_hidden_metadata_block()

        # Build complete header (steps 1–6)
        header = _build_v2_header(
            credential=credential,
            dek=dek,
            payload_descriptor=payload_desc,
            metadata_block=metadata_block,
            object_id_b64=object_id_b64,
        )

        # Step 7: Encrypt text payload via message armor
        armored = encrypt_message(header, dek, plaintext)

    return armored
