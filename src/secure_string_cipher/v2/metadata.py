"""Metadata AEAD operations for SSC v2."""

import json
import re
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_string_cipher.v2.envelope import MetadataPolicy, V2Header, canonical_json
from secure_string_cipher.v2.kdf import derive_metadata_key
from secure_string_cipher.v2.keywrap import (
    build_projection_m_context,
    compute_metadata_aad,
)
from secure_string_cipher.v2.vault_schema import b64url_decode


def get_metadata_aad(header: V2Header) -> bytes:
    """Computes the AAD for metadata AEAD using M_context.

    Thin delegate: M_context is owned by keywrap.build_projection_m_context
    and the AAD construction by keywrap.compute_metadata_aad.
    """
    return compute_metadata_aad(build_projection_m_context(header))


def encrypt_metadata(
    header: V2Header,
    dek: bytes,
    original_filename: str | None = None,
    original_size: int | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypts the metadata.
    Returns (ciphertext, tag).
    The header MUST contain a metadata block with:
    'policy': 'encrypted', 'alg': 'aes-256-gcm', 'kdf', and 'nonce'.
    """
    metadata_block = header.metadata
    if metadata_block.get("policy") != MetadataPolicy.ENCRYPTED.value:
        raise ValueError("Cannot encrypt metadata with policy != encrypted")

    kdf_block = metadata_block.get("kdf")
    if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
        raise TypeError("Metadata kdf block missing or invalid")

    kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
    if not isinstance(kdf_salt, str):
        raise TypeError("Metadata kdf salt missing or invalid")

    nonce_b64 = metadata_block.get("nonce")
    if not isinstance(nonce_b64, str):
        raise TypeError("Metadata nonce missing or invalid")

    nonce = b64url_decode(nonce_b64, expected_length=12)
    k_metadata = derive_metadata_key(dek, b64url_decode(kdf_salt, expected_length=32))

    from typing import Any

    metadata_plaintext_dict: dict[str, Any] = {}
    if original_filename is not None:
        if not isinstance(original_filename, str):
            raise TypeError("original_filename must be a string")
        if len(original_filename) > 255:
            raise ValueError("original_filename exceeds 255 characters")
        if len(original_filename.encode("utf-8")) > 1020:
            raise ValueError("original_filename exceeds 1020 bytes")
        metadata_plaintext_dict["original_filename"] = original_filename

    if original_size is not None:
        if not isinstance(original_size, int) or isinstance(original_size, bool):
            raise TypeError("original_size must be an integer")
        if original_size < 0 or original_size > 104857600:
            raise ValueError("original_size is out of bounds")
        metadata_plaintext_dict["original_size"] = original_size

    metadata_plaintext = canonical_json(metadata_plaintext_dict)

    aad = get_metadata_aad(header)
    aead = AESGCM(k_metadata)
    full_ciphertext = aead.encrypt(nonce, metadata_plaintext, aad)
    return full_ciphertext[:-16], full_ciphertext[-16:]


def decrypt_metadata(header: V2Header, dek: bytes) -> dict[str, Any]:
    """
    Decrypts the metadata block.
    Returns the parsed plaintext JSON dictionary.
    """
    metadata_block = header.metadata
    if metadata_block.get("policy") == MetadataPolicy.HIDDEN.value:
        return {}

    if metadata_block.get("policy") != MetadataPolicy.ENCRYPTED.value:
        raise ValueError(f"Unknown metadata policy: {metadata_block.get('policy')}")

    kdf_block = metadata_block.get("kdf")
    if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
        raise TypeError("Metadata kdf block missing or invalid")

    kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
    if not isinstance(kdf_salt, str):
        raise TypeError("Metadata kdf salt missing or invalid")

    nonce_b64 = metadata_block.get("nonce")
    if not isinstance(nonce_b64, str):
        raise TypeError("Metadata nonce missing or invalid")

    ciphertext_b64 = metadata_block.get("ciphertext")
    if not isinstance(ciphertext_b64, str):
        raise TypeError("Metadata ciphertext missing or invalid")

    tag_b64 = metadata_block.get("tag")
    if not isinstance(tag_b64, str):
        raise TypeError("Metadata tag missing or invalid")

    nonce = b64url_decode(nonce_b64, expected_length=12)
    ciphertext = b64url_decode(ciphertext_b64)
    tag = b64url_decode(tag_b64, expected_length=16)

    k_metadata = derive_metadata_key(dek, b64url_decode(kdf_salt, expected_length=32))
    aad = get_metadata_aad(header)

    aead = AESGCM(k_metadata)
    try:
        metadata_plaintext = aead.decrypt(nonce, ciphertext + tag, aad)
    except Exception as e:
        raise ValueError("Metadata authentication failed") from e

    if len(metadata_plaintext) > 4096:
        raise ValueError("Metadata exceeds 4096 bytes limit")

    try:
        parsed = json.loads(metadata_plaintext.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise ValueError("Metadata is not valid UTF-8") from e
    except json.JSONDecodeError as e:
        raise ValueError("Metadata is not valid JSON") from e

    if not isinstance(parsed, dict):
        raise ValueError("Metadata must be a JSON object")

    return parsed


def sanitize_filename(filename: str) -> str:
    """Sanitizes a filename to prevent path traversal and hostile characters."""
    if not isinstance(filename, str):
        raise TypeError("Filename must be a string")

    # Remove any directory components
    if "/" in filename or "\\" in filename:
        raise ValueError("Filename contains path separators")

    if filename in (".", ".."):
        raise ValueError("Filename is a traversal component")

    if re.search(r"[\x00-\x1f]", filename):
        raise ValueError("Filename contains control characters")

    # Windows reserved names
    windows_reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
    }
    if filename.lower().split(".")[0] in windows_reserved:
        raise ValueError("Filename is a Windows reserved name")

    # No drive letters or UNC
    if re.match(r"^[a-zA-Z]:", filename):
        raise ValueError("Filename looks like a Windows drive path")

    return filename
