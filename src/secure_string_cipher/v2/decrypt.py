"""V2 decrypt orchestrator — wires together reader order from spec §8.2.

Public API:
    decrypt_v2_file(...)
    decrypt_v2_text(...)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secure_string_cipher.secure_memory import SecureBytes
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    V2Credential,
)
from secure_string_cipher.v2.envelope import PayloadType, V2Header
from secure_string_cipher.v2.header_parser import parse_header_stream
from secure_string_cipher.v2.keywrap import unwrap_dek_from_grant
from secure_string_cipher.v2.message import decrypt_message
from secure_string_cipher.v2.metadata import decrypt_metadata, sanitize_filename
from secure_string_cipher.v2.output import safe_atomic_output, validate_path_safety
from secure_string_cipher.v2.payload import FrameReader

__all__ = [
    "decrypt_v2_file",
    "decrypt_v2_text",
]


def _unwrap_dek_for_credential(
    header: V2Header,
    credential: V2Credential,
) -> bytes:
    """Unwrap DEK using the appropriate credential grant."""
    if isinstance(credential, PasswordCredential):
        pwd: str | bytes = (
            bytes(credential.passphrase.data)
            if isinstance(credential.passphrase, SecureBytes)
            else credential.passphrase
        )
        return unwrap_dek_from_grant(header, password=pwd)
    if isinstance(credential, KeyCredential):
        ms: bytes = (
            bytes(credential.managed_secret.data)
            if isinstance(credential.managed_secret, SecureBytes)
            else credential.managed_secret
        )
        return unwrap_dek_from_grant(header, managed_secret=ms)
    if isinstance(credential, CombinedCredential):
        pwd_c: str | bytes = (
            bytes(credential.passphrase.data)
            if isinstance(credential.passphrase, SecureBytes)
            else credential.passphrase
        )
        ms_c: bytes = (
            bytes(credential.managed_secret.data)
            if isinstance(credential.managed_secret, SecureBytes)
            else credential.managed_secret
        )
        return unwrap_dek_from_grant(
            header,
            password=pwd_c,
            managed_secret=ms_c,
        )
    raise TypeError(f"Unsupported credential type: {type(credential).__name__}")


def decrypt_v2_file(
    input_path: Path,
    credential: V2Credential,
    *,
    output_path: Path | None = None,
    output_dir: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Decrypt a V2 binary container into a file.

    Args:
        input_path: Path to the encrypted file.
        credential: Typed credential (password, key, or combined).
        output_path: Explicit path for the decrypted output file.
        output_dir: Directory to place the output file if output_path is None
            and the original filename was stored in metadata.
        overwrite: Whether to overwrite an existing output file.

    Returns:
        The path where the decrypted file was written.

    Raises:
        CryptoError: On any decryption failure or path unsafety.
    """
    input_p = validate_path_safety(input_path)
    if not input_p.exists():
        raise CryptoError(f"Input file does not exist: {input_p}")
    if not input_p.is_file():
        raise CryptoError(f"Input path is not a regular file: {input_p}")

    with open(input_p, "rb") as in_file:
        try:
            header, raw_json_bytes = parse_header_stream(in_file)
        except Exception as e:
            raise CryptoError(f"Failed to parse V2 header: {e}") from e

        if header.payload.type != PayloadType.FILE:
            raise CryptoError("Cannot use decrypt_v2_file on non-FILE payload")

        try:
            dek_raw = _unwrap_dek_for_credential(header, credential)
        except Exception as e:
            raise CryptoError(f"Failed to unwrap DEK: {e}") from e

        with SecureBytes(dek_raw) as secure_dek:
            dek = bytes(secure_dek.data)

            # Metadata decryption (optional but required if output_path is None)
            metadata_dict: dict[str, Any] = {}
            if header.metadata.get("policy") == "encrypted":
                try:
                    metadata_dict = decrypt_metadata(header, dek)
                except Exception as e:
                    raise CryptoError(f"Failed to decrypt metadata: {e}") from e

            # Determine output destination
            dest_path: Path
            if output_path is not None:
                dest_path = Path(output_path)
            else:
                original_name = metadata_dict.get("original_filename")
                if not original_name or not isinstance(original_name, str):
                    raise CryptoError(
                        "No output_path provided and original_filename not found in metadata"
                    )
                try:
                    safe_name = sanitize_filename(original_name)
                except Exception as e:
                    raise CryptoError(f"Unsafe original filename: {e}") from e

                base_dir = (
                    Path(output_dir) if output_dir is not None else input_p.parent
                )
                dest_path = base_dir / safe_name

            # Stream decrypt to safe_atomic_output
            try:
                reader = FrameReader(header, dek, in_file)
            except Exception as e:
                raise CryptoError(f"Failed to initialize payload reader: {e}") from e

            expected_size = metadata_dict.get("original_size")
            bytes_written = 0

            # Every authentication check MUST raise inside this scope: the
            # atomic writer publishes via os.replace only on clean exit, so a
            # failure here leaves the destination absent or byte-identical.
            with safe_atomic_output(dest_path, overwrite=overwrite) as out:
                try:
                    # read_frames enforces AEAD tags, frame finality (FINAL
                    # flag consumed, exact EOF after it) and padding shape.
                    for chunk in reader.read_frames():
                        out.write(chunk)
                        bytes_written += len(chunk)
                except Exception as e:
                    raise CryptoError(
                        f"Failed to authenticate or decrypt payload: {e}"
                    ) from e

                # For encrypted metadata, original_size is an additional
                # length signal. For hidden metadata there is no
                # original_size; frame finality is the length signal.
                # type(...) is int rejects JSON booleans (true/false).
                if expected_size is not None and type(expected_size) is int:  # noqa: E721
                    if bytes_written != expected_size:
                        raise CryptoError(
                            f"Decrypted payload size {bytes_written} does not match "
                            f"original size {expected_size} from metadata"
                        )

    return dest_path


def decrypt_v2_text(
    armored_text: str,
    credential: V2Credential,
) -> str:
    """Decrypt a V2 armored message into a text string.

    Args:
        armored_text: ASCII-armored V2 encrypted message.
        credential: Typed credential (password, key, or combined).

    Returns:
        The decrypted plaintext string.

    Raises:
        CryptoError: On any decryption failure.
    """
    import base64

    from secure_string_cipher.v2.header_parser import validate_v2_header
    from secure_string_cipher.v2.message import unarmor_message
    from secure_string_cipher.v2.vault_schema import _reject_duplicate_object_hook

    try:
        parsed_msg = unarmor_message(armored_text)
    except Exception as e:
        raise CryptoError(f"Failed to unarmor message: {e}") from e

    try:
        header_bytes = base64.b64decode(parsed_msg.header_b64, validate=True)
        header_text = header_bytes.decode("utf-8")
        header_dict = json.loads(
            header_text, object_pairs_hook=_reject_duplicate_object_hook
        )
        header = validate_v2_header(header_dict, header_bytes)
    except Exception as e:
        raise CryptoError(f"Failed to parse V2 header from armor: {e}") from e

    if header.payload.type != PayloadType.TEXT:
        raise CryptoError("Cannot use decrypt_v2_text on non-TEXT payload")

    try:
        dek_raw = _unwrap_dek_for_credential(header, credential)
    except Exception as e:
        raise CryptoError(f"Failed to unwrap DEK: {e}") from e

    with SecureBytes(dek_raw) as secure_dek:
        dek = bytes(secure_dek.data)

        # Message metadata is always hidden, no need to decrypt it
        try:
            plaintext = decrypt_message(header, dek, armored_text)
        except Exception as e:
            raise CryptoError(
                f"Failed to authenticate or decrypt message payload: {e}"
            ) from e

    return plaintext
