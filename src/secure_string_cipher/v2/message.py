import hashlib
import struct
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_string_cipher.v2.envelope import (
    PayloadType,
    V2Header,
    canonical_json,
)
from secure_string_cipher.v2.kdf import derive_payload_key
from secure_string_cipher.v2.keywrap import build_projection_m_context
from secure_string_cipher.v2.vault_schema import b64url_decode


def _m_context_digest(header: V2Header) -> bytes:
    """SHA-256 digest of the canonical M_context projection (owned by keywrap)."""
    return hashlib.sha256(
        canonical_json(build_projection_m_context(header).mapping)
    ).digest()


class ParsedMessage(NamedTuple):
    header_b64: str
    body_b64: str


def armor_message(header: V2Header, ciphertext: bytes, tag: bytes) -> str:
    """Format an encrypted text payload as an armored message."""
    import base64

    if header.payload.type != PayloadType.TEXT:
        raise ValueError("Message armor is only for TEXT payload type")

    # The armored header is the canonical JSON of the validated V2Header — the
    # exact same serialization encrypt_v2_file uses for the binary container.
    # Hand-rebuilding the grant dict here previously dropped key_fingerprint
    # and combined_kdf, which broke commitment verification on decrypt.
    header_bytes = canonical_json(header)
    header_b64 = base64.b64encode(header_bytes).decode("ascii")
    body_b64 = base64.b64encode(ciphertext + tag).decode("ascii")

    lines = [
        "-----BEGIN SSC MESSAGE-----",
        "Version: 2",
        "Type: text",
        f"Header: {header_b64}",
        "",
        body_b64,
        "-----END SSC MESSAGE-----",
        "",
    ]
    return "\n".join(lines)


def unarmor_message(armored_text: str) -> ParsedMessage:
    """Parse an armored message into header and body base64 strings."""
    if "\r\n" in armored_text and "\n" in armored_text.replace("\r\n", ""):
        raise ValueError("Mixed line endings are not allowed")

    lines = armored_text.splitlines()

    if not lines:
        raise ValueError("Empty armored message")

    if lines[-1] == "":
        lines.pop()

    if len(lines) < 7:
        raise ValueError("Malformed armored message: too few lines")

    if lines[0] != "-----BEGIN SSC MESSAGE-----":
        raise ValueError("Malformed armored message: invalid begin marker")

    if lines[-1] != "-----END SSC MESSAGE-----":
        raise ValueError("Malformed armored message: invalid end marker")

    if " " in lines[0] or " " in lines[-1]:
        # Trailing spaces or leading spaces not allowed on markers
        if not lines[0].startswith("-----BEGIN SSC MESSAGE-----") or not lines[
            -1
        ].startswith("-----END SSC MESSAGE-----"):
            raise ValueError(
                "Malformed armored message: trailing/leading spaces on markers"
            )

    version_line = lines[1]
    if version_line != "Version: 2":
        raise ValueError("Unsupported message version or malformed Version line")

    type_line = lines[2]
    if type_line != "Type: text":
        raise ValueError("Unsupported message type or malformed Type line")

    header_line = lines[3]
    if not header_line.startswith("Header: "):
        raise ValueError("Malformed Header line")

    header_b64 = header_line[8:]

    if lines[4] != "":
        raise ValueError("Malformed armored message: expected empty line after Header")

    body_b64 = lines[5]
    if lines[6] != "-----END SSC MESSAGE-----":
        raise ValueError("Malformed armored message: expected end marker after body")

    if len(lines) > 7:
        raise ValueError("Extra lines or multiple blocks found")

    return ParsedMessage(header_b64=header_b64, body_b64=body_b64)


def encrypt_message(header: V2Header, dek: bytes, plaintext: str) -> str:
    """Encrypt a text plaintext into an armored message."""
    if header.payload.type != PayloadType.TEXT:
        raise ValueError("encrypt_message is only for TEXT payload type")

    try:
        pt_bytes = plaintext.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        raise ValueError("Plaintext is not valid UTF-8") from e

    kdf_block = header.payload.kdf
    if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
        raise TypeError("Payload kdf block missing or invalid")

    kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
    if not isinstance(kdf_salt, str):
        raise TypeError("Payload kdf salt missing or invalid")

    k_payload = derive_payload_key(
        dek, b64url_decode(kdf_salt, expected_length=32), PayloadType.TEXT
    )
    m_context_digest = _m_context_digest(header)

    nonce_b64 = header.payload.nonce
    if not isinstance(nonce_b64, str):
        raise TypeError("Payload nonce missing or invalid")
    nonce = b64url_decode(nonce_b64, expected_length=12)

    plaintext_length = header.payload.plaintext_length
    if plaintext_length is None or plaintext_length != len(pt_bytes):
        raise ValueError("Payload plaintext_length mismatch")

    object_id_b64 = header.object_id
    object_id = b64url_decode(object_id_b64, expected_length=16)

    pt_len_bytes = struct.pack("<Q", plaintext_length)

    aad = b"SSC2/message/v1\0" + m_context_digest + object_id + pt_len_bytes

    aead = AESGCM(k_payload)
    full_ct = aead.encrypt(nonce, pt_bytes, aad)

    ciphertext = full_ct[:-16]
    tag = full_ct[-16:]

    return armor_message(header, ciphertext, tag)


def decrypt_message(header: V2Header, dek: bytes, armored_text: str) -> str:
    """Decrypt an armored message back into plaintext."""
    import base64

    if header.payload.type != PayloadType.TEXT:
        raise ValueError("decrypt_message is only for TEXT payload type")

    parsed = unarmor_message(armored_text)

    # We do not strictly need to compare the parsed header with the input header here,
    # as the decrypt orchestrator should pass in the header parsed from the armor.
    # However, we must ensure we decode the body correctly.
    try:
        body_bytes = base64.b64decode(parsed.body_b64, validate=True)
    except Exception as e:
        raise ValueError("Invalid Base64 in message body") from e

    if len(body_bytes) < 16:
        raise ValueError("Message body too short to contain tag")

    kdf_block = header.payload.kdf
    if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
        raise TypeError("Payload kdf block missing or invalid")

    kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
    if not isinstance(kdf_salt, str):
        raise TypeError("Payload kdf salt missing or invalid")

    k_payload = derive_payload_key(
        dek, b64url_decode(kdf_salt, expected_length=32), PayloadType.TEXT
    )
    m_context_digest = _m_context_digest(header)

    nonce_b64 = header.payload.nonce
    if not isinstance(nonce_b64, str):
        raise TypeError("Payload nonce missing or invalid")
    nonce = b64url_decode(nonce_b64, expected_length=12)

    plaintext_length = header.payload.plaintext_length
    if plaintext_length is None:
        raise ValueError("Payload plaintext_length missing")

    object_id_b64 = header.object_id
    object_id = b64url_decode(object_id_b64, expected_length=16)

    pt_len_bytes = struct.pack("<Q", plaintext_length)

    aad = b"SSC2/message/v1\0" + m_context_digest + object_id + pt_len_bytes

    aead = AESGCM(k_payload)
    try:
        pt_bytes = aead.decrypt(nonce, body_bytes, aad)
    except Exception as e:
        raise ValueError("Message authentication failed") from e

    if len(pt_bytes) != plaintext_length:
        raise ValueError("Plaintext length mismatch after decryption")

    try:
        return pt_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise ValueError("Decrypted plaintext is not valid UTF-8") from e
