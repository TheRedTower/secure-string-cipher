"""
Core encryption functionality for secure-string-cipher

This module provides AES-256-GCM encryption with:
- Argon2id key derivation (memory-hard, GPU-resistant)
- Key commitment (HMAC-SHA256) to prevent invisible salamanders attacks
- File metadata storage for original filename restoration
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.ciphers.base import AEADDecryptionContext

from .atomic_io import atomic_binary_writer
from .config import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CHUNK_SIZE,
    FILENAME_MAX_LENGTH,
    KEY_COMMITMENT_CONTEXT,
    KEY_COMMITMENT_SIZE,
    MAX_FILE_SIZE,
    MAX_METADATA_LENGTH,
    METADATA_MAGIC,
    METADATA_VERSION,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from .utils import CryptoError, ProgressBar

_SYSTEM_SYMLINK_ALLOWLIST = {Path("/var")}


def _ensure_no_symlink(path: Path, role: str) -> None:
    """Reject lexical symlink components unless explicitly allowlisted.

    This is a best-effort preflight check. It does not replace descriptor-based
    opening for protection against path changes made by concurrent processes.
    """

    absolute_path = path if path.is_absolute() else Path.cwd() / path

    for current in [absolute_path, *absolute_path.parents]:
        # Stop once we reach filesystem root
        if current == current.parent:
            break

        try:
            if current.is_symlink():
                resolved = current.resolve(strict=False)
                allowed = any(
                    allowed_path == current or resolved == allowed_path
                    for allowed_path in _SYSTEM_SYMLINK_ALLOWLIST
                )

                if not allowed:
                    raise CryptoError(
                        f"Refusing to use symlinked {role} path: {current}"
                    )
        except OSError as exc:
            # Fail closed if we cannot resolve the path safely
            raise CryptoError(f"Unable to validate {role} path: {current}") from exc


__all__ = [
    "StreamProcessor",
    "CryptoError",
    "derive_key",
    "compute_key_commitment",
    "verify_key_commitment",
    "generate_key_pair",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_text",
    "decrypt_text",
    "encrypt_file",
    "decrypt_file",
    "FileMetadata",
]


class StreamProcessor:
    """Context manager for secure file operations with progress tracking."""

    def __init__(self, path: str, mode: str):
        """
        Initialize a secure file stream processor.

        Args:
            path: Path to the file to process
            mode: File mode ('rb' for read, 'wb' for write)

        Raises:
            CryptoError: If file operations fail or security checks fail
        """
        self.path = path
        self.mode = mode
        self.file: BinaryIO | None = None
        self._progress: ProgressBar | None = None
        self.bytes_processed = 0

        if isinstance(path, (str, bytes, os.PathLike)):
            # Security check for large files
            if mode == "rb" and os.path.exists(path):
                size = os.path.getsize(path)
                if size > MAX_FILE_SIZE:
                    raise CryptoError(
                        f"File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024):.1f} MB"
                    )

    def _check_path(self) -> None:
        """
        Validate file path and prevent unsafe operations.

        Raises:
            CryptoError: If path is unsafe or permissions are incorrect
        """
        # Skip checks for file-like objects (stdin/stdout)
        if not isinstance(self.path, (str, bytes, os.PathLike)):
            return

        if self.mode == "wb":
            if os.path.exists(self.path):
                raise CryptoError(
                    f"Output file already exists: {self.path}. "
                    "Delete it first or choose a different path."
                )

            directory = Path(os.path.dirname(self.path) or ".")
            _ensure_no_symlink(directory, "output parent")
            if not directory.exists():
                raise CryptoError(f"Output directory does not exist: {directory}")
            if not directory.is_dir():
                raise CryptoError(f"Output parent is not a directory: {directory}")

    def __enter__(self) -> StreamProcessor:
        """
        Open file and setup progress tracking.

        Returns:
            Self for context manager use

        Raises:
            CryptoError: If file operations fail
        """
        if isinstance(self.path, (str, bytes, os.PathLike)):
            path_obj = Path(self.path)
            role = "input" if self.mode == "rb" else "output"
            _ensure_no_symlink(path_obj, role)
            self._check_path()
            try:
                self.file = open(self.path, self.mode)  # type: ignore[assignment]
            except OSError as e:
                raise CryptoError(f"Failed to open file: {e}") from e

            # Setup progress bar for reading
            if self.mode == "rb":
                with suppress(OSError):
                    size = os.path.getsize(self.path)
                    self._progress = ProgressBar(size)
        else:
            self.file = self.path

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up file handle."""
        if self.file:
            self.file.close()

    def read(self, size: int = -1) -> bytes:
        """
        Read with progress tracking.

        Args:
            size: Number of bytes to read, -1 for all

        Returns:
            Bytes read from file

        Raises:
            CryptoError: If read fails
        """
        if not self.file:
            raise CryptoError("File not open")
        data = self.file.read(size)
        self.bytes_processed += len(data)
        if self._progress:
            self._progress.update(self.bytes_processed)
        return data

    def write(self, data: bytes) -> int:
        """
        Write with progress tracking.

        Args:
            data: Bytes to write

        Returns:
            Number of bytes written

        Raises:
            CryptoError: If write fails
        """
        if not self.file:
            raise CryptoError("File not open")
        try:
            n = self.file.write(data)
            self.bytes_processed += n
            return n
        except OSError as e:
            raise CryptoError(f"Write failed: {e}") from e


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive encryption key using Argon2id (memory-hard KDF).

    Argon2id is the recommended KDF for password hashing. It is:
    - Memory-hard: Resistant to GPU/ASIC attacks
    - Side-channel resistant: Hybrid of Argon2i and Argon2d
    - Password Hashing Competition winner

    Args:
        passphrase: User-provided password
        salt: Random salt for key derivation (16+ bytes recommended)

    Returns:
        32-byte key suitable for AES-256

    Raises:
        CryptoError: If key derivation fails
    """
    from .secure_memory import SecureBytes, SecureString

    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as e:
        raise CryptoError(
            "Argon2 support requires argon2-cffi. Install with: pip install argon2-cffi"
        ) from e

    try:
        with SecureString(passphrase) as secure_pass:
            with SecureBytes(secure_pass.string.encode()) as secure_bytes:
                key = hash_secret_raw(
                    secret=bytes(secure_bytes.data),
                    salt=salt,
                    time_cost=ARGON2_TIME_COST,
                    memory_cost=ARGON2_MEMORY_COST,
                    parallelism=ARGON2_PARALLELISM,
                    hash_len=ARGON2_HASH_LENGTH,
                    type=Type.ID,  # Argon2id
                )
                return key
    except Exception as e:
        raise CryptoError(f"Argon2id key derivation failed: {e}") from e


# =============================================================================
# Key Commitment Functions
# =============================================================================
# Key commitment prevents "invisible salamanders" attacks where an attacker
# crafts a ciphertext that decrypts to different plaintexts under different keys.
# We compute HMAC-SHA256(key, context) and store it with the ciphertext.
# =============================================================================


def compute_key_commitment(key: bytes) -> bytes:
    """
    Compute a key commitment value using HMAC-SHA256.

    The commitment binds the ciphertext to a specific key, preventing
    attacks where a ciphertext could decrypt to different plaintexts
    under different keys.

    Args:
        key: The derived encryption key (32 bytes)

    Returns:
        32-byte commitment value

    Raises:
        CryptoError: If commitment computation fails
    """
    try:
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(KEY_COMMITMENT_CONTEXT)
        return h.finalize()
    except Exception as e:
        raise CryptoError(f"Key commitment computation failed: {e}") from e


def verify_key_commitment(key: bytes, expected_commitment: bytes) -> bool:
    """
    Verify that a key matches the expected commitment.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        key: The derived encryption key (32 bytes)
        expected_commitment: The commitment stored with the ciphertext

    Returns:
        True if the commitment matches, False otherwise
    """
    try:
        # Use HMAC verify which does constant-time comparison internally
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(KEY_COMMITMENT_CONTEXT)
        try:
            h.verify(expected_commitment)
            return True
        except Exception:
            return False
    except CryptoError:
        return False


# =============================================================================
# File Metadata
# =============================================================================
#
# Format: MAGIC(5) + META_LEN(2 big-endian) + META_JSON + SALT(16) + NONCE(12) + CIPHERTEXT + TAG(16)
#
# The metadata JSON contains:
#   - original_filename: The original filename before encryption
#   - version: Supported metadata format version (4 or 5)
#   - key_commitment: Base64-encoded HMAC-SHA256 commitment binding ciphertext to key
# =============================================================================


class _MetadataValidationError(CryptoError):
    """Generic public metadata error with a non-secret diagnostic category."""

    def __init__(self, category: str, *, detail: str | None = None) -> None:
        super().__init__("Invalid metadata format")
        self.category = category
        self.detail = detail


def _decode_canonical_base64(value: str | bytes) -> bytes:
    """Strictly decode standard Base64 and reject alternate textual spellings."""
    try:
        encoded = value.encode("ascii") if isinstance(value, str) else value
    except UnicodeEncodeError as error:
        raise ValueError("Base64 input must be ASCII") from error

    decoded = base64.b64decode(encoded, validate=True)
    if base64.b64encode(decoded) != encoded:
        raise ValueError("Base64 input is not canonical")
    return decoded


def _metadata_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _MetadataValidationError("duplicate_key", detail=key)
        result[key] = value
    return result


@dataclass
class FileMetadata:
    """Metadata stored with encrypted files."""

    original_filename: str | None = None
    version: int = field(default=METADATA_VERSION)
    key_commitment: str | None = None  # Base64-encoded HMAC commitment

    def to_bytes(self) -> bytes:
        """Serialize metadata to JSON bytes."""
        data: dict[str, str | int] = {
            "version": self.version,
        }
        if self.original_filename:
            # Truncate filename if too long
            data["original_filename"] = self.original_filename[:FILENAME_MAX_LENGTH]
        if self.key_commitment:
            data["key_commitment"] = self.key_commitment
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> FileMetadata:
        """Strictly deserialize supported v4/v5 metadata."""
        if len(data) > MAX_METADATA_LENGTH:
            raise _MetadataValidationError("oversized")

        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise _MetadataValidationError("invalid_utf8") from error

        try:
            obj = json.loads(text, object_pairs_hook=_metadata_object)
        except _MetadataValidationError:
            raise
        except json.JSONDecodeError as error:
            raise _MetadataValidationError("invalid_json") from error

        if not isinstance(obj, dict):
            raise _MetadataValidationError("non_object")

        allowed_fields = {"version", "original_filename", "key_commitment"}
        if unknown_fields := set(obj) - allowed_fields:
            raise _MetadataValidationError(
                "unknown_field", detail=sorted(unknown_fields)[0]
            )

        if "version" not in obj:
            raise _MetadataValidationError("missing_version")
        version = obj["version"]
        if type(version) is not int:
            raise _MetadataValidationError("invalid_version_type")
        if version not in {4, 5}:
            raise _MetadataValidationError("unsupported_version")

        if "key_commitment" not in obj:
            raise _MetadataValidationError("missing_key_commitment")
        key_commitment = obj["key_commitment"]
        if not isinstance(key_commitment, str):
            raise _MetadataValidationError("invalid_key_commitment_type")
        try:
            commitment_bytes = _decode_canonical_base64(key_commitment)
        except (binascii.Error, ValueError) as error:
            raise _MetadataValidationError("invalid_key_commitment_base64") from error
        if len(commitment_bytes) != KEY_COMMITMENT_SIZE:
            raise _MetadataValidationError("invalid_key_commitment_length")

        original_filename = obj.get("original_filename")
        if original_filename is not None:
            if not isinstance(original_filename, str):
                raise _MetadataValidationError("invalid_filename_type")
            if len(original_filename) > FILENAME_MAX_LENGTH:
                raise _MetadataValidationError("filename_too_long")

        return cls(
            original_filename=original_filename,
            version=version,
            key_commitment=key_commitment,
        )


# =============================================================================
# Text Encryption/Decryption
# =============================================================================


def _encrypt_data(data: bytes, passphrase: str) -> bytes:
    """
    Encrypt data using AES-256-GCM with Argon2id and key commitment.

    Internal function used by encrypt_text.

    Args:
        data: Data to encrypt
        passphrase: Encryption password

    Returns:
        Encrypted data with salt, nonce, and tag

    Raises:
        CryptoError: If encryption fails
    """
    from .secure_memory import SecureBytes
    from .timing_safe import add_timing_jitter

    try:
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)

        with SecureBytes(derive_key(passphrase, salt)) as secure_key:
            # Compute key commitment
            commitment = compute_key_commitment(bytes(secure_key.data))

            encryptor = Cipher(
                algorithms.AES(secure_key.data),
                modes.GCM(nonce),
                backend=default_backend(),
            ).encryptor()

            add_timing_jitter()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag

            # Format: salt + nonce + commitment + ciphertext + tag
            return salt + nonce + commitment + ciphertext + tag
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def _decrypt_data(encrypted: bytes, passphrase: str) -> bytes:
    """
    Decrypt data using AES-256-GCM with Argon2id and key commitment verification.

    Internal function used by decrypt_text.

    Args:
        encrypted: Encrypted data with salt, nonce, commitment, ciphertext, and tag
        passphrase: Decryption password

    Returns:
        Decrypted data

    Raises:
        CryptoError: If decryption fails or key commitment verification fails
    """
    try:
        # Format: salt(16) + nonce(12) + commitment(32) + ciphertext + tag(16)
        min_len = SALT_SIZE + NONCE_SIZE + 32 + TAG_SIZE
        if len(encrypted) < min_len:
            raise CryptoError("Invalid encrypted data format")

        salt = encrypted[:SALT_SIZE]
        nonce = encrypted[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        commitment = encrypted[SALT_SIZE + NONCE_SIZE : SALT_SIZE + NONCE_SIZE + 32]
        ciphertext_with_tag = encrypted[SALT_SIZE + NONCE_SIZE + 32 :]

        if len(ciphertext_with_tag) < TAG_SIZE:
            raise CryptoError("Data too short - not valid encrypted data")

        tag = ciphertext_with_tag[-TAG_SIZE:]
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]

        # Wrap key in SecureBytes to ensure it's wiped after use
        from .secure_memory import SecureBytes

        with SecureBytes(derive_key(passphrase, salt)) as secure_key:
            # Verify key commitment
            if not verify_key_commitment(bytes(secure_key.data), commitment):
                raise CryptoError(
                    "Key commitment verification failed - wrong password or tampered data"
                )

            decryptor = Cipher(
                algorithms.AES(secure_key.data),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            ).decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}") from e


def encrypt_text(text: str, passphrase: str) -> str:
    """
    Encrypt text using AES-256-GCM with Argon2id and key commitment.

    Args:
        text: Text to encrypt
        passphrase: Encryption password

    Returns:
        Base64-encoded encrypted text

    Raises:
        CryptoError: If encryption fails
    """
    try:
        encrypted = _encrypt_data(text.encode("utf-8"), passphrase)
        return base64.b64encode(encrypted).decode("ascii")
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Text encryption failed: {e}") from e


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    """
    Encrypt bytes using AES-256-GCM with Argon2id and key commitment.

    Args:
        data: Bytes to encrypt
        passphrase: Encryption password

    Returns:
        Base64-encoded encrypted bytes

    Raises:
        CryptoError: If encryption fails
    """
    try:
        encrypted = _encrypt_data(data, passphrase)
        return base64.b64encode(encrypted)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Bytes encryption failed: {e}") from e


def decrypt_bytes(token: bytes, passphrase: str) -> bytes:
    """
    Decrypt bytes encrypted with ``encrypt_bytes``.

    Args:
        token: Base64-encoded encrypted bytes
        passphrase: Decryption password

    Returns:
        Decrypted bytes

    Raises:
        CryptoError: If decryption fails
    """
    try:
        encrypted = _decode_canonical_base64(token)
    except (binascii.Error, ValueError):
        raise CryptoError("Bytes decryption failed: invalid base64") from None

    try:
        return _decrypt_data(encrypted, passphrase)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Bytes decryption failed: {e}") from e


def decrypt_text(token: str, passphrase: str) -> str:
    """
    Decrypt text using AES-256-GCM with Argon2id and key commitment verification.

    Args:
        token: Base64-encoded encrypted text
        passphrase: Decryption password

    Returns:
        Decrypted text

    Raises:
        CryptoError: If decryption fails or key commitment verification fails
    """
    try:
        encrypted = _decode_canonical_base64(token)
    except (binascii.Error, ValueError):
        raise CryptoError("Text decryption failed: invalid base64") from None

    try:
        decrypted = _decrypt_data(encrypted, passphrase)
        return decrypted.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Text decryption failed: invalid UTF-8 plaintext") from None
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Text decryption failed: {e}") from e


# =============================================================================
# File Encryption/Decryption
# =============================================================================


def encrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str,
    *,
    store_filename: bool = True,
    overwrite: bool = False,
) -> None:
    """
    Encrypt a file using AES-256-GCM with Argon2id and key commitment.

    The file format stores metadata including the original filename
    and a key commitment to prevent invisible salamanders attacks.

    Args:
        input_path: Path to file to encrypt
        output_path: Path for encrypted output
        passphrase: Encryption password
        store_filename: If True, store original filename in metadata
        overwrite: If True, atomically replace an existing output after success

    Raises:
        CryptoError: If encryption fails
    """
    from .secure_memory import SecureBytes
    from .timing_safe import add_timing_jitter

    try:
        _ensure_no_symlink(Path(input_path), "input")
        _ensure_no_symlink(Path(output_path), "output")

        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)

        with SecureBytes(derive_key(passphrase, salt)) as secure_key:
            # Compute key commitment to bind ciphertext to this specific key
            commitment = compute_key_commitment(bytes(secure_key.data))
            commitment_b64 = base64.b64encode(commitment).decode("ascii")

            # Build metadata with key commitment
            metadata = FileMetadata(
                original_filename=os.path.basename(input_path)
                if store_filename
                else None,
                version=METADATA_VERSION,
                key_commitment=commitment_b64,
            )
            meta_bytes = metadata.to_bytes()

            if len(meta_bytes) > 65535:
                raise CryptoError("Metadata too large")

            with StreamProcessor(input_path, "rb") as r:
                with atomic_binary_writer(
                    output_path,
                    overwrite=overwrite,
                    mode=0o600,
                ) as w:
                    # Write header: MAGIC + metadata length (2 bytes big-endian) + metadata
                    w.write(METADATA_MAGIC)
                    w.write(len(meta_bytes).to_bytes(2, "big"))
                    w.write(meta_bytes)

                    # Write encryption header
                    w.write(salt + nonce)

                    # Encrypt data
                    encryptor = Cipher(
                        algorithms.AES(secure_key.data),
                        modes.GCM(nonce),
                        backend=default_backend(),
                    ).encryptor()
                    if metadata.version >= 5:
                        encryptor.authenticate_additional_data(meta_bytes)

                    for chunk in iter(lambda: r.read(CHUNK_SIZE), b""):
                        w.write(encryptor.update(chunk))
                        add_timing_jitter()

                    w.write(encryptor.finalize() + encryptor.tag)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def _decrypt_stream(
    reader: BinaryIO,
    decryptor: AEADDecryptionContext,
    writer: BinaryIO | None = None,
) -> None:
    """Decrypt a ciphertext stream while retaining its trailing GCM tag."""
    buffer = bytearray()
    for chunk in iter(lambda: reader.read(CHUNK_SIZE), b""):
        buffer.extend(chunk)
        if len(buffer) > TAG_SIZE:
            emit_len = len(buffer) - TAG_SIZE
            plaintext = decryptor.update(memoryview(buffer)[:emit_len])
            if writer is not None:
                writer.write(plaintext)
            del buffer[:emit_len]

    if len(buffer) < TAG_SIZE:
        raise CryptoError("File too short - not a valid encrypted file")

    tail_view = memoryview(buffer)
    ciphertext_tail = tail_view[:-TAG_SIZE]
    tag = bytes(tail_view[-TAG_SIZE:])

    if ciphertext_tail:
        plaintext = decryptor.update(ciphertext_tail)
        if writer is not None:
            writer.write(plaintext)

    final_plaintext = decryptor.finalize_with_tag(tag)
    if writer is not None:
        writer.write(final_plaintext)


def _decryption_fallback_path(input_path: str) -> Path:
    """Return a deterministic .dec path without consulting file metadata."""
    path = Path(input_path)
    if path.suffix == ".enc":
        return path.with_suffix(".dec")
    return path.with_name(path.name + ".dec")


def decrypt_file(
    input_path: str,
    output_path: str | None,
    passphrase: str,
    *,
    restore_filename: bool = True,
    overwrite: bool = False,
) -> tuple[str, FileMetadata | None]:
    """
    Decrypt a file using AES-256-GCM with Argon2id and key commitment verification.

    Args:
        input_path: Path to encrypted file
        output_path: Path for decrypted output (if None, uses an authenticated
            v5 filename or a deterministic .dec fallback)
        passphrase: Decryption password
        restore_filename: If True and output_path is None, attempt to restore original filename
        overwrite: If True, atomically replace an existing output after authentication

    Returns:
        Tuple of (actual_output_path, metadata)

    Raises:
        CryptoError: If decryption fails or key commitment verification fails
    """
    from .security import sanitize_filename

    try:
        _ensure_no_symlink(Path(input_path), "input")
        with open(input_path, "rb") as f:
            # Check for magic header
            magic = f.read(len(METADATA_MAGIC))

            if magic != METADATA_MAGIC:
                raise CryptoError(
                    "Invalid file format: missing magic header. "
                    "This file may have been encrypted with an older version."
                )

            # Read metadata
            meta_len_bytes = f.read(2)
            if len(meta_len_bytes) != 2:
                raise CryptoError("Invalid file: truncated metadata length")
            meta_len = int.from_bytes(meta_len_bytes, "big")

            if meta_len > MAX_METADATA_LENGTH:
                raise CryptoError("Invalid file: metadata too large")

            meta_bytes = f.read(meta_len)
            if len(meta_bytes) != meta_len:
                raise CryptoError("Invalid file: truncated metadata")

            metadata = FileMetadata.from_bytes(meta_bytes)

            # Read encryption header
            header = f.read(SALT_SIZE + NONCE_SIZE)
            if len(header) != SALT_SIZE + NONCE_SIZE:
                raise CryptoError("Invalid encrypted file format")

            salt, nonce = header[:SALT_SIZE], header[SALT_SIZE:]

            # Wrap key in SecureBytes to ensure it's wiped after use
            from .secure_memory import SecureBytes

            with SecureBytes(derive_key(passphrase, salt)) as secure_key:
                # Verify key commitment
                if metadata.key_commitment is not None:
                    try:
                        expected_commitment = _decode_canonical_base64(
                            metadata.key_commitment
                        )
                        if len(expected_commitment) != KEY_COMMITMENT_SIZE:
                            raise CryptoError("Invalid key commitment format")
                        if not verify_key_commitment(
                            bytes(secure_key.data), expected_commitment
                        ):
                            raise CryptoError(
                                "Key commitment verification failed - wrong password or tampered file"
                            )
                    except (binascii.Error, ValueError, TypeError) as e:
                        raise CryptoError("Invalid key commitment format") from e
                else:
                    raise CryptoError(
                        "File missing key commitment - may have been tampered with"
                    )

                decryptor = Cipher(
                    algorithms.AES(secure_key.data),
                    modes.GCM(nonce),
                    backend=default_backend(),
                ).decryptor()
                if metadata.version >= 5:
                    decryptor.authenticate_additional_data(meta_bytes)

                ciphertext_start = f.tell()

                if output_path is None:
                    # Authenticate before allowing stored metadata to select a path.
                    _decrypt_stream(f, decryptor)

                    if (
                        restore_filename
                        and metadata.version >= 5
                        and metadata.original_filename
                    ):
                        safe_name = sanitize_filename(metadata.original_filename)
                        output_dir = Path(input_path).parent
                        output_path_obj = output_dir / safe_name
                    else:
                        # Version 4 metadata is unauthenticated and never selects a path.
                        output_path_obj = _decryption_fallback_path(input_path)

                    f.seek(ciphertext_start)
                    decryptor = Cipher(
                        algorithms.AES(secure_key.data),
                        modes.GCM(nonce),
                        backend=default_backend(),
                    ).decryptor()
                    if metadata.version >= 5:
                        decryptor.authenticate_additional_data(meta_bytes)
                else:
                    output_path_obj = Path(output_path)

                _ensure_no_symlink(output_path_obj, "output")
                _ensure_no_symlink(output_path_obj.parent, "output parent")
                with atomic_binary_writer(
                    output_path_obj,
                    overwrite=overwrite,
                    mode=0o600,
                ) as writer:
                    _decrypt_stream(f, decryptor, writer)

        return str(output_path_obj), metadata

    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}") from e


# =============================================================================
# Key File Support
# =============================================================================


def derive_passphrase_from_key_file(key_file_path: str | Path) -> str:
    """Derive the deterministic passphrase string for a key file."""
    try:
        key_file = Path(key_file_path).expanduser()
        _ensure_no_symlink(key_file, "key file")
        if not key_file.exists():
            raise CryptoError(f"Key file not found: {key_file_path}")
        if not key_file.is_file():
            raise CryptoError(f"Key file is not a regular file: {key_file_path}")
        if key_file.stat().st_size > MAX_FILE_SIZE:
            raise CryptoError(
                f"Key file too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024):.1f} MB"
            )

        key_data = key_file.read_bytes()
        if len(key_data) == 0:
            raise CryptoError(f"Key file is empty: {key_file_path}")

        from hashlib import sha256

        return sha256(key_data).hexdigest()
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Key file processing failed: {e}") from e


def derive_key_from_key_file(key_file_path: str | Path, salt: bytes) -> bytes:
    """
    Derive an encryption key from a key file using Argon2id.

    The key file can be any file (PEM public key, SSH key, or random data).
    Its content is hashed and used as the passphrase for Argon2id.

    Args:
        key_file_path: Path to the key file
        salt: Random salt for key derivation

    Returns:
        32-byte key suitable for AES-256

    Raises:
        CryptoError: If key file cannot be read or key derivation fails
    """
    try:
        key_hash = derive_passphrase_from_key_file(key_file_path)
        return derive_key(key_hash, salt)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Key file processing failed: {e}") from e


def generate_key_pair(
    private_key_path: str | Path, public_key_path: str | Path | None = None
) -> None:
    """
    Generate an RSA key pair for recipient-based encryption.

    This is a convenience function for creating key files that can be used
    with the recipient/key-file encryption workflow.

    Args:
        private_key_path: Path where private key will be saved
        public_key_path: Path where public key will be saved (defaults to private_key_path + '.pub')

    Raises:
        CryptoError: If key generation or file operations fail
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_path = Path(private_key_path)
        if public_key_path is None:
            public_path = Path(str(private_path) + ".pub")
        else:
            public_path = Path(public_key_path)

        _ensure_no_symlink(private_path, "private key")
        _ensure_no_symlink(public_path, "public key")
        _ensure_no_symlink(private_path.parent, "private key parent")
        _ensure_no_symlink(public_path.parent, "public key parent")

        if private_path.resolve(strict=False) == public_path.resolve(strict=False):
            raise CryptoError("Private and public key paths must be different files")

        private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        for key_path, label in (
            (private_path, "Private"),
            (public_path, "Public"),
        ):
            if key_path.exists() and not key_path.is_file():
                raise CryptoError(f"{label} key path is not a regular file: {key_path}")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Serialize private key (PKCS8, no encryption for simplicity)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        def _write_key_file_securely(path: Path, data: bytes) -> None:
            # Re-check immediately before open to reduce TOCTOU window and
            # enforce no-symlink behavior even when O_NOFOLLOW is unavailable.
            if path.is_symlink():
                raise CryptoError(f"Refusing to use symlinked key output path: {path}")

            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            try:
                fd = os.open(path, flags, 0o600)
            except OSError as exc:
                raise CryptoError(
                    f"Failed to open key file for secure write: {path}"
                ) from exc

            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)

                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written == 0:
                        raise CryptoError(
                            f"Failed to write key file completely: {path}"
                        )
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)

            if not hasattr(os, "fchmod"):
                os.chmod(path, 0o600)

        # Keep both key files owner-only. Public keys can be shared explicitly.
        _write_key_file_securely(private_path, private_pem)
        _write_key_file_securely(public_path, public_pem)

    except ImportError as err:
        raise CryptoError(
            "Key pair generation requires cryptography library. "
            "Install with: pip install cryptography"
        ) from err
    except Exception as e:
        raise CryptoError(f"Key pair generation failed: {e}") from e
