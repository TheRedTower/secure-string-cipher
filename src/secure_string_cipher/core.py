"""
Core encryption functionality for secure-string-cipher
"""

from __future__ import annotations

import base64
import io
import os
import secrets
from typing import BinaryIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import (
    CHUNK_SIZE,
    KDF_ITERATIONS,
    MAX_FILE_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from .utils import CryptoError, ProgressBar

__all__ = [
    "StreamProcessor",
    "CryptoError",
    "derive_key",
    "encrypt_text",
    "decrypt_text",
    "encrypt_stream",
    "decrypt_stream",
    "encrypt_file",
    "decrypt_file",
]


class InMemoryStreamProcessor:
    """Stream processor for in-memory data like strings."""

    def __init__(self, stream: io.BytesIO, mode: str):
        """Initialize with a BytesIO stream."""
        self.stream = stream
        self.mode = mode

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def write(self, data: bytes) -> int:
        return self.stream.write(data)

    def tell(self) -> int:
        return self.stream.tell()

    def seek(self, pos: int, whence: int = 0) -> int:
        return self.stream.seek(pos, whence)


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
        if self.mode == "wb":
            if os.path.exists(self.path):
                ans = input(
                    f"\nWarning: {self.path} exists. Overwrite? [y/N]: "
                ).lower()
                if ans not in ("y", "yes"):
                    raise CryptoError("Operation cancelled")

            try:
                directory = os.path.dirname(self.path) or "."
                test_file = os.path.join(directory, ".write_test")
                with open(test_file, "wb") as f:
                    f.write(b"test")
                os.unlink(test_file)
            except OSError as e:
                raise CryptoError(f"Cannot write to directory: {e}") from e

    def __enter__(self) -> StreamProcessor:
        """
        Open file and setup progress tracking.

        Returns:
            Self for context manager use

        Raises:
            CryptoError: If file operations fail
        """
        if isinstance(self.path, (str, bytes, os.PathLike)):
            self._check_path()
            try:
                self.file = open(self.path, self.mode)  # type: ignore[assignment]
            except OSError as e:
                raise CryptoError(f"Failed to open file: {e}") from e

            # Setup progress bar for reading
            if self.mode == "rb":
                try:
                    size = os.path.getsize(self.path)
                    self._progress = ProgressBar(size)
                except OSError:
                    pass  # Skip progress if we can't get file size
        else:
            self.file = self.path

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
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
    Derive encryption key from passphrase using PBKDF2.

    Args:
        passphrase: User-provided password
        salt: Random salt for key derivation

    Returns:
        32-byte key suitable for AES-256

    Raises:
        CryptoError: If key derivation fails
    """
    from .secure_memory import SecureBytes, SecureString

    try:
        with SecureString(passphrase) as secure_pass:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=KDF_ITERATIONS,
                backend=default_backend(),
            )
            with SecureBytes(secure_pass.string.encode()) as secure_bytes:
                return kdf.derive(secure_bytes.data)
    except Exception as e:
        raise CryptoError(f"Key derivation failed: {e}") from e


def encrypt_stream(r: StreamProcessor, w: StreamProcessor, passphrase: str) -> None:
    """
    Encrypt a file stream using AES-256-GCM.

    Args:
        r: Input stream processor
        w: Output stream processor
        passphrase: Encryption password

    Raises:
        CryptoError: If encryption fails
    """
    from .secure_memory import SecureBytes
    from .timing_safe import add_timing_jitter

    try:
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)

        with SecureBytes(derive_key(passphrase, salt)) as secure_key:
            w.write(salt + nonce)
            encryptor = Cipher(
                algorithms.AES(secure_key.data),
                modes.GCM(nonce),
                backend=default_backend(),
            ).encryptor()

            for chunk in iter(lambda: r.read(CHUNK_SIZE), b""):
                w.write(encryptor.update(chunk))
                add_timing_jitter()

            w.write(encryptor.finalize() + encryptor.tag)
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def decrypt_stream(r: StreamProcessor, w: StreamProcessor, passphrase: str) -> None:
    """
    Decrypt a file stream using AES-256-GCM.

    Args:
        r: Input stream processor
        w: Output stream processor
        passphrase: Decryption password

    Raises:
        CryptoError: If decryption fails or data is corrupted
    """
    try:
        header = r.read(SALT_SIZE + NONCE_SIZE)
        if len(header) != SALT_SIZE + NONCE_SIZE:
            raise CryptoError("Invalid encrypted file format")

        salt, nonce = header[:SALT_SIZE], header[SALT_SIZE:]
        data = r.read()

        if len(data) < TAG_SIZE:
            raise CryptoError("File too short - not a valid encrypted file")

        tag = data[-TAG_SIZE:]
        ciphertext = data[:-TAG_SIZE]
        key = derive_key(passphrase, salt)

        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        w.write(plaintext)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}") from e


def encrypt_text(text: str, passphrase: str) -> str:
    """
    Encrypt text using AES-256-GCM.

    Args:
        text: Text to encrypt
        passphrase: Encryption password

    Returns:
        Base64-encoded encrypted text
    """
    ri = io.BytesIO(text.encode("utf-8"))
    wi = io.BytesIO()

    try:
        # Use in-memory processors to avoid closing the BytesIO buffers
        r = InMemoryStreamProcessor(ri, "rb")
        w = InMemoryStreamProcessor(wi, "wb")
        encrypt_stream(r, w, passphrase)  # type: ignore[arg-type]

        wi.seek(0)
        encrypted = wi.getvalue()
        return base64.b64encode(encrypted).decode("ascii")
    except Exception as e:
        raise CryptoError(f"Text encryption failed: {e}") from e
    finally:
        try:
            ri.close()
        except Exception:  # nosec B110
            pass  # BytesIO close errors can be safely ignored
        try:
            wi.close()
        except Exception:  # nosec B110
            pass  # BytesIO close errors can be safely ignored


def decrypt_text(token: str, passphrase: str) -> str:
    """
    Decrypt text using AES-256-GCM.

    Args:
        token: Base64-encoded encrypted text
        passphrase: Decryption password

    Returns:
        Decrypted text

    Raises:
        CryptoError: If decryption fails
    """
    try:
        encrypted = base64.b64decode(token)
    except ValueError:
        # Wrap base64 errors to provide a consistent decryption error message
        raise CryptoError("Text decryption failed") from None

    ri = io.BytesIO(encrypted)
    wi = io.BytesIO()

    try:
        r = InMemoryStreamProcessor(ri, "rb")
        w = InMemoryStreamProcessor(wi, "wb")
        decrypt_stream(r, w, passphrase)  # type: ignore[arg-type]
        wi.seek(0)
        result = wi.getvalue().decode("utf-8", "ignore")
        return result
    except Exception as e:
        raise CryptoError(f"Text decryption failed: {e}") from e
    finally:
        ri.close()
        wi.close()


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """
    Encrypt a file using AES-256-GCM.

    Args:
        input_path: Path to file to encrypt
        output_path: Path for encrypted output
        passphrase: Encryption password

    Raises:
        CryptoError: If encryption fails
    """
    with (
        StreamProcessor(input_path, "rb") as r,
        StreamProcessor(output_path, "wb") as w,
    ):
        encrypt_stream(r, w, passphrase)


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """
    Decrypt a file using AES-256-GCM.

    Args:
        input_path: Path to encrypted file
        output_path: Path for decrypted output
        passphrase: Decryption password

    Raises:
        CryptoError: If decryption fails
    """
    with (
        StreamProcessor(input_path, "rb") as r,
        StreamProcessor(output_path, "wb") as w,
    ):
        decrypt_stream(r, w, passphrase)
