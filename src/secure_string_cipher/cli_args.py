"""Non-interactive command-line interface for secure-string-cipher.

This module provides the `ssc` CLI with subcommands for encryption,
decryption, and vault management.

Entry point: ssc
Subcommands: start, encrypt, decrypt, store, vault
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from .v2.envelope import V2Header

from . import __version__
from .audit_log import AuditEvent, get_audit_logger
from .cli import main as run_interactive_menu
from .config import (
    KEY_COMMITMENT_SIZE,
    MAX_FILE_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    load_vault_settings,
    set_vault_backend,
)
from .core import (
    CryptoError,
    _ensure_no_symlink,
    _FileInputError,
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    derive_passphrase_from_key_file,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
)
from .keychain_backend import KeychainError
from .passphrase_generator import generate_passphrase
from .passphrase_manager import (
    PassphraseVault,
    VaultTransactionError,
    read_bounded_vault_file,
    validate_raw_vault,
)
from .rate_limiter import PersistentRateLimiter, RateLimitError
from .security import SecurityError
from .timing_safe import check_password_strength
from .utils import colorize, secure_overwrite
from .v2.decrypt import decrypt_v2_file, decrypt_v2_text
from .v2.encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    V2Credential,
    encrypt_v2_file,
    encrypt_v2_text,
)
from .v2.key_identity import KeyStatus
from .v2.keyfile import KeyFileData, load_keyfile
from .v2.keywrap import KeyWrapError
from .v2.vault_lock import VaultBusyError
from .v2.vault_service import (
    KeyExportSurvivedRegistrationFailureError,
    V2VaultService,
)
from .vault_transport import canonicalize_cli_vault_candidate

# Global rate limiter for CLI authentication attempts
_cli_limiter = PersistentRateLimiter()

# =============================================================================
# Exit Codes
# =============================================================================

EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1  # Invalid arguments, missing flags
EXIT_AUTH_ERROR = 2  # Wrong password, decryption failed
EXIT_VAULT_ERROR = 3  # Not initialized, label not found
EXIT_FILE_ERROR = 4  # Not found, permission denied
EXIT_INTERNAL_ERROR = 70  # Unexpected fault in this program (sysexits EX_SOFTWARE)

# Generic V2 decryption failure message (never includes exception internals).
_V2_DECRYPT_FAILURE_MESSAGE = "Decryption failed. Wrong password/key or corrupted data."

# =============================================================================
# Global State
# =============================================================================

_quiet_mode = False
_no_color = False
_debug_mode = False


class _StdinSizeError(CryptoError):
    """Internal signal for stdin data outside the documented payload bound."""


def _read_stdin_bounded(maximum_bytes: int) -> bytes:
    """Read at most one byte beyond a caller-supplied stdin bound."""
    data = sys.stdin.buffer.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise _StdinSizeError("Stdin input exceeds the allowed size.")
    return data


def _maximum_stdin_ciphertext_size() -> int:
    """Return Base64 size for a maximum plaintext plus text-token framing."""
    raw_size = MAX_FILE_SIZE + SALT_SIZE + NONCE_SIZE + KEY_COMMITMENT_SIZE + TAG_SIZE
    return 4 * ((raw_size + 2) // 3)


def _remove_one_terminal_line_ending(data: bytes) -> bytes:
    """Remove one shell transport line ending without broad whitespace stripping."""
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


_RATE_LIMIT_IDENTITY_PREFIX_BYTES = 4096


def _file_rate_limit_identity(path: Path) -> str:
    """Derive a rate-limit identifier from ciphertext content, not its path.

    Every SSC container (v4/v5 or v2) carries fresh random salt/nonce/commitment
    material within its first few dozen bytes, so hashing a bounded prefix gives
    a stable per-object fingerprint: copying or renaming the same ciphertext to
    a new path yields the same identifier (so its lockout state survives),
    while a distinct encryption of the same plaintext gets its own fresh
    budget, as intended. Falls back to the path string if the file cannot be
    read here (rare: permission change or deletion racing this read); that
    degrades to the previous, weaker behavior only in that corner case rather
    than skipping the rate-limit check entirely.
    """
    try:
        with open(path, "rb") as f:
            prefix = f.read(_RATE_LIMIT_IDENTITY_PREFIX_BYTES)
    except OSError:
        return str(path)
    return hashlib.sha256(prefix).hexdigest()[:32]


def _print_info(message: str) -> None:
    """Print info message (suppressed in quiet mode)."""
    if not _quiet_mode:
        if _no_color:
            print(message, file=sys.stderr)
        else:
            print(colorize(message, "green"), file=sys.stderr)


def _print_warning(message: str) -> None:
    """Print warning message (suppressed in quiet mode)."""
    if not _quiet_mode:
        if _no_color:
            print(f"Warning: {message}", file=sys.stderr)
        else:
            print(colorize(f"⚠️  {message}", "yellow"), file=sys.stderr)


def _print_error(message: str) -> None:
    """Print error message (always shown)."""
    if _no_color:
        print(f"Error: {message}", file=sys.stderr)
    else:
        print(colorize(f"Error: {message}", "red"), file=sys.stderr)


def _exit_error(code: int, message: str) -> NoReturn:
    """Print error and exit with code."""
    _print_error(message)
    sys.exit(code)


def _print_password_policy() -> None:
    """Print static password policy guidance without password-derived details."""
    print(
        "  Password requirements: at least 12 chars, uppercase, lowercase, digits, symbols",
        file=sys.stderr,
    )
    print(file=sys.stderr)


def _key_file_error_message(error: Exception) -> str:
    """Return a fixed key-file error message without echoing paths or internals."""
    message = str(error)
    if "Key file not found" in message:
        return "Key file not found."
    if "Key file is empty" in message:
        return "Key file is empty."
    if "Key file is not a regular file" in message:
        return "Key file is not a regular file."
    if "Key file too large" in message:
        return "Key file too large."
    return "Key file error."


def _audit_encryption(
    event: AuditEvent,
    success: bool,
    *,
    file_path: str | None = None,
    error: str | None = None,
) -> None:
    """Log encryption/decryption activity without exposing plaintext or keys."""
    get_audit_logger().log_encryption(
        event, success=success, file_path=file_path, error=error
    )


def _audit_vault(
    event: AuditEvent,
    success: bool,
    vault: PassphraseVault,
    *,
    label: str | None = None,
    error: str | None = None,
) -> None:
    """Log vault activity without exposing stored secrets."""
    get_audit_logger().log_vault_operation(
        event,
        success=success,
        vault_path=vault.get_vault_path(),
        label=label,
        error=error,
    )


def _audit_rate_limit(operation: str, wait: float, identifier: str = "") -> None:
    """Log rate-limit triggers."""
    get_audit_logger().log_rate_limit(operation, wait, identifier or None)


# =============================================================================
# Password Handling
# =============================================================================


def _prompt_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Prompt for password with hidden input.

    Args:
        prompt: The prompt to display
        confirm: If True, ask for confirmation

    Returns:
        The entered password
    """
    password = getpass.getpass(prompt)

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            _exit_error(EXIT_INPUT_ERROR, "Passwords do not match.")

    return password


def _prompt_password_with_validation(prompt: str = "Password: ") -> str:
    """Prompt for password with strength validation.

    Args:
        prompt: The prompt to display

    Returns:
        A valid password meeting strength requirements
    """
    while True:
        password = getpass.getpass(prompt)
        is_strong, _ = check_password_strength(password)

        if is_strong:
            # Confirm
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                _print_error("Passwords do not match. Try again.")
                continue
            return password

        _print_error("Password does not meet security requirements:")
        _print_password_policy()


def _prompt_master_password() -> str:
    """Prompt for vault master password."""
    return getpass.getpass("Master password: ")


def _get_vault() -> PassphraseVault:
    """Get or initialize the vault."""
    vault = PassphraseVault()

    # Check if vault exists
    if not vault.vault_exists():
        print("Vault not initialized. Initialize now? (y/n): ", end="", flush=True)
        response = input().strip().lower()
        if response != "y":
            _exit_error(EXIT_VAULT_ERROR, "Vault not initialized.")

        # Initialize vault
        print()
        master = _prompt_password_with_validation("Set master password: ")
        # Store a dummy entry to initialize, then delete it
        vault.store_passphrase("__init__", "init", master)
        vault.delete_passphrase("__init__", master)
        _print_info("✓ Vault initialized.")
        print()

    return vault


def _get_password_from_vault(label: str) -> str:
    """Retrieve password from vault with rate limiting.

    Args:
        label: The label to retrieve

    Returns:
        The stored password
    """
    vault = _get_vault()
    vault_id = str(vault.vault_path)

    # Check rate limit before prompting for password
    allowed, wait = _cli_limiter.check_rate_limit("vault_unlock", vault_id)
    if not allowed:
        _audit_rate_limit("vault_unlock", wait, vault_id)
        _exit_error(
            EXIT_AUTH_ERROR,
            f"Too many failed attempts. Please wait {wait:.0f} seconds.",
        )

    master = _prompt_master_password()

    try:
        result = vault.retrieve_passphrase(label, master)
        _cli_limiter.record_attempt("vault_unlock", vault_id, success=True)
        _audit_vault(AuditEvent.VAULT_RETRIEVE, True, vault, label=label)
        return result
    except ValueError as e:
        _cli_limiter.record_attempt("vault_unlock", vault_id, success=False)
        if "not found" in str(e):
            _audit_vault(
                AuditEvent.VAULT_RETRIEVE, False, vault, label=label, error="not_found"
            )
            _exit_error(EXIT_VAULT_ERROR, f"Label '{label}' not found in vault.")
        _audit_vault(
            AuditEvent.VAULT_UNLOCK, False, vault, label=label, error="auth_failed"
        )
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except CryptoError:
        _cli_limiter.record_attempt("vault_unlock", vault_id, success=False)
        _audit_vault(
            AuditEvent.VAULT_UNLOCK, False, vault, label=label, error="auth_failed"
        )
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")


def _get_password_from_key_file(key_file_path: str) -> str:
    """Derive deterministic passphrase from a key file.

    Uses SHA-256 hash of the key file content as the passphrase.
    This ensures consistent key derivation regardless of file format.

    Args:
        key_file_path: Path to the key file

    Returns:
        Hex-encoded SHA-256 hash of key file content

    Raises:
        CryptoError: If key file cannot be read or is invalid
    """
    try:
        return derive_passphrase_from_key_file(key_file_path)
    except CryptoError as e:
        _exit_error(EXIT_FILE_ERROR, _key_file_error_message(e))


# =============================================================================
# Command: start (interactive)
# =============================================================================


def cmd_start(args: argparse.Namespace) -> int:
    """Launch interactive menu."""
    run_interactive_menu(sys.stdin, sys.stdout, exit_on_completion=False)
    return EXIT_SUCCESS


# =============================================================================
# Command: encrypt
# =============================================================================


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt text or file."""
    positional_path = getattr(args, "positional_path", None)

    # The positional path is an alias for --file, not a fourth independent
    # input: silently preferring one of --file/--text when a positional is
    # also given would encrypt something other than what the prominently
    # supplied positional argument named, with no indication to the user.
    inputs_given = sum(bool(x) for x in (positional_path, args.file, args.text))
    if inputs_given > 1:
        _exit_error(
            EXIT_INPUT_ERROR,
            "Specify only one of: a positional file path, --file, or --text.",
        )

    if positional_path:
        args.file = positional_path

    # Validate: must have -t or -f
    if not args.text and not args.file:
        _exit_error(EXIT_INPUT_ERROR, "Must specify --text or --file.")

    if args.text and args.file:
        _exit_error(EXIT_INPUT_ERROR, "Cannot specify both --text and --file.")

    is_v2 = bool(getattr(args, "with_sources", None))

    if is_v2:
        sources = args.with_sources
        require_all = args.require == "all"

        has_password = "password" in sources
        keys = [s[4:] for s in sources if s.startswith("key:")]

        if len(sources) != has_password + len(keys) or any(not k for k in keys):
            _exit_error(
                EXIT_INPUT_ERROR, "Invalid --with source. Use 'password' or 'key:ID'"
            )

        if len(keys) > 1:
            _exit_error(EXIT_INPUT_ERROR, "Cannot specify multiple key sources.")

        if len(sources) > 1 and not require_all:
            _exit_error(EXIT_INPUT_ERROR, "Multiple sources require --require all")

        credential: V2Credential
        if has_password and keys and require_all:
            password = _prompt_password("Enter password: ", confirm=True)
            key_data = _resolve_v2_key_source(keys[0])
            if getattr(args, "vault", None):
                _enforce_v2_key_status(key_data.fingerprint)
            credential = CombinedCredential(
                password, key_data.fingerprint, key_data.secret_bytes
            )
        elif has_password:
            password = _prompt_password("Enter password: ", confirm=True)
            credential = PasswordCredential(password)
        elif keys:
            key_data = _resolve_v2_key_source(keys[0])
            if getattr(args, "vault", None):
                _enforce_v2_key_status(key_data.fingerprint)
            credential = KeyCredential(key_data.fingerprint, key_data.secret_bytes)
        else:
            _exit_error(EXIT_INPUT_ERROR, "Invalid --with combination.")

        if args.text:
            try:
                ciphertext = encrypt_v2_text(args.text, credential)
                print(ciphertext)
                _audit_encryption(AuditEvent.ENCRYPT_TEXT, True)
                _print_info("✓ Encrypted successfully")
                return EXIT_SUCCESS
            except CryptoError:
                _audit_encryption(
                    AuditEvent.ENCRYPT_TEXT, False, error="encryption_failed"
                )
                _exit_error(EXIT_INPUT_ERROR, "Encryption failed.")
        elif args.file:
            if args.file == "-":
                _exit_error(EXIT_INPUT_ERROR, "V2 does not support stdin streaming.")
            filepath_obj = Path(args.file)
            if not filepath_obj.exists():
                _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

            output_path = (
                Path(args.output)
                if getattr(args, "output", None)
                else filepath_obj.with_suffix(filepath_obj.suffix + ".ssc")
            )

            if output_path.exists() and not args.force:
                _exit_error(
                    EXIT_FILE_ERROR,
                    f"{output_path} already exists.\nRun again with --force to overwrite.",
                )

            try:
                encrypt_v2_file(
                    filepath_obj, output_path, credential, overwrite=args.force
                )
                _audit_encryption(
                    AuditEvent.ENCRYPT_FILE, True, file_path=str(filepath_obj)
                )
                _print_info(f"✓ Encrypted to {output_path}")
                return EXIT_SUCCESS
            except _FileInputError:
                _audit_encryption(
                    AuditEvent.ENCRYPT_FILE,
                    False,
                    file_path=str(filepath_obj),
                    error="input_rejected",
                )
                _exit_error(EXIT_FILE_ERROR, "Input file rejected.")
            except CryptoError:
                _audit_encryption(
                    AuditEvent.ENCRYPT_FILE,
                    False,
                    file_path=str(filepath_obj),
                    error="encryption_failed",
                )
                _exit_error(EXIT_INPUT_ERROR, "Encryption failed.")
            except PermissionError:
                _exit_error(EXIT_FILE_ERROR, f"Permission denied: {args.file}")
            except OSError:
                _exit_error(EXIT_FILE_ERROR, "File error.")

        return EXIT_SUCCESS

    # ==================== V1 Encryption ====================

    # Validate mutually exclusive options
    if args.vault and getattr(args, "key_file", None):
        _exit_error(
            EXIT_INPUT_ERROR,
            "Cannot specify both --vault and --key-file. Choose one.",
        )

    # Validate file existence and overwrite BEFORE prompting for password
    v1_output_path: Path | None = None
    if args.file and args.file != "-":
        filepath = Path(args.file)

        if not filepath.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        v1_output_path = filepath.with_suffix(filepath.suffix + ".enc")

        # Check overwrite
        if v1_output_path.exists() and not args.force:
            _exit_error(
                EXIT_FILE_ERROR,
                f"{v1_output_path} already exists.\nRun again with --force to overwrite.",
            )

    # Get password/key
    if args.vault:
        password = _get_password_from_vault(args.vault)
    elif getattr(args, "key_file", None):
        try:
            password = _get_password_from_key_file(args.key_file)
        except CryptoError:
            raise
        except Exception:
            _exit_error(EXIT_FILE_ERROR, "Key file error.")
    else:
        password = _prompt_password("Enter password: ", confirm=True)

    # Encrypt text
    if args.text:
        try:
            ciphertext = encrypt_text(args.text, password)
            print(ciphertext)
            _audit_encryption(AuditEvent.ENCRYPT_TEXT, True)
            _print_info("✓ Encrypted successfully")
            return EXIT_SUCCESS
        except CryptoError:
            _audit_encryption(AuditEvent.ENCRYPT_TEXT, False, error="encryption_failed")
            _exit_error(EXIT_AUTH_ERROR, "Encryption failed.")

    # Encrypt file
    if args.file:
        filepath = args.file

        # Handle stdin/stdout streaming
        if filepath == "-":
            try:
                data = _read_stdin_bounded(MAX_FILE_SIZE)
                ciphertext_bytes = encrypt_bytes(data, password)
                sys.stdout.buffer.write(ciphertext_bytes + b"\n")
                _audit_encryption(AuditEvent.ENCRYPT_FILE, True, file_path="stdin")
                _print_info("✓ Encrypted stdin to stdout")
                return EXIT_SUCCESS
            except _StdinSizeError:
                _exit_error(EXIT_FILE_ERROR, "Stdin input too large.")
            except CryptoError:
                _audit_encryption(
                    AuditEvent.ENCRYPT_FILE,
                    False,
                    file_path="stdin",
                    error="encryption_failed",
                )
                _exit_error(EXIT_AUTH_ERROR, "Encryption failed.")
            except Exception:
                _exit_error(EXIT_FILE_ERROR, "File error.")

        filepath_obj = Path(filepath)
        v1_output_path = filepath_obj.with_suffix(filepath_obj.suffix + ".enc")

        try:
            encrypt_file(
                str(filepath_obj),
                str(v1_output_path),
                password,
                overwrite=args.force,
            )
            _audit_encryption(
                AuditEvent.ENCRYPT_FILE, True, file_path=str(filepath_obj)
            )
            _print_info(f"✓ Encrypted to {v1_output_path}")
            return EXIT_SUCCESS
        except _FileInputError:
            _audit_encryption(
                AuditEvent.ENCRYPT_FILE,
                False,
                file_path=str(filepath_obj),
                error="input_rejected",
            )
            _exit_error(EXIT_FILE_ERROR, "Input file rejected.")
        except CryptoError:
            _audit_encryption(
                AuditEvent.ENCRYPT_FILE,
                False,
                file_path=str(filepath_obj),
                error="encryption_failed",
            )
            _exit_error(EXIT_AUTH_ERROR, "Encryption failed.")
        except PermissionError:
            _exit_error(EXIT_FILE_ERROR, f"Permission denied: {args.file}")
        except OSError:
            _exit_error(EXIT_FILE_ERROR, "File error.")

    return EXIT_SUCCESS


# =============================================================================
# Command: decrypt
# =============================================================================


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt text or file."""
    # Validate: must have -t or -f
    if not args.text and not args.file:
        _exit_error(EXIT_INPUT_ERROR, "Must specify --text or --file.")

    if args.text and args.file:
        _exit_error(EXIT_INPUT_ERROR, "Cannot specify both --text and --file.")

    # Validate mutually exclusive options
    if args.vault and args.key_file:
        _exit_error(
            EXIT_INPUT_ERROR,
            "Cannot specify both --vault and --key-file. Choose one.",
        )

    # Validate file existence and overwrite BEFORE prompting for password
    output_arg = getattr(args, "output", None)
    restore_filename = getattr(args, "restore_filename", True)
    output_path = None
    if args.file and args.file != "-":
        filepath = Path(args.file)

        if not filepath.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        # Explicit destinations can be checked without consulting file metadata.
        try:
            _ensure_no_symlink(filepath, "input")
            if output_arg:
                output_path = Path(output_arg)
                _ensure_no_symlink(output_path, "output")
        except (OSError, PermissionError, CryptoError):
            _exit_error(EXIT_FILE_ERROR, "File error.")

        if output_path is not None and output_path.exists() and not args.force:
            _exit_error(
                EXIT_FILE_ERROR,
                f"{output_path} already exists.\nRun again with --force to overwrite.",
            )

    rate_operation = "decrypt_text" if args.text else "decrypt_file"
    if args.text or not args.file or args.file == "-":
        # No persistent on-disk ciphertext to fingerprint: text is identified
        # by operation alone, "-" is stdin (nothing to copy/rename to bypass).
        rate_identifier = str(args.file) if args.file else ""
    else:
        # Identify by ciphertext content, not path: renaming or copying the
        # same encrypted file must not reset its lockout state.
        rate_identifier = _file_rate_limit_identity(Path(args.file))
    allowed, wait = _cli_limiter.check_rate_limit(rate_operation, rate_identifier)
    if not allowed:
        _audit_rate_limit(rate_operation, wait, rate_identifier)
        _exit_error(
            EXIT_AUTH_ERROR,
            f"Too many failed attempts. Please wait {wait:.0f} seconds.",
        )

    is_v2 = False
    is_message = False

    # Format detection
    if args.text:
        is_message = args.text.startswith("-----BEGIN SSC MESSAGE-----")
        if not is_message and args.text.startswith("SSC2"):
            # A raw V2 container shouldn't be passed as string, but maybe it's base64 encoded?
            # V2 messages are armored, so if it's not a message, it's V1 text.
            pass
    elif args.file and args.file != "-":
        filepath = Path(args.file)
        try:
            with open(filepath, "rb") as f:
                magic = f.read(5)
            if magic.startswith(b"SSC2"):
                is_v2 = True
            elif magic.startswith(b"SSCV2"):
                is_v2 = False
        except Exception:
            pass

    if is_message or is_v2:
        return _cmd_decrypt_v2(args, is_message, rate_identifier)

    # V1 Decryption
    password = _get_v1_password(args)

    # Decrypt text
    if args.text:
        try:
            plaintext = decrypt_text(args.text, password)
            _cli_limiter.record_attempt("decrypt_text", "", success=True)
            print(plaintext)
            _audit_encryption(AuditEvent.DECRYPT_TEXT, True)
            _print_info("✓ Decrypted successfully")
            return EXIT_SUCCESS
        except CryptoError:
            _cli_limiter.record_attempt("decrypt_text", "", success=False)
            _audit_encryption(AuditEvent.DECRYPT_TEXT, False, error="decryption_failed")
            _exit_error(
                EXIT_AUTH_ERROR, "Decryption failed. Wrong password or corrupted data."
            )

    # Decrypt file
    if args.file:
        filepath = args.file

        # Handle stdin/stdout streaming
        if filepath == "-":
            # Read from stdin, decrypt, write to stdout
            try:
                maximum_token_size = _maximum_stdin_ciphertext_size()
                data = _read_stdin_bounded(maximum_token_size + 2)
                data = _remove_one_terminal_line_ending(data)
                if len(data) > maximum_token_size:
                    raise _StdinSizeError("Stdin input exceeds the allowed size.")
                plaintext_bytes = decrypt_bytes(data, password)
                if len(plaintext_bytes) > MAX_FILE_SIZE:
                    raise _StdinSizeError("Stdin input exceeds the allowed size.")
                sys.stdout.buffer.write(plaintext_bytes)
                _cli_limiter.record_attempt("decrypt_file", "-", success=True)
                _audit_encryption(AuditEvent.DECRYPT_FILE, True, file_path="stdin")
                _print_info("✓ Decrypted stdin to stdout")
                return EXIT_SUCCESS
            except _StdinSizeError:
                _exit_error(EXIT_FILE_ERROR, "Stdin input too large.")
            except CryptoError:
                _cli_limiter.record_attempt("decrypt_file", "-", success=False)
                _audit_encryption(
                    AuditEvent.DECRYPT_FILE,
                    False,
                    file_path="stdin",
                    error="decryption_failed",
                )
                _exit_error(
                    EXIT_AUTH_ERROR,
                    "Decryption failed. Wrong password or corrupted data.",
                )
            except Exception:
                _exit_error(EXIT_FILE_ERROR, "File error.")

        filepath_obj = Path(filepath)

        if not filepath_obj.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        try:
            actual_output, _ = decrypt_file(
                str(filepath_obj),
                str(output_path) if output_path else None,
                password,
                restore_filename=restore_filename,
                overwrite=args.force,
            )
            _cli_limiter.record_attempt("decrypt_file", rate_identifier, success=True)
            _audit_encryption(
                AuditEvent.DECRYPT_FILE, True, file_path=str(filepath_obj)
            )
            _print_info(f"✓ Decrypted to {actual_output}")
            return EXIT_SUCCESS
        except _FileInputError:
            _audit_encryption(
                AuditEvent.DECRYPT_FILE,
                False,
                file_path=str(filepath_obj),
                error="input_rejected",
            )
            _exit_error(EXIT_FILE_ERROR, "Input file rejected.")
        except CryptoError as exc:
            if str(exc).startswith("Output file already exists:"):
                _exit_error(
                    EXIT_FILE_ERROR,
                    "Output file already exists.\nRun again with --force to overwrite.",
                )
            _cli_limiter.record_attempt("decrypt_file", rate_identifier, success=False)
            _audit_encryption(
                AuditEvent.DECRYPT_FILE,
                False,
                file_path=str(filepath_obj),
                error="decryption_failed",
            )
            _exit_error(
                EXIT_AUTH_ERROR, "Decryption failed. Wrong password or corrupted data."
            )
        except PermissionError:
            _exit_error(EXIT_FILE_ERROR, f"Permission denied: {args.file}")
        except OSError:
            _exit_error(EXIT_FILE_ERROR, "File error.")

    return EXIT_SUCCESS


def _get_v1_password(args: argparse.Namespace) -> str:
    """Resolve password for V1 decryption."""
    if args.vault:
        return _get_password_from_vault(args.vault)
    elif getattr(args, "key_file", None):
        try:
            return _get_password_from_key_file(args.key_file)
        except CryptoError:
            raise
        except Exception:
            _exit_error(EXIT_FILE_ERROR, "Key file error.")
    else:
        return _prompt_password("Enter password: ", confirm=False)


def _resolve_v2_key_source(key_ref: str) -> KeyFileData:
    """Resolve a V2 key reference to validated keyfile data.

    ``key_ref`` is either a path to a ``.ssckey`` file or a fingerprint/key-id
    registered under ``~/.ssc/keys/``. Shared by encryption (``key:X`` sources)
    and decryption (``--key-file`` or header grant fingerprints) so both sides
    use one resolution model. ``load_keyfile`` always receives a ``Path``.
    """
    candidate = Path(key_ref).expanduser()
    if candidate.suffix == ".ssckey" or candidate.is_file():
        try:
            return load_keyfile(candidate)
        except Exception:
            _exit_error(EXIT_FILE_ERROR, "Could not load key file.")

    keys_dir = Path.home() / ".ssc" / "keys"
    if keys_dir.is_dir():
        for child in sorted(keys_dir.iterdir()):
            if child.suffix != ".ssckey":
                continue
            try:
                key_data = load_keyfile(child)
            except Exception:
                continue
            if key_ref in (key_data.fingerprint, key_data.key_id):
                return key_data

    _exit_error(
        EXIT_FILE_ERROR,
        "Key not found: provide a .ssckey path or a fingerprint/key-id "
        "present in ~/.ssc/keys/.",
    )


def _get_v2_password(args: argparse.Namespace) -> str:
    """Resolve the password component of a V2 credential (vault or prompt)."""
    if getattr(args, "vault", None):
        return _get_password_from_vault(args.vault)
    return _prompt_password("Enter password: ", confirm=False)


def _enforce_v2_key_status(fingerprint: str) -> None:
    """Reject a managed key that this vault has marked revoked or destroyed.

    Encrypt/decrypt normally resolve ``.ssckey`` files straight off disk
    (see ``_resolve_v2_key_source``) without ever touching the vault, so a
    key you still physically hold keeps working even after ``ssc key
    revoke``/``destroy`` — that's inherent to holding the file, not a bug.
    This check is therefore opt-in: it only runs when the caller passes
    ``--vault``, and even then a key with no matching vault record (a bare
    ``.ssckey`` that was never registered) can't be checked and is let
    through unchanged. It only closes the gap for keys this vault actually
    tracks.
    """
    vault = PassphraseVault()
    if not vault.vault_exists():
        return
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        records = service.list_keys(master)
    except Exception:
        _exit_error(EXIT_AUTH_ERROR, "Could not unlock vault to check key status.")
    for record in records:
        if record.fingerprint != fingerprint:
            continue
        if record.status == KeyStatus.REVOKED:
            _exit_error(
                EXIT_AUTH_ERROR,
                f"Key '{record.id}' is revoked in this vault; refusing to use it.",
            )
        if record.status == KeyStatus.DESTROYED:
            _exit_error(
                EXIT_AUTH_ERROR,
                f"Key '{record.id}' has been destroyed in this vault; refusing "
                "to use it.",
            )
        return


def _resolve_v2_credential_from_header(
    header: V2Header, args: argparse.Namespace
) -> V2Credential:
    from .v2.envelope import GrantType

    has_password = any(g.type == GrantType.PASSWORD for g in header.access.grants)
    has_key = any(g.type == GrantType.MANAGED_KEY for g in header.access.grants)
    has_combined = any(
        g.type == GrantType.COMBINED_PASSWORD_MANAGED_KEY for g in header.access.grants
    )

    key_file_ref = getattr(args, "key_file", None)

    if has_combined:
        password = _get_v2_password(args)
        grant = next(
            g
            for g in header.access.grants
            if g.type == GrantType.COMBINED_PASSWORD_MANAGED_KEY
        )
        if not grant.key_fingerprint:
            _exit_error(EXIT_AUTH_ERROR, "No usable access grant found in V2 header.")
        key_data = _resolve_v2_key_source(key_file_ref or grant.key_fingerprint)
        if getattr(args, "vault", None):
            _enforce_v2_key_status(grant.key_fingerprint)
        return CombinedCredential(
            passphrase=password,
            key_fingerprint=grant.key_fingerprint,
            managed_secret=key_data.secret_bytes,
        )

    if has_password:
        if key_file_ref:
            _exit_error(
                EXIT_INPUT_ERROR,
                "--key-file is only usable with V2 key-protected containers.",
            )
        password = _get_v2_password(args)
        return PasswordCredential(passphrase=password)

    if has_key:
        grant = next(g for g in header.access.grants if g.type == GrantType.MANAGED_KEY)
        if not grant.key_fingerprint:
            _exit_error(EXIT_AUTH_ERROR, "No usable access grant found in V2 header.")
        key_data = _resolve_v2_key_source(key_file_ref or grant.key_fingerprint)
        if getattr(args, "vault", None):
            _enforce_v2_key_status(grant.key_fingerprint)
        return KeyCredential(
            key_fingerprint=grant.key_fingerprint, managed_secret=key_data.secret_bytes
        )

    _exit_error(EXIT_AUTH_ERROR, "No usable access grant found in V2 header.")


def _cmd_decrypt_v2(
    args: argparse.Namespace, is_message: bool, rate_identifier: str = ""
) -> int:
    import base64
    import json

    from .v2.header_parser import parse_header_stream, validate_v2_header
    from .v2.message import unarmor_message
    from .v2.vault_schema import _reject_duplicate_object_hook

    if is_message:
        # Armored messages carry the header as raw canonical JSON (Base64),
        # not the binary SSC2 framing parse_header_stream expects. Mirror
        # decrypt_v2_text: unarmor, decode, then validate the JSON header.
        try:
            parsed = unarmor_message(args.text)
            raw_bytes = base64.b64decode(parsed.header_b64, validate=True)
            header_dict = json.loads(
                raw_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_object_hook,
            )
            header = validate_v2_header(header_dict, raw_bytes)
        except Exception:
            _cli_limiter.record_attempt("decrypt_text", "", success=False)
            _audit_encryption(AuditEvent.DECRYPT_TEXT, False, error="decryption_failed")
            _exit_error(EXIT_AUTH_ERROR, _V2_DECRYPT_FAILURE_MESSAGE)

        cred = _resolve_v2_credential_from_header(header, args)
        try:
            plaintext = decrypt_v2_text(args.text, cred)
            _cli_limiter.record_attempt("decrypt_text", "", success=True)
            print(plaintext)
            _audit_encryption(AuditEvent.DECRYPT_TEXT, True)
            _print_info("✓ Decrypted successfully (V2)")
            return EXIT_SUCCESS
        except CryptoError:
            _cli_limiter.record_attempt("decrypt_text", "", success=False)
            _audit_encryption(AuditEvent.DECRYPT_TEXT, False, error="decryption_failed")
            _exit_error(EXIT_AUTH_ERROR, _V2_DECRYPT_FAILURE_MESSAGE)

    # File decrypt V2 (real binary SSC2 container: magic + length prefix).
    filepath = Path(args.file)
    try:
        with open(filepath, "rb") as f:
            header, _ = parse_header_stream(f)
    except (OSError, PermissionError):
        _exit_error(EXIT_FILE_ERROR, "File error.")
    except Exception:
        _cli_limiter.record_attempt("decrypt_file", rate_identifier, success=False)
        _audit_encryption(AuditEvent.DECRYPT_FILE, False, error="decryption_failed")
        _exit_error(EXIT_AUTH_ERROR, _V2_DECRYPT_FAILURE_MESSAGE)

    cred = _resolve_v2_credential_from_header(header, args)

    explicit_output = getattr(args, "output", None)
    try:
        decrypted_path = decrypt_v2_file(
            filepath,
            cred,
            output_path=Path(explicit_output) if explicit_output else None,
            overwrite=getattr(args, "force", False),
            restore_filename=getattr(args, "restore_filename", True),
        )
        _cli_limiter.record_attempt("decrypt_file", rate_identifier, success=True)
        _audit_encryption(AuditEvent.DECRYPT_FILE, True, file_path=str(filepath))
        _print_info(f"✓ Decrypted V2 container to {decrypted_path}")
        return EXIT_SUCCESS
    except CryptoError as e:
        if str(e).startswith("Output file already exists:"):
            _exit_error(
                EXIT_FILE_ERROR,
                "Output file already exists.\nRun again with --force to overwrite.",
            )
        _cli_limiter.record_attempt("decrypt_file", rate_identifier, success=False)
        _audit_encryption(AuditEvent.DECRYPT_FILE, False, error="decryption_failed")
        _exit_error(EXIT_AUTH_ERROR, _V2_DECRYPT_FAILURE_MESSAGE)
    except (OSError, PermissionError):
        _exit_error(EXIT_FILE_ERROR, "File error.")
    return EXIT_INPUT_ERROR


# =============================================================================
# Command: store
# =============================================================================


def cmd_store(args: argparse.Namespace) -> int:
    """Store password in vault."""
    vault = _get_vault()

    # Get password to store
    if args.generate:
        password, _ = generate_passphrase(length=24)
    else:
        password = _prompt_password_with_validation("Enter password to store: ")

    # Get master password
    master = _prompt_master_password()

    # Store in vault
    try:
        vault.store_passphrase(args.label, password, master)
        _audit_vault(AuditEvent.VAULT_STORE, True, vault, label=args.label)
        _print_info(
            f"✓ {'Generated and stored' if args.generate else 'Stored'} as: {args.label}"
        )
        return EXIT_SUCCESS
    except CryptoError:
        _audit_vault(
            AuditEvent.VAULT_STORE, False, vault, label=args.label, error="auth_failed"
        )
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except Exception:
        _audit_vault(
            AuditEvent.VAULT_STORE, False, vault, label=args.label, error="store_failed"
        )
        _exit_error(EXIT_VAULT_ERROR, "Failed to store passphrase.")


# =============================================================================
# Command: vault
# =============================================================================


def cmd_vault_list(args: argparse.Namespace) -> int:
    """List vault entries."""
    vault = _get_vault()
    master = _prompt_master_password()

    try:
        labels = vault.list_labels(master)
        if not labels:
            print("Vault is empty.")
        else:
            print("Stored labels:")
            for label in sorted(labels):
                print(f"  - {label}")
        _audit_vault(AuditEvent.VAULT_LIST, True, vault)
        return EXIT_SUCCESS
    except CryptoError:
        _audit_vault(AuditEvent.VAULT_LIST, False, vault, error="auth_failed")
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except ValueError:
        _audit_vault(AuditEvent.VAULT_LIST, False, vault, error="vault_error")
        _exit_error(EXIT_AUTH_ERROR, "Vault operation failed.")


def cmd_vault_delete(args: argparse.Namespace) -> int:
    """Delete vault entry."""
    vault = _get_vault()
    master = _prompt_master_password()

    try:
        vault.delete_passphrase(args.label, master)
        _audit_vault(AuditEvent.VAULT_DELETE, True, vault, label=args.label)
        _print_info(f"✓ Deleted: {args.label}")
        return EXIT_SUCCESS
    except ValueError as e:
        _audit_vault(
            AuditEvent.VAULT_DELETE, False, vault, label=args.label, error="vault_error"
        )
        if "not found" in str(e):
            _exit_error(EXIT_VAULT_ERROR, f"Label '{args.label}' not found.")
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except KeyError:
        _audit_vault(
            AuditEvent.VAULT_DELETE,
            False,
            vault,
            label=args.label,
            error="not_found",
        )
        _exit_error(EXIT_VAULT_ERROR, f"Label '{args.label}' not found.")
    except CryptoError:
        _audit_vault(
            AuditEvent.VAULT_DELETE, False, vault, label=args.label, error="auth_failed"
        )
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")


def cmd_vault_export(args: argparse.Namespace) -> int:
    """Export vault."""
    vault = _get_vault()
    master = _prompt_master_password()

    try:
        # Verify master password by listing labels
        vault.list_labels(master)

        content = vault.read_raw_vault()
        if content is not None:
            sys.stdout.buffer.write(content.encode("utf-8"))
            sys.stdout.buffer.flush()
            _audit_vault(AuditEvent.VAULT_LIST, True, vault)
            _print_info("✓ Vault exported (pipe to file to save)")
            return EXIT_SUCCESS
        _audit_vault(AuditEvent.VAULT_LIST, False, vault, error="vault_not_found")
        _exit_error(EXIT_VAULT_ERROR, "Vault not found.")
    except (CryptoError, ValueError):
        _audit_vault(AuditEvent.VAULT_LIST, False, vault, error="auth_failed")
        _exit_error(EXIT_AUTH_ERROR, "Vault export failed.")


def cmd_vault_import(args: argparse.Namespace) -> int:
    """Validate and transactionally import a vault backup."""
    import_path = Path(args.file)

    if not import_path.exists():
        _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

    vault = PassphraseVault()
    print(f"Candidate: {import_path}")
    print(f"Target backend: {vault.backend}")
    master = _prompt_master_password()

    try:
        content = read_bounded_vault_file(import_path)
        content = canonicalize_cli_vault_candidate(content)
        validate_raw_vault(content, master)
    except VaultTransactionError:
        _exit_error(EXIT_FILE_ERROR, "Cannot read import file.")
    except ValueError:
        _exit_error(EXIT_AUTH_ERROR, "Vault validation failed.")

    # Confirm if vault exists
    if vault.vault_exists():
        print("Existing vault will be replaced. Continue? (y/n): ", end="", flush=True)
        response = input().strip().lower()
        if response != "y":
            _exit_error(EXIT_INPUT_ERROR, "Import cancelled.")

    try:
        backup_identifier = vault.import_raw_vault(content, master, backup_current=True)
        _audit_vault(AuditEvent.VAULT_STORE, True, vault)
        _print_info("✓ Vault imported successfully.")
        if backup_identifier is not None:
            _print_info(f"Previous vault backup: {backup_identifier}")
        return EXIT_SUCCESS
    except VaultTransactionError as error:
        audit_category = (
            "rollback_failed"
            if error.rollback_succeeded is False
            else "transaction_failed"
        )
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error=audit_category)
        if error.rollback_succeeded is False:
            _exit_error(
                EXIT_VAULT_ERROR,
                "Import failed and rollback failed; active vault may be inconsistent.",
            )
        _exit_error(EXIT_VAULT_ERROR, "Import failed; active vault was preserved.")


def cmd_vault_reset(args: argparse.Namespace) -> int:
    """Reset (wipe) vault."""
    vault = PassphraseVault()

    if not vault.vault_exists():
        _exit_error(EXIT_VAULT_ERROR, "Vault does not exist.")

    print("⚠️  This will PERMANENTLY DELETE all stored passwords.")
    print("Type RESET to confirm: ", end="", flush=True)
    response = input().strip()

    if response != "RESET":
        _exit_error(EXIT_INPUT_ERROR, "Reset cancelled.")

    try:
        vault.delete_vault_storage()
        _audit_vault(AuditEvent.VAULT_DELETE, True, vault)
        _print_info("✓ Vault reset. All passwords deleted.")
        return EXIT_SUCCESS
    except OSError:
        _audit_vault(AuditEvent.VAULT_DELETE, False, vault, error="reset_failed")
        _exit_error(EXIT_FILE_ERROR, "Reset failed.")
    except Exception:
        _audit_vault(AuditEvent.VAULT_DELETE, False, vault, error="reset_failed")
        _exit_error(EXIT_VAULT_ERROR, "Reset failed.")


def cmd_vault_migrate(args: argparse.Namespace) -> int:
    """Migrate vault between backends."""
    from .keychain_backend import KeychainUnavailableError

    target = args.target_backend
    vault = PassphraseVault()

    master = _prompt_master_password()

    try:
        if target == "keychain":
            vault.migrate_to_keychain(master)
            set_vault_backend("keychain")
            _audit_vault(AuditEvent.VAULT_STORE, True, PassphraseVault())
            _print_info("✓ Vault migrated to OS keychain.")
            _print_info(
                "  Your vault is now stored in the OS keychain. "
                "The file vault remains as a backup."
            )
        else:
            vault.migrate_to_file(master)
            set_vault_backend("file")
            _audit_vault(AuditEvent.VAULT_STORE, True, PassphraseVault())
            _print_info("✓ Vault migrated to file.")
            _print_info(f"  Vault location: {vault.vault_path}")
        return EXIT_SUCCESS
    except KeychainUnavailableError:
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error="keychain_unavailable")
        _exit_error(
            EXIT_VAULT_ERROR,
            "Keychain backend unavailable. Install keychain support and ensure your OS keychain service is running.",
        )
    except ValueError:
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error="auth_failed")
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except Exception:
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error="migration_failed")
        _exit_error(EXIT_VAULT_ERROR, "Migration failed.")


def cmd_vault_status(args: argparse.Namespace) -> int:
    """Show active vault backend and locations."""
    settings = load_vault_settings()
    vault = PassphraseVault()

    print(f"Backend: {vault.backend}")
    print(f"Vault location: {vault.get_vault_path()}")
    print(f"File vault path: {vault.vault_path}")
    print(f"Backup directory: {vault.backup_dir}")
    print(f"Config backend: {settings.vault_backend}")
    print(f"Vault exists: {'yes' if vault.vault_exists() else 'no'}")
    return EXIT_SUCCESS


def cmd_vault_backend(args: argparse.Namespace) -> int:
    """Show or set the active vault backend."""
    if args.backend is None:
        settings = load_vault_settings()
        print(settings.vault_backend)
        return EXIT_SUCCESS

    try:
        settings = set_vault_backend(args.backend)
    except ValueError:
        _exit_error(EXIT_INPUT_ERROR, "Invalid vault backend.")

    _print_info(f"✓ Active vault backend set to: {settings.vault_backend}")
    return EXIT_SUCCESS


def cmd_vault_backups(args: argparse.Namespace) -> int:
    """List configured-vault backups without decrypted content."""
    vault = PassphraseVault()
    backups = vault.list_backup_records()
    if not backups:
        print("No backups available.")
        return EXIT_SUCCESS

    print("Available backups:")
    for backup in backups:
        print(f"  {backup.identifier}  {backup.created_at.isoformat()}")
    return EXIT_SUCCESS


def cmd_vault_restore(args: argparse.Namespace) -> int:
    """Validate and transactionally restore an exact backup identifier."""
    vault = PassphraseVault()
    print(f"Backup: {args.identifier}")

    print(f"Target backend: {vault.backend}")
    master = _prompt_master_password()
    try:
        vault.validate_backup(args.identifier, master)
    except VaultTransactionError:
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error="validation_failed")
        _exit_error(EXIT_AUTH_ERROR, "Restore validation failed.")

    if vault.vault_exists():
        print("Existing vault will be replaced. Continue? (y/n): ", end="", flush=True)
        if input().strip().lower() != "y":
            _exit_error(EXIT_INPUT_ERROR, "Restore cancelled.")

    try:
        backup_identifier = vault.restore_from_backup(args.identifier, master)
        _audit_vault(AuditEvent.VAULT_STORE, True, vault)
        _print_info(f"✓ Restored backup: {args.identifier}")
        if backup_identifier is not None:
            _print_info(f"Previous vault backup: {backup_identifier}")
        return EXIT_SUCCESS
    except VaultTransactionError as error:
        audit_category = (
            "rollback_failed"
            if error.rollback_succeeded is False
            else "transaction_failed"
        )
        _audit_vault(AuditEvent.VAULT_STORE, False, vault, error=audit_category)
        if error.rollback_succeeded is False:
            _exit_error(
                EXIT_VAULT_ERROR,
                "Restore failed and rollback failed; active vault may be inconsistent.",
            )
        _exit_error(EXIT_VAULT_ERROR, "Restore failed; active vault was preserved.")


def cmd_vault_migrate_schema(args: argparse.Namespace) -> int:
    """Migrate vault schema (V2)."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.migrate_schema(master)
        _audit_vault(AuditEvent.VAULT_MIGRATE_SCHEMA, True, vault)
        _print_info("✓ Vault schema migrated to V2.")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(
            AuditEvent.VAULT_MIGRATE_SCHEMA, False, vault, error="migration_failed"
        )
        _exit_error(EXIT_VAULT_ERROR, "Schema migration failed.")


def cmd_vault_change_password(args: argparse.Namespace) -> int:
    """Change master password."""
    vault = PassphraseVault()
    _print_info("Enter current master password:")
    old_master = _prompt_master_password()
    _print_info("Enter new master password:")
    new_master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.change_master_password(old_master, new_master)
        _audit_vault(AuditEvent.VAULT_CHANGE_PASSWORD, True, vault)
        _print_info("✓ Master password changed.")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(
            AuditEvent.VAULT_CHANGE_PASSWORD, False, vault, error="change_failed"
        )
        _exit_error(EXIT_VAULT_ERROR, "Password change failed.")


def cmd_vault(args: argparse.Namespace) -> int:
    """Vault subcommand router."""
    # This shouldn't be called directly - subparsers handle routing
    _exit_error(
        EXIT_INPUT_ERROR,
        "Must specify vault subcommand: list, delete, export, import, reset, "
        "migrate, status, backend, backups, restore, migrate-schema, change-password",
    )


# =============================================================================
# Command: key
# =============================================================================


def cmd_key_create(args: argparse.Namespace) -> int:
    """Generate new managed key."""
    from .v2.vault_schema import KeyStorageMode

    ext_path = str(args.external_file) if getattr(args, "external_file", None) else None
    vault_copy = getattr(args, "vault_copy", False)
    storage_mode = (
        KeyStorageMode.VAULT_COPY if vault_copy else KeyStorageMode.EXTERNAL_ONLY
    )

    if not vault_copy and ext_path is None:
        _exit_error(
            EXIT_INPUT_ERROR,
            "An external-only key needs --external-file PATH to save the "
            "generated secret, or use --vault-copy to store it in the vault "
            "instead. Neither was given, so no key was created.",
        )

    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        identity, _ = service.create_key(
            key_id=args.id,
            storage=storage_mode,
            master_password=master,
            export_path=Path(ext_path) if ext_path is not None else None,
        )
        _audit_vault(AuditEvent.KEY_CREATE, True, vault)
        _print_info(f"✓ Key created: {identity.fingerprint} ({identity.id})")
        return EXIT_SUCCESS
    except KeyExportSurvivedRegistrationFailureError as e:
        # Extracted before the sink call: the exception object itself must
        # never flow into an output/log sink (see check_sensitive_output.py),
        # only this specific non-secret attribute.
        written_to = e.export_path
        _audit_vault(AuditEvent.KEY_CREATE, False, vault, error="registration_failed")
        _exit_error(
            EXIT_VAULT_ERROR,
            "Key creation failed: the generated secret was written to "
            f"{written_to}, but registering it in the vault failed. "
            "That file is your real, recoverable key — keep it, or import "
            "it later with 'ssc key import'. Do not run 'ssc key create' "
            "again for this id until the vault issue is resolved.",
        )
    except Exception:
        _audit_vault(AuditEvent.KEY_CREATE, False, vault, error="creation_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key creation failed.")


def cmd_key_import(args: argparse.Namespace) -> int:
    """Register existing .ssckey."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        from .v2.keyfile import load_keyfile
        from .v2.vault_schema import KeyStorageMode

        key_data = load_keyfile(Path(args.file))
        storage_mode = (
            KeyStorageMode.VAULT_COPY
            if getattr(args, "vault_copy", False)
            else KeyStorageMode.EXTERNAL_ONLY
        )

        identity = service.import_key(
            keyfile_data=key_data,
            storage=storage_mode,
            master_password=master,
            path_hint=str(args.file),
        )
        _audit_vault(AuditEvent.KEY_IMPORT, True, vault)
        _print_info(f"✓ Key imported: {identity.fingerprint} ({identity.id})")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_IMPORT, False, vault, error="import_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key import failed.")


def cmd_key_list(args: argparse.Namespace) -> int:
    """Show all registered keys."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        keys = service.list_keys(master)
        if not keys:
            _print_info("No keys found.")
            return EXIT_SUCCESS

        for key in keys:
            print(f"{key.id}: {key.fingerprint} ({key.status.value})")
        _audit_vault(AuditEvent.VAULT_LIST, True, vault)
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.VAULT_LIST, False, vault, error="key_listing_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key listing failed.")


def cmd_key_show(args: argparse.Namespace) -> int:
    """Full details of a key."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        identity, _ = service.get_key(args.id, master)
        print(f"ID: {identity.id}")
        print(f"Fingerprint: {identity.fingerprint}")
        print(f"Status: {identity.status.value}")
        print(f"Type: {identity.type.value}")
        print(f"Storage: {identity.storage.value}")
        print(f"Created: {identity.created_at}")
        _audit_vault(AuditEvent.VAULT_RETRIEVE, True, vault)
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(
            AuditEvent.VAULT_RETRIEVE, False, vault, error="key_retrieval_failed"
        )
        _exit_error(EXIT_VAULT_ERROR, "Failed to get key details.")


def cmd_key_export(args: argparse.Namespace) -> int:
    """Export .ssckey to explicit destination."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.export_key(args.id, Path(args.dest), master)
        _audit_vault(AuditEvent.KEY_EXPORT, True, vault)
        _print_info(f"✓ Key exported to {args.dest}")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_EXPORT, False, vault, error="export_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key export failed.")


def cmd_key_rename(args: argparse.Namespace) -> int:
    """Change human ID."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.rename_key(args.id, args.new_id, master)
        _audit_vault(AuditEvent.KEY_RENAME, True, vault)
        _print_info(f"✓ Key {args.id} renamed to {args.new_id}")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_RENAME, False, vault, error="rename_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key rename failed.")


def cmd_key_archive(args: argparse.Namespace) -> int:
    """Set status=archived."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.archive_key(args.id, master)
        _audit_vault(AuditEvent.KEY_ARCHIVE, True, vault)
        _print_info(f"✓ Key {args.id} archived.")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_ARCHIVE, False, vault, error="archive_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key archiving failed.")


def cmd_key_revoke(args: argparse.Namespace) -> int:
    """Set status=revoked."""
    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.revoke_key(args.id, master)
        _audit_vault(AuditEvent.KEY_REVOKE, True, vault)
        _print_info(f"✓ Key {args.id} revoked.")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_REVOKE, False, vault, error="revoke_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key revocation failed.")


def cmd_key_destroy(args: argparse.Namespace) -> int:
    """Remove inner secret."""
    if not getattr(args, "confirm", False):
        print(
            "This will permanently destroy the key secret. Continue? (y/n): ",
            end="",
            flush=True,
        )
        if input().strip().lower() != "y":
            _exit_error(EXIT_INPUT_ERROR, "Key destruction cancelled.")

    vault = PassphraseVault()
    master = _prompt_master_password()
    service = V2VaultService(vault)
    try:
        service.destroy_key(args.id, master)
        _audit_vault(AuditEvent.KEY_DESTROY, True, vault)
        _print_info(f"✓ Key {args.id} destroyed.")
        return EXIT_SUCCESS
    except Exception:
        _audit_vault(AuditEvent.KEY_DESTROY, False, vault, error="destroy_failed")
        _exit_error(EXIT_VAULT_ERROR, "Key destruction failed.")


def cmd_key(args: argparse.Namespace) -> int:
    """Key subcommand router."""
    if hasattr(args, "key_command") and args.key_command is None:
        _exit_error(
            EXIT_INPUT_ERROR, "A key command is required. Try 'ssc key --help'."
        )
    return EXIT_SUCCESS


# =============================================================================
# Command: shred
# =============================================================================


def cmd_shred(args: argparse.Namespace) -> int:
    """Overwrite and delete files on a best-effort basis."""
    paths = [Path(p) for p in args.paths]
    force = args.force

    for path in paths:
        if not path.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {path}")

        if not force:
            print(
                f"Overwrite and delete (best effort): {path}? Type 'yes' to confirm: ",
                end="",
                flush=True,
            )
            response = input().strip()
            if response != "yes":
                _print_info(f"Skipped: {path}")
                continue

        try:
            secure_overwrite(str(path))
            _print_info(f"✓ Shredded: {path}")
        except OSError:
            _exit_error(EXIT_FILE_ERROR, f"Failed to shred {path}.")

    return EXIT_SUCCESS


# =============================================================================
# Argument Parser
# =============================================================================


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ssc",
        description="Secure String Cipher - AES-256-GCM encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc start                           Launch interactive menu
  ssc encrypt -t "secret message"     Encrypt text
  ssc encrypt -f document.pdf         Encrypt file
  ssc decrypt -t "gAAAA..."           Decrypt text
  ssc store "my-key" --generate       Generate and store password
  ssc vault list                      List stored labels

Run 'ssc <command> --help' for command-specific help.
""",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"secure-string-cipher {__version__}",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential output",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "On an unexpected failure, print a traceback to stderr instead of "
            "a one-line summary (or set SSC_DEBUG=1)"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", title="commands")

    # --- start ---
    start_parser = subparsers.add_parser(
        "start",
        help="Launch interactive menu",
        description="Launch the interactive menu interface.",
    )
    start_parser.set_defaults(func=cmd_start)

    # --- encrypt ---
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt text or files",
        description="Encrypt text or files using AES-256-GCM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc encrypt -t "secret message"
  ssc encrypt -f document.pdf
  ssc encrypt -t "secret" --vault "my-key"
  ssc encrypt -f doc.pdf --force
""",
    )
    encrypt_parser.add_argument(
        "-t",
        "--text",
        metavar="MESSAGE",
        help="Text to encrypt",
    )
    encrypt_parser.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        help="File to encrypt",
    )
    encrypt_parser.add_argument(
        "--vault",
        metavar="LABEL",
        help="Use password from vault",
    )
    encrypt_parser.add_argument(
        "--key-file",
        metavar="PATH",
        help="Use key file for encryption (deterministic key derivation)",
    )
    encrypt_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output file",
    )
    encrypt_parser.add_argument(
        "--with",
        action="append",
        dest="with_sources",
        metavar="SOURCE",
        help="V2 authentication source (e.g. 'password' or 'key:ID')",
    )
    encrypt_parser.add_argument(
        "--require",
        choices=["all", "any"],
        default="any",
        help="V2 authentication requirement when using multiple sources",
    )
    encrypt_parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Output file path (V2 only)",
    )
    encrypt_parser.add_argument(
        "positional_path",
        metavar="PATH",
        nargs="?",
        help="File to encrypt (positional alias for file workflow)",
    )
    encrypt_parser.set_defaults(func=cmd_encrypt)

    # --- decrypt ---
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt text or files",
        description="Decrypt text or files encrypted with ssc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc decrypt -t "gAAAAABh..."
  ssc decrypt -f document.pdf.enc
  ssc decrypt -t "gAAAAABh..." --vault "my-key"
""",
    )
    decrypt_parser.add_argument(
        "-t",
        "--text",
        metavar="CIPHERTEXT",
        help="Base64 ciphertext to decrypt",
    )
    decrypt_parser.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        help="File to decrypt",
    )
    decrypt_parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Output file path (overrides stored filename)",
    )
    decrypt_parser.add_argument(
        "--restore-filename",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Restore original filename from metadata when available (default: on)",
    )
    decrypt_parser.add_argument(
        "--vault",
        metavar="LABEL",
        help="Use password from vault",
    )
    decrypt_parser.add_argument(
        "--key-file",
        metavar="PATH",
        help="Use key file for decryption (deterministic key derivation)",
    )
    decrypt_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output file",
    )
    decrypt_parser.set_defaults(func=cmd_decrypt)

    # --- store ---
    store_parser = subparsers.add_parser(
        "store",
        help="Store password in vault",
        description="Store a password in the encrypted vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc store "my-key"              Prompt for password to store
  ssc store "my-key" --generate   Generate and store password
""",
    )
    store_parser.add_argument(
        "label",
        metavar="LABEL",
        help="Label for the stored password",
    )
    store_parser.add_argument(
        "-g",
        "--generate",
        action="store_true",
        help="Generate secure password instead of prompting",
    )
    store_parser.set_defaults(func=cmd_store)

    # --- vault ---
    vault_parser = subparsers.add_parser(
        "vault",
        help="Manage vault",
        description="Manage the password vault.",
    )
    vault_subparsers = vault_parser.add_subparsers(
        dest="vault_command", title="vault commands"
    )

    # vault list
    vault_list_parser = vault_subparsers.add_parser(
        "list",
        help="List all stored labels",
    )
    vault_list_parser.set_defaults(func=cmd_vault_list)

    # vault delete
    vault_delete_parser = vault_subparsers.add_parser(
        "delete",
        help="Delete a stored password",
    )
    vault_delete_parser.add_argument(
        "label",
        metavar="LABEL",
        help="Label to delete",
    )
    vault_delete_parser.set_defaults(func=cmd_vault_delete)

    # vault export
    vault_export_parser = vault_subparsers.add_parser(
        "export",
        help="Export vault to stdout",
    )
    vault_export_parser.set_defaults(func=cmd_vault_export)

    # vault import
    vault_import_parser = vault_subparsers.add_parser(
        "import",
        help="Import vault from backup",
    )
    vault_import_parser.add_argument(
        "file",
        metavar="FILE",
        help="Backup file to import",
    )
    vault_import_parser.set_defaults(func=cmd_vault_import)

    # vault reset
    vault_reset_parser = vault_subparsers.add_parser(
        "reset",
        help="Wipe vault (requires confirmation)",
    )
    vault_reset_parser.set_defaults(func=cmd_vault_reset)

    # vault migrate
    vault_migrate_parser = vault_subparsers.add_parser(
        "migrate",
        help="Migrate vault between backends (file ↔ keychain)",
        description="Migrate vault data between file and keychain backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc vault migrate --to keychain    Move vault to OS keychain
  ssc vault migrate --to file        Move vault back to disk
""",
    )
    vault_migrate_parser.add_argument(
        "--to",
        dest="target_backend",
        choices=["keychain", "file"],
        required=True,
        help="Target backend to migrate to",
    )
    vault_migrate_parser.set_defaults(func=cmd_vault_migrate)

    # vault status
    vault_status_parser = vault_subparsers.add_parser(
        "status",
        help="Show active vault backend and locations",
    )
    vault_status_parser.set_defaults(func=cmd_vault_status)

    # vault backend
    vault_backend_parser = vault_subparsers.add_parser(
        "backend",
        help="Show or set active vault backend",
        description="Show or set the active vault backend.",
    )
    vault_backend_parser.add_argument(
        "--set",
        dest="backend",
        choices=["file", "keychain"],
        help="Persist active vault backend",
    )
    vault_backend_parser.set_defaults(func=cmd_vault_backend)

    # vault backups
    vault_backups_parser = vault_subparsers.add_parser(
        "backups",
        help="List file-vault backups",
    )
    vault_backups_parser.set_defaults(func=cmd_vault_backups)

    # vault restore
    vault_restore_parser = vault_subparsers.add_parser(
        "restore",
        help="Restore a vault backup by exact identifier",
    )
    vault_restore_parser.add_argument(
        "identifier",
        metavar="BACKUP_ID",
        help="Exact backup identifier from `ssc vault backups`",
    )
    vault_restore_parser.set_defaults(func=cmd_vault_restore)

    # vault migrate-schema
    vault_migrate_schema_parser = vault_subparsers.add_parser(
        "migrate-schema",
        help="Explicit schema migration (separate from backend migration)",
    )
    vault_migrate_schema_parser.set_defaults(func=cmd_vault_migrate_schema)

    # vault change-password
    vault_change_pwd_parser = vault_subparsers.add_parser(
        "change-password",
        help="Master password change with inner-key rewrapping",
    )
    vault_change_pwd_parser.set_defaults(func=cmd_vault_change_password)

    vault_parser.set_defaults(func=cmd_vault)

    # --- key ---
    key_parser = subparsers.add_parser(
        "key",
        help="Manage V2 encryption keys",
        description="Manage lifecycle of V2 managed keys.",
    )
    key_subparsers = key_parser.add_subparsers(dest="key_command", title="key commands")

    # key create
    key_create_parser = key_subparsers.add_parser(
        "create", help="Generate new managed key"
    )
    key_create_parser.add_argument("id", metavar="ID", help="New key ID")
    key_create_parser.add_argument(
        "--external-file",
        metavar="PATH",
        help="Write the generated .ssckey to this path",
    )
    key_create_parser.add_argument(
        "--vault-copy", action="store_true", help="Store a copy in the secure vault"
    )
    key_create_parser.set_defaults(func=cmd_key_create)

    # key import
    key_import_parser = key_subparsers.add_parser(
        "import", help="Register existing .ssckey"
    )
    key_import_parser.add_argument("file", metavar="PATH", help="Path to .ssckey file")
    key_import_parser.add_argument(
        "--vault-copy", action="store_true", help="Store a copy in the secure vault"
    )
    key_import_parser.set_defaults(func=cmd_key_import)

    # key list
    key_list_parser = key_subparsers.add_parser("list", help="Show all registered keys")
    key_list_parser.set_defaults(func=cmd_key_list)

    # key show
    key_show_parser = key_subparsers.add_parser("show", help="Full details of a key")
    key_show_parser.add_argument("id", metavar="ID", help="Key ID")
    key_show_parser.set_defaults(func=cmd_key_show)

    # key export
    key_export_parser = key_subparsers.add_parser(
        "export", help="Export .ssckey to explicit destination"
    )
    key_export_parser.add_argument("id", metavar="ID", help="Key ID")
    key_export_parser.add_argument("dest", metavar="PATH", help="Destination path")
    key_export_parser.set_defaults(func=cmd_key_export)

    # key rename
    key_rename_parser = key_subparsers.add_parser("rename", help="Change human ID")
    key_rename_parser.add_argument("id", metavar="ID", help="Current key ID")
    key_rename_parser.add_argument("new_id", metavar="NEW_ID", help="New key ID")
    key_rename_parser.set_defaults(func=cmd_key_rename)

    # key archive
    key_archive_parser = key_subparsers.add_parser(
        "archive", help="Set status=archived (bookkeeping only, never blocks use)"
    )
    key_archive_parser.add_argument("id", metavar="ID", help="Key ID")
    key_archive_parser.set_defaults(func=cmd_key_archive)

    # key revoke
    key_revoke_parser = key_subparsers.add_parser(
        "revoke",
        help="Set status=revoked (enforced at encrypt/decrypt only with --vault)",
    )
    key_revoke_parser.add_argument("id", metavar="ID", help="Key ID")
    key_revoke_parser.set_defaults(func=cmd_key_revoke)

    # key destroy
    key_destroy_parser = key_subparsers.add_parser(
        "destroy", help="Remove inner secret, leaving tombstone"
    )
    key_destroy_parser.add_argument("id", metavar="ID", help="Key ID")
    key_destroy_parser.add_argument(
        "--confirm", action="store_true", help="Skip confirmation prompt"
    )
    key_destroy_parser.set_defaults(func=cmd_key_destroy)

    key_parser.set_defaults(func=cmd_key)

    # --- shred ---
    shred_parser = subparsers.add_parser(
        "shred",
        help="Best-effort overwrite and delete",
        description=(
            "Overwrite files once with zeros, sync, then delete them. Erasure is "
            "best effort: SSDs, copy-on-write storage, snapshots, and backups "
            "may retain copies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ssc shred secret.txt
  ssc shred file1.txt file2.txt --force
""",
    )
    shred_parser.add_argument(
        "paths",
        metavar="PATH",
        nargs="+",
        help="Files to shred",
    )
    shred_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    shred_parser.set_defaults(func=cmd_shred)

    return parser


# =============================================================================
# Main Entry Point
# =============================================================================


def _env_flag_enabled(name: str) -> bool:
    """Report whether an environment variable holds an affirmative value.

    Only an explicit affirmative enables the flag. Treating "any non-empty
    value except 0" as true would mean `SSC_DEBUG=false` — a common way for a
    deployment manifest to disable an option — switched debug output *on*,
    which for this particular flag would start printing exception text.
    """
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _classify_failure(error: BaseException) -> tuple[int, str]:
    """Map an escaped exception to an exit code and a user-facing message.

    Without this, every unanticipated failure collapsed into a single
    "Command failed." with EXIT_INPUT_ERROR, which told a script that its
    arguments were wrong when the real cause might have been a full disk, a
    revoked key or a bug in this program. The documented exit-code taxonomy
    above only described the codes that individual commands returned
    deliberately; anything raised was flattened.

    Specific types are tested before their bases: VaultBusyError,
    VaultTransactionError and KeyWrapError all derive from ValueError, and
    PermissionError/FileNotFoundError derive from OSError.
    """
    # Rate limiting carries its own wait time and was previously uncaught.
    if isinstance(error, RateLimitError):
        return EXIT_AUTH_ERROR, str(error)

    # Credential / cryptographic failures.
    if isinstance(error, KeyWrapError | CryptoError):
        return EXIT_AUTH_ERROR, str(error) or _V2_DECRYPT_FAILURE_MESSAGE

    # Vault state: busy, mid-transaction, missing record, or backend trouble.
    if isinstance(
        error,
        VaultBusyError
        | VaultTransactionError
        | KeyExportSurvivedRegistrationFailureError
        | KeychainError,
    ):
        return EXIT_VAULT_ERROR, str(error)

    # KeyError is deliberately *not* mapped to a vault miss. V2VaultService
    # does raise it for an unknown key id, but KeyError is also one of the
    # most common ordinary programming faults, and its str() is the missing
    # key itself — which on a non-vault path could be arbitrary content. It
    # therefore falls through to the sanitized internal-error branch below.
    # Distinguishing a genuine vault miss needs a typed not-found exception
    # on the service, which belongs with the service-layer extraction rather
    # than here.

    # Path and permission policy violations.
    if isinstance(error, SecurityError):
        return EXIT_FILE_ERROR, str(error)

    # Filesystem problems.
    if isinstance(error, OSError):
        detail = error.strerror or str(error)
        location = f": {error.filename}" if error.filename else ""
        return EXIT_FILE_ERROR, f"{detail}{location}"

    # No input available — typically getpass with stdin closed, which is how
    # a non-interactive invocation without a credential source fails.
    if isinstance(error, EOFError):
        return (
            EXIT_INPUT_ERROR,
            "No input available for a required prompt. This command needs a "
            "credential it can only read interactively.",
        )

    # Anything left is a fault in this program. Report the type but not the
    # message, which could carry arbitrary interpolated content; --debug
    # prints the full traceback for diagnosis.
    return (
        EXIT_INTERNAL_ERROR,
        f"Internal error ({type(error).__name__}). "
        "Re-run with --debug for a traceback, and please report this.",
    )


def main() -> NoReturn:
    """Main entry point for ssc CLI."""
    global _quiet_mode, _no_color, _debug_mode

    parser = create_parser()
    args = parser.parse_args()

    # Set global flags
    _quiet_mode = args.quiet
    _no_color = args.no_color
    _debug_mode = args.debug or _env_flag_enabled("SSC_DEBUG")

    # No command specified
    if not args.command:
        parser.print_help()
        sys.exit(EXIT_SUCCESS)

    # Vault subcommand check
    if args.command == "vault" and not hasattr(args, "func"):
        _exit_error(
            EXIT_INPUT_ERROR,
            "Must specify vault subcommand: list, delete, export, import, reset, "
            "migrate, status, backend, backups, restore",
        )

    if args.command == "vault" and args.vault_command is None:
        _exit_error(
            EXIT_INPUT_ERROR,
            "Must specify vault subcommand: list, delete, export, import, reset, "
            "migrate, status, backend, backups, restore",
        )

    # Run command
    try:
        exit_code = args.func(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(EXIT_INPUT_ERROR)
    except Exception as error:
        if _debug_mode:
            traceback.print_exc()
        code, message = _classify_failure(error)
        _exit_error(code, message)


if __name__ == "__main__":
    main()
