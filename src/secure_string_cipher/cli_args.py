"""Non-interactive command-line interface for secure-string-cipher.

This module provides the `ssc` CLI with subcommands for encryption,
decryption, and vault management.

Entry point: ssc
Subcommands: start, encrypt, decrypt, store, vault
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import NoReturn

from . import __version__
from .cli import main as run_interactive_menu
from .config import METADATA_MAGIC
from .core import (
    CryptoError,
    FileMetadata,
    _ensure_no_symlink,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
)
from .passphrase_generator import generate_passphrase
from .passphrase_manager import PassphraseVault
from .rate_limiter import RateLimiter
from .security import sanitize_filename
from .timing_safe import check_password_strength
from .utils import colorize, secure_overwrite

# Global rate limiter for CLI authentication attempts
_cli_limiter = RateLimiter()

# =============================================================================
# Exit Codes
# =============================================================================

EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1  # Invalid arguments, missing flags
EXIT_AUTH_ERROR = 2  # Wrong password, decryption failed
EXIT_VAULT_ERROR = 3  # Not initialized, label not found
EXIT_FILE_ERROR = 4  # Not found, permission denied

# =============================================================================
# Global State
# =============================================================================

_quiet_mode = False
_no_color = False


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
        is_strong, issues = check_password_strength(password)

        if is_strong:
            # Confirm
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                _print_error("Passwords do not match. Try again.")
                continue
            return password

        _print_error("Password does not meet security requirements:")
        for issue in issues:
            print(f"  ✗ {issue}", file=sys.stderr)
        print(file=sys.stderr)


def _prompt_master_password() -> str:
    """Prompt for vault master password."""
    return getpass.getpass("Master password: ")


def _get_vault() -> PassphraseVault:
    """Get or initialize the vault."""
    vault = PassphraseVault()

    # Check if vault exists
    if not vault.vault_path.exists():
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
        _exit_error(
            EXIT_AUTH_ERROR,
            f"Too many failed attempts. Please wait {wait:.0f} seconds.",
        )

    master = _prompt_master_password()

    try:
        result = vault.retrieve_passphrase(label, master)
        _cli_limiter.record_attempt("vault_unlock", vault_id, success=True)
        return result
    except KeyError:
        _exit_error(EXIT_VAULT_ERROR, f"Label '{label}' not found in vault.")
    except (CryptoError, ValueError):
        _cli_limiter.record_attempt("vault_unlock", vault_id, success=False)
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
    from hashlib import sha256

    key_file = Path(key_file_path)
    _ensure_no_symlink(key_file, "key file")
    if not key_file.exists():
        _exit_error(EXIT_FILE_ERROR, f"Key file not found: {key_file_path}")
    key_data = key_file.read_bytes()
    if len(key_data) == 0:
        _exit_error(EXIT_FILE_ERROR, f"Key file is empty: {key_file_path}")
    return sha256(key_data).hexdigest()


def _load_file_metadata(input_path: Path) -> FileMetadata:
    """Load unencrypted metadata from an encrypted file.

    Args:
        input_path: Encrypted file path

    Returns:
        Parsed FileMetadata

    Raises:
        CryptoError: When the file is malformed or missing required headers
    """

    with open(input_path, "rb") as f:
        magic = f.read(len(METADATA_MAGIC))
        if magic != METADATA_MAGIC:
            raise CryptoError(
                "Invalid file format: missing magic header. "
                "This file may have been encrypted with an older version."
            )

        meta_len_bytes = f.read(2)
        if len(meta_len_bytes) != 2:
            raise CryptoError("Invalid file: truncated metadata length")
        meta_len = int.from_bytes(meta_len_bytes, "big")
        if meta_len > 65535:
            raise CryptoError("Invalid file: metadata too large")

        meta_bytes = f.read(meta_len)
        if len(meta_bytes) != meta_len:
            raise CryptoError("Invalid file: truncated metadata")

    return FileMetadata.from_bytes(meta_bytes)


def _determine_output_path(filepath: Path, restore_filename: bool) -> Path:
    """Choose output path using metadata when available.

    Prefers restoring the original filename stored in metadata when
    `restore_filename` is True; otherwise falls back to deterministic names
    that avoid overwriting the original file.
    """

    metadata: FileMetadata | None = None
    if restore_filename:
        try:
            metadata = _load_file_metadata(filepath)
        except CryptoError:
            metadata = None

    if restore_filename and metadata and metadata.original_filename:
        safe_name = sanitize_filename(metadata.original_filename)
        if safe_name:
            output_dir = filepath.parent or Path(".")
            return output_dir / safe_name

    if not restore_filename and filepath.suffix == ".enc":
        return filepath.with_suffix(".dec")

    if filepath.suffix == ".enc":
        return filepath.with_suffix("")

    return filepath.with_name(filepath.name + ".dec")


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
    output_path = None
    if args.file and args.file != "-":
        filepath = Path(args.file)

        if not filepath.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        output_path = filepath.with_suffix(filepath.suffix + ".enc")

        # Check overwrite
        if output_path.exists() and not args.force:
            _exit_error(
                EXIT_FILE_ERROR,
                f"{output_path} already exists.\nRun again with --force to overwrite.",
            )

    # Get password/key
    password: str
    if args.vault:
        password = _get_password_from_vault(args.vault)
    elif getattr(args, "key_file", None):
        try:
            password = _get_password_from_key_file(args.key_file)
        except CryptoError:
            raise
        except Exception as e:
            _exit_error(EXIT_FILE_ERROR, f"Key file error: {e}")
    else:
        password = _prompt_password("Enter password: ", confirm=True)

    # Encrypt text
    if args.text:
        try:
            ciphertext = encrypt_text(args.text, password)
            print(ciphertext)
            _print_info("✓ Encrypted successfully")
            return EXIT_SUCCESS
        except CryptoError as e:
            _exit_error(EXIT_AUTH_ERROR, f"Encryption failed: {e}")

    # Encrypt file
    if args.file:
        filepath = args.file

        # Handle stdin/stdout streaming
        if filepath == "-":
            try:
                data = sys.stdin.buffer.read()
                ciphertext = encrypt_text(
                    data.decode("utf-8", errors="replace"), password
                )
                sys.stdout.buffer.write((ciphertext + "\n").encode("utf-8"))
                _print_info("✓ Encrypted stdin to stdout")
                return EXIT_SUCCESS
            except CryptoError as e:
                _exit_error(EXIT_AUTH_ERROR, f"Encryption failed: {e}")
            except Exception as e:
                _exit_error(EXIT_FILE_ERROR, f"Error: {e}")

        filepath_obj = Path(filepath)
        output_path = filepath_obj.with_suffix(filepath_obj.suffix + ".enc")

        # Remove file for overwrite
        if output_path.exists() and args.force:
            output_path.unlink()

        try:
            encrypt_file(str(filepath_obj), str(output_path), password)
            _print_info(f"✓ Encrypted to {output_path}")
            return EXIT_SUCCESS
        except CryptoError as e:
            _exit_error(EXIT_AUTH_ERROR, f"Encryption failed: {e}")
        except PermissionError:
            _exit_error(EXIT_FILE_ERROR, f"Permission denied: {args.file}")
        except OSError as e:
            _exit_error(EXIT_FILE_ERROR, f"File error: {e}")

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
    if args.file:
        filepath = Path(args.file)

        if not filepath.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        # Determine intended output path (surface filesystem errors as file-exit)
        try:
            _ensure_no_symlink(filepath, "input")
            if output_arg:
                output_path = Path(output_arg)
            else:
                output_path = _determine_output_path(filepath, restore_filename)
        except (OSError, PermissionError, CryptoError) as e:
            _exit_error(EXIT_FILE_ERROR, f"File error: {e}")

        # Check overwrite
        if output_path.exists() and not args.force:
            _exit_error(
                EXIT_FILE_ERROR,
                f"{output_path} already exists.\nRun again with --force to overwrite.",
            )

    # Get password/key
    password: str
    if args.vault:
        password = _get_password_from_vault(args.vault)
    elif getattr(args, "key_file", None):
        try:
            password = _get_password_from_key_file(args.key_file)
        except CryptoError:
            raise
        except Exception as e:
            _exit_error(EXIT_FILE_ERROR, f"Key file error: {e}")
    else:
        password = _prompt_password("Enter password: ", confirm=False)

    # Decrypt text
    if args.text:
        # Rate limit text decryption attempts
        allowed, wait = _cli_limiter.check_rate_limit("decrypt_text", "")
        if not allowed:
            _exit_error(
                EXIT_AUTH_ERROR,
                f"Too many failed attempts. Please wait {wait:.0f} seconds.",
            )
        try:
            plaintext = decrypt_text(args.text, password)
            _cli_limiter.record_attempt("decrypt_text", "", success=True)
            print(plaintext)
            _print_info("✓ Decrypted successfully")
            return EXIT_SUCCESS
        except CryptoError:
            _cli_limiter.record_attempt("decrypt_text", "", success=False)
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
                data = sys.stdin.buffer.read().decode("utf-8").strip()
                plaintext = decrypt_text(data, password)
                sys.stdout.buffer.write(plaintext.encode("utf-8"))
                _print_info("✓ Decrypted stdin to stdout")
                return EXIT_SUCCESS
            except CryptoError as e:
                _exit_error(EXIT_AUTH_ERROR, f"Decryption failed: {e}")
            except Exception as e:
                _exit_error(EXIT_FILE_ERROR, f"Error: {e}")

        filepath_obj = Path(filepath)

        if not filepath_obj.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

        # Determine intended output path (surface filesystem errors as file-exit)
        try:
            _ensure_no_symlink(filepath_obj, "input")
            if output_arg:
                output_path = Path(output_arg)
            else:
                output_path = _determine_output_path(filepath_obj, restore_filename)
        except (OSError, PermissionError, CryptoError) as e:
            _exit_error(EXIT_FILE_ERROR, f"File error: {e}")

        # Check overwrite
        if output_path.exists():
            if not args.force:
                _exit_error(
                    EXIT_FILE_ERROR,
                    f"{output_path} already exists.\nRun again with --force to overwrite.",
                )
            # Remove existing file for overwrite
            output_path.unlink()

        try:
            actual_output, _ = decrypt_file(
                str(filepath_obj),
                str(output_path) if output_path else None,
                password,
                restore_filename=restore_filename,
            )
            _cli_limiter.record_attempt("decrypt_file", str(filepath_obj), success=True)
            _print_info(f"✓ Decrypted to {actual_output}")
            return EXIT_SUCCESS
        except CryptoError:
            _cli_limiter.record_attempt(
                "decrypt_file", str(filepath_obj), success=False
            )
            _exit_error(
                EXIT_AUTH_ERROR, "Decryption failed. Wrong password or corrupted data."
            )
        except PermissionError:
            _exit_error(EXIT_FILE_ERROR, f"Permission denied: {args.file}")
        except OSError as e:
            _exit_error(EXIT_FILE_ERROR, f"File error: {e}")

    return EXIT_SUCCESS


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
        _print_info(
            f"✓ {'Generated and stored' if args.generate else 'Stored'} as: {args.label}"
        )
        return EXIT_SUCCESS
    except CryptoError:
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")
    except Exception as e:
        _exit_error(EXIT_VAULT_ERROR, f"Failed to store: {e}")


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
        return EXIT_SUCCESS
    except CryptoError:
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")


def cmd_vault_delete(args: argparse.Namespace) -> int:
    """Delete vault entry."""
    vault = _get_vault()
    master = _prompt_master_password()

    try:
        vault.delete_passphrase(args.label, master)
        _print_info(f"✓ Deleted: {args.label}")
        return EXIT_SUCCESS
    except KeyError:
        _exit_error(EXIT_VAULT_ERROR, f"Label '{args.label}' not found.")
    except CryptoError:
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")


def cmd_vault_export(args: argparse.Namespace) -> int:
    """Export vault."""
    vault = _get_vault()
    master = _prompt_master_password()

    try:
        # Verify master password by listing labels
        vault.list_labels(master)

        # Read raw vault file
        if vault.vault_path.exists():
            content = vault.vault_path.read_text()
            print(content)
            _print_info("✓ Vault exported (pipe to file to save)")
            return EXIT_SUCCESS
        else:
            _exit_error(EXIT_VAULT_ERROR, "Vault file not found.")
    except CryptoError:
        _exit_error(EXIT_AUTH_ERROR, "Wrong master password.")


def _validate_vault_format(content: str) -> bool:
    """Validate imported vault file format.

    Checks for SSCVAULT header, HMAC salt, data separator,
    encrypted payload, and HMAC separator.
    """
    lines = content.strip().split("\n")
    if len(lines) < 6:
        return False
    if not lines[0].startswith("SSCVAULT"):
        return False
    if lines[2] != "---DATA---":
        return False
    if "---HMAC---" not in lines:
        return False
    # Validate salt is hex
    try:
        bytes.fromhex(lines[1])
    except ValueError:
        return False
    return True


def cmd_vault_import(args: argparse.Namespace) -> int:
    """Import vault from backup."""
    import_path = Path(args.file)

    if not import_path.exists():
        _exit_error(EXIT_FILE_ERROR, f"File not found: {args.file}")

    vault = PassphraseVault()

    # Validate vault format before replacing
    try:
        content = import_path.read_text()
    except OSError as e:
        _exit_error(EXIT_FILE_ERROR, f"Cannot read import file: {e}")

    if not _validate_vault_format(content):
        _exit_error(
            EXIT_FILE_ERROR,
            "Invalid vault format. File does not appear to be a valid vault backup.",
        )

    # Confirm if vault exists
    if vault.vault_path.exists():
        print("Existing vault will be replaced. Continue? (y/n): ", end="", flush=True)
        response = input().strip().lower()
        if response != "y":
            _exit_error(EXIT_INPUT_ERROR, "Import cancelled.")

    try:
        vault.vault_path.parent.mkdir(parents=True, exist_ok=True)
        vault.vault_path.write_text(content)
        os.chmod(vault.vault_path, 0o600)
        _print_info("✓ Vault imported successfully")
        return EXIT_SUCCESS
    except OSError as e:
        _exit_error(EXIT_FILE_ERROR, f"Import failed: {e}")


def cmd_vault_reset(args: argparse.Namespace) -> int:
    """Reset (wipe) vault."""
    vault = PassphraseVault()

    if not vault.vault_path.exists():
        _exit_error(EXIT_VAULT_ERROR, "Vault does not exist.")

    print("⚠️  This will PERMANENTLY DELETE all stored passwords.")
    print("Type RESET to confirm: ", end="", flush=True)
    response = input().strip()

    if response != "RESET":
        _exit_error(EXIT_INPUT_ERROR, "Reset cancelled.")

    try:
        vault.vault_path.unlink()
        _print_info("✓ Vault reset. All passwords deleted.")
        return EXIT_SUCCESS
    except OSError as e:
        _exit_error(EXIT_FILE_ERROR, f"Reset failed: {e}")


def cmd_vault(args: argparse.Namespace) -> int:
    """Vault subcommand router."""
    # This shouldn't be called directly - subparsers handle routing
    _exit_error(
        EXIT_INPUT_ERROR,
        "Must specify vault subcommand: list, delete, export, import, reset",
    )


# =============================================================================
# Command: shred
# =============================================================================


def cmd_shred(args: argparse.Namespace) -> int:
    """Securely delete files."""
    paths = [Path(p) for p in args.paths]
    force = args.force

    for path in paths:
        if not path.exists():
            _exit_error(EXIT_FILE_ERROR, f"File not found: {path}")

        if not force:
            print(
                f"Securely delete: {path}? Type 'yes' to confirm: ", end="", flush=True
            )
            response = input().strip()
            if response != "yes":
                _print_info(f"Skipped: {path}")
                continue

        try:
            secure_overwrite(str(path))
            _print_info(f"✓ Shredded: {path}")
        except OSError as e:
            _exit_error(EXIT_FILE_ERROR, f"Failed to shred {path}: {e}")

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

    vault_parser.set_defaults(func=cmd_vault)

    # --- shred ---
    shred_parser = subparsers.add_parser(
        "shred",
        help="Securely delete files",
        description="Securely overwrite and delete files using multiple passes.",
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


def main() -> NoReturn:
    """Main entry point for ssc CLI."""
    global _quiet_mode, _no_color

    parser = create_parser()
    args = parser.parse_args()

    # Set global flags
    _quiet_mode = args.quiet
    _no_color = args.no_color

    # No command specified
    if not args.command:
        parser.print_help()
        sys.exit(EXIT_SUCCESS)

    # Vault subcommand check
    if args.command == "vault" and not hasattr(args, "func"):
        _exit_error(
            EXIT_INPUT_ERROR,
            "Must specify vault subcommand: list, delete, export, import, reset",
        )

    if args.command == "vault" and args.vault_command is None:
        _exit_error(
            EXIT_INPUT_ERROR,
            "Must specify vault subcommand: list, delete, export, import, reset",
        )

    # Run command
    try:
        exit_code = args.func(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(EXIT_INPUT_ERROR)
    except Exception as e:
        _exit_error(EXIT_INPUT_ERROR, str(e))


if __name__ == "__main__":
    main()
