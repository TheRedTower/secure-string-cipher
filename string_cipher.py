#!/usr/bin/env python3
"""
secure-string-cipher - A secure, user-friendly encryption utility

This tool provides AES-256-GCM encryption with a focus on security,
usability, and efficiency. It supports both text and file encryption
with progress tracking, strong password validation, and safe file handling.

Security Features:
  • AES-256-GCM authenticated encryption
  • PBKDF2-HMAC-SHA256 key derivation (390k iterations)
  • Secure random salt and nonce generation
  • Strong password validation
  • File integrity protection

Usability Features:
  • Progress tracking for large files
  • Safe file handling with overwrite protection
  • Memory-efficient streaming (64 KiB chunks)
  • Clipboard integration
  • Color-aware interactive CLI
  • Detailed error messages

Installation Options:
  1. pip install secure-string-cipher    # Recommended
  2. pipx install secure-string-cipher   # Isolated environment
  3. Download and run directly           # Auto-installs dependencies

Usage:
  As package: cipher
  Direct:    python3 string_cipher.py

Project: https://github.com/yourusername/secure-string-cipher
License: MIT
"""

from __future__ import annotations
import base64
import io
import os
import sys
import time
import secrets
from pathlib import Path
from typing import Optional, BinaryIO

from .config import (
    CHUNK_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    KDF_ITERATIONS,
    COLORS
)

class CryptoError(Exception):
    """Custom exception for encryption/decryption errors."""
    pass

import importlib.util
import subprocess

# Package management with secure defaults
def _ensure_dependencies():
    """Ensure required packages are available, with secure installation."""
    PACKAGES = {
        "cryptography": ">=41.0.0",  # Minimum version for security
        "pyperclip": ">=1.8.0"      # Stable version
    }
    
    def _verify_pkg(name: str, min_version: str) -> bool:
        """Verify package is installed with minimum version."""
        try:
            pkg = __import__(name)
            if hasattr(pkg, '__version__'):
                from packaging.version import parse
                return parse(pkg.__version__) >= parse(min_version.lstrip('>='))
            return True  # Can't verify version
        except ImportError:
            return False
    
    missing = [(name, ver) for name, ver in PACKAGES.items() 
               if not _verify_pkg(name, ver)]
    
    if not missing:
        return
        
    if not sys.stdout.isatty():
        sys.exit("Required packages missing and no TTY available for prompts.")
    
    print(_colour("\n📦 Required packages missing or outdated:"))
    for name, ver in missing:
        print(_colour(f"  • {name}{ver}"))
    
    # Offer installation options
    print(_colour("\nInstallation options:"))
    print(_colour("1) Install in temporary environment (recommended)"))
    print(_colour("2) Install in user environment"))
    print(_colour("3) Exit"))
    
    choice = input(_colour("\nSelect option [1]: ")).strip() or "1"
    
    if choice == "3":
        sys.exit("Installation cancelled.")
        
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--no-input"]
        
        if choice == "1":
            import tempfile
            import atexit
            import shutil
            
            # Create temporary environment
            temp_dir = tempfile.mkdtemp(prefix="cipher_deps_")
            atexit.register(shutil.rmtree, temp_dir, ignore_errors=True)
            
            cmd.extend(["--target", temp_dir])
            print(_colour("\nInstalling in temporary environment..."))
        else:
            cmd.append("--user")
            print(_colour("\nInstalling in user environment..."))
        
        # Install packages with version constraints
        cmd.extend(f"{name}{ver}" for name, ver in missing)
        subprocess.check_call(cmd)
        
        # Add temporary directory to path if used
        if choice == "1":
            sys.path.insert(0, temp_dir)
            
    except subprocess.CalledProcessError as e:
        sys.exit(f"Package installation failed: {e}")
    except Exception as e:
        sys.exit(f"Unexpected error during installation: {e}")

# Ensure dependencies are available
_ensure_dependencies()

# Now safe to import pyperclip
import pyperclip

# Crypto imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
Configuration settings for secure-string-cipher
"""

# Cryptographic parameters
CHUNK_SIZE = 64 * 1024  # 64 KiB stream size
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KDF_ITERATIONS = 390_000

# Security limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MIN_PASSWORD_LENGTH = 12
PASSWORD_PATTERNS = {
    'uppercase': lambda s: any(c.isupper() for c in s),
    'lowercase': lambda s: any(c.islower() for c in s),
    'digits': lambda s: any(c.isdigit() for c in s),
    'symbols': lambda s: any(not c.isalnum() for c in s)
}
COMMON_PASSWORDS = {
    'password', '123456', 'qwerty', 'admin',
    'letmein', 'welcome', 'monkey', 'dragon'
}

# Terminal colors
COLORS = {
    'reset': '\033[0m',
    'cyan': '\033[96m',
    'blue': '\033[34m',
    'red': '\033[91m',
    'green': '\033[92m'
}

# Command line interface
DEFAULT_MODE = 1  # Encrypt text
CLIPBOARD_ENABLED = True
CLI_TIMEOUT = 300  # 5 minutes inactivity timeout

class ProgressBar:
    """Simple progress bar for file operations."""
    def __init__(self, total_bytes: int, width: int = 40):
        self.total = total_bytes
        self.width = width
        self.last_print = 0
    
    def update(self, current: int):
        if not sys.stdout.isatty():
            return
        
        # Update at most 10 times/second
        now = time.time()
        if now - self.last_print < 0.1 and current < self.total:
            return
        
        self.last_print = now
        filled = int(self.width * current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)
        percent = current / self.total * 100
        
        # Use carriage return to update in place
        print(f"\r{bar} {percent:0.1f}%", end="", flush=True)
        if current >= self.total:
            print()  # New line when done

class StreamProcessor:
    """Context manager for file operations with safety checks."""
    def __init__(self, path: str | BinaryIO, mode: str):
        """Initialize with file path and mode.
        
        Args:
            path: Either a file path string or a binary IO object
            mode: File open mode ('rb' for read, 'wb' for write)
            
        Raises:
            ValueError: If mode is not 'rb' or 'wb'
            CryptoError: If file size exceeds limit
        """
        if mode not in ('rb', 'wb'):
            raise ValueError(f"Invalid mode: {mode}. Use 'rb' or 'wb'")
            
        self.path = path if isinstance(path, str) else None
        self.mode = mode
        self.file: Optional[BinaryIO] = None if isinstance(path, str) else path
        self._progress: Optional[ProgressBar] = None
        self.bytes_processed = 0
        
        # Check file size limit for reading
        if isinstance(path, str) and mode == 'rb' and os.path.exists(path):
            try:
                size = os.path.getsize(path)
                if size > MAX_FILE_SIZE:
                    raise CryptoError(
                        f"File too large. Maximum size is {MAX_FILE_SIZE/(1024*1024):.1f} MB"
                    )
            except OSError as e:
                raise CryptoError(f"Failed to check file size: {e}")
    
    def _check_path(self) -> None:
        """Validate file path and prevent unsafe operations."""
        if not isinstance(self.path, str):
            return
            
        if self.mode == 'wb':
            if os.path.exists(self.path):
                ans = input(_colour(f"\nWarning: {self.path} exists. Overwrite? [y/N]: ")).lower()
                if ans not in ('y', 'yes'):
                    raise CryptoError("Operation cancelled")
            
            # Check directory permissions
            try:
                directory = os.path.dirname(self.path) or '.'
                test_file = os.path.join(directory, '.write_test')
                with open(test_file, 'wb') as f:
                    f.write(b'test')
                os.unlink(test_file)
            except OSError as e:
                raise CryptoError(f"Cannot write to directory: {e}")
    
    def __enter__(self) -> 'StreamProcessor':
        """Open file and setup progress tracking."""
        if isinstance(self.path, str):
            self._check_path()
            try:
                self.file = open(self.path, self.mode)
            except OSError as e:
                raise CryptoError(f"Failed to open file: {e}")
            
            # Setup progress bar for reading
            if self.mode == 'rb':
                try:
                    size = os.path.getsize(self.path)
                    self._progress = ProgressBar(size)
                except OSError:
                    pass  # Skip progress if we can't get file size
                
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up file handle."""
        if self.file and isinstance(self.path, str):
            self.file.close()
    
    def read(self, size: int = -1) -> bytes:
        """Read with progress tracking."""
        if not self.file:
            raise CryptoError("File not open")
        data = self.file.read(size)
        self.bytes_processed += len(data)
        if self._progress:
            self._progress.update(self.bytes_processed)
        return data
    
    def write(self, data: bytes) -> int:
        """Write with progress tracking."""
        if not self.file:
            raise CryptoError("File not open")
        n = self.file.write(data)
        self.bytes_processed += n
        return n

def _detect_dark_bg() -> bool:
    cfg = os.getenv("COLORFGBG", "")
    if ";" in cfg:
        try:
            return int(cfg.split(";")[-1]) <= 6
        except ValueError:
            pass
    return True

def _colour(text: str) -> str:
    if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return text
    colour = COLORS['cyan'] if _detect_dark_bg() else COLORS['blue']
    return f"{colour}{text}{COLORS['reset']}"

# Key derivation
def _check_password_strength(password: str) -> tuple[bool, str]:
    """
    Check password strength against basic rules:
    - At least 12 chars
    - Mix of upper, lower, digits, symbols
    - Not common patterns
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    if not (has_upper and has_lower and has_digit and has_symbol):
        return False, "Password must include uppercase, lowercase, digits, and symbols"
    
    # Check for common patterns
    common = ['password', '123456', 'qwerty', 'admin']
    if any(pattern in password.lower() for pattern in common):
        return False, "Password contains common patterns"
        
    return True, "Password strength acceptable"

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive AES key from passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Stream encrypt file-like
def _encrypt_stream(r: StreamProcessor, w: StreamProcessor, passphrase: str) -> None:
    # Check password strength before proceeding
    valid, msg = _check_password_strength(passphrase)
    if not valid:
        raise CryptoError(f"Password too weak: {msg}")
        
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key   = _derive_key(passphrase, salt)
    w.write(salt + nonce)
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()
    
    try:
        for chunk in iter(lambda: r.read(CHUNK_SIZE), b""):
            w.write(encryptor.update(chunk))
        w.write(encryptor.finalize() + encryptor.tag)
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}")

# Stream decrypt file-like
def _decrypt_stream(r: StreamProcessor, w: StreamProcessor, passphrase: str) -> None:
    try:
        hdr = r.read(SALT_SIZE + NONCE_SIZE)
        if len(hdr) != SALT_SIZE + NONCE_SIZE:
            raise CryptoError("Invalid encrypted file format")
            
        salt, nonce = hdr[:SALT_SIZE], hdr[SALT_SIZE:]
        data = r.read()
        
        if len(data) < TAG_SIZE:
            raise CryptoError("File too short - not a valid encrypted file")
            
        tag = data[-TAG_SIZE:]
        ct  = data[:-TAG_SIZE]
        key = _derive_key(passphrase, salt)
        
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        ).decryptor()
        
        pt = decryptor.update(ct) + decryptor.finalize()
        w.write(pt)
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}")

# Text wrappers
def _encrypt_text(plaintext: str, passphrase: str) -> str:
    ri = io.BytesIO(plaintext.encode())
    wi = io.BytesIO()
    _encrypt_stream(ri, wi, passphrase)
    return base64.b64encode(wi.getvalue()).decode()

def _decrypt_text(token: str, passphrase: str) -> str:
    data = base64.b64decode(token)
    ri = io.BytesIO(data)
    wi = io.BytesIO()
    _decrypt_stream(ri, wi, passphrase)
    return wi.getvalue().decode('utf-8', 'ignore')

# Interactive wizard

def main() -> None:
    print(_colour("\n🔐 AES-GCM Encrypt/Decrypt Utility\n"))
    options = ["Encrypt text", "Decrypt text", "Encrypt file", "Decrypt file"]
    for i, opt in enumerate(options, 1):
        print(_colour(f"  {i}) {opt}"))

    choice = input(_colour("\nSelect mode [1]: ")).strip() or "1"
    if choice not in {"1","2","3","4"}:
        sys.exit("Invalid selection.")
    mode = int(choice)

    # read payload
    if mode in (1,2):
        payload = input(_colour("\nEnter message:\n> "))
        if not payload:
            sys.exit("No message provided.")
    else:
        path = input(_colour("\nEnter file path:\n> "))
        if not Path(path).is_file():
            sys.exit("File not found.")
        payload = path

    # passphrase
    passphrase = input(_colour("\nEnter passphrase: "))
    if not passphrase:
        sys.exit("Passphrase required.")

    print(_colour("\nProcessing…"))
    try:
        if mode == 1:
            out = _encrypt_text(payload, passphrase)
        elif mode == 2:
            out = _decrypt_text(payload, passphrase)
        elif mode == 3:
            out_path = payload + '.enc'
            with StreamProcessor(payload, 'rb') as inp, StreamProcessor(out_path, 'wb') as outp:
                _encrypt_stream(inp, outp, passphrase)
            print(_colour(f"\nEncrypted → {out_path}"))
            return
        else:
            out_path = payload + '.dec'
            with StreamProcessor(payload, 'rb') as inp, StreamProcessor(out_path, 'wb') as outp:
                _decrypt_stream(inp, outp, passphrase)
            print(_colour(f"\nDecrypted → {out_path}"))
            return
    except Exception as e:
        sys.exit(f"Error: {e}")

    # text mode: show & optional copy
    print(_colour(f"\nResult:\n{out}\n"))
    if sys.stdout.isatty() and pyperclip:
        ans = input(_colour("Copy to clipboard? [y/N]: ")).strip().lower()
        if ans in ("y","yes"):
            try:
                pyperclip.copy(out)
                print(_colour("Copied to clipboard."))
            except Exception as e:
                print(_colour(f"Copy failed: {e}"))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Aborted by user.")
