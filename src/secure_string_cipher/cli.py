"""
Command-line interface for secure-string-cipher
"""
import os
import sys
from pathlib import Path
from typing import Optional

import pyperclip

from .core import (
    encrypt_text, decrypt_text,
    encrypt_file, decrypt_file,
    CryptoError
)
from .config import (
    DEFAULT_MODE,
    CLIPBOARD_ENABLED,
    CLI_TIMEOUT
)
from .utils import (
    colorize,
    check_password_strength,
    handle_timeout
)

def _get_mode() -> int:
    """
    Get operation mode from user.
    
    Returns:
        Mode number (1-4)
        
    Raises:
        SystemExit: If invalid selection
    """
    print(colorize("\n🔐 AES-GCM Encrypt/Decrypt Utility\n"))
    options = ["Encrypt text", "Decrypt text", "Encrypt file", "Decrypt file"]
    
    for i, opt in enumerate(options, 1):
        print(colorize(f"  {i}) {opt}"))

    with handle_timeout(CLI_TIMEOUT)():
        choice = input(colorize(f"\nSelect mode [{DEFAULT_MODE}]: ")).strip()
        if not choice:
            return DEFAULT_MODE
            
        if choice not in {"1","2","3","4"}:
            sys.exit(colorize("Invalid selection.", 'red'))
            
        return int(choice)

def _get_input(mode: int) -> str:
    """
    Get input text or file path from user.
    
    Args:
        mode: Operation mode
        
    Returns:
        Input text or file path
        
    Raises:
        SystemExit: If input invalid
    """
    with handle_timeout(CLI_TIMEOUT)():
        if mode in (1, 2):
            payload = input(colorize("\nEnter message:\n> "))
            if not payload:
                sys.exit(colorize("No message provided.", 'red'))
        else:
            path = input(colorize("\nEnter file path:\n> "))
            if not Path(path).is_file():
                sys.exit(colorize("File not found.", 'red'))
            payload = path
            
        return payload

def _get_password(verify: bool = False) -> str:
    """
    Get password from user with optional verification.
    
    Args:
        verify: Whether to verify password by typing twice
        
    Returns:
        Password string
        
    Raises:
        SystemExit: If password invalid or verification fails
    """
    import getpass
    
    with handle_timeout(CLI_TIMEOUT)():
        while True:
            try:
                password = getpass.getpass(colorize("\nEnter passphrase: "))
                if not password:
                    sys.exit(colorize("Passphrase required.", 'red'))
                
                # Verify password strength for encryption
                if verify:
                    valid, msg = check_password_strength(password)
                    if not valid:
                        print(colorize(f"\nWeak password: {msg}", 'red'))
                        continue
                    
                    verify_pass = getpass.getpass(colorize("Verify passphrase: "))
                    if password != verify_pass:
                        print(colorize("\nPassphrases don't match!", 'red'))
                        continue
                
                return password
            
            except KeyboardInterrupt:
                sys.exit("\nOperation cancelled.")

def _handle_clipboard(text: str) -> None:
    """
    Handle clipboard operations safely.
    
    Args:
        text: Text to potentially copy to clipboard
    """
    if not CLIPBOARD_ENABLED or not sys.stdout.isatty():
        return
        
    try:
        ans = input(colorize("\nCopy to clipboard? [y/N]: ")).strip().lower()
        if ans in ("y", "yes"):
            pyperclip.copy(text)
            print(colorize("Copied to clipboard.", 'green'))
    except Exception as e:
        print(colorize(f"Copy failed: {e}", 'red'))

def main() -> None:
    """Main CLI entry point."""
    try:
        mode = _get_mode()
        payload = _get_input(mode)
        
        # Get password with verification for encryption
        password = _get_password(verify=mode in (1, 3))
        
        print(colorize("\nProcessing…"))
        
        try:
            if mode == 1:  # Encrypt text
                out = encrypt_text(payload, password)
                print(colorize(f"\nResult:\n{out}\n"))
                _handle_clipboard(out)
                
            elif mode == 2:  # Decrypt text
                out = decrypt_text(payload, password)
                print(colorize(f"\nResult:\n{out}\n"))
                _handle_clipboard(out)
                
            elif mode == 3:  # Encrypt file
                out_path = payload + '.enc'
                encrypt_file(payload, out_path, password)
                print(colorize(f"\nEncrypted → {out_path}", 'green'))
                
            else:  # Decrypt file
                out_path = payload + '.dec'
                decrypt_file(payload, out_path, password)
                print(colorize(f"\nDecrypted → {out_path}", 'green'))
                
        except CryptoError as e:
            sys.exit(colorize(f"\nError: {e}", 'red'))
            
    except KeyboardInterrupt:
        sys.exit(colorize("\nOperation cancelled by user.", 'red'))

if __name__ == '__main__':
    main()