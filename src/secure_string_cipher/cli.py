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
    handle_timeout
)
from .timing_safe import check_password_strength

def _print_banner():
    """Print a welcome banner with program info."""
    banner = """
╭──────────────────────────────────────╮
│   🔐 Secure String Cipher Utility    │
│        AES-256-GCM Encryption        │
│                                      │
│      Encrypt/Decrypt Securely        │
╰──────────────────────────────────────╯
    """
    print(colorize(banner, 'cyan'))

def _show_help():
    """Display detailed help information and security guidelines."""
    help_text = """
📚 Secure String Cipher - Help & Information
===========================================

🔐 Security Features:
------------------
• AES-256-GCM encryption (industry standard)
• Memory wiping after operations
• Timing attack protections
• Secure password handling
• File integrity verification

📝 Text Operations:
---------------
1. To Encrypt Text:
   - Choose option 1 from main menu
   - Enter your message
   - Create a strong password
   - Encrypted text is copied to clipboard

2. To Decrypt Text:
   - Choose option 2 from main menu
   - Paste the encrypted text
   - Enter the original password
   - See your decrypted message

📂 File Operations:
---------------
3. To Encrypt Files:
   - Choose option 3 from main menu
   - Enter the file path
   - Create a strong password
   - A new .enc file is created

4. To Decrypt Files:
   - Choose option 4 from main menu
   - Enter the encrypted file path
   - Enter the original password
   - Choose output location

🔑 Password Guidelines:
------------------
Strong passwords must have:
• Minimum 12 characters
• Uppercase letters (A-Z)
• Lowercase letters (a-z)
• Numbers (0-9)
• Special characters (!@#$%^&*)
• No common patterns/words

⚠️ Important Notes:
---------------
• Never share your passwords
• Store encrypted files securely
• Keep backup of important files
• Remember: encryption is permanent

Press Enter to return to main menu..."""
    print(colorize(help_text, 'yellow'))
    input()

def _get_mode() -> int:
    """
    Display the main menu and get operation mode from user.
    
    Returns:
        Mode number (1-4)
        
    Raises:
        SystemExit: If invalid selection
    """
    _print_banner()
    
    # Show main menu with detailed descriptions
    menu = """
🔐 Available Operations:

1. 📝 Encrypt Text
   - Securely encrypt text messages
   - Result is copied to clipboard
   - Uses AES-256-GCM encryption

2. 🔓 Decrypt Text
   - Decrypt previously encrypted messages
   - Paste encrypted text from clipboard
   - Requires original password

3. 📁 Encrypt File
   - Secure your sensitive files
   - Creates encrypted .enc file
   - Original file remains unchanged

4. 📂 Decrypt File
   - Restore encrypted files
   - Requires original password
   - Verifies file integrity

5. ❓ Help & Information
   - View detailed instructions
   - Security best practices
   - Password guidelines

0. ❌ Exit Program

Enter your choice (0-5): """
    options = [
        ("� Encrypt text", "Secure your message with strong encryption"),
        ("🔓 Decrypt text", "Recover your encrypted message"),
        ("📁 Encrypt file", "Protect files with encryption"),
        ("📂 Decrypt file", "Restore encrypted files")
    ]
    
    print(colorize("\nAvailable Operations:", 'yellow'))
    for i, (opt, desc) in enumerate(options, 1):
        print(colorize(f"  {i}) {opt:<20} - {desc}", 'white'))

    with handle_timeout(CLI_TIMEOUT)():
        choice = input(colorize(f"\nSelect operation [{DEFAULT_MODE}]: ", 'green')).strip()
        if not choice:
            return DEFAULT_MODE
            
        if choice not in {"1","2","3","4"}:
            sys.exit(colorize("❌ Invalid selection.", 'red'))
            
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
            print(colorize("\n💬 Enter your message", 'yellow'))
            print(colorize("   Type or paste the text to process:", 'white'))
            payload = input(colorize("➜ ", 'green'))
            if not payload:
                sys.exit(colorize("❌ No message provided.", 'red'))
        else:
            print(colorize("\n📂 Enter file details", 'yellow'))
            print(colorize("   Type or paste the file path:", 'white'))
            path = input(colorize("➜ ", 'green'))
            if not Path(path).is_file():
                sys.exit(colorize("❌ File not found.", 'red'))
            payload = path
            
        return payload

def _get_password(confirm: bool = True, operation: str = "") -> str:
    """
    Securely get password from user with optional confirmation.
    Shows a wizard-style interface with clear instructions.
    
    Args:
        confirm: Whether to require password confirmation
        operation: Type of operation (e.g., "encryption", "decryption")
        
    Returns:
        Password string
        
    Raises:
        SystemExit: If passwords don't match or requirements not met
    """
    print(colorize(f"\n🔑 Password Entry for {operation}", "cyan"))
    print(colorize("\nPassword Requirements:", "yellow"))
    print("• Minimum 12 characters long")
    print("• Must include uppercase letters (A-Z)")
    print("• Must include lowercase letters (a-z)")
    print("• Must include numbers (0-9)")
    print("• Must include special characters (!@#$%^&*)")
    print("• Cannot contain common patterns/words")
    print(colorize("\n⚠️  Your password is crucial for security!", "red"))
    if operation == "encryption":
        print("   Make sure to remember it - there's no way to recover encrypted data\n")

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

def _show_progress(operation: str) -> None:
    """Show a simple progress indicator."""
    print(colorize(f"\n⏳ {operation}...", 'yellow'))

def main() -> None:
    """Main CLI entry point."""
    try:
        # Get operation mode
        mode = _get_mode()
        
        # Get input
        payload = _get_input(mode)
        
        # Get password with verification for encryption
        operation = "encryption" if mode in (1, 3) else "decryption"
        password = _get_password(confirm=mode in (1, 3), operation=operation)
        
        # Process the operation
        _show_progress("Processing")
        
        try:
            if mode == 1:  # Encrypt text
                out = encrypt_text(payload, password)
                print(colorize("\n✅ Text encrypted successfully!", 'green'))
                print(colorize("\n📋 Encrypted Result:", 'yellow'))
                print(colorize(f"{out}", 'white'))
                _handle_clipboard(out)
                
            elif mode == 2:  # Decrypt text
                out = decrypt_text(payload, password)
                print(colorize("\n✅ Text decrypted successfully!", 'green'))
                print(colorize("\n📋 Decrypted Result:", 'yellow'))
                print(colorize(f"{out}", 'white'))
                _handle_clipboard(out)
                
            elif mode == 3:  # Encrypt file
                out_path = payload + '.enc'
                encrypt_file(payload, out_path, password)
                print(colorize("\n✅ File encrypted successfully!", 'green'))
                print(colorize(f"📁 Output: {out_path}", 'yellow'))
                
            else:  # Decrypt file
                out_path = payload + '.dec'
                decrypt_file(payload, out_path, password)
                print(colorize("\n✅ File decrypted successfully!", 'green'))
                print(colorize(f"📁 Output: {out_path}", 'yellow'))
                
        except CryptoError as e:
            sys.exit(colorize(f"\nError: {e}", 'red'))
            
    except KeyboardInterrupt:
        sys.exit(colorize("\nOperation cancelled by user.", 'red'))

if __name__ == '__main__':
    main()