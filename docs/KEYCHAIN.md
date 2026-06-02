# Keychain Backend

The keychain backend stores your passphrase vault in your operating system's
secure credential storage instead of an encrypted file on disk.

## Overview

| Platform | Keychain Service                                |
| -------- | ----------------------------------------------- |
| macOS    | Keychain Access (via Security framework)        |
| Windows  | Windows Credential Vault                        |
| Linux    | Secret Service API (GNOME Keyring / KDE Wallet) |

**Benefits:**

- No vault file on disk to be accidentally deleted or copied
- OS-level access control (biometric, session lock, etc.)
- Defense in depth: vault data is still encrypted with your master password
- Seamless integration with system credential management

## Installation

The keychain backend requires the `keyring` package:

```bash
# Existing pipx install: add keychain support to the pipx venv
pipx inject secure-string-cipher keyring

# New pipx install with keychain support
pipx install 'secure-string-cipher[keychain]'

# Or for a normal pip/venv install
python -m pip install 'secure-string-cipher[keychain]'

# Or add the dependency directly to the active environment
python -m pip install keyring
```

## Usage

### Migrate existing vault to keychain

```bash
ssc vault migrate --to keychain
```

This copies your encrypted vault data from the file (`~/.secure-cipher/passphrase_vault.enc`)
into the OS keychain. The file vault is preserved as a backup.

### Migrate back to file

```bash
ssc vault migrate --to file
```

### Programmatic usage

```python
from secure_string_cipher import PassphraseVault, BACKEND_KEYCHAIN, is_keychain_available

# Check if keychain is available
if is_keychain_available():
    vault = PassphraseVault(backend=BACKEND_KEYCHAIN)
    vault.store_passphrase("my-label", "my-secret", "master-password")
    secret = vault.retrieve_passphrase("my-label", "master-password")
```

## How It Works

1. Your vault data (encrypted JSON blob with HMAC integrity) is stored as a
   single credential entry in the OS keychain under the service name
   `secure-string-cipher`.

2. The master password still encrypts the vault data using AES-256-GCM with
   Argon2id key derivation — the keychain provides an additional layer of
   protection for the encrypted blob.

3. All vault operations (store, retrieve, list, delete, update) work identically
   regardless of backend.

## Troubleshooting

### Linux: "No usable keychain backend found"

Ensure the Secret Service daemon is running:

```bash
# GNOME
sudo apt install gnome-keyring
eval $(gnome-keyring-daemon --start)

# KDE
sudo apt install kwalletmanager
```

### macOS: Keychain access prompts

macOS may prompt you to allow access the first time. Click "Always Allow" to
avoid repeated prompts.

### Windows: Credential Manager

Credentials are stored in Windows Credential Manager. You can view them via:
Control Panel → User Accounts → Credential Manager → Windows Credentials

### Fallback to file backend

If the keychain is unavailable, the vault will use the file backend by default.
You can explicitly choose:

```python
from secure_string_cipher import PassphraseVault, BACKEND_FILE

vault = PassphraseVault(backend=BACKEND_FILE)  # Always use file
```

## Security Considerations

- The keychain backend still encrypts all data with your master password
- OS keychain adds protection against unauthorized disk access
- On shared systems, each OS user has their own keychain
- Keychain entries are tied to the current user session
- Backup your vault before migrating: `ssc vault export > backup.txt`
