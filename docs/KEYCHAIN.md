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

4. Vault import and restore validate before mutation and read back/revalidate
   after publication. The file backend uses atomic replacement. OS credential
   stores expose no multi-record transaction, so a failed keychain publication
   receives a best-effort restore of the retained prior raw value; crash
   atomicity is not claimed.

## Backend Selection

The configured backend is resolved from the persisted config and then optional
`CIPHER_VAULT_BACKEND` environment override. With no explicit selection, a
usable keychain is preferred and the file backend is the fallback. Inspect or
pin the choice with:

```bash
ssc vault backend
ssc vault backend file
ssc vault backend keychain
```

Import, backup listing, and restore use this configured backend; they do not
silently instantiate a file-only vault. Backup files remain encrypted raw vault
records in the configured backup directory. There is no cross-process vault
lock, and the focused CI matrix mocks credential-store behavior rather than
exercising a real logged-in OS keychain.

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

If no explicit backend has been saved and the keychain is unavailable, the
vault uses the file backend. You can explicitly choose:

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
- Export writes exact six-line UTF-8 bytes without a terminal newline. CLI
  import accepts exactly one terminal LF or CRLF from an older redirected
  export; direct vault APIs and all other whitespace remain byte-strict.
