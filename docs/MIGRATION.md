# Migration Guide: V1 to V2

> **Status:** V2 shipped as part of package release `v2.0.0` (2026-09-11).
> The `ssc key create`/`rename` issues noted in a 2026-09-10 audit are
> fixed; the sections below reflect the released behavior.

## Overview

Secure String Cipher V2 adds a new `.ssc` container alongside the existing V1
`.enc` format — it does not replace it, and you do not need to migrate
existing files. The legacy format (v4 and v5) derives a key directly from a
single passphrase. The new V2 format decouples the payload's Data Encryption
Key (DEK) from the authentication material via AEAD key wrapping — but each
`.ssc` object still carries exactly **one** access grant, not an array of
independent grants. That single grant can require a password and a managed
key *together*; it cannot be opened by either one independently, and it
cannot be opened by more than one distinct credential.

**V1 data keeps working:**

- `ssc decrypt` auto-detects and continues to decrypt older `.enc` files.
- V1 vaulted passphrases are unaffected; V2 does not migrate or touch them.

## What's New in V2?

1. **`.ssc` Format**: New file extension for the V2 container, auto-detected
   by decrypt via its magic bytes (independent of the file extension).
2. **Managed Keys**: `.ssckey` files hold a random 256-bit secret. `ssc key
   create`, `import`, `show`, `export`, `list`, and `rename` all work end to
   end. Key status changes (`archive`/`revoke`/`destroy`) are vault
   bookkeeping, and `ssc encrypt`/`ssc decrypt` now enforce
   `revoke`/`destroy` by default for any key a vault on this machine
   tracks. `--no-enforce-key-status` skips the check; a `.ssckey` file you
   hold can always be used offline — see the Key Management section
   below.
3. **Combined authentication**: You can encrypt a single file so that its one
   grant requires *both* a password and a key. There is no "either one"
   (any-of) mode — `--require any` with more than one `--with` source is
   rejected by the CLI.

## Migrating Your Workflows

### 1. File Encryption

**Old (V1)**:
```bash
ssc encrypt -f data.txt --vault my-server
```

**New (V2, combined password + key)**:

```bash
ssc encrypt -f data.txt --with password --with key:/path/to/my-server.ssckey --require all
```

`--require any` is only meaningful with a single `--with` source; with two
sources it must be `--require all`. `key:ID` resolves either a literal
`.ssckey` path or a fingerprint/key-id found under `~/.ssc/keys/*.ssckey` —
nothing in this CLI currently populates that directory automatically, so
place or symlink the `.ssckey` file there yourself, or use the direct path.

### 2. Using Keys

**Old (V1 - Legacy Key Files)**:
```bash
ssc encrypt -f data.txt --key-file ./id_rsa
```

**New (V2 - Managed Keys)**:

```bash
ssc key create laptop-backup --external-file ./laptop-backup.ssckey
ssc encrypt -f data.txt --with key:laptop-backup
```

`ssc key create ID` requires exactly one storage target: `--external-file
PATH` (writes the generated secret to a `.ssckey` file you keep yourself) or
`--vault-copy` (stores it inside the encrypted vault instead — export it to
a file later with `ssc key export ID DEST` before it can be used with
`--with key:ID`). `key:ID` then resolves either that literal `.ssckey` path
or a fingerprint/key-id found under `~/.ssc/keys/*.ssckey` — nothing in this
CLI currently populates that directory automatically, so place or symlink
the file there yourself if you want to reference it by id instead of path.

### 3. Decryption

**Old (V1)**:
```bash
ssc decrypt -f data.enc --vault my-server
```

**New (V2)**:

```bash
ssc decrypt -f data.ssc
```

`decrypt` has no `--with`/`--require` flags. It detects a `.ssc` container by
its magic bytes and reads the credential type it needs directly from the
file's own header (password, managed key, or both), then prompts for
whichever the header's grant requires. `--vault LABEL` is honored here to
supply the password component without a prompt.

## Key Management

`ssc key` lifecycle commands all work end to end:

```bash
ssc key list                       # works
ssc key show <id-or-fingerprint>   # works
ssc key import <path-to.ssckey>    # works
ssc key export <id> <dest>         # works, but only for a --vault-copy key
ssc key rename <id> <new-id>       # works
ssc key create <id> (--external-file PATH | --vault-copy)
                                    # works — exactly one storage target is
                                    #   required; omitting both exits with
                                    #   an input error
ssc key archive <id>               # flips a vault status field; never
                                    #   blocks use
ssc key revoke <id>                # flips a vault status field, and is
ssc key destroy <id>               #   enforced at encrypt/decrypt by
                                    #   default whenever a vault exists
                                    #   here (see below)
```

Revoking or destroying a key you tracked in this vault:

```bash
ssc key revoke laptop-backup
ssc encrypt file.txt --with key:laptop-backup   # rejected

# --no-enforce-key-status is a global flag, so it precedes the subcommand
ssc --no-enforce-key-status encrypt file.txt --with key:laptop-backup
```

The check reads the vault, so it needs the master password; supply it with
`--master-password-file` or `SSC_MASTER_PASSWORD` in automation. With no
vault on this machine there is nothing to check and nothing to prompt for,
so scripted use of a bare `.ssckey` is unaffected.

`--no-enforce-key-status` does not un-revoke anything. Whoever holds the
`.ssckey` file holds the key, so an offline copy always works; the check
stops a revoked key being used where the vault *is* reachable.

## FAQ

**Do I need to re-encrypt all my V1 files?**
No. The CLI will continue to decrypt V1 `.enc` files transparently.

**Are my V1 vault passphrases still safe?**
Yes, V2 does not touch them. Note, though, that `ssc encrypt --with password`
does **not** currently read from `--vault` — it always prompts interactively,
even if you pass `--vault my-server`. `ssc decrypt --vault my-server` on a
`.ssc` file *does* use the vaulted password. This asymmetry is a known gap.
