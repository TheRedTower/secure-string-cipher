# Migration Guide: V1 to V2

> **Status:** V2 is in-progress and unreleased (see [ROADMAP.md](../ROADMAP.md)).
> This guide was substantially corrected on 2026-09-10: several commands it
> previously showed do not work against the current CLI. Corrections are
> noted inline. Do not follow an older copy of this file.

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
2. **Managed Keys**: `.ssckey` files hold a random 256-bit secret. **Current
   limitation**: `ssc key create` cannot yet be given a name, and its default
   mode does not persist the generated secret anywhere recoverable — creating
   a key today without `--vault-copy` throws the secret away. Treat `ssc key
   create` as not yet usable; `ssc key import`/`show`/`export`/`list` work on
   a `.ssckey` file you already have.
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

**New (V2 - Managed Keys)**: not yet available end-to-end. `ssc key create`
cannot name a key or reliably persist the secret it generates (see above), so
there is currently no supported path from "create a managed key" to
"reference it with `--with key:ID`" through the CLI alone. If you need a V2
managed key today, generate 32 random bytes and hand-construct a `.ssckey`
file matching the format in `src/secure_string_cipher/v2/keyfile.py`, or wait
for this to be fixed.

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

`ssc key` lifecycle commands exist, but several do not currently work as a
lifecycle:

```bash
ssc key list                       # works
ssc key show <id-or-fingerprint>   # works
ssc key import <path-to.ssckey>    # works
ssc key export <id> <dest>         # works, but only for a --vault-copy key
ssc key archive <id>               # flips a vault status field only —
ssc key revoke <id>                #   neither has any effect on whether the
                                    #   matching .ssckey file can still
                                    #   encrypt or decrypt (not enforced yet)
ssc key rename <id> <new-id>       # registered but always fails — the
                                    #   backing method does not exist
ssc key create [--vault-copy] [--external-file PATH]
                                    # cannot be given a name (always "default",
                                    #   so a second create always fails); the
                                    #   default (external-only) mode discards
                                    #   the generated secret rather than
                                    #   writing it anywhere
```

Until `ssc key create`/`rename` are fixed, treat key export/import/list/show
as the only reliable parts of this command group, operating on a `.ssckey`
file you already have from another source.

## FAQ

**Do I need to re-encrypt all my V1 files?**
No. The CLI will continue to decrypt V1 `.enc` files transparently.

**Are my V1 vault passphrases still safe?**
Yes, V2 does not touch them. Note, though, that `ssc encrypt --with password`
does **not** currently read from `--vault` — it always prompts interactively,
even if you pass `--vault my-server`. `ssc decrypt --vault my-server` on a
`.ssc` file *does* use the vaulted password. This asymmetry is a known gap.
