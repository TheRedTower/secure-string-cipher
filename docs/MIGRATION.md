# Migration Guide: V1 to V2

> **Status:** V2 is merged to `main` (PR #40, commit `59147fc`,
> 2026-09-11) but not yet the source of a tagged release (see
> [ROADMAP.md](../ROADMAP.md) for the remaining release gate). The `ssc key
> create`/`rename` issues noted in a 2026-09-10 audit are fixed as of this
> merge; the sections below have been updated accordingly.

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
   end. **Current limitation**: key status changes (`archive`/`revoke`/
   `destroy`) are vault bookkeeping only — they do not currently prevent a
   `.ssckey` file from still being used to encrypt or decrypt.
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
ssc key rename <id> <new-id>       # works
ssc key create <id> [--vault-copy] [--external-file PATH]
                                    # works — persists the generated secret
                                    #   either to the named external file or
                                    #   into the vault
ssc key archive <id>               # flips a vault status field only —
ssc key revoke <id>                #   neither has any effect on whether the
ssc key destroy <id>               #   matching .ssckey file can still
                                    #   encrypt or decrypt (not enforced yet)
```

Note there is currently no CLI end-to-end test coverage for this command
group (only the underlying vault-service methods and CLI argument parsing
are tested directly) — see [ROADMAP.md](../ROADMAP.md).

## FAQ

**Do I need to re-encrypt all my V1 files?**
No. The CLI will continue to decrypt V1 `.enc` files transparently.

**Are my V1 vault passphrases still safe?**
Yes, V2 does not touch them. Note, though, that `ssc encrypt --with password`
does **not** currently read from `--vault` — it always prompts interactively,
even if you pass `--vault my-server`. `ssc decrypt --vault my-server` on a
`.ssc` file *does* use the vaulted password. This asymmetry is a known gap.
