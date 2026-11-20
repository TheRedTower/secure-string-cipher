# SSC 3.0 threat model

This expands the threat model in the [charter](CHARTER.md). The formats it
relies on are specified in [FORMAT.md](spec/FORMAT.md),
[ACCESS.md](spec/ACCESS.md) and [VAULT.md](spec/VAULT.md).

## What SSC protects

**The contents of a file at rest, against anyone who has a copy of the
`.ssc` file but none of its ways in.** It also detects any change to the
file.

- **The payload:** AES-256-GCM in 64 KiB chunks, under a key derived from a
  random 32-byte file key. A stream cut short, reordered or extended fails to
  decrypt (FORMAT.md section 6).
- **The access block:** this lists the file's ways in. An HMAC-SHA256 keyed
  from the file key authenticates it, and it's checked before any payload is
  decrypted. That MAC also commits the file to one key: AES-GCM alone does
  not (FORMAT.md section 5).
- **Passwords:** Argon2id with 64 MiB of memory, 3 passes and 4 lanes, with
  a fresh 16-byte salt for every password factor written. A reader runs only these
  parameters, so a crafted file can't make it do a much larger Argon2id run
  (ACCESS.md section 2.1).
- **Keys and recovery codes:** a key is 32 random bytes and a recovery code 18
  random bytes. Neither can be guessed.
- **The vault:** an SSC file itself, opened by the master password or by this
  device's key in the OS keychain. The keychain holds only that device key,
  never the vault's contents (VAULT.md section 2).

## What SSC does not protect against

- **A compromised computer.** Someone who controls your machine while you
  unlock a file, through malware, a keylogger or a debugger, can take the
  password, the key or the plaintext. Python can't reliably wipe secrets
  from memory, and SSC doesn't claim to.
- **A weak way in.** A file is only as strong as its weakest way in. SSC
  warns about a weak password when one is set for encryption, and when a
  password-only way in is added to a file that had stronger ones. It cannot
  stop either.
- **Copies made before you removed access.** Removing a way in, or
  revoking a vault entry, stops SSC from using it. It can't reach a copy
  that someone already opened or kept. Only rotation (`ssc access rotate`, a
  new file key and full re-encryption) protects the new contents of a file,
  and only from then on.
- **Losing every way in.** There is no backdoor. A file whose only way in is
  a vault key entry is lost with the vault, unless it also has another way
  in, such as a recovery code. SSC offers one when you add a key.
- **Traffic analysis of the file itself.** A `.ssc` file shows roughly how
  big its plaintext is, how many ways in it has and what kind each one is.

## Where plaintext and secrets can touch the disk

- **Outputs:** they're written to a temporary file in the destination folder
  and renamed into place only once complete. When decrypting to a file, the
  plaintext is in that folder until the rename.
- **`decrypt -o -`:** nothing is written to stdout until the whole file has
  authenticated. Up to 64 MiB is held in memory. Beyond that, it spools to
  an owner-only temporary file in the OS temp folder, deleted afterwards.
  Decrypting to a file with `-o <out>` keeps it out of the temp folder, but
  that file is on disk too. To keep plaintext off the disk entirely, write
  it to memory-backed storage, such as a RAM disk or `tmpfs`.
- **Key files (`.ssckey`):** plaintext bearer secrets. Anyone with the file
  has the key. SSC writes them owner-only and refuses symlinked ones.
- **Credential files** (`--password-file` and the like): SSC refuses a
  symlinked one, and on POSIX one that others can read. Environment
  variables (`SSC_*`) can be read by other processes of the same user, and
  sometimes by administrators.
- **`ssc shred`:** this overwrites a file before deleting it. SSDs,
  copy-on-write filesystems, snapshots and backups can keep old copies it
  can't reach, and it says so before it runs.

## The vault's history

History is off by default. When on, it records which vault entries were
used, and when, but never file names, paths or secrets. Each event is
hash-chained to the one before. That is tamper evidence against someone who
can unlock the vault, not proof: such a person can rewrite or trim the whole
chain (VAULT.md section 5). If the vault can't record a decrypt, because
it's in use or unreadable, the decrypt still succeeds and SSC says the event
was not recorded.

## Docker

A container has no OS keychain, so SSC asks for the master password and
never falls back to keeping a key in a plain file. The image runs as an
unprivileged user, with dependencies hash-locked and installed only as
prebuilt wheels. Its vault lives in the `/ssc` volume you mount, so protect
that folder as you would the vault on any machine.

## Supply chain

Dependencies are pinned to exact versions, with hashes, in `uv.lock`, and CI
installs only from the lock. GitHub Actions are pinned by commit.
