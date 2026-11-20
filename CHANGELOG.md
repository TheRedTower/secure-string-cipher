# Changelog

## 3.0.0 (unreleased)

SSC 3.0 is a ground-up rebuild. Each file has its own random key, and the
file itself says what can unlock that key.

**3.0 cannot read files made by 2.x.** To move them, decrypt them with 2.x
first, then encrypt them with 3.0.

### Added

- **A new file format** ([FORMAT.md](docs/spec/FORMAT.md)): AES-256-GCM in
  64 KiB chunks, and an access block authenticated by HMAC-SHA256 before
  anything is decrypted. It has an armoured text form for pasting.
- **Ways in** ([ACCESS.md](docs/spec/ACCESS.md)):
  - a file can be unlocked by a password, a vault entry, a key file or a
    recovery code;
  - factors can be combined ("all of", such as `password+vault:laptop`);
  - a file can have several ways in ("any of"), up to 16.
- **The vault** ([VAULT.md](docs/spec/VAULT.md)): one encrypted file holds
  password, key and recovery entries, and profiles. It's unlocked by a
  master password or by this device's key in the OS keychain, on Linux,
  macOS and Windows. It has opt-in, hash-chained history that records no
  file names.
- **Commands** ([CLI.md](docs/spec/CLI.md)): `encrypt`, `decrypt`, `access`
  (`show`, `add`, `remove`, `rotate`, `apply`), `vault`, `key`, `profile`,
  `generate` and `shred`. Each has fixed exit codes, credentials can come
  from files and environment variables for scripts, and none of it hangs
  without a TTY.
- **A guided interactive mode:** run `ssc` with no arguments in a terminal.
- **A Docker image:** hash-locked dependencies, no compiler, unprivileged,
  run with `docker run --rm`.

### Changed from 2.x

- **Python:** 3.13 or newer.
- **The passphrase vault** is now a vault of SSC entries. The OS keychain
  holds only the key that unlocks it.
- **Revoking is honest:** revoking a vault entry stops SSC from using it,
  and offers to rotate the files it opens. SSC says plainly that a copy of
  the secret still opens old copies of those files.

### Removed

- **Old formats:** the v4, v5 and SSC2 formats, and the legacy key-file mode.
- **The rate limiter:** it can't slow someone who has a copy of the file.
- **Secure-memory wrappers and timing jitter:** Python can't reliably wipe
  secrets, and nothing observed the jitter.
- **The Python library API:** 3.0 is a command-line tool, and its internals
  are private.

## 2.x and earlier

The history of 2.x and earlier is in the `CHANGELOG.md` of the
[v2.0.0 release](https://github.com/TheRedTower/secure-string-cipher/blob/v2.0.0/CHANGELOG.md).
