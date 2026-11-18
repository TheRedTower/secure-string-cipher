# SSC 3.0 charter

SSC is a terminal tool for local file encryption. Each file carries its own
access rules, and an interactive mode does the whole job in a few simple steps.

## Purpose

SSC is an advanced but approachable terminal tool for local file encryption,
for people who don't want a password manager. You encrypt a file once with its
own random key, and the file says what can unlock that key: a password, a key
file, a vault entry, a recovery code, or several of these together. SSC runs as
a local CLI and in a Docker container, on Linux, macOS and Windows. It has no
server.

## Who it serves, in order

1. **3.0: one person across their devices.** Passwords, vault entries and
   managed keys; "all of" and "any of" rules; profiles; recovery codes; the
   vault with keychain unlock; the guided interactive mode.
2. **3.1: people who share files.** Public-key recipients.
3. **3.2 and later: small teams.** Threshold rules ("any 2 of these 3") and
   applying a profile to many files at once.

## Threat model

- **SSC protects:** the contents of a file at rest, against anyone who has a
  copy of the `.ssc` file but none of the ways to unlock it. It also detects
  any change to the file. A file is only as strong as its weakest way in.
- **SSC does not protect:** against someone who controls your computer while
  you unlock a file, for example through malware or a keylogger. Python cannot
  reliably wipe secrets from memory, and SSC does not claim to.
- **Removing access is not revoking it:** anyone who already opened a file, or
  kept an old copy, keeps what they had. Marking a key revoked stops SSC from
  using it but cannot stop someone else's copy. Only rotation (a new file key
  and full re-encryption) protects new versions of a file.
- **Losing every way in loses the file:** there is no backdoor. A file locked
  only by a vault key entry is lost with the vault unless it also carries
  another way in, such as a recovery code.
- **Deleting is not guaranteed:** secure shred overwrites a file, but SSDs and
  copy-on-write filesystems can keep old copies that SSC cannot reach.

## Non-goals

- A password manager. The vault holds only secrets for SSC files.
- Cloud sync. Nothing leaves your machine unless you move it.
- A replacement for gpg.
- A server or hosted service.
