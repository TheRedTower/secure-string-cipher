# Secure String Cipher roadmap

This roadmap tracks planned architectural work for the SSC Beta. The current
priority is to preserve v4/v5 compatibility while hardening the existing core;
the project is not yet stable.

## Current Beta Boundary

The current writer emits metadata version 5 and reads legacy version 4. Regular
files of any internal format are handled as opaque bytes up to 100 MiB.
Directories and large SSC2 objects are not supported. Version 5 authenticates
metadata; version 4 does not, and its stored filename is ignored.

The merged stabilization tranche 2 added authenticated transactional vault
import/restore, immutable released-writer v4/v5 fixtures, strict metadata
parsing, a cryptography 50 compatibility pin, and a focused
Ubuntu/macOS/Windows CI job. The protected PR #67 matrix passed on all three
platforms; future changes must pass the same current protected checks on their
own exact commits.

The next hardening priorities are descriptor-level path opening, broader
keychain integration tests against actual OS credential stores, and an
independent third-party security audit. Cross-process vault locking and
`.ssckey` key files already exist (see below); they are not future work.

---

## SSC v2.0.0 — Managed Key Identity Utility (IN PROGRESS, NOT RELEASED)

SSC v2.0.0 is developing a managed-key architecture alongside the v1 core,
designed from [`docs/V2_MANAGED_KEYS_ARCHITECTURE.md`](docs/V2_MANAGED_KEYS_ARCHITECTURE.md).
The core cryptography (KDF, DEK wrapping, header authentication, chunked AEAD
framing) is implemented and covered by unit tests, but the feature is **not
complete, not merged to `main`, and not the source of a release**. A 2026-09-10
independent audit found the `ssc key` command group non-functional (`ssc key
create` discards the generated secret and cannot take a name; `rename` is an
unconditional stub) and the on-disk frame/armor format does not match either
design document. Do not advertise v2 as done until that audit's P0/P1 findings
are closed; see the audit for the full list.

High-level v2 goals:

- Keep the current v1 password/keyfile encryption path intact.
- Add a parallel implementation package at `src/secure_string_cipher/v2/`
  (import path: `secure_string_cipher.v2`).
- Add generated `.ssckey` files using a PEM-like ASCII-armoured format.
- Add lifecycle-aware managed symmetric key identities.
- Support initial key storage modes: `external-only` and `vault-copy`.
- Store key identity records in a structured namespace inside the existing encrypted vault.
- Store `vault-copy` key material as an inner AEAD-wrapped secret.
- Use a random object DEK for v2 encrypted objects.
- Wrap object DEKs using AEAD and protected header AAD.
- Use HKDF-SHA256 for generated managed keys and Argon2id for human passwords.
- Support three v2 unlock modes:
  - password;
  - managed key;
  - password + managed key.
- Use framed chunked AES-256-GCM for files.
- Use single-shot AES-256-GCM plus ASCII armour for text/messages.
- Use canonical JSON protected headers plus binary chunk frames for v2 encrypted files.
- Encrypt file restore metadata by default, with hidden metadata as an option.
- Use intuitive CLI syntax:
  - `ssc encrypt file --with password`
  - `ssc encrypt file --with key:laptop-backup`
  - `ssc encrypt file --with password --with key:laptop-backup --require all`
  - `ssc decrypt file.ssc`
- Auto-detect v1/v2 during decrypt.
- Keep v2 explicit on encrypt until the format and tests are mature.

Required v2.0.0 release gate (not yet met — tracked against the 2026-09-10 audit):

- golden compatibility fixtures for the KDF/wrap/commitment layers exist;
  container- and frame-level golden vectors do not yet cover the shipped wire
  format, only an earlier draft of it;
- tamper tests exist for the header and frame layers;
- vault migration tests exist;
- CLI mapping tests exist for `encrypt`/`decrypt --with`, but there is no
  end-to-end test coverage of any `ssc key` subcommand, and `ssc key create`
  cannot currently produce a usable key (see audit P0-1/P0-2).

Recommended staged PR sequence (1–7 landed and tested; 8–9 incomplete):

1. Documentation and design.
2. v2 module skeleton and dataclasses.
3. `.ssckey` keyfile format.
4. Structured v2 vault schema and `V2VaultService`.
5. HKDF helpers and AEAD DEK wrapping.
6. v2 envelope and header authentication.
7. v2 payload encryption and chunk frames.
8. CLI integration with `--with` syntax — encrypt-side done; `decrypt` has no
   `--with`/`--require` flags, and the `ssc key` lifecycle commands are not
   functional end to end.
9. Docs, migration guide, and release hardening — not started; current docs
   (README, CHANGELOG, MIGRATION, CRYPTOGRAPHY, THREAT_MODEL) describe a
   multi-grant, fully wired v2 that does not match the shipped code.

---

## SSC v3.0.0 — Vault-Policy-First Encryption System

SSC v3.0.0 can build on the v2 managed-key foundation and introduce a full access-policy model.

Potential v3 work:

- multiple grants per encrypted object;
- any-of and all-of access policies;
- threshold recovery grants;
- access add/remove without payload rewrite;
- X25519 or HPKE-style public/private recipient grants;
- hardware-backed key grants;
- OS keychain/device-bound grants;
- profile-based encryption policies;
- optional SQLite encrypted-record vault backend;
- tamper-evident audit logging.

v3 should only be designed after the v2 managed-key foundation has fixtures,
migration tests, and a mature CLI contract.
