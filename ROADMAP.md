# Secure String Cipher roadmap

This roadmap tracks planned architectural work for SSC. The current priority is to preserve the stable v1 encryption core while introducing a controlled v2 managed-key architecture.

---

## SSC v2.0.0 — Managed Key Identity Utility

SSC v2.0.0 will introduce a managed-key architecture without rewriting the existing v1 core. The design is approved in detail in [`docs/V2_MANAGED_KEYS_ARCHITECTURE.md`](docs/V2_MANAGED_KEYS_ARCHITECTURE.md).

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

Required v2.0.0 release gate:

- golden compatibility fixtures;
- tamper tests;
- vault migration tests;
- CLI mapping tests.

Recommended staged PR sequence:

1. Documentation and design.
2. v2 module skeleton and dataclasses.
3. `.ssckey` keyfile format.
4. Structured v2 vault schema and `V2VaultService`.
5. HKDF helpers and AEAD DEK wrapping.
6. v2 envelope and header authentication.
7. v2 payload encryption and chunk frames.
8. CLI integration with `--with` syntax.
9. Docs, migration guide, and release hardening.

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

v3 should only be designed after the v2 managed-key foundation has fixtures, migration tests, and stable CLI behaviour.
