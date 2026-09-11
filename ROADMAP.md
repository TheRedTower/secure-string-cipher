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

## SSC v2 (the `.ssc` container format) — shipping in package v2.0.0

"v2" is the name of the managed-key container format, not the package
version — the two happen to share a number in this release, but for an
unrelated reason: it ships as part of package release **v2.0.0**, a major
bump because `ssc vault backups`/`ssc vault restore` changed incompatibly
(numeric indices → stable string identifiers) relative to v1.3.0 — see
CHANGELOG.md's `[2.0.0]` entry. The managed-key feature itself is purely
additive: no other existing v1 API/CLI/format changed or was removed.
Designed from [`docs/V2_MANAGED_KEYS_ARCHITECTURE.md`](docs/V2_MANAGED_KEYS_ARCHITECTURE.md)
and refined in
[`docs/SSC_V2_REFINED_IMPLEMENTATION_SPEC.md`](docs/SSC_V2_REFINED_IMPLEMENTATION_SPEC.md).
The full feature — container format, `.ssckey` identities, vault-backed key
lifecycle, and CLI integration (`ssc encrypt --with ...`, `ssc key ...`) —
merged to `main` in PR #40 (commit `59147fc`) on 2026-09-11, followed by
fixes from three automated PR reviews and the release-gate closures below.
`ssc key create` and `ssc key rename` work end to end (a 2026-09-10 audit
had found both broken; that audit is no longer current).

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

Required v2.0.0 release gate — all items below are now closed as of
2026-09-11; this roadmap no longer tracks an open release gate for v2.

- golden compatibility fixtures for the KDF/wrap/commitment layers, the
  three grant-header shapes, tamper tests for the header and frame layers,
  and vault migration tests all exist.
- **Container/frame-level golden vector.** `tools/generate_v2_vectors.py`
  now also generates a container through the real `encrypt_v2_file`,
  checked in as `tests/fixtures/v2/golden_two_frame_container.ssc`
  (`tests/unit/test_v2_container_golden.py`): the fixture's own bytes are
  pinned by sha256, it must always decrypt to the exact recorded
  plaintext, and both frames' raw magic/index/length/flags layout is
  verified directly, not just via successful decryption. Necessarily
  decrypt-only (frame nonces/salts are random every encryption by design).
- **Key status (`archive`/`revoke`/`destroy`) enforcement at encrypt/decrypt
  time.** By default `cli_args.py::_resolve_v2_key_source` still resolves
  `.ssckey` files directly off disk without consulting vault status — a
  revoked or destroyed key you still hold keeps working, which is inherent
  to holding the file, not a bug — but passing `--vault LABEL` alongside a
  key source now unlocks the vault and rejects a `revoked`/`destroyed` key
  that this vault tracks.
- **CLI end-to-end test coverage for the full `ssc key` subcommand group.**
  `create`/`import`/`show`/`export`/`list`/`rename`/`archive`/`revoke`/
  `destroy` are each now exercised as real `cmd_key_*` calls against a
  hermetic, file-backed vault (`tests/unit/test_v2_key_cli_e2e.py`),
  including the revoke/destroy interaction with `--vault` enforcement
  above — not just argument parsing or the underlying `V2VaultService`
  methods in isolation.

Recommended staged PR sequence (1–8 landed and tested; 9 in progress):

1. Documentation and design.
2. v2 module skeleton and dataclasses.
3. `.ssckey` keyfile format.
4. Structured v2 vault schema and `V2VaultService`.
5. HKDF helpers and AEAD DEK wrapping.
6. v2 envelope and header authentication.
7. v2 payload encryption and chunk frames.
8. CLI integration with `--with` syntax and the `ssc key` lifecycle
   commands — merged and functional; `decrypt` intentionally has no
   `--with`/`--require` flags (credential type is read from the header).
9. Docs, migration guide, and release hardening — docs corrected as of
   2026-09-11; the release gate above (golden vectors, `ssc key` CLI e2e
   tests, key-status enforcement) is what remains before a release.

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
