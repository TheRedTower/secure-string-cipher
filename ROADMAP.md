# Secure String Cipher security architecture roadmap

This roadmap turns the storage/encryption research analysis into an implementation plan for SSC. It is deliberately ordered by dependency and risk so that high-level features such as SQLite vaults, XChaCha20 streaming, biometric unlock, and hardware-key unlock do not get bolted onto the current design prematurely.

## Current position

SSC is already past the toy-project stage. The current codebase has a working CLI, AES-256-GCM encryption, Argon2id-derived keys, key commitment, authenticated metadata, key-file support, OS keychain support, passphrase vault commands, persistent rate limiting, audit logging, and secure-memory best-effort helpers.

The project should **not** jump straight to many ciphers, MFA, biometrics, and a database. The next major milestone should be a stable internal architecture:

> SSC v2 architecture: versioned encrypted envelope, algorithm/KDF/key-source registries, storage backend abstraction, and migration-safe metadata.

## Design principles

1. **Encrypt first, shred second.** File shredding should be best effort only. Modern SSDs, snapshots, copy-on-write filesystems, backups, and journaling can retain old data outside the tool's control.
2. **Keep safe defaults.** Users should not need to pick ciphers to be secure. Advanced choices should be explicit profiles, not the normal path.
3. **Do not invent crypto.** Add ciphers only through well-maintained libraries and a versioned compatibility layer.
4. **Separate keys and encrypted data where possible.** The long-term shape should be encrypted data in files/SQLite and small wrapping/device secrets in OS keychain storage.
5. **Treat biometrics as key release, not key material.** Biometrics should unlock an OS/hardware-protected secret, not become the cryptographic secret.
6. **Do not accidentally become a password manager.** A secure vault is in scope; browser autofill, website account management, breach checks, sync, and TOTP account storage are a different product.

## Priority legend

- **P0**: Foundation required before larger features.
- **P1**: High-value architectural/security work after P0.
- **P2**: Useful feature work once the design is stable.
- **P3**: Long-term or aspirational work.

---

## P0 - Required foundation

### P0.1 Threat model and scope document

Create `docs/THREAT_MODEL.md` (extract/expand from the existing Threat Model section in `.github/CRYPTOGRAPHY.md`).

The document should define attacker models, protected assets, assumptions, and non-goals.

Suggested attacker models:

- A1: attacker obtains encrypted file only.
- A2: attacker obtains encrypted vault file plus config.
- A3: attacker obtains local OS account access.
- A4: malware runs as the same user while SSC is decrypting.
- A5: attacker has old backups, filesystem snapshots, or cloud-sync history.
- A6: user forgets the master passphrase.
- A7: user loses a key file, device secret, or hardware key.

Suggested non-goals:

- SSC cannot protect plaintext after the user intentionally decrypts it.
- SSC cannot fully defend against malware running as the same OS user.
- SSC cannot guarantee secure per-file deletion on SSDs, APFS, Btrfs, ZFS, snapshots, or backups.
- SSC is not a browser password manager.
- SSC does not claim that biometrics alone are cryptographic secrets.

Acceptance criteria:

- Threat model exists in docs.
- README links to the threat model.
- Security-sensitive roadmap items reference the relevant attacker model.

### P0.2 Versioned encryption envelope

Define a single explicit envelope format for text, file, vault-entry, and vault-export encryption.

The envelope should include at minimum:

```text
magic: SSC
format_version: 2
object_type: text | file | vault_entry | vault_export
cipher_suite: aes-256-gcm | xchacha20poly1305-stream | future-suite
kdf: argon2id | scrypt | pbkdf2-hmac-sha256
kdf_params:
  salt
  memory_cost
  time_cost
  parallelism
key_sources:
  password
  keyfile
  keychain_device_secret
  hardware_key
metadata_aad:
  created_at
  ssc_version
  chunk_size
  original_filename_policy
nonce_or_stream_header
key_commitment
ciphertext
tag_or_stream_final_tag
```

Implementation notes:

- Metadata needed for decryption must be stored with the encrypted object.
- Sensitive metadata must be authenticated as AAD and encrypted where feasible.
- Format parsers should reject unknown required fields and unsupported versions clearly.
- Add golden fixtures for v1/current and v2/future formats.

Acceptance criteria:

- `EnvelopeHeader` or equivalent dataclass exists.
- Parser rejects tampered headers and unknown required versions.
- Tests cover wrong password, tampered metadata, tampered ciphertext, unsupported suite, and migration path.

### P0.3 Algorithm, KDF, and key-source registries

Introduce internal registries so algorithms and unlock methods are not hard-coded throughout the codebase.

Suggested interfaces:

```python
class CipherSuite(Protocol):
    name: str
    version: int

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> EncryptedPayload: ...
    def decrypt(self, key: bytes, payload: EncryptedPayload, aad: bytes) -> bytes: ...
```

```python
class KDF(Protocol):
    name: str

    def derive(self, passphrase: bytes, params: KDFParams) -> bytes: ...
```

```python
class KeySource(Protocol):
    name: str

    def get_key_material(self, context: UnlockContext) -> bytes: ...
```

Initial registry entries:

- Cipher suite: `aes-256-gcm`.
- KDF: `argon2id`.
- Key sources: `password`, `keyfile`, `keychain`.

Acceptance criteria:

- Existing encryption/decryption flows use the registry.
- Unsupported cipher/KDF names fail closed.
- Tests prove current AES-GCM/Argon2id compatibility is preserved.

### P0.4 Storage backend abstraction

Add a clean `VaultStore` abstraction before adding SQLite.

Suggested interface:

```python
class VaultStore(Protocol):
    def load(self) -> bytes | None: ...
    def save(self, data: bytes) -> None: ...
    def delete(self) -> None: ...
    def exists(self) -> bool: ...
    def status(self) -> VaultStoreStatus: ...
```

Start with:

- `FileVaultStore`
- `KeychainVaultStore`

Then later add:

- `SQLiteVaultStore`

Acceptance criteria:

- Existing vault commands work through `VaultStore`.
- File and keychain backends pass the same behavioural test suite.
- Backend selection remains backwards compatible.

### P0.5 Compatibility and migration harness

Add tests and commands that make future format changes safe.

Required items:

- Golden encrypted fixtures.
- `ssc vault status` shows backend and format version.
- `ssc vault migrate` can migrate old vault formats to the new format.
- `ssc doctor` reports unsupported or deprecated formats without modifying data.

Acceptance criteria:

- CI proves old fixtures can still decrypt.
- CI proves tampered fixtures fail.
- Migrations are idempotent and tested.

---

## P1 - High-value architecture and storage work

### P1.1 SQLite encrypted-record vault backend

Add SQLite only after P0 storage abstractions exist.

Recommended model:

```text
~/.secure-string-cipher/vault.sqlite

vault_meta:
  schema_version
  created_at
  default_cipher_suite
  default_kdf_policy
  migration_state

entries:
  id
  label_mac
  encrypted_label
  encrypted_payload
  payload_type
  cipher_suite
  kdf_id
  key_version
  created_at
  updated_at
  deleted_at

keys:
  key_id
  wrapped_dek
  wrapping_method
  created_at
  rotated_at
```

Important constraints:

- Do not store plaintext labels by default.
- Use deterministic label MACs for lookup.
- Store encrypted labels for display after unlock.
- Store encrypted payloads per entry.
- Keep OS keychain usage to small secrets such as a device secret or wrapped KEK.

Acceptance criteria:

- SQLite backend is opt-in or experimental initially.
- Existing file/keychain vaults can migrate to SQLite.
- Entries can be updated without rewriting the entire vault blob.
- Metadata leakage is documented and minimized.

### P1.2 Key hierarchy and wrapping model

Move toward a key hierarchy instead of using passphrase-derived keys directly for everything.

Recommended model:

```text
master passphrase
  -> Argon2id
  -> KEK: key-encryption key
  -> unwraps DEK: data-encryption key
  -> encrypts file/text/vault entry
```

For multi-source unlock:

```text
password-derived material
+ keyfile material
+ keychain device secret
+ hardware-key result
-> HKDF/domain-separated combiner
-> KEK
```

Acceptance criteria:

- KEK/DEK terminology is documented.
- Key rotation can change the KEK without re-encrypting every payload where possible.
- DEK wrapping metadata is stored in the envelope/vault schema.

### P1.3 KDF policy, calibration, and migration

Current Argon2id settings are strong enough to keep as defaults, but future versions should make KDF policy explicit and migratable.

Add commands:

```bash
ssc kdf benchmark
ssc kdf calibrate
ssc vault migrate-kdf
```

Acceptance criteria:

- Encrypted objects store the KDF name and parameters used.
- Users can benchmark local performance.
- KDF parameter upgrades can be detected and migrated.
- PBKDF2-HMAC-SHA256 is only offered for compatibility/FIPS-style profiles, not as the normal default.

### P1.4 Secure deletion improvements

Keep the secure-delete feature honest and platform-aware.

Required behaviour:

- Rename user messaging from "securely shredded" to "best-effort shredded" unless the backend can make stronger guarantees.
- Reject symlinks and directories.
- Use GNU `shred` on Linux when available.
- On macOS/APFS, use fallback overwrite/unlink but warn that per-file secure deletion is unreliable.
- Use `subprocess.run([...], shell=False)` for external tools.
- Recommend full-disk encryption and cryptographic erase for stronger protection.

Acceptance criteria:

- Symlink attack tests exist.
- Platform warnings exist.
- Docs distinguish memory wiping from file deletion.

### P1.5 Streaming file encryption

Add a streaming backend for large files. Preferred candidate: libsodium `secretstream_xchacha20poly1305`.

Recommended split:

- Small text/messages: continue using AES-256-GCM.
- Large files: use XChaCha20-Poly1305 secretstream.

Acceptance criteria:

- Large files do not need to be fully loaded into memory.
- Stream headers are included in the versioned envelope.
- Truncation and tampering fail closed.
- AAD binds stream metadata to the encrypted file.

---

## P2 - Feature expansion after the architecture is stable

### P2.1 Hardware-key unlock

Add support for hardware-backed key contribution after the key-source registry and key hierarchy are stable.

Candidate approaches:

- FIDO2 `hmac-secret` extension.
- YubiKey-backed wrapping secret.
- PIV-backed unwrap/decrypt operation.

Acceptance criteria:

- Hardware-key support is optional.
- Recovery/lockout UX is documented before release.
- Tests/mocks cover missing key, wrong key, and fallback behaviour.

### P2.2 Biometric-gated keychain unlock

Biometric support should be implemented as OS-gated release of a keychain/hardware-backed secret, not as a standalone secret.

Acceptance criteria:

- Biometrics are documented as local key-release UX, not cryptographic key material.
- Feature is platform-specific and optional.
- CLI clearly reports when biometric unlock is unavailable.

### P2.3 CLI UX split for text, phrase, and file modes

Refine the CLI so the user can understand exactly what is being encrypted.

Possible commands:

```bash
ssc encrypt --text
ssc decrypt --text
ssc encrypt-file ./document.pdf
ssc decrypt-file ./document.pdf.ssc
ssc vault add github-token
ssc vault get github-token
ssc doctor
```

Add warning when plaintext secrets are provided as command-line arguments because shell history and process listings may leak them.

### P2.4 ASCII-armoured message format

Support copy/paste-friendly encrypted messages:

```text
-----BEGIN SSC MESSAGE-----
Version: 2
Cipher: AES-256-GCM
KDF: Argon2id

base64...
-----END SSC MESSAGE-----
```

Acceptance criteria:

- Armour parser is strict.
- Raw binary format remains available for files.
- Headers are authenticated by the envelope AAD.

### P2.5 Key rotation and re-encryption commands

Add commands:

```bash
ssc vault rotate-key
ssc vault reencrypt --suite xchacha20poly1305-stream
ssc vault reencrypt --kdf-policy modern
```

Acceptance criteria:

- Rotation is resumable or fails cleanly.
- Backup is created before destructive migrations.
- Audit events are emitted.

---

## P3 - Long-term options

### P3.1 Optional Rust core

Do not rewrite now. Consider a Rust core only after the v2 envelope, key-source model, and storage abstractions are stable.

Potential benefits:

- Stronger memory discipline.
- Easier native binary distribution.
- Type-safe format parsing.
- Lower-level streaming control.

Risk:

- Premature rewrite delays useful features.
- Cross-language bindings add packaging complexity.

### P3.2 GUI or editor integrations

Only consider after the CLI and envelope are stable.

Possible integrations:

- Minimal desktop GUI.
- VS Code command integration.
- Shell completion and secure clipboard helpers.

### P3.3 Sync and sharing

Treat as a separate security project.

Before sync/sharing, require:

- Threat model update.
- Recipient/key agreement design.
- Conflict handling.
- Recovery and revocation model.

---

## Feature priority matrix

| Feature | Value | Risk | Priority |
| --- | --- | --- | --- |
| Threat model | Very high | Low | P0 |
| Versioned envelope | Very high | Medium | P0 |
| Algorithm/KDF/key-source registries | Very high | Medium | P0 |
| Storage abstraction | Very high | Low/medium | P0 |
| Migration fixtures | Very high | Medium | P0 |
| SQLite encrypted-record backend | High | Medium | P1 |
| KEK/DEK hierarchy | High | Medium | P1 |
| KDF calibration | High | Low/medium | P1 |
| Secure deletion warnings/hardening | Medium | Low | P1 |
| XChaCha20 secretstream | High | Medium | P1 |
| Hardware key unlock | High | High | P2 |
| Biometric-gated unlock | Medium/high | High | P2 |
| ASCII-armoured messages | Medium | Low | P2 |
| Key rotation commands | High | Medium/high | P2 |
| Rust core | Medium | Very high | P3 |
| Sync/sharing | High | Very high | P3 |

## Recommended next PRs

1. `docs: add threat model and security scope`
2. `refactor: introduce encryption envelope model`
3. `refactor: add cipher and KDF registries`
4. `refactor: introduce vault storage backend interface`
5. `test: add encrypted format compatibility fixtures`
6. `feat: add experimental SQLite encrypted vault backend`
7. `feat: add KDF benchmark and calibration commands`
8. `feat: add XChaCha20 secretstream file encryption`

## Research notes

- OWASP recommends beginning cryptographic storage design with architecture and threat modelling, and highlights that encryption layer choice depends on threat model.
- OWASP recommends authenticated encryption modes where available and explicitly says not to use custom algorithms.
- OWASP key-storage guidance recommends using secure OS/framework/cloud storage where available, separating keys from encrypted data where possible, and using DEK/KEK-style wrapping for stored keys.
- OWASP password-storage guidance recommends Argon2id as the preferred password hashing/KDF family and gives a minimum profile of 19 MiB memory, 2 iterations, and 1 degree of parallelism.
- Libsodium secretstream is a strong candidate for large-file encryption because it is designed for encrypted streams and file encryption using XChaCha20-Poly1305.
- NIST guidance treats biometrics as limited-use authentication material and says they should be used as part of multi-factor authentication with a physical authenticator, not as a standalone authenticator.

## Product boundary

SSC should aim to be:

> A local, OS-integrated encryption utility for files, messages, phrases, passphrases, key material, and small secure vault items.

SSC should avoid becoming:

> A browser password manager with website records, autofill, breach monitoring, cloud sync, account sharing, and TOTP account storage.
