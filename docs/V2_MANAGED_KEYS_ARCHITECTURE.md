# SSC v2 Managed Keys Architecture

Status: Approved design draft  
Target release: v2.0.0  
Future direction: v3.0.0 vault-policy-first architecture

This document records the approved architecture for Secure String Cipher (SSC) v2.0.0 managed-key support. It is intended to be detailed enough for implementation planning while preserving the current stable v1 core.

The design deliberately avoids turning SSC into an OpenSSL wrapper, an age clone, a browser password manager, or a full policy engine in v2.0.0. The v2 release should introduce managed key identities in a controlled, compatibility-first way. The v3 release can then build on this foundation to become a vault-policy-first encryption system.

---

## 1. Purpose

SSC currently provides a security-focused local encryption CLI with AES-256-GCM, Argon2id, file/text encryption, key-file support, passphrase vault support, OS keychain integration, rate limiting, audit logging, and secure-memory best-effort helpers.

The next major architectural goal is to let users create and manage SSC-generated keyfiles and use those keys as first-class encryption identities.

The v2 feature should support these workflows:

```bash
ssc key create laptop-backup --external
ssc key create laptop-backup --vault-copy
ssc encrypt report.pdf --with key:laptop-backup
ssc encrypt report.pdf --with password
ssc encrypt report.pdf --with password --with key:laptop-backup --require all
ssc decrypt report.pdf.ssc
```

The important distinction is that a managed key is not just random bytes. It is a lifecycle-aware key identity with a human label, cryptographic fingerprint, storage mode, status, metadata, and import/export behaviour.

---

## 2. Product identity

### v2.0.0 identity

SSC v2.0.0 is a **managed key identity utility**.

It should remain a local encryption CLI, but add first-class support for:

- generated `.ssckey` files;
- managed symmetric key identities;
- external-only key storage;
- vault-copy key storage;
- v2 encrypted objects;
- optional v2 password envelopes;
- one combined password + managed-key mode;
- intuitive `--with` CLI syntax;
- auto-detecting decrypt compatibility for v1 and v2 objects.

### v3.0.0 identity

SSC v3.0.0 can become a **vault-policy-first encryption system**.

v3 can add a real access-policy model with multiple grants, any-of/all-of semantics, threshold options, public/private identities, hardware-backed keys, device-bound unlocks, and access mutation. Those features are intentionally not part of v2.0.0.

---

## 3. v2/v3 release strategy

v2.0.0 must be additive and compatibility-first.

Rules:

- Keep the current v1 crypto core intact.
- Do not rewrite `core.py` as part of the first v2 implementation.
- Do not dump all v2 logic into `passphrase_manager.py`.
- Introduce v2 as a parallel path under `secure_string_cipher/v2/`.
- Keep v1 password encryption as the default initially.
- Use v2 explicitly when the user selects v2 features.
- Auto-detect v1/v2 during decryption.
- Delay full policy graphs, threshold unlocking, hardware keys, and active asymmetric recipient encryption until v3 or later v2.x work.

---

## 4. Non-goals

SSC v2.0.0 is not:

- a browser password manager;
- an autofill product;
- a cloud sync product;
- an age/OpenPGP/GPG clone;
- an OpenSSL shell-wrapper;
- a full v3 access-policy engine;
- a hardware-token system;
- an active public/private recipient-encryption system;
- a guarantee of secure per-file deletion on modern filesystems and SSDs.

SSC v2.0.0 must not claim to protect plaintext after the user has decrypted it. It also must not claim complete protection against malware running as the same OS user, a compromised kernel/root/admin account, terminal history leakage, clipboard leakage, screenshots, logs, or weak user passwords.

---

## 5. Practical local threat model

### Protected against

SSC v2.0.0 should protect against:

- **A1:** attacker obtains encrypted file only;
- **A2:** attacker obtains encrypted file plus public metadata;
- **A3:** attacker obtains encrypted vault file but not the master password;
- **A4:** attacker obtains a `.ssckey`-protected object but not the matching `.ssckey`;
- **A5:** attacker tampers with the header, chunk frames, encrypted metadata, wrapped DEK, grant fields, KDF parameters, or key fingerprints;
- **A6:** attacker has old backups or snapshots of encrypted objects;
- **A7:** attacker has archived or revoked-key metadata but not usable key material.

### Partially protected or warned against

SSC v2.0.0 can partially protect or warn against:

- **A8:** attacker obtains vault-copy key material after the vault has been legitimately unlocked;
- **A9:** attacker obtains an external keyfile but not the password in combined mode;
- **A10:** attacker obtains the password but not the managed key in combined mode;
- **A11:** attacker tries to exploit metadata leakage.

### Not fully protected against

SSC v2.0.0 does not fully protect against:

- malware running as the same OS user while SSC is decrypting;
- compromised root/admin/kernel accounts;
- terminal history, shell history, logs, clipboard leakage, screenshots, or process inspection after user action;
- plaintext after successful decryption;
- weak user passwords;
- lost keyfiles or destroyed keys without backups;
- broken operating-system random number generation;
- filesystem snapshots or cloud backups containing plaintext outside SSC's control;
- modern filesystem and SSD behaviour that makes per-file secure deletion unreliable.

---

## 6. Approved decisions summary

The following decisions are locked for the v2 architecture:

1. v2.0.0 is a managed key identity utility; v3.0.0 moves toward vault-policy-first design.
2. v2 uses a parallel managed-key path and keeps the current v1 core intact.
3. v2 uses hybrid managed-key storage: `external-only` and `vault-copy` initially.
4. v2 key identities are lifecycle-aware and include selected v3-enabling fields.
5. v2 encrypted objects use a random object DEK; an unlock source derives a KEK to wrap that DEK.
6. Object DEKs are wrapped using AEAD.
7. Generated managed key material uses HKDF-SHA256; human passwords use Argon2id.
8. v2 password envelopes are optional; v1 password encryption remains the default initially.
9. v2 supports one combined mode: password + managed key.
10. Files use framed chunked AES-256-GCM; text/small messages use single-shot AES-256-GCM.
11. v2 encrypted files use canonical JSON protected headers plus binary chunk frames.
12. Generated `.ssckey` files use PEM-like ASCII armour.
13. Key identity records live in a structured namespace inside the existing encrypted vault.
14. `vault-copy` key material is inner AEAD-wrapped inside the encrypted vault.
15. The `vault-copy` wrapping key comes from `master password -> Argon2id -> vault_root_key -> HKDF subkey`.
16. Key fingerprints are domain-separated hashes of key material.
17. v2 encrypted objects use `access.policy = single-grant` and exactly one grant.
18. The primary CLI uses intuitive `--with` syntax plus interactive mode.
19. Decrypt auto-detects v1/v2; encrypt remains explicit for v2 initially.
20. v2 code lives under `secure_string_cipher/v2/`.
21. v2 vault integration uses a `V2VaultService` adapter around `PassphraseVault`.
22. Headers are authenticated through split protected sections and canonical digests.
23. v2 file chunks use explicit indexed binary frames with flags.
24. File metadata is encrypted by default, with hidden metadata as an option.
25. Encrypted metadata uses a dedicated HKDF-derived metadata key.
26. HKDF salts are random per derivation.
27. Text/messages use ASCII-armoured SSC MESSAGE format.
28. Asymmetric identity support is reserved, but not active in v2.0.0.
29. Key lifecycle status is conservatively enforced.
30. Managed-key export is guarded with warnings, safe output handling, and audit.
31. v2 uses structured, privacy-preserving audit events.
32. v2 requires golden fixtures, tamper tests, migration tests, and CLI mapping tests.
33. v2 lands through staged PRs with strict boundaries.
34. v2 uses a practical local attacker model.
35. This document is the canonical detailed architecture; `ROADMAP.md` contains the short summary.
36. This document is implementer-focused, not merely a roadmap and not a formal proof.

---

## 7. v2 architecture overview

The approved v2 encryption model is:

```text
random object DEK
  -> encrypt payload

password / managed key / password + managed key
  -> derive KEK
  -> AEAD-wrap object DEK
```

This separates data encryption from key access.

Benefits:

- key rotation and future rewrapping become possible;
- v3 access grants can wrap the same object DEK without rewriting payloads;
- password, managed-key, and combined modes use one common object model;
- v1 functions can remain stable while v2 is introduced in parallel.

---

## 8. Managed key identity model

A v2 managed key identity is a lifecycle-aware object.

Conceptual record:

```json
{
  "schema_version": 1,
  "id": "laptop-backup",
  "type": "symmetric-key",
  "fingerprint": "ssc-k1-...",
  "storage": "external-only",
  "status": "active",
  "created_at": "2026-06-03T00:00:00Z",
  "updated_at": "2026-06-03T00:00:00Z",
  "last_used_at": null,
  "public_metadata": {
    "label": "laptop-backup",
    "algorithm": "hkdf-sha256",
    "key_length": 32,
    "format": "ssckey-v1"
  },
  "external": {
    "path_hint": "~/keys/laptop-backup.ssckey"
  },
  "vault_secret": null,
  "future": {
    "capabilities": ["wrap", "unwrap"],
    "exportable": true,
    "portable": true,
    "requires_user_presence": false,
    "requires_device_binding": false
  }
}
```

### Required v2 fields

- `schema_version`
- `id`
- `type`
- `fingerprint`
- `storage`
- `status`
- `created_at`
- `updated_at`
- `last_used_at`
- `public_metadata`
- `external`
- `vault_secret`

### Active v2.0.0 key type

Only this type is active in v2.0.0:

```text
symmetric-key
```

Reserved future key types:

```text
x25519-identity
rsa-oaep-legacy
hardware-backed-key
os-keychain-secret
```

### Storage modes

Active in v2.0.0:

```text
external-only
vault-copy
```

Reserved for later:

```text
vault-only
metadata-only
```

### Lifecycle status

Approved status values:

```text
active
archived
revoked
destroyed
```

Enforcement:

```text
active:
  encryption allowed
  decryption allowed

archived:
  encryption blocked by default
  decryption allowed with warning

revoked:
  encryption blocked
  decryption blocked by default
  decryption allowed only with explicit recovery override

destroyed:
  encryption blocked
  decryption impossible if secret material is removed
  metadata may remain for audit/history
```

---

## 9. Key fingerprints

Managed keys have two identifiers:

```text
Human ID:
  user-facing label, renameable
  example: laptop-backup

Fingerprint:
  cryptographic identity, stable
  example: ssc-k1-...
```

The human ID is not security-critical. The fingerprint is used for cryptographic matching.

Approved fingerprint rule:

```text
fingerprint_input =
  "secure-string-cipher/v2/key-fingerprint/symmetric" || key_material

fingerprint_full =
  SHA-256(fingerprint_input)

fingerprint_display =
  "ssc-k1-" + base32_no_padding(fingerprint_full)[0:32]
```

Rules:

1. Key labels are user-facing and renameable.
2. Fingerprints are stable and cryptographic.
3. v2 encrypted objects store the fingerprint.
4. Vault records store both human ID and fingerprint.
5. `.ssckey` imports recompute the fingerprint and reject mismatches.
6. If a key is renamed, the fingerprint does not change.

---

## 10. `.ssckey` keyfile format

Generated `.ssckey` files use a PEM-like ASCII-armoured format.

Example:

```text
-----BEGIN SSC SYMMETRIC KEY-----
Version: 1
Key-ID: laptop-backup
Type: symmetric-key
KDF: hkdf-sha256
Fingerprint: ssc-k1-...
Created: 2026-06-03T00:00:00Z

base64url-secret-key-material
-----END SSC SYMMETRIC KEY-----
```

### Rules

- Extension: `.ssckey`
- Secret material: 32 random bytes minimum
- Default KDF for generated keys: `hkdf-sha256`
- File permissions: `0600` where supported
- Reject symlinked key paths
- Reject malformed armour
- Reject malformed base64
- Reject unknown key types
- Recompute and verify fingerprint on import
- Warn or fail on overly broad permissions, depending on platform capability

The `.ssckey` file is not encrypted by default in v2.0.0. If the user wants convenience and vault-based recovery, they should use `vault-copy`. A future encrypted keyfile export format may be added later.

---

## 11. v2 encrypted object model

v2 encrypted objects use:

```text
object_dek = random 32-byte content key
payload = encrypted with object_dek
access grant = wraps object_dek
```

Allowed v2 grant types:

```text
password
managed-key
combined-password-managed-key
```

The header uses a future-compatible access shape:

```json
{
  "access": {
    "version": 1,
    "policy": "single-grant",
    "grants": [
      {
        "grant_id": "grant-0",
        "type": "managed-key",
        "key_fingerprint": "ssc-k1-...",
        "kek_derivation": {
          "alg": "hkdf-sha256",
          "salt": "base64url-random..."
        },
        "wrap_alg": "aes-256-gcm",
        "wrap_nonce": "base64url...",
        "wrapped_dek": "base64url...",
        "tag": "base64url..."
      }
    ]
  }
}
```

v2 rule:

```text
access.policy MUST equal "single-grant".
access.grants MUST contain exactly one grant.
```

The array shape exists only to preserve a clean v3 migration path.

---

## 12. Key derivation rules

### Human passwords

Human passwords use Argon2id.

Password grant flow:

```text
password
  -> Argon2id using grant password_kdf metadata
  -> password KEK
  -> AEAD unwrap object DEK
```

### Generated managed keys

Generated managed keys use HKDF-SHA256 with domain separation.

Managed-key grant flow:

```text
managed key secret
  -> HKDF-SHA256 with random grant salt and v2 info string
  -> managed-key KEK
  -> AEAD unwrap object DEK
```

### Combined password + managed key

Combined mode is the only multi-source unlock mode in v2.0.0.

Flow:

```text
password
  -> Argon2id
  -> password_component

managed key secret
  -> HKDF-SHA256
  -> managed_key_component

password_component + managed_key_component
  -> HKDF-SHA256 with random combined salt
  -> combined KEK

combined KEK
  -> AEAD unwrap object DEK
```

v2.0.0 must not generalise this into arbitrary policy graphs.

### HKDF salt rule

All HKDF derivations use random per-derivation salts.

Examples:

```text
managed key -> object DEK wrap KEK:
  salt = random per grant

object DEK -> payload key:
  salt = random per payload descriptor

object DEK -> metadata key:
  salt = random per metadata container

vault root key -> vault-copy key wrapping KEK:
  salt = random per key record

password component + managed-key component -> combined KEK:
  salt = random per combined grant
```

The object ID is authenticated context/AAD, not the HKDF salt.

### Domain separation

Every derived key must use an explicit, versioned `info` string.

Recommended strings:

```text
secure-string-cipher/v2/key-fingerprint/symmetric
secure-string-cipher/v2/managed-key/dek-wrap/aes-256-gcm
secure-string-cipher/v2/password/dek-wrap/aes-256-gcm
secure-string-cipher/v2/combined/password+managed-key/dek-wrap/aes-256-gcm
secure-string-cipher/v2/payload/aes-256-gcm/chunked
secure-string-cipher/v2/payload/aes-256-gcm/text
secure-string-cipher/v2/metadata/aes-256-gcm
secure-string-cipher/v2/vault-copy/key-material-wrap/aes-256-gcm
secure-string-cipher/v3/access-grant
```

---

## 13. DEK wrapping

Object DEKs are wrapped with AEAD.

Default v2.0.0 wrap algorithm:

```text
aes-256-gcm
```

A wrapped DEK contains:

```json
{
  "wrap_alg": "aes-256-gcm",
  "wrap_nonce": "base64url...",
  "wrapped_dek": "base64url...",
  "tag": "base64url..."
}
```

The wrapped DEK must be bound to protected metadata via AAD. Header authentication is described below.

---

## 14. Header authentication model

v2 uses split protected header sections and canonical digests as AAD.

### Canonical JSON

Protected header objects must be serialized deterministically:

```python
json.dumps(
    header,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
```

### Wrap protected header

`wrap_protected_header` contains fields needed to bind the wrapped DEK:

- format;
- header version;
- object ID;
- object type;
- payload descriptor;
- grant type;
- key fingerprint or password KDF metadata;
- combined KDF metadata when relevant;
- wrap algorithm;
- KEK derivation metadata.

Then:

```text
wrap_aad = SHA-256(canonical_json(wrap_protected_header))
```

### Full protected header

After the wrapped DEK exists, the final security-critical header is canonicalized:

```text
payload_header_digest = SHA-256(canonical_json(full_protected_header))
```

Each payload chunk uses AAD derived from:

- `payload_header_digest`;
- `object_id`;
- `chunk_index`;
- `plaintext_length`;
- `final_chunk` flag.

This prevents undetected header edits, grant edits, algorithm substitution, metadata-policy edits, chunk reordering, and chunk truncation.

---

## 15. File payload format

v2 file encryption uses a binary `.ssc` container:

```text
SSC2 magic
header_length
canonical_json_protected_header
chunk_frame_0
chunk_frame_1
...
final_chunk_frame
```

### Payload encryption

Files use framed chunked AES-256-GCM.

```text
object_dek
  -> HKDF-SHA256 using random payload salt
  -> payload_key
  -> AES-256-GCM chunk encryption
```

### AES-GCM nonce construction

For file chunks:

```text
nonce_prefix: 4 random bytes stored in protected header
chunk_index:  8-byte big-endian integer from the frame
nonce:        nonce_prefix || chunk_index
```

### Chunk frame

Conceptual frame:

```text
frame_magic:        4 bytes
frame_version:      1 byte
flags:              1 byte
reserved:           2 bytes
chunk_index:        8 bytes unsigned big-endian
plaintext_length:   4 bytes unsigned big-endian
ciphertext_length:  4 bytes unsigned big-endian
ciphertext:         ciphertext_length bytes
tag:                16 bytes
```

The `FINAL_CHUNK` flag indicates the end of the payload.

### Validation rules

Decryption must enforce:

1. First chunk index is `0`.
2. Each next chunk index equals previous + 1.
3. No repeated chunk index.
4. `FINAL_CHUNK` appears exactly once.
5. No bytes appear after `FINAL_CHUNK`.
6. Non-final chunks have `plaintext_length == chunk_size`.
7. Final chunk has `plaintext_length <= chunk_size`.
8. Every AES-GCM tag verifies.
9. Decryption writes to a temporary file first.
10. Output is atomically moved into place only after all chunks authenticate.

---

## 16. File metadata privacy

v2 stores restore metadata in encrypted metadata by default.

Default:

```text
filename_policy = encrypted
```

Optional high-privacy mode:

```text
filename_policy = hidden
```

Plaintext filename storage is not the v2 default.

### Encrypted metadata

Encrypted metadata uses a dedicated key derived from the object DEK:

```text
metadata_key = HKDF-SHA256(
  IKM = object_dek,
  salt = random metadata salt,
  info = "secure-string-cipher/v2/metadata/aes-256-gcm",
  length = 32
)
```

Example metadata plaintext:

```json
{
  "original_filename": "report.pdf",
  "original_size": 1234567
}
```

Visible header container:

```json
{
  "metadata": {
    "policy": "encrypted",
    "alg": "aes-256-gcm",
    "kdf": {
      "alg": "hkdf-sha256",
      "salt": "base64url-random..."
    },
    "nonce": "base64url...",
    "ciphertext": "base64url...",
    "tag": "base64url..."
  }
}
```

For hidden metadata:

```json
{
  "metadata": {
    "policy": "hidden"
  }
}
```

---

## 17. Text/message format

Text and small messages use single-shot AES-256-GCM internally, but are serialized as ASCII-armoured SSC MESSAGE blocks.

Example:

```text
-----BEGIN SSC MESSAGE-----
Version: 2
Type: text
Header: base64url(...)

base64url(...)
-----END SSC MESSAGE-----
```

Rules:

- The armour parser must be strict.
- The header remains canonical/protected internally.
- The text/message format shares the same access-grant model as files.
- Compact one-line tokens may be added later in v2.x.

---

## 18. Vault schema and V2VaultService

v2 key identity records live in a structured namespace inside the existing encrypted vault.

The existing outer vault storage remains file/keychain-backed. v2 adds a structured decrypted JSON schema.

### Structured vault shape

```json
{
  "schema_version": 2,
  "vault_meta": {
    "vault_id": "base64url-random",
    "vault_kdf": {
      "alg": "argon2id",
      "salt": "base64url...",
      "memory_kib": 65536,
      "time_cost": 3,
      "parallelism": 4
    }
  },
  "items": {
    "passphrases": {},
    "keys": {}
  }
}
```

Existing flat vaults migrate from:

```json
{
  "github": "secret",
  "backup": "secret2"
}
```

to:

```json
{
  "schema_version": 2,
  "items": {
    "passphrases": {
      "github": "secret",
      "backup": "secret2"
    },
    "keys": {}
  }
}
```

### V2VaultService

v2 uses an adapter around `PassphraseVault`.

Responsibility split:

```text
PassphraseVault:
  existing encrypted vault backend
  existing file/keychain storage
  existing outer vault encryption
  existing passphrase CRUD compatibility
  raw vault read/write hooks

V2VaultService:
  structured v2 vault schema
  v1-flat-to-v2 migration
  key identity records
  vault-copy wrapping/unwrapping
  key lookup by id/fingerprint
  future bridge toward SQLite or v3 policy vault
```

v2 key-management logic must live in `secure_string_cipher/v2/`, not inside `PassphraseVault` directly.

---

## 19. Vault-copy key material wrapping

`vault-copy` stores an encrypted copy of managed key material inside the vault.

It is inner-wrapped rather than stored raw in the decrypted vault JSON.

Conceptual record:

```json
{
  "vault_secret": {
    "protection": "vault-wrapped",
    "wrap_alg": "aes-256-gcm",
    "kek_derivation": "vault-root-hkdf-sha256",
    "salt": "base64url-random...",
    "nonce": "base64url...",
    "encrypted_key_material": "base64url...",
    "tag": "base64url..."
  }
}
```

Derivation:

```text
master password
  -> Argon2id using vault_meta.vault_kdf
  -> vault_root_key

vault_root_key
  -> HKDF-SHA256 using random per-record salt
  -> vault_copy_kek

vault_copy_kek
  -> AES-256-GCM unwrap managed key secret
```

Boundary rule:

```text
v2.0.0 may introduce vault_root_key only for inner vault-copy wrapping.
It must not become a full vault rewrite or per-entry encryption system.
```

---

## 20. CLI UX

Primary verbs:

```text
encrypt
decrypt
key
vault
```

Primary unlock syntax:

```bash
ssc encrypt report.pdf --with password
ssc encrypt report.pdf --with key:laptop-backup
ssc encrypt report.pdf --with password --with key:laptop-backup --require all
ssc decrypt report.pdf.ssc
```

Interactive mode:

```bash
ssc encrypt report.pdf
```

If no unlock source is supplied, SSC should prompt the user to choose:

1. password;
2. managed key;
3. password + managed key;
4. create a new key.

### Key commands

```bash
ssc key create laptop-backup --external
ssc key create laptop-backup --vault-copy
ssc key import ~/keys/laptop-backup.ssckey --vault-copy
ssc key list
ssc key show laptop-backup
ssc key export laptop-backup --out ~/keys/laptop-backup.ssckey
ssc key archive laptop-backup
ssc key revoke laptop-backup
ssc key destroy laptop-backup
```

### Ambiguity rules

1. `--with password` creates a password grant.
2. `--with key:ID` creates a managed-key grant.
3. `--with password --with key:ID --require all` creates the combined grant.
4. Multiple `--with` values without `--require all` must fail clearly.
5. `decrypt` auto-detects v1/v2 by magic/header.
6. v2 decrypt with a vault-copy key asks for vault unlock if needed.
7. v2 decrypt with an external-only key uses a stored path hint when possible, otherwise asks for `--key-file`.

---

## 21. Compatibility and migration

Approved behaviour:

```text
Decrypt:
  auto-detect v1 or v2 from magic/header.

Encrypt:
  existing password-only behaviour remains v1 by default initially.
  v2 is used explicitly through the new UX.
```

Rules:

1. v1 encrypted files remain decryptable.
2. v1 vaults remain readable.
3. v2 files are detected by new `SSC2` magic/header.
4. `ssc decrypt` auto-detects v1/v2.
5. Password-only existing commands keep v1 behaviour initially.
6. Any managed-key operation creates v2 output.
7. `ssc encrypt --with password` creates v2 password-envelope output.
8. A future config option may allow users to make v2 the default.
9. v1 -> v2 migration tools come after v2 fixtures are stable.

Vault migration rules:

1. Existing vaults remain readable.
2. Migration creates a backup first.
3. Migration is idempotent.
4. If migration fails, the original vault remains untouched.
5. Existing passphrase commands continue to work.
6. The first key-identity operation may trigger migration.

---

## 22. Key export and recovery

Managed-key export is guarded.

Approved behaviour:

```text
active key:
  export allowed after vault unlock + warning

archived key:
  export allowed after vault unlock + warning

revoked key:
  export blocked unless explicit recovery override is supplied

destroyed key:
  export impossible if secret material was removed

external-only key:
  export cannot recreate the key unless the original external .ssckey is supplied

vault-copy key:
  export can recreate a .ssckey after vault unlock and confirmation
```

Export rules:

1. Require vault unlock.
2. Refuse overwrite unless `--force` is supplied.
3. Reject symlink output paths.
4. Write with `0600` permissions where supported.
5. Display key ID and fingerprint before export.
6. Warn that export creates another copy of the decryption secret.
7. Do not export to stdout by default.
8. Emit an audit event.
9. Require explicit override for revoked keys.
10. Never export destroyed keys if secret material is absent.

Suggested command:

```bash
ssc key export laptop-backup --out ~/keys/laptop-backup.ssckey
```

For revoked-key recovery:

```bash
ssc key export laptop-backup --out ~/keys/laptop-backup.ssckey --allow-revoked-key
```

---

## 23. Audit events

v2 uses structured, privacy-preserving audit events.

Log:

```text
key.create
key.import
key.export
key.archive
key.revoke
key.destroy
encrypt.v2
decrypt.v2.success
decrypt.v2.failure
vault.migrate_v2
vault_copy.wrap
vault_copy.unwrap
recovery.override_used
```

Never log:

```text
raw key material
passphrases
plaintext file contents
decrypted metadata
encrypted key material
vault contents
full plaintext file paths by default
```

Example event:

```json
{
  "timestamp": "2026-06-03T00:00:00Z",
  "event_type": "key.export",
  "result": "success",
  "format_version": "v2",
  "key_id": "laptop-backup",
  "key_fingerprint": "ssc-k1-...",
  "key_status": "active",
  "storage_mode": "vault-copy"
}
```

Failure events should use generic reason codes:

```json
{
  "timestamp": "2026-06-03T00:00:00Z",
  "event_type": "decrypt.v2.failure",
  "result": "failure",
  "format_version": "v2",
  "failure_reason_code": "wrong_key_or_tampered_object"
}
```

Avoid making audit logs into an oracle. Normal audit output should not reveal overly specific internal failure details.

---

## 24. Code organisation

v2 code lives under:

```text
src/secure_string_cipher/v2/
```

Suggested module layout:

```text
secure_string_cipher/v2/
  envelope.py
    V2Header
    AccessBlock
    AccessGrant
    PayloadDescriptor
    canonical_json()

  key_identity.py
    KeyIdentity
    KeyStatus
    KeyStorageMode
    compute_key_fingerprint()

  keyfile.py
    write_ssckey()
    read_ssckey()
    validate_ssckey()

  kdf.py
    hkdf_sha256()
    derive_managed_key_kek()
    derive_combined_kek()
    derive_vault_copy_kek()

  keywrap.py
    wrap_dek_aead()
    unwrap_dek_aead()

  payload.py
    encrypt_file_chunked_aes_gcm()
    decrypt_file_chunked_aes_gcm()
    encrypt_text_single_aes_gcm()
    decrypt_text_single_aes_gcm()

  vault_schema.py
    migrate_flat_vault_to_v2()
    load_key_identity()
    save_key_identity()
    wrap_vault_copy_secret()
    unwrap_vault_copy_secret()

  encrypt.py
    high-level v2 encryption orchestration

  decrypt.py
    high-level v2 decryption orchestration
```

Rules:

- `core.py` remains the v1/stable crypto surface.
- `v2/` owns managed-key identities, v2 envelopes, chunked payloads, and v2 key wrapping.
- Shared low-risk utilities may be reused.
- v2 logic must not sprawl through v1 modules.

---

## 25. Testing and release gate

v2.0.0 must not be released until the following pass in CI.

### Golden fixtures

- v1 password file decrypts;
- v1 keyfile file decrypts;
- v2 password object decrypts;
- v2 managed-key object decrypts;
- v2 combined object decrypts;
- v2 ASCII-armoured message decrypts;
- v2 `.ssckey` import/export round-trips.

### Tamper tests

- modified protected header fails;
- modified wrapped DEK fails;
- modified key fingerprint fails;
- modified KDF salt fails;
- modified metadata ciphertext fails;
- modified chunk index fails;
- reordered chunks fail;
- duplicated chunks fail;
- missing final chunk fails;
- trailing bytes after final chunk fail;
- modified chunk tag fails.

### Migration tests

- flat v1 vault migrates to structured v2 vault;
- migration creates backup;
- failed migration leaves original vault untouched;
- migration is idempotent;
- existing passphrase commands still work after migration.

### CLI mapping tests

- `--with password` maps to password grant;
- `--with key:ID` maps to managed-key grant;
- `--with password --with key:ID --require all` maps to combined grant;
- ambiguous flag combinations fail safely;
- decrypt auto-detects v1/v2.

Property-based and fuzz testing should be added in v2.x hardening, especially around binary chunk frames and parser robustness, but they are not mandatory for the first v2.0.0 gate.

---

## 26. Staged PR implementation plan

v2 must land through small, reviewable PRs.

Recommended sequence:

```text
PR 1 — docs/design
  Add docs/V2_MANAGED_KEYS_ARCHITECTURE.md
  Add ROADMAP.md summary/link
  No production code

PR 2 — v2 module skeleton and dataclasses
  Add secure_string_cipher/v2/
  Add dataclasses/types only
  Add canonical JSON helper
  No encryption behaviour change

PR 3 — .ssckey keyfile format
  read/write/validate PEM-like keyfiles
  fingerprint computation
  keyfile tests

PR 4 — structured v2 vault schema + V2VaultService
  V2VaultService adapter
  flat-vault-to-v2 migration
  key identity records
  no encrypted object support yet

PR 5 — HKDF + AEAD DEK wrapping
  HKDF helpers
  AEAD DEK wrap/unwrap
  vault-copy inner wrapping
  tamper tests

PR 6 — v2 envelope + header authentication
  protected header sections
  canonical digests
  access.single-grant model
  golden header fixtures

PR 7 — v2 payload encryption + chunk frames
  chunked AES-GCM file payloads
  single-shot text payloads
  explicit indexed binary chunk frames
  tamper/truncation/reorder tests

PR 8 — CLI integration with --with syntax
  ssc encrypt/decrypt --with syntax
  interactive mode
  auto-detect v1/v2 decrypt
  ambiguity failure tests

PR 9 — docs, migration guide, release hardening
  user docs
  migration guide
  threat model update
  release checklist
```

No production v2 encryption should be exposed through CLI until the envelope, key wrapping, payload encryption, and tamper tests are in place.

---

## 27. Future v3 direction

v3.0.0 can evolve the v2 shape into a vault-policy-first system.

Potential v3 features:

- multiple grants per object;
- any-of policies;
- all-of policies;
- threshold recovery grants;
- access add/remove without payload rewrite;
- public/private X25519 or HPKE-style recipient grants;
- hardware-backed grants;
- OS keychain/device-bound grants;
- SQLite encrypted-record vault backend;
- profile-based encryption policies;
- optional tamper-evident audit logs.

v2 deliberately reserves the shape for this while implementing only the bounded `single-grant` model.

---

## 28. External references

These references inform the design but are not copied as protocols:

- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- NIST SP 800-38D, GCM and GMAC: https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 9180 HPKE, future public-key direction: https://www.rfc-editor.org/rfc/rfc9180
- Python cryptography AEAD documentation: https://cryptography.io/en/latest/hazmat/primitives/aead/

---

## 29. Final implementation principle

SSC v2.0.0 should be powerful, but not sprawling.

The implementation should prove one clean idea:

> SSC can manage local symmetric key identities, use them to wrap object keys, encrypt files/messages with authenticated encryption, preserve v1 compatibility, and create a future path toward v3 access policies without destabilising the existing core.
