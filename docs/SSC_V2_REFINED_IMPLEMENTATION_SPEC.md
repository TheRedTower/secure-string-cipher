# Secure String Cipher V2 — Refined Implementation Specification

Specification: SSC-V2-REFINED-1.0
Review date: 9 September 2026
Target feature release: 2.0.0; retain Beta status until separately justified
Status: implementation-planning baseline, with repository evidence and explicit technical decisions

## 1. Purpose, authority, and scope

This document verifies the quoted Gemini 3.1 Pro review and supplies a concrete replacement baseline for Antigravity's V2 implementation plan. It is a design specification, not evidence that V2 cryptography has been implemented or audited.

The maintainer explicitly selected **a 100 MiB maximum plaintext file size for the initial V2 release**, with a separate **4 MiB maximum chunk size**. The remaining decisions below are the review's technical recommendations, resolved sufficiently for implementation planning; they must not be represented as an independent security certification or as previously approved maintainer decisions.

For the requested plan, this specification supersedes conflicting details in the original architecture, particularly vault integration, exact wire encodings, resource limits, commitments, and claims about future rewrapping. Preserve the original document as historical design evidence. Reconcile its current counterpart and ROADMAP.md when implementing the approved documentation changes.

MUST and MUST NOT identify acceptance requirements. Antigravity must revise its plan against these requirements before starting production implementation. A later explicit maintainer instruction takes precedence. This document does not authorize a merge, tag, release, package upload, or source changes during this review.

### 1.1 Exact reviewed repository state

Repository: [TheRedTower/secure-string-cipher](https://github.com/TheRedTower/secure-string-cipher).

| Surface | Verified reference | Meaning |
| --- | --- | --- |
| Current main | e3d1d67a2676834fc9900cb36e1791c7ac15c626 | Baseline for future implementation |
| V2 feature branch | 112eebf9ad05e59311af4581720ef552492fa86e | codex/v2-module-skeleton |
| V2 merge base | ff1d4791e6792744710c774cd2e6f2e33ff31ddd | Branch is one commit ahead and 44 commits behind main |
| V2 pull request | [PR #40](https://github.com/TheRedTower/secure-string-cipher/pull/40) | Open draft; six added files, 389 added lines |
| Architecture introduction | [PR #33](https://github.com/TheRedTower/secure-string-cipher/pull/33) | Merged design document |
| Current packaging/guidance integration | [PR #70](https://github.com/TheRedTower/secure-string-cipher/pull/70) | Merged; its current-main changes must be preserved |
| Latest GitHub release observed | [v1.3.0](https://github.com/TheRedTower/secure-string-cipher/releases/tag/v1.3.0) | Published 6 June 2026; peeled commit f7ff04c4d5a0adc0cbdc3cb841d5048f2f14dcac |
| Package metadata on main | 1.3.0, Python >=3.12, Beta | Includes changes newer than the published v1.3.0 tag |

The architecture is **docs/V2_MANAGED_KEYS_ARCHITECTURE.md**, not a root-level file. Its contents are identical on the two reviewed branch tips. The quoted separate file v2_architecture_score_and_refinements.md was not supplied and was not found in fetched repository history; this review assesses the quoted claims, not unseen content.

Refresh main and the exact PR head before implementation. Do not check out or overwrite the maintainer's working tree. Rebase or transplant the bounded V2 change onto fresh main in an isolated checkout, retaining current dependency, packaging, security, and documentation changes.

### 1.2 Verification actually performed

The connected GitHub repository supplied repository/branch information, PR metadata and discussions, and branch comparisons. A separate local clone of that repository supplied complete source and history inspection.

On macOS, CPython 3.14.7, in each snapshot's locked environment:

- **307 existing main tests passed**, covering KDFs, size limits, metadata parsing, vault validation/transactions/transport, atomic publication, core/key-pair behavior, key commitment, and released v4/v5 fixtures.
- **All 8 V2 skeleton tests passed**.
- Synthetic probes confirmed nine architecture-relevant behaviors: nested authenticated vault rejection; changing outer encryption salt, HMAC salt, and encryption key on save; acceptance of NaN, coerced JSON keys, negative chunk sizes, empty grants, and mutation through nested mappings.
- Every tracked file in both extracted snapshots remained byte-identical to its Git object after these checks.

The full suite, fresh coverage measurement, fresh remote CI matrix, real OS keychains, package builds, and an external cryptographic audit were **not** run for this document. Historical PR test totals are historical evidence only. There is no V2 encryption implementation to validate end to end yet.

## 2. Verdict on Gemini's claims

| Claim | Finding | Required disposition |
| --- | --- | --- |
| Architecture merits 9.5/10 | A subjective score cannot establish readiness. The direction is useful, but vault-schema incompatibility and incomplete protocol definitions prevent implementation readiness as written. | Replace the score with requirements and evidence. |
| V1/V2 separation is strong | Confirmed as a design intention and package layout. The branch adds value types only; it does not prove service or cryptographic boundaries. | Keep the parallel package and define the narrow vault/CLI bridges below. |
| Canonical JSON AAD binding establishes cryptographic rigor | The document proposes split AAD projections, but the code only serializes data. There is no AAD construction, parser, AEAD, or tamper-test implementation. | Specify exact projections, byte encodings, validation, and ordering. |
| Add a 4 MiB chunk cap | Sound refinement for the proposed framed format. Current V1 already uses a fixed 256 KiB streaming buffer and a 100 MiB plaintext cap. A chunk cap alone does not bound headers, frame reads, KDF work, or total output. | Adopt the full resource policy in section 5. |
| Choose how V2 obtains a vault root key | A real unresolved implementation boundary. V1 has independent password-derived encryption and HMAC keys, not a stable exported root. | Select a separate V2 derivation with its own persistent salt; do not add export_derived_root_key(). |
| Bind Argon2 parameters to prevent downgrade | Already required in principle by original sections 12 and 14. Changing parameters changes the derived key; authenticated metadata must also bind their interpretation. | Define the complete KDF descriptor and reject unsupported parameters before running Argon2. Do not describe this as proof of an existing exploitable downgrade. |
| generate_key_pair() is orphaned and should be deprecated in 1.4.0 | It is disconnected from recipient encryption, but remains an exported, documented, tested RSA utility introduced in 1.1.0. No 1.4.0 deprecation schedule was found. | Preserve it in this work; any deprecation needs a separate API/release decision. |

Additional material gaps:

1. Current vault validation requires a flat dictionary of strings. The proposed nested schema will fail, including through transactional import/restore.
2. Outer encryption and HMAC salts change on save. Neither is a suitable persistent inner-wrapping root identity.
3. Frozen dataclasses are only shallowly frozen; supplied lists and dictionaries remain mutable. Serialization coerces non-string keys and permits non-finite numbers.
4. Header length encoding, frame magic/version/flags, empty-file handling, text nonce placement, and metadata AAD need exact definitions.
5. The payload digest includes the full access grant. Access changes therefore invalidate payload authentication; V2 does not provide payload-preserving rewrapping.
6. V1 explicitly uses key commitment. AES-GCM and an AAD hash alone do not automatically preserve that property in V2.
7. Migration, password changes, concurrent writers, backup recovery, and local lifecycle enforcement need explicit semantics.
8. Current documentation contains some historical or overly broad cryptographic wording. Current code, fixtures, and measured behavior take precedence over generic security adjectives.

## 3. Architecture decisions

| ID | Decision |
| --- | --- |
| D01 | Keep V1 encryption, supported formats, and existing default CLI behavior. V2 remains explicit on encryption. |
| D02 | V2 uses random 32-byte object DEKs, AES-256-GCM, Argon2id for passwords, and HKDF-SHA256 for generated secrets and subkeys. |
| D03 | V2 has exactly one password, managed-key, or combined password-and-managed-key grant. |
| D04 | V2VaultService derives a separate operation-scoped vault root. No public or private export of V1 encryption/HMAC keys for this purpose. |
| D05 | Keep the existing outer vault cryptography and storage backends; introduce a narrowly scoped structured-document bridge. |
| D06 | Keep 100 MiB file payloads initially, 256 KiB default chunks, and 4 MiB maximum chunks. |
| D07 | Use a strict SSC canonical-JSON profile with explicit schemas; do not call the current helper a general RFC 8785 implementation. |
| D08 | Keep full-header payload authentication. Defer access mutation without payload rewriting to a separately versioned protocol. |
| D09 | Add explicit, domain-separated grant commitment as specified below; do not silently drop V1's commitment objective. |
| D10 | Make metadata confidential by default and bound all restoration behavior. |
| D11 | Use full fingerprints for stored identity and matching; abbreviations are display-only. |
| D12 | Require transactional migration/rewrapping and cooperative cross-process serialization before enabling managed-key vault mutations. |
| D13 | Retain generate_key_pair() unchanged in this feature; do not schedule a speculative 1.4.0 release. |
| D14 | Require negative/parser/property tests before V2.0.0, not only later hardening. |

These are bounded additions to the existing product. Multiple grants, any-of policies, thresholds, recipient encryption, public/private identities, hardware keys, directories, synchronization, SQLite, and larger files remain outside V2.0.0.

## 4. Compatibility and module ownership

### 4.1 Preserve these V1 contracts

- The existing file family uses five-byte magic **SSCV2** and metadata versions 4 and 5. It is distinct from the new four-byte **SSC2** family.
- Continue writing V1 metadata version 5 and reading supported versions 4/5. Do not restore unsupported historical PBKDF2 formats under the label "V1 compatibility."
- Preserve V5 authentication of the exact metadata bytes. V4 stored filenames remain ignored for automatic destinations; explicit destinations remain authoritative.
- Preserve the existing salt, nonce, commitment, tag sizes, Argon2 constants, legacy Base64 encoding, six-line vault envelope, and released fixtures.
- The existing text/bytes token decodes as salt(16) || nonce(12) || commitment(32) || ciphertext || tag(16). Preserve this actual layout even where an older illustrative diagram omits the commitment.
- V1's 256 KiB reads feed one GCM operation with one final tag. They are not independently authenticated V2 chunk frames.
- Legacy key-file mode remains SHA-256(file bytes).hexdigest() used as an Argon2 password. It does not parse RSA semantics and must not silently reinterpret existing --key-file inputs as new managed keys.
- Preserve root exports and existing return types. No automatic root re-export of unfinished V2 APIs.
- Keep existing passphrase CRUD behavior and defaults on unmigrated vaults. New-version passphrase commands must preserve V2 records after migration.

### 4.2 Ownership

| Module/surface | Responsibility |
| --- | --- |
| core.py | Existing V1 crypto implementation; no V2 protocol logic |
| v2/envelope.py | Typed headers, strict schemas, canonical projections |
| v2/key_identity.py | Identity types, full fingerprint computation, lifecycle rules |
| v2/keyfile.py | Strict .ssckey codec and bounded safe file operations |
| v2/kdf.py | Explicit V2 Argon2 profiles, HKDF, combined derivation |
| v2/keywrap.py | DEK wrapping and grant commitments |
| v2/payload.py | Indexed file frames and single-shot messages |
| v2/metadata.py | Metadata encoding, AEAD, validation |
| v2/vault_schema.py | Pure structured schema and record validation; no backend access |
| v2/vault_service.py | V2VaultService, key records, root lifecycle, migration, rewrapping |
| v2/encrypt.py and v2/decrypt.py | Operation orchestration and error translation |
| Shared vault-document bridge | Existing outer vault codec, schema dispatch, full-document preservation |
| Shared vault transaction/lock layer | Backend publication, backups, read-back, rollback, cooperative writer serialization |
| cli_args.py and cli.py | Explicit V1/V2 routing, prompting, lifecycle and recovery UX |
| atomic_io.py, secure_memory.py | Reused low-level helpers with their documented limitations |

All key-management and V2 derivation logic stays under src/secure_string_cipher/v2/. A small, explicit schema dispatch from the shared vault bridge to the pure V2 validator is allowed. It must not import V2VaultService, create import cycles, or expose V1 key material.

The current six-file skeleton is a starting point. Its placeholder examples and field shapes are not released wire-format commitments.

## 5. Resource policy

> **2026-09-10 correction:** this section originally specified a 262,144-byte
> default chunk size and a 40-byte per-frame overhead. The shipped
> implementation (`v2/encrypt.py`, `v2/payload.py`) uses a 65,536-byte default
> chunk and a 35-byte per-frame overhead (see the corrected §9.2). Numbers
> below are corrected to match the encoder.
>
> **2026-09-11 update:** at the time of the correction above, the decrypt
> path did not enforce a cumulative frame-count or byte cap —
> `FrameReader.read_frames` looped until a FINAL frame with no counter. This
> is now fixed: `FrameReader` computes `max_frames = max(1,
> ceil(MAX_PLAINTEXT_FILE_SIZE / chunk_size))` per the header's own
> `chunk_size` and rejects a stream once either the frame index or the
> cumulative plaintext byte count would exceed it, checked before each
> frame's ciphertext body is read.

MiB means 1,048,576 bytes; KiB means 1,024 bytes. Limits apply to both writers and readers. These are initial application limits, not mathematical AES-GCM maxima.

| Quantity | Initial V2 requirement |
| --- | --- |
| Plaintext file | 0 through 104,857,600 bytes inclusive |
| Chunk size | One of 65,536; 131,072; 262,144; 524,288; 1,048,576; 2,097,152; 4,194,304 (only 65,536 is reachable from the CLI today — `chunk_size` is not exposed as a flag) |
| Default chunk size | 65,536 bytes |
| Maximum file frames | max(1, ceil(104,857,600 / chunk_size)) — 1,600 for the default 65,536-byte chunk; enforced on decrypt per-object from its own header |
| Canonical protected header | 1 through 65,536 bytes |
| File container raw cap | 8 + 65,536 + 104,857,600 + 1,600 × 35 = 104,979,144 bytes (default chunk size; enforced on decrypt) |
| Metadata plaintext | At most 4,096 bytes |
| V2 message plaintext | At most 1,048,576 UTF-8 bytes |
| V2 message armour | At most 2,097,152 bytes |
| .ssckey armour | At most 8,192 bytes; decoded secret exactly 32 bytes |
| V2 password input | At most 65,536 UTF-8 bytes before copying/deriving |
| Object/header JSON | At most 16 container levels and 1,024 total members/elements |
| Vault raw representation | Existing 104,857,600-byte cap, counted as strict UTF-8 bytes |
| Managed identities per V2 vault | At most 1,024; no new semantic count limit on legacy passphrase entries |
| Argon2 profile | Exactly the initial profile in section 7; one derivation at a time per operation |

The header JSON node/depth limits do not apply wholesale to a large legacy vault. V2 vault schema depth is separately bounded to 16; its passphrase namespace remains governed by the legacy raw-size boundary.

Before a file KDF, reject unsupported file types and snapshot sizes outside the raw cap. After header validation, tighten the maximum frame count to max(1, ceil(104857600 / chunk_size)) and the corresponding raw size. During processing, enforce cumulative raw bytes, plaintext bytes, and frame counts independently; a stat result is not a substitute for runtime counters.

Before allocating a frame body, validate its fixed-size header, index, flags, and lengths. Do not call read(attacker_length) first. Bounded exact-read helpers must reject short reads and overlong input. Repeated read results and additions must remain checked even on Python's unbounded integers.

No parser may initiate multiple candidate KDFs, automatically retry a weaker profile, decompress data, or process arbitrary nested JSON before applying its resource boundary. V2 file stdin/stdout streaming is deferred; existing V1 stdin behavior remains available. This avoids claiming safe whole-file publication through a non-retractable pipe.

A 4 MiB chunk cap bounds plaintext chunk length; GCM ciphertext has the same length and its separate tag adds 16 bytes. Libraries may make additional bounded copies, so this is not a 4 MiB process-RAM guarantee.

## 6. Common encodings and strict types

Define these operations once:

~~~text
U32(n) = unsigned 4-byte little-endian representation
U64(n) = unsigned 8-byte little-endian representation
B64(x) = RFC 4648 URL-safe Base64, no "=" padding, no whitespace
H(x)   = SHA-256(x), raw 32-byte output
C(x)   = SSC canonical JSON bytes defined below
||     = byte concatenation, never text concatenation
~~~

> **2026-09-10 correction:** U32/U64 were originally specified big-endian.
> The shipped implementation packs every wire integer little-endian
> (`struct.pack("<I", ...)`, `"<Q"`, and the frame's `"<H"` padding-length
> field — see the corrected §9.2). Corrected here to match.

B64 decoding MUST check the alphabet, expected encoded/decoded lengths, unused padding bits, and encode(decode(value)) == value. It must not accept standard Base64's "+" or "/" spelling. V1 retains its existing padded standard Base64.

> **2026-09-10 correction:** this B64 definition (URL-safe, unpadded) governs
> every header field (salts, nonces, wrapped DEK, tags, commitment values —
> all via `v2/vault_schema.b64url_encode`). The V2 **message armor**
> transport (§9.5) is a documented exception: the shipped implementation
> encodes the armored header and body with standard padded
> `base64.b64encode`, not this B64. Both encodings exist in the codebase;
> know which one applies to which field.

All protocol object keys are specified ASCII strings. Reject unknown fields, missing fields, duplicate keys at every level, wrong types, non-UTF-8 input, BOMs, lone surrogates, non-finite numbers, and floats. Integers must have type int exactly, not bool, and lie in their specified ranges; otherwise use 0 through 2^53-1 as the JSON integer bound. Null is accepted only where explicitly specified.

SSC canonical JSON uses:

~~~python
json.dumps(
    validated_plain_object,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
~~~

Only validated string keys may enter the encoder. Never coerce keys with str(). Parsed protected-header bytes MUST equal C(parsed_header); reject alternate whitespace, property order, escaping, or numeric spelling. Validate depth while scanning/parsing rather than relying solely on recursive construction failure.

This is a restricted SSC profile. General JCS has additional numeric and property-sorting rules; the original helper is not a complete [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) implementation.

Validate and deeply own data before calculating digests. Do not retain caller-owned mutable dictionaries/lists. Frozen dataclasses alone are insufficient. A digest and the encryption operation must consume the same immutable validated snapshot.

## 7. Key hierarchy and KDFs

### 7.1 Sizes and randomness

Use the operating system CSPRNG through secrets.token_bytes:

- Managed secret: exactly 32 bytes.
- Object DEK: exactly 32 fresh bytes per object.
- Object ID, vault ID, immutable record ID: 16 random bytes.
- Argon2 salt: 16 random bytes.
- Every HKDF descriptor salt: 32 random bytes, independently generated when that descriptor is created.
- Single-shot GCM nonces: 12 random bytes.
- File nonce prefix: 4 random bytes, combined with the frame index as specified later.
- AES-GCM tags: 16 bytes; no truncation.

"Fresh salt" means new for a new derivation instance. Re-deriving an existing key MUST use the stored salt. Normal vault saves MUST NOT replace the inner vault-root salt.

### 7.2 Initial Argon2 descriptor

~~~json
{
  "alg": "argon2id",
  "version": 19,
  "memory_kib": 65536,
  "time_cost": 3,
  "parallelism": 4,
  "hash_len": 32,
  "salt": "<B64 of 16 bytes>"
}
~~~

The placeholders in this document explain types; they are not valid fixtures.

Use argon2.low_level.hash_secret_raw with Type.ID and version=19 explicitly. Parameters are literal integers; no booleans, strings, aliases, omitted defaults, or caller-selected algorithm dispatch. V2.0.0 accepts exactly this parameter tuple. Future profiles require a reviewed allowlist and fixtures; deployment memory limits can reject a supported profile, never silently reduce it.

The tuple matches the memory-constrained recommendation in [RFC 9106, section 4](https://www.rfc-editor.org/rfc/rfc9106). It is an initial interoperability profile, not a universal performance guarantee. KDF cost must be measured on the supported platforms.

Encode password text as exact UTF-8. Do not trim, normalize Unicode, lowercase, or change an existing password while decrypting. New-password prompts should apply a documented policy and confirmation; recovery must accept the credential that created the data, subject to resource limits. Legacy V1 password behavior is unchanged.

An envelope descriptor is untrusted until authenticated, but its type and resource bounds MUST be validated **before** derivation. Its complete content is also included in the authenticated grant transcript. Authentication cannot prevent memory exhaustion that already happened.

### 7.3 Derivation definitions

HKDF below means RFC 5869 HKDF-SHA256, including extract and expand, producing 32 bytes. Info strings are literal ASCII protocol constants selected by code, not arbitrary header inputs. Salt and context fields are authenticated. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) supplies the primitive; the compositions below are SSC design choices.

Let P = Argon2id(password, password_kdf). Let K be the decoded managed secret.

~~~text
Password grant:
  R = P
  KEK = HKDF(R, kek_derivation.salt,
             "secure-string-cipher/v2/password/dek-wrap/aes-256-gcm")

Managed-key grant:
  R = K
  KEK = HKDF(R, kek_derivation.salt,
             "secure-string-cipher/v2/managed-key/dek-wrap/aes-256-gcm")

Combined grant:
  M = HKDF(K, combined_kdf.managed_key_salt,
           "secure-string-cipher/v2/combined/managed-key-component")
  R = HKDF(P || M, combined_kdf.salt,
           "secure-string-cipher/v2/combined/password+managed-key/root")
  KEK = HKDF(R, kek_derivation.salt,
             "secure-string-cipher/v2/combined/password+managed-key/dek-wrap/aes-256-gcm")

All grant types:
  K_commit = HKDF(R, commitment.kdf.salt,
                 "secure-string-cipher/v2/grant/key-commitment/hmac-sha256")

File payload:
  K_payload = HKDF(DEK, payload.kdf.salt,
                  "secure-string-cipher/v2/payload/aes-256-gcm/chunked")

Text payload:
  K_payload = HKDF(DEK, payload.kdf.salt,
                  "secure-string-cipher/v2/payload/aes-256-gcm/text")

Metadata:
  K_metadata = HKDF(DEK, metadata.kdf.salt,
                   "secure-string-cipher/v2/metadata/aes-256-gcm")
~~~

P and M are each exactly 32 bytes; P || M is exactly 64 bytes in that order. Do not use XOR, hexadecimal strings, password text concatenation, or two independent alternative grants.

The combined construction requires both inputs. It is not automatically independent-factor authentication: if the managed key is recoverable from a vault unlocked with the same password, possession of that password and vault can supply both inputs. Explain that limitation in the combined/vault-copy UX.

### 7.4 Key commitment

V1 has an explicit HMAC commitment. General AES-GCM authentication does not itself imply key commitment; see [Albertini et al., How to Abuse and Fix Authenticated Encryption Without Key Commitment](https://eprint.iacr.org/2020/1456).

For every V2 grant, include:

~~~json
{
  "commitment": {
    "alg": "hmac-sha256",
    "kdf": {"alg": "hkdf-sha256", "salt": "<B64 of 32 bytes>"},
    "value": "<B64 of 32 bytes>"
  }
}
~~~

Compute its value after DEK wrapping using the exact transcript in section 8. Verify it with constant-time HMAC verification before attempting DEK unwrap. Use a different key from the AES wrapping key. Do not log either the value or the key.

This is a specified SSC composition requiring cryptographic review and golden vectors before release. Passing ordinary tamper tests is not a proof of committing security, and the document does not assert one. Do not replace it with a password-only commitment in combined mode: that would create a password-only offline verifier in a grant intended to require both inputs.


## 8. Object header and authentication transcript

### 8.1 Exact header schema

The top-level header has exactly these fields:

| Field | Value/type |
| --- | --- |
| format | "SSC2" |
| version | Integer 2 |
| object_id | B64 of 16 bytes |
| object_type | "file" or "text" |
| payload | Descriptor below |
| access | Access block below |
| metadata | Hidden or encrypted metadata container |

Payload common fields are type, alg, kdf, and metadata_policy:

- type equals object_type.
- alg is "aes-256-gcm".
- kdf is exactly {"alg":"hkdf-sha256","salt":B64(32 bytes)}.
- metadata_policy equals metadata.policy.
- File descriptors additionally require chunk_size and nonce_prefix = B64(4 bytes), and forbid text-only fields.
- Text descriptors additionally require nonce = B64(12 bytes) and plaintext_length in 0..1048576; they forbid chunk_size and nonce_prefix.
- Text metadata is {"policy":"hidden"} in V2.0.0.

The access block is exactly version=1, policy="single-grant", grants=[one grant]. A grant has common fields grant_id="grant-0", type, kek_derivation, wrap_alg, wrap_nonce, wrapped_dek, tag, and commitment.

| Grant field | Requirement |
| --- | --- |
| type | "password", "managed-key", or "combined-password-managed-key" |
| kek_derivation | Exact HKDF descriptor with 32-byte salt |
| wrap_alg | "aes-256-gcm" |
| wrap_nonce | B64 of 12 bytes |
| wrapped_dek | B64 of exactly 32 ciphertext bytes |
| tag | B64 of exactly 16 bytes |
| commitment | Section 7.4 descriptor and value |
| password_kdf | Required only for password and combined grants |
| key_fingerprint | Required only for managed-key and combined grants |
| combined_kdf | Required only for combined grants |

combined_kdf has exactly alg="hkdf-sha256", salt=B64(32 bytes), and managed_key_salt=B64(32 bytes). Other grant-specific fields are absent, not null. No generic algorithm registry or arbitrary plug-in dispatch is needed for this three-case format.

Hidden metadata has exactly policy="hidden". Encrypted metadata has exactly policy="encrypted", alg="aes-256-gcm", kdf, nonce, ciphertext, and tag, with the KDF/nonce/tag sizes above. Decode ciphertext only within the 4,096-byte metadata limit.

The skeleton's format="SSC-V2", object_type="encrypted-object", permissive mappings, and implicit nulls are test placeholders, not compatible wire alternatives. Replace them in new protocol fixtures.

### 8.2 Construction order and exact projections

A projection is an exact object construction/deep copy with only the listed omissions. It must not be an informal list of fields the implementer considers important.

~~~text
M_context = {
  format, version, object_id, object_type, payload,
  metadata: metadata container with only ciphertext and tag omitted
}

metadata_aad =
  b"SSC2/metadata/v1\0" || H(C(M_context))

W = complete header with only these fields omitted:
  access.grants[0].wrapped_dek
  access.grants[0].tag
  access.grants[0].commitment.value

wrap_aad =
  b"SSC2/wrap/v1\0" || H(C(W))

Q = complete header after DEK wrapping, with only this field omitted:
  access.grants[0].commitment.value

commitment.value =
  B64(HMAC-SHA256(K_commit, b"SSC2/commit/v1\0" || H(C(Q))))

m_context_digest = H(C(M_context))
~~~

> **2026-09-10 correction:** this section originally defined
> `payload_header_digest = H(C(complete_header))` — a digest of the *entire*
> header, including `access` — as the value authenticated by every payload
> frame and by the text message (§9.2, §9.5). The shipped implementation
> authenticates payload frames and messages against `m_context_digest`
> instead: the digest of `M_context`, which (like the metadata AAD) excludes
> `access` entirely. `payload_header_digest`/`compute_payload_header_digest`
> still exists in `v2/keywrap.py` but is dead code — nothing calls it.
>
> This is a real narrowing from the design in §8.3 below: "changing an access
> grant changes the payload AAD" does **not** hold for the shipped format,
> because the grant is outside `M_context`. In practice this does not let an
> attacker decrypt anything — the grant (and hence the DEK) is still bound to
> the complete header via `wrap_aad`/`commitment` (both project the full
> header), so a substituted grant cannot unwrap the original DEK — but the
> payload layer alone no longer detects a grant substitution the way this
> section originally promised. Note also that the implemented **message** AAD
> (§9.5) includes `decoded(object_id)` in addition to `m_context_digest`,
> while the implemented **frame** AAD (§9.2) does not include `object_id` at
> all; this is an unreviewed inconsistency between the two payload types, not
> a deliberate design choice.

The notation \0 denotes one zero byte. String field names and enum values are JSON strings; the digest values in AAD are raw bytes.

Writer order:

1. Validate inputs; generate IDs, DEK, salts, nonces, and all descriptors.
2. If metadata is encrypted, derive K_metadata and encrypt it with metadata_aad. Store its ciphertext and tag.
3. Derive the grant's R, KEK, and K_commit.
4. Encrypt the 32-byte DEK with AESGCM(KEK), wrap_nonce, and wrap_aad. Split the returned 48 bytes into 32-byte wrapped_dek and 16-byte tag.
5. Calculate commitment.value.
6. Validate and freeze the final header, compute C(header) and its digest once.
7. Encrypt the payload using that digest.

Reader order:

1. Bound and parse the complete header; apply exact schema/type/canonical checks.
2. Check the required credential source and all KDF/resource limits.
3. Derive the same keys; verify commitment; unwrap DEK with the same W projection.
4. Authenticate/decrypt encrypted metadata using M_context.
5. Authenticate every file frame, or the complete message, against the full header digest.
6. Validate declared metadata size and safe output handling.
7. Publish/return plaintext only on complete success.

No circular dependency exists: metadata excludes access and its own output; wrapping includes finished metadata but excludes its own output and the not-yet-computed commitment value; commitment includes the wrap output; payload authentication includes everything.

All security-relevant values are covered: formats/versions, policy and grant count, object identity/type, algorithms, every derivation parameter and salt, nonces, fingerprint, metadata policy and ciphertext, wrapped DEK, tags, and commitment descriptors/value.

A digest is not a MAC. Integrity comes from AEAD/HMAC keyed authentication of the transcript.

### 8.3 Rewrapping boundary

The full header, including the grant, is authenticated by each payload unit. Changing an access grant changes the payload AAD.

V2.0.0 MUST NOT offer in-place grant changes, claim payload-preserving rewrapping, or merely recalculate tags under reused key/nonce pairs. To change access in this version, fully decrypt and create a new object with a new DEK, object ID, salts, and nonces, through atomic output publication.

A future format may split immutable content authentication from mutable access authentication after dedicated review. The grant array alone does not make that protocol backward-compatible.

## 9. Binary files, metadata, and messages

### 9.1 File container

~~~text
magic                   4 bytes: ASCII "SSC2"
header_length           U32(len(C(header)))
protected_header        exactly header_length canonical UTF-8 bytes
frames                  one or more frames, ending in exactly one FINAL frame
EOF                     immediately after the final frame's tag
~~~

No BOM, line ending, trailing padding, appended object, or alternative magic is allowed. Parse five bytes when distinguishing legacy SSCV2 from the new family, without discarding the fifth byte when it belongs to the new length prefix. A malformed recognized format must not fall back to another parser.

### 9.2 Frame format

> **2026-09-10 correction:** this section originally specified a 24-byte
> big-endian prefix with a `frame_version` byte, `reserved` bytes, and a
> `ciphertext_length` field. The shipped implementation
> (`v2/payload.py`) is different in every one of those respects. Corrected
> below to match; see the §8.2 correction note for the frame AAD digest
> change (`payload_header_digest` → `m_context_digest`) that goes with this.

~~~text
frame_magic             4 bytes: ASCII "S2FR"
chunk_index             U64(index)
plaintext_length        U32(n)
padding_length          U16(n)
flags                   1 byte: 0x00 or 0x01 (FINAL)
ciphertext              (plaintext_length + padding_length) bytes
tag                     16 bytes
~~~

The fixed prefix is 19 bytes (`4 + 8 + 4 + 2 + 1`). Per-frame overhead is 35
bytes (19-byte prefix + 16-byte tag). Non-final frames pad their plaintext up
to `chunk_size` with random bytes (`padding_length = chunk_size -
plaintext_length`); the final frame may carry `padding_length = 0`. The
ciphertext length equals `plaintext_length + padding_length`, not a
separately transmitted `ciphertext_length` field.

~~~text
nonce = decoded(payload.nonce_prefix) || U64(chunk_index)

frame_aad =
  b"SSC2/frame/v2\0" ||
  m_context_digest ||
  U64(chunk_index) ||
  U32(plaintext_length) ||
  U16(padding_length) ||
  flags
~~~

Note the domain string is `.../frame/v2\0`, not `.../frame/v1\0` as originally
specified, and `object_id` is not part of this AAD (see the §8.2 correction
note on the frame/message AAD inconsistency).

Use AESGCM.encrypt/decrypt for each bounded frame. Its return value contains ciphertext plus a 16-byte tag; the wire stores them separately. These API semantics and nonce requirements are documented by [cryptography 50.0.0](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/). The underlying GCM mode is specified in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

Required framing behavior:

- Index begins at zero and increases by one. Reject duplicates, gaps, reorderings, overflow, and excessive frame count.
- plaintext_length + padding_length MUST NOT exceed chunk_size before reading the body.
- Non-final frames have length exactly chunk_size.
- A final frame for nonempty input has length 1..chunk_size.
- Empty input consists of one authenticated final frame at index zero with zero ciphertext bytes and a valid tag.
- For an exact multiple of chunk_size, mark the last full frame final; do not append a zero-length final frame.
- Reject zero-length final frames after any preceding frame.
- FINAL appears exactly once. Require actual EOF immediately afterward.
- Reject unknown flag bits, nonzero reserved bytes, wrong frame magic/version, truncation in any field, and invalid tags.
- Enforce cumulative payload and raw-size limits even when an opened file grows or its reported size is wrong.
- A valid early chunk does not authorize publishing a prefix of an incomplete file.

Writers use bounded lookahead to identify the last frame. They must never encrypt different contents or retry partially changed input with the same object key/index nonce sequence. Restarting an encryption operation creates an entirely fresh object.

For encryption of an opened regular file, verify the bytes read agree with its selected source snapshot size; if the source grows/shrinks, abort before publication. Stat checks cannot guarantee a stable snapshot against a hostile writer performing same-size changes; do not claim they can.

### 9.3 Output handling

Reuse the existing same-directory atomic publication behavior:

1. Reject unsuitable or symlinked inputs/outputs and parent components under the current path policy; inspect opened input descriptors.
2. Use owner-only temporary files and never pre-delete an existing destination.
3. Validate all tags, final framing, totals, and metadata before successful exit from the atomic writer.
4. Flush/sync before final replacement; clean up temporary plaintext on failures.
5. Treat directory sync after irreversible publication as best effort, consistently with current atomic_io.py.
6. --force authorizes final replacement only.

With an explicit destination, one verified pass can write to an unpublished temporary. With an automatic metadata-derived destination, perform a complete authentication pass without plaintext publication, determine the sanitized name, then seek on the same opened descriptor and perform a second fully authenticated pass into the atomic writer. Preserve the parsed header snapshot and verify all frames again.

The current helper's no-overwrite preflights and lexical path checks do not provide hostile-race-free publication. Do not relabel them as such; broader descriptor-relative path hardening remains separate work.

### 9.4 Encrypted restore metadata

For file metadata.policy="encrypted", the plaintext is canonical JSON with exactly:

~~~json
{
  "original_filename": "report.pdf",
  "original_size": 1234567
}
~~~

original_filename is a string of at most 255 Unicode scalar values and no more than 1,020 UTF-8 bytes. Store the source basename, not a full source path. original_size is an integer within the file limit and MUST equal the final authenticated plaintext total.

Authenticate metadata before decoding or using its content. Sanitization is a destination step: reject/remove path separators, traversal components, controls, absolute/drive/UNC syntax, and invalid platform names under a tested policy. An explicit output path overrides stored names. If restoration cannot produce a safe basename, use the deterministic input-name-plus-".dec" fallback.

For metadata.policy="hidden", omit all restore metadata rather than encrypting an empty filename. Use an explicit output or the deterministic fallback.

Hidden/encrypted metadata does not hide ciphertext length, frame count, algorithms, KDF costs, or the stable key fingerprint. Do not promise size padding, unlinkability, or anonymity.

### 9.5 Text/message container

The canonical writer emits these exact lines, LF-separated, with one final LF:

~~~text
-----BEGIN SSC MESSAGE-----
Version: 2
Type: text
Header: <one line containing standard-Base64(C(header)), padded>

<one line containing standard-Base64(ciphertext || tag), padded>
-----END SSC MESSAGE-----
~~~

> **2026-09-10 correction:** the two Base64 fields above use standard padded
> Base64 (`base64.b64encode`), not the URL-safe unpadded B64 defined in §6 —
> see the §6 correction note. This is a shipped-code exception to the general
> B64 rule, not a typo.

The header is the text schema from section 8. Body decoded length MUST equal payload.plaintext_length + 16.

~~~text
message_aad =
  b"SSC2/message/v1\0" ||
  m_context_digest ||
  decoded(object_id) ||
  U64(payload.plaintext_length)
~~~

(Only `payload_header_digest` → `m_context_digest` changed here from the
original text; the message AAD's domain string, inclusion of `object_id`,
and U64 length field are otherwise as originally specified — see the §8.2
correction note on why frames and messages ended up inconsistent on
`object_id`.)

Encrypt with K_payload and decoded(payload.nonce). Empty text still has a 16-byte authentication tag. Return UTF-8 text only after the tag verifies and strict UTF-8 decoding succeeds.

The transport parser accepts canonical LF, or uniform CRLF converted at the outer armour boundary, and permits omission of the single final line ending. Reject mixed line endings, extra lines, leading/trailing spaces, multiple blocks, duplicate armour fields, unknown fields, and content outside the block. Do not fold arbitrary whitespace in Base64. This transport rule must not be reused for the legacy six-line vault parser.

## 10. Managed identities and .ssckey files

### 10.1 Fingerprints and identity

~~~text
fingerprint_bytes =
  SHA-256(
    b"secure-string-cipher/v2/key-fingerprint/symmetric" ||
    managed_secret_32_bytes
  )

fingerprint =
  "ssc-k1-" + uppercase_RFC4648_base32_without_padding(fingerprint_bytes)
~~~

The suffix is **52 characters**. Store and compare the full fingerprint in headers, keyfiles, and vault indexes. The original 32-character suffix becomes an optional UI abbreviation only. Never accept an abbreviation as authenticated identity, silently match an ambiguous prefix, or substitute a human label for a fingerprint.

This deliberately clarifies the original full-hash/display distinction before a V2 format has shipped. Fingerprints establish key identity/self-consistency, not the trustworthiness or provenance of a supplied keyfile.

Human key IDs follow [a-z][a-z0-9._-]{0,63}. They are unique within a vault and renameable. Each registered identity also receives an immutable random record_id. Index items.keys by full fingerprint and maintain a unique human-ID lookup; renaming does not change either fingerprint or record_id.

Store only the active symmetric-key type. Reject reserved future types as unsupported. Do not serialize a "future" policy bag that implies hardware or public-key capabilities work.

### 10.2 Canonical keyfile

~~~text
-----BEGIN SSC SYMMETRIC KEY-----
Version: 1
Key-ID: laptop-backup
Type: symmetric-key
KDF: hkdf-sha256
Fingerprint: <full fingerprint>
Created: 2026-09-09T00:00:00Z

<one line containing B64 of exactly 32 random bytes>
-----END SSC SYMMETRIC KEY-----
~~~

The writer emits fixed field order, LF line endings, and a single final LF. Apply the same bounded LF/uniform-CRLF outer transport allowance as messages. Created is a valid UTC calendar timestamp in YYYY-MM-DDTHH:MM:SSZ form.

Reject malformed delimiters, repeated/unknown/missing fields, unsupported versions, alternate KDF/type values, invalid dates/IDs/fingerprints, malformed Base64, and secret lengths other than 32. Recompute the full fingerprint after decoding and reject mismatches.

Keyfiles are **plaintext bearer secrets**. The format is not encrypted, signed, or public-key encryption. The .ssckey suffix alone does not establish validity. Require regular files, reject symlinked key paths/parents, bound reads before decoding, and publish with 0600 permissions where supported. On POSIX, fail a secret-key import/read with group/other access; an explicit recovery permission override may be added only with a focused tested UX. On Windows, report the actual ACL/permission protection that has been validated rather than treating chmod as a POSIX-equivalent guarantee.

### 10.3 Storage and lifecycle

| State | New encryption | Decryption | Export |
| --- | --- | --- | --- |
| active | Allowed | Allowed | Explicit destination and warning |
| archived | Blocked | Allowed with warning | Allowed with warning |
| revoked | Blocked | Explicit --allow-revoked-key recovery only | Same explicit recovery override |
| destroyed | Blocked | No key supplied by this record | No key supplied by this record |

- external-only stores metadata and an optional path hint, never the secret in the vault.
- vault-copy stores metadata and an inner-wrapped copy. It still permits a separate external keyfile.
- A path hint is an untrusted convenience, not authorization to read arbitrary paths. Validate the selected keyfile and recompute its fingerprint.
- Destroy removes the active inner secret and leaves a tombstone. It does not erase external files, snapshots, historical vault backups, or previously exported copies.
- Revocation/archive are local application policy. An attacker or another program with the key can still decrypt old objects. Backup rollback can also restore older policy.
- A supplied external key must never silently reactivate a revoked/destroyed record or change storage mode.
- Public metadata, dataclass representations, errors, and audit events must not expose secret material.

Every key creation/export uses explicit safe destination handling; never print a .ssckey secret to stdout by default. Export of an external-only identity requires the original matching keyfile; metadata cannot regenerate a secret.

For creation with both an external file and a vault record, two resources cannot be published atomically. Prepare/validate the candidate first, publish the new external file without overwriting, then commit the vault record. If the second step fails, retain the recoverable external keyfile and report partial completion and import recovery; do not claim full success or automatically delete a potentially replaced path.

For import, preserve the supplied original file. A normal import registers external-only metadata unless --vault-copy is explicit.


## 11. Vault integration and the root-key decision

### 11.1 Why the parallel root is selected

Current PassphraseVault is not an unlocked session holding a stable root. It uses encrypt_text() and an independent Argon2-derived HMAC, with fresh encryption and HMAC salts when saving.

| Option | Assessment |
| --- | --- |
| V2VaultService derives its own root from the master password and persistent V2 salt | **Selected.** Keeps V1 crypto behavior unchanged, gives inner wrapping a stable lifetime, and confines the root to V2. Costs an additional Argon2 derivation when inner wrapping is needed. |
| PassphraseVault.export_derived_root_key() exposes a V1 key | **Rejected.** No stable V1 root exists. Exporting either existing key couples V2 to V1 internals and save-time salt changes. Creating a new V1 root would be a broader cryptographic redesign. |
| PassphraseVault exposes only a V2 domain-specific derivation/operation | Better than a raw export, but places V2 key hierarchy inside the V1 facade unnecessarily. The adapter already receives the master credential for an authorized operation. |
| Random vault master key wrapped by a password-derived KEK | A reasonable future hierarchy that can make password changes cheaper, but changes the approved direct-root approach and adds another recovery object. Defer to a separately reviewed vault redesign. |

The selected root is an **inner-wrap root**, not the outer vault encryption key or HMAC key.

~~~text
vault_root_key =
  Argon2id(exact_master_password_utf8, authenticated vault_meta.vault_kdf)

vault_copy_kek =
  HKDF(vault_root_key, vault_secret.kek_derivation.salt,
       "secure-string-cipher/v2/vault-copy/key-material-wrap/aes-256-gcm")
~~~

The inner salt is inside the encrypted document. This is not circular: the existing outer envelope contains the salts needed to authenticate/decrypt the document first; only afterward does V2 read its inner-root descriptor.

Requirements:

- Authenticate and validate the outer vault before using vault_meta.
- Derive the root lazily, at most once for an operation/session that needs inner secrets.
- Do not derive it for flat-vault reads, key metadata listing, or external-only operations that need no inner wrapping.
- Keep it in an operation-scoped secret buffer; no property/getter, root export, global cache, disk storage, repr, audit field, or keychain plaintext entry.
- Expose narrow wrapping/unwrapping operations or a scoped per-key secret handle to the V2 orchestrator.
- Release/wipe managed buffers on success, failure, cancellation, and password change. Python and library copies prevent guaranteed zeroization.
- Measure outer unlock plus inner-root cost; do not silently lower KDF costs to compensate.

This adds separation against accidental exposure/reuse of a V1 encryption key. It is not a second password, additional authentication factor, or protection from malware in the unlocked process. Offline attackers can test the master password against the outer vault; the extra inner Argon2 does not automatically multiply password-guessing cost.

### 11.2 Structured document schema

The outer six-line SSCVAULT envelope, outer HMAC, encrypted-text construction, and configured file/keychain storage remain unchanged.

Its V2 decrypted document has exactly:

~~~json
{
  "schema_version": 2,
  "vault_meta": {
    "vault_id": "<B64 of 16 bytes>",
    "revision": 1,
    "wrap_generation": 1,
    "vault_kdf": {
      "alg": "argon2id",
      "version": 19,
      "memory_kib": 65536,
      "time_cost": 3,
      "parallelism": 4,
      "hash_len": 32,
      "salt": "<B64 of 16 bytes>"
    }
  },
  "items": {
    "passphrases": {},
    "keys": {}
  }
}
~~~

revision increments on successful document mutation. wrap_generation increments only when rotating the inner root/KDF. Both are bounded positive JSON integers. They are useful for consistency and debugging, not trusted anti-rollback counters.

Write V2 document plaintext as C(document), and require that canonical spelling when reading schema 2. Preserve the historical JSON whitespace/serialization acceptance of the legacy flat document; do not retroactively impose the V2 canonical rule on released vaults.

A complete key record contains exactly:

~~~text
schema_version          integer 1
record_id               B64 of 16 random bytes, immutable
id                      unique human ID
type                    "symmetric-key"
fingerprint             full ssc-k1 fingerprint
storage                 "external-only" or "vault-copy"
status                  active / archived / revoked / destroyed
created_at              strict UTC timestamp
updated_at              strict UTC timestamp
last_used_at            strict UTC timestamp or null
public_metadata         {label: id, algorithm: "hkdf-sha256",
                         key_length: 32, format: "ssckey-v1"}
external                {path_hint: string or null}
vault_secret            null or inner-wrap container
~~~

items.keys maps full fingerprint to a record with that same fingerprint. Bound a path hint to 4,096 UTF-8 bytes; never use it without safe path validation. external-only always has vault_secret=null. A non-destroyed vault-copy record requires the inner container; a destroyed record has vault_secret=null. Records and namespaces reject duplicate keys and unsupported schema versions.

Migration copies all legacy labels and values byte-for-byte as strings into items.passphrases, even labels named "schema_version", "items", or "vault_meta". Detect a valid legacy all-string dictionary first; a string value "2" is not a schema discriminator. Do not normalize/trim legacy values during migration.

No new count limit is imposed on migrated passphrases. If adding structured overhead would exceed the existing raw-vault cap, fail without mutation and report that migration cannot fit; never truncate entries.

### 11.3 The required narrow PassphraseVault bridge

A raw write hook does not solve migration. Today, validate_raw_vault() rejects nested values, and import/restore call it both before and after publication. Bypassing it would discard existing safety guarantees.

Implement these contracts through a small shared document layer:

| Contract | Required behavior |
| --- | --- |
| Legacy validate_raw_vault(raw, password) | Preserve its flat-dictionary result and strict released-format validation |
| Full-document validation | Authenticate the same outer format, parse duplicate-free JSON, dispatch to legacy or exact V2 schema, and return a validated document |
| Authenticated document read | Read the selected backend once and return the complete authenticated document without migration |
| Atomic document update | Hold the shared writer lock, load the fresh complete document, transform it, validate/encode the candidate, back up, publish, read back, validate, and roll back on failure |
| Passphrase namespace accessor | For flat documents use the root dictionary; for schema 2 use items.passphrases |
| Structured passphrase CRUD | Mutate only items.passphrases and preserve vault_meta and every key record |
| Import/restore/backend migration | Select the full-document validator, with the same framing, bounds, snapshot, backup, verification, and rollback discipline |

Existing public passphrase methods retain their signatures and return types. Their implementation must load and save the **complete** document; taking the passphrase view and passing it to the old flat _save_vault() would erase V2 metadata/keys.

Keep one implementation of the existing outer codec. Extract only what the document bridge needs; do not introduce a second V2 outer cipher format, unrelated backend hierarchy, or root-key export. Pure structured validation may be delegated to v2/vault_schema.py; that module must not import the vault service.

The transaction layer must support trusted operation-specific candidate/read-back validation. V2 import, migration, and password change additionally verify every affected inner secret and its fingerprint before success. A schema-only pass is insufficient to prove a copied secret remains usable.

Do not store V2 state as a JSON string disguised as an ordinary passphrase entry. Older clients could list, overwrite, or delete it, and that would contradict the structured namespace contract.

### 11.4 Inner-wrap container and record AAD

~~~json
{
  "protection": "vault-wrapped",
  "wrap_alg": "aes-256-gcm",
  "kek_derivation": {"alg": "hkdf-sha256", "salt": "<B64 of 32 bytes>"},
  "nonce": "<B64 of 12 bytes>",
  "encrypted_key_material": "<B64 of 32 bytes>",
  "tag": "<B64 of 16 bytes>"
}
~~~

The exact inner context is:

~~~text
V_context = {
  schema_version: 2,
  vault_id: vault_meta.vault_id,
  wrap_generation: vault_meta.wrap_generation,
  vault_kdf: vault_meta.vault_kdf,
  record_id: record.record_id,
  key_type: record.type,
  fingerprint: record.fingerprint,
  storage: "vault-copy",
  protection: vault_secret.protection,
  wrap_alg: vault_secret.wrap_alg,
  kek_derivation: vault_secret.kek_derivation,
  nonce: vault_secret.nonce
}

vault_copy_aad = b"SSC2/vault-copy/v1\0" || H(C(V_context))
~~~

Encrypt exactly the 32-byte managed secret with vault_copy_kek and the declared nonce. After unwrap, recompute the full fingerprint and require it to match the record/index.

This binds the inner secret to the vault, root generation, immutable record, key type, and cryptographic identity. Human labels, status, timestamps, and path hints are protected by outer authentication but omitted from this inner AAD so ordinary metadata edits do not require rewrapping.

Never reuse the outer encryption salt, HMAC salt, object ID, label, or fingerprint as a substitute HKDF salt. Normal outer saves carry existing inner ciphertext unchanged. Creating/replacing an inner wrapping uses a fresh record salt and nonce.

### 11.5 Migration transaction

Read-only commands MUST NOT trigger migration. A first managed-key create/import mutation may migrate after displaying the new format and backup/downgrade consequences. Explicit ssc vault migrate-schema is also supported; keep it distinct from backend migration.

Required sequence:

1. Resolve the configured backend and acquire the writer lock.
2. Read and retain exact active raw bytes, or verified absence.
3. Authenticate a legacy document. Existing malformed/empty storage is not silently treated as an empty V2 vault.
4. If already schema 2, validate and leave it unchanged; migration is idempotent.
5. Construct the complete candidate with new vault_id/root salt, revision=1, wrap_generation=1, and an exact passphrase copy.
6. Validate the full document; encode with the existing outer cipher; enforce the encoded raw cap.
7. Authenticate/decode the candidate and check semantic equality before publication.
8. Back up exact previous raw state; a backup failure aborts the active write.
9. Recheck that active state still matches the retained snapshot; publish atomically for files.
10. Read back exact raw contents, authenticate/revalidate, and verify any created inner records.
11. If publication or verification fails, restore exact prior raw bytes/absence and verify the rollback.
12. Preserve the source and pre-mutation backup during rotation; report rollback failure as possible active-state inconsistency.

A new V2-aware binary must keep passphrase commands working after migration. An old V1 binary is **not** promised to understand schema 2; current V1 rejects it after authentication. Document this one-way active-schema change and recovery via a preserved pre-migration backup. Restoring that backup loses subsequent active records unless they were separately exported/recovered.

Before candidate encryption, calculate its outer encoded size from the bounded UTF-8 document length L: 161 + 4 × ceil((L + 76) / 3) bytes. The 76 bytes are the unchanged encrypted-text overhead; 161 accounts for fixed six-line framing, HMAC salt, and HMAC text. Reject an oversized candidate before running its encryption KDF, then check actual encoded size again. Do not discover a predictable size failure only after allocating the ciphertext.

Do not call migration "backward-compatible with old writers." Raw export can carry either encrypted document unchanged, but old clients must not be used to mutate a migrated vault.

### 11.6 Master-password and inner-KDF changes

Current main has no dedicated master-password-change API. Add the V2-aware operation as part of vault integration, rather than letting callers re-encrypt the outer document and strand all inner secrets.

The operation MUST:

1. Hold the same writer lock and authenticate the current complete document with the old password.
2. Derive the old inner root once if wrapped keys exist.
3. Sequentially unwrap and fingerprint-check every vault-copy record, discarding each plaintext secret after this validation pass.
4. Generate a new inner Argon2 salt and increment wrap_generation.
5. Derive the new inner root from the new password and descriptor if wrapped records exist.
6. Walk the records again, unwrapping one old secret, rewrapping it with fresh per-record salt/nonce and updated AAD, and wiping that plaintext before the next record.
7. Preserve vault_id, record_id, fingerprints, lifecycle states, passphrases, and external references.
8. Encode a complete candidate outer vault under the new password.
9. Validate all new inner secrets and candidate raw bytes before publication.
10. Use the shared backup, exact read-back, validation, and rollback transaction.
11. Invalidate all operation/session root and resolved-key caches after completion or failure.

No partial per-record publication is allowed. A failure must preserve the previous usable vault or clearly report rollback failure. Do not hold all unwrapped secrets in memory simultaneously.

Old backups remain encrypted under the password active when they were created. Password change does not revoke a compromised old backup, change managed secrets, or retroactively change encrypted objects. Rotation of a managed secret creates a **new identity/fingerprint**, then requires decrypting and newly encrypting affected objects if access must change.

Existing legacy vault credentials outside the new V2 input limit remain readable through the legacy path; migration must fail without mutation or be combined with an explicit supported master-password change. Never alter the legacy KDF or normalize credentials as a workaround.

### 11.7 Concurrent writers and backends

Atomic file replacement does not prevent lost read-modify-write updates. A bounded cooperative lock is a prerequisite for managed-key vault mutation, including migration, lifecycle changes, and password rotation.

- Use one stable lock identity per active vault: the absolute normalized backend path after parent-path validation for file storage, or OS user plus keychain service/entry identity for keychain storage. Do not derive the lock identity from a vault inode or revision that changes on replacement.
- Use OS-released advisory locks on a persistent owner-only lock file in a private local directory. Do not implement security using only PID files, unlinking lock files, or stale-time guesses.
- Hold the lock from the fresh active snapshot through validation, backup, publication, read-back, and any rollback.
- All V2-aware writers, including passphrase CRUD, import, restore, reset, and backend-copy operations, must cooperate.
- Backend migration acquires both identities in deterministic order, verifies the destination before changing selection, and preserves the source.
- Use a bounded 10-second acquisition timeout and a distinct "vault busy" failure; never continue unlocked or retry automatically with stale state.
- Compare exact active raw state against the snapshot before publication. This detects some noncooperative changes but is not a substitute for the lock.
- Test lock release on exceptions/process termination and real multiprocess contention on each supported OS.
- Do not claim protection from old binaries, hostile same-user processes, remote filesystems with unsuitable lock semantics, or rollback to an older valid vault.

OS keychains keep storing one encrypted blob. Their capacity may be much smaller than the application's 100 MiB raw cap. Catch capacity/availability failures without truncation or silently switching backends; verify rollback and disclose its actual result. Do not claim multi-resource or crash atomicity for native credential stores. Real credential-store validation is a separate platform release gate.

## 12. CLI mapping and user-visible behavior

### 12.1 Encryption dispatch

| Invocation shape | Result |
| --- | --- |
| Existing ssc encrypt -f PATH or -t TEXT, without --with | Existing V1 behavior |
| Existing legacy --key-file PATH without --with | Existing V1 key-file hashing behavior |
| ssc encrypt PATH without --with | New positional alias for the existing V1 file workflow |
| --with password | V2 password grant |
| --with key:ID | V2 managed-key grant |
| --with password --with key:ID --require all | V2 combined grant |
| Multiple sources without --require all | Reject |
| Duplicate sources, two managed keys, --require any, unknown selectors | Reject |
| --require all without exactly password plus one managed key | Reject |

Permit at most one input among positional file, -f, and -t. Add -o/--output to V2 encryption for explicit destinations. Default new V2 file output is input-name + ".ssc"; legacy output naming remains unchanged.

Reject ambiguous mixing of legacy --vault or legacy key-file encryption mode with new selectors. A --key-file path supplied alongside --with key:ID may only locate that managed identity and must match its full fingerprint.

The interactive menu must use the same dispatcher and validation. Preserve existing choices/defaults; expose V2 through explicit new choices. Do not silently turn existing password operations into V2.

### 12.2 Decryption dispatch and credentials

Detect format before selecting key-file semantics:

- SSCV2 -> existing supported V1 file parser.
- SSC2 -> strict V2 file parser.
- SSC MESSAGE armour -> V2 message parser.
- Existing text token -> existing V1 token parser only in the appropriate text path.
- Unknown/recognized-but-malformed input -> fail without fallback guessing.

For registered managed identities, unlock/read the catalog to enforce local status and resolve the fingerprint; use a validated path hint or explicit --key-file for external-only storage. Vault-copy requires the V2 root only when unwrapping the stored secret.

A V2 object may also be recovered using an explicitly supplied matching .ssckey on a machine without the original vault. Treat this as unregistered external-key recovery, explain that original catalog policy is unavailable, and do not silently create/import records. If a local matching record is found but cannot be unlocked or is revoked/destroyed, do not silently bypass it as "unregistered"; apply explicit recovery policy.

Prompts for an object password and a vault master password are distinct. Never substitute one automatically for the other. Parse header values as untrusted display data until authenticated; do not echo attacker-controlled control characters or paths.

New key commands must provide create, import, list, show, export, rename, archive, revoke, and destroy. Key create requires an explicit external output or a documented private configured key directory. --vault-copy is an explicit storage choice. Destroy and secret export display the selected identity and consequences; support explicit noninteractive acknowledgement without exposing secrets in arguments.

Add a dedicated vault master-password-change command as defined above. Keep vault backend migration, schema migration, and password change separate operations with clear names.

### 12.3 Errors and audit

Preserve existing exit-code meanings: 0 success, 1 input/usage, 2 authentication, 3 vault, 4 file operation. A resource-policy or unsupported-format rejection is not a wrong-password verdict. Internal corruption/wrong-key/tag/commitment failures share a generic authentication message.

A successful file operation means final publication occurred. A vault rollback failure must clearly report possible inconsistent active state and a usable backup identifier when available. An audit-write failure after publication must not misreport the encryption or vault transaction as rolled back.

Use structured allowlisted V2 events for key lifecycle, export, migration, wrapping, encryption, decryption, and recovery overrides. Record result, format version, and non-secret failure category. Omit raw secrets, ciphertext key blobs, decrypted metadata, full paths, passwords, root keys, DEKs, and fingerprints/labels by default. Optional identity metadata logging requires an explicit documented privacy setting.

Audit logs are editable local records, not evidence of cryptographic revocation or tamper-evident history. Local rate limiting does not protect copied ciphertext from offline guessing. Generic error wording does not prove constant-time execution of the whole program.


## 13. Required tests and acceptance evidence

Implement tests at the boundary where the risk occurs. Positive round trips alone are insufficient. Preserve existing tests unless a narrowly documented bridge changes their private implementation assumptions; do not weaken public compatibility assertions.

| ID | Required acceptance evidence |
| --- | --- |
| T01 — Legacy preservation | Existing V4/V5 and vault fixture hashes are unchanged; released fixtures decrypt; V4 names remain ignored and V5 names authenticated before destination use. Existing text/bytes/key-file modes and public return types remain compatible. |
| T02 — Package/value types | V2 imports without side effects; caller-owned mappings/lists cannot mutate a validated snapshot; serialization rejects non-string keys, NaN/infinity, floats, lone surrogates, and invalid enum combinations. |
| T03 — Strict header parser | Reject duplicates at every depth, unknown/missing fields, wrong types including bool-as-int, alternate canonical spellings, unsupported versions/algorithms, multiple/empty grants, illegal conditional fields, excessive nesting/nodes, and oversize headers. |
| T04 — Rejection before work | Instrument Argon2, allocation/read helpers, backend writes, and output creation. Unsupported KDF profiles, size overflows, malformed fixed prefixes, and unsupported types must fail before the corresponding expensive or mutating step. |
| T05 — Primitive/derivation vectors | RFC HKDF known answers and fixed SSC Argon2/managed/combined derivation vectors; fixed input ordering, salts, info strings, output lengths, and version=19. Changing any component changes the expected result. |
| T06 — Grant transcripts | Golden C(M_context), C(W), C(Q), AAD bytes, commitments, wrapped DEKs, and final header digests for all three grants. Wrong password, wrong key, either wrong combined component, changed KDF fields/nonces/fingerprint/policy/wrap output/commitment all reject. |
| T07 — Combined secrecy boundary | Neither component alone unwraps the DEK. No password-only commitment/verifier is emitted in the combined object. Explain the same-password/vault-copy caveat separately from cryptographic AND semantics. |
| T08 — File boundaries | Empty, one byte, chunk_size-1, chunk_size, chunk_size+1, exact multiples, maximum file size, and maximum+1. Include minimum/default/maximum legal chunk sizes and reject illegal sizes. |
| T09 — Frame adversaries | Truncation at every prefix/body/tag boundary; negative-equivalent/overflow encodings; length mismatch; unknown flags/version/magic; nonzero reserved bits; index gaps/reorder/repetition; zero intermediate frames; missing/fake/multiple final frames; trailing bytes and concatenated objects. |
| T10 — Growth and resource limits | Descriptor snapshot underreporting, source growth/shrink, cumulative raw/plaintext caps, excessive frame count, special files, and huge declared lengths. Assert oversized body reads are never issued. |
| T11 — Atomic output failures | Wrong credential, corrupt late tag, invalid final framing, metadata-size mismatch, write/flush/sync/replace failure, cancellation, and cleanup failure. Existing destination survives pre-publication failure even with --force; no partial plaintext success. |
| T12 — Metadata privacy | Wrong metadata tag/salt/nonce/policy; substitution from another object; hostile filenames, controls, Unicode, separators, drive/UNC syntax, hidden metadata, and explicit-output precedence. Authenticated original_size equals final payload count. |
| T13 — Message armour | Empty and maximum messages, maximum+1, exact text length, strict UTF-8 after authentication, Base64 padding-bit variants, malformed armour, duplicate headers, extra/mixed line endings, multiple blocks, and altered header/body/tag. |
| T14 — Keyfile validation | 32-byte secret, full fingerprint, byte-exact canonical export/import, wrong fingerprint/type/KDF/version, field injection, invalid dates/IDs, symlink/nonregular files, broad POSIX permissions, and boundary/growth reads. |
| T15 — V1/V2 vault bridge | Passphrase read/list/store/update/delete preserve the entire structured document. Raw export/import/restore/backend migration select the correct validator and preserve framing/transport contracts. Legacy-only validator still rejects nested documents. |
| T16 — Migration | Exact preservation of ordinary and reserved-looking legacy labels, empty valid legacy mapping, large passphrase namespaces, no mutation for malformed existing storage, idempotence, backup before publication, and failure/rollback injection at every transaction stage. |
| T17 — Root persistence | Repeated normal outer saves change outer salts but leave the inner descriptor and usable wrapping unchanged. Root is derived only when needed, once per operation, never returned/exported, and never logged. |
| T18 — Inner record binding | Cross-vault/record substitution, altered fingerprint, record_id, root generation, KDF metadata, nonce, salt, ciphertext, and tag fail. Rename/status/path metadata changes preserve usable inner wrapping and full outer authentication. |
| T19 — Password rotation | All inner copies work under the new password; old active password fails; old backups remain recoverable with their old passwords; failure midway through rewrapping publishes nothing; rollback and missing-secret cases are explicit. No outer-only V2 password-change path is exposed. |
| T20 — Concurrency | Real competing processes serialize; stale snapshots are rejected; locks release after exceptions/process death; timeout never falls through unlocked; backup rotation and restore protect selected/new snapshots; backend lock order cannot deadlock. |
| T21 — Lifecycle/recovery | Active/archived/revoked/destroyed matrix, export overrides, external-only secret absence, missing catalog recovery, known-record no-bypass, duplicate IDs/fingerprints, rename, tombstones, and no claim of cryptographic revocation. |
| T22 — Multi-resource creation | If external publication succeeds and vault registration fails, the external key remains recoverable, the vault rolls back, and the command reports partial completion. Import preserves its input file. |
| T23 — CLI routing | Exhaustive selector combinations, legacy key-file semantics, format distinction SSCV2 versus SSC2, no parser fallback on corrupt recognized formats, distinct password prompts, no secret command-line arguments, and preserved exit meanings. |
| T24 — Sensitive output | Logs, exceptions, repr, debug traces, CLI warnings, and secret-output guards exclude root/DEK/managed-secret material and decrypted metadata. Recovery errors contain safe categories and backup identifiers only. |
| T25 — Platform/backend behavior | Python 3.12/3.13/3.14; file/permission/newline/lock checks on Ubuntu, macOS, Windows; mocked keychain failure/rollback tests plus actual supported credential-store capacity and availability tests before claiming support. |
| T26 — Packaging/release | Locked wheel and sdist both include intended V2 modules and py.typed, preserve root API behavior, exclude private/scratch files, install separately, and pass CLI/import/version smoke tests. Versions and future tags remain coherent. |

### 13.1 Golden-fixture policy

Existing released fixtures are immutable. Add new V2 fixtures rather than regenerating old ones.

Each V2 fixture manifest records:

- This specification ID and relevant protocol version.
- Producer commit, interpreter, dependency versions, and generation procedure.
- Fixed synthetic non-secret inputs/randomness, expected plaintext, object/key identity, and every intermediate transcript required by T06.
- Exact ciphertext/armour bytes, byte lengths, and SHA-256 hashes.
- Expected success or specific safe rejection class.
- Cross-checks from a separately written test/reference calculation, not only decrypt(encrypt(x)) from the same implementation.

Fixed randomness is allowed only in fixture/test dependency injection. Production RNG failure must fail closed, never select deterministic fixture randomness.

At minimum, include files for all three grants, encrypted/hidden metadata, empty and multi-frame payloads, text messages, .ssckey, flat-to-structured vault migration, wrapped records, and password rotation. Add released-writer legacy key-file and text vectors where current fixtures only cover password files.

Property-based tests for malformed headers, armour, frames, and schema transitions are a V2.0.0 gate. Fuzzing must have explicit runtime/input budgets; do not run unbounded random KDF work.

### 13.2 Existing immutable anchors

| Evidence | SHA-256 |
| --- | --- |
| Legacy payload.bin | eb201352e0a8bfe4c333ca7ad4580932d6803164ca824ecf43a7f7f28ef84a68 |
| Released file-v4.ssc | 5e506bc990439ae8249aeae04e88a71fb1aa21c6e9fa8a7d9f9545fe0519551d |
| Released file-v5.ssc | df1f06b8f8c4861bbd950f4db8863fae18422a33aa9276295c2b68069bee9c97 |
| Decoded current-vault.enc.b64 | 7da09b6852e28060ee416d03a44d8df3c59bcad57b6e10e82d10edb44f81e16d |

The V4 producer is v1.2.10 at f7e3fc797e737ddfdd2a27d28cafec6dc5d710cb. The V5 and vault producer is v1.3.0 at f7ff04c4d5a0adc0cbdc3cb841d5048f2f14dcac. Tag object hashes are not interchangeable with these peeled commit hashes.

### 13.3 Release gates

Retain the current enforced 85% branch-coverage gate and current quality, type, sensitive-output, tracked-file secret, dependency, and OS safety checks. Add V2-specific negative coverage and protocol review; aggregate coverage is not a substitute.

Run the project's locked commands from the exact candidate checkout:

~~~bash
uv sync --extra dev --locked
uv run --locked ruff format --check src tests tools
uv run --locked ruff check src tests tools
uv run --locked mypy src
uv run --locked python tools/check_sensitive_output.py
make dependency-audit
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=term-missing --cov-fail-under=85 -n 0
make build
~~~

Also run the current tracked-file secret guard, independent wheel/sdist install smoke checks, and protected remote matrix as defined in the then-current repository. Record exact commands, versions, counts, coverage, source SHA, artifact hashes, and unresolved limitations.

Review the complete V2 transcript/commitment construction before the first interoperable release. Until then, generated V2 files are development fixtures, not a stable format promise. Do not claim resistance to all multi-key attacks from an AAD hash or a test count.

Keep Python >=3.12 and current dependency pins unless a separate verified change requires otherwise. The observed baseline pins cryptography 50.0.0 and argon2-cffi 25.1.0; open dependency PRs are not the implemented baseline.

## 14. Dependency-ordered implementation packets

Every packet must list its requirement/test IDs, exact baseline, allowed files, invariants, and evidence. Code changes belong to future authorized implementation, not this review.

| Packet | Dependencies | Deliverable and boundary |
| --- | --- | --- |
| P00 — Reconcile design | None | Refresh references; compare this specification with current main and PR #40; update architecture/roadmap plan and record explicit departures. No source behavior change. |
| P01 — Harden value types | P00 | Reapply the six-file skeleton to current main; strict types, deep immutability, canonical encoder, explicit unknown-field policy. Preserve root exports; no encryption CLI. |
| P02 — Keyfiles and parsing | P01 | Full fingerprints, strict .ssckey codec, bounded header/armour parsing, identity validation and fixtures. No implicit legacy-keyfile reinterpretation. |
| P03 — Derivation and transcripts | P01 | Argon2 profile validation, HKDF, combined input rule, DEK wrapping, commitments, metadata AEAD, exact projections, golden intermediate vectors. Internal APIs only. |
| P04 — Payloads | P02, P03 | Bounded indexed frames, text messages, complete-object authentication, safe publication, metadata restoration, and tamper/resource tests. Internal APIs only. |
| P05 — Vault bridge and locking | P01 | Narrow outer-document codec/schema dispatch, complete-document CRUD preservation, shared transactions, and cooperative locks. Preserve the legacy validator/API and outer format. Do not enable V2 migrations yet. |
| P06 — V2 vault service | P02, P03, P05 | Structured records, selected parallel root, inner wrapping, transactional migration, lifecycle, password change, import/restore integration, and recovery tests. No unvalidated partial migration. |
| P07 — CLI integration | P04, P06 | Explicit --with mapping, auto-detect decrypt, interactive parity, key lifecycle/export/recovery, safe errors/audit, and legacy compatibility. This is the first user-facing V2 encryption exposure. |
| P08 — Release readiness | All above | Update public docs/API/security claims; cross-platform and real-backend evidence; package inspection; independent transcript review; future version/release preparation. |

Do not resurrect stale copies of pyproject.toml, uv.lock, workflows, or pre-professionalisation documents when updating PR #40. Port its bounded additions, then apply this specification.

Keep version 1.3.0 during internal feature work unless a deliberate release-preparation change updates it. Target V2.0.0 coherently when the feature is accepted. Do not invent a 1.4.0 prerequisite solely to deprecate RSA utility generation.

If a requirement cannot be met, report its ID, evidence, impact, and concrete alternatives in the plan. Do not weaken the requirement silently or mark a packet complete because unrelated CI is green.

## 15. Evidence register and review limits

These are immutable source links at the reviewed commits. The conclusions above come from reading their implementations and tests, rather than accepting design prose as executable behavior.

| Evidence | Source and relevance |
| --- | --- |
| E01 — Original design | [Architecture, main](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/docs/V2_MANAGED_KEYS_ARCHITECTURE.md): sections 3/6 boundaries, 12 KDFs, 14 AAD, 15 frames, 18/19 vault, 25/26 gates |
| E02 — Actual skeleton | [envelope.py](https://github.com/TheRedTower/secure-string-cipher/blob/112eebf9ad05e59311af4581720ef552492fa86e/src/secure_string_cipher/v2/envelope.py#L54), [key_identity.py](https://github.com/TheRedTower/secure-string-cipher/blob/112eebf9ad05e59311af4581720ef552492fa86e/src/secure_string_cipher/v2/key_identity.py), [package entrypoint](https://github.com/TheRedTower/secure-string-cipher/blob/112eebf9ad05e59311af4581720ef552492fa86e/src/secure_string_cipher/v2/__init__.py): value types and serializer only |
| E03 — Flat validator | [passphrase_manager.py:205](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/passphrase_manager.py#L205): six-line framing, HMAC, decrypt, duplicate rejection, exact string values |
| E04 — Save/CRUD | [passphrase_manager.py:420](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/passphrase_manager.py#L420): fresh outer salts and flat CRUD |
| E05 — Raw transactions | [passphrase_manager.py:612](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/passphrase_manager.py#L612): raw hooks, candidate validation, backups, exact read-back, rollback, backend migration |
| E06 — Existing KDF/commitment | [core.py:304](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/core.py#L304), [config.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/config.py#L16): fixed Argon2 parameters and HMAC commitment |
| E07 — V1 payload behavior | [core.py:540](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/core.py#L540), [core.py:747](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/core.py#L747): text token and streamed V4/V5 file implementation |
| E08 — Keyfiles/RSA | [core.py:1044](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/core.py#L1044), [API.md:409](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/docs/API.md#L409), [root exports](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/__init__.py): standalone RSA utility is public, not recipient encryption |
| E09 — Publication/storage | [atomic_io.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/atomic_io.py), [keychain_backend.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/keychain_backend.py), [KEYCHAIN.md](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/docs/KEYCHAIN.md): actual helper/backend guarantees |
| E10 — Limits and rejection tests | [test_file_size_limits.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_file_size_limits.py), [test_metadata_parser.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_metadata_parser.py), [test_kdf.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_kdf.py) |
| E11 — Vault regressions | [test_vault_candidate_validation.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_vault_candidate_validation.py), [test_vault_transactions.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_vault_transactions.py), [test_vault_transport.py](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/unit/test_vault_transport.py) |
| E12 — Immutable fixtures | [legacy manifest](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/fixtures/legacy/manifest.json), [vault manifest](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/fixtures/vault/manifest.json), [legacy integration tests](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/tests/integration/test_legacy_fixtures.py) |
| E13 — Version/packaging | [pyproject.toml](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/pyproject.toml), [CHANGELOG.md](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/CHANGELOG.md), [Makefile](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/Makefile) |
| E14 — Current delivery gates | [CI](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/.github/workflows/ci.yml), [release workflow](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/.github/workflows/release.yml), [release guide](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/RELEASE.md) |
| E15 — Current limits/history | [README](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/README.md), [ROADMAP](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/ROADMAP.md), [cryptographic design](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/.github/CRYPTOGRAPHY.md), [stabilization evidence](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/docs/archive/2026/stabilization-tranche-2.md) |
| E16 — Existing CLI surface | [cli_args.py:1027](https://github.com/TheRedTower/secure-string-cipher/blob/e3d1d67a2676834fc9900cb36e1791c7ac15c626/src/secure_string_cipher/cli_args.py#L1027): current input and key-source arguments |

The source inventory included current source/test/configuration trees, package exports, KDF and key-commitment implementations, metadata/file parsers, vault/backend/atomic operations, CLI routing, fixtures, API/release/security guidance, relevant archived stabilization records, branch/tag history, and architecture/skeleton PR context. Unrelated source functions, every historical PR, all old release artifacts, live OS credential stores, and unseen local Antigravity artifacts were not claimed as exhaustively audited.

External primary references support the primitive and risk analysis. They do not endorse SSC's new protocol composition. Exact profile choices, file/resource limits, commitment transcript, vault integration, and compatibility policy above are this specification's recommendations.

## 16. Required Antigravity response before implementation

Use this document to replace/refine the existing implementation plan. Produce a plan that contains:

1. The refreshed main/head SHAs and a delta from this review snapshot.
2. A disposition for every Gemini refinement and D01–D14.
3. A requirement-to-packet mapping covering sections 4–12 and T01–T26.
4. The concrete outer-vault document bridge and shared-lock design, including all existing public passphrase/import/restore callers affected.
5. Exact proposed schemas, binary constants, canonical projections, and golden-fixture layout matching this specification.
6. A dependency-ordered PR/commit sequence with allowed files and explicit preservation of current-main changes.
7. Validation commands and evidence required per packet; separate implemented, tested, historical, and unverified claims.
8. A recovery and downgrade procedure covering schema migration, password change, failed publication, backups, and external key copies.
9. Any remaining conflict stated with its requirement ID and a concrete alternative, rather than silent assumptions.

Do not begin by exporting a V1 derived key, weakening the flat validator, widening legacy file limits, changing current Argon2 constants, rewriting core.py, removing generate_key_pair(), or treating the V2 skeleton's current passing tests as protocol acceptance.

The implementation is ready for release consideration only when the requirements, fixtures, failure behavior, packaging, platform results, and cryptographic review support the claim. This document itself is the review deliverable; no source code, repository branch, tag, or release was modified to produce it.
