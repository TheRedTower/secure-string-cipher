# SSC2 Container Format — Protocol Specification

**Status:** Draft v1, extracted from and cross-checked against the shipped
Python reference implementation (`secure_string_cipher.v2`) as of package
release `v2.0.0`.
**Audience:** Anyone implementing a second, independent encoder/decoder for
the `.ssc` v2 container format, or reviewing its cryptographic design
without reading Python.
**Relationship to other v2 documents:** [`SSC_V2_REFINED_IMPLEMENTATION_SPEC.md`](SSC_V2_REFINED_IMPLEMENTATION_SPEC.md)
is this format's design-decision record — it explains *why* choices were
made, documents corrections made during implementation, and includes
Python-specific implementation guidance. This document is the normative,
implementation-language-neutral wire format extracted from it. Where the
two ever disagree, treat this document and the shipped code
(`src/secure_string_cipher/v2/`) as authoritative — the implementation
spec is a historical decision record, not itself the protocol definition.
**Verification:** Every claim below was checked directly against
`src/secure_string_cipher/v2/{envelope,header_parser,kdf,keywrap,payload,message,keyfile}.py`
at the time this document was written, not copied forward from the
implementation spec without re-checking.

## 1. Scope

This document defines the wire format for:

- the `.ssc` binary file container (magic, header, chunked frames);
- the ASCII-armoured text/message container;
- the `.ssckey` managed symmetric key file;
- the cryptographic key hierarchy, KDF parameters, and AAD/transcript
  construction that both containers depend on.

**Out of scope**, deliberately: the vault's internal storage schema for
managed-key records (`V2VaultService`'s document format), CLI syntax, and
key-lifecycle *enforcement* policy (what a client chooses to do when a key
is marked archived/revoked/destroyed). None of that is exchanged between
parties or needs to interoperate across implementations — it is this
application's own bookkeeping. A future revision of this document may add
an appendix on vault-copy key export/import if that ever needs to
interoperate across implementations; today it does not.

## 2. Conventions and encodings

```text
U16(n) = unsigned 2-byte little-endian representation
U32(n) = unsigned 4-byte little-endian representation
U64(n) = unsigned 8-byte little-endian representation
B64(x) = RFC 4648 URL-safe Base64, no "=" padding, no whitespace
H(x)   = SHA-256(x), raw 32-byte output
C(x)   = SSC canonical JSON bytes (defined below)
||     = byte concatenation, never text concatenation
```

All multi-byte integers on the wire are **little-endian**.

`B64` decoding MUST check the alphabet, expected encoded/decoded lengths,
unused padding bits, and that `encode(decode(value)) == value`. It MUST NOT
accept standard Base64's `+`/`/` alphabet. `B64` governs every header field
that is Base64 at all (salts, nonces, wrapped DEK, tags, commitment
values, object IDs) **and** the `.ssckey` secret body (§9.2). **Exception:**
the text/message armour transport (§7) uses standard *padded* Base64
(`+`/`/` alphabet, `=` padding) instead — this is a real, shipped
inconsistency between subsystems, not a typo; an implementation must use
the correct alphabet for the field it is decoding. **`key_fingerprint` is
not Base64 at all** — see §9.1's distinct `ssc-k1-`-prefixed Base32 form;
do not attempt to `B64`-decode it.

### 2.1 Canonical JSON

```text
canonical_json(obj) =
  UTF-8 bytes of a JSON serialization of obj where:
    - object keys are sorted (byte-wise ascending)
    - separators are "," and ":" with no extra whitespace
    - non-ASCII characters are emitted literally, not \uXXXX-escaped
    - NaN/Infinity are forbidden (the object must not contain them)
```

This is a restricted profile, not a complete [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
JCS implementation (no special numeric formatting rules). An implementation
must own an immutable, already-validated copy of a JSON value before
computing `C(value)` over it — a parser must not compute a digest over a
value that a concurrent caller could still mutate.

All header field names are fixed ASCII strings. A parser MUST reject
unknown fields, missing required fields, duplicate keys at any nesting
level, wrong JSON types, non-UTF-8 header bytes, byte-order marks, lone
UTF-16 surrogates, non-finite numbers, and floats where an integer is
required. JSON integers must be JSON number tokens with no fractional or
exponent part (not booleans), in range `0..2^53-1` unless a field specifies
a narrower range. `null` is accepted only where a field explicitly allows
it (no field currently does).

## 3. Resource limits

MiB = 1,048,576 bytes; KiB = 1,024 bytes. These are application-level
limits enforced by both writers and readers, not mathematical AES-GCM
maxima. A reader MUST enforce a limit before allocating or reading a
resource it bounds, not only after the fact (e.g. reject an oversized
declared header length before reading that many bytes).

| Quantity | Limit |
| --- | --- |
| Plaintext file size | 0 to 104,857,600 bytes (100 MiB) inclusive |
| Chunk size | One of 65,536; 131,072; 262,144; 524,288; 1,048,576; 2,097,152; 4,194,304 bytes |
| Default chunk size | 65,536 bytes (64 KiB) |
| Maximum frames per file | `max(1, ceil(104,857,600 / chunk_size))` — enforced by the reader from the object's own header `chunk_size`, independent of any declared/stored size |
| Canonical protected header | 1 to 65,536 bytes |
| Metadata plaintext (decrypted) | At most 4,096 bytes |
| Text/message plaintext | At most 1,048,576 UTF-8 bytes |
| `.ssckey` armour | At most 8,192 bytes; decoded secret exactly 32 bytes |
| Header JSON structure | At most 16 container levels deep, 1,024 total members/elements |
| Per-frame plaintext | At most 4 MiB (bounded by the chunk-size allowlist above) |

A reader must enforce the frame-count and cumulative-plaintext-byte caps
per frame, before reading that frame's ciphertext body — not only after
consuming the whole stream — so a crafted container cannot force
unbounded work by lying about its own size.

## 4. Key hierarchy and KDFs

### 4.1 Randomness

All of the following use a CSPRNG (the reference implementation uses
Python's `secrets.token_bytes`):

| Value | Size |
| --- | --- |
| Managed secret (`.ssckey`) | 32 bytes |
| Object DEK | 32 fresh bytes per object |
| Object ID | 16 bytes |
| Argon2id salt | 16 bytes |
| Every HKDF descriptor salt | 32 bytes, freshly generated per derivation instance |
| Single-shot GCM nonce (text/message) | 12 bytes |
| File frame nonce prefix | 4 bytes (combined with a per-frame counter — see §6) |
| AES-GCM tag | 16 bytes, never truncated |

Re-deriving an existing key MUST reuse its stored salt; a fresh salt is
only for a new derivation instance.

### 4.2 Argon2id parameters

The password KDF descriptor is exactly:

```json
{
  "alg": "argon2id",
  "version": 19,
  "memory_kib": 65536,
  "time_cost": 3,
  "parallelism": 4,
  "hash_len": 32,
  "salt": "<B64 of 16 bytes>"
}
```

These parameters are **exact required values, not a minimum/maximum
range** — a parser MUST reject any header whose Argon2id descriptor
deviates from this exact tuple (this is stricter than a generic
minimum/maximum KDF-cost policy, and is what the shipped parser actually
does). This tuple matches the memory-constrained recommendation in
[RFC 9106 §4](https://www.rfc-editor.org/rfc/rfc9106). Password text is
encoded as exact UTF-8 with no normalization, trimming, or case-folding.

### 4.3 Derivations

`HKDF` denotes [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
HKDF-SHA256 (extract + expand), producing 32 bytes. Info strings below are
literal ASCII constants — never derived from untrusted header input.

Let `P = Argon2id(password, password_kdf)` and `K` = the decoded 32-byte
managed secret.

```text
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
```

`P` and `M` are each exactly 32 bytes; `P || M` is exactly 64 bytes in that
order (never XOR, hex-string, or plain text concatenation). **The combined
grant is not independent two-factor authentication**: if an attacker can
recover the managed key from a vault unlocked with the same password, they
can supply both inputs from one compromise.

### 4.4 Key commitment

Plain AES-GCM authentication does not by itself imply key commitment (see
[Albertini et al., 2020](https://eprint.iacr.org/2020/1456)). Every v2
grant therefore carries an explicit HMAC commitment:

```json
{
  "commitment": {
    "alg": "hmac-sha256",
    "kdf": {"alg": "hkdf-sha256", "salt": "<B64 of 32 bytes>"},
    "value": "<B64 of 32 bytes>"
  }
}
```

`commitment.value` is computed over the transcript defined in §5, using
`K_commit` (a key independent of the AES wrapping key `KEK`). A reader
MUST verify it with constant-time comparison **before** attempting to
unwrap the DEK.

## 5. Header schema and authentication transcript

### 5.1 Top-level header

```text
format       "SSC2"
version      2
object_id    B64 of 16 bytes
object_type  "file" | "text"
payload      <payload descriptor>
access       <access block>
metadata     <hidden or encrypted metadata container>
```

**Payload descriptor** common fields: `type` (= `object_type`), `alg`
(= `"aes-256-gcm"`), `kdf` (= `{"alg":"hkdf-sha256","salt":B64(32 bytes)}`),
`metadata_policy` (= `metadata.policy`).

- `object_type = "file"` additionally requires `chunk_size` (one of §3's
  allowlist) and `nonce_prefix` (`B64` of 4 bytes); forbids text-only
  fields.
- `object_type = "text"` additionally requires `nonce` (`B64` of 12 bytes)
  and `plaintext_length` (integer, `0..1,048,576`); forbids `chunk_size`
  and `nonce_prefix`.

**Access block**: exactly `version = 1`, `policy = "single-grant"`,
`grants = [<exactly one grant>]`. **There is no multi-grant access control
in this format version** — that is a v3 concern, not this one.

**Grant** common fields: `grant_id` (any string; the reference writer
always emits `"grant-0"`, but this is writer convention, not a
parser-enforced value — the single grant is consumed positionally, and a
reader MUST NOT reject a header whose `grant_id` differs), `type`
(`"password"` | `"managed-key"` | `"combined-password-managed-key"`),
`kek_derivation` (HKDF descriptor, 32-byte salt), `wrap_alg`
(= `"aes-256-gcm"`), `wrap_nonce` (`B64` of 12 bytes), `wrapped_dek`
(`B64` of exactly 32 bytes), `tag` (`B64` of exactly 16 bytes),
`commitment` (§4.4). `password_kdf` is required only for `password`/
`combined-password-managed-key` grants; `key_fingerprint` only for
`managed-key`/`combined-password-managed-key`; `combined_kdf` (exactly
`alg="hkdf-sha256"`, `salt`, `managed_key_salt`, both `B64` of 32 bytes)
only for combined grants. Fields not applicable to a grant type MUST be
absent, never present-as-`null`.

**Metadata container**: `{"policy": "hidden"}` exactly, or
`{"policy": "encrypted", "alg": "aes-256-gcm", "kdf": <descriptor>,
"nonce": B64(12 bytes), "ciphertext": B64(...), "tag": B64(16 bytes)}`.
A reader MUST enforce the 4,096-byte metadata-plaintext limit before
decoding `ciphertext`.

A parser MUST reject any field not listed above at any level (no
"unknown fields are ignored" compatibility mode exists in this version).

### 5.2 Construction order and projections

A *projection* is an exact deep copy of the header with only the listed
fields omitted — not an implementation's informal idea of "the important
fields."

```text
M_context = {
  format, version, object_id, object_type, payload,
  metadata: metadata container with only ciphertext and tag omitted
}
metadata_aad = b"SSC2/metadata/v1\0" || H(C(M_context))

W = complete header with only these fields omitted:
  access.grants[0].wrapped_dek
  access.grants[0].tag
  access.grants[0].commitment.value
wrap_aad = b"SSC2/wrap/v1\0" || H(C(W))

Q = complete header with only access.grants[0].commitment.value omitted
commitment.value = B64(HMAC-SHA256(K_commit, b"SSC2/commit/v1\0" || H(C(Q))))

m_context_digest = H(C(M_context))
```

**`m_context_digest` — not a digest of the complete header — is what
authenticates every payload frame (§6) and the text message (§7).**
Because `M_context` excludes `access` entirely, changing the access grant
on an object does **not** change the payload-layer AAD. This does not by
itself let an attacker decrypt anything (the grant is still bound to the
*complete* header via `wrap_aad`/`commitment`, both of which project the
full header, so a substituted grant cannot unwrap the original DEK) — but
the payload layer alone cannot detect a grant substitution. Treat this as
a real, current property of the format, not an oversight to silently
"fix" in a compatible way: doing so would require a new header/payload
version.

**The frame AAD (§6) and message AAD (§7) are inconsistent with each
other**: the message AAD includes the decoded `object_id`; the frame AAD
does not. An implementation must match each construction exactly as
specified in its own section — do not assume symmetry between them.

Writer order: validate inputs and generate all random values → encrypt
metadata (if `policy = "encrypted"`) using `metadata_aad` → derive the
grant's `R`/`KEK`/`K_commit` → wrap the DEK under `AESGCM(KEK)` with
`wrap_nonce`/`wrap_aad`, splitting the 48-byte result into 32-byte
`wrapped_dek` + 16-byte `tag` → compute `commitment.value` → freeze the
final header and compute `C(header)` once → encrypt the payload.

Reader order: bound and parse the header under strict schema/type/
canonical checks → validate KDF/resource limits → derive keys, verify
`commitment.value` (constant-time), unwrap the DEK using the same `W`
projection → authenticate/decrypt metadata using `metadata_aad` →
authenticate every frame (or the whole message) → validate declared
metadata against the actual authenticated plaintext total → publish
plaintext only after every check succeeds.

### 5.3 No in-place rewrapping

This format version does not support changing an object's access grant in
place. There is no mechanism to "rewrap" a DEK under a new KEK while
preserving the ciphertext payload and simply recomputing a tag under a
reused key/nonce pair — that would violate AES-GCM's nonce-reuse
requirements. To change access, decrypt fully and produce an entirely new
object (new DEK, object ID, salts, nonces).

## 6. File container and frame format

```text
magic              4 bytes: ASCII "SSC2"
header_length      U32(len(C(header)))
protected_header   exactly header_length canonical UTF-8 bytes
frames             one or more frames, ending in exactly one FINAL frame
EOF                immediately after the final frame's tag
```

No byte-order mark, line ending, trailing padding, or appended data after
the final frame's tag is permitted.

### 6.1 Frame wire format

```text
frame_magic         4 bytes: ASCII "S2FR"
chunk_index         U64(index)
plaintext_length    U32(n)
padding_length      U16(n)
flags               1 byte: 0x00, or 0x01 (FINAL)
ciphertext          (plaintext_length + padding_length) bytes
tag                 16 bytes
```

Fixed prefix: 19 bytes (`4 + 8 + 4 + 2 + 1`). Per-frame overhead: 35 bytes
(19-byte prefix + 16-byte tag). Non-final frames pad plaintext up to
`chunk_size` with random bytes (`padding_length = chunk_size -
plaintext_length`); the final frame may have `padding_length = 0`.
`ciphertext`'s length is derived (`plaintext_length + padding_length`),
never a separately transmitted field.

```text
nonce = decoded(payload.nonce_prefix) || U64(chunk_index)

frame_aad =
  b"SSC2/frame/v2\0" ||
  m_context_digest ||
  U64(chunk_index) ||
  U32(plaintext_length) ||
  U16(padding_length) ||
  flags
```

Required reader behavior:

- Frame index starts at 0 and increases by exactly 1 per frame. Reject
  duplicate, skipped, reordered, or overflowing indices.
- `plaintext_length + padding_length` MUST NOT exceed `chunk_size`,
  checked before reading the ciphertext body.
- Non-final frames MUST have length exactly `chunk_size`.
- The final frame for non-empty input has length `1..chunk_size`.
- Empty input is exactly one FINAL frame at index 0 with zero ciphertext
  bytes and a valid tag (never zero frames).
- Reject a zero-length final frame that follows any preceding frame (an
  exact multiple of `chunk_size` must mark its last full frame FINAL
  rather than appending an empty one).
- `FINAL` (flag `0x01`) appears exactly once, on the last frame; any other
  flag bit set is a hard reject.
- The stream MUST reach exact EOF immediately after the FINAL frame's tag
  — any trailing byte (including a second FINAL frame) is a hard reject.
- Enforce the cumulative frame-count and plaintext-byte caps from §3
  before reading each frame's ciphertext body, independent of any
  declared/stored file size.

## 7. Text/message container

ASCII-armoured transport, LF line endings, one trailing LF:

```text
-----BEGIN SSC MESSAGE-----
Version: 2
Type: text
Header: <one line: standard padded Base64 of C(header)>

<one line: standard padded Base64 of ciphertext || tag>
-----END SSC MESSAGE-----
```

Both Base64 fields here use the **standard padded alphabet**
(`base64.b64encode` in the reference implementation), not the `B64` from
§2 — see §2's note on this exception. The header is the `object_type =
"text"` schema from §5.1; decoded body length MUST equal
`payload.plaintext_length + 16` (the AEAD tag).

```text
message_aad =
  b"SSC2/message/v1\0" ||
  m_context_digest ||
  decoded(object_id) ||
  U64(payload.plaintext_length)
```

Encrypt with `K_payload` and `decoded(payload.nonce)`. Empty text still
produces a 16-byte tag. A reader returns plaintext only after the tag
verifies and the result strictly decodes as UTF-8.

Transport parsing accepts canonical LF or uniform CRLF (normalized at the
armour boundary), and permits omitting the single final line ending.
Reject mixed line endings, extra lines, leading/trailing whitespace,
multiple armour blocks, duplicate or unknown armour fields, and any
content outside the block. Do not fold arbitrary whitespace inside a
Base64 field.

## 8. Encrypted restore metadata

When `metadata.policy = "encrypted"` on a file object, the decrypted
plaintext is canonical JSON with exactly:

```json
{
  "original_filename": "report.pdf",
  "original_size": 1234567
}
```

`original_filename`: at most 255 Unicode scalar values and 1,020 UTF-8
bytes; the source **basename** only, never a full path. `original_size`:
an integer within the file-size limit (§3) that MUST equal the actual
authenticated plaintext total — a reader must verify this, not trust the
stored value blindly. Metadata MUST be authenticated before any of its
fields are decoded or acted on. Destination-side filename sanitization
(rejecting path separators, traversal components, control characters,
absolute paths, and platform-reserved names) is an implementation
responsibility, not something this document can make portable across
operating systems.

`metadata.policy = "hidden"` carries no restore metadata at all (not an
encrypted-then-omitted filename).

**Hidden/encrypted metadata does not hide** ciphertext length, frame
count, algorithm identifiers, KDF cost parameters, or the managed-key
fingerprint (when present) — none of that is metadata-protected, all of
it is visible in the plaintext header. Do not describe this format as
providing size padding, unlinkability, or object anonymity.

## 9. `.ssckey` managed key file

### 9.1 Fingerprint

```text
fingerprint_bytes =
  SHA-256(
    b"secure-string-cipher/v2/key-fingerprint/symmetric" ||
    managed_secret_32_bytes
  )

fingerprint =
  "ssc-k1-" + uppercase_RFC4648_base32_without_padding(fingerprint_bytes)
```

The full fingerprint is exactly **59 characters**: the 7-character
`ssc-k1-` prefix plus 52 characters of unpadded Base32 (a 32-byte/256-bit
digest encodes to `ceil(256/5) = 52` Base32 characters). This exact length
is enforced by the reference implementation
(`key_identity.py`/`header_parser.py`). The full fingerprint — never an
abbreviation or prefix — is what
gets stored and compared in headers, keyfiles, and any index. A
fingerprint establishes a key's self-consistency (does this keyfile's
bytes match this claimed identity), not the trustworthiness or provenance
of a keyfile someone hands you.

### 9.2 File format

```text
-----BEGIN SSC SYMMETRIC KEY-----
Version: 1
Key-ID: laptop-backup
Type: symmetric-key
KDF: hkdf-sha256
Fingerprint: <full 59-character fingerprint>
Created: 2026-09-09T00:00:00Z

<one line: B64 (§2, URL-safe unpadded) of exactly 32 random bytes>
-----END SSC SYMMETRIC KEY-----
```

Fixed field order, LF line endings, one trailing LF; the same bounded
LF/uniform-CRLF transport allowance as §7 applies. `Created` is a UTC
calendar timestamp in `YYYY-MM-DDTHH:MM:SSZ` form. A reader MUST
recompute the fingerprint from the decoded secret and reject any file
where it does not match the `Fingerprint:` field, and MUST reject
malformed delimiters, unknown/missing/repeated fields, an unsupported
`Version`/`Type`/`KDF` value, an invalid `Key-ID` (pattern
`[a-z][a-z0-9._-]{0,63}`), an invalid `Created` timestamp, malformed
Base64, or a decoded secret length other than 32 bytes.

**A `.ssckey` file is a plaintext bearer secret** — this format applies no
encryption, signing, or access control of its own. The `.ssckey` file
extension carries no authority; only content validation does. An
implementation should require the path to be a regular file (reject
symlinked keyfiles and symlinked parent directories), bound how many bytes
it reads before attempting to decode them, and publish newly-created
keyfiles with owner-only permissions where the platform supports it.

## 10. Explicitly out of scope for interoperability

- **Vault storage schema.** How `V2VaultService` persists key records
  (metadata, wrapped vault-copy secrets, lifecycle state) inside the
  encrypted vault document is this application's own bookkeeping. It is
  never transmitted to, or expected to be read by, another implementation.
- **Key-lifecycle enforcement policy.** What a client does when a key is
  marked `archived`/`revoked`/`destroyed` (whether it blocks use, requires
  an extra flag, etc.) is local application policy, not a wire-format
  concern — and is currently opt-in in the reference implementation
  (enforced only when a vault is explicitly consulted via `--vault`),
  not a property every implementation of this format must replicate.
- **CLI syntax and error message text.**

## 11. Known non-goals of this format version

Recorded here as normative facts about what v2.0.0 *is*, not a to-do list:

- Exactly one access grant per object (no multi-grant, no `any-of`/`all-of`
  policy). That is v3 design space.
- No in-place grant rewrapping (§5.3).
- The combined password+managed-key grant is not independent two-factor
  authentication if both secrets are recoverable from one compromised
  vault (§4.3).
- Metadata protection does not hide object size, frame count, algorithm
  identifiers, or KDF cost (§8).
- The frame AAD and message AAD are asymmetric in whether they include
  `object_id` (§5.2, §6.1, §7) — implementations must match each
  construction exactly rather than assuming consistency between them.

## 12. Change history

- **Draft v1** (this document): extracted from
  `SSC_V2_REFINED_IMPLEMENTATION_SPEC.md` and independently re-verified
  against `src/secure_string_cipher/v2/` as it stood at package release
  `v2.0.0`, as part of the post-v2 hardening review. Several claims in the
  implementation spec's own §10.3 (a `--allow-revoked-key` recovery
  override, an `archived` state blocking new encryption) describe an
  earlier design intent that was not what shipped; this document describes
  only verified, currently-shipped behavior and omits that table rather
  than propagate it.
