# SSC 3.0 file format

Status: **draft for review** (Phase 1, step 1). Nothing here is frozen until
the Phase 1 gate: review comments answered and test vectors frozen.

This document defines the container an `.ssc` file uses: the fixed header, the
access block's framing and MAC, and the payload. What goes *inside* the access
block (factors, grants, and how each grant wraps the file key) is defined by
the access spec, Phase 1, step 2. That spec is the part posted for community
review.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Design goals

1. **The payload never depends on who has access.** The payload is
   authenticated by the file key and the fixed header only. Grants can be
   added or removed by rewriting the access block alone, without
   re-encrypting the payload.
2. **The access block authenticates itself.** A MAC keyed from the file key
   covers the access block and the fixed header. Only someone who can already
   open the file can produce a valid access block for it.
3. **A plain, boring payload.** 64 KiB chunks, AES-256-GCM, a counter nonce
   with a last-chunk flag. A stream that ends without a valid final chunk is
   rejected.
4. **Strict parsing.** Each file has exactly one valid encoding. Anything
   else, including trailing bytes, unknown versions and out-of-range lengths,
   is rejected.

These follow the [age format](https://github.com/C2SP/C2SP/blob/main/age.md),
which uses the same separation between header and payload.

## 2. Notation and primitives

- `||` is byte concatenation. `"text"` is the ASCII bytes of `text`, with no
  terminator.
- `u32be(n)` is `n` as 4 bytes, big-endian. `u88be(n)` is `n` as 11 bytes,
  big-endian.
- `HKDF(ikm, salt, info)` is HKDF-SHA256 (RFC 5869) with a 32-byte output. An
  empty `salt` means the RFC's default of 32 zero bytes.
- `HMAC(key, msg)` is HMAC-SHA256, 32 bytes.
- `AES-GCM-Seal(key, nonce, plaintext)` is AES-256-GCM with a 12-byte nonce,
  empty associated data, and a 16-byte tag appended to the ciphertext.
- All random values come from the operating system's CSPRNG (Python's
  `secrets` module).

## 3. Keys

| Key | Size | Derivation |
| --- | --- | --- |
| `file_key` | 32 bytes | Random, generated once per file. Replaced only by rotation (section 7.3). |
| `mac_key` | 32 bytes | `HKDF(file_key, "", "ssc3/access-mac")` |
| `payload_key` | 32 bytes | `HKDF(file_key, payload_nonce, "ssc3/payload-key" \|\| fixed_header)` |

`file_key` never appears in the file. Each grant in the access block wraps it
separately, as defined by the access spec. `mac_key` and `payload_key` are
independent keys derived from it under different labels.

## 4. File layout

```text
offset    size     field
0         8        magic            89 53 53 43 0D 0A 1A 0A
8         1        version          0x01
9         16       payload_nonce    random
--------------------------------    fixed_header = bytes 0..24 (25 bytes)
25        4        access_length    u32be(n), 1 <= n <= 65,536
29        n        access_body      defined by the access spec
29+n      32       access_mac       HMAC(mac_key, fixed_header || access_length || access_body)
61+n      ...      payload          one or more chunks (section 6)
```

### 4.1 Magic

The 8-byte magic is `\x89SSC\r\n\x1a\n`. As with PNG, the high-bit first byte
and the CR LF, SUB and LF bytes expose a file that was damaged by text-mode
transfer or line-ending conversion. SSC recognises its files by these bytes,
never by the `.ssc` extension.

### 4.2 Version

This document defines version `0x01`. A reader MUST reject any other value. A
future incompatible format uses a new version number; there is no in-band
negotiation and no flags field.

### 4.3 Payload nonce

16 random bytes. A writer MUST generate a fresh `payload_nonce` **every time
it writes a payload**: on encryption, on rotation, and when it replaces the
payload under the same file key (section 7.4). Since `payload_key` is
derived from it, each payload gets its own key, and the counter nonces of
section 6 are never reused under one key. Rewriting only the access block
leaves the payload bytes, and so `payload_nonce`, unchanged.

### 4.4 Access block

`access_length` is the length of `access_body` only, not counting
`access_mac`. A reader MUST check `1 <= n <= 65,536` before reading or
allocating `access_body`. The 64 KiB cap is far above what 3.0 needs, since a
3 of 5 threshold policy is only 10 grants. The cap exists so that a crafted
length cannot force a large allocation.

This document treats `access_body` as opaque bytes. The access spec defines
its encoding, which MUST itself be canonical.

`access_mac` is computed over the fixed header, the length field and the
body. Including the fixed header binds the access block to this file's
payload nonce, so an access block cannot be moved onto another file, even
one that shares the same file key.

## 5. Why the MAC also commits to the key

AES-GCM is not key-committing: one ciphertext can be made to decrypt validly
under two different keys. HMAC-SHA256 is committing in practice. Because a
reader verifies `access_mac` (section 7.2) before it decrypts any payload, a
file key recovered from a grant is confirmed as *the* file key for this file
before it is used. A grant that unwraps to a different key, whether by
accident or by construction, fails at the MAC and is never used to decrypt.

## 6. Payload

The plaintext is split into chunks of exactly 65,536 bytes. The last chunk
holds the remainder, which is 1 to 65,536 bytes. Empty plaintext is a single
empty final chunk.

Chunk `i`, counting from 0, is encrypted as:

```text
nonce_i      = u88be(i) || last_flag     (12 bytes; last_flag is 0x01 for the final chunk, 0x00 otherwise)
chunk_ct_i   = AES-GCM-Seal(payload_key, nonce_i, chunk_plaintext_i)
```

The payload is the concatenation of every `chunk_ct_i`. Chunk boundaries are
implicit: each non-final chunk is exactly 65,552 bytes on disk (65,536 plus
the 16-byte tag), and the final chunk is 16 to 65,552 bytes.

Rules for writers and readers:

- A plaintext that is an exact multiple of 65,536 bytes ends with a full
  final chunk. It never ends with an extra empty chunk.
- An empty final chunk is valid only as chunk 0, which means the plaintext
  is empty.
- A reader treats a chunk as final exactly when the file ends immediately
  after it. It MUST decrypt that chunk with `last_flag = 0x01`, and every
  other chunk with `0x00`.
  - A file truncated at a chunk boundary therefore fails, because its new
    last chunk was sealed as non-final.
  - A file with bytes appended fails, because its real final chunk is no
    longer last.
- A payload shorter than 16 bytes, or a trailing partial chunk under 16
  bytes, is rejected.
- Writers MUST NOT write more than 2^32 chunks (256 TiB) under one payload
  key. This keeps AES-GCM well inside its per-key limits. Readers MUST
  reject a payload that reaches chunk index 2^32.

The format sets no smaller size limit. An implementation MAY impose one, and
MUST then enforce it while streaming, before reading each chunk.

## 7. Operations

### 7.1 Encrypt

1. Generate `file_key` and `payload_nonce`.
2. Build `access_body` from the requested grants (access spec).
3. Compute `access_mac`.
4. Write the header and access block, then the payload chunks.

### 7.2 Decrypt

A reader MUST follow this order:

1. Read and check the magic and version.
2. Read `payload_nonce` and `access_length`, check the length range, then
   read `access_body` and `access_mac`.
3. Parse `access_body` strictly (access spec). Reject it before trying any
   grant if it does not parse.
4. For each grant the caller has factors for, unwrap a candidate `file_key`.
   Derive `mac_key` from it and compare `access_mac` in constant time. Stop
   at the first candidate that verifies. If none verifies, fail with a
   single error that does not say which grant or factor was wrong.
5. Derive `payload_key` and decrypt the chunks in order, following section 6.

Because the payload is streamed, chunks are authenticated one at a time, and
a reader sees early plaintext before it knows the file is complete. A reader
MUST NOT treat output as valid until the final chunk has verified. The CLI
writes to a temporary file and renames it into place only after success. It
removes the temporary file on any failure.

### 7.3 Change access

- **Add a grant:** open the file (section 7.2, steps 1 to 4) to recover
  `file_key`. Build the new `access_body` with the extra grant and recompute
  `access_mac`. Write the new header and access block, followed by the
  unchanged payload bytes. Only someone who can open the file can add a
  grant, because the MAC needs `file_key`.
- **Remove a grant:** the same, without that grant. The file key and payload
  are unchanged, so anyone who saw the file key before, or kept an old copy,
  can still open the old copy. **Removing a grant is not revocation.**
- **Rotate:** generate a new `file_key` and `payload_nonce`, re-encrypt the
  whole payload, and rewrap every grant that is kept. This is the only
  operation that stops a previously known file key from opening the new
  file. It does nothing about old copies.

### 7.4 Replace the payload

This is used for an object whose contents change while its access stays the
same, such as the vault. Open the file to recover `file_key`, generate a
**new** `payload_nonce`, encrypt the new contents, and recompute
`access_mac`. That recomputation is needed because `payload_nonce` is part
of the fixed header the MAC covers. The grants are kept byte for byte.

Reusing the old `payload_nonce` here would encrypt different plaintext under
the same key and nonces, which breaks AES-GCM completely. Writers MUST NOT
do it.

### 7.5 Writing safely

Every rewrite goes to a temporary file in the same directory, which is then
renamed over the original, so a failure never leaves a half-written file.

## 8. Armoured form

An SSC file MAY be carried as text. The armoured form is the complete binary
file, from magic to final chunk, encoded with standard padded Base64 (RFC
4648 section 4):

```text
-----BEGIN SSC MESSAGE-----
<Base64, 64 characters per line; the last line holds 1 to 64 characters>
-----END SSC MESSAGE-----
```

Rules:

- Lines end in LF. A reader also accepts CRLF, but only if every line uses
  it. It rejects mixed line endings.
- The END line MAY be followed by one line ending and nothing else.
- Base64 MUST be canonical. That means no whitespace inside a line, no line
  longer than 64 characters, no short line except the last, correct padding,
  and zero unused bits.
- A reader rejects anything before BEGIN or after END, and more than one
  block.
- After decoding, the bytes are parsed exactly as a binary file.

A reader detects the form from the first bytes: the magic means binary, and
`-----BEGIN SSC MESSAGE-----` means armoured. Anything else is rejected.

## 9. What the format does not hide

The following are visible to anyone with the file: the format version, the
payload length (from which the exact plaintext length follows),
and whatever the access spec leaves in the clear about grants, such as how
many there are. The format does not pad lengths and does not store a file
name.

## 10. Open questions for the owner

1. **Original file name.** The format does not store one. The CLI would
   derive the output name by removing `.ssc` (`report.pdf.ssc` becomes
   `report.pdf`) and ask when that is not possible. Storing an encrypted
   name is possible, but it adds metadata to authenticate and sanitise.
   Proposed: do not store it in 3.0.
2. **Text messages.** 2.x could encrypt a string as well as a file. The
   brief covers only files. The armoured form (section 8) lets the CLI
   encrypt text from stdin to an armoured block without any extra format.
   Proposed: that is the only text support in 3.0.
3. **Size limit.** 2.x capped files at 100 MiB. Streaming removes the need
   for a cap. Proposed: none in the format, and none in the CLI unless a
   test shows one is needed.

## 11. Test vectors

The vectors are in [`tests/vectors/`](../../tests/vectors/), described by
`manifest.json` there. They were generated by `tools/vectors/generate.py`
(Phase 1, step 5) and are frozen: `tests/test_vectors_frozen.py` fails on any
change to them. Each valid vector records all of its randomness, so an
encryptor must reproduce it byte for byte, and each rejection vector names
the rule it breaks.
