# SSC 3.0 access spec

Status: **draft for review** (Phase 1, step 2). This spec is the part of SSC
that will be posted for outside review (Phase 1, step 6). Nothing here is
frozen until the review comments are answered and the test vectors are
frozen.

This document defines what goes inside an SSC file's `access_body`: the
factors, the grants built from them, and how each grant wraps the file key.
The surrounding container, including `file_key`, `access_mac` and the
payload, is defined in [FORMAT.md](FORMAT.md), and this spec uses its
notation (section 2 there).

## 1. The model

| Term | Meaning |
| --- | --- |
| **Factor** | One thing someone knows or holds: a password, a vault entry, a key, or a recovery code. |
| **Grant** | A set of factors that must all be present. Each grant wraps the file key once. |
| **Policy** | The set of grants on one file. Any one grant opens it. |

This is enough to express every 3.0 rule:

- **One way in:** one grant with one factor.
- **All of (password and key):** one grant with two factors.
- **Any of:** several grants, each wrapping the same file key.
- **Threshold (k of n), in 3.2:** one all-of grant per qualifying
  combination, so 2 of 3 is 3 grants. No secret sharing is involved.

There are no other policy types, and no special cases.

## 2. Factors

Every factor yields a 32-byte **factor secret** `s`. The grant combines the
factor secrets (section 3). Each factor type has a type byte and a
fixed-length body, written into the grant in the clear.

| Type | Name | Body | Body size |
| --- | --- | --- | --- |
| `0x01` | password | `salt (16) \|\| m_kib u32be \|\| t u32be \|\| p u8` | 25 |
| `0x02` | vault password entry | `entry_id (16) \|\| salt (16) \|\| m_kib u32be \|\| t u32be \|\| p u8` | 41 |
| `0x03` | key | `key_id (16)` | 16 |
| `0x04` | recovery code | (empty) | 0 |

### 2.1 Password (`0x01`) and vault password entry (`0x02`)

```text
s = Argon2id(password = UTF-8(NFC(password_text)),
             salt = salt, memory = m_kib KiB, iterations = t,
             parallelism = p, version = 0x13, output length = 32)
```

- `salt` is 16 random bytes, fresh for every password factor written.
- 3.0 writers use exactly `m_kib = 65536` (64 MiB), `t = 3` and `p = 4`,
  RFC 9106's memory-constrained recommendation, and **3.0 readers reject any
  other tuple**. The parameters are stored so that a later version can raise
  them, but a reader never runs an Argon2id cost it did not choose. That also
  stops a crafted file from making a reader run a huge Argon2id.
- Password text is normalised to Unicode NFC and then encoded as UTF-8. It is
  not trimmed or case-folded. NFC means the same password typed on two
  operating systems derives the same secret. Empty passwords are rejected.

A vault password entry is the same factor, with `entry_id` added: 16 random
bytes that name the entry in the owner's vault, so `ssc decrypt` can find
the password without asking. The factor secret is computed exactly as for
`0x01`. **If the vault is lost, the file still opens by typing that
password**, because a reader that cannot find `entry_id` asks for the
password instead.

### 2.2 Key (`0x03`)

A key is 32 random bytes. It lives either in a `.ssckey` file or as a vault
key entry. The wire format does not distinguish the two, so a key can move
between them.

```text
key_id = SHA-256("ssc3/key-id" || key)[0..16]
s      = HKDF(key, "", "ssc3/factor/key")
```

`key_id` lets a reader find the key among the vault's key entries and the
key files the caller supplies (CLI.md section 1), without trial decryption. A reader recomputes `key_id` from a candidate key and uses only a
key whose ID matches.

### 2.3 Recovery code (`0x04`)

A recovery code is 18 random bytes `R`, printed for the owner to keep
somewhere safe. It has 144 bits of entropy, so it needs no password hashing.

```text
s = HKDF(R, "", "ssc3/factor/recovery-code")
```

**Printed form.**

- 20 bytes, `R || SHA-256("ssc3/recovery-check" || R)[0..2]`, are encoded
  as Crockford Base32: 32 characters, printed as 8 groups of 4 joined by
  hyphens.
- When reading a code, a reader ignores case, spaces and hyphens, and maps
  `O` to `0` and `I` and `L` to `1`.
- If the 2-byte check does not match, the reader reports a typo before doing
  any cryptography.

The body is empty, so a file's recovery-code grants look identical to each
other. A reader tries the entered code against each of them, which is cheap.

## 3. Grants

### 3.1 Wire format

```text
grant_length   u16be     number of bytes that follow, up to and including wrapped_key
grant_salt     16        random, fresh every time this grant is written
factor_count   u8        1 <= k <= 5
factors        k times:  type u8 || body (section 2)
wrapped_key    48        AES-GCM-Seal(kek, 0x00 * 12, file_key)
```

The **grant descriptor** `D` is every byte from `grant_salt` up to the end of
the factors, that is, the grant without `grant_length` and `wrapped_key`.

### 3.2 Deriving the wrapping key

```text
ikm = s_1 || s_2 || ... || s_k              (factor secrets, in the order they appear in the grant)
kek = HKDF(ikm, grant_salt, "ssc3/grant-kek" || D)
```

- Each factor secret is exactly 32 bytes, so the concatenation is
  unambiguous.
- `D` carries each factor's type and parameters, so every factor is
  labelled, and the key is bound to the grant's exact contents. Changing a
  salt, a parameter, an ID or the factor list gives a different `kek`.
- The rule is the same for one factor or five. "Password and key" is just
  `k = 2`.

### 3.3 Wrapping the file key

`wrapped_key = AES-GCM-Seal(kek, 0x00 * 12, file_key)` is 32 bytes of
ciphertext plus a 16-byte tag.

The fixed all-zero nonce is safe only because each `kek` seals exactly one
message. `grant_salt` is 16 fresh random bytes every time a grant is
written. **A writer MUST NOT reuse a `grant_salt`, including when rewriting
a grant after rotation.**

A matching tag means the factors fit this grant. It does not by itself prove
that the result is this file's key; see section 4, step 4.

### 3.4 Canonical form

A reader MUST reject a grant that is not canonical:

- `factor_count` is outside `1..5`.
- Factors are not in strictly increasing byte order of their encoding (type
  byte first). This one rule fixes their order and rules out duplicates.
- A known factor's body has the wrong size, or a password factor's
  parameters are not the 3.0 tuple.
- `grant_length` does not equal the exact size of what it covers.

A grant that contains a factor type the reader does not know is **skipped,
not rejected**. Its `grant_length` lets the reader step over it, and it
still counts towards `access_mac`. That is how a 3.0 reader can open a 3.1
file through a password grant while ignoring a 3.1 public-key grant on the
same file.

## 4. The access body

```text
grant_count    u8        1 <= n <= 16
grants         n times:  grant (section 3.1)
```

The body MUST end exactly after the last grant. Grants keep the order they
were added in, and the CLI numbers them `g1`, `g2`, and so on in that order.

The limit of 16 covers a 3 of 5 threshold policy (10 grants) plus a recovery
code and a few more. It also bounds how much work a crafted file can demand.

### Opening a file

Given the factors the caller can supply:

1. Parse the whole body strictly (sections 3.4 and 4) before deriving
   anything.
2. Choose the grants the caller can satisfy. The CLI looks up `key_id` and
   `entry_id` in the vault and the key files supplied, and asks only for
   what is still missing, such as a password or a recovery code.
3. For each chosen grant, derive `kek` and open `wrapped_key`. If the tag
   fails, move on to the next grant.
4. For a candidate `file_key`, verify `access_mac` (FORMAT.md section 7.2).
   Stop at the first candidate that verifies.
5. If none verifies, fail with one error that does not say which grant or
   factor was wrong.

An implementation SHOULD derive each password secret once per distinct
`(password, salt, parameters)` and reuse it within one open attempt, rather
than rerunning Argon2id when it retries a grant. The cache key MUST include
the password itself. A cache keyed on `(salt, parameters)` alone would hand back the
secret from a mistyped password after the person corrects it. The cache is
discarded when the open attempt ends.

## 5. Changing access

All three operations are defined in FORMAT.md section 7.3. On grants
specifically:

- **Add.** Open the file, then append a new grant with fresh salts. Existing
  grants, including skipped unknown ones, are kept byte for byte.
- **Remove.** Drop the grant. The CLI calls this **removed**, never revoked.
- **Rotate.** A new `file_key` means every grant that is kept must be
  rebuilt with new salts, which needs that grant's factors again. The CLI
  asks for any it cannot find. A grant whose factors cannot be supplied,
  including a grant of an unknown type, cannot be kept, and the CLI must
  say so before it rotates. The CLI calls this **rotated**.

## 6. Security properties and honest limits

- **A file is only as strong as its weakest grant.** Adding a password-only
  grant to a file that otherwise needs a key makes it guessable offline at
  Argon2id speed. The CLI warns when someone adds a grant weaker than the
  ones already there.
- **All of is not independent two-factor authentication** when the factors
  live together. If the vault holds the key and is unlocked by the same
  password used in the grant, one compromise yields both.
- **Removing a grant is not revocation.** Anyone who already recovered
  `file_key`, or kept an old copy, still can. Only rotation protects new
  versions, and nothing protects old copies.
- **Key status is advisory.** A key marked revoked in the vault stops SSC
  from using it. It cannot stop a copy of that key file elsewhere. Revoking
  a key should offer to rotate every file that key can open.
- **No oracle on which factor was wrong.** Decryption fails with a single
  error, after the same checks, whichever factor was wrong.

### What is visible without any factor

- The number of grants.
- The factor types in each grant.
- The Argon2id salts and parameters.
- `key_id` and `entry_id`. Two files that use the same key or vault entry
  can therefore be linked to each other, though not to the owner's identity.

## 7. Decisions

Settled with the owner on 2026-11-18. Outside reviewers may still challenge them in Phase 1, step 6.

1. **`key_id` and `entry_id` stay in the clear.** They let a reader find a
   key or entry without trial decryption, which would cost one Argon2id run
   per vault password entry. The cost is that two files using the same key
   or entry can be linked to each other (section 6).
2. **Passwords are normalised to NFC**, unlike 2.x, so that the same
   password typed on different systems matches. NFC never changes plain
   ASCII.
3. **A grant holds at most 5 factors**, the same cap as threshold `n`.

## 8. Test vectors

The vectors are in [`tests/vectors/`](../../tests/vectors/), described by
`manifest.json` there. They were generated by a throwaway script,
`tools/vectors/generate.py` (Phase 1, step 5), which was deleted at the
Phase 2 gate once the implementation reproduced every vector; it remains in
git history. The vectors are frozen: `tests/test_vectors_frozen.py` fails on any
change to them. Each valid vector records all of its randomness, so an
encryptor must reproduce it byte for byte, and each rejection vector names
the rule it breaks.
