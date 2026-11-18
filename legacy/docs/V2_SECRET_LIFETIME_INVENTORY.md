# V2 Secret Lifetime Inventory

**Status:** Living reference document, part of the post-v2 hardening review.
**Scope:** The v2 managed-key container format (`secure_string_cipher.v2`)
and the shared vault subsystem it depends on for `vault-copy` key storage
and master-password handling. v1's standalone `encrypt_text`/`encrypt_file`
path is referenced only for contrast — it is not itself in scope for
changes here.

This document answers, for every secret v2 code creates or handles: where
it comes from, how long it lives, what representation it's in, whether it's
copied, and whether/how it's wiped. It does not recommend a rewrite; several
of the gaps below are accepted, documented trade-offs rather than open
defects. Where a gap is real and worth fixing, that is called out explicitly
as a candidate for its own future, separately-reviewed change — not bundled
into this inventory pass.

## Summary table

| Secret | Source | Representation | Wiped? |
|---|---|---|---|
| Object DEK (encrypt) | `os.urandom(32)` in `encrypt.py` | `bytes`, then briefly `SecureBytes` | Partial — see DEK below |
| Object DEK (decrypt) | Unwrapped via AEAD in `keywrap.py` | `bytes`, then briefly `SecureBytes` | Partial — see DEK below |
| V2 password credential | CLI: `_get_v2_password` (plain `str`); public API: `PasswordCredential.passphrase: str \| SecureBytes` | Plain `str` via CLI; `derive_argon2id` re-encodes to `bytes` regardless | No |
| Grant KEK (`kek`) | HKDF/Argon2id output in `kdf.py` | Plain `bytes` | No |
| Commitment key (`k_commit`) | Same HKDF/Argon2id call as KEK | Plain `bytes` | No |
| Payload/metadata subkeys | `derive_payload_key`/`derive_metadata_key` (HKDF from DEK) | Plain `bytes` | No |
| Vault master password, outer vault codec | Passed to `core.py`'s `encrypt_text`/`decrypt_text`/`derive_key` for the vault document's own AEAD/HMAC | Plain `str` in, briefly `SecureString`/`SecureBytes` **inside** `derive_key` | Partial — same immutable-copy puncture as the DEK |
| Vault root key (v2, inner) | **Argon2id** direct (`hash_secret_raw` in `_derive_vault_root_key`) — not HKDF | Plain `bytes` | No |
| Per-record vault-copy KEK | HKDF-SHA256 from the root key (`_derive_vault_copy_kek`) | Plain `bytes` | No |
| Managed key plaintext (`.ssckey`) | `secrets.token_bytes(32)` at `key create`, or read from disk | Plain `bytes`, **returned to and retained by the caller** | No |
| Vault-copy unwrapped secret | AEAD-unwrapped in `vault_service.get_key` | Plain `bytes`, **returned to and retained by the caller** | No |
| v1 passphrase (contrast only) | User input | `SecureString` in `core.py` | Yes (own buffer) |
| v1 derived key (contrast only) | `derive_key()` in `core.py` | `SecureBytes` | Yes (own buffer) |

## Detail

### Object DEK

- **Encrypt path** (`v2/encrypt.py`): generated via `os.urandom(32)`, held as
  plain `bytes` while building the header, then wrapped for output
  (`wrap_dek_for_grant`). `SecureBytes(dek_raw)` is used only around the
  frame-encryption call (`with SecureBytes(dek_raw) as secure_dek:`), and
  even there `payload.py`'s `FrameWriter`/`FrameReader` are constructed from
  `derive_payload_key(dek, ...)`, i.e. the DEK is passed onward as a `bytes`
  argument regardless of the wrapper.
- **Decrypt path** (`v2/decrypt.py`): `_unwrap_dek_for_credential` returns
  plain `bytes`; immediately wrapped as `SecureBytes(dek_raw)`, then
  immediately unwrapped again — `dek = bytes(secure_dek.data)` — before use.
  This `SecureBytes(...).data` → `bytes(...)` round trip creates a second,
  unwiped, immutable copy of the DEK on every single decrypt. The `with`
  block wipes the `SecureBytes`-owned buffer on exit, but the `dek` variable
  used for the actual decryption is not that buffer — it is the fresh
  immutable copy pulled out of it.
- **Net effect:** the DEK is *briefly* touched by `SecureBytes`, but the
  wrapping does not reduce the DEK's real lifetime as a plain, unwiped
  `bytes` object, because every consumer (`derive_payload_key`,
  `derive_metadata_key`, `FrameWriter`/`FrameReader`) takes `bytes`, not a
  buffer-protocol object, forcing a copy out of the wrapper before it can be
  used. This matches `THREAT_MODEL.md` §5.3's existing, accurate disclosure:
  "the value handed to encrypt/decrypt logic is copied to an immutable
  `bytes` object before use, which `SecureBytes`' own zeroing cannot reach."

### V2 password credential

The CLI always supplies a plain `str`: `cli_args.py::_get_v2_password`
returns either a vault-sourced password (also a `str`) or a freshly
prompted one, with no wrapping. The public API's `PasswordCredential`/
`CombinedCredential` dataclasses type `passphrase` as `str | SecureBytes`,
so a caller of the library (not the CLI) could pass a pre-wrapped
`SecureBytes` — but it wouldn't matter: `v2/kdf.py::derive_argon2id` takes
`password: str | bytes` and immediately does `password.encode("utf-8")` on
a `str`, or uses `bytes`/`bytearray` as-is, with no `SecureBytes`/
`SecureString` involvement anywhere in the function. So the v2 password
credential receives **no secure-memory treatment at any point** in its
life, from CLI prompt to KDF input — a strictly worse position than the
DEK's briefly-wrapped-then-punctured treatment described above, and worse
than v1's `core.py::derive_key`, which at least wraps briefly.

### Grant KEK, commitment key, payload/metadata subkeys

`kdf.py`'s `derive_password_grant_keys`, `derive_managed_key_grant_keys`,
`derive_combined_grant_keys`, `derive_payload_key`, and
`derive_metadata_key` all return plain `bytes`. None of `kdf.py` imports or
uses `SecureBytes`/`secure_wipe` anywhere. `keywrap.py`'s `kek` and `r`
locals are likewise plain `bytes`, used to build an `AESGCM` cipher object
and then left for the garbage collector.

**Why this is lower-severity than it sounds:** every one of these values is
*derived* — reproducible from the DEK, the password, or the managed
secret, none of which is itself wiped either (see above and below) — so
wrapping only these derived values would not close a real gap while the
values they are derived from remain unwiped. Fixing this meaningfully
requires starting from the top of the chain (the DEK and the credential
secrets), not each derived subkey independently.

### Vault master password and root key

The vault master password is threaded through `passphrase_manager.py`
(`PassphraseVault`) and `v2/vault_service.py` (`V2VaultService`) as a plain
Python `str` in essentially every method signature:
`_load_document`, `_save_document`, `create_key`, `import_key`, `get_key`,
`list_keys`, `export_key`, `set_key_status`, and more.

**This is not a uniform "zero treatment" gap — it splits into two distinct
paths that must not be conflated:**

- **Outer vault codec (v1-backed, has some wrapping).** Every vault
  document encode/decode and its HMAC integrity check goes through
  `core.py`'s `encrypt_text`, `decrypt_text`, and `derive_key`
  (`passphrase_manager.py::_compute_vault_hmac`,
  `_encode_document`/`_load_document`'s use of `decrypt_text`/
  `encrypt_text`). `derive_key` internally wraps the passphrase in
  `SecureString` and the encoded bytes in `SecureBytes` — punctured by the
  same immediate re-copy-to-immutable pattern described for the DEK above,
  but not literally untouched.
- **Inner v2 root-key derivation (no wrapping at all).**
  `V2VaultService._derive_vault_root_key` calls
  `hash_secret_raw(secret=master_password.encode("utf-8"), ...)`
  directly — **Argon2id, not HKDF** (HKDF is used one step later, in
  `_derive_vault_copy_kek`, to derive each record's per-key wrapping key
  from the already-derived root key) — with no `SecureString`/`SecureBytes`
  involvement whatsoever. This path is real, current, and unlike the outer
  codec path above, genuinely receives no secure-memory treatment at any
  point.

**The inner v2 root-key derivation's master-password handling is the
largest concrete gap this inventory found**, not the master password in
general — the outer vault codec path already gets v1's (punctured, but
present) treatment. The master password is plausibly the longest-lived
secret in the whole system — a CLI session unlocking the vault once (e.g.
`ssc key list --vault personal`) may hold it across an entire multi-key
operation — and every one of those operations calls
`_derive_vault_root_key` at least once with zero wrapping.

**Deliberately not fixed in this pass.** `master_password: str` is a
function-signature-level type used across dozens of call sites in both
`passphrase_manager.py` and `v2/vault_service.py`, plus every CLI command
that accepts `--vault`. Retrofitting `SecureString`/buffer-protocol handling
through that whole call graph is a real, separately-scoped refactor with
its own regression risk — not a fit for a documentation-and-inventory pass,
and not something to bundle into an unrelated PR per this review's own "no
bundled mega-PRs" rule. Recorded here as the top candidate for a dedicated
future PR.

### Managed key plaintext (`.ssckey`) and vault-copy unwrapped secret

- `ssc key create` generates the managed secret via `secrets.token_bytes(32)`
  and either writes it to a `.ssckey` file (external-only) or AEAD-wraps it
  under the vault root key for storage (vault-copy). In both cases the
  plaintext secret is a local `bytes` variable with no explicit wipe.
- `V2VaultService.get_key` unwraps a vault-copy secret back to plain
  `bytes` (`secret_bytes`) and returns it to the caller (e.g. `export_key`,
  or the CLI's encrypt/decrypt credential resolution). No wrapping or
  wiping at any point in this path. Both `create_key` (returns
  `tuple[KeyIdentity, bytes]`) and `get_key` (returns
  `tuple[KeyIdentity, bytes | None]`) hand the plaintext secret back to
  the caller rather than keeping it internal — see the "caller-escaped
  secrets" note in Conclusions below.
- **Note on the *other* code path:** `cli_args.py::_resolve_v2_key_source`
  (used by ordinary `ssc encrypt --with key:ID` / `ssc decrypt`, without
  `--vault`) reads `.ssckey` files directly off disk and never touches the
  vault at all — see `ROADMAP.md`'s v2 release-gate notes on key-status
  enforcement. That path's secret handling is a separate, already-documented
  design area from the vault-copy path described here.

### v1 passphrase and derived key (for contrast, not in scope)

`core.py`'s `encrypt_text`/`decrypt_text`/`encrypt_file`/`decrypt_file` wrap
the passphrase in `SecureString` and the output of `derive_key()` in
`SecureBytes`, and the underlying `SecureBytes`/`SecureString` wipe their
own buffers on `__exit__`/`__del__`. This is the pattern the rest of the
codebase (v2 and the vault) does not currently follow — included here only
so the comparison in the summary table has a working example to point at.

## Conclusions

1. **No internal caching exists anywhere in v2** — there is no
   process-lifetime or cross-operation cache to audit or bound.
   `SSC-KEY-LIFE-01` ("object DEKs are short-lived and not cached by
   default") already holds without any code change. This is a distinct
   claim from "every secret's lifetime ends with the operation," which is
   not true: `create_key` and `get_key` both return the plaintext managed
   secret directly to their caller (see above), and nothing stops that
   caller — CLI code, or a library consumer — from retaining it
   indefinitely after the vault call returns. The absence of a cache means
   v2 itself doesn't prolong a secret's life; it says nothing about what a
   caller does with a secret it was handed.
2. **`SecureBytes`/`SecureString` provide real value in v1's `core.py`,
   partial (punctured) value on the vault's outer codec path that calls
   into `core.py`, and none at all in v2's own code (`v2/kdf.py`,
   `v2/keywrap.py`, `v2/vault_service.py`'s inner root-key derivation)**,
   because every consumer that does receive a wrapped secret immediately
   unwraps it back to plain `bytes`/`str` before use. The wrapping is not
   wrong, but it is not currently earning its complexity in the v2-specific
   call paths.
3. **The inner v2 vault root-key derivation's handling of the master
   password (`_derive_vault_root_key`, Argon2id-direct, zero wrapping) is
   the most under-protected long-lived-secret path in the codebase** and
   the most valuable target for a future, dedicated secure-memory PR —
   deliberately not attempted here. The v2 password credential (§ above)
   is a close second, since it also receives zero treatment end to end.
4. **Derived subkeys (KEK, commitment key, payload/metadata subkeys) are
   the least valuable target** for the same treatment, since they are
   reproducible from already-unwiped upstream secrets.

This inventory should be re-read (and re-verified against the code, not
assumed still accurate) before any future PR claims to have addressed
secret-lifetime handling in v2 or the vault.
