# Threat Model: Secure String Cipher V2

> **Status:** V2 shipped as part of package release `v2.0.0` (2026-09-11).
> This document was substantially corrected on 2026-09-10 after an
> independent audit found several claims did not match the implementation
> at the time; that audit's findings are fixed, and the security content
> below reflects the released behavior.

## 1. Overview
Secure String Cipher V2 adds a new `.ssc` container **alongside** the existing
V1 `.enc` format — it does not replace it. Both remain fully supported and
readable; `ssc decrypt` auto-detects which one a file is. The overarching
security goals of V2 are the same as V1: provide an authenticated encryption
tool that safeguards data at rest against unauthorized access and tampering.

V2 changes the key architecture by decoupling the payload's Data Encryption
Key (DEK) from the user's credential via AEAD key wrapping. **It does not
introduce multi-grant access control**: each `.ssc` object carries exactly one
access grant (`AccessPolicy.SINGLE_GRANT`, enforced in `v2/envelope.py`). That
single grant can itself require a password and a managed key together, but no
object can be opened by more than one independent credential.

## 2. Trust Boundaries
* **The Application Boundary**: The memory space and executable logic of `secure-string-cipher`.
* **The Filesystem**: The local storage media where `.ssc` ciphertexts, `.ssckey` key files, and vault backups reside.
* **The OS Keychain**: Native credential storage (macOS Keychain, Windows Credential Vault, Linux Secret Service).
* **The User**: The entity providing input passwords and executing operations.

## 3. Threat Actors & Capabilities

| Actor | Capability | Addressed By |
|-------|------------|--------------|
| **Passive Eavesdropper** | Read access to `.ssc` files on disk. | AES-256-GCM encryption of payload. The access grant does not reveal the DEK. |
| **Active Tamperer** | Write access to `.ssc` files; ability to alter ciphertext, metadata, or the grant. | GCM authentication tag; HMAC-SHA256 grant commitment; strict header field validation and canonical-JSON re-verification. |
| **Brute-force Attacker** | Offline computational capability to guess passwords. | Argon2id KDF (memory-hard; `time_cost=3`, `memory_kib=65536`, `parallelism=4` — OWASP-baseline, not unusually high); local CLI rate limiting on the interactive path only (see §5.4 — it does not slow an attacker operating directly against a copied file). |
| **Key Compromiser** | Access to a stolen password or `.ssckey` file. | A grant built with `--require all` needs both components together, so a stolen password alone (or a stolen key alone) is insufficient for that object. **Not addressed**: `.ssckey` files store the raw 256-bit secret in plaintext (base64), so possession of the file is possession of the key — see §5.4. Revoking or destroying a key in the vault is enforced on the honest code paths but cannot stop a copy of that key's file from decrypting — see §5.5. |

## 4. Key Security Mechanisms in V2

### 4.1. Data Encryption Key (DEK) Wrapping
In V1, the file was encrypted using a key derived directly from the user's password. In V2, a randomly generated 32-byte DEK is used for the AES-256-GCM payload encryption. The credential (password, managed key, or both together) wraps (encrypts) the DEK via AEAD, forming the object's single access grant.

* **Benefit**: The DEK is cryptographically independent of the user's password.
* **Not a benefit**: this does *not* let multiple independent credentials decrypt the same object — see §1.

### 4.2. Combined Authentication (single grant, two components)
The CLI's `--with`/`--require` flags select what a grant requires; they are
not stored access-policy fields on the object (there is no `require_all` or
`require_any` field in the `.ssc` header schema).

* `--require all` with two `--with` sources builds one grant requiring both a
  password and a managed key together.
* `--require any` with more than one `--with` source is rejected by the CLI —
  there is no "any of N credentials" mode.
* **Threat mitigated**: for a combined grant, a single stolen credential
  (password *or* key alone) is insufficient.

### 4.3. Key Commitment
V2 retains an HMAC-SHA256 commitment, computed per grant over a canonical-JSON
transcript of the header (with only the commitment value itself blanked). It
is keyed by a value derived from the *credential* (`K_commit`) under a random
per-object salt — **not** derived from the DEK, and **not deterministic**
(a fresh random salt means re-encrypting the same plaintext under the same
credential produces a different commitment each time).
* **Threat Mitigated**: Partitioning Oracle Attacks. The wrapped DEK and the
  grant are bound to the whole header transcript; commitment is verified
  before the DEK is unwrapped.

## 5. Known Limitations & Residual Risks

### 5.1. File Size Limits & RAM Usage
Both the V2 encrypt and decrypt paths enforce the 100 MiB plaintext cap (the
same limit as V1). On decrypt, `FrameReader` rejects a stream once either the
frame index or the cumulative plaintext byte count would exceed the limit for
the header's own `chunk_size` (checked before each frame's ciphertext body is
read, not only after the fact) — a crafted `.ssc` file with more frames or
more total plaintext than the design allows is rejected mid-stream rather
than decrypted to completion.

### 5.2. Offline Brute-force
While Argon2id increases the cost of offline password guessing, a weak
password combined with an exposed `.ssc` file is still vulnerable. Users are
encouraged to use strong passphrases or `.ssckey` managed keys (256 bits of
entropy, generated with `secrets.token_bytes`, not deterministic).

### 5.3. Memory Zeroization
Python's garbage collector and memory model make absolute memory zeroing
unreliable. `SecureBytes` and `libsodium` (when available) are used for
best-effort wiping, but sensitive data (like the decrypted DEK) may linger in
memory after process exit or crash. On the V2 DEK path specifically, the value
handed to encrypt/decrypt logic is copied to an immutable `bytes` object
before use, which `SecureBytes`' own zeroing cannot reach.

### 5.4. `.ssckey` files are unprotected at rest
A `.ssckey` file is the base64-encoded raw 256-bit secret with no passphrase
wrapping. File permissions (0600, symlink rejection, `O_NOFOLLOW`) are the
only protection; anyone who obtains the bytes has the key, with no secondary
factor required. `--require all` is the only mitigation, and only for objects
deliberately encrypted that way (§4.2).

### 5.5. Key lifecycle enforcement is advisory, not cryptographic
`ssc key archive` / `revoke` / `destroy` change a status field on the vault's
metadata record for that key. `ssc encrypt --with key:ID` and `ssc decrypt`
enforce that field by default: whenever a vault exists on this machine, the
key's record is read and a `REVOKED`/`DESTROYED` key is refused. A bare
`.ssckey` that was never registered in this vault cannot be checked and is
unaffected; `archive` never blocks use, being bookkeeping only.

The limit of this control is that it is advisory. The check runs inside the
process the operator invokes, so `--no-enforce-key-status` — or a build with
the check removed, or any independent implementation of the format — will
decrypt with the raw secret regardless. That follows from §5.4: the `.ssckey`
file *is* the key, and revocation cannot reach a copy of it. What the check
does buy is that a revoked key stops working across the honest paths, so
continued use requires a deliberate act that leaves a trace, rather than
being the silent default. Revocation that must hold against a motivated
holder of the file requires re-encrypting the affected objects under a new
key.

### 5.6. Local rate limiting is bypassable, not a confidentiality risk
The CLI's exponential-backoff rate limiter identifies a decrypt attempt by a
salted HMAC of a bounded ciphertext prefix, not the file path — copying the
ciphertext to a new path inherits the original's lockout rather than
resetting it. The state file (`~/.secure-cipher/rate_limits.json`) stores
only these salted HMAC keys (never plaintext paths or labels) and is capped
at 500 records with LRU eviction. The remaining limitation is enforcement
scope, not disclosure: it is a local, single-process CLI mechanism, so it
cannot prevent an offline or distributed password-guessing attack against
the ciphertext itself.
