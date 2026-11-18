# SSC rebuild game plan

Nov 17, 2026 · @Adi Dhar

SSC 3.0 is a fresh Python codebase on a `v3` branch that will replace `main`. It does local file encryption where every file carries its own access rules, with an interactive mode that does the job in a few simple steps. The plan is cut into small steps sized for a few hours a week.

## 1. Decisions made

Seventeen choices are settled; everything below follows from them.

| Topic | Decision |
| --- | --- |
| Current users | None, so 3.0 is a clean break: no legacy reader, no migration. |
| Purpose | An advanced but approachable terminal tool for local file encryption, for people who don't want a password manager. |
| Where it runs | A local CLI and a Docker container. No server. |
| Codebase | A fresh Python package on a `v3` branch. The old code is kept only as a reference for tests and ideas. |
| Repository | Same repo and name. The branch replaces `main`, and the README, licence, contributing guide, security policy and all docs are rewritten for 3.0. |
| Vault | Kept as a convenience. Each entry holds either a typeable password or a random key, and `--vault <entry>` encrypts with it. |
| Recovery | An optional printable recovery code, added to a file as an extra grant. |
| Who it serves, in order | One person across devices in 3.0, sharing in 3.1, team rules after that. |
| Interactive mode | Simple, and does the whole job for you. |
| Platforms | Linux, macOS and Windows, all tested in CI. |
| Library | CLI first; a supported Python API after 3.0. |
| Pace | A few hours a week, so every step is small and finishes on its own. |
| Review | Community review of the crypto design. |
| Licence | MIT. |
| Python | 3.13 or newer; CI tests 3.13, 3.14 and 3.15. |
| File names | .ssc for files, .ssckey for keys, vault.ssc for the vault; files recognised by their header, not the extension. |
| OS integration | Use the OS wherever it is more secure: keychain, standard folders, owner-only permissions (section 12). |

## 2. The diagnosis

Your ideas are sound, and they already point in one direction. The mismatch comes from how they were added, not from what they are.

Your own v2 and v3 docs describe one product: a **vault-policy-first encryption system**, where each file carries rules for who may open it. That fills a real gap. age and gpg let you pick recipients, but neither offers "password AND key", "any 2 of these 3", reusable profiles, or key lifecycle in a friendly local tool. The permissions idea is the part worth building the project around.

Why it feels like a hodge-podge today:

1. **Built in generations, never merged.** v2 was deliberately a parallel package that left `core.py` alone. That was the safe call at the time. The result is three file formats (v4, v5, SSC2), two vault formats, two key mechanisms (legacy key file and `.ssckey`), and two CLIs.
2. **Features bolted on beside the core instead of built on it.** The rate limiter, audit log, secure-memory wrappers, timing jitter, keychain storage and shred each have their own storage and rules. None of them uses the encryption engine.
3. **The permissions model was reserved, not built.** The SSC2 header has a `grants` array that must hold exactly one grant, and the policy is fixed to `single-grant`. Key status (revoked, destroyed) is enforced only by SSC's own code paths.
4. **The current format blocks the v3 headline feature.** SSC2 authenticates every payload chunk against the full header, grants included. So access cannot be added or removed without re-encrypting the file, as your refined spec's section 8.3 already says.
5. **Docs multiplied.** There are three overlapping v2 specs, process guides and redirect stubs, about 11,700 lines of Markdown.

The fix is not to drop ideas. It is to rebuild around one mechanism, so that each idea becomes a small addition to it instead of a separate subsystem.

## 3. The unifying idea

Every SSC feature becomes a use of one mechanism: a file is encrypted once with its own random key, and a list of **access grants** says what can unlock that key.

Think of a safe-deposit box. The file is the box, and its key is copied into several small lockboxes, one per grant. Each lockbox needs certain things to open: a password, a key file, this laptop's keychain, a YubiKey. Open any one lockbox and you get the box key. Change who has access by adding or removing lockboxes; the box itself never changes.

This is called envelope encryption. You already use it in SSC2 (a random DEK wrapped by one grant). The rebuild just takes it all the way.

| Feature you have or planned | In the new model |
| --- | --- |
| Encrypt with a password | One grant, one factor: password |
| Encrypt with a `.ssckey` | One grant, one factor: managed key |
| `--require all` (password and key) | One grant, two factors |
| Any of several ways in | Several grants on one file |
| Threshold (2 of 3) | One grant per qualifying combination |
| Share with another person | A grant to their public key |
| OS keychain / device-bound | A factor whose secret lives in the keychain |
| Hardware key | A factor answered by the YubiKey |
| The vault | Itself an SSC object, protected by grants |
| Profiles | Named, reusable sets of grants |
| Key lifecycle | Vault bookkeeping, plus rotation when it matters |
| Audit log | The vault's own access history |
| Encrypt with a vault entry | One grant, one factor: the entry's stored password or key |
| Recovery code | An extra grant you print and keep somewhere safe |

Nothing in that table is a special case. Each row is the same engine with a different grant, which is what turns the hodge-podge into one product.

## 4. The target architecture

Five layers, each with one job: the payload stays boring, the access layer is your product, and everything above it is a thin user of the engine.

[embedded content: SSC 3.0 architecture · 5 layers, with factors feeding the access layer]

Requests flow down through the layers. Factors feed the access layer from the side, including vault entries and recovery codes. The rule that keeps this clean: each layer calls only the one beneath it, and cryptography lives only in layers 4 and 5 and the factors.

## 5. The permissions system, done properly

Build it as factors, grants and policies, keep all the cryptography in one small reviewed component, and be honest that removing access is not the same as revoking it.

### Four words to use everywhere

- **Factor:** one thing someone knows or holds. Password, vault entry, managed key, recovery code, and later a recipient private key or hardware key.
- **Grant:** a set of factors that must all be present. Each grant wraps the file key once.
- **Policy:** the set of grants on one file. Any one grant opens it.
- **Profile:** a named policy saved in the vault, so `ssc encrypt --profile backup` applies the same rules every time.

### How each rule works

- **All of (password and key):** derive the grant's wrapping key from every factor together (each factor's secret, labelled, fed through HKDF), then wrap the file key once. Your `combined-password-managed-key` grant already does this for two factors; this generalises it.
- **Any of:** add more grants, each wrapping the same file key. A file is only as strong as its weakest grant, so the CLI should say so when someone adds a weak one.
- **Threshold (k of n), in the team release:** for small n, write one all-of grant per qualifying combination. 2 of 3 is 3 grants; 3 of 5 is 10. That needs no Shamir secret sharing, which is easy to get subtly wrong. Cap n (5 is a reasonable start) and revisit only if real users need more.
- **Change access without re-encrypting:** the payload must be authenticated by the file key and the fixed parts of the header only. The access block gets its own MAC, keyed from the file key and recomputed whenever grants change, much as age does with its header. Adding a grant requires opening the file first, so only someone with access can grant access.

### Honest limits to design in, not discover later

- **Removing a grant is not revocation.** Anyone who already opened the file, or kept an old copy, still has what they had. True revocation is `ssc access rotate`: a new file key and full re-encryption. The CLI should use the words "removed" and "rotated" and never blur them.
- **Key status is advisory.** Marking a key revoked stops SSC from using it. It cannot stop a copy of that key file in someone else's hands. Revoking a key should offer to rotate every file that key can open.
- **Policy lives in each file.** Changing a profile does not change files already written. A batch command (`ssc access apply --profile backup *.ssc`) closes that gap.

### What the commands could look like

```
ssc encrypt report.pdf --profile backup
ssc access show report.pdf.ssc
ssc access add report.pdf.ssc --grant "password+key:laptop"
ssc access remove report.pdf.ssc --grant g2
ssc access rotate report.pdf.ssc
ssc profile create backup --grant "key:laptop" --grant "password+key:usb"
```

### What makes people trust it

One short spec covering only the access block, published test vectors, and an outside review of that spec. It is a few hundred lines of logic, small enough to review properly.

## 6. The vault

The vault stays the convenience you built it to be: name an entry once, then encrypt and decrypt with `--vault <entry>` instead of typing or remembering a password. In 3.0 the vault is itself an SSC object, so it runs on the same engine as everything else.

### Two kinds of entry, chosen per entry

| Entry type | What it holds | If the vault is lost |
| --- | --- | --- |
| Password entry | A password you chose or generated, which you can see and type | Files still open by typing the password |
| Key entry | A random 256-bit key you never see | Files are lost unless they also carry another grant, such as a recovery code |

When someone creates a key entry, SSC should offer a recovery code in the same step, since that entry has no fallback otherwise.

### How it works

- **An entry is a factor.** `ssc encrypt -f report.pdf --vault work` builds a grant from the `work` entry, and `ssc decrypt report.pdf.ssc` finds it automatically.
- **Unlocking the vault.** The vault's own grants are your master password and, optionally, a small key held in this device's keychain. On your own machine you then need not type the master password every time.
- **The keychain holds only that small unlock key, never the vault**, so Windows' Credential Manager size limit stops mattering.
- **Changing the master password rewraps one grant.** Nothing else is re-encrypted.
- **Each entry records** a label, type, created date and status (active, archived, revoked).
- **Backup:** `ssc vault backup` writes an encrypted copy. A recovery code on the vault itself covers a forgotten master password.

This is not the kind of password manager your users avoid. It only holds secrets for SSC files, it lives as a local file you control, and nothing syncs anywhere.

## 7. Interactive mode

Typing `ssc` with no arguments opens a short guided flow that does the whole job: pick a task, answer two or three plain questions, and it's done.

### Example: encrypting a file

1. **What do you want to do?** Encrypt, Decrypt, Vault, Keys, Settings.
2. **Which file?** A path prompt with tab completion; dragging the file into the terminal also works.
3. **How should it unlock?** Saved profiles first (for example "Laptop backup: vault entry + recovery code"), then: a password I'll type, a vault entry, a key file, or something else.
4. **Confirm:** "Encrypt report.pdf to report.pdf.ssc, unlocked by vault entry 'work'. Go?"
5. **Done**, with the output path.

Decrypting is shorter still: pick the file, and SSC reads from the file what it needs and asks only for that.

### Principles

- Safe defaults, so pressing Enter all the way through is fine.
- Arrow-key choices, not typed numbers.
- Never ask for something SSC can work out itself.
- Profiles turn the common case into one choice.
- Plain words on screen: "unlock with", never "grant" or "factor".
- It calls the same service layer as the CLI, so the two always behave the same.
- Works in any plain terminal, over SSH and inside Docker, with no mouse needed.

The prompt library is chosen in the design phase. Prompt-style libraries (for example `questionary`) fit this better than a full-screen interface such as Textual, which is heavier to build and test across three platforms.

## 8. Every feature: keep, reshape, cut or drop

Most features carry into 3.0 in a cleaner form; the old formats drop because nobody needs them, and three features go because they can't deliver what they promise in Python.

| Feature | Verdict | In 3.0 |
| --- | --- | --- |
| AES-256-GCM, Argon2id | Keep | The payload layer and the password factor. |
| `.ssckey` managed keys | Keep | A factor. Passphrase-protected export can come later. |
| `--with` / `--require all` | Keep, generalise | Grants and profiles. |
| Key lifecycle | Keep, make honest | Entry status in the vault; revoking offers rotation. |
| Passphrase vault | Rebuild | An SSC object with password and key entries (section 6). |
| OS keychain | Reshape | Holds only the small key that unlocks the vault. |
| Passphrase generator | Keep | The EFF large wordlist, shipped as a data file. |
| Interactive menu | Redesign | The guided flow (section 7). |
| Docker image | Keep, simplify | Hash-locked install, no compiler toolchain, run with `docker run --rm`. |
| Audit log | Reshape | Opt-in vault history, no file paths, hash-chained. |
| Password strength check | Simplify | Minimum length plus a strength estimator, on encrypt only. |
| Secure shred | Keep, with a clear warning | SSDs and copy-on-write filesystems defeat overwriting. |
| Rate limiter | Cut | It cannot slow an attacker who has a copy of the file. |
| Secure-memory wrappers, timing jitter | Cut | Python cannot reliably wipe secrets, and nothing observes the jitter. |
| v4, v5 and SSC2 formats, legacy key-file mode | Drop | No users, so no reader is needed. |
| Python library API | After 3.0 | Internals stay private until the design settles. |
| SQLite vault backend | Defer | One encrypted object is enough for now. |
| Hardware keys | Later 3.x | Added as a factor once the core is proven. |

Worth carrying over from the old repo: the golden-vector approach, the fuzzing harness, the three-platform CI matrix, and the check that secrets never reach output.

## 9. Where age fits

Borrow age's design, not age as the whole format. Your permissions system (all-of, threshold, profiles) is exactly what age does not do, so making it the product means owning the access layer.

What age gets right that SSC3 should copy ([format spec](https://github.com/C2SP/C2SP/blob/main/age.md)):

- **The payload never depends on who has access.** The payload key comes from the file key and a nonce. Recipients sit in the header, protected by a MAC keyed from the file key. That separation is what makes adding and removing access possible without re-encryption.
- **A plain, boring payload.** 64 KiB chunks, a counter nonce with a last-chunk flag, and failure if the stream ends without a valid final chunk. You already do this in SSC2.
- **A proven public-key recipient.** age's X25519 construction is a good model for your "share with someone" grant.
- **Strict parsing:** one canonical encoding, with everything else rejected.

Where age stops short of your vision:

- Any of its recipients can open a file, but it has no way to require all of several.
- Its passphrase mode cannot be combined with any other recipient, by design.
- It has no profiles, lifecycle or vault.
- As far as I could see, the Python bindings ([pyrage](https://pypi.org/project/pyrage/)) expose encrypt and decrypt but not the internal file key, so SSC could not attach its own grants to an age file.

An option worth keeping: an export to plain age for files whose policy is simple (one password, or public-key recipients only). That gives users an escape hatch to a standard tool and costs little, but it is optional and can wait until after 3.0.

## 10. Release scope

3.0 serves one person across their devices. Sharing and teams follow as their own releases, each built the same way on the same engine.

| Release | Who it serves | What it adds |
| --- | --- | --- |
| 3.0 | One person, many devices | Password, vault-entry and managed-key factors; all-of and any-of; profiles; recovery codes; `ssc access show`, `add`, `remove`, `rotate`; the vault with keychain unlock; the guided interactive mode; Docker image; Linux, macOS and Windows |
| 3.1 | People who share files | Public-key recipients (X25519 identities), and exporting your public key for others |
| 3.2 | Small teams | Threshold grants (k of n), applying a profile to many files at once |
| Later | Anyone | Hardware keys, a supported Python API, optional export to plain age |

Every release follows the same order: a short spec addendum, community review, test vectors, code, then docs.

## 11. The game plan, step by step

Six phases to 3.0, each ending at a gate you can check. Every numbered step is meant to be one pull request on the `v3` branch, small enough to finish in a week or two at a few hours a week. Nothing in a phase starts until the previous gate is met.

[embedded content: Roadmap · 6 phases to 3.0, each ending at a gate]

Each diamond is a gate: the check that must pass before the next phase starts.

### Phase 0: set up

1. Write the charter: one page with the purpose, who it serves in order, the threat model in five bullets, and the non-goals (password manager, cloud sync, gpg replacement).
2. Create the `v3` branch with an empty package, `pyproject.toml`, and CI for Linux, macOS and Windows: tests, lint and type checks.
3. Freeze `main`: add a README note that 3.0 is being rebuilt on `v3`. Spend no more time fixing 2.x, since that code is being replaced.

**Gate:** CI is green on all three platforms for the empty package.

### Phase 1: design on paper

1. File format: the fixed header, the payload, and the separate access block.
2. Access spec: factors, grants, how a grant's wrapping key is derived, and how the access block's MAC changes when grants change.
3. Vault spec: the vault as an object, its two entry types, its unlock grants.
4. CLI contract and the interactive flows, written out screen by screen.
5. Test vectors, generated by a throwaway script and then frozen.
6. Post the access spec for community review, as a GitHub discussion and on crypto-focused forums.

**Gate:** review comments are answered and the vectors are frozen.

### Phase 2: the engine

1. Payload layer, passing its vectors.
2. Access layer with the password factor, all-of and any-of.
3. Managed-key factor and `.ssckey` files.
4. Access changes: add, remove, rotate.
5. Fuzzing of the header and access-block parsers.

**Gate:** every vector passes and fuzzing is clean.

### Phase 3: the vault

1. The vault object with its master-password grant.
2. Password and key entries, and the vault-entry factor.
3. Keychain unlock on all three platforms.
4. Profiles and recovery codes.
5. Opt-in history.

**Gate:** changing the master password rewraps one grant, and the vault works on all three platforms.

### Phase 4: CLI and interactive mode

1. The service layer.
2. CLI commands, exactly as the contract says.
3. The guided interactive flow.
4. The Docker image.

**Gate:** every flow in the contract works end to end in CI on all three platforms.

### Phase 5: replace main and release 3.0

1. Rewrite the README, security policy, contributing guide, threat model, spec and changelog, and confirm the licence.
2. Delete the old docs and code from the branch.
3. Publish a release candidate with signed, attested builds, and use it on your own files.
4. Merge `v3` into `main` and tag 3.0.

**Gate:** you have used the release candidate for real, and the docs describe only what exists.

## 12. Smaller choices, settled

The last four choices are settled, and the OS is used wherever it is the more secure option.

| Choice | Decision | Why |
| --- | --- | --- |
| Licence | MIT | Simple, permissive, and what the repo already uses. Apache-2.0 is the one alternative worth knowing: the same freedoms plus an explicit patent grant. |
| Minimum Python | 3.13. CI tests 3.13, 3.14 and 3.15; the Docker image uses 3.14. | 3.12 already gets security fixes only, while 3.13 is supported until October 2029. 3.15 is tested but not required, since dependency wheels can lag a new release. |
| File names | `.ssc` for encrypted files, `.ssckey` for key files, `vault.ssc` for the vault | The extension is only a label. SSC recognises its files by the magic bytes in the header, and armoured text sits between `-----BEGIN SSC MESSAGE-----` lines. |
| OS integration | Use the OS wherever it is more secure | See the list below. |

Where the OS takes over:

- **Vault unlock key:** the macOS Keychain, Windows Credential Manager or Linux Secret Service, through `keyring`.
- **No keychain available** (headless Linux, Docker): fall back to the master password, never silently to a plain file.
- **Folders:** each OS's standard data and config locations, through `platformdirs`.
- **Permissions:** everything SSC writes is owner-only: mode 0600 for files and 0700 for folders on Linux and macOS. On Windows, the equivalent owner-only access is checked in Phase 3.
- **Randomness:** always the OS generator, through Python's `secrets`.
- **Later:** hardware-backed device keys (Secure Enclave, TPM) as the device factor in 3.x.
