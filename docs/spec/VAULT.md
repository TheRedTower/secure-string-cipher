# SSC 3.0 vault spec

Status: **draft for review** (Phase 1, step 3). Nothing here is frozen until
the Phase 1 gate.

The vault is a convenience. You name a secret once, then encrypt and decrypt
with `--vault <entry>` instead of typing or remembering it. It holds only
secrets for SSC files, it is a local file you control, and nothing syncs
anywhere. It is not a password manager.

The vault is itself an SSC file ([FORMAT.md](FORMAT.md)), unlocked by grants
([ACCESS.md](ACCESS.md)). It has no format of its own beyond the document
inside its payload (section 3).

## 1. Where things live

| Thing | Location |
| --- | --- |
| The vault | `vault.ssc` in the OS's standard user data folder, from `platformdirs.user_data_dir("ssc")` |
| Key files | `.ssckey` files, wherever the owner keeps them (section 6) |
| The device unlock key | The OS keychain, through `keyring`: macOS Keychain, Windows Credential Manager or Linux Secret Service |
| Settings | The OS's standard config folder, from `platformdirs.user_config_dir("ssc")`. No secrets |

Everything SSC writes is owner-only: mode `0600` for files and `0700` for
folders on Linux and macOS. The Windows equivalent is decided and tested in
Phase 3. Every write goes to a temporary file in the same folder that is
renamed into place (FORMAT.md section 7.5). Writers hold a lock file
(`vault.ssc.lock`) for the whole read, modify and write, so that two `ssc`
processes cannot lose each other's changes.

## 2. Unlocking the vault

The vault's own grants are:

| Grant | Factors | Purpose |
| --- | --- | --- |
| Master password | password (`0x01`) | Always present. Opens the vault on any device |
| Device key | key (`0x03`) | Optional, one per device. The key is 32 random bytes held only in that device's keychain |
| Recovery code | recovery code (`0x04`) | Optional. Covers a forgotten master password |

### Rules

- **The keychain holds only the 32-byte device key, never the vault.**
  Windows' Credential Manager size limit therefore doesn't matter.
  - The keychain item has service `ssc` and account `vault-unlock:` followed
    by the grant's `key_id` in lowercase hex.
  - A reader looks it up from the `key_id` it sees in the vault file. The
    vault needs no ID of its own.
- **No keychain available** (headless Linux, Docker): SSC asks for the master
  password. It never falls back silently to keeping the device key in a
  plain file.
- **Adding a device:** unlock with the master password on the new device,
  generate a device key, store it in the keychain, and add a device-key
  grant.
- **Removing a device:** remove its grant. This is *removal*, not
  revocation: that device has already seen the vault's file key. To lock a
  lost device out, rotate the vault (FORMAT.md section 7.3). Rotation needs
  the master password, and every other device then re-adds its grant.
- **Changing the master password:** open the vault, remove the old password
  grant, and add one for the new password. That rewraps one grant. The file
  key and every other grant stay byte for byte the same.
  - With history off, the payload is untouched too.
  - With history on, the same write also appends a `vault-access-change`
    event. That means replacing the payload under the same file key, with a
    fresh payload nonce (FORMAT.md section 7.4).
  - Either way, no secret is re-encrypted under a new key. The same applies
    to adding or removing a device or a recovery code.
- **Changing what the vault holds:** use FORMAT.md section 7.4, which keeps
  the same file key and grants, with a fresh payload nonce every time.

## 3. The vault document

The payload is one UTF-8 JSON document in canonical form:

- Object keys are sorted.
- There is no insignificant whitespace.
- There are no floats, and no duplicate keys.
- Strings are escaped only where JSON requires it.

A reader parses it only after the payload has fully authenticated. It
rejects:

- Unknown or missing fields.
- Values of the wrong type.
- Documents over 16 MiB.

Byte strings are Base64url without padding, marked `b64` below.

```json
{
  "entries": [],
  "format": 1,
  "history": null,
  "profiles": []
}
```

`format` is 1 for this spec. `history` is `null` while history is off
(section 5).

### 3.1 Entries

```json
{
  "created": "2026-11-18T09:30:00Z",
  "id": "<b64 of 16 random bytes>",
  "kind": "password",
  "label": "work",
  "secret": "<see below>",
  "status": "active"
}
```

| Field | Rule |
| --- | --- |
| `id` | 16 random bytes, unique in the vault, never reused. A `password` entry's `id` is the `entry_id` its files carry (ACCESS.md section 2.1) |
| `label` | `[a-z][a-z0-9._-]{0,63}`, unique among the vault's entries. This is the name used in `--vault <label>` |
| `kind` | `password`, `key` or `recovery` |
| `secret` | `password`: the password text, NFC-normalised, at least one character. `key`: b64 of 32 bytes. `recovery`: b64 of the 18-byte recovery value `R` (ACCESS.md section 2.3) |
| `created` | UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ` |
| `status` | `active`, `archived` or `revoked` |

| Entry kind | Factor it makes | If the vault is lost |
| --- | --- | --- |
| `password` | Vault password entry (`0x02`) | Files still open by typing the password |
| `key` | Key (`0x03`); `key_id` derives from the key | Files are lost unless they also carry another grant, such as a recovery code |
| `recovery` | Recovery code (`0x04`) | Files open from the printed code |

#### How entries behave

- **Secrets are never changed in place.** An entry's secret is fixed when
  it's created. Files already written use the old secret, so "changing" one
  means creating a new entry and moving files to it with
  `ssc access apply`.
- **When a key entry is created,** SSC offers a recovery code in the same
  step, since a key entry has no other fallback.
- **A recovery entry is printed once** when it's created. The printed copy
  is the point: it opens files when the vault is gone. The vault keeps `R`
  so the same code can be added to new files without retyping it. Anyone
  who can open the vault can therefore read its recovery codes. That is no
  worse than what they could already open, but it means a recovery code is
  never stronger than the vault.
- **Status is advisory:**
  - `active` entries are used and offered everywhere.
  - `archived` entries still decrypt, but are no longer offered for new
    files.
  - `revoked` entries are refused by SSC, and revoking one offers to rotate
    every file it can open that SSC can find.
  - A revoked secret still works for anyone who has a copy (ACCESS.md
    section 6).

### 3.2 Profiles

A profile is a named policy: a list of grants, each a list of factor
references.

```json
{
  "grants": [
    [{"entry": "<b64 id>"}],
    [{"ask": "password"}, {"entry": "<b64 id>"}]
  ],
  "name": "backup"
}
```

- `name` follows the same pattern as an entry label and is unique among
  profiles.
- A factor reference is either `{"entry": <id>}`, which names an entry of any
  kind, or `{"ask": "password"}`, which means a password typed at encrypt
  time.
- Each grant follows ACCESS.md's limits: 1 to 5 factors per grant and 1 to
  16 grants per profile. No grant may name the same entry twice, and a grant
  holds at most one `ask`.
- A profile that names a revoked or missing entry can't be applied until it
  is edited.

Applying a profile builds exactly those grants. Changing a profile does not
change files already written. `ssc access apply --profile <name> <file>`
replaces a file's grants with the profile's, and doing that for many files
at once comes in 3.2.

## 4. Backup

`ssc vault backup <path>` writes a copy of `vault.ssc`. It is already
encrypted, so it opens with whatever grants the vault had when it was
copied: the master password at that time, and that time's recovery code.
A device key works only while that device's keychain item exists. The CLI
says so when it writes the backup.

## 5. History (opt-in)

History is off by default. When it's on, `history` is an object:

```json
{
  "anchor": "<b64 of 32 bytes>",
  "events": [
    {"action": "decrypt", "at": "2026-11-18T09:31:02Z", "entry": "<b64 id or null>", "prev": "<b64 of 32 bytes>"}
  ],
  "trimmed": 0
}
```

- **What is recorded:** only operations that use the vault. That means
  unlocking it, changing its grants, creating, archiving or revoking an
  entry, and encrypting or decrypting with an entry. The `action` values are
  listed in the CLI contract (Phase 1, step 4). Decrypting a file with a
  typed password and no vault records nothing.
- **No file names or paths, ever,** and no secrets.
- **The chain:**
  - `prev` is `SHA-256` of the previous event's canonical JSON.
  - `anchor` is the `prev` that the first kept event must have. When history
    is turned on, `anchor` is `SHA-256("ssc3/history-genesis")` and
    `trimmed` is 0.
  - A reader checks that `events[0].prev` equals `anchor`, and that each
    later event's `prev` hashes the event before it. It rejects anything
    else, including an empty `events` list with `trimmed` above 0.
- **The cap:** history keeps the newest 1,000 events. To trim the oldest
  event, a writer sets `anchor` to that event's hash (which the next event's
  `prev` already holds), removes the event, and adds 1 to `trimmed`. So the
  chain stays checkable after trimming, and `trimmed` says how many events
  came before the ones kept.
- **What it protects against:** the whole vault is already authenticated
  by its access MAC. The chain adds tamper evidence against edits made by
  someone who can unlock the vault, such as a script with the device key.
  It cannot stop that person from rewriting the whole chain, or from
  trimming events and moving `anchor` forward. The docs must say so.

Turning history off sets `history` to `null`, which deletes the events.

## 6. Key files (`.ssckey`)

A key file carries one key (ACCESS.md section 2.2) as text:

```text
-----BEGIN SSC KEY-----
Label: laptop
Created: 2026-11-18T09:30:00Z
Key-ID: <key_id as 32 lowercase hex characters>
<the 32-byte key as Base64url without padding: 43 characters>
-----END SSC KEY-----
```

- **Field order is fixed.**
  - `Label` follows the entry-label pattern.
  - `Created` uses the entry timestamp form.
  - A reader recomputes `key_id` from the key and rejects the file if it
    differs from `Key-ID`, which catches damage and hand edits.
- **Transport rules follow FORMAT.md section 8:**
  - Lines end in LF, or uniformly in CRLF.
  - There is at most one trailing line ending.
  - Nothing is allowed before BEGIN or after END.
  - A reader reads at most 1 KiB.
- **SSC recognises a key file** by its BEGIN line, never by the extension.
  - It refuses a symlinked key file.
  - It writes new ones owner-only.
- **A key file is a plaintext bearer secret.** Anyone who has the file has
  the key. A passphrase-protected export can come later.

`ssc key export` writes a vault key entry as a key file, and `ssc key import`
adds a key file as a key entry. Both keep the same key, so the key's
`key_id` and the files it opens do not change.

## 7. Open questions for the owner

1. **Recovery codes in the vault.** Storing `R` lets one printed code cover
   many files. The alternative is a new code per file, which is safer if the
   vault leaks but means one sheet of paper per file. Proposed: store it, as
   above.
2. **History cap.** Proposed: 1,000 events.
3. **Device keys per vault.** Proposed: no limit beyond the 16-grant cap, so
   up to 14 devices alongside a master password and a recovery code.
