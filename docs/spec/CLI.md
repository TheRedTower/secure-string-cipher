# SSC 3.0 CLI contract

Status: **draft for review** (Phase 1, step 4). Phase 4 builds the CLI
"exactly as the contract says", so anything not written here is not in 3.0.

Both the command line and the interactive mode call the same service layer
(Phase 4, step 1), so they always behave the same. This document uses the
words of [ACCESS.md](ACCESS.md), such as grant and factor. The interactive
mode never shows those words to the person; it says "unlock with".

## 1. Conventions

- **Files are positional:** `ssc encrypt report.pdf`, never `-f`.
- **Output:**
  - Encrypting writes `<input>.ssc` unless `-o` is given.
  - Decrypting writes the input name without its `.ssc`. If the name does
    not end in `.ssc`, the CLI requires `-o`, or asks for a name in
    interactive mode.
- **Never overwrites:** an existing output is an error unless `--force` is
  given. Interactive mode asks instead.
- **Atomic writes:** every output goes to a temporary file in the
  destination folder, which is renamed into place only on success
  (FORMAT.md section 7.5).
- **stdin and stdout:**
  - `-` as the input reads stdin, and `-o -` writes stdout.
  - `--armor` writes the armoured form (FORMAT.md section 8), which is how
    text is encrypted.
  - Decryption detects armour by itself.
  - **`decrypt -o -` writes nothing to stdout until the whole file has
    authenticated**, final chunk included (FORMAT.md section 7.2). That way
    a program reading the output never gets truncated or forged plaintext
    before SSC reports the failure.
    - Until then, SSC holds the plaintext in memory, up to 64 MiB.
    - Beyond 64 MiB, it spools the plaintext to an owner-only temporary file
      in the OS temp folder. It deletes the file when done, whether or not
      decryption succeeded.
    - The docs say that plaintext touches disk in that case. To avoid it,
      decrypt to a file with `-o <out>` instead.
- **Secrets never reach output.** No secret is printed, logged or put in an
  error message. There are two exceptions, each shown once, on screen, at
  the person's request:
  - A new recovery code, when it's created.
  - A generated password, with `--show`.
  - CI checks this rule, carrying over 2.x's sensitive-output check.
- **Messages:** errors go to stderr as one plain sentence, with no
  traceback unless `--debug` is given.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Input error: bad arguments, missing options, invalid grant spec |
| 2 | Cannot open: wrong or missing credentials. Always the same message, whichever factor was wrong |
| 3 | Vault error: no vault, entry or profile not found, vault locked, keychain unavailable when it was explicitly asked for |
| 4 | File error: not found, permission denied, not an SSC file, corrupt or truncated |
| 70 | Internal error: a bug in SSC |

### Credentials without a prompt

These exist for scripts and Docker:

| Credential | Flag | Environment variable |
| --- | --- | --- |
| Passwords that open a file | `--password-file <path>`, repeatable up to 5 times | `SSC_PASSWORD`: one more |
| A new password, for `encrypt`, `access add`, `access apply` and `vault add --password` | `--new-password-file <path>` | `SSC_NEW_PASSWORD` |
| The vault's current master password | `--master-password-file <path>` | `SSC_MASTER_PASSWORD` |
| A new master password, for `vault init` and `vault change-password` | `--new-master-password-file <path>` | `SSC_NEW_MASTER_PASSWORD` |
| A recovery code | `--recovery-code-file <path>` | `SSC_RECOVERY_CODE` |
| Standalone key files | `--key-file <path>`, repeatable | `SSC_KEY_FILES`: paths separated by the OS path separator (`:` or `;`) |

- A flag beats its variable.
- A credential file must be a regular file, not reached through a symlink,
  and on POSIX not readable by group or others. Otherwise SSC refuses to
  use it.
- One trailing newline is removed from a password or recovery-code file.
- **Key files:**
  - `--key-file` makes a `.ssckey` available to any command that opens a
    file: `decrypt` and `access` (`show` excepted).
  - SSC reads each key file under VAULT.md section 6's rules.
  - It uses a key only for a grant whose `key_id` matches.
  - Keys are found only in the vault's key entries and the key files given
    this way. There is no key folder to search.
  - Giving `--key-file` with no vault, and nothing else, is how a script or a
    Docker container decrypts a file that was encrypted with
    `--grant keyfile:<path>`.
- Without a TTY, a credential that is needed but not supplied is an exit 1
  error, never a hang.
- **Opening with a password and setting one are separate roles**, so they
  have separate sources.
  - `access add --grant password` can open a file with password A
    (`--password-file`) and add password B (`--new-password-file`).
  - `access rotate` rebuilds a password grant with the password that opened
    it, so it reads only the opening source.
  - Several opening passwords serve an all-of grant with more than one
    password factor, such as `vault:work+vault:personal` after the vault is
    lost. SSC tries each supplied password against each password factor the
    vault cannot fill, and it needs no file-to-factor mapping. That is at
    most 5 Argon2id runs per factor.
- **Setting a master password and using one are separate roles** in the same
  way.
  - `vault init` reads only the new one.
  - `vault change-password` needs both. It refuses to run when the new one
    is missing, rather than reusing the current one and reporting a
    rotation that did not happen.
  - This is carried over from 2.x.

## 2. Grant specs

`--grant` takes one grant, written as factors joined by `+`:

| Token | Factor |
| --- | --- |
| `password` | A new password: typed twice now, or taken from `--new-password-file` or `SSC_NEW_PASSWORD` |
| `vault:<label>` | The vault entry `<label>`. It must be a password, key or recovery entry |
| `keyfile:<path>` | The key in a `.ssckey` file |
| `recovery` | The vault's recovery entry, chosen by the rule below. Name one with `vault:<label>` instead to pick it explicitly |

Examples: `--grant password`, `--grant "password+vault:laptop"`,
`--grant vault:usb --grant recovery`. Each `--grant` adds one grant, so
several of them mean "any of".

- A grant spec may name a factor only once.
- It may have at most 5 factors.
- A file may have at most 16 grants.

**How `recovery` picks an entry** (this also applies to `--recovery-code`).
SSC looks only at the vault's `active` recovery entries, never at archived
or revoked ones:

| Active recovery entries | What `recovery` does |
| --- | --- |
| Exactly one | Uses it |
| None | Creates one with the first unused label of `recovery`, `recovery-2`, `recovery-3` and so on, prints the code once (with the typed-back check from section 4.4), and uses it. Without a TTY, this is an exit 1 error, since the code could not be shown safely |
| More than one | Exit 1 error, listing their labels and asking for `vault:<label>` |

The vault stores no "default recovery entry".

## 3. Commands

### 3.1 Files

```text
ssc encrypt <file> [--profile <name> | --vault <label> | --grant <spec>...]
                   [--recovery-code] [-o <out>] [--armor] [--force]
ssc decrypt <file> [-o <out>] [--force] [--key-file <path>...]
```

- **`encrypt`:**
  - `--vault <label>` is shorthand for `--grant vault:<label>`.
  - `--recovery-code` adds a `recovery` grant to whatever else was chosen.
  - With no unlock option, it uses the default profile if one is set, or
    otherwise asks for a password.
  - Without a TTY, that becomes exit 1.
- **`decrypt`:** reads the grants from the file. It uses whatever the vault,
  the keychain and any `--key-file` can supply, and asks only for what is
  still missing. It never asks for something it can work out.

### 3.2 Access

```text
ssc access show   <file>
ssc access add    <file> --grant <spec>
ssc access remove <file> --grant <gN>
ssc access rotate <file>
ssc access apply  <file> --profile <name>
```

- **`show`** lists each grant as `g1`, `g2` and so on, in plain words, for
  example `g1: password + key "laptop"`. It shows a key or entry by label
  where the vault knows it, and by ID otherwise. It needs no credentials.
- **`add`** opens the file first. If the new grant is weaker than the
  existing ones, it warns, for example: "Adding a password-only way in makes
  this file only as strong as that password".
- **`remove`** prints: "Removed g2. Anyone who already opened this file, or
  has an old copy, can still open that copy. To lock them out of this
  file's future contents, use `ssc access rotate`."
- **`rotate`** re-encrypts the file under a new file key. It lists any
  grant it can't rebuild and asks before dropping it. With `--force`, it
  drops them without asking.
- **`apply`** replaces the file's grants with the profile's.
- **Words:** these commands say "removed" and "rotated" and never use
  "revoked" for either.

### 3.3 Vault

```text
ssc vault init            [--no-device-key] [--recovery-code]
ssc vault status
ssc vault add <label>     (--password [--generate [--show]] | --key | --recovery-code)
ssc vault list
ssc vault archive <label>
ssc vault revoke <label>
ssc vault change-password
ssc vault add-device
ssc vault remove-device   <gN>
ssc vault backup <path>
ssc vault history         (on | off | show)
```

- **`init`** creates `vault.ssc`, asks for a master password, and adds this
  device's key to the keychain unless the keychain is unavailable or
  `--no-device-key` is given.
- **`add --key`** offers a recovery code in the same step, as VAULT.md
  section 3.1 requires.
- **`revoke`** marks the entry revoked. It then lists the files SSC can find
  that the entry opens, and offers to rotate them. It says plainly that a
  copy of the secret still works for whoever has it.
- **History `action` values** (VAULT.md section 5) are exactly:
  - `vault-unlock`
  - `vault-access-change`, covering a password change and adding or
    removing a device or recovery code
  - `entry-create`, `entry-archive` and `entry-revoke`
  - `profile-change`
  - `encrypt` and `decrypt`, which are recorded only when a vault entry was
    used. `entry` names that entry.

### 3.4 Keys, profiles and the rest

```text
ssc key new    <path> [--label <label>]
ssc key import <path> [--label <label>]
ssc key export <label> <path>

ssc profile create <name> --grant <spec>...
ssc profile list
ssc profile show   <name>
ssc profile delete <name>
ssc profile default (<name> | --none)

ssc generate [--words <n>]
ssc shred <file>
```

- **`key new`** writes a standalone `.ssckey` with no vault involved.
- **`import` and `export`** move a key between a key file and a vault key
  entry without changing it.
- **Profile grant specs** use the same syntax as `--grant`, except for
  `keyfile:`.
  - A profile can only refer to what the vault holds (VAULT.md section 3.2).
    So `keyfile:<path>` in a profile is an exit 1 error, which says to run
    `ssc key import <path>` first and then use `vault:<label>`.
  - A `password` token in a profile means the password is asked for at
    encrypt time.
  - A `recovery` token in a profile is resolved when the profile is
    created, by the rule in section 2. The profile stores that entry's ID,
    so later recovery entries do not change it.
- **`generate`** prints a passphrase from the EFF large wordlist: 6 words by
  default, at least 4.
- **`shred`** first prints that SSDs, copy-on-write filesystems and backups
  can keep old copies, and asks for confirmation. `--force` skips the
  question.
- **Weak passwords:** when a password is typed for encryption, SSC rejects
  one shorter than 8 characters and warns if a strength estimator rates it
  weak. It does not check passwords at decryption.

## 4. Interactive mode

Running `ssc` with no arguments in a TTY opens the guided flow. Without a TTY
it prints the help and exits 1.

- **Controls:** arrow keys and Enter. Every prompt has a safe default, so
  pressing Enter all the way through works.
- **Terminals:** it works in any plain terminal, over SSH and inside Docker,
  with no mouse.
- **Prompt library:** [`questionary`](https://pypi.org/project/questionary/),
  as the brief suggests. It gives arrow-key selects and path completion,
  and it is light to test on three platforms. Confirmed in Phase 4, step 3:
  questionary 2.1.1, which is pure Python and needs only prompt_toolkit.

### 4.1 Start

```text
SSC  ·  vault unlocked with this device

What do you want to do?
❯ Encrypt a file
  Decrypt a file
  Vault
  Keys
  Settings
  Quit
```

The first line shows the vault state: "unlocked with this device", "locked",
or "no vault yet". With no vault, choosing Vault starts `vault init`.

### 4.2 Encrypt

```text
Which file?  report.pdf▌            (Tab completes; dragging a file in also works)

How should it unlock?
❯ Laptop backup  (vault entry "laptop" + recovery code)     ← saved profiles first
  A password I'll type
  A saved vault entry…
  A key file…
  Something else…                                            → combine, or several ways in

Encrypt report.pdf to report.pdf.ssc, unlocked by profile "Laptop backup". Go? (Y/n)

✓ Wrote report.pdf.ssc
```

- **"Something else…"** builds grants step by step: "Unlock needs all of…"
  or "Any one of these opens it…", in those words.
- **"A password I'll type"** asks twice. It shows the strength warning from
  section 3.4 and offers to generate a passphrase instead.
- **An existing `report.pdf.ssc`** makes SSC ask "Replace it? (y/N)" before
  the confirm step.

### 4.3 Decrypt

```text
Which file?  report.pdf.ssc▌

This file opens with your vault entry "laptop".       ← nothing to ask; or:
Password for report.pdf.ssc: ••••••••                  ← only what it needs

Decrypt to report.pdf? (Y/n)

✓ Wrote report.pdf
```

If several ways in are possible, SSC uses one that needs nothing typed. If
every way needs typing, it asks which to use, in plain words, for example
"your password" or "a recovery code".

### 4.4 Vault

```text
Vault  ·  3 entries, 1 profile, unlocked with this device
❯ Add a password
  Add a key
  Add a recovery code
  Show entries
  Archive or revoke an entry
  Change master password
  Back up the vault
  Back
```

Adding a key ends with: "This key has no other way back if the vault is
lost. Add a recovery code now? (Y/n)". The recovery code screen shows the
code once and asks the person to type its last group back, to confirm they
have written it down.

### 4.5 Keys

This screen offers: Export a key to a file, Import a key file, Create a
standalone key file, and Back.

### 4.6 Settings

This screen offers:

- The default profile.
- Use this device's keychain (on/off), which adds or removes this device's
  grant.
- History (off/on/show).
- Back.

## 5. Decisions

Settled with the owner on 2026-11-18. Outside reviewers may still challenge them in Phase 1, step 6.

1. **Files are positional arguments only**, never `-f`. The brief's examples
   used both forms.
2. **Password strength is estimated with `zxcvbn`**, provided its Python
   package is maintained and pure Python when Phase 4 starts. Otherwise
   SSC uses the minimum length only.
3. **`revoke` scans a folder the person names** to find the files a revoked
   entry opens. SSC keeps no index of files, since history has no paths.
