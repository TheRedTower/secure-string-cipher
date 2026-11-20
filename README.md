# SSC: secure-string-cipher

Local file encryption where every file carries its own access rules.

You encrypt a file once, with its own random key. The file says what can
unlock that key: a password, a key file, an entry in your SSC vault, a
recovery code, or several of these together. SSC runs on Linux, macOS and
Windows, and in Docker. It has no server, and nothing leaves your machine.

SSC 3.0 cannot read files made by 2.x. To move them, decrypt them with 2.x
first, then encrypt them with 3.0.

## Install

SSC needs Python 3.13 or newer.

```sh
uv tool install secure-string-cipher
# or
pipx install secure-string-cipher
```

## The guided way

Run `ssc` with no arguments in a terminal. It asks what you want to do, with
arrow keys and Enter, and every question has a safe default:

```text
SSC  ·  no vault yet
? What do you want to do?
❯ Encrypt a file
  Decrypt a file
  Vault
  Keys
  Settings
  Quit
```

## On the command line

```sh
ssc encrypt report.pdf                 # asks for a password, writes report.pdf.ssc
ssc decrypt report.pdf.ssc             # writes report.pdf

ssc vault init                         # a vault, unlocked by this device's keychain
ssc vault add laptop --key             # a key kept in the vault
ssc encrypt report.pdf --grant "password+vault:laptop" --recovery-code
ssc access show report.pdf.ssc         # g1: password + key "laptop"
                                       # g2: recovery code
```

- **Ways in:** `--grant` takes one way in. Factors joined by `+` are all
  needed, and each further `--grant` adds another way in, any one of which
  opens the file. `--recovery-code` adds a recovery code, shown once.
- **Profiles** save a set of ways in: `ssc profile create daily --grant
  vault:laptop`, then `ssc encrypt report.pdf --profile daily`.
- **Changing access:** `ssc access add`, `remove`, `rotate` and `apply`.
  Removing a way in doesn't affect copies someone already has. Rotating
  re-encrypts the file under a new key, so it protects the file's new
  contents.
- **Text:** `ssc encrypt - -o - --armor` encrypts stdin to armoured text,
  and `ssc decrypt -` detects armour by itself.
- **Other commands:** `ssc generate` prints a passphrase, `ssc key` manages
  standalone `.ssckey` files, and `ssc shred` overwrites a file before
  deleting it.

Every command is listed in the [CLI contract](docs/spec/CLI.md), and `ssc
<command> --help` describes it.

## In scripts

Without a TTY, SSC never waits for input. A credential that is needed but
not supplied is an error. Credentials come from files or environment
variables, such as `--password-file` or `SSC_PASSWORD`, and
`--master-password-file` or `SSC_MASTER_PASSWORD`. A credential file must
not be readable by other users.

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Input error, including a credential that is needed but not supplied |
| 2 | Cannot open: the credentials given do not open it |
| 3 | Vault error |
| 4 | File error: not found, not an SSC file, damaged or truncated |
| 70 | A bug in SSC |

## Docker

```sh
docker build -t ssc .
mkdir -m 700 -p ~/.ssc-docker
docker run --rm -it --network=none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v ~/.ssc-docker:/ssc ssc
```

- **Running:** with no arguments in a terminal, this runs the guided mode.
  Add a command, such as `encrypt report.pdf`, to run it instead.
- **Folders:** `/work` is the folder files are read from and written to.
  `/ssc` holds the vault and settings, so they outlive each container.
- **Keychain:** a container has no OS keychain, so SSC asks for the master
  password. Scripts can pass `--env SSC_MASTER_PASSWORD` and the other
  variables listed in [CLI.md](docs/spec/CLI.md) section 1.
- **Ownership:** `--user` makes the files it writes yours.

The image installs exactly the hash-locked versions in `uv.lock`, from
wheels only, and has no compiler.

## Security

A file is only as strong as its weakest way in. SSC protects a file's
contents at rest, and detects any change to it. It doesn't protect you
against someone who controls your computer while you unlock a file.

- **Threat model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) says
  exactly what SSC protects and what it doesn't.
- **Reporting:** report a vulnerability privately, as the
  [security policy](SECURITY.md) explains.
- **Specs:** [FORMAT.md](docs/spec/FORMAT.md),
  [ACCESS.md](docs/spec/ACCESS.md), [VAULT.md](docs/spec/VAULT.md) and
  [CLI.md](docs/spec/CLI.md) specify the file format, the access rules,
  the vault and the commands.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under the [MIT licence](LICENSE).
