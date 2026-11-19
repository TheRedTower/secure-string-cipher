"""The `ssc` command line, exactly as CLI.md section 3 lists it."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import NoReturn

from secure_string_cipher.errors import InputError


class Parser(argparse.ArgumentParser):
    """Bad arguments are exit 1 (CLI.md section 1), not argparse's 2."""

    def error(self, message: str) -> NoReturn:
        raise InputError(f"{self.prog}: {message}. See {self.prog} --help.")


def _credentials() -> Parser:
    """Credential sources and --debug, accepted by every command."""
    common = Parser(add_help=False)
    common.add_argument(
        "--debug", action="store_true", help="show a traceback on an error"
    )
    group = common.add_argument_group("credentials without a prompt")
    group.add_argument(
        "--password-file",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help="a password that opens a file (up to 5; SSC_PASSWORD adds one more)",
    )
    group.add_argument(
        "--new-password-file",
        type=Path,
        metavar="PATH",
        help="a new password to set (SSC_NEW_PASSWORD)",
    )
    group.add_argument(
        "--master-password-file",
        type=Path,
        metavar="PATH",
        help="the vault's master password (SSC_MASTER_PASSWORD)",
    )
    group.add_argument(
        "--new-master-password-file",
        type=Path,
        metavar="PATH",
        help="a new master password (SSC_NEW_MASTER_PASSWORD)",
    )
    group.add_argument(
        "--recovery-code-file",
        type=Path,
        metavar="PATH",
        help="a recovery code (SSC_RECOVERY_CODE)",
    )
    group.add_argument(
        "--key-file",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help="a standalone .ssckey (repeatable; SSC_KEY_FILES)",
    )
    return common


def build() -> Parser:
    common = _credentials()
    root = Parser(
        prog="ssc",
        description="Encrypt files so that each one carries its own access rules.",
    )
    commands = root.add_subparsers(
        dest="command", metavar="COMMAND", parser_class=Parser
    )

    def command(
        group: argparse._SubParsersAction[Parser], name: str, help: str
    ) -> Parser:
        """A command that runs. Only these take credentials and --debug: a
        flag on a parent parser would be reset by the child's default."""
        return group.add_parser(name, help=help, description=help, parents=[common])

    def family(name: str, help: str) -> argparse._SubParsersAction[Parser]:
        """A command with actions, such as `ssc vault <action>`."""
        parent = commands.add_parser(name, help=help, description=help)
        actions = parent.add_subparsers(
            dest="action", metavar="ACTION", parser_class=Parser
        )
        actions.required = True
        return actions

    # 3.1 Files
    enc = command(commands, "encrypt", "encrypt a file")
    enc.add_argument("file", help="the file, or - for stdin")
    how = enc.add_mutually_exclusive_group()
    how.add_argument("--profile", metavar="NAME", help="unlock as a saved profile")
    how.add_argument(
        "--vault", metavar="LABEL", help="shorthand for --grant vault:LABEL"
    )
    how.add_argument(
        "--grant",
        action="append",
        default=[],
        metavar="SPEC",
        help="one way in, such as password+vault:laptop (repeatable)",
    )
    enc.add_argument(
        "--recovery-code", action="store_true", help="also add a recovery grant"
    )
    enc.add_argument("-o", dest="output", metavar="OUT", help="output, or - for stdout")
    enc.add_argument("--armor", action="store_true", help="write armoured text")
    enc.add_argument("--force", action="store_true", help="replace an existing output")

    dec = command(commands, "decrypt", "decrypt a file")
    dec.add_argument("file", help="the file, or - for stdin")
    dec.add_argument("-o", dest="output", metavar="OUT", help="output, or - for stdout")
    dec.add_argument("--force", action="store_true", help="replace an existing output")

    # 3.2 Access
    acts = family("access", "see or change who can open a file")
    show = command(acts, "show", "list a file's ways in")
    show.add_argument("file", type=Path)
    add = command(acts, "add", "add a way in")
    add.add_argument("file", type=Path)
    add.add_argument("--grant", required=True, metavar="SPEC")
    remove = command(acts, "remove", "remove a way in")
    remove.add_argument("file", type=Path)
    remove.add_argument("--grant", required=True, metavar="gN")
    rotate = command(acts, "rotate", "re-encrypt under a new file key")
    rotate.add_argument("file", type=Path)
    rotate.add_argument(
        "--force", action="store_true", help="drop what cannot be rebuilt, unasked"
    )
    apply = command(acts, "apply", "replace a file's ways in with a profile's")
    apply.add_argument("file", type=Path)
    apply.add_argument("--profile", required=True, metavar="NAME")

    # 3.3 Vault
    ops = family("vault", "the vault of saved secrets")
    init = command(ops, "init", "create the vault")
    init.add_argument("--no-device-key", action="store_true")
    init.add_argument("--recovery-code", action="store_true")
    command(ops, "status", "what the vault holds, without asking for anything")
    vadd = command(ops, "add", "add an entry")
    vadd.add_argument("label")
    kind = vadd.add_mutually_exclusive_group(required=True)
    kind.add_argument("--password", action="store_true")
    kind.add_argument("--key", action="store_true")
    kind.add_argument("--recovery-code", action="store_true")
    vadd.add_argument(
        "--generate", action="store_true", help="with --password: a passphrase"
    )
    vadd.add_argument(
        "--show", action="store_true", help="with --generate: print it once"
    )
    command(ops, "list", "list the entries")
    command(ops, "archive", "archive an entry").add_argument("label")
    revoke = command(ops, "revoke", "revoke an entry")
    revoke.add_argument("label")
    revoke.add_argument(
        "--scan",
        type=Path,
        metavar="FOLDER",
        help="list the files under FOLDER that the entry opens, and offer to "
        "rotate them",
    )
    command(ops, "change-password", "change the master password")
    command(ops, "add-device", "let this device unlock the vault")
    command(ops, "remove-device", "remove a device's way in").add_argument(
        "grant", metavar="gN"
    )
    command(ops, "backup", "copy the encrypted vault").add_argument("path", type=Path)
    history = command(ops, "history", "the opt-in history")
    history.add_argument("switch", choices=["on", "off", "show"])

    # 3.4 Keys, profiles and the rest
    keys = family("key", "standalone key files")
    knew = command(keys, "new", "write a new .ssckey")
    knew.add_argument("path", type=Path)
    knew.add_argument("--label")
    kimp = command(keys, "import", "add a key file to the vault")
    kimp.add_argument("path", type=Path)
    kimp.add_argument("--label")
    kexp = command(keys, "export", "write a vault key entry as a key file")
    kexp.add_argument("label")
    kexp.add_argument("path", type=Path)

    profs = family("profile", "saved ways to unlock new files")
    pcreate = command(profs, "create", "save a profile")
    pcreate.add_argument("name")
    pcreate.add_argument("--grant", action="append", required=True, metavar="SPEC")
    command(profs, "list", "list the profiles")
    command(profs, "show", "show a profile").add_argument("name")
    command(profs, "delete", "delete a profile").add_argument("name")
    default = command(profs, "default", "set or clear the default profile")
    which = default.add_mutually_exclusive_group(required=True)
    which.add_argument("name", nargs="?")
    which.add_argument("--none", action="store_true")

    gen = command(commands, "generate", "print a random passphrase")
    gen.add_argument("--words", type=int, default=6, metavar="N")

    shred = command(commands, "shred", "overwrite a file, then delete it")
    shred.add_argument("file", type=Path)
    shred.add_argument("--force", action="store_true", help="do not ask first")
    return root
