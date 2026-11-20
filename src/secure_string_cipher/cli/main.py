"""`ssc`: parse the command line, run the command, and turn any error into
one plain sentence on stderr and an exit code (CLI.md section 1)."""

from __future__ import annotations

import sys
import traceback
from collections.abc import Sequence

from secure_string_cipher.cli import commands, parser, sources
from secure_string_cipher.cli.prompter import CliPrompter, StdTerminal, Terminal
from secure_string_cipher.errors import (
    CannotOpen,
    FormatError,
    InputError,
    RecoveryCodeError,
    SSCError,
    VaultError,
)
from secure_string_cipher.interactive import flow
from secure_string_cipher.interactive.prompter import UiPrompter
from secure_string_cipher.interactive.ui import QuestionaryUi, Ui
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import store

OK = 0
INPUT = 1
CANNOT_OPEN = 2
VAULT = 3
FILE = 4
INTERNAL = 70


def exit_code(error: BaseException) -> int:
    if isinstance(error, InputError | RecoveryCodeError | KeyboardInterrupt | EOFError):
        return INPUT
    if isinstance(error, CannotOpen):
        return CANNOT_OPEN
    if isinstance(error, VaultError):
        return VAULT
    if isinstance(error, FormatError | OSError):
        return FILE
    return INTERNAL


def message(error: BaseException) -> str:
    """One plain sentence, never a secret: SSC's own errors are written
    that way, an OS error gives only its reason and path, and anything else
    is a bug whose details appear only with --debug."""
    if isinstance(error, KeyboardInterrupt):
        return "Cancelled."
    if isinstance(error, EOFError):
        return "Cancelled: the input ended before an answer was given."
    if isinstance(error, OSError) and error.strerror and error.filename:
        return f"{error.filename}: {error.strerror}."
    if isinstance(error, SSCError | OSError):
        return str(error)
    return "SSC hit an internal error. Run the command again with --debug for details."


def main(
    argv: Sequence[str] | None = None,
    terminal: Terminal | None = None,
    ui: Ui | None = None,
) -> int:
    """`ssc`. With no arguments in a terminal, the guided flow (CLI.md
    section 4); without one, the help and exit 1. `terminal` and `ui` are
    for tests."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    debug = "--debug" in args_list
    try:
        args = parser.build().parse_args(args_list)
        if args.command is None:
            if ui is None and not (terminal or StdTerminal()).interactive():
                parser.build().print_help(sys.stderr)
                return INPUT
            return _guided(ui or QuestionaryUi())
        given = sources.gather(
            password_files=args.password_file,
            new_password_file=args.new_password_file,
            master_password_file=args.master_password_file,
            new_master_password_file=args.new_master_password_file,
            recovery_code_file=args.recovery_code_file,
            key_files=args.key_file,
        )
        ctx = Context(
            CliPrompter(given, terminal),
            vault_path=store.default_path(),
            passwords=given.passwords,
            recovery_codes=[given.recovery_code] if given.recovery_code else [],
            key_files=given.key_files,
            master_password=given.master_password,
        )
        commands.HANDLERS[args.command](args, ctx)
    except (Exception, KeyboardInterrupt) as error:
        if debug:
            traceback.print_exc()
        print(f"ssc: {message(error)}", file=sys.stderr)
        return exit_code(error)
    return OK


def _guided(ui: Ui) -> int:
    """Credentials from the environment still count, so a script can set
    SSC_MASTER_PASSWORD; everything else is asked."""
    given = sources.gather()
    ctx = Context(
        UiPrompter(ui),
        vault_path=store.default_path(),
        ask_key_file=lambda: flow.ask_path(ui, "Which key file?"),
        passwords=given.passwords,
        recovery_codes=[given.recovery_code] if given.recovery_code else [],
        key_files=given.key_files,
        master_password=given.master_password,
    )
    return flow.run(ctx, ui)
