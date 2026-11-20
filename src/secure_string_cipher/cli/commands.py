"""What each `ssc` command does: it calls the service layer and prints the
result. Results go to stdout; messages go to stderr through the prompter."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher.errors import InputError, SSCError
from secure_string_cipher.service import (
    access_ops,
    files,
    keys,
    passwords,
    profile_ops,
    settings,
    shred,
    vaults,
)
from secure_string_cipher.service.context import Context

Handler = Callable[[argparse.Namespace, Context], None]
STDIO = "-"


def out(text: str = "") -> None:
    print(text, flush=True)


# --- files ----------------------------------------------------------------------------


def _stdin() -> BinaryIO:
    return sys.stdin.buffer


def _stdout() -> BinaryIO:
    return sys.stdout.buffer


def _target(name: str) -> files.Output:
    return _stdout() if name == STDIO else Path(name)


def encrypt(args: argparse.Namespace, ctx: Context) -> None:
    if args.output is None:
        if args.file == STDIO:
            raise InputError("Encrypting stdin needs -o, such as -o - for stdout.")
        args.output = args.file + ".ssc"
    choice = files.Choice(
        grant_specs=args.grant,
        vault_label=args.vault,
        profile=args.profile,
        recovery_code=args.recovery_code,
    )
    output = _target(args.output)
    if args.file == STDIO:
        files.encrypt(
            ctx, _stdin(), output, choice, armored=args.armor, force=args.force
        )
    else:
        with Path(args.file).open("rb") as source:
            files.encrypt(
                ctx, source, output, choice, armored=args.armor, force=args.force
            )
    if args.output != STDIO:
        ctx.prompter.notice(f"Wrote {args.output}")


def decrypt(args: argparse.Namespace, ctx: Context) -> None:
    if args.output is None:
        name = Path(args.file).name
        # A name that is only ".ssc" would leave nothing to write to.
        if args.file == STDIO or not name.endswith(".ssc") or name == ".ssc":
            raise InputError(
                "Give the output with -o: no name can be made for it from the input."
            )
        args.output = args.file.removesuffix(".ssc")
    output = _target(args.output)
    if args.file == STDIO:
        files.decrypt(ctx, _stdin(), output, force=args.force)
    else:
        with Path(args.file).open("rb") as source:
            files.decrypt(ctx, source, output, force=args.force)
    if args.output != STDIO:
        ctx.prompter.notice(f"Wrote {args.output}")


# --- access ---------------------------------------------------------------------------


def access(args: argparse.Namespace, ctx: Context) -> None:
    match args.action:
        case "show":
            for line in access_ops.show(ctx, args.file):
                out(line)
        case "add":
            access_ops.add(ctx, args.file, args.grant)
            ctx.prompter.notice(f"Added a way in to {args.file}.")
        case "remove":
            access_ops.remove(ctx, args.file, args.grant)
        case "rotate":
            access_ops.rotate(ctx, args.file, force=args.force)
        case "apply":
            access_ops.apply(ctx, args.file, args.profile)
            ctx.prompter.notice(f'{args.file} now unlocks as profile "{args.profile}".')


# --- vault ----------------------------------------------------------------------------


def _change_password(ctx: Context) -> None:
    """With a recovery code supplied and no master password, the code opens
    the vault instead: it covers a forgotten master password (VAULT.md
    section 2)."""
    if ctx.recovery_codes and ctx.master_password is None:
        vaults.reset_password(ctx, ctx.recovery_codes[0])
    else:
        vaults.change_password(ctx)
    ctx.prompter.notice("Changed the master password.")


def _add(args: argparse.Namespace, ctx: Context) -> None:
    if (args.generate and not args.password) or (args.show and not args.generate):
        raise InputError("--generate goes with --password, and --show with --generate.")
    if args.password:
        generated = passwords.generate() if args.generate else None
        vaults.add_password(ctx, args.label, generated)
        if generated and args.show:
            out(generated)
    elif args.key:
        vaults.add_key(ctx, args.label)
    else:
        vaults.add_recovery(ctx, args.label)
    ctx.prompter.notice(f'Added "{args.label}" to the vault.')


def _status(ctx: Context) -> None:
    status = vaults.status(ctx)
    out(f"Vault: {status.state.value} ({ctx.vault_path})")
    if status.entries is not None:
        out(f"Entries: {status.entries}")
        out(f"Profiles: {status.profiles}")
        out(f"History: {'on' if status.history else 'off'}")


def _list(ctx: Context) -> None:
    for e in vaults.list_entries(ctx):
        out(f"{e.label}\t{e.kind}\t{e.status}\t{e.created}")


def _revoke(args: argparse.Namespace, ctx: Context) -> None:
    found = vaults.revoke(ctx, args.label, scan=args.scan)
    if args.scan is None:
        return
    if not found:
        ctx.prompter.notice(f'No file under {args.scan} uses "{args.label}".')
        return
    for path in found:
        out(str(path))
    if not ctx.prompter.confirm(
        f"Rotate these {len(found)} files now, so the revoked secret no longer "
        "opens their future contents?",
        default=False,
    ):
        return
    failed = 0
    for path in found:  # one file failing does not stop the rest
        try:
            access_ops.rotate(ctx, path, without=args.label)
        except (SSCError, OSError) as error:
            failed += 1
            reason = error.strerror if isinstance(error, OSError) else None
            ctx.prompter.notice(f"{path}: {reason or error}")
    if failed:
        raise OSError(f"{failed} of {len(found)} files could not be rotated.")


def _history(args: argparse.Namespace, ctx: Context) -> None:
    match args.switch:
        case "on":
            vaults.history_on(ctx)
            ctx.prompter.notice("History is on.")
        case "off":
            vaults.history_off(ctx)
            ctx.prompter.notice("History is off, and what it held is gone.")
        case "show":
            shown = vaults.history_show(ctx)
            if shown is None:
                ctx.prompter.notice(
                    "History is off. Turn it on with ssc vault history on."
                )
                return
            labels = {e.id: e.label for e in vaults.list_entries(ctx)}
            for event in shown.events:
                name = labels.get(event.entry, "") if event.entry else ""
                out(f"{event.at}\t{event.action}\t{name}".rstrip())


def vault(args: argparse.Namespace, ctx: Context) -> None:
    match args.action:
        case "init":
            vaults.init(
                ctx, device_key=not args.no_device_key, recovery_code=args.recovery_code
            )
            ctx.prompter.notice(f"Created the vault at {ctx.vault_path}.")
        case "status":
            _status(ctx)
        case "add":
            _add(args, ctx)
        case "list":
            _list(ctx)
        case "archive":
            vaults.archive(ctx, args.label)
            ctx.prompter.notice(f'Archived "{args.label}".')
        case "revoke":
            _revoke(args, ctx)
        case "change-password":
            _change_password(ctx)
        case "add-device":
            index = vaults.add_device(ctx)
            ctx.prompter.notice(f"This device can now unlock the vault (g{index + 1}).")
        case "remove-device":
            vaults.remove_device(ctx, args.grant)
        case "backup":
            vaults.backup(ctx, args.path)
        case "history":
            _history(args, ctx)


# --- keys, profiles and the rest ------------------------------------------------------


def key(args: argparse.Namespace, ctx: Context) -> None:
    match args.action:
        case "new":
            made = keys.new(args.path, args.label)
            ctx.prompter.notice(f'Wrote key "{made.label}" to {args.path}.')
        case "import":
            label = keys.import_(ctx, args.path, args.label)
            ctx.prompter.notice(f'Imported {args.path} as vault key "{label}".')
        case "export":
            keys.export(ctx, args.label, args.path)
            ctx.prompter.notice(f'Wrote vault key "{args.label}" to {args.path}.')


def profile(args: argparse.Namespace, ctx: Context) -> None:
    match args.action:
        case "create":
            profile_ops.create(ctx, args.name, args.grant)
            ctx.prompter.notice(f'Saved profile "{args.name}".')
        case "list":
            default = settings.load().default_profile
            for p in profile_ops.list_(ctx):
                out(p.name + ("\t(default)" if p.name == default else ""))
        case "show":
            for line in profile_ops.show(ctx, args.name):
                out(line)
        case "delete":
            profile_ops.delete(ctx, args.name)
            ctx.prompter.notice(f'Deleted profile "{args.name}".')
        case "default":
            name = None if args.none else args.name
            profile_ops.set_default(ctx, name)
            ctx.prompter.notice(
                f'New files now unlock as profile "{name}" by default.'
                if name
                else "There is no default profile now."
            )


def generate(args: argparse.Namespace, ctx: Context) -> None:
    out(passwords.generate(args.words))


def shred_(args: argparse.Namespace, ctx: Context) -> None:
    if not args.force:
        ctx.prompter.notice(shred.WARNING)
        if not ctx.prompter.confirm(f"Shred {args.file}?", default=False):
            raise InputError("Not shredded. Use --force to shred without asking.")
    shred.shred(args.file)
    ctx.prompter.notice(f"Shredded {args.file}.")


HANDLERS: dict[str, Handler] = {
    "encrypt": encrypt,
    "decrypt": decrypt,
    "access": access,
    "vault": vault,
    "key": key,
    "profile": profile,
    "generate": generate,
    "shred": shred_,
}
