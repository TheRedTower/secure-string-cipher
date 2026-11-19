"""The guided flow (CLI.md section 4): what `ssc` with no arguments runs in
a terminal. Every screen calls the same service layer as the command line,
and every prompt has a safe default, so pressing Enter all the way through
works. It says "unlock with", never "grant" or "factor"."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from secure_string_cipher.errors import InputError, SSCError
from secure_string_cipher.interactive.ui import Back, Ui
from secure_string_cipher.service import (
    access_ops,
    files,
    keys,
    profile_ops,
    settings,
    vaults,
)
from secure_string_cipher.service.context import Context
from secure_string_cipher.service.vaults import State
from secure_string_cipher.vault import document as doc

Screen = Callable[[Context, Ui], None]


def _path(answer: str) -> Path:
    """A typed or dragged-in path: terminals quote a dragged file, or escape
    its spaces."""
    text = answer.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    elif "\\ " in text:
        text = text.replace("\\ ", " ")
    if not text:
        raise InputError("No file was given.")
    return Path(text).expanduser()


def _plural(n: int, word: str, words: str | None = None) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {words or word + 's'}"


def _entries(ctx: Context, *kinds: str) -> list[doc.Entry]:
    document = vaults.peek(ctx)  # None if locked here: then ask
    found = vaults.list_entries(ctx) if document is None else document.entries
    return [e for e in found if e.status == "active" and (not kinds or e.kind in kinds)]


def _pick_entry(ctx: Context, ui: Ui, question: str, *kinds: str) -> doc.Entry:
    found = _entries(ctx, *kinds)
    if not found:
        raise InputError("The vault has no entry of that kind yet.")
    return found[ui.select(question, [f'"{e.label}"  ({e.kind})' for e in found])]


# --- encrypt (4.2) -------------------------------------------------------------------


def _profiles(ctx: Context) -> list[tuple[str, str]]:
    """Each saved profile, with its ways in in plain words."""
    document = vaults.peek(ctx)
    if document is None:
        return []
    found = []
    for profile in document.profiles:
        lines = profile_ops.show(ctx, profile.name)
        words = " or ".join(line.split(": ", 1)[1] for line in lines)
        found.append((profile.name, words))
    return found


def _ways(ctx: Context, ui: Ui) -> tuple[list[str], str]:
    """ "Something else…": ways in built step by step, as grant specs, and
    how to say them."""
    options = ["A password I'll type"]
    tokens = ["password"]
    names = ["a password"]
    for entry in _entries(ctx) if vaults.exists(ctx) else []:
        options.append(f'Vault entry "{entry.label}"')
        tokens.append(f"vault:{entry.label}")
        names.append(f'vault entry "{entry.label}"')
    options += ["A key file…", "A recovery code"]
    tokens += ["keyfile:", "recovery"]
    names += ["", "a recovery code"]
    specs: list[str] = []
    words: list[str] = []
    while True:
        picked = ui.checkbox("Unlock needs all of…", options)
        if not picked:
            if specs:
                break
            raise InputError("Choose at least one way to unlock it.")
        parts, said = [], []
        for i in picked:
            token, name = tokens[i], names[i]
            if token == "keyfile:":
                key = _path(ui.path("Which key file?"))
                token, name = f"keyfile:{key}", f"key file {key.name}"
            parts.append(token)
            said.append(name)
        specs.append("+".join(parts))
        words.append(" + ".join(said))
        if not ui.confirm(
            "Add another way in? Any one of these opens it…", default=False
        ):
            break
    return specs, " or ".join(words)


def _how(ctx: Context, ui: Ui) -> tuple[files.Choice, str]:
    saved = _profiles(ctx)
    options = [f"{name}  ({words})" for name, words in saved]
    options += [
        "A password I'll type",
        "A saved vault entry…",
        "A key file…",
        "Something else…",
    ]
    pick = ui.select("How should it unlock?", options)
    if pick < len(saved):
        name = saved[pick][0]
        return files.Choice(profile=name), f'profile "{name}"'
    match pick - len(saved):
        case 0:
            return files.Choice(grant_specs=["password"]), "a password"
        case 1:
            entry = _pick_entry(ctx, ui, "Which vault entry?")
            return files.Choice(vault_label=entry.label), f'vault entry "{entry.label}"'
        case 2:
            key = _path(ui.path("Which key file?"))
            return files.Choice(grant_specs=[f"keyfile:{key}"]), f"key file {key.name}"
    specs, words = _ways(ctx, ui)
    return files.Choice(grant_specs=specs), words


def _replace(ui: Ui, out: Path) -> bool | None:
    """None to stop; otherwise whether to replace."""
    if not out.exists():
        return False
    return True if ui.confirm(f"{out} exists. Replace it?", default=False) else None


def encrypt(ctx: Context, ui: Ui) -> None:
    source = _path(ui.path("Which file?"))
    if not source.is_file():
        raise InputError(f"{source} is not a file.")
    out = source.with_name(source.name + ".ssc")
    choice, words = _how(ctx, ui)
    force = _replace(ui, out)
    if force is None:
        return
    if not ui.confirm(
        f"Encrypt {source.name} to {out.name}, unlocked by {words}. Go?", default=True
    ):
        return
    with source.open("rb") as handle:
        files.encrypt(ctx, handle, out, choice, force=force)
    ui.say(f"✓ Wrote {out}")


# --- decrypt (4.3) -------------------------------------------------------------------


def decrypt(ctx: Context, ui: Ui) -> None:
    source = _path(ui.path("Which file?"))
    with source.open("rb") as handle:
        opening = files.open_file(ctx, handle)
        if not opening.asked():
            document = opening.opener.document
            factors = opening.grant.factors or ()
            how = " + ".join(access_ops.describe(f, document) for f in factors)
            ui.say(f"This file opens with your {how}.")
        if source.name.endswith(".ssc") and len(source.name) > 4:
            out = source.with_name(source.name.removesuffix(".ssc"))
        else:
            out = _path(ui.path("Decrypt to which file?", str(source) + ".out"))
        force = _replace(ui, out)
        if force is None:
            return
        if not ui.confirm(f"Decrypt to {out.name}?", default=True):
            return
        files.write_plaintext(opening, out, force=force)
    ui.say(f"✓ Wrote {out}")


# --- vault (4.4) ---------------------------------------------------------------------


def _init(ctx: Context, ui: Ui) -> bool:
    if not ui.confirm("There is no vault yet. Create one?", default=True):
        return False
    code = ui.confirm(
        "Also make a recovery code for the vault, in case you forget the "
        "master password?",
        default=False,
    )
    vaults.init(ctx, recovery_code=code)
    ui.say(f"✓ Created the vault at {ctx.vault_path}")
    return True


def _archive_or_revoke(ctx: Context, ui: Ui) -> None:
    entry = _pick_entry(ctx, ui, "Which entry?")
    what = ui.select(
        f'Archive or revoke "{entry.label}"?',
        [
            "Archive it: keep it for opening, stop offering it",
            "Revoke it: refuse it from now on",
            "Back",
        ],
        default=2,
    )
    if what == 0:
        vaults.archive(ctx, entry.label)
        ui.say(f'✓ Archived "{entry.label}"')
        return
    if what != 1:
        return
    answer = ui.path("Folder to search for files it opens (Enter to skip)").strip()
    folder = _path(answer) if answer else None
    found = vaults.revoke(ctx, entry.label, scan=folder)
    ui.say(f'✓ Revoked "{entry.label}"')
    if folder is None:
        return
    if not found:
        ui.say(f"No file under {folder} uses it.")
        return
    for path in found:
        ui.say(f"  {path}")
    if ui.confirm(
        f"Rotate these {_plural(len(found), 'file')}, so the revoked secret no "
        "longer opens their future contents?",
        default=False,
    ):
        for path in found:
            try:
                access_ops.rotate(ctx, path, without=entry.label)
            except SSCError as error:
                ui.say(f"✗ {path}: {error}")


def vault(ctx: Context, ui: Ui) -> None:
    if not vaults.exists(ctx) and not _init(ctx, ui):
        return
    while True:
        status = vaults.status(ctx)
        if status.entries is None:
            ui.say(f"Vault  ·  {status.state.value}")
        else:
            ui.say(
                f"Vault  ·  {_plural(status.entries, 'entry', 'entries')}, "
                f"{_plural(status.profiles or 0, 'profile')}, {status.state.value}"
            )
        pick = ui.select(
            "What do you want to do?",
            [
                "Add a password",
                "Add a key",
                "Add a recovery code",
                "Show entries",
                "Archive or revoke an entry",
                "Change master password",
                "Back up the vault",
                "Back",
            ],
            default=7,
        )
        if pick == 7:
            return
        try:
            _vault_action(ctx, ui, pick)
        except Back:
            continue
        except (SSCError, OSError) as error:
            ui.say(f"✗ {_message(error)}")


def _label(ui: Ui, question: str, default: str = "") -> str:
    return vaults.check_label(ui.text(question, default).strip())


def _vault_action(ctx: Context, ui: Ui, pick: int) -> None:
    match pick:
        case 0:
            label = _label(ui, "Label for this password?")
            vaults.add_password(ctx, label)
            ui.say(f'✓ Added "{label}"')
        case 1:
            label = _label(ui, "Label for this key?")
            vaults.add_key(ctx, label)
            ui.say(f'✓ Added "{label}"')
        case 2:
            label = _label(ui, "Label for this recovery code?", "recovery")
            vaults.add_recovery(ctx, label)
            ui.say(f'✓ Added "{label}"')
        case 3:
            for e in vaults.list_entries(ctx):
                ui.say(f'  "{e.label}"  {e.kind}, {e.status}, made {e.created}')
        case 4:
            _archive_or_revoke(ctx, ui)
        case 5:
            vaults.change_password(ctx)
            ui.say("✓ Changed the master password")
        case 6:
            path = _path(
                ui.path("Back up the vault to which file?", "vault-backup.ssc")
            )
            vaults.backup(ctx, path)
            ui.say(f"✓ Wrote {path}")


# --- keys (4.5) ----------------------------------------------------------------------


def keys_screen(ctx: Context, ui: Ui) -> None:
    pick = ui.select(
        "Keys",
        [
            "Export a key to a file",
            "Import a key file",
            "Create a standalone key file",
            "Back",
        ],
        default=3,
    )
    match pick:
        case 0:
            entry = _pick_entry(ctx, ui, "Which key?", "key")
            path = _path(ui.path("Write it to which file?", f"{entry.label}.ssckey"))
            keys.export(ctx, entry.label, path)
            ui.say(f"✓ Wrote {path}")
        case 1:
            path = _path(ui.path("Which key file?"))
            label = ui.text("Label in the vault? (Enter keeps the file's)").strip()
            saved = keys.import_(
                ctx, path, vaults.check_label(label) if label else None
            )
            ui.say(f'✓ Imported as "{saved}"')
        case 2:
            path = _path(ui.path("Write the new key file where?", "key.ssckey"))
            label = ui.text("Label? (Enter names it after the file)").strip()
            made = keys.new(path, vaults.check_label(label) if label else None)
            ui.say(f'✓ Wrote key "{made.label}" to {path}')


# --- settings (4.6) ------------------------------------------------------------------


def _default_profile(ctx: Context, ui: Ui) -> None:
    names = [p.name for p in profile_ops.list_(ctx)]
    current = settings.load().default_profile
    options = [*names, "None"]
    default = names.index(current) if current in names else len(names)
    pick = ui.select("Default profile for new files?", options, default=default)
    name = None if pick == len(names) else names[pick]
    profile_ops.set_default(ctx, name)
    ui.say(f"✓ Default profile: {name or 'none'}")


def _keychain(ctx: Context, ui: Ui) -> None:
    index = vaults.this_device(ctx)
    if index is None:
        vaults.add_device(ctx)
        ui.say("✓ This device's keychain now unlocks the vault")
    elif ui.confirm(
        "Stop using this device's keychain? The vault will ask for its master "
        "password here.",
        default=False,
    ):
        vaults.remove_device(ctx, f"g{index + 1}")


def _history(ctx: Context, ui: Ui) -> None:
    on = vaults.history_show(ctx) is not None
    pick = ui.select(
        f"History is {'on' if on else 'off'}.",
        ["Turn it off" if on else "Turn it on", "Show it", "Back"],
        default=2,
    )
    if pick == 0 and on:
        if ui.confirm("Turn history off? What it holds is deleted.", default=False):
            vaults.history_off(ctx)
            ui.say("✓ History is off")
    elif pick == 0:
        vaults.history_on(ctx)
        ui.say("✓ History is on")
    elif pick == 1:
        shown = vaults.history_show(ctx)
        if shown is None:
            ui.say("History is off.")
            return
        labels = {e.id: e.label for e in vaults.list_entries(ctx)}
        for event in shown.events:
            name = labels.get(event.entry, "") if event.entry else ""
            ui.say(f"  {event.at}  {event.action}  {name}".rstrip())


def settings_screen(ctx: Context, ui: Ui) -> None:
    if not vaults.exists(ctx):
        ui.say("These settings live in the vault. Create one under Vault first.")
        return
    default = settings.load().default_profile
    keychain = "on" if vaults.this_device(ctx) is not None else "off"
    pick = ui.select(
        "Settings",
        [
            f"Default profile: {default or 'none'}",
            f"Use this device's keychain: {keychain}",
            "History",
            "Back",
        ],
        default=3,
    )
    match pick:
        case 0:
            _default_profile(ctx, ui)
        case 1:
            _keychain(ctx, ui)
        case 2:
            _history(ctx, ui)


# --- start (4.1) ---------------------------------------------------------------------


def _message(error: BaseException) -> str:
    if isinstance(error, OSError) and error.strerror and error.filename:
        return f"{error.filename}: {error.strerror}."
    return str(error)


def _header(ctx: Context) -> str:
    state = vaults.status(ctx).state
    if state is State.NONE:
        return "SSC  ·  no vault yet"
    return f"SSC  ·  vault {state.value}"


SCREENS: list[Screen] = [encrypt, decrypt, vault, keys_screen, settings_screen]


def run(ctx: Context, ui: Ui) -> int:
    """The start screen, until Quit or Ctrl-C."""
    while True:
        ui.say(_header(ctx))
        try:
            pick = ui.select(
                "What do you want to do?",
                [
                    "Encrypt a file",
                    "Decrypt a file",
                    "Vault",
                    "Keys",
                    "Settings",
                    "Quit",
                ],
            )
        except Back:
            return 0
        if pick == len(SCREENS):
            return 0
        try:
            SCREENS[pick](ctx, ui)
        except Back:
            continue
        except (SSCError, OSError) as error:
            ui.say(f"✗ {_message(error)}")
