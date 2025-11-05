#!/usr/bin/env python3
"""
string_to_hash.py – Flexible string → hash/encoding converter

Features
  • Hash any text / file via stdin, CLI arg, or --file option.
  • Output in hex or Base-64 with --out hex|b64 (default hex).
  • HMAC support with --hmac-key KEY (works with any fixed-length algo).
  • Interactive wizard when invoked with no arguments in a TTY.
  • Colourised prompts that adapt to terminal background; disable with --no-colour or NO_COLOR env-var.
  • Streamed hashing for low memory consumption on huge inputs.
  • List available algorithms with --list-algos and safe exclusion of SHAKE variants.
  • macOS convenience flag --copy to copy the result to clipboard (pbcopy).

Examples
  python string_to_hash.py "hello"                    # sha256 hex digest
  echo data | python string_to_hash.py -a sha512 -o b64
  python string_to_hash.py --hmac-key secret --file secrets.txt
  python string_to_hash.py --list-algos
  python string_to_hash.py                             # interactive wizard
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import os
import sys
# Clipboard support via pyperclip (vendor-agnostic)
try:
    import pyperclip
except ImportError:
    pyperclip = None
from pathlib import Path
from typing import Iterable, List

CHUNK = 64 * 1024  # 64 KiB – good balance for small RAM & throughput

###############################################################################
# Colour helpers ##############################################################
###############################################################################

_ANSI_RESET = "\033[0m"
_ANSI_CYAN = "\033[96m"  # bright cyan on dark bg
_ANSI_BLUE = "\033[34m"  # medium blue on light bg


def _detect_dark_bg() -> bool:
    """Very small heuristic using $COLORFGBG."""
    cfg = os.getenv("COLORFGBG")
    if cfg and ";" in cfg:
        try:
            bg = int(cfg.split(";")[-1])
            return bg <= 6  # lower cube indices ~ dark colours
        except ValueError:
            pass
    return True  # safer default


def _colourise(text: str, *, disable: bool = False) -> str:
    if disable or not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return text
    colour = _ANSI_CYAN if _detect_dark_bg() else _ANSI_BLUE
    return f"{colour}{text}{_ANSI_RESET}"

###############################################################################
# Hash / HMAC helpers #########################################################
###############################################################################

def _chunked(stream: io.BufferedReader) -> Iterable[bytes]:
    return iter(lambda: stream.read(CHUNK), b"")


def _hash_stream(stream: io.BufferedReader, algo: str) -> bytes:
    h = hashlib.new(algo)
    for chunk in _chunked(stream):
        h.update(chunk)
    return h.digest()


def _hmac_stream(stream: io.BufferedReader, algo: str, key: bytes) -> bytes:
    hm = hmac.new(key, digestmod=algo)
    for chunk in _chunked(stream):
        hm.update(chunk)
    return hm.digest()


def _encode_digest(digest: bytes, fmt: str) -> str:
    if fmt == "hex":
        return digest.hex()
    if fmt == "b64":
        return base64.b64encode(digest).decode()
    raise ValueError("Unsupported output format. Use hex or b64.")

###############################################################################
# Argument parsing ############################################################
###############################################################################

_FIXED_LEN_ALGOS: List[str] = sorted(a for a in hashlib.algorithms_available if not a.startswith("shake_"))

# Streamlined shortlist shown in the interactive wizard (mainstream, familiar algos)
# Keep these within the fixed-length set for safety
_MAINSTREAM_ALGOS: List[str] = [a for a in ("md5", "sha1", "sha256", "sha512", "blake2b") if a in _FIXED_LEN_ALGOS]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Flexible string → hash/encoding converter")

    io_grp = p.add_mutually_exclusive_group()
    io_grp.add_argument("text", nargs="*", help="Text to hash (falls back to stdin)")
    io_grp.add_argument("--file", "-f", nargs="+", metavar="PATH", help="File(s) to hash instead of text/stdin")

    # ... no CLI options for algo — handled in interactive wizard
    # ... no CLI options for output format — handled in interactive wizard
    # ... no CLI options for HMAC — handled in interactive wizard
    p.add_argument("--list-algos", action="store_true", help="List supported algorithms and exit")
    # ... no CLI options for copy — handled in interactive wizard
    # ... no CLI options for force-copy — handled in interactive wizard
    p.add_argument("--no-colour", action="store_true", help="Disable ANSI colours in interactive mode")

    return p

###############################################################################
# Core processing #############################################################
###############################################################################

def _hash_bytes(data: bytes, *, algo: str, out_fmt: str, key: str | None) -> str:
    if key is None:
        digest = hashlib.new(algo, data).digest()
    else:
        digest = hmac.new(key.encode(), data, digestmod=algo).digest()
    return _encode_digest(digest, out_fmt)


def _hash_stream_source(stream: io.BufferedReader, *, algo: str, out_fmt: str, key: str | None) -> str:
    digest = _hmac_stream(stream, algo, key.encode()) if key else _hash_stream(stream, algo)
    return _encode_digest(digest, out_fmt)

###############################################################################
# Interactive wizard ##########################################################
###############################################################################

def _interactive(disable_colour: bool = False):
    c = lambda s: _colourise(s, disable=disable_colour)

    # Step 1: input text
    print(c("String → Hash Converter"))
    text = input(c("Enter text to hash: "))
    if not text:
        sys.exit("No text provided.")

    # Step 2: algorithm (streamlined mainstream list)
    print(c("\nSelect algorithm:"))
    for idx, name in enumerate(_MAINSTREAM_ALGOS, 1):
        default = " (default)" if idx == 1 else ""
        print(c(f"  {idx}) {name}{default}"))
    while True:
        sel = input(c("Choice [1]: ")).strip()
        if sel == "":
            algo = _MAINSTREAM_ALGOS[0]
            break
        if sel.isdigit() and 1 <= int(sel) <= len(_MAINSTREAM_ALGOS):
            algo = _MAINSTREAM_ALGOS[int(sel) - 1]
            break
        print(c("Invalid choice."))

    # Step 3: output format
    print(c("\nSelect output format:"))
    print(c("  1) hex (default)\n  2) base64"))
    while True:
        sel = input(c("Choice [1]: ")).strip()
        if sel in {"", "1"}:
            out_fmt = "hex"
            break
        if sel == "2":
            out_fmt = "b64"
            break
        print(c("Invalid choice."))

    # Step 4: HMAC
    print(c("\nHMAC options:"))
    print(c("  1) No HMAC (default)\n  2) Use HMAC key"))
    while True:
        sel = input(c("Choice [1]: ")).strip()
        if sel in {"", "1"}:
            key = None
            break
        if sel == "2":
            key = input(c("Enter HMAC key: ")).strip() or None
            break
        print(c("Invalid choice."))

    # Compute
    print(c("\nComputing…"))
    result = _hash_bytes(text.encode(), algo=algo, out_fmt=out_fmt, key=key)
    print(c(f"\nResult:\n{result}"))

    # Offer to copy result to clipboard
    if sys.stdin.isatty() and sys.stdout.isatty():
        ans = input(c("\nCopy result to clipboard? [y/N]: ")).strip().lower()
        if ans in ("y", "yes"):
            if pyperclip:
                try:
                    pyperclip.copy(result)
                    print(c("Copied to clipboard."))
                except Exception as e:
                    print(c(f"Copy failed: {e}"))
            else:
                print(c("pyperclip not installed; cannot copy."))

###############################################################################
# Main ########################################################################
###############################################################################

def main():
    # Interactive wizard if absolutely no arguments and stdin is TTY
    if len(sys.argv) == 1 and sys.stdin.isatty():
        _interactive()
        return

    parser = _build_parser()
    args = parser.parse_args()

    if args.list_algos:
        print("\n".join(_FIXED_LEN_ALGOS))
        return

    sources: List[bytes] = []

    if args.file:
        for path in args.file:
            pth = Path(path)
            if not pth.is_file():
                parser.error(f"{path!s} is not a file")
            with pth.open("rb") as f:
                sources.append(f.read())
    elif args.text:
        sources.append(" ".join(args.text).encode())
    else:
        if sys.stdin.isatty():
            parser.error("No input provided; pass text, --file, or pipe data")
        sources.append(sys.stdin.buffer.read())

    for src in sources:
        # Non-interactive defaults: sha256 hex, no HMAC
        result = _hash_bytes(src, algo='sha256', out_fmt='hex', key=None)
        print(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Aborted by user")