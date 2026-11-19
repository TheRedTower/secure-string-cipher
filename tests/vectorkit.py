"""Helpers for reading the frozen test vectors in tests/vectors/.

These follow the specs directly and use none of SSC's own code, so the
tests compare SSC against the spec rather than against itself.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).parent / "vectors"


@cache
def manifest() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (VECTORS / "manifest.json").read_text(encoding="utf-8")
    )
    return data


def read(name: str) -> bytes:
    return (VECTORS / name).read_bytes()


def valid(name: str) -> dict[str, Any]:
    entry: dict[str, Any] = next(v for v in manifest()["valid"] if v["name"] == name)
    return entry


def reject(name: str) -> dict[str, Any]:
    entry: dict[str, Any] = next(v for v in manifest()["reject"] if v["name"] == name)
    return entry


def plaintext(spec: str) -> bytes:
    """The manifest writes N patterned bytes as 'mod251:N'."""
    if spec.startswith("mod251:"):
        return bytes(i % 251 for i in range(int(spec.split(":")[1])))
    return spec.encode()


@dataclass(frozen=True)
class Parts:
    """A binary SSC file cut at the boundaries of FORMAT.md section 4."""

    fixed_header: bytes
    access_body: bytes
    access_mac: bytes
    payload: bytes


def split(data: bytes) -> Parts:
    (n,) = struct.unpack(">I", data[25:29])
    return Parts(data[:25], data[29 : 29 + n], data[29 + n : 61 + n], data[61 + n :])
