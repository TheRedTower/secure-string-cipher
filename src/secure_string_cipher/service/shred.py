"""`ssc shred <file>`: overwrite a file with random bytes, then delete it.

SSDs, copy-on-write filesystems, snapshots and backups can keep old copies,
so this is best effort; the CLI says so and asks first (CLI.md section 3.4).
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

WARNING = (
    "Shredding overwrites the file, then deletes it. SSDs, copy-on-write "
    "filesystems and backups can still keep old copies."
)


def shred(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise IsADirectoryError(f"Only a regular file can be shredded: {path}")
    with path.open("r+b") as handle:
        remaining = info.st_size
        while remaining:
            block = min(remaining, 1 << 20)
            handle.write(secrets.token_bytes(block))
            remaining -= block
        handle.flush()
        os.fsync(handle.fileno())
    path.unlink()
