"""The printed form of a recovery code (ACCESS.md section 2.3).

The 18 random bytes `R`, followed by a 2-byte check, are 20 bytes: exactly
32 Crockford Base32 characters, printed as 8 groups of 4. The check catches
a typo before any cryptography is done.
"""

from __future__ import annotations

import hashlib
import secrets

from secure_string_cipher.engine.access import RECOVERY_SIZE
from secure_string_cipher.errors import Reason, RecoveryCodeError

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CHECK_SIZE = 2
LENGTH = 32
GROUP = 4
# A reader ignores case, spaces and hyphens, and reads O as 0 and I or L as 1.
_READ = {c: i for i, c in enumerate(ALPHABET)} | {"O": 0, "I": 1, "L": 1}


def new() -> bytes:
    """A fresh recovery value `R`."""
    return secrets.token_bytes(RECOVERY_SIZE)


def _check(r: bytes) -> bytes:
    return hashlib.sha256(b"ssc3/recovery-check" + r).digest()[:CHECK_SIZE]


def encode(r: bytes) -> str:
    """`R` as printed: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`."""
    if len(r) != RECOVERY_SIZE:
        raise ValueError(f"A recovery code is {RECOVERY_SIZE} bytes.")
    number = int.from_bytes(r + _check(r))
    chars = [ALPHABET[(number >> (5 * i)) & 31] for i in reversed(range(LENGTH))]
    text = "".join(chars)
    return "-".join(text[i : i + GROUP] for i in range(0, LENGTH, GROUP))


def decode(text: str) -> bytes:
    """Read a typed or pasted code back to `R`. A wrong length or character
    is `recovery-code`; a failed check, almost always a typo, is
    `recovery-check`."""
    cleaned = text.upper().replace("-", "").replace(" ", "")
    if len(cleaned) != LENGTH or any(c not in _READ for c in cleaned):
        raise RecoveryCodeError(
            Reason.RECOVERY_CODE,
            f"A recovery code is {LENGTH} letters and digits, in groups of {GROUP}.",
        )
    number = 0
    for c in cleaned:
        number = number << 5 | _READ[c]
    data = number.to_bytes(RECOVERY_SIZE + CHECK_SIZE)
    r, check = data[:RECOVERY_SIZE], data[RECOVERY_SIZE:]
    if _check(r) != check:
        raise RecoveryCodeError(
            Reason.RECOVERY_CHECK,
            "That recovery code has a typo: check it against the printed copy.",
        )
    return r
