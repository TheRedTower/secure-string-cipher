# /// script
# requires-python = ">=3.13"
# dependencies = ["cryptography==50.0.1", "argon2-cffi==25.1.0"]
# ///
"""Throwaway generator for the SSC 3.0 test vectors (Phase 1, step 5).

Run with:  uv run tools/vectors/generate.py

It writes every vector under tests/vectors/ from fixed, recorded randomness,
then re-reads each one with a strict reader written from docs/spec/. Valid
vectors must decrypt to their expected plaintext, and each rejection vector
must fail for exactly the reason it is named after. Once the vectors are
frozen, this script is kept only so reviewers can reproduce them. It is
deleted at the Phase 2 gate, when the real implementation passes them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = Path(__file__).resolve().parents[2] / "tests" / "vectors"

MAGIC = b"\x89SSC\r\n\x1a\n"
VERSION = 0x01
CHUNK = 65536
TAG = 16
MAX_ACCESS = 65536
MAX_GRANTS = 16
MAX_FACTORS = 5
ARGON = (65536, 3, 4)  # m_kib, t, p
PW, VAULT_PW, KEY, RECOVERY = 0x01, 0x02, 0x03, 0x04
ZERO_NONCE = bytes(12)
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ARMOR_BEGIN = "-----BEGIN SSC MESSAGE-----"
ARMOR_END = "-----END SSC MESSAGE-----"


# --- primitives (FORMAT.md section 2) --------------------------------------


def rand(label: str, n: int) -> bytes:
    """Deterministic stand-in for the CSPRNG. Every value is recorded."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"ssc3-vectors/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt or None, info).derive(ikm)


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def argon(password: str, salt: bytes) -> bytes:
    m, t, p = ARGON
    pw = unicodedata.normalize("NFC", password).encode()
    return hash_secret_raw(pw, salt, t, m, p, 32, Type.ID, 19)


def key_id(key: bytes) -> bytes:
    return hashlib.sha256(b"ssc3/key-id" + key).digest()[:16]


def pattern(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


# --- factors and grants (ACCESS.md sections 2 and 3) -----------------------


@dataclass(frozen=True)
class Factor:
    encoding: bytes  # type byte || body
    secret: bytes


def password_factor(password: str, salt: bytes) -> Factor:
    body = salt + u32(ARGON[0]) + u32(ARGON[1]) + bytes([ARGON[2]])
    return Factor(bytes([PW]) + body, argon(password, salt))


def vault_password_factor(entry_id: bytes, password: str, salt: bytes) -> Factor:
    body = entry_id + salt + u32(ARGON[0]) + u32(ARGON[1]) + bytes([ARGON[2]])
    return Factor(bytes([VAULT_PW]) + body, argon(password, salt))


def key_factor(key: bytes) -> Factor:
    return Factor(bytes([KEY]) + key_id(key), hkdf(key, b"", b"ssc3/factor/key"))


def recovery_factor(r: bytes) -> Factor:
    return Factor(bytes([RECOVERY]), hkdf(r, b"", b"ssc3/factor/recovery-code"))


def grant(
    file_key: bytes,
    salt: bytes,
    factors: list[Factor],
    *,
    sort: bool = True,
    count: int | None = None,
) -> bytes:
    fs = sorted(factors, key=lambda f: f.encoding) if sort else factors
    d = salt + bytes([len(fs) if count is None else count])
    d += b"".join(f.encoding for f in fs)
    ikm = b"".join(f.secret for f in fs)
    kek = hkdf(ikm, salt, b"ssc3/grant-kek" + d)
    wrapped = AESGCM(kek).encrypt(ZERO_NONCE, file_key, None)
    return struct.pack(">H", len(d) + len(wrapped)) + d + wrapped


def unknown_grant(salt: bytes) -> bytes:
    """A grant with factor type 0x7f, as a later version might write."""
    d = salt + bytes([1, 0x7F]) + rand("unknown-body", 32)
    return struct.pack(">H", len(d) + 48) + d + rand("unknown-wrapped", 48)


# --- container (FORMAT.md sections 3 to 6) ---------------------------------


def seal_file(
    file_key: bytes,
    nonce: bytes,
    grants: list[bytes],
    plaintext: bytes,
    *,
    version: int = VERSION,
    magic: bytes = MAGIC,
    access_body: bytes | None = None,
    extra_empty_chunk: bool = False,
) -> bytes:
    fixed = magic + bytes([version]) + nonce
    body = (
        bytes([len(grants)]) + b"".join(grants) if access_body is None else access_body
    )
    mac_key = hkdf(file_key, b"", b"ssc3/access-mac")
    mac = hmac.new(mac_key, fixed + u32(len(body)) + body, "sha256").digest()
    payload_key = hkdf(file_key, nonce, b"ssc3/payload-key" + fixed)
    aead = AESGCM(payload_key)
    chunks = [plaintext[i : i + CHUNK] for i in range(0, len(plaintext), CHUNK)] or [
        b""
    ]
    if extra_empty_chunk:
        chunks.append(b"")
    out = [fixed, u32(len(body)), body, mac]
    for i, c in enumerate(chunks):
        flag = 1 if i == len(chunks) - 1 else 0
        out.append(aead.encrypt(i.to_bytes(11, "big") + bytes([flag]), c, None))
    return b"".join(out)


# --- strict reader ----------------------------------------------------------


class Reject(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Credentials:
    passwords: list[str] = field(default_factory=list)
    keys: list[bytes] = field(default_factory=list)
    recovery: list[bytes] = field(default_factory=list)
    vault_entries: dict[bytes, str] = field(default_factory=dict)


def parse_grant(g: bytes) -> list[tuple[int, bytes]] | None:
    """Return the grant's factors, or None for a grant to skip."""
    count = g[16]
    if not 1 <= count <= MAX_FACTORS:
        raise Reject("factor-count")
    pos, factors = 17, []
    sizes = {PW: 25, VAULT_PW: 41, KEY: 16, RECOVERY: 0}
    for _ in range(count):
        if pos >= len(g) - 48:
            raise Reject("grant-length")
        t = g[pos]
        if t not in sizes:
            return None
        body = g[pos + 1 : pos + 1 + sizes[t]]
        if len(body) != sizes[t] or pos + 1 + sizes[t] > len(g) - 48:
            raise Reject("grant-length")
        if t in (PW, VAULT_PW):
            p = body[-9:]
            if (
                struct.unpack(">I", p[0:4])[0],
                struct.unpack(">I", p[4:8])[0],
                p[8],
            ) != ARGON:
                raise Reject("argon-params")
        factors.append((t, g[pos : pos + 1 + sizes[t]]))
        pos += 1 + sizes[t]
    if pos != len(g) - 48:
        raise Reject("grant-length")
    encs = [e for _, e in factors]
    if any(a >= b for a, b in zip(encs, encs[1:], strict=False)):
        raise Reject("factor-order")
    return factors


def secrets_for(
    factors: list[tuple[int, bytes]], creds: Credentials
) -> list[list[bytes]]:
    """Every combination of factor secrets the caller can supply."""
    options: list[list[bytes]] = []
    for t, enc in factors:
        if t == PW:
            opts = [argon(p, enc[1:17]) for p in creds.passwords]
        elif t == VAULT_PW:
            pw = creds.vault_entries.get(enc[1:17])
            pws = ([pw] if pw is not None else []) + creds.passwords
            opts = [argon(p, enc[17:33]) for p in pws]
        elif t == KEY:
            opts = [key_factor(k).secret for k in creds.keys if key_id(k) == enc[1:17]]
        else:
            opts = [recovery_factor(r).secret for r in creds.recovery]
        options.append(opts)
    combos: list[list[bytes]] = [[]]
    for opts in options:
        combos = [c + [s] for c in combos for s in opts]
    return combos


def open_file(data: bytes, creds: Credentials) -> bytes:
    if data.startswith(ARMOR_BEGIN.encode()):
        data = dearmor(data)
    if data[:8] != MAGIC:
        raise Reject("magic")
    if len(data) < 9 or data[8] != VERSION:
        raise Reject("version")
    if len(data) < 29:
        raise Reject("truncated")
    fixed, n = data[:25], struct.unpack(">I", data[25:29])[0]
    if not 1 <= n <= MAX_ACCESS:
        raise Reject("access-length")
    if len(data) < 29 + n + 32:
        raise Reject("truncated")
    body, mac = data[29 : 29 + n], data[29 + n : 61 + n]
    count = body[0]
    if not 1 <= count <= MAX_GRANTS:
        raise Reject("grant-count")
    pos, grants = 1, []
    for _ in range(count):
        if pos + 2 > len(body):
            raise Reject("access-body-length")
        glen = struct.unpack(">H", body[pos : pos + 2])[0]
        g = body[pos + 2 : pos + 2 + glen]
        if len(g) != glen or glen < 16 + 1 + 48:
            raise Reject("grant-length")
        grants.append(g)
        pos += 2 + glen
    if pos != len(body):
        raise Reject("access-body-length")
    parsed = [(g, parse_grant(g)) for g in grants]  # parse everything first
    file_key = None
    for g, factors in parsed:
        if factors is None:
            continue
        d = g[:-48]
        for ikm in secrets_for(factors, creds):
            kek = hkdf(b"".join(ikm), g[:16], b"ssc3/grant-kek" + d)
            try:
                candidate = AESGCM(kek).decrypt(ZERO_NONCE, g[-48:], None)
            except InvalidTag:
                continue
            mac_key = hkdf(candidate, b"", b"ssc3/access-mac")
            want = hmac.new(mac_key, fixed + u32(n) + body, "sha256").digest()
            if hmac.compare_digest(want, mac):
                file_key = candidate
                break
        if file_key:
            break
    if file_key is None:
        raise Reject("cannot-open")
    payload_key = hkdf(file_key, fixed[9:25], b"ssc3/payload-key" + fixed)
    aead, payload, out, i, p = AESGCM(payload_key), data[61 + n :], [], 0, 0
    while True:
        remaining = len(payload) - p
        if remaining < TAG:
            raise Reject("truncated")
        final = remaining <= CHUNK + TAG
        size = remaining if final else CHUNK + TAG
        if final and size == TAG and i > 0:
            raise Reject("empty-final-chunk")
        if i >= 2**32:
            raise Reject("too-many-chunks")
        nonce = i.to_bytes(11, "big") + bytes([1 if final else 0])
        try:
            out.append(aead.decrypt(nonce, payload[p : p + size], None))
        except InvalidTag:
            raise Reject("chunk-auth") from None
        p, i = p + size, i + 1
        if final:
            return b"".join(out)


# --- armour (FORMAT.md section 8) ------------------------------------------


def armor(data: bytes) -> bytes:
    b = base64.b64encode(data).decode()
    lines = [b[i : i + 64] for i in range(0, len(b), 64)]
    return ("\n".join([ARMOR_BEGIN, *lines, ARMOR_END]) + "\n").encode()


def dearmor(data: bytes) -> bytes:
    text = data.decode("ascii", errors="strict")
    if "\r\n" in text:
        if "\n" in text.replace("\r\n", ""):
            raise Reject("armor-line-endings")
        text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise Reject("armor-line-endings")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    if lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END or len(lines) < 3:
        raise Reject("armor-frame")
    body = lines[1:-1]
    if any(len(line) > 64 for line in body) or any(
        len(line) != 64 for line in body[:-1]
    ):
        raise Reject("armor-line-length")
    joined = "".join(body)
    try:
        decoded = base64.b64decode(joined, validate=True)
    except ValueError:
        raise Reject("armor-base64") from None
    if base64.b64encode(decoded).decode() != joined:
        raise Reject("armor-base64")
    return decoded


# --- recovery codes (ACCESS.md section 2.3) --------------------------------


def recovery_text(r: bytes) -> str:
    raw = r + hashlib.sha256(b"ssc3/recovery-check" + r).digest()[:2]
    n, chars = int.from_bytes(raw, "big"), []
    for _ in range(32):
        chars.append(CROCKFORD[n & 31])
        n >>= 5
    s = "".join(reversed(chars))
    return "-".join(s[i : i + 4] for i in range(0, 32, 4))


def recovery_parse(text: str) -> bytes:
    s = text.upper().replace("-", "").replace(" ", "")
    s = s.replace("O", "0").replace("I", "1").replace("L", "1")
    if len(s) != 32 or any(c not in CROCKFORD for c in s):
        raise Reject("recovery-format")
    n = 0
    for c in s:
        n = (n << 5) | CROCKFORD.index(c)
    raw = n.to_bytes(20, "big")
    if hashlib.sha256(b"ssc3/recovery-check" + raw[:18]).digest()[:2] != raw[18:]:
        raise Reject("recovery-check")
    return raw[:18]


# --- vault and key files (VAULT.md) ----------------------------------------


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def keyfile_text(label: str, created: str, key: bytes) -> str:
    return (
        "-----BEGIN SSC KEY-----\n"
        f"Label: {label}\nCreated: {created}\nKey-ID: {key_id(key).hex()}\n"
        f"{b64u(key)}\n-----END SSC KEY-----\n"
    )


# --- the vectors ------------------------------------------------------------

PASSWORD = "correct horse battery staple"
UNICODE_PASSWORD_NFD = "pássword"  # NFD; NFC is "pássword"
KEY_A = rand("key-a", 32)
KEY_B = rand("key-b", 32)
R = rand("recovery", 18)
ENTRY_ID = rand("entry-id", 16)


def hexd(**kw: bytes) -> dict[str, str]:
    return {k: v.hex() for k, v in kw.items()}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.ssc*"):
        old.unlink()
    manifest: dict[str, Any] = {
        "about": (
            "SSC 3.0 test vectors. All randomness is fixed and recorded, so an "
            "encryptor given the same inputs must reproduce each file byte for "
            "byte. Plaintext 'mod251:N' means bytes(i % 251 for i in range(N))."
        ),
        "credentials": {
            "password": PASSWORD,
            "unicode_password_nfd": UNICODE_PASSWORD_NFD,
            "key_a": KEY_A.hex(),
            "key_b": KEY_B.hex(),
            "recovery_r": R.hex(),
            "recovery_text": recovery_text(R),
            "vault_entry_id": ENTRY_ID.hex(),
        },
        "valid": [],
        "reject": [],
        "recovery_codes": [],
        "keyfiles": [],
    }
    fk, nonce = rand("file-key", 32), rand("payload-nonce", 16)
    gs = [rand(f"grant-salt-{i}", 16) for i in range(4)]
    ps = [rand(f"password-salt-{i}", 16) for i in range(3)]
    key_only = grant(fk, gs[0], [key_factor(KEY_A)])

    def write(name: str, data: bytes) -> str:
        fname = f"{name}.ssc"
        (OUT / fname).write_bytes(data)
        return fname

    def valid(
        name: str,
        data: bytes,
        plaintext: str,
        creds: Credentials,
        note: str,
        rnd: dict[str, str],
    ) -> None:
        pt = (
            pattern(int(plaintext.split(":")[1]))
            if plaintext.startswith("mod251:")
            else plaintext.encode()
        )
        assert open_file(data, creds) == pt, name
        manifest["valid"].append(
            {
                "name": name,
                "file": write(name, data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "plaintext": plaintext,
                "plaintext_sha256": hashlib.sha256(pt).hexdigest(),
                "open_with": creds_json(creds),
                "random": rnd,
                "note": note,
            }
        )

    def reject(
        name: str, data: bytes, reason: str, creds: Credentials, note: str
    ) -> None:
        try:
            open_file(data, creds)
        except Reject as e:
            assert e.reason == reason, f"{name}: got {e.reason}, want {reason}"
        else:
            raise AssertionError(f"{name} was accepted")
        manifest["reject"].append(
            {
                "name": name,
                "file": write(f"reject-{name}", data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "reason": reason,
                "open_with": creds_json(creds),
                "note": note,
            }
        )

    ka = Credentials(keys=[KEY_A])
    base_rnd = hexd(file_key=fk, payload_nonce=nonce, grant_salt=gs[0])

    # Format: payload sizes around the chunk boundary, all with one key grant.
    for n in (0, 1, CHUNK, CHUNK + 1):
        valid(
            f"format-{n}-bytes",
            seal_file(fk, nonce, [key_only], pattern(n)),
            f"mod251:{n}",
            ka,
            "One key grant (key_a).",
            base_rnd,
        )
    valid(
        "format-armored",
        armor(seal_file(fk, nonce, [key_only], b"hello, ssc 3\n")),
        "hello, ssc 3\n",
        ka,
        "The armoured form of a one-key-grant file.",
        base_rnd,
    )

    # Access: each factor type, combinations, several grants, an unknown grant.
    pw = password_factor(PASSWORD, ps[0])
    cases = [
        (
            "access-password",
            [grant(fk, gs[0], [pw])],
            Credentials(passwords=[PASSWORD]),
            {"password_salt": ps[0]},
        ),
        (
            "access-vault-password-entry",
            [grant(fk, gs[0], [vault_password_factor(ENTRY_ID, PASSWORD, ps[0])])],
            Credentials(vault_entries={ENTRY_ID: PASSWORD}),
            {"password_salt": ps[0]},
        ),
        ("access-key", [key_only], ka, {}),
        (
            "access-recovery-code",
            [grant(fk, gs[0], [recovery_factor(R)])],
            Credentials(recovery=[R]),
            {},
        ),
        (
            "access-password-and-key",
            [grant(fk, gs[0], [pw, key_factor(KEY_A)])],
            Credentials(passwords=[PASSWORD], keys=[KEY_A]),
            {"password_salt": ps[0]},
        ),
        (
            "access-password-key-recovery",
            [grant(fk, gs[0], [pw, key_factor(KEY_A), recovery_factor(R)])],
            Credentials(passwords=[PASSWORD], keys=[KEY_A], recovery=[R]),
            {"password_salt": ps[0]},
        ),
        (
            "access-any-of-three-grants",
            [
                grant(fk, gs[0], [pw]),
                grant(fk, gs[1], [key_factor(KEY_B)]),
                grant(fk, gs[2], [recovery_factor(R)]),
            ],
            Credentials(recovery=[R]),
            {"password_salt": ps[0], "grant_salt_2": gs[1], "grant_salt_3": gs[2]},
        ),
        (
            "access-unknown-grant-skipped",
            [unknown_grant(gs[1]), key_only],
            ka,
            {"unknown_grant": unknown_grant(gs[1])},
        ),
        (
            "access-password-nfc",
            [grant(fk, gs[0], [password_factor("pássword", ps[0])])],
            Credentials(passwords=[UNICODE_PASSWORD_NFD]),
            {"password_salt": ps[0]},
        ),
    ]
    for name, grants, creds, extra in cases:
        valid(
            name,
            seal_file(fk, nonce, grants, b"access\n"),
            "access\n",
            creds,
            "",
            base_rnd | hexd(**extra),
        )

    # Rejections. Each one breaks exactly one rule of a valid file.
    good = seal_file(fk, nonce, [key_only], pattern(CHUNK + 1))
    one = seal_file(fk, nonce, [key_only], b"x")
    reject("magic", b"\x89SSD" + one[4:], "magic", ka, "Magic changed.")
    reject("version", one[:8] + b"\x02" + one[9:], "version", ka, "Version 2.")
    reject(
        "access-length-zero",
        seal_file(fk, nonce, [], b"x", access_body=b""),
        "access-length",
        ka,
        "",
    )
    big = bytes([1]) + b"\x00" * MAX_ACCESS
    reject(
        "access-length-too-big",
        seal_file(fk, nonce, [], b"x", access_body=big),
        "access-length",
        ka,
        "65,537 bytes.",
    )
    mac_at = 29 + 1 + len(key_only)  # first byte of access_mac
    flipped = bytearray(one)
    flipped[mac_at] ^= 1
    reject(
        "access-mac",
        bytes(flipped),
        "cannot-open",
        ka,
        "First bit of access_mac flipped.",
    )
    flipped = bytearray(one)
    flipped[9] ^= 1
    reject(
        "payload-nonce-flipped",
        bytes(flipped),
        "cannot-open",
        ka,
        "First bit of payload_nonce flipped; the MAC covers the fixed header.",
    )
    reject(
        "truncated-at-chunk-boundary",
        good[: -(1 + TAG)],
        "chunk-auth",
        ka,
        "Final chunk removed.",
    )
    reject("appended-byte", one + b"\x00", "chunk-auth", ka, "One byte appended.")
    reject(
        "empty-trailing-chunk",
        seal_file(fk, nonce, [key_only], pattern(CHUNK), extra_empty_chunk=True),
        "empty-final-chunk",
        ka,
        "65,536 bytes written as a full chunk plus an empty final chunk.",
    )
    reject(
        "trailing-partial-chunk", good[: -(1 + TAG)] + b"\x00" * 8, "truncated", ka, ""
    )
    reject("wrong-key", one, "cannot-open", Credentials(keys=[KEY_B]), "")
    reject(
        "factor-order",
        seal_file(
            fk, nonce, [grant(fk, gs[0], [key_factor(KEY_A), pw], sort=False)], b"x"
        ),
        "factor-order",
        Credentials(passwords=[PASSWORD], keys=[KEY_A]),
        "Key factor before password factor.",
    )
    reject(
        "factor-duplicate",
        seal_file(
            fk, nonce, [grant(fk, gs[0], [key_factor(KEY_A), key_factor(KEY_A)])], b"x"
        ),
        "factor-order",
        ka,
        "",
    )
    reject(
        "factor-count-six",
        seal_file(
            fk,
            nonce,
            [grant(fk, gs[0], [key_factor(rand(f"k{i}", 32)) for i in range(6)])],
            b"x",
        ),
        "factor-count",
        ka,
        "",
    )
    bad_pw = Factor(
        bytes([PW]) + ps[0] + u32(32768) + u32(3) + bytes([4]), argon(PASSWORD, ps[0])
    )
    reject(
        "argon-params",
        seal_file(fk, nonce, [grant(fk, gs[0], [bad_pw])], b"x"),
        "argon-params",
        Credentials(passwords=[PASSWORD]),
        "m_kib = 32768.",
    )
    reject(
        "grant-count-zero",
        seal_file(fk, nonce, [], b"x", access_body=b"\x00"),
        "grant-count",
        ka,
        "",
    )
    seventeen = [grant(fk, rand(f"g{i}", 16), [key_factor(KEY_A)]) for i in range(17)]
    reject(
        "grant-count-seventeen",
        seal_file(fk, nonce, seventeen, b"x"),
        "grant-count",
        ka,
        "",
    )
    long_grant = bytearray(key_only)
    long_grant[0:2] = struct.pack(">H", len(key_only) - 2 + 1)
    reject(
        "grant-length",
        seal_file(
            fk, nonce, [], b"x", access_body=b"\x01" + bytes(long_grant) + b"\x00"
        ),
        "grant-length",
        ka,
        "grant_length one too big, padded so the body length still fits.",
    )
    reject(
        "access-body-trailing",
        seal_file(fk, nonce, [], b"x", access_body=b"\x01" + key_only + b"\x00"),
        "access-body-length",
        ka,
        "One extra byte after the last grant.",
    )
    a = armor(one).decode()
    reject(
        "armor-mixed-line-endings",
        a.replace("\n", "\r\n", 1).encode(),
        "armor-line-endings",
        ka,
        "",
    )
    lines = a.split("\n")
    reject(
        "armor-long-line",
        "\n".join(
            [lines[0], lines[1] + lines[2][:1], lines[2][1:], *lines[3:]]
        ).encode(),
        "armor-line-length",
        ka,
        "",
    )
    reject("armor-after-end", (a + "x\n").encode(), "armor-frame", ka, "")
    b = base64.b64encode(one).decode()
    assert b.endswith("="), "the one-byte file must leave unused Base64 bits"
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = len(b.rstrip("=")) - 1
    noncanon = b[:last] + std[std.index(b[last]) + 1] + b[last + 1 :]
    reject(
        "armor-noncanonical-base64",
        armor_raw(noncanon),
        "armor-base64",
        ka,
        "The lowest unused bit of the last Base64 character set.",
    )

    # Recovery codes.
    text = recovery_text(R)
    assert recovery_parse(text) == R
    assert (
        recovery_parse(
            text.lower().replace("-", " ").replace("0", "o").replace("1", "l")
        )
        == R
    )
    typo = text[:-1] + ("0" if text[-1] != "0" else "1")
    try:
        recovery_parse(typo)
    except Reject as e:
        assert e.reason == "recovery-check"
    else:
        raise AssertionError("typo accepted")
    manifest["recovery_codes"] = [
        {"r": R.hex(), "text": text, "valid": True},
        {
            "text": text.lower().replace("-", " "),
            "r": R.hex(),
            "valid": True,
            "note": "Lowercase, spaces.",
        },
        {"text": typo, "valid": False, "reason": "recovery-check"},
    ]

    # Key file.
    kf = keyfile_text("laptop", "2026-11-18T09:30:00Z", KEY_A)
    (OUT / "laptop.ssckey").write_text(kf, newline="\n")
    manifest["keyfiles"] = [
        {
            "file": "laptop.ssckey",
            "sha256": hashlib.sha256(kf.encode()).hexdigest(),
            "key": KEY_A.hex(),
            "key_id": key_id(KEY_A).hex(),
        }
    ]

    # A vault: master password grant, device key grant, one entry of each kind,
    # one profile and two history events.
    anchor = hashlib.sha256(b"ssc3/history-genesis").digest()
    e1 = {
        "action": "vault-unlock",
        "at": "2026-11-18T09:30:00Z",
        "entry": None,
        "prev": b64u(anchor),
    }
    e2 = {
        "action": "encrypt",
        "at": "2026-11-18T09:31:00Z",
        "entry": b64u(ENTRY_ID),
        "prev": b64u(hashlib.sha256(canonical_json(e1)).digest()),
    }
    doc = {
        "entries": [
            {
                "created": "2026-11-18T09:30:00Z",
                "id": b64u(ENTRY_ID),
                "kind": "password",
                "label": "work",
                "secret": PASSWORD,
                "status": "active",
            },
            {
                "created": "2026-11-18T09:30:00Z",
                "id": b64u(rand("entry-key", 16)),
                "kind": "key",
                "label": "laptop",
                "secret": b64u(KEY_B),
                "status": "active",
            },
            {
                "created": "2026-11-18T09:30:00Z",
                "id": b64u(rand("entry-rec", 16)),
                "kind": "recovery",
                "label": "paper",
                "secret": b64u(R),
                "status": "archived",
            },
        ],
        "format": 1,
        "history": {"anchor": b64u(anchor), "events": [e1, e2], "trimmed": 0},
        "profiles": [
            {
                "grants": [
                    [{"entry": b64u(rand("entry-key", 16))}],
                    [{"ask": "password"}, {"entry": b64u(rand("entry-rec", 16))}],
                ],
                "name": "backup",
            }
        ],
    }
    device = rand("device-key", 32)
    vk, vn = rand("vault-file-key", 32), rand("vault-payload-nonce", 16)
    vault = seal_file(
        vk,
        vn,
        [
            grant(vk, gs[0], [password_factor("master password", ps[1])]),
            grant(vk, gs[1], [key_factor(device)]),
        ],
        canonical_json(doc),
    )
    assert open_file(vault, Credentials(keys=[device])) == canonical_json(doc)
    (OUT / "vault.ssc").write_bytes(vault)
    manifest["vault"] = {
        "file": "vault.ssc",
        "sha256": hashlib.sha256(vault).hexdigest(),
        "master_password": "master password",
        "device_key": device.hex(),
        "keychain_account": f"vault-unlock:{key_id(device).hex()}",
        "document": doc,
        "random": hexd(
            file_key=vk,
            payload_nonce=vn,
            grant_salt_1=gs[0],
            password_salt=ps[1],
            grant_salt_2=gs[1],
        ),
    }

    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", newline="\n"
    )
    print(
        f"{len(manifest['valid'])} valid and {len(manifest['reject'])} reject vectors"
        f" written to {OUT}"
    )


def creds_json(creds: Credentials) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if creds.passwords:
        out["passwords"] = creds.passwords
    if creds.keys:
        out["keys"] = [k.hex() for k in creds.keys]
    if creds.recovery:
        out["recovery_r"] = [r.hex() for r in creds.recovery]
    if creds.vault_entries:
        out["vault_entries"] = {k.hex(): v for k, v in creds.vault_entries.items()}
    return out


def armor_raw(b64: str) -> bytes:
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return ("\n".join([ARMOR_BEGIN, *lines, ARMOR_END]) + "\n").encode()


if __name__ == "__main__":
    main()
