import json
import struct
import tempfile
from pathlib import Path

import pytest

from secure_string_cipher.secure_memory import SecureBytes
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.decrypt import (
    decrypt_v2_file,
    decrypt_v2_text,
)
from secure_string_cipher.v2.encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    encrypt_v2_file,
    encrypt_v2_text,
)
from secure_string_cipher.v2.envelope import canonical_json
from secure_string_cipher.v2.header_parser import validate_v2_header
from secure_string_cipher.v2.key_identity import compute_fingerprint
from secure_string_cipher.v2.keywrap import unwrap_dek_from_grant, wrap_dek_for_grant
from secure_string_cipher.v2.metadata import encrypt_metadata
from secure_string_cipher.v2.vault_schema import b64url_encode

CHUNK_SIZE = 65536
# Frame wire size for a full chunk: 19-byte header (S2FR|index|pt|pad|flags)
# + chunk_size ciphertext + 16-byte AEAD tag.
FULL_FRAME_LEN = 4 + 8 + 4 + 2 + 1 + CHUNK_SIZE + 16

_MANAGED_SECRET = b"K" * 32
_MANAGED_FINGERPRINT = compute_fingerprint(_MANAGED_SECRET)


def _key_credential() -> KeyCredential:
    return KeyCredential(
        key_fingerprint=_MANAGED_FINGERPRINT, managed_secret=_MANAGED_SECRET
    )


def _combined_credential() -> CombinedCredential:
    return CombinedCredential(
        passphrase=SecureBytes(b"password123"),
        key_fingerprint=_MANAGED_FINGERPRINT,
        managed_secret=_MANAGED_SECRET,
    )


def test_file_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        input_path = tmp / "test.txt"
        input_path.write_text("Hello World!")
        output_path = tmp / "test.enc"

        cred = PasswordCredential(SecureBytes(b"password123"))

        encrypt_v2_file(
            input_path=input_path,
            credential=cred,
            output_path=output_path,
        )

        assert output_path.exists()

        decrypt_dir = tmp / "decrypted"
        decrypt_dir.mkdir()

        decrypted_path = decrypt_v2_file(
            input_path=output_path,
            credential=cred,
            output_dir=decrypt_dir,
        )

        assert decrypted_path.exists()
        assert decrypted_path.name == "test.txt"
        assert decrypted_path.read_text() == "Hello World!"


def test_file_roundtrip_no_restore_filename_uses_dec_fallback() -> None:
    """restore_filename=False must use the deterministic .dec fallback even
    though the original filename is available in (encrypted) metadata —
    previously this parameter was accepted but silently ignored for V2
    files, always restoring the stored name regardless of its value."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        input_path = tmp / "secret-report.txt"
        input_path.write_text("Confidential contents")
        output_path = tmp / "secret-report.ssc"

        cred = PasswordCredential(SecureBytes(b"password123"))

        encrypt_v2_file(
            input_path=input_path,
            credential=cred,
            output_path=output_path,
            store_filename=True,
        )

        decrypt_dir = tmp / "decrypted"
        decrypt_dir.mkdir()

        decrypted_path = decrypt_v2_file(
            input_path=output_path,
            credential=cred,
            output_dir=decrypt_dir,
            restore_filename=False,
        )

        assert decrypted_path.exists()
        assert decrypted_path.name == "secret-report.dec"
        assert decrypted_path.name != "secret-report.txt"
        assert decrypted_path.read_text() == "Confidential contents"


def test_text_roundtrip() -> None:
    cred = PasswordCredential(SecureBytes(b"password123"))
    plaintext = "Super secret text"

    armored = encrypt_v2_text(
        plaintext=plaintext,
        credential=cred,
    )
    assert "BEGIN SSC MESSAGE" in armored
    assert "Version: 2" in armored

    decrypted = decrypt_v2_text(
        armored_text=armored,
        credential=cred,
    )

    assert decrypted == plaintext


def test_file_roundtrip_key_credential(tmp_path: Path) -> None:
    input_path = tmp_path / "key-test.txt"
    input_path.write_text("Hello managed key!")
    output_path = tmp_path / "key-test.enc"

    cred = _key_credential()
    encrypt_v2_file(input_path=input_path, credential=cred, output_path=output_path)
    assert output_path.exists()

    decrypt_dir = tmp_path / "decrypted"
    decrypt_dir.mkdir()
    decrypted_path = decrypt_v2_file(
        input_path=output_path, credential=cred, output_dir=decrypt_dir
    )

    assert decrypted_path.read_text() == "Hello managed key!"


def test_encrypt_rejects_mismatched_key_fingerprint(tmp_path: Path) -> None:
    """A KeyCredential whose fingerprint doesn't match its own secret must be
    rejected before writing anything — otherwise the header would advertise
    a fingerprint (for automatic CLI key lookup) that isn't the key the
    payload is actually encrypted under."""
    other_secret = b"O" * 32
    mismatched = KeyCredential(
        key_fingerprint=_MANAGED_FINGERPRINT,  # fingerprint of _MANAGED_SECRET
        managed_secret=other_secret,  # but a different secret
    )
    input_path = tmp_path / "plain.txt"
    input_path.write_text("data")
    output_path = tmp_path / "out.ssc"

    with pytest.raises(ValueError, match="key_fingerprint"):
        encrypt_v2_file(
            input_path=input_path, credential=mismatched, output_path=output_path
        )
    assert not output_path.exists()

    with pytest.raises(ValueError, match="key_fingerprint"):
        encrypt_v2_text(plaintext="data", credential=mismatched)


def test_encrypt_rejects_mismatched_fingerprint_in_combined_credential() -> None:
    other_secret = b"O" * 32
    mismatched = CombinedCredential(
        passphrase="password123",
        key_fingerprint=_MANAGED_FINGERPRINT,
        managed_secret=other_secret,
    )
    with pytest.raises(ValueError, match="key_fingerprint"):
        encrypt_v2_text(plaintext="data", credential=mismatched)


def test_text_roundtrip_key_credential() -> None:
    cred = _key_credential()
    plaintext = "Managed-key secret text"

    armored = encrypt_v2_text(plaintext=plaintext, credential=cred)
    assert "BEGIN SSC MESSAGE" in armored

    assert decrypt_v2_text(armored_text=armored, credential=cred) == plaintext


def test_file_roundtrip_combined_credential(tmp_path: Path) -> None:
    input_path = tmp_path / "combined-test.txt"
    input_path.write_text("Hello combined credential!")
    output_path = tmp_path / "combined-test.enc"

    cred = _combined_credential()
    encrypt_v2_file(input_path=input_path, credential=cred, output_path=output_path)
    assert output_path.exists()

    decrypt_dir = tmp_path / "decrypted"
    decrypt_dir.mkdir()
    decrypted_path = decrypt_v2_file(
        input_path=output_path, credential=cred, output_dir=decrypt_dir
    )

    assert decrypted_path.read_text() == "Hello combined credential!"


def test_text_roundtrip_combined_credential() -> None:
    cred = _combined_credential()
    plaintext = "Combined credential secret text"

    armored = encrypt_v2_text(plaintext=plaintext, credential=cred)
    assert "BEGIN SSC MESSAGE" in armored

    assert decrypt_v2_text(armored_text=armored, credential=cred) == plaintext


@pytest.mark.parametrize(
    "size",
    [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 200000],  # 200000 >= 2.5x chunk
)
@pytest.mark.parametrize("store_filename", [True, False])
def test_file_roundtrip_boundary_sizes(
    tmp_path: Path, size: int, store_filename: bool
) -> None:
    """File round-trips at frame boundary sizes x both metadata policies."""
    input_path = tmp_path / "plain.bin"
    content = bytes((i * 7 + 3) % 256 for i in range(size))
    input_path.write_bytes(content)
    output_path = tmp_path / "enc.ssc"

    cred = _key_credential()
    encrypt_v2_file(
        input_path=input_path,
        credential=cred,
        output_path=output_path,
        store_filename=store_filename,
        chunk_size=CHUNK_SIZE,
    )

    dest = tmp_path / "out.bin"
    result = decrypt_v2_file(input_path=output_path, credential=cred, output_path=dest)

    assert result == dest
    assert dest.read_bytes() == content


# ---------------------------------------------------------------------------
# A2 acceptance: no plaintext byte is published before the complete stream is
# authenticated (frame finality + trailing-EOF + original_size when present).
# ---------------------------------------------------------------------------


def _encrypt_container(
    tmp_path: Path, size: int, *, store_filename: bool
) -> tuple[Path, bytes]:
    input_path = tmp_path / f"plain-{size}-{store_filename}.bin"
    content = bytes((i * 7 + 3) % 256 for i in range(size))
    input_path.write_bytes(content)
    output_path = tmp_path / f"enc-{size}-{store_filename}.ssc"
    encrypt_v2_file(
        input_path=input_path,
        credential=_key_credential(),
        output_path=output_path,
        store_filename=store_filename,
        chunk_size=CHUNK_SIZE,
    )
    return output_path, content


def _split_container(data: bytes) -> tuple[bytes, bytes]:
    """Split a binary container into (header_section, frame_section)."""
    header_len = struct.unpack("<I", data[4:8])[0]
    return data[: 8 + header_len], data[8 + header_len :]


def _assert_decrypt_fails_without_publish(enc_path: Path, dest: Path) -> None:
    """Assert decrypt raises, never creates dest, and never clobbers it."""
    with pytest.raises(CryptoError):
        decrypt_v2_file(
            input_path=enc_path, credential=_key_credential(), output_path=dest
        )
    assert not dest.exists()

    sentinel = b"PRE-EXISTING DESTINATION CONTENT"
    dest.write_bytes(sentinel)
    with pytest.raises(CryptoError):
        decrypt_v2_file(
            input_path=enc_path,
            credential=_key_credential(),
            output_path=dest,
            overwrite=True,
        )
    assert dest.read_bytes() == sentinel
    dest.unlink()


def test_decrypt_truncated_at_frame_boundary_hidden_metadata_does_not_publish(
    tmp_path: Path,
) -> None:
    """Regression: a hidden-metadata container truncated at a frame boundary
    MUST fail WITHOUT creating or overwriting the destination.

    With hidden metadata there is no original_size; frame finality (the FINAL
    flag) is the only length signal, so a missing FINAL frame must error.
    """
    enc, _ = _encrypt_container(tmp_path, 2 * CHUNK_SIZE + 100, store_filename=False)
    header_section, frames = _split_container(enc.read_bytes())

    tampered = tmp_path / "truncated.ssc"
    tampered.write_bytes(header_section + frames[:FULL_FRAME_LEN])

    _assert_decrypt_fails_without_publish(tampered, tmp_path / "out.bin")


def test_decrypt_truncated_at_frame_boundary_encrypted_metadata_does_not_publish(
    tmp_path: Path,
) -> None:
    enc, _ = _encrypt_container(tmp_path, 2 * CHUNK_SIZE + 100, store_filename=True)
    header_section, frames = _split_container(enc.read_bytes())

    tampered = tmp_path / "truncated.ssc"
    tampered.write_bytes(header_section + frames[:FULL_FRAME_LEN])

    _assert_decrypt_fails_without_publish(tampered, tmp_path / "out.bin")


def test_decrypt_truncated_mid_frame_does_not_publish(tmp_path: Path) -> None:
    for store_filename in (True, False):
        enc, _ = _encrypt_container(
            tmp_path, CHUNK_SIZE + 100, store_filename=store_filename
        )
        header_section, frames = _split_container(enc.read_bytes())

        tampered = tmp_path / f"truncated-mid-{store_filename}.ssc"
        # Cut inside frame 0's ciphertext
        tampered.write_bytes(header_section + frames[: 19 + 100])

        _assert_decrypt_fails_without_publish(
            tampered, tmp_path / f"out-{store_filename}.bin"
        )


def test_decrypt_auto_destination_never_touches_target_dir_on_auth_failure(
    tmp_path: Path,
) -> None:
    """When output_path is None (destination auto-derived from metadata or
    the .dec fallback), a decrypt that fails authentication must never
    create so much as a scratch temp file in the destination directory —
    not just "clean it up after," but never create one at all. This is the
    two-pass wiring: the full payload is authenticated in a discard-only
    pass before process_with_two_pass_auth's write pass ever calls
    safe_atomic_output (the thing that calls tempfile.mkstemp in the
    destination directory)."""
    enc, _ = _encrypt_container(tmp_path, 2 * CHUNK_SIZE + 100, store_filename=True)
    header_section, frames = _split_container(enc.read_bytes())

    tampered = tmp_path / "truncated.ssc"
    tampered.write_bytes(header_section + frames[:FULL_FRAME_LEN])

    out_dir = tmp_path / "auto_dest"
    out_dir.mkdir()
    assert list(out_dir.iterdir()) == []

    real_mkstemp = tempfile.mkstemp
    mkstemp_calls = []

    def _spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        mkstemp_calls.append((args, kwargs))
        return real_mkstemp(*args, **kwargs)

    import secure_string_cipher.atomic_io as atomic_io_module

    original = atomic_io_module.tempfile.mkstemp
    atomic_io_module.tempfile.mkstemp = _spy_mkstemp  # type: ignore[attr-defined]
    try:
        with pytest.raises(CryptoError):
            decrypt_v2_file(
                input_path=tampered, credential=_key_credential(), output_dir=out_dir
            )
    finally:
        atomic_io_module.tempfile.mkstemp = original  # type: ignore[attr-defined]

    assert mkstemp_calls == []
    assert list(out_dir.iterdir()) == []


def test_decrypt_auto_destination_write_pass_runs_once_on_success(
    tmp_path: Path,
) -> None:
    """The successful two-pass round trip creates exactly one scratch temp
    file (the write pass) — the auth pass must never touch the filesystem
    in the destination directory."""
    enc, content = _encrypt_container(
        tmp_path, 2 * CHUNK_SIZE + 100, store_filename=True
    )

    out_dir = tmp_path / "auto_dest_ok"
    out_dir.mkdir()

    real_mkstemp = tempfile.mkstemp
    mkstemp_calls = []

    def _spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        mkstemp_calls.append((args, kwargs))
        return real_mkstemp(*args, **kwargs)

    import secure_string_cipher.atomic_io as atomic_io_module

    original = atomic_io_module.tempfile.mkstemp
    atomic_io_module.tempfile.mkstemp = _spy_mkstemp  # type: ignore[attr-defined]
    try:
        dest = decrypt_v2_file(
            input_path=enc, credential=_key_credential(), output_dir=out_dir
        )
    finally:
        atomic_io_module.tempfile.mkstemp = original  # type: ignore[attr-defined]

    assert len(mkstemp_calls) == 1
    assert dest.read_bytes() == content


def test_decrypt_trailing_garbage_after_final_does_not_publish(
    tmp_path: Path,
) -> None:
    enc, _ = _encrypt_container(tmp_path, 100, store_filename=False)

    tampered = tmp_path / "trailing.ssc"
    tampered.write_bytes(enc.read_bytes() + b"TRAILING-GARBAGE")

    _assert_decrypt_fails_without_publish(tampered, tmp_path / "out.bin")


def test_decrypt_final_bit_flip_on_first_frame_does_not_publish(
    tmp_path: Path,
) -> None:
    enc, _ = _encrypt_container(tmp_path, CHUNK_SIZE + 100, store_filename=False)
    header_section, frames = _split_container(enc.read_bytes())

    tampered_bytes = bytearray(header_section + frames)
    # flags byte of frame 0: S2FR(4) | index(8) | pt_len(4) | pad_len(2) | flags(1)
    flags_offset = len(header_section) + 18
    tampered_bytes[flags_offset] = 0x01  # set FINAL on frame 0 of a 2-frame stream

    tampered = tmp_path / "flagflip.ssc"
    tampered.write_bytes(bytes(tampered_bytes))

    _assert_decrypt_fails_without_publish(tampered, tmp_path / "out.bin")


def test_decrypt_wrong_original_size_does_not_publish(tmp_path: Path) -> None:
    """Valid FINAL frames but a wrong metadata original_size -> raises inside
    the atomic-output scope -> destination not published."""
    enc, content = _encrypt_container(tmp_path, 1000, store_filename=True)
    data = enc.read_bytes()
    header_section, frames = _split_container(data)
    raw_header = header_section[8:]

    header_dict = json.loads(raw_header.decode("utf-8"))
    header = validate_v2_header(header_dict, raw_header)
    dek = unwrap_dek_from_grant(header, managed_secret=_MANAGED_SECRET)

    # Re-encrypt metadata with a WRONG original_size. The metadata AEAD is
    # valid; M_context strips ciphertext/tag, so frame AADs still verify and
    # decryption proceeds all the way to the original_size check.
    ct, tag = encrypt_metadata(
        header,
        dek,
        original_filename="plain-1000-True.bin",
        original_size=len(content) + 7,
    )
    header_dict["metadata"]["ciphertext"] = b64url_encode(ct)
    header_dict["metadata"]["tag"] = b64url_encode(tag)

    # Re-wrap the DEK so the grant commitment covers the new metadata block.
    rewrapped = wrap_dek_for_grant(header_dict, dek, managed_secret=_MANAGED_SECRET)
    new_raw = canonical_json(rewrapped)

    tampered = tmp_path / "wrong-size.ssc"
    tampered.write_bytes(b"SSC2" + struct.pack("<I", len(new_raw)) + new_raw + frames)

    with pytest.raises(CryptoError, match="does not match"):
        decrypt_v2_file(
            input_path=tampered,
            credential=_key_credential(),
            output_path=tmp_path / "out.bin",
        )
    assert not (tmp_path / "out.bin").exists()

    _assert_decrypt_fails_without_publish(tampered, tmp_path / "out2.bin")
