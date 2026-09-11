import json
from pathlib import Path

import pytest

from secure_string_cipher.v2.kdf import (
    derive_argon2id,
    derive_combined_grant_keys,
    derive_managed_key_grant_keys,
    derive_password_grant_keys,
    hkdf_sha256,
)
from secure_string_cipher.v2.keywrap import (
    build_projection_q,
    build_projection_w,
    compute_grant_commitment,
    compute_wrap_aad,
    unwrap_dek_aead,
)
from secure_string_cipher.v2.vault_schema import b64url_decode

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "v2"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"


@pytest.fixture(scope="session")
def golden_manifest():
    if not MANIFEST_PATH.exists():
        pytest.skip(f"Golden vector manifest not found at {MANIFEST_PATH}")
    with open(MANIFEST_PATH, "rb") as f:
        return json.load(f)


def test_hkdf_golden(golden_manifest):
    for vec in golden_manifest["hkdf"]:
        ikm = b64url_decode(vec["ikm"])
        salt = b64url_decode(vec["salt"])
        info = vec["info"].encode("ascii")
        expected_okm = b64url_decode(vec["okm"])

        okm = hkdf_sha256(ikm, salt=salt, info=info, length=32)
        assert okm == expected_okm


def test_argon2_golden(golden_manifest):
    for vec in golden_manifest["argon2"]:
        password = b64url_decode(vec["password"])
        salt = b64url_decode(vec["salt"])
        expected_out = b64url_decode(vec["output"])

        out = derive_argon2id(
            password=password,
            salt=salt,
            memory_kib=vec["memory_kib"],
            time_cost=vec["time_cost"],
            parallelism=vec["parallelism"],
            hash_len=vec["hash_len"],
            version=vec["version"],
        )
        assert out == expected_out


def test_password_grant_golden(golden_manifest):
    vec = golden_manifest["grants"]["password"]
    pw = vec["password"].encode("utf-8")
    a2_salt = b64url_decode(vec["argon2_salt"])

    header = vec["complete_header"]
    grant = header["access"]["grants"][0]

    kek_salt = b64url_decode(grant["kek_derivation"]["salt"])
    commit_salt = b64url_decode(grant["commitment"]["kdf"]["salt"])

    r, kek, k_commit = derive_password_grant_keys(
        password=pw,
        salt_kek=kek_salt,
        salt_commit=commit_salt,
        salt_argon2=a2_salt,
        strict_profile=False,
    )

    assert r == b64url_decode(vec["r"])
    assert kek == b64url_decode(vec["kek"])
    assert k_commit == b64url_decode(vec["k_commit"])

    # A5 consensus-bytes guard: W/Q-derived bytes identical to golden manifest
    wrap_aad = compute_wrap_aad(build_projection_w(header))
    assert wrap_aad == b64url_decode(vec["wrap_aad"])
    q = build_projection_q(header)
    assert compute_grant_commitment(k_commit, q) == vec["commit_value"]
    assert grant["commitment"]["value"] == vec["commit_value"]
    assert unwrap_dek_aead(
        b64url_decode(grant["wrapped_dek"]),
        b64url_decode(grant["tag"]),
        kek,
        b64url_decode(grant["wrap_nonce"]),
        wrap_aad,
    ) == b64url_decode(vec["dek"])


def test_managed_key_grant_golden(golden_manifest):
    vec = golden_manifest["grants"]["managed_key"]
    managed_secret = b64url_decode(vec["managed_secret"])

    header = vec["complete_header"]
    grant = header["access"]["grants"][0]

    kek_salt = b64url_decode(grant["kek_derivation"]["salt"])
    commit_salt = b64url_decode(grant["commitment"]["kdf"]["salt"])

    r, kek, k_commit = derive_managed_key_grant_keys(
        managed_secret=managed_secret, salt_kek=kek_salt, salt_commit=commit_salt
    )

    assert r == b64url_decode(vec["r"])
    assert kek == b64url_decode(vec["kek"])
    assert k_commit == b64url_decode(vec["k_commit"])

    # A5 consensus-bytes guard: W/Q-derived bytes identical to golden manifest
    wrap_aad = compute_wrap_aad(build_projection_w(header))
    assert wrap_aad == b64url_decode(vec["wrap_aad"])
    q = build_projection_q(header)
    assert compute_grant_commitment(k_commit, q) == vec["commit_value"]
    assert grant["commitment"]["value"] == vec["commit_value"]
    assert unwrap_dek_aead(
        b64url_decode(grant["wrapped_dek"]),
        b64url_decode(grant["tag"]),
        kek,
        b64url_decode(grant["wrap_nonce"]),
        wrap_aad,
    ) == b64url_decode(vec["dek"])


def test_combined_grant_golden(golden_manifest):
    vec = golden_manifest["grants"]["combined"]
    pw = vec["password"].encode("utf-8")
    managed_secret = b64url_decode(vec["managed_secret"])
    a2_salt = b64url_decode(vec["argon2_salt"])

    header = vec["complete_header"]
    grant = header["access"]["grants"][0]

    mk_salt = b64url_decode(grant["combined_kdf"]["managed_key_salt"])
    root_salt = b64url_decode(grant["combined_kdf"]["salt"])
    kek_salt = b64url_decode(grant["kek_derivation"]["salt"])
    commit_salt = b64url_decode(grant["commitment"]["kdf"]["salt"])

    r, kek, k_commit = derive_combined_grant_keys(
        password=pw,
        managed_secret=managed_secret,
        salt_managed_key=mk_salt,
        salt_root=root_salt,
        salt_kek=kek_salt,
        salt_commit=commit_salt,
        salt_argon2=a2_salt,
        strict_profile=False,
    )

    assert r == b64url_decode(vec["r"])
    assert kek == b64url_decode(vec["kek"])
    assert k_commit == b64url_decode(vec["k_commit"])

    # A5 consensus-bytes guard: W/Q-derived bytes identical to golden manifest
    wrap_aad = compute_wrap_aad(build_projection_w(header))
    assert wrap_aad == b64url_decode(vec["wrap_aad"])
    q = build_projection_q(header)
    assert compute_grant_commitment(k_commit, q) == vec["commit_value"]
    assert grant["commitment"]["value"] == vec["commit_value"]
    assert unwrap_dek_aead(
        b64url_decode(grant["wrapped_dek"]),
        b64url_decode(grant["tag"]),
        kek,
        b64url_decode(grant["wrap_nonce"]),
        wrap_aad,
    ) == b64url_decode(vec["dek"])
