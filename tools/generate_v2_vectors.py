import base64
import hashlib
import hmac
import json

import argon2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_string_cipher.v2.vault_schema import b64url_encode


def b64_encode(data: bytes) -> str:
    # Delegate to the single b64url owner (vault_schema); do not re-implement.
    return b64url_encode(data)


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def do_hkdf(ikm: bytes, salt: bytes, info: str, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info.encode("ascii"),
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def do_argon2(password: bytes, salt: bytes) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID,
        version=19,
    )


def main():
    manifest = {
        "hkdf": [],
        "argon2": [],
        "grants": {},
        "vault": {},
        "keyfile": {},
        "migration": {},
    }

    # 1. HKDF Vectors (RFC 5869 App A, tests 1, 2, 3 as baseline)
    # Using our own constants
    ikm = b"\x0b" * 22
    salt = b"\x00" * 13
    info = "secure-string-cipher/v2/password/dek-wrap/aes-256-gcm"
    okm = do_hkdf(ikm, salt, info)
    manifest["hkdf"].append(
        {
            "ikm": b64_encode(ikm),
            "salt": b64_encode(salt),
            "info": info,
            "okm": b64_encode(okm),
        }
    )

    # 2. Argon2id profile
    pw = b"password123"
    a2_salt = b"A" * 16
    a2_out = do_argon2(pw, a2_salt)
    manifest["argon2"].append(
        {
            "password": b64_encode(pw),
            "salt": b64_encode(a2_salt),
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "output": b64_encode(a2_out),
        }
    )

    # Generate common parameters for grants
    dek = b"D" * 32
    object_id = b"O" * 16

    # Helper to create grant vectors
    def make_password_grant():
        p = do_argon2(pw, a2_salt)
        r = p
        kek_salt = b"K" * 32
        kek = do_hkdf(
            r, kek_salt, "secure-string-cipher/v2/password/dek-wrap/aes-256-gcm"
        )
        commit_salt = b"C" * 32
        k_commit = do_hkdf(
            r, commit_salt, "secure-string-cipher/v2/grant/key-commitment/hmac-sha256"
        )

        wrap_nonce = b"W" * 12
        # Mock M_context
        m_context = {
            "format": "SSC2",
            "version": 2,
            "object_id": b64_encode(object_id),
            "object_type": "text",
            "payload": {
                "type": "text",
                "alg": "aes-256-gcm",
                "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(b"P" * 32)},
                "metadata_policy": "hidden",
                "nonce": b64_encode(b"N" * 12),
                "plaintext_length": 100,
            },
            "metadata": {"policy": "hidden"},
        }

        # W context
        w_context = dict(m_context)
        w_context["access"] = {
            "version": 1,
            "policy": "single-grant",
            "grants": [
                {
                    "grant_id": "grant-0",
                    "type": "password",
                    "password_kdf": {
                        "alg": "argon2id",
                        "version": 19,
                        "memory_kib": 65536,
                        "time_cost": 3,
                        "parallelism": 4,
                        "hash_len": 32,
                        "salt": b64_encode(a2_salt),
                    },
                    "kek_derivation": {
                        "alg": "hkdf-sha256",
                        "salt": b64_encode(kek_salt),
                    },
                    "wrap_alg": "aes-256-gcm",
                    "wrap_nonce": b64_encode(wrap_nonce),
                    "commitment": {
                        "alg": "hmac-sha256",
                        "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(commit_salt)},
                    },
                }
            ],
        }

        wrap_aad = (
            b"SSC2/wrap/v1\0" + hashlib.sha256(canonical_json(w_context)).digest()
        )

        aead = AESGCM(kek)
        wrapped_full = aead.encrypt(wrap_nonce, dek, wrap_aad)
        wrapped_dek = wrapped_full[:-16]
        tag = wrapped_full[-16:]

        q_context = json.loads(json.dumps(w_context))
        q_context["access"]["grants"][0]["wrapped_dek"] = b64_encode(wrapped_dek)
        q_context["access"]["grants"][0]["tag"] = b64_encode(tag)

        commit_value = hmac.new(
            k_commit,
            b"SSC2/commit/v1\0" + hashlib.sha256(canonical_json(q_context)).digest(),
            hashlib.sha256,
        ).digest()

        complete_header = json.loads(json.dumps(q_context))
        complete_header["access"]["grants"][0]["commitment"]["value"] = b64_encode(
            commit_value
        )

        payload_header_digest = hashlib.sha256(canonical_json(complete_header)).digest()

        return {
            "password": pw.decode("utf-8"),
            "argon2_salt": b64_encode(a2_salt),
            "dek": b64_encode(dek),
            "r": b64_encode(r),
            "kek": b64_encode(kek),
            "k_commit": b64_encode(k_commit),
            "wrap_aad": b64_encode(wrap_aad),
            "wrapped_dek": b64_encode(wrapped_dek),
            "tag": b64_encode(tag),
            "commit_value": b64_encode(commit_value),
            "payload_header_digest": b64_encode(payload_header_digest),
            "complete_header": complete_header,
        }

    manifest["grants"]["password"] = make_password_grant()

    def make_managed_key_grant():
        # managed key grant logic
        k = b"M" * 32
        r = k
        kek_salt = b"K" * 32
        kek = do_hkdf(
            r, kek_salt, "secure-string-cipher/v2/managed-key/dek-wrap/aes-256-gcm"
        )
        commit_salt = b"C" * 32
        k_commit = do_hkdf(
            r, commit_salt, "secure-string-cipher/v2/grant/key-commitment/hmac-sha256"
        )

        wrap_nonce = b"W" * 12
        m_context = {
            "format": "SSC2",
            "version": 2,
            "object_id": b64_encode(object_id),
            "object_type": "text",
            "payload": {
                "type": "text",
                "alg": "aes-256-gcm",
                "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(b"P" * 32)},
                "metadata_policy": "hidden",
                "nonce": b64_encode(b"N" * 12),
                "plaintext_length": 100,
            },
            "metadata": {"policy": "hidden"},
        }

        fp_bytes = hashlib.sha256(
            b"secure-string-cipher/v2/key-fingerprint/symmetric" + k
        ).digest()
        fingerprint = "ssc-k1-" + base64.b32encode(fp_bytes).decode("ascii").rstrip("=")

        w_context = dict(m_context)
        w_context["access"] = {
            "version": 1,
            "policy": "single-grant",
            "grants": [
                {
                    "grant_id": "grant-0",
                    "type": "managed-key",
                    "key_fingerprint": fingerprint,
                    "kek_derivation": {
                        "alg": "hkdf-sha256",
                        "salt": b64_encode(kek_salt),
                    },
                    "wrap_alg": "aes-256-gcm",
                    "wrap_nonce": b64_encode(wrap_nonce),
                    "commitment": {
                        "alg": "hmac-sha256",
                        "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(commit_salt)},
                    },
                }
            ],
        }

        wrap_aad = (
            b"SSC2/wrap/v1\0" + hashlib.sha256(canonical_json(w_context)).digest()
        )
        aead = AESGCM(kek)
        wrapped_full = aead.encrypt(wrap_nonce, dek, wrap_aad)
        wrapped_dek = wrapped_full[:-16]
        tag = wrapped_full[-16:]

        q_context = json.loads(json.dumps(w_context))
        q_context["access"]["grants"][0]["wrapped_dek"] = b64_encode(wrapped_dek)
        q_context["access"]["grants"][0]["tag"] = b64_encode(tag)

        commit_value = hmac.new(
            k_commit,
            b"SSC2/commit/v1\0" + hashlib.sha256(canonical_json(q_context)).digest(),
            hashlib.sha256,
        ).digest()

        complete_header = json.loads(json.dumps(q_context))
        complete_header["access"]["grants"][0]["commitment"]["value"] = b64_encode(
            commit_value
        )

        payload_header_digest = hashlib.sha256(canonical_json(complete_header)).digest()

        return {
            "managed_secret": b64_encode(k),
            "fingerprint": fingerprint,
            "dek": b64_encode(dek),
            "r": b64_encode(r),
            "kek": b64_encode(kek),
            "k_commit": b64_encode(k_commit),
            "wrap_aad": b64_encode(wrap_aad),
            "wrapped_dek": b64_encode(wrapped_dek),
            "tag": b64_encode(tag),
            "commit_value": b64_encode(commit_value),
            "payload_header_digest": b64_encode(payload_header_digest),
            "complete_header": complete_header,
        }

    manifest["grants"]["managed_key"] = make_managed_key_grant()

    def make_combined_grant():
        k = b"M" * 32
        p = do_argon2(pw, a2_salt)

        mk_salt = b"Y" * 32
        m = do_hkdf(
            k, mk_salt, "secure-string-cipher/v2/combined/managed-key-component"
        )
        root_salt = b"Z" * 32
        r = do_hkdf(
            p + m,
            root_salt,
            "secure-string-cipher/v2/combined/password+managed-key/root",
        )

        kek_salt = b"K" * 32
        kek = do_hkdf(
            r,
            kek_salt,
            "secure-string-cipher/v2/combined/password+managed-key/dek-wrap/aes-256-gcm",
        )
        commit_salt = b"C" * 32
        k_commit = do_hkdf(
            r, commit_salt, "secure-string-cipher/v2/grant/key-commitment/hmac-sha256"
        )

        wrap_nonce = b"W" * 12
        m_context = {
            "format": "SSC2",
            "version": 2,
            "object_id": b64_encode(object_id),
            "object_type": "text",
            "payload": {
                "type": "text",
                "alg": "aes-256-gcm",
                "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(b"P" * 32)},
                "metadata_policy": "hidden",
                "nonce": b64_encode(b"N" * 12),
                "plaintext_length": 100,
            },
            "metadata": {"policy": "hidden"},
        }

        fp_bytes = hashlib.sha256(
            b"secure-string-cipher/v2/key-fingerprint/symmetric" + k
        ).digest()
        fingerprint = "ssc-k1-" + base64.b32encode(fp_bytes).decode("ascii").rstrip("=")

        w_context = dict(m_context)
        w_context["access"] = {
            "version": 1,
            "policy": "single-grant",
            "grants": [
                {
                    "grant_id": "grant-0",
                    "type": "combined-password-managed-key",
                    "password_kdf": {
                        "alg": "argon2id",
                        "version": 19,
                        "memory_kib": 65536,
                        "time_cost": 3,
                        "parallelism": 4,
                        "hash_len": 32,
                        "salt": b64_encode(a2_salt),
                    },
                    "key_fingerprint": fingerprint,
                    "combined_kdf": {
                        "alg": "hkdf-sha256",
                        "salt": b64_encode(root_salt),
                        "managed_key_salt": b64_encode(mk_salt),
                    },
                    "kek_derivation": {
                        "alg": "hkdf-sha256",
                        "salt": b64_encode(kek_salt),
                    },
                    "wrap_alg": "aes-256-gcm",
                    "wrap_nonce": b64_encode(wrap_nonce),
                    "commitment": {
                        "alg": "hmac-sha256",
                        "kdf": {"alg": "hkdf-sha256", "salt": b64_encode(commit_salt)},
                    },
                }
            ],
        }

        wrap_aad = (
            b"SSC2/wrap/v1\0" + hashlib.sha256(canonical_json(w_context)).digest()
        )
        aead = AESGCM(kek)
        wrapped_full = aead.encrypt(wrap_nonce, dek, wrap_aad)
        wrapped_dek = wrapped_full[:-16]
        tag = wrapped_full[-16:]

        q_context = json.loads(json.dumps(w_context))
        q_context["access"]["grants"][0]["wrapped_dek"] = b64_encode(wrapped_dek)
        q_context["access"]["grants"][0]["tag"] = b64_encode(tag)

        commit_value = hmac.new(
            k_commit,
            b"SSC2/commit/v1\0" + hashlib.sha256(canonical_json(q_context)).digest(),
            hashlib.sha256,
        ).digest()

        complete_header = json.loads(json.dumps(q_context))
        complete_header["access"]["grants"][0]["commitment"]["value"] = b64_encode(
            commit_value
        )

        payload_header_digest = hashlib.sha256(canonical_json(complete_header)).digest()

        return {
            "password": pw.decode("utf-8"),
            "argon2_salt": b64_encode(a2_salt),
            "managed_secret": b64_encode(k),
            "fingerprint": fingerprint,
            "dek": b64_encode(dek),
            "m": b64_encode(m),
            "r": b64_encode(r),
            "kek": b64_encode(kek),
            "k_commit": b64_encode(k_commit),
            "wrap_aad": b64_encode(wrap_aad),
            "wrapped_dek": b64_encode(wrapped_dek),
            "tag": b64_encode(tag),
            "commit_value": b64_encode(commit_value),
            "payload_header_digest": b64_encode(payload_header_digest),
            "complete_header": complete_header,
        }

    manifest["grants"]["combined"] = make_combined_grant()

    # 4. Vault inner wrap
    vault_id = b"V" * 16
    record_id = b"R" * 16
    vault_root_key = do_argon2(pw, a2_salt)
    vault_copy_salt = b"S" * 32
    vault_copy_kek = do_hkdf(
        vault_root_key,
        vault_copy_salt,
        "secure-string-cipher/v2/vault-copy/key-material-wrap/aes-256-gcm",
    )

    managed_secret = b"M" * 32
    fp_bytes = hashlib.sha256(
        b"secure-string-cipher/v2/key-fingerprint/symmetric" + managed_secret
    ).digest()
    fingerprint = "ssc-k1-" + base64.b32encode(fp_bytes).decode("ascii").rstrip("=")

    v_context = {
        "schema_version": 2,
        "vault_id": b64_encode(vault_id),
        "wrap_generation": 1,
        "vault_kdf": {
            "alg": "argon2id",
            "version": 19,
            "memory_kib": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
            "salt": b64_encode(a2_salt),
        },
        "record_id": b64_encode(record_id),
        "key_type": "symmetric-key",
        "fingerprint": fingerprint,
        "storage": "vault-copy",
        "protection": "vault-wrapped",
        "wrap_alg": "aes-256-gcm",
        "kek_derivation": {"alg": "hkdf-sha256", "salt": b64_encode(vault_copy_salt)},
        "nonce": b64_encode(b"N" * 12),
    }
    vault_copy_aad = (
        b"SSC2/vault-copy/v1\0" + hashlib.sha256(canonical_json(v_context)).digest()
    )
    aead_vault = AESGCM(vault_copy_kek)
    vault_wrapped_full = aead_vault.encrypt(b"N" * 12, managed_secret, vault_copy_aad)

    manifest["vault"]["inner_wrap"] = {
        "password": pw.decode("utf-8"),
        "argon2_salt": b64_encode(a2_salt),
        "managed_secret": b64_encode(managed_secret),
        "fingerprint": fingerprint,
        "vault_copy_aad": b64_encode(vault_copy_aad),
        "wrapped_material": b64_encode(vault_wrapped_full[:-16]),
        "tag": b64_encode(vault_wrapped_full[-16:]),
        "v_context": v_context,
    }

    # 5. Keyfile round trip
    keyfile_content = f"-----BEGIN SSC SYMMETRIC KEY-----\nVersion: 1\nKey-ID: test-key\nType: symmetric-key\nKDF: hkdf-sha256\nFingerprint: {fingerprint}\nCreated: 2026-09-09T00:00:00Z\n\n{b64_encode(managed_secret)}\n-----END SSC SYMMETRIC KEY-----\n"
    keyfile_sha256 = hashlib.sha256(keyfile_content.encode("utf-8")).hexdigest()
    manifest["keyfile"]["round_trip"] = {
        "content": keyfile_content,
        "secret": b64_encode(managed_secret),
        "fingerprint": fingerprint,
        "sha256": keyfile_sha256,
    }

    # 6. Migration
    legacy_vault_input = {
        "gmail": "secret123",
        "github": "token456",
        "schema_version": "this-is-a-password",
        "vault_meta": "also-a-password",
        "items": "yet-another-password",
    }
    v2_vault_output = {
        "schema_version": 2,
        "vault_meta": {
            "vault_id": b64_encode(vault_id),
            "revision": 1,
            "wrap_generation": 1,
            "vault_kdf": {
                "alg": "argon2id",
                "version": 19,
                "memory_kib": 65536,
                "time_cost": 3,
                "parallelism": 4,
                "hash_len": 32,
                "salt": b64_encode(a2_salt),
            },
        },
        "items": {
            "passphrases": {
                "github": "token456",
                "gmail": "secret123",
                "items": "yet-another-password",
                "schema_version": "this-is-a-password",
                "vault_meta": "also-a-password",
            },
            "keys": {},
        },
    }
    manifest["migration"]["flat_to_v2"] = {
        "legacy_input": legacy_vault_input,
        "v2_output": v2_vault_output,
        "vault_id": b64_encode(vault_id),
        "argon2_salt": b64_encode(a2_salt),
    }

    with open("tests/fixtures/v2/manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    with open("tests/fixtures/v2/password_grant_header.json", "w") as f:
        json.dump(manifest["grants"]["password"]["complete_header"], f, indent=2)

    with open("tests/fixtures/v2/managed_key_grant_header.json", "w") as f:
        json.dump(manifest["grants"]["managed_key"]["complete_header"], f, indent=2)

    with open("tests/fixtures/v2/combined_grant_header.json", "w") as f:
        json.dump(manifest["grants"]["combined"]["complete_header"], f, indent=2)

    with open("tests/fixtures/v2/test-key.ssckey", "w") as f:
        f.write(manifest["keyfile"]["round_trip"]["content"])

    with open("tests/fixtures/v2/legacy_vault_pre_migration.json", "w") as f:
        json.dump(manifest["migration"]["flat_to_v2"]["legacy_input"], f, indent=2)

    with open("tests/fixtures/v2/v2_vault_post_migration.json", "w") as f:
        json.dump(manifest["migration"]["flat_to_v2"]["v2_output"], f, indent=2)


if __name__ == "__main__":
    main()
