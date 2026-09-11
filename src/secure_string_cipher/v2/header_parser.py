"""Wire-format parsing and validation for V2 protected headers."""

import json
from typing import Any, BinaryIO

from secure_string_cipher.v2.envelope import (
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    CommitmentDescriptor,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
    canonical_json,
)
from secure_string_cipher.v2.vault_schema import (
    _as_int,
    _reject_duplicate_object_hook,
    b64url_decode,
)


def _validate_hkdf_sha256(mapping: Any, context: str) -> None:
    if not isinstance(mapping, dict):
        raise TypeError(f"{context} must be a dictionary")
    alg = mapping.get("alg")
    if alg != "hkdf-sha256":
        raise ValueError(f"{context} alg must be 'hkdf-sha256', got {alg!r}")
    salt = mapping.get("salt")
    if not isinstance(salt, str):
        raise ValueError(f"{context} salt must be a string")
    b64url_decode(salt, expected_length=32)
    extra = set(mapping.keys()) - {"alg", "salt"}
    if extra:
        raise ValueError(f"Unexpected keys in {context}: {sorted(extra)}")


def _validate_argon2id(mapping: Any, context: str) -> None:
    if not isinstance(mapping, dict):
        raise TypeError(f"{context} must be a dictionary")
    alg = mapping.get("alg")
    if alg != "argon2id":
        raise ValueError(f"{context} alg must be 'argon2id', got {alg!r}")
    version = _as_int(mapping.get("version"))
    if version != 19:
        raise ValueError(f"{context} version must be 19")
    memory_kib = _as_int(mapping.get("memory_kib"))
    if memory_kib != 65536:
        raise ValueError(f"{context} memory_kib must be 65536")
    time_cost = _as_int(mapping.get("time_cost"))
    if time_cost != 3:
        raise ValueError(f"{context} time_cost must be 3")
    parallelism = _as_int(mapping.get("parallelism"))
    if parallelism != 4:
        raise ValueError(f"{context} parallelism must be 4")
    hash_len = _as_int(mapping.get("hash_len"))
    if hash_len != 32:
        raise ValueError(f"{context} hash_len must be 32")
    salt = mapping.get("salt")
    if not isinstance(salt, str):
        raise ValueError(f"{context} salt must be a string")
    b64url_decode(salt, expected_length=16)

    expected = {
        "alg",
        "version",
        "memory_kib",
        "time_cost",
        "parallelism",
        "hash_len",
        "salt",
    }
    extra = set(mapping.keys()) - expected
    if extra:
        raise ValueError(f"Unexpected keys in {context}: {sorted(extra)}")


def validate_v2_header(
    doc: dict[str, Any], raw_json_bytes: bytes | None = None
) -> V2Header:
    if not isinstance(doc, dict):
        raise TypeError("Header document must be a dictionary")

    expected_top = {
        "format",
        "version",
        "object_id",
        "object_type",
        "payload",
        "access",
        "metadata",
    }
    extra_top = set(doc.keys()) - expected_top
    if extra_top:
        raise ValueError(f"Unexpected keys in header: {sorted(extra_top)}")

    if doc.get("format") != "SSC2":
        raise ValueError("Header format must be 'SSC2'")

    version = doc.get("version")
    if not (isinstance(version, int) and not isinstance(version, bool)) or version != 2:
        raise ValueError(f"Header version must be 2, got {version!r}")

    object_id = doc.get("object_id")
    if not isinstance(object_id, str):
        raise TypeError("object_id must be a string")
    b64url_decode(object_id, expected_length=16)

    object_type_str = doc.get("object_type")
    if not isinstance(object_type_str, str):
        raise TypeError("object_type must be a string")

    # payload
    payload_dict = doc.get("payload")
    if not isinstance(payload_dict, dict):
        raise ValueError("payload must be a dictionary")

    payload_type_str = payload_dict.get("type")
    if object_type_str != payload_type_str:
        raise ValueError(
            f"object_type {object_type_str!r} does not match payload type {payload_type_str!r}"
        )

    try:
        payload_type = PayloadType(payload_type_str)
    except ValueError:
        raise ValueError(f"Unknown payload type: {payload_type_str!r}") from None

    payload_alg = payload_dict.get("alg")
    if payload_alg != "aes-256-gcm":
        raise ValueError(f"payload alg must be 'aes-256-gcm', got {payload_alg!r}")

    payload_kdf = payload_dict.get("kdf")
    _validate_hkdf_sha256(payload_kdf, "payload.kdf")
    assert isinstance(payload_kdf, dict)

    mp_str = payload_dict.get("metadata_policy")
    try:
        metadata_policy = MetadataPolicy(mp_str)
    except ValueError:
        raise ValueError(f"Unknown metadata_policy: {mp_str!r}") from None

    expected_payload_keys = {"type", "alg", "kdf", "metadata_policy"}
    if payload_type == PayloadType.FILE:
        expected_payload_keys.update({"chunk_size", "nonce_prefix"})
    elif payload_type == PayloadType.TEXT:
        expected_payload_keys.update({"nonce", "plaintext_length"})

    extra_payload = set(payload_dict.keys()) - expected_payload_keys
    if extra_payload:
        raise ValueError(f"Unexpected keys in payload: {sorted(extra_payload)}")

    chunk_size = None
    nonce_prefix = None
    nonce = None
    plaintext_length = None

    if payload_type == PayloadType.FILE:
        chunk_size = payload_dict.get("chunk_size")
        if not (isinstance(chunk_size, int) and not isinstance(chunk_size, bool)):
            raise ValueError("chunk_size must be an integer")
        nonce_prefix = payload_dict.get("nonce_prefix")
        if not isinstance(nonce_prefix, str):
            raise TypeError("nonce_prefix must be a string")
        b64url_decode(nonce_prefix, expected_length=4)
    else:
        nonce = payload_dict.get("nonce")
        if not isinstance(nonce, str):
            raise TypeError("nonce must be a string")
        b64url_decode(nonce, expected_length=12)
        plaintext_length = payload_dict.get("plaintext_length")
        if not (
            isinstance(plaintext_length, int) and not isinstance(plaintext_length, bool)
        ):
            raise ValueError("plaintext_length must be an integer")

    payload_desc = PayloadDescriptor(
        type=payload_type,
        alg=payload_alg,
        kdf=dict(payload_kdf),
        metadata_policy=metadata_policy,
        chunk_size=chunk_size,
        nonce_prefix=nonce_prefix,
        nonce=nonce,
        plaintext_length=plaintext_length,
    )

    # metadata
    metadata_dict = doc.get("metadata")
    if not isinstance(metadata_dict, dict):
        raise ValueError("metadata must be a dictionary")

    # The payload descriptor's metadata_policy and the metadata block's own
    # "policy" field are two independent places the same fact is recorded;
    # both end up in the authenticated M_context, so a header where they
    # disagree is malformed and must be rejected here rather than letting
    # metadata decryption later decide which one it trusts.
    if metadata_dict.get("policy") != metadata_policy.value:
        raise ValueError(
            f"metadata.policy {metadata_dict.get('policy')!r} does not match "
            f"payload.metadata_policy {metadata_policy.value!r}"
        )

    if metadata_policy == MetadataPolicy.HIDDEN:
        if set(metadata_dict.keys()) != {"policy"}:
            raise ValueError("hidden metadata must be exactly {'policy': 'hidden'}")
    elif metadata_policy == MetadataPolicy.ENCRYPTED:
        meta_alg = metadata_dict.get("alg")
        if meta_alg != "aes-256-gcm":
            raise ValueError(f"metadata alg must be 'aes-256-gcm', got {meta_alg!r}")

        meta_kdf = metadata_dict.get("kdf")
        _validate_hkdf_sha256(meta_kdf, "metadata.kdf")

        meta_nonce = metadata_dict.get("nonce")
        if not isinstance(meta_nonce, str):
            raise TypeError("metadata nonce must be a string")
        b64url_decode(meta_nonce, expected_length=12)

        meta_ciphertext = metadata_dict.get("ciphertext")
        if not isinstance(meta_ciphertext, str):
            raise TypeError("metadata ciphertext must be a string")
        b64url_decode(meta_ciphertext)

        meta_tag = metadata_dict.get("tag")
        if not isinstance(meta_tag, str):
            raise TypeError("metadata tag must be a string")
        b64url_decode(meta_tag, expected_length=16)

        expected_meta_keys = {"policy", "alg", "kdf", "nonce", "ciphertext", "tag"}
        extra_meta = set(metadata_dict.keys()) - expected_meta_keys
        if extra_meta:
            raise ValueError(f"Unexpected keys in metadata: {sorted(extra_meta)}")

    # access
    access_dict = doc.get("access")
    if not isinstance(access_dict, dict):
        raise ValueError("access must be a dictionary")

    acc_version = access_dict.get("version")
    if (
        not (isinstance(acc_version, int) and not isinstance(acc_version, bool))
        or acc_version != 1
    ):
        raise ValueError(f"access.version must be 1, got {acc_version!r}")

    acc_policy_str = access_dict.get("policy")
    try:
        acc_policy = AccessPolicy(acc_policy_str)
    except ValueError:
        raise ValueError(f"Unknown access policy: {acc_policy_str!r}") from None

    grants_list = access_dict.get("grants")
    if not isinstance(grants_list, list):
        raise TypeError("access.grants must be a list")

    expected_access_keys = {"version", "policy", "grants"}
    extra_access = set(access_dict.keys()) - expected_access_keys
    if extra_access:
        raise ValueError(f"Unexpected keys in access: {sorted(extra_access)}")

    parsed_grants = []
    for grant_doc in grants_list:
        if not isinstance(grant_doc, dict):
            raise TypeError("access grant must be a dictionary")

        grant_id = grant_doc.get("grant_id")
        if not isinstance(grant_id, str):
            raise TypeError("grant_id must be a string")

        grant_type_str = grant_doc.get("type")
        try:
            grant_type = GrantType(grant_type_str)
        except ValueError:
            raise ValueError(f"Unknown grant type: {grant_type_str!r}") from None

        expected_grant_keys = {
            "grant_id",
            "type",
            "kek_derivation",
            "wrap_alg",
            "wrap_nonce",
            "wrapped_dek",
            "tag",
        }

        kek_derivation = grant_doc.get("kek_derivation")
        _validate_hkdf_sha256(kek_derivation, f"grant {grant_id} kek_derivation")
        assert isinstance(kek_derivation, dict)

        wrap_alg = grant_doc.get("wrap_alg")
        if wrap_alg != "aes-256-gcm":
            raise ValueError(f"grant wrap_alg must be 'aes-256-gcm', got {wrap_alg!r}")

        wrap_nonce = grant_doc.get("wrap_nonce")
        if not isinstance(wrap_nonce, str):
            raise TypeError("wrap_nonce must be a string")
        b64url_decode(wrap_nonce, expected_length=12)

        wrapped_dek = grant_doc.get("wrapped_dek")
        if not isinstance(wrapped_dek, str):
            raise TypeError("wrapped_dek must be a string")
        b64url_decode(wrapped_dek, expected_length=32)

        tag = grant_doc.get("tag")
        if not isinstance(tag, str):
            raise TypeError("tag must be a string")
        b64url_decode(tag, expected_length=16)

        password_kdf = None
        combined_kdf = None
        key_fingerprint = None
        commitment = None

        if grant_type == GrantType.PASSWORD:
            expected_grant_keys.update({"password_kdf", "commitment"})
            password_kdf = grant_doc.get("password_kdf")
            _validate_argon2id(password_kdf, f"grant {grant_id} password_kdf")

        elif grant_type == GrantType.MANAGED_KEY:
            expected_grant_keys.update({"key_fingerprint", "commitment"})
            key_fingerprint = grant_doc.get("key_fingerprint")

        elif grant_type == GrantType.COMBINED_PASSWORD_MANAGED_KEY:
            expected_grant_keys.update(
                {"password_kdf", "combined_kdf", "key_fingerprint", "commitment"}
            )
            password_kdf = grant_doc.get("password_kdf")
            _validate_argon2id(password_kdf, f"grant {grant_id} password_kdf")
            combined_kdf = grant_doc.get("combined_kdf")
            if not isinstance(combined_kdf, dict):
                raise TypeError(f"grant {grant_id} combined_kdf must be a dictionary")
            alg = combined_kdf.get("alg")
            if alg != "hkdf-sha256":
                raise ValueError(f"combined_kdf alg must be 'hkdf-sha256', got {alg!r}")
            salt = combined_kdf.get("salt")
            if not isinstance(salt, str):
                raise ValueError("combined_kdf salt must be a string")
            b64url_decode(salt, expected_length=32)
            managed_key_salt = combined_kdf.get("managed_key_salt")
            if not isinstance(managed_key_salt, str):
                raise ValueError("combined_kdf managed_key_salt must be a string")
            b64url_decode(managed_key_salt, expected_length=32)

            ext_comb = set(combined_kdf.keys()) - {"alg", "salt", "managed_key_salt"}
            if ext_comb:
                raise ValueError(f"Unexpected keys in combined_kdf: {sorted(ext_comb)}")

            key_fingerprint = grant_doc.get("key_fingerprint")

        extra_grant = set(grant_doc.keys()) - expected_grant_keys
        if extra_grant:
            raise ValueError(
                f"Unexpected keys in grant {grant_id}: {sorted(extra_grant)}"
            )

        if "commitment" in expected_grant_keys:
            commit_doc = grant_doc.get("commitment")
            if not isinstance(commit_doc, dict):
                raise TypeError(f"grant {grant_id} commitment must be a dictionary")
            commit_alg = commit_doc.get("alg")
            if commit_alg != "hmac-sha256":
                raise ValueError(
                    f"commitment alg must be 'hmac-sha256', got {commit_alg!r}"
                )
            commit_kdf = commit_doc.get("kdf")
            _validate_hkdf_sha256(commit_kdf, f"grant {grant_id} commitment.kdf")
            assert isinstance(commit_kdf, dict)
            commit_val = commit_doc.get("value")
            if not isinstance(commit_val, str):
                raise TypeError("commitment value must be a string")
            b64url_decode(commit_val, expected_length=32)

            commit_extra = set(commit_doc.keys()) - {"alg", "kdf", "value"}
            if commit_extra:
                raise ValueError(
                    f"Unexpected keys in commitment: {sorted(commit_extra)}"
                )

            commitment = CommitmentDescriptor(
                alg=commit_alg,
                kdf=dict(commit_kdf),
                value=commit_val,
            )

        parsed_grants.append(
            AccessGrant(
                grant_id=grant_id,
                type=grant_type,
                kek_derivation=dict(kek_derivation),
                wrap_alg=wrap_alg,
                wrap_nonce=wrap_nonce,
                wrapped_dek=wrapped_dek,
                tag=tag,
                commitment=commitment,
                key_fingerprint=key_fingerprint,
                password_kdf=dict(password_kdf) if password_kdf else None,
                combined_kdf=dict(combined_kdf) if combined_kdf else None,
            )
        )

    access_block = AccessBlock(
        version=acc_version,
        policy=acc_policy,
        grants=parsed_grants,
    )

    v2_header = V2Header(
        format="SSC2",
        version=version,
        object_id=object_id,
        object_type=object_type_str,
        payload=payload_desc,
        access=access_block,
        metadata=dict(metadata_dict),
    )

    if raw_json_bytes is not None:
        expected_canonical = canonical_json(doc)
        if expected_canonical != raw_json_bytes:
            raise ValueError(
                "Header document does not match canonical JSON representation"
            )

    return v2_header


def parse_header_stream(stream: BinaryIO) -> tuple[V2Header, bytes]:
    magic = stream.read(4)
    if not magic:
        raise EOFError("Empty stream")
    if magic == b"SSCV":
        # Check if the next byte is '2' to be sure, or just reject
        raise ValueError("Unsupported legacy V2 preview schema")
    if magic != b"SSC2":
        raise ValueError(f"Invalid magic: {magic!r}")

    length_bytes = stream.read(4)
    if len(length_bytes) != 4:
        raise ValueError("Truncated header length")

    header_length = int.from_bytes(length_bytes, "little")
    if header_length < 1 or header_length > 65536:
        raise ValueError(f"Header length out of bounds: {header_length}")

    raw_json_bytes = stream.read(header_length)
    if len(raw_json_bytes) != header_length:
        raise ValueError("Truncated header JSON")

    try:
        text = raw_json_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("Header is not valid UTF-8") from e

    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_object_hook)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid JSON in header: {e}") from e

    v2_header = validate_v2_header(parsed, raw_json_bytes)
    return v2_header, raw_json_bytes
