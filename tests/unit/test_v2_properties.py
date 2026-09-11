"""Property-based testing scaffold for V2 components."""

import hypothesis.strategies as st
from hypothesis import given

from secure_string_cipher.v2.vault_schema import b64url_decode, b64url_encode


@given(
    data=st.binary(min_size=0, max_size=1024),
)
def test_b64url_roundtrip(data):
    """Proof of capability: Test that b64url encoding and decoding round-trips correctly."""
    encoded = b64url_encode(data)
    assert isinstance(encoded, str)

    # Must not contain padding
    assert "=" not in encoded

    decoded = b64url_decode(encoded)
    assert decoded == data
