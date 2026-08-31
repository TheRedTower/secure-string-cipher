"""CLI-only transport compatibility for raw vault files."""


def canonicalize_cli_vault_candidate(contents: bytes) -> bytes:
    """Remove exactly one legacy terminal LF or CRLF from CLI input bytes."""
    if contents.endswith(b"\r\n"):
        return contents[:-2]
    if contents.endswith(b"\n"):
        return contents[:-1]
    return contents
