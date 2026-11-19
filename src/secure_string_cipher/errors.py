"""Errors raised by SSC, and the reason codes the test vectors name."""

from enum import StrEnum


class Reason(StrEnum):
    """Why a file was rejected. The values match the `reason` field of the
    rejection vectors in tests/vectors/manifest.json."""

    MAGIC = "magic"
    VERSION = "version"
    TRUNCATED = "truncated"
    CHUNK_AUTH = "chunk-auth"
    EMPTY_FINAL_CHUNK = "empty-final-chunk"
    TOO_MANY_CHUNKS = "too-many-chunks"


class SSCError(Exception):
    """Base class for every error SSC raises on purpose."""


class FormatError(SSCError):
    """The input is not a valid SSC file, or it is corrupt or truncated.

    The CLI reports this as a file error (CLI.md section 1, exit code 4).
    """

    def __init__(self, reason: Reason, message: str) -> None:
        super().__init__(message)
        self.reason = reason
