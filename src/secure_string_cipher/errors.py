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
    ACCESS_LENGTH = "access-length"
    ACCESS_BODY_LENGTH = "access-body-length"
    GRANT_COUNT = "grant-count"
    GRANT_LENGTH = "grant-length"
    FACTOR_COUNT = "factor-count"
    FACTOR_ORDER = "factor-order"
    ARGON_PARAMS = "argon-params"
    ARMOR_FRAME = "armor-frame"
    ARMOR_LINE_ENDINGS = "armor-line-endings"
    ARMOR_LINE_LENGTH = "armor-line-length"
    ARMOR_BASE64 = "armor-base64"
    KEYFILE = "keyfile"
    KEYFILE_KEY_ID = "keyfile-key-id"
    CANNOT_OPEN = "cannot-open"


class SSCError(Exception):
    """Base class for every error SSC raises on purpose."""

    reason: Reason


class FormatError(SSCError):
    """The input is not a valid SSC file, or it is corrupt or truncated.

    The CLI reports this as a file error (CLI.md section 1, exit code 4).
    """

    def __init__(self, reason: Reason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class CannotOpen(SSCError):
    """None of the file's grants could be opened with what was supplied.

    The message never says which grant or factor was wrong (ACCESS.md
    section 4). The CLI reports this as exit code 2.
    """

    reason = Reason.CANNOT_OPEN

    def __init__(self) -> None:
        super().__init__("This file cannot be opened with what was supplied.")
