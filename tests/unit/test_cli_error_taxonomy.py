"""Tests for the CLI's exception-to-exit-code mapping.

Before this mapping existed, `main()` caught every exception with a bare
`except Exception` and reported "Command failed." with EXIT_INPUT_ERROR. A
script could not distinguish bad arguments from a full disk, a revoked key,
or a bug in this program, and the real cause was discarded entirely.
"""

from pathlib import Path

import pytest

from secure_string_cipher.cli_args import (
    EXIT_AUTH_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_VAULT_ERROR,
    _classify_failure,
    _env_flag_enabled,
    create_parser,
)
from secure_string_cipher.core import CryptoError
from secure_string_cipher.keychain_backend import KeychainError
from secure_string_cipher.passphrase_manager import VaultTransactionError
from secure_string_cipher.rate_limiter import RateLimitError
from secure_string_cipher.security import SecurityError
from secure_string_cipher.v2.keywrap import DekUnwrapError, GrantCommitmentError
from secure_string_cipher.v2.vault_lock import VaultBusyError
from secure_string_cipher.v2.vault_service import (
    KeyExportSurvivedRegistrationFailureError,
)


class TestExitCodeMapping:
    @pytest.mark.parametrize(
        ("error", "expected_code"),
        [
            (RateLimitError(12.5), EXIT_AUTH_ERROR),
            (CryptoError("decryption failed"), EXIT_AUTH_ERROR),
            (GrantCommitmentError("commitment mismatch"), EXIT_AUTH_ERROR),
            (DekUnwrapError("unwrap failed"), EXIT_AUTH_ERROR),
            (VaultBusyError("vault is locked"), EXIT_VAULT_ERROR),
            (VaultTransactionError("write", "rollback failed"), EXIT_VAULT_ERROR),
            (KeychainError("keychain refused"), EXIT_VAULT_ERROR),
            (
                KeyExportSurvivedRegistrationFailureError(
                    Path("/keys/k.ssckey"), RuntimeError("vault commit failed")
                ),
                EXIT_VAULT_ERROR,
            ),
            (SecurityError("symlink rejected"), EXIT_FILE_ERROR),
            (PermissionError(13, "Permission denied"), EXIT_FILE_ERROR),
            (FileNotFoundError(2, "No such file"), EXIT_FILE_ERROR),
            (IsADirectoryError(21, "Is a directory"), EXIT_FILE_ERROR),
            (OSError(28, "No space left on device"), EXIT_FILE_ERROR),
            (EOFError(), EXIT_INPUT_ERROR),
        ],
    )
    def test_known_failures_map_to_documented_codes(
        self, error: Exception, expected_code: int
    ) -> None:
        code, message = _classify_failure(error)
        assert code == expected_code
        assert message, "every classified failure must carry a message"

    @pytest.mark.parametrize(
        "error",
        [
            RuntimeError("unexpected"),
            AttributeError("'NoneType' has no attribute 'x'"),
            TypeError("bad operand"),
            ZeroDivisionError("division by zero"),
        ],
    )
    def test_unexpected_failures_use_the_internal_error_code(
        self, error: Exception
    ) -> None:
        code, _ = _classify_failure(error)
        assert code == EXIT_INTERNAL_ERROR, (
            "a fault in this program must not be reported as an input error"
        )

    def test_subclasses_of_value_error_are_not_misclassified(self) -> None:
        """VaultBusyError and KeyWrapError both derive from ValueError.

        A mapping that tested bases first would send these to the internal
        error code instead of their documented ones.
        """
        assert _classify_failure(VaultBusyError("busy"))[0] == EXIT_VAULT_ERROR
        assert _classify_failure(DekUnwrapError("nope"))[0] == EXIT_AUTH_ERROR
        # A plain ValueError has no documented code and is a program fault.
        assert _classify_failure(ValueError("plain"))[0] == EXIT_INTERNAL_ERROR

    def test_key_error_is_an_internal_fault_not_a_vault_miss(self) -> None:
        """KeyError is a common programming fault and its str() is the key.

        Mapping it to a vault miss would both mislabel ordinary bugs and echo
        whatever the missing key happened to be.
        """
        code, message = _classify_failure(KeyError("some-internal-dict-key"))
        assert code == EXIT_INTERNAL_ERROR
        assert "some-internal-dict-key" not in message

    def test_permission_error_is_not_treated_as_a_generic_os_error(self) -> None:
        """PermissionError derives from OSError; both land on EXIT_FILE_ERROR."""
        code, message = _classify_failure(
            PermissionError(13, "Permission denied", "/vault/x.enc")
        )
        assert code == EXIT_FILE_ERROR
        assert "/vault/x.enc" in message, "the offending path should be reported"


class TestNoLeakageOnUnexpectedFailures:
    def test_unexpected_failure_message_omits_the_exception_text(self) -> None:
        """An unexpected exception's message may hold interpolated secrets.

        Only the type name is surfaced; the content is reachable via --debug,
        which the operator opts into.
        """
        secret = "CorrectHorseBatteryStaple1!"  # pragma: allowlist secret
        _, message = _classify_failure(RuntimeError(f"failed for {secret}"))
        assert secret not in message
        assert "RuntimeError" in message
        assert "--debug" in message, "the message should say how to get detail"

    def test_classified_failures_still_explain_themselves(self) -> None:
        """Known types are safe to quote: their messages are authored here."""
        _, message = _classify_failure(RateLimitError(30.0))
        assert "30" in message


class TestDebugFlag:
    def test_debug_flag_is_accepted_and_defaults_off(self) -> None:
        parser = create_parser()
        assert parser.parse_args(["vault", "list"]).debug is False
        assert parser.parse_args(["--debug", "vault", "list"]).debug is True

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " on "])
    def test_affirmative_env_values_enable_debug(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_DEBUG", value)
        assert _env_flag_enabled("SSC_DEBUG") is True

    @pytest.mark.parametrize("value", ["", "0", "false", "FALSE", "no", "off", "maybe"])
    def test_non_affirmative_env_values_leave_debug_off(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`SSC_DEBUG=false` must not enable debug output.

        A deployment manifest disabling a boolean by setting it to "false" is
        common, and enabling traceback printing there would start emitting
        exception text.
        """
        monkeypatch.setenv("SSC_DEBUG", value)
        assert _env_flag_enabled("SSC_DEBUG") is False

    def test_unset_env_leaves_debug_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSC_DEBUG", raising=False)
        assert _env_flag_enabled("SSC_DEBUG") is False
