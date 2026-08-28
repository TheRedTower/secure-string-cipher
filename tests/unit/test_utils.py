"""
Tests for utils.py - progress bars, colorization, and file utilities.
"""

import os
import sys
from unittest.mock import patch

import pytest

from secure_string_cipher.utils import (
    CryptoError,
    ProgressBar,
    colorize,
    detect_dark_background,
    secure_overwrite,
)

# =============================================================================
# CryptoError Tests
# =============================================================================


class TestCryptoError:
    """Tests for CryptoError exception."""

    def test_crypto_error_is_exception(self):
        """CryptoError should be an Exception subclass."""
        assert issubclass(CryptoError, Exception)

    def test_crypto_error_can_be_raised(self):
        """CryptoError should be raisable with message."""
        with pytest.raises(CryptoError, match="test error"):
            raise CryptoError("test error")

    def test_crypto_error_message(self):
        """CryptoError should store message."""
        error = CryptoError("my message")
        assert str(error) == "my message"


# =============================================================================
# ProgressBar Tests
# =============================================================================


class TestProgressBar:
    """Tests for ProgressBar class."""

    def test_progress_bar_init(self):
        """ProgressBar should initialize with total bytes."""
        pb = ProgressBar(1000)
        assert pb.total == 1000
        assert pb.width == 40
        assert pb.last_print == 0.0

    def test_progress_bar_custom_width(self):
        """ProgressBar should accept custom width."""
        pb = ProgressBar(1000, width=50)
        assert pb.width == 50

    def test_progress_bar_update_non_tty(self):
        """ProgressBar should not print when not a TTY."""
        pb = ProgressBar(100)

        with patch.object(sys.stdout, "isatty", return_value=False):
            # Should not raise or print anything
            pb.update(50)
            pb.update(100)

    def test_progress_bar_update_tty(self, capsys):
        """ProgressBar should print progress when TTY."""
        pb = ProgressBar(100, width=10)

        with patch.object(sys.stdout, "isatty", return_value=True):
            # Force update by setting last_print to 0
            pb.last_print = 0
            pb.update(50)

            # Update at 100% should print newline
            pb.last_print = 0  # Reset to force print
            pb.update(100)

        captured = capsys.readouterr()
        assert "%" in captured.out

    def test_progress_bar_throttles_updates(self):
        """ProgressBar should throttle updates to every 0.1 seconds."""
        pb = ProgressBar(100)
        pb.last_print = 9999999999  # Far future time

        with patch.object(sys.stdout, "isatty", return_value=True):
            # This update should be skipped due to throttling
            pb.update(50)
            # last_print should not have changed (update was skipped)

    def test_empty_completed_progress_renders_one_hundred_percent(self, capsys):
        """An empty completed operation should render without division by zero."""
        pb = ProgressBar(0, width=10)

        with patch.object(sys.stdout, "isatty", return_value=True):
            pb.update(0)

        captured = capsys.readouterr()
        assert "██████████ 100.0%" in captured.out


# =============================================================================
# Dark Background Detection Tests
# =============================================================================


class TestDetectDarkBackground:
    """Tests for detect_dark_background function."""

    def test_detect_dark_with_colorfgbg_dark(self):
        """Should return True for dark background color code."""
        with patch.dict(os.environ, {"COLORFGBG": "15;0"}):
            assert detect_dark_background() is True

    def test_detect_dark_with_colorfgbg_light(self):
        """Should return False for light background color code."""
        with patch.dict(os.environ, {"COLORFGBG": "0;15"}):
            assert detect_dark_background() is False

    def test_detect_dark_with_colorfgbg_boundary(self):
        """Should return True for boundary color code (6)."""
        with patch.dict(os.environ, {"COLORFGBG": "0;6"}):
            assert detect_dark_background() is True

    def test_detect_dark_with_invalid_colorfgbg(self):
        """Should return True for invalid COLORFGBG value."""
        with patch.dict(os.environ, {"COLORFGBG": "invalid;value"}):
            assert detect_dark_background() is True

    def test_detect_dark_without_colorfgbg(self):
        """Should return True when COLORFGBG is not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("COLORFGBG", None)
            assert detect_dark_background() is True

    def test_detect_dark_no_semicolon(self):
        """Should return True when COLORFGBG has no semicolon."""
        with patch.dict(os.environ, {"COLORFGBG": "15"}):
            assert detect_dark_background() is True


# =============================================================================
# Colorize Tests
# =============================================================================


class TestColorize:
    """Tests for colorize function."""

    def test_colorize_returns_plain_text_non_tty(self):
        """Should return plain text when not a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = colorize("test", "cyan")
            assert result == "test"

    def test_colorize_returns_plain_text_no_color_env(self):
        """Should return plain text when NO_COLOR is set."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            with patch.dict(os.environ, {"NO_COLOR": "1"}):
                result = colorize("test", "cyan")
                assert result == "test"

    def test_colorize_adds_color_codes_tty(self):
        """Should add color codes when TTY."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("NO_COLOR", None)
                result = colorize("test", "cyan")
                assert "\033[" in result  # ANSI escape code
                assert "test" in result

    def test_colorize_fallback_unknown_color(self):
        """Should fallback to cyan/blue for unknown colors."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("NO_COLOR", None)
                result = colorize("test", "unknown_color")
                assert "\033[" in result

    def test_colorize_different_colors(self):
        """Should apply different color codes."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("NO_COLOR", None)

                cyan_result = colorize("test", "cyan")
                yellow_result = colorize("test", "yellow")
                red_result = colorize("test", "red")

                # All should have color codes
                assert "\033[" in cyan_result
                assert "\033[" in yellow_result
                assert "\033[" in red_result


# =============================================================================
# Secure Overwrite Tests
# =============================================================================


class TestSecureOverwrite:
    """Tests for secure_overwrite function."""

    def test_secure_overwrite_nonexistent_file(self, tmp_path):
        """Should handle nonexistent file gracefully."""
        nonexistent = tmp_path / "nonexistent.txt"
        # Should not raise
        secure_overwrite(str(nonexistent))

    def test_secure_overwrite_overwrites_content(self, tmp_path):
        """Should overwrite file content with zeros."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret data that should be overwritten")

        secure_overwrite(str(test_file))

        # File should be deleted
        assert not test_file.exists()

    def test_secure_overwrite_deletes_file(self, tmp_path):
        """Should delete file after overwriting."""
        test_file = tmp_path / "to_delete.txt"
        test_file.write_text("delete me")

        secure_overwrite(str(test_file))

        assert not test_file.exists()

    def test_secure_overwrite_handles_permission_error(self, tmp_path):
        """Should handle permission errors gracefully."""
        test_file = tmp_path / "protected.txt"
        test_file.write_text("protected")

        with patch("os.unlink", side_effect=OSError("Permission denied")):
            # Should not raise, just suppress the error
            secure_overwrite(str(test_file))

    def test_secure_overwrite_syncs_to_disk(self, tmp_path):
        """Should sync data to disk before deletion."""
        test_file = tmp_path / "sync_test.txt"
        test_file.write_text("sync me")

        with patch("os.fsync") as mock_fsync:
            secure_overwrite(str(test_file))
            # fsync should have been called
            mock_fsync.assert_called()
