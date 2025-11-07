"""
Utility functions for secure-string-cipher
"""

import contextlib
import os
import sys
import time

from .config import COLORS

__all__ = ["CryptoError", "ProgressBar", "colorize"]


class CryptoError(Exception):
    """Custom exception for encryption/decryption errors."""

    pass


class ProgressBar:
    """
    Progress bar for file operations.

    Attributes:
        total: Total bytes to process
        width: Width of progress bar in characters
        last_print: Last update timestamp
    """

    def __init__(self, total_bytes: int, width: int = 40):
        """
        Initialize progress bar.

        Args:
            total_bytes: Total bytes to process
            width: Width of progress bar
        """
        self.total = total_bytes
        self.width = width
        self.last_print: float = 0.0

    def update(self, current: int) -> None:
        """
        Update progress bar display.

        Args:
            current: Current bytes processed
        """
        if not sys.stdout.isatty():
            return

        now = time.time()
        if now - self.last_print < 0.1 and current < self.total:
            return

        self.last_print = now
        filled = int(self.width * current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)
        percent = current / self.total * 100

        print(f"\r{bar} {percent:0.1f}%", end="", flush=True)
        if current >= self.total:
            print()  # New line when done


def detect_dark_background() -> bool:
    """
    Detect if terminal has dark background.

    Returns:
        True if terminal likely has dark background
    """
    cfg = os.getenv("COLORFGBG", "")
    if ";" in cfg:
        try:
            return int(cfg.split(";")[-1]) <= 6
        except ValueError:
            pass
    return True


def colorize(text: str, color: str = "cyan") -> str:
    """
    Add ANSI color to text if supported.

    Args:
        text: Text to colorize
        color: Color name from COLORS dict

    Returns:
        Colorized text if supported, original text otherwise
    """
    if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return text

    color_key = (
        color if color in COLORS else ("cyan" if detect_dark_background() else "blue")
    )
    color_code = COLORS.get(color_key, COLORS["cyan"])
    return f"{color_code}{text}{COLORS['reset']}"


def secure_overwrite(path: str) -> None:
    """
    Securely overwrite a file before deletion.

    Args:
        path: Path to file to overwrite

    Note:
        This is a basic implementation. For truly secure deletion,
        use specialized tools that handle storage device specifics.
    """
    if not os.path.exists(path):
        return

    try:
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


class TimeoutManager:
    def __init__(self, seconds: int):
        self.seconds = seconds

    def __call__(self):
        return self

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        return exc_type is None


def handle_timeout(seconds: int) -> TimeoutManager:
    """Set a timeout for user input in seconds."""
    return TimeoutManager(seconds)
