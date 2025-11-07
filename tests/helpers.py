"""
Test helper utilities and shared test functions.
"""

import os
import string
from pathlib import Path
from typing import Any


def create_test_files(
    directory: Path, count: int = 5, prefix: str = "test"
) -> list[Path]:
    """
    Create multiple test files in a directory.

    Args:
        directory: Directory to create files in
        count: Number of files to create
        prefix: Prefix for filenames

    Returns:
        List of created file paths
    """
    files = []
    for i in range(count):
        file_path = directory / f"{prefix}_{i}.txt"
        file_path.write_text(f"Test content {i}\n")
        files.append(file_path)
    return files


def create_nested_structure(base_dir: Path, depth: int = 3) -> Path:
    """
    Create a nested directory structure for testing.

    Args:
        base_dir: Base directory to start from
        depth: How many levels deep to create

    Returns:
        Path to the deepest directory
    """
    current = base_dir
    for i in range(depth):
        current = current / f"level_{i}"
        current.mkdir()
    return current


def assert_file_secure(file_path: Path, expected_mode: int = 0o600) -> None:
    """
    Assert that a file has secure permissions.

    Args:
        file_path: Path to file to check
        expected_mode: Expected permission mode
    """
    stat_info = file_path.stat()
    actual_mode = stat_info.st_mode & 0o777
    assert actual_mode == expected_mode, (
        f"File {file_path} has mode {oct(actual_mode)}, expected {oct(expected_mode)}"
    )


def assert_directory_secure(dir_path: Path, expected_mode: int = 0o700) -> None:
    """
    Assert that a directory has secure permissions.

    Args:
        dir_path: Path to directory to check
        expected_mode: Expected permission mode
    """
    stat_info = dir_path.stat()
    actual_mode = stat_info.st_mode & 0o777
    assert actual_mode == expected_mode, (
        f"Directory {dir_path} has mode {oct(actual_mode)}, "
        f"expected {oct(expected_mode)}"
    )


def generate_test_string(length: int = 100, chars: str = string.printable) -> str:
    """
    Generate a test string with predictable content.

    Args:
        length: Length of string to generate
        chars: Characters to use

    Returns:
        Generated test string
    """
    return "".join(chars[i % len(chars)] for i in range(length))


def is_running_in_ci() -> bool:
    """Check if tests are running in CI environment."""
    return any(
        os.environ.get(var) for var in ["CI", "GITHUB_ACTIONS", "TRAVIS", "CIRCLECI"]
    )


def skip_if_root() -> bool:
    """Check if current user is root (should skip permission tests)."""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def skip_if_no_permission_support() -> bool:
    """Check if filesystem supports permission restrictions."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = Path(tmpdir) / "test"
        test_dir.mkdir(mode=0o000)

        # Try to write - if it succeeds, permissions aren't respected
        try:
            (test_dir / "test.txt").write_text("test")
            test_dir.chmod(0o755)
            return True  # Should skip - permissions not enforced
        except PermissionError:
            test_dir.chmod(0o755)
            return False  # Don't skip - permissions work


def compare_file_contents(file1: Path, file2: Path) -> bool:
    """
    Compare contents of two files.

    Args:
        file1: First file path
        file2: Second file path

    Returns:
        True if contents match, False otherwise
    """
    return file1.read_bytes() == file2.read_bytes()


def get_file_size(file_path: Path) -> int:
    """Get size of file in bytes."""
    return file_path.stat().st_size


class TestTimer:
    """Context manager for timing test operations."""

    def __init__(self) -> None:
        self.start_time: float = 0
        self.end_time: float = 0
        self.elapsed: float = 0

    def __enter__(self) -> TestTimer:
        import time

        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        import time

        self.end_time = time.perf_counter()
        self.elapsed = self.end_time - self.start_time
