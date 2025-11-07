"""
Shared test configuration and fixtures
"""

import contextlib
import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def test_env() -> Generator[None]:
    """Set up test environment variables."""
    old_env = {}

    # Store old values
    for key in ["NO_COLOR", "COLORFGBG"]:
        old_env[key] = os.environ.get(key)

    # Set test values
    os.environ["NO_COLOR"] = "1"  # Disable colors in tests

    yield

    # Restore old values
    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture
def temp_dir() -> Generator[Path]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_file() -> Generator[Path]:
    """Create a temporary file for tests."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        path = Path(tf.name)

    yield path

    with contextlib.suppress(OSError):
        path.unlink()


@pytest.fixture
def large_test_file() -> Generator[str]:
    """Create a large temporary test file."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # Write 1MB of random-like but reproducible data
        for i in range(1024):  # 1024 * 1024 = 1MB
            tf.write(bytes([i % 256] * 1024))
        path = tf.name

    yield path

    with contextlib.suppress(OSError):
        os.unlink(path)


@pytest.fixture
def test_data_file(temp_dir: Path) -> Path:
    """Create a test file with sample data."""
    file_path = temp_dir / "test_data.txt"
    file_path.write_text("Sample test data for testing\n" * 10)
    return file_path


@pytest.fixture
def secure_test_dir(temp_dir: Path) -> Path:
    """Create a directory with restricted permissions."""
    secure_dir = temp_dir / "secure"
    secure_dir.mkdir(mode=0o700)
    return secure_dir


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment state between tests."""
    # Store original environment
    original_env = os.environ.copy()

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_vault_path(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Mock vault path for testing."""
    vault_path = temp_dir / "test_vault.json"
    monkeypatch.setenv("CIPHER_VAULT_PATH", str(vault_path))
    return vault_path


# Configure pytest-timeout default
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom settings."""
    config.addinivalue_line("markers", "unit: Unit tests (fast, isolated)")
    config.addinivalue_line(
        "markers", "integration: Integration tests (slower, may use filesystem)"
    )
    config.addinivalue_line("markers", "slow: Slow tests (take more than 1 second)")
    config.addinivalue_line("markers", "security: Security-focused tests")
