"""
Shared test configuration and fixtures
"""

import contextlib
import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Hermetic home directory
#
# Every on-disk location this package chooses for itself resolves through
# Path.home(): the config dir (config.py::get_config_dir -> ~/.secure-cipher,
# which also carries the vault, its backups and rate_limits.json), the default
# audit log (audit_log.py, since config.AUDIT_LOG_PATH is None), the vault lock
# directory (v2/vault_lock.py -> ~/.secure_string_cipher) and managed-key
# lookup (cli_args.py -> ~/.ssc/keys). Redirecting HOME therefore redirects
# all of them at once.
#
# This runs at conftest *import* time, not in a fixture, because
# cli_args.py:74 instantiates a PersistentRateLimiter at module import and
# that binds its state path immediately. A fixture would run too late: any
# test module importing cli_args would already have bound the real path. Under
# pytest-xdist each worker imports this file in its own process, so each worker
# also gets its own private home and they cannot contend for the same log.
# ---------------------------------------------------------------------------
# The invoking user's real home is captured through the environment, not by
# calling Path.home() here. With -n auto the xdist controller imports this
# file and rewrites HOME *before* spawning workers, so a worker evaluating
# Path.home() at this point would see the controller's fake home and the
# guard tests below would then be monitoring a temporary directory rather
# than the home they exist to protect. setdefault means the controller
# records the true value once and every worker inherits it.
REAL_HOME = Path(os.environ.setdefault("SSC_TEST_REAL_HOME", str(Path.home())))

_FAKE_HOME = Path(tempfile.mkdtemp(prefix="ssc-test-home-"))
os.environ["HOME"] = str(_FAKE_HOME)
os.environ["USERPROFILE"] = str(_FAKE_HOME)  # Path.home() uses this on Windows


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
def reset_environment() -> Generator[None]:
    """Reset environment state between tests."""
    # Store original environment
    original_env = os.environ.copy()
    os.environ["CIPHER_VAULT_BACKEND"] = "file"

    # Re-assert the hermetic home (see module header). The module-level
    # assignment covers import time; this covers a test that reassigns HOME
    # directly instead of via monkeypatch, so the next test still starts
    # pointed away from the real home.
    os.environ["HOME"] = str(_FAKE_HOME)
    os.environ["USERPROFILE"] = str(_FAKE_HOME)

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture(autouse=True)
def reset_cli_output_flags() -> Generator[None]:
    """Restore cli_args' module-level flags after each test.

    `_quiet_mode` and `_no_color` gate `_print_info`/`_print_warning`, and 39
    tests in tests/unit/test_cli_args.py set them to True without restoring.
    Every later test in the same xdist worker then saw silenced output — a
    latent order dependency that surfaced as `CaptureResult(out='', err='')`
    in the `ssc key` end-to-end tests on whichever Python version happened to
    distribute those files together.

    The credential sources matter more: a leaked `_password_source` would
    make a later test appear to succeed without prompting, hiding exactly the
    behaviour it meant to exercise.
    """
    from secure_string_cipher import cli_args

    names = (
        "_quiet_mode",
        "_no_color",
        "_debug_mode",
        "_password_source",
        "_master_password_source",
        "_new_master_password_source",
    )
    saved = {name: getattr(cli_args, name) for name in names if hasattr(cli_args, name)}

    yield

    for name, value in saved.items():
        setattr(cli_args, name, value)


@pytest.fixture
def fake_home() -> Path:
    """The session's hermetic home directory (what Path.home() resolves to)."""
    return _FAKE_HOME


@pytest.fixture
def real_home() -> Path:
    """The invoking user's actual home, captured before redirection.

    Only for the isolation guard tests, which assert it stays untouched.
    """
    return REAL_HOME


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


def pytest_sessionfinish(
    session: pytest.Session, exitstatus: int
) -> None:  # pragma: no cover - teardown
    """Remove this worker's hermetic home directory."""
    shutil.rmtree(_FAKE_HOME, ignore_errors=True)
