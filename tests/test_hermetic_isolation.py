"""Guard tests proving the suite never writes to the real user's home.

These exist because the suite previously did exactly that: running the tests
reset the real `~/.secure-cipher/rate_limits.json` (a security control),
appended mock objects to the real `~/.secure-cipher/logs/audit.log`, and
accumulated thousands of stray lock files in `~/.secure_string_cipher/`.

Every path the package picks for itself resolves through `Path.home()`, so
`tests/conftest.py` redirects HOME at import time. These tests fail if that
redirection stops working, rather than letting the pollution resume silently.
"""

from pathlib import Path

import pytest

from secure_string_cipher.audit_log import AuditEvent, AuditLogger
from secure_string_cipher.config import (
    get_config_dir,
    get_default_backup_dir,
    get_default_vault_path,
)
from secure_string_cipher.rate_limiter import PersistentRateLimiter
from secure_string_cipher.v2.vault_lock import get_vault_lock_path

# Directories the package creates under a home directory. If any of these
# appear under the *real* home during a test run, isolation has broken.
_SSC_HOME_DIRS = (".secure-cipher", ".secure_string_cipher", ".ssc")


def _snapshot(path: Path) -> tuple[bool, int, int]:
    """Capture (exists, mtime_ns, size) so a later write is detectable."""
    try:
        stat = path.stat()
    except OSError:
        return (False, 0, 0)
    return (True, stat.st_mtime_ns, stat.st_size)


def test_home_is_redirected_away_from_the_real_home(
    fake_home: Path, real_home: Path
) -> None:
    assert Path.home() == fake_home
    assert Path.home() != real_home, (
        "HOME still resolves to the real user home; conftest redirection failed"
    )


def test_every_config_path_resolves_under_the_fake_home(fake_home: Path) -> None:
    for path in (
        get_config_dir(),
        get_default_vault_path(),
        get_default_backup_dir(),
        Path(PersistentRateLimiter().state_path),
    ):
        assert fake_home in path.parents or path == fake_home, (
            f"{path} is outside the hermetic home {fake_home}"
        )


def test_rate_limiter_persists_under_the_fake_home(fake_home: Path) -> None:
    """Regression: this previously rewrote the real user's rate-limit state."""
    limiter = PersistentRateLimiter()
    state_path = Path(limiter.state_path)
    assert fake_home in state_path.parents

    limiter.record_attempt("decrypt_file", "guard-test", success=False)
    assert state_path.exists(), "rate-limit state was not written where expected"


def test_audit_log_writes_under_the_fake_home(fake_home: Path) -> None:
    """Regression: this previously appended to the real user's audit log."""
    AuditLogger._instance = None  # singleton; test_audit_log.py does the same
    try:
        logger = AuditLogger()
        log_path = Path(logger.log_path)
        assert fake_home in log_path.parents, (
            f"audit log {log_path} is outside the hermetic home"
        )

        logger.log(AuditEvent.VAULT_UNLOCK, success=True)
        assert log_path.exists()
    finally:
        AuditLogger._instance = None


def test_vault_lock_directory_is_under_the_fake_home(fake_home: Path) -> None:
    """Regression: this previously left stray lock files in the real home."""
    lock_path = get_vault_lock_path("keychain:secure-string-cipher:guard-test")
    assert fake_home in lock_path.parents, (
        f"lock path {lock_path} is outside the hermetic home"
    )


@pytest.mark.security
def test_exercising_every_sink_leaves_the_real_home_untouched(
    real_home: Path,
) -> None:
    """End-to-end guard: the check that would have caught the original bug."""
    watched = [real_home / name for name in _SSC_HOME_DIRS]
    before = {path: _snapshot(path) for path in watched}

    # Exercise each sink that historically wrote to the real home.
    PersistentRateLimiter().record_attempt("decrypt_file", "guard", success=False)
    get_vault_lock_path("keychain:secure-string-cipher:guard")
    get_default_backup_dir().mkdir(parents=True, exist_ok=True)
    AuditLogger._instance = None
    try:
        AuditLogger().log(AuditEvent.VAULT_UNLOCK, success=False)
    finally:
        AuditLogger._instance = None

    after = {path: _snapshot(path) for path in watched}
    assert after == before, (
        "the test suite modified the real user home: "
        f"{[str(p) for p in watched if after[p] != before[p]]}"
    )
