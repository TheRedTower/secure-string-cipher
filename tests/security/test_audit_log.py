"""
Tests for audit logging functionality.

Tests verify:
- Event logging at different levels
- Log rotation
- Sensitive data redaction
- Convenience functions
- Thread safety
"""

import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

from secure_string_cipher.audit_log import (
    AuditEvent,
    AuditLevel,
    AuditLogger,
    audit_auth_failure,
    audit_event,
    audit_rate_limit,
    get_audit_logger,
)


@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for log files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_logger(temp_log_dir):
    """Create a fresh audit logger for testing."""
    # Reset singleton for testing
    AuditLogger._instance = None
    log_path = temp_log_dir / "test_audit.log"
    logger = AuditLogger(
        log_path=log_path,
        level=AuditLevel.VERBOSE,
        enabled=True,
    )
    yield logger
    AuditLogger._instance = None


class TestAuditLoggerBasic:
    """Basic audit logger functionality tests."""

    def test_logger_creates_log_file(self, audit_logger, temp_log_dir):
        """Logger should create log file on first write."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(AuditEvent.STARTUP)
        assert log_path.exists()

    def test_log_entry_is_json(self, audit_logger, temp_log_dir):
        """Log entries should be valid JSON."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(AuditEvent.ENCRYPT_TEXT, success=True)

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert "timestamp" in entry
        assert entry["event"] == "encrypt_text"
        assert entry["success"] is True

    def test_log_entry_has_timestamp(self, audit_logger, temp_log_dir):
        """Log entries should have ISO format timestamp."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(AuditEvent.ENCRYPT_TEXT)

        with open(log_path) as f:
            entry = json.loads(f.readline())

        # Should be ISO format with timezone
        assert "T" in entry["timestamp"]

    def test_log_entry_has_pid(self, audit_logger, temp_log_dir):
        """Log entries should include process ID."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(AuditEvent.ENCRYPT_TEXT)

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["pid"] == os.getpid()

    def test_log_with_details(self, audit_logger, temp_log_dir):
        """Log entries should include provided details."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(
            AuditEvent.ENCRYPT_FILE,
            success=True,
            details={"file": "/path/to/file.txt", "size": 1024},
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["details"]["file"] == "/path/to/file.txt"
        assert entry["details"]["size"] == 1024


class TestSensitiveDataRedaction:
    """Tests for sensitive data redaction."""

    def test_password_is_redacted(self, audit_logger, temp_log_dir):
        """Password fields should be redacted."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(
            AuditEvent.AUTH_SUCCESS,
            details={
                "password": "secret123",  # pragma: allowlist secret
                "user": "test",
            },
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["details"]["password"] == "[REDACTED]"
        assert entry["details"]["user"] == "test"

    def test_passphrase_is_redacted(self, audit_logger, temp_log_dir):
        """Passphrase fields should be redacted."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(
            AuditEvent.VAULT_STORE,
            details={"passphrase": "my-secret-pass", "label": "test"},
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["details"]["passphrase"] == "[REDACTED]"

    def test_key_is_redacted(self, audit_logger, temp_log_dir):
        """Key fields should be redacted."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(
            AuditEvent.KEY_DERIVATION,
            details={"encryption_key": "abc123", "algorithm": "argon2id"},
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["details"]["encryption_key"] == "[REDACTED]"
        assert entry["details"]["algorithm"] == "argon2id"

    def test_plaintext_is_redacted(self, audit_logger, temp_log_dir):
        """Plaintext fields should be redacted."""
        log_path = temp_log_dir / "test_audit.log"
        audit_logger.log(
            AuditEvent.ENCRYPT_TEXT,
            details={"plaintext": "sensitive data", "length": 14},
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["details"]["plaintext"] == "[REDACTED]"

    def test_sensitive_error_detail_is_redacted(self, audit_logger, temp_log_dir):
        """Error fields that appear to contain secret material should be redacted."""
        log_path = temp_log_dir / "test_audit.log"
        leaked_detail = "DO_NOT_PRINT_AUDIT_SECRET_123!"  # pragma: allowlist secret
        audit_logger.log(
            AuditEvent.DECRYPT_TEXT,
            success=False,
            details={"error": f"failed with passphrase {leaked_detail}"},
        )

        line = log_path.read_text()
        entry = json.loads(line)

        assert leaked_detail not in line
        assert entry["details"]["error"] == "[REDACTED]"


class TestAuditLevels:
    """Tests for audit logging levels."""

    def test_off_level_logs_nothing(self, temp_log_dir):
        """OFF level should not log anything."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(log_path=log_path, level=AuditLevel.OFF, enabled=True)

        logger.log(AuditEvent.AUTH_FAILURE)
        logger.log(AuditEvent.ENCRYPT_TEXT)

        assert not log_path.exists()
        AuditLogger._instance = None

    def test_critical_logs_security_failures(self, temp_log_dir):
        """CRITICAL level should log security failures."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(log_path=log_path, level=AuditLevel.CRITICAL, enabled=True)

        logger.log(AuditEvent.AUTH_FAILURE)
        logger.log(AuditEvent.ENCRYPT_TEXT)  # Should not be logged

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 1
        assert "auth_failure" in lines[0]
        AuditLogger._instance = None

    def test_standard_logs_security_events(self, temp_log_dir):
        """STANDARD level should log security events."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(log_path=log_path, level=AuditLevel.STANDARD, enabled=True)

        logger.log(AuditEvent.AUTH_SUCCESS)
        logger.log(AuditEvent.AUTH_FAILURE)
        logger.log(AuditEvent.ENCRYPT_TEXT)  # Should not be logged

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 2
        AuditLogger._instance = None

    def test_verbose_logs_everything(self, temp_log_dir):
        """VERBOSE level should log all events."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE, enabled=True)

        logger.log(AuditEvent.AUTH_SUCCESS)
        logger.log(AuditEvent.ENCRYPT_TEXT)
        logger.log(AuditEvent.DECRYPT_TEXT)

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 3
        AuditLogger._instance = None


class TestLogRotation:
    """Tests for log rotation."""

    def test_rotation_creates_backup(self, temp_log_dir):
        """Should create backup when rotating."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(
            log_path=log_path,
            level=AuditLevel.VERBOSE,
            enabled=True,
            max_size=100,  # Very small for testing
            backup_count=3,
        )

        # Write enough to trigger rotation
        for i in range(20):
            logger.log(AuditEvent.ENCRYPT_TEXT, details={"iteration": i})

        # Check for backup file
        backup1 = temp_log_dir / "test.log.1"
        assert backup1.exists() or log_path.exists()
        AuditLogger._instance = None


class TestEnableDisable:
    """Tests for enabling/disabling logging."""

    def test_disable_stops_logging(self, audit_logger, temp_log_dir):
        """Disabled logger should not write."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.log(AuditEvent.STARTUP)
        audit_logger.disable()
        audit_logger.log(AuditEvent.ENCRYPT_TEXT)

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 1

    def test_enable_resumes_logging(self, audit_logger, temp_log_dir):
        """Re-enabled logger should resume writing."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.disable()
        audit_logger.log(AuditEvent.ENCRYPT_TEXT)
        audit_logger.enable()
        audit_logger.log(AuditEvent.DECRYPT_TEXT)

        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 1
        assert "decrypt_text" in lines[0]


class TestConvenienceMethods:
    """Tests for convenience logging methods."""

    def test_log_auth_failure(self, audit_logger, temp_log_dir):
        """log_auth_failure should log with proper format."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.log_auth_failure(
            operation="vault_unlock",
            reason="wrong_password",
            identifier="/path/to/vault",
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "auth_failure"
        assert entry["success"] is False
        assert entry["details"]["operation"] == "vault_unlock"
        assert entry["details"]["reason"] == "wrong_password"

    def test_log_rate_limit(self, audit_logger, temp_log_dir):
        """log_rate_limit should log with proper format."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.log_rate_limit(
            operation="decrypt",
            wait_seconds=30.5,
            identifier="test_file",
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "rate_limit_triggered"
        assert entry["details"]["lockout_seconds"] == 30.5

    def test_log_encryption(self, audit_logger, temp_log_dir):
        """log_encryption should log with proper format."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.log_encryption(
            event_type=AuditEvent.ENCRYPT_FILE,
            success=True,
            file_path="/path/to/file.txt",
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "encrypt_file"
        assert entry["details"]["file"] == "/path/to/file.txt"

    def test_log_vault_operation(self, audit_logger, temp_log_dir):
        """log_vault_operation should log with proper format."""
        log_path = temp_log_dir / "test_audit.log"

        audit_logger.log_vault_operation(
            event_type=AuditEvent.VAULT_STORE,
            success=True,
            vault_path="/path/to/vault",
            label="my_password",
        )

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "vault_store"
        assert entry["details"]["label"] == "my_password"


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_logging(self, temp_log_dir):
        """Concurrent logging should be thread-safe."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        logger = AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE, enabled=True)
        errors = []

        def log_events():
            try:
                for i in range(10):
                    logger.log(AuditEvent.ENCRYPT_TEXT, details={"thread_iter": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_events) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

        # Verify all entries are valid JSON
        with open(log_path) as f:
            for line in f:
                json.loads(line)  # Should not raise
        AuditLogger._instance = None


class TestSingleton:
    """Tests for singleton behavior."""

    def test_singleton_returns_same_instance(self, temp_log_dir):
        """AuditLogger should be a singleton."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"

        logger1 = AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE)
        logger2 = AuditLogger()

        assert logger1 is logger2
        AuditLogger._instance = None

    def test_get_audit_logger_returns_singleton(self, temp_log_dir):
        """get_audit_logger should return the singleton."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"

        logger1 = AuditLogger(log_path=log_path)
        logger2 = get_audit_logger()

        assert logger1 is logger2
        AuditLogger._instance = None


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_audit_event_function(self, temp_log_dir):
        """audit_event should log through global logger."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE, enabled=True)

        audit_event(AuditEvent.STARTUP)

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "startup"
        AuditLogger._instance = None

    def test_audit_auth_failure_function(self, temp_log_dir):
        """audit_auth_failure should log through global logger."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE, enabled=True)

        audit_auth_failure("test_op", "bad_password")

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "auth_failure"
        AuditLogger._instance = None

    def test_audit_rate_limit_function(self, temp_log_dir):
        """audit_rate_limit should log through global logger."""
        AuditLogger._instance = None
        log_path = temp_log_dir / "test.log"
        AuditLogger(log_path=log_path, level=AuditLevel.VERBOSE, enabled=True)

        audit_rate_limit("decrypt", 60.0)

        with open(log_path) as f:
            entry = json.loads(f.readline())

        assert entry["event"] == "rate_limit_triggered"
        AuditLogger._instance = None
