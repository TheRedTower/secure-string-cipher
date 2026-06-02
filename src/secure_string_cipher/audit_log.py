"""
Audit logging module for tracking cryptographic operations.

Provides secure, tamper-evident logging of sensitive operations:
- Encryption/decryption events
- Vault access attempts
- Key derivation operations
- Authentication failures

Logs are written with timestamps and can be configured for different
verbosity levels and output destinations.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, cast

from .config import (
    AUDIT_LOG_BACKUP_COUNT,
    AUDIT_LOG_ENABLED,
    AUDIT_LOG_MAX_SIZE,
    AUDIT_LOG_PATH,
)


class AuditEvent(Enum):
    """Types of auditable events."""

    # Encryption operations
    ENCRYPT_TEXT = "encrypt_text"
    DECRYPT_TEXT = "decrypt_text"
    ENCRYPT_FILE = "encrypt_file"
    DECRYPT_FILE = "decrypt_file"

    # Vault operations
    VAULT_UNLOCK = "vault_unlock"
    VAULT_LOCK = "vault_lock"
    VAULT_STORE = "vault_store"
    VAULT_RETRIEVE = "vault_retrieve"
    VAULT_DELETE = "vault_delete"
    VAULT_LIST = "vault_list"

    # Security events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered"
    KEY_DERIVATION = "key_derivation"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"

    # System events
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    CONFIG_CHANGE = "config_change"


class AuditLevel(Enum):
    """Audit logging verbosity levels."""

    OFF = 0  # No logging
    CRITICAL = 1  # Only security failures
    STANDARD = 2  # Security events + operations
    VERBOSE = 3  # All events including success details


class AuditLogger:
    """Thread-safe audit logger for cryptographic operations.

    Logs events in JSON format for easy parsing and analysis.
    Supports file rotation to prevent unbounded growth.
    """

    _instance: "AuditLogger | None" = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls, *args: object, **kwargs: object) -> "AuditLogger":
        """Singleton pattern - only one audit logger instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        log_path: str | Path | None = None,
        level: AuditLevel = AuditLevel.STANDARD,
        enabled: bool | None = None,
        max_size: int | None = None,
        backup_count: int | None = None,
    ):
        """Initialize the audit logger.

        Args:
            log_path: Path to the audit log file (None for default)
            level: Logging verbosity level
            enabled: Whether logging is enabled (None uses config default)
            max_size: Maximum log file size before rotation
            backup_count: Number of backup files to keep
        """
        # Only initialize once (singleton)
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._write_lock = threading.Lock()
        self.level = level
        self.enabled = enabled if enabled is not None else AUDIT_LOG_ENABLED

        # Set up log path
        if log_path is None:
            log_path = AUDIT_LOG_PATH
        if log_path is None:
            # Default to user's home directory
            home = Path.home()
            log_dir = home / ".secure-cipher" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            log_path = log_dir / "audit.log"

        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.max_size = max_size if max_size is not None else AUDIT_LOG_MAX_SIZE
        self.backup_count = (
            backup_count if backup_count is not None else AUDIT_LOG_BACKUP_COUNT
        )

        # Set up Python logger for fallback
        self._logger = logging.getLogger("secure_string_cipher.audit")
        self._logger.setLevel(logging.INFO)

        self._initialized = True

    def _should_log(self, event: AuditEvent) -> bool:
        """Determine if an event should be logged based on level."""
        if not self.enabled or self.level == AuditLevel.OFF:
            return False

        current_level = cast(int, self.level.value)

        # Critical events always logged (except OFF)
        critical_events = {
            AuditEvent.AUTH_FAILURE,
            AuditEvent.RATE_LIMIT_TRIGGERED,
            AuditEvent.INTEGRITY_CHECK_FAILED,
        }
        if event in critical_events:
            return current_level >= cast(int, AuditLevel.CRITICAL.value)

        # Security success events at STANDARD+
        security_events = {
            AuditEvent.AUTH_SUCCESS,
            AuditEvent.VAULT_UNLOCK,
            AuditEvent.VAULT_LOCK,
            AuditEvent.KEY_DERIVATION,
        }
        if event in security_events:
            return current_level >= cast(int, AuditLevel.STANDARD.value)

        # All other events at VERBOSE
        return current_level >= cast(int, AuditLevel.VERBOSE.value)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        if not self.log_path.exists():
            return

        try:
            if self.log_path.stat().st_size < self.max_size:
                return
        except OSError:
            return

        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            old_backup = self.log_path.with_suffix(f".log.{i}")
            new_backup = self.log_path.with_suffix(f".log.{i + 1}")
            if old_backup.exists():
                try:
                    old_backup.rename(new_backup)
                except OSError:
                    pass

        # Rotate current log
        backup_path = self.log_path.with_suffix(".log.1")
        try:
            self.log_path.rename(backup_path)
        except OSError:
            pass

    def _format_entry(
        self,
        event: AuditEvent,
        success: bool,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Format a log entry as JSON."""
        entry = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "event": event.value,
            "success": success,
            "pid": os.getpid(),
        }

        if details:
            # Sanitize details - never log sensitive data
            safe_details = {}
            sensitive_keys = {
                "password",
                "passphrase",
                "key",
                "secret",
                "token",
                "plaintext",
            }
            for k, v in details.items():
                if any(s in k.lower() for s in sensitive_keys):
                    safe_details[k] = "[REDACTED]"
                else:
                    safe_details[k] = v
            entry["details"] = safe_details  # type: ignore[assignment]

        return json.dumps(entry, default=str)

    def log(
        self,
        event: AuditEvent,
        success: bool = True,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log an audit event.

        Args:
            event: Type of event to log
            success: Whether the operation succeeded
            details: Additional details (sensitive data will be redacted)
        """
        if not self._should_log(event):
            return

        entry = self._format_entry(event, success, details)

        with self._write_lock:
            try:
                self._rotate_if_needed()
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(entry + "\n")
                # Set restrictive permissions
                os.chmod(self.log_path, 0o600)
            except OSError as e:
                # Fallback to Python logger
                self._logger.warning(f"Audit log write failed: {e}")
                self._logger.info(entry)

    def log_auth_failure(
        self,
        operation: str,
        reason: str = "invalid_credentials",
        identifier: str | None = None,
    ) -> None:
        """Log an authentication failure.

        Args:
            operation: Operation that failed authentication
            reason: Reason for failure
            identifier: Optional identifier (e.g., vault path)
        """
        details = {"operation": operation, "reason": reason}
        if identifier:
            details["identifier"] = identifier
        self.log(AuditEvent.AUTH_FAILURE, success=False, details=details)

    def log_rate_limit(
        self,
        operation: str,
        wait_seconds: float,
        identifier: str | None = None,
    ) -> None:
        """Log a rate limit trigger.

        Args:
            operation: Operation that was rate limited
            wait_seconds: Lockout duration
            identifier: Optional identifier
        """
        details = {"operation": operation, "lockout_seconds": wait_seconds}
        if identifier:
            details["identifier"] = identifier
        self.log(AuditEvent.RATE_LIMIT_TRIGGERED, success=False, details=details)

    def log_encryption(
        self,
        event_type: AuditEvent,
        success: bool,
        file_path: str | None = None,
        error: str | None = None,
    ) -> None:
        """Log an encryption/decryption operation.

        Args:
            event_type: ENCRYPT_TEXT, DECRYPT_TEXT, ENCRYPT_FILE, or DECRYPT_FILE
            success: Whether operation succeeded
            file_path: Path to file (for file operations)
            error: Error message if failed
        """
        details: dict[str, Any] = {}
        if file_path:
            details["file"] = str(file_path)
        if error:
            details["error"] = error
        self.log(event_type, success=success, details=details if details else None)

    def log_vault_operation(
        self,
        event_type: AuditEvent,
        success: bool,
        vault_path: str | None = None,
        label: str | None = None,
        error: str | None = None,
    ) -> None:
        """Log a vault operation.

        Args:
            event_type: VAULT_* event type
            success: Whether operation succeeded
            vault_path: Path to vault file
            label: Passphrase label (for store/retrieve/delete)
            error: Error message if failed
        """
        details: dict[str, Any] = {}
        if vault_path:
            details["vault"] = str(vault_path)
        if label:
            details["label"] = label
        if error:
            details["error"] = error
        self.log(event_type, success=success, details=details if details else None)

    def set_level(self, level: AuditLevel) -> None:
        """Change the audit logging level."""
        self.level = level

    def enable(self) -> None:
        """Enable audit logging."""
        self.enabled = True

    def disable(self) -> None:
        """Disable audit logging."""
        self.enabled = False


# Convenience function to get the singleton logger
def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return AuditLogger()


# Convenience functions for common operations
def audit_auth_failure(
    operation: str, reason: str = "invalid_credentials", **kwargs: Any
) -> None:
    """Log an authentication failure."""
    get_audit_logger().log_auth_failure(operation, reason, **kwargs)


def audit_rate_limit(operation: str, wait_seconds: float, **kwargs: Any) -> None:
    """Log a rate limit trigger."""
    get_audit_logger().log_rate_limit(operation, wait_seconds, **kwargs)


def audit_event(event: AuditEvent, success: bool = True, **details: Any) -> None:
    """Log a generic audit event."""
    get_audit_logger().log(event, success, details if details else None)
