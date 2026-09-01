"""
Configuration settings for secure-string-cipher.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# =============================================================================
# Key Derivation Function (KDF) Settings
# =============================================================================

# Argon2id settings (memory-hard, GPU/ASIC resistant)
# These follow OWASP recommendations for password hashing
ARGON2_TIME_COST = 3  # Number of iterations
ARGON2_MEMORY_COST = 65536  # Memory in KiB (64 MB)
ARGON2_PARALLELISM = 4  # Degree of parallelism
ARGON2_HASH_LENGTH = 32  # Output key length (256 bits for AES-256)

# =============================================================================
# Encryption Parameters
# =============================================================================

CHUNK_SIZE = 256 * 1024
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_COMMITMENT_SIZE = 32  # HMAC-SHA256 output size

# Key commitment constant - used to bind ciphertext to a specific key
# This prevents "invisible salamanders" attacks where a ciphertext
# could decrypt to different plaintexts under different keys
KEY_COMMITMENT_CONTEXT = b"secure-string-cipher-v1-key-commitment"

# File metadata format
METADATA_VERSION = 5  # Version 5: Argon2id + key commitment + authenticated metadata
METADATA_MAGIC = b"SSCV2"  # Magic bytes to identify format
MAX_METADATA_LENGTH = 65535  # Maximum encoded by the two-byte metadata length
FILENAME_MAX_LENGTH = 255  # Maximum stored filename length

# Maximum plaintext payload for file/stdin crypto. Active/candidate vault data
# and legacy key files separately use the same value as their raw-byte ingestion
# cap; SSC framing may make an encrypted file larger than this value.
MAX_FILE_SIZE = 100 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12
PASSWORD_PATTERNS = {
    "uppercase": lambda s: any(c.isupper() for c in s),
    "lowercase": lambda s: any(c.islower() for c in s),
    "digits": lambda s: any(c.isdigit() for c in s),
    "symbols": lambda s: any(not c.isalnum() for c in s),
}
COMMON_PASSWORDS = {
    "password",
    "123456",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
}

COLORS = {
    "reset": "\033[0m",
    "cyan": "\033[96m",
    "blue": "\033[34m",
    "red": "\033[91m",
    "green": "\033[92m",
}

DEFAULT_MODE = 1
CLIPBOARD_ENABLED = True
CLI_TIMEOUT = 300

# =============================================================================
# Rate Limiting Settings
# =============================================================================

# Maximum attempts before lockout
RATE_LIMIT_MAX_ATTEMPTS = 5

# Time window for counting attempts (seconds)
RATE_LIMIT_WINDOW_SECONDS = 60.0

# Base lockout duration after exceeding max attempts (seconds)
RATE_LIMIT_LOCKOUT_SECONDS = 30.0

# Multiplier for exponential backoff on repeated lockouts
# e.g., 2.0 means: 30s -> 60s -> 120s -> 240s...
RATE_LIMIT_BACKOFF_MULTIPLIER = 2.0

# =============================================================================
# Audit Logging Settings
# =============================================================================

# Enable/disable audit logging (can be overridden by environment variable)
AUDIT_LOG_ENABLED = True

# Path to audit log file (None = default ~/.secure-cipher/logs/audit.log)
AUDIT_LOG_PATH = None

# Maximum audit log file size before rotation (bytes)
AUDIT_LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB

# Number of backup log files to keep
AUDIT_LOG_BACKUP_COUNT = 5

# =============================================================================
# Vault Settings
# =============================================================================

VAULT_BACKEND_FILE = "file"
VAULT_BACKEND_KEYCHAIN = "keychain"
VAULT_BACKENDS = {VAULT_BACKEND_FILE, VAULT_BACKEND_KEYCHAIN}

ENV_VAULT_PATH = "CIPHER_VAULT_PATH"
ENV_BACKUP_DIR = "CIPHER_BACKUP_DIR"
ENV_VAULT_BACKEND = "CIPHER_VAULT_BACKEND"


@dataclass
class VaultSettings:
    """Runtime settings for vault storage."""

    vault_backend: str = VAULT_BACKEND_FILE
    vault_path: str | None = None
    backup_dir: str | None = None


def get_config_dir() -> Path:
    """Return the secure-string-cipher configuration directory."""
    return Path.home() / ".secure-cipher"


def get_config_path() -> Path:
    """Return the persisted vault settings path."""
    return get_config_dir() / "config.json"


def get_default_vault_path() -> Path:
    """Return the default file-backed vault path."""
    return get_config_dir() / "passphrase_vault.enc"


def get_default_backup_dir(vault_path: str | Path | None = None) -> Path:
    """Return the default vault backup directory."""
    if vault_path is None:
        return get_config_dir() / "backups"
    return Path(vault_path).parent / "backups"


def _validated_backend(value: object) -> str:
    """Validate and normalize a vault backend name."""
    backend = str(value).strip().lower()
    if backend not in VAULT_BACKENDS:
        raise ValueError(
            f"Unknown vault backend '{value}'. Use '{VAULT_BACKEND_FILE}' "
            f"or '{VAULT_BACKEND_KEYCHAIN}'."
        )
    return backend


def _default_vault_backend() -> str:
    """Return the safest available default vault backend."""
    with suppress(Exception):
        from .keychain_backend import is_keychain_available

        if is_keychain_available():
            return VAULT_BACKEND_KEYCHAIN
    return VAULT_BACKEND_FILE


def _settings_from_mapping(data: dict[str, Any]) -> VaultSettings:
    """Build vault settings from persisted JSON data."""
    settings = VaultSettings(vault_backend=_default_vault_backend())
    if "vault_backend" in data and data["vault_backend"] is not None:
        settings.vault_backend = _validated_backend(data["vault_backend"])
    if "vault_path" in data and data["vault_path"]:
        settings.vault_path = str(data["vault_path"])
    if "backup_dir" in data and data["backup_dir"]:
        settings.backup_dir = str(data["backup_dir"])
    return settings


def load_vault_settings(*, apply_env: bool = True) -> VaultSettings:
    """Load vault settings from defaults, config file, and environment.

    Environment variables override persisted settings so Docker and scripts can
    control vault placement without mutating the user's config file.
    """
    settings = VaultSettings(
        vault_backend=_default_vault_backend(),
        vault_path=str(get_default_vault_path()),
        backup_dir=str(get_default_backup_dir()),
    )

    config_path = get_config_path()
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                loaded = _settings_from_mapping(data)
                settings.vault_backend = loaded.vault_backend
                if loaded.vault_path is not None:
                    settings.vault_path = loaded.vault_path
                if loaded.backup_dir is not None:
                    settings.backup_dir = loaded.backup_dir
        except (OSError, json.JSONDecodeError, ValueError):
            # Invalid config should not make the CLI unusable; callers can
            # repair it by saving fresh settings.
            pass

    if apply_env:
        env_backend = os.environ.get(ENV_VAULT_BACKEND)
        if env_backend:
            settings.vault_backend = _validated_backend(env_backend)

        env_vault_path = os.environ.get(ENV_VAULT_PATH)
        if env_vault_path:
            settings.vault_path = env_vault_path

        env_backup_dir = os.environ.get(ENV_BACKUP_DIR)
        if env_backup_dir:
            settings.backup_dir = env_backup_dir

    if settings.backup_dir is None:
        settings.backup_dir = str(get_default_backup_dir(settings.vault_path))

    return settings


def save_vault_settings(settings: VaultSettings) -> None:
    """Persist vault settings to ``~/.secure-cipher/config.json``."""
    settings.vault_backend = _validated_backend(settings.vault_backend)
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    config_path = get_config_path()
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{config_path.name}.",
        suffix=".tmp",
        dir=config_dir,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(asdict(settings), f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, config_path)
    except Exception:
        with suppress(OSError):
            os.unlink(temp_path)
        raise


def set_vault_backend(backend: str) -> VaultSettings:
    """Persist and return the active vault backend setting."""
    settings = load_vault_settings(apply_env=False)
    settings.vault_backend = _validated_backend(backend)
    save_vault_settings(settings)
    return load_vault_settings()
