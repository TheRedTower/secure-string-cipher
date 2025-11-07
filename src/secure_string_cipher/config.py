"""
Configuration settings for secure-string-cipher
"""

CHUNK_SIZE = 64 * 1024
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KDF_ITERATIONS = 390_000

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
