from importlib.metadata import version

import secure_string_cipher


def test_version_matches_installed_metadata() -> None:
    assert secure_string_cipher.__version__ == version("secure-string-cipher")
