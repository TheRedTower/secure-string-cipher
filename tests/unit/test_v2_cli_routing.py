import argparse
from unittest.mock import mock_open, patch

from secure_string_cipher.cli_args import (
    cmd_decrypt,
    cmd_encrypt,
)


@patch("secure_string_cipher.cli_args.encrypt_text")
@patch("secure_string_cipher.cli_args._get_password_from_vault")
@patch("secure_string_cipher.cli_args._prompt_password")
@patch("secure_string_cipher.cli_args.encrypt_v2_text")
def test_encrypt_routing_v1_vs_v2(
    mock_v2_encrypt, mock_prompt_pwd, mock_get_vault, mock_v1_encrypt
):
    args_v2 = argparse.Namespace(
        text="secret",
        file=None,
        positional_path=None,
        vault=None,
        key_file=None,
        force=False,
        with_sources=["password"],
        require="any",
        output=None,
    )
    cmd_encrypt(args_v2)
    mock_v2_encrypt.assert_called_once()
    mock_v1_encrypt.assert_not_called()

    mock_v2_encrypt.reset_mock()
    mock_prompt_pwd.return_value = "password"
    args_v1 = argparse.Namespace(
        text="secret",
        file=None,
        positional_path=None,
        vault=None,
        key_file=None,
        force=False,
        with_sources=None,
        require="any",
        output=None,
    )
    cmd_encrypt(args_v1)
    mock_v1_encrypt.assert_called_once()
    mock_v2_encrypt.assert_not_called()


@patch("secure_string_cipher.cli_args._cmd_decrypt_v2")
@patch("secure_string_cipher.cli_args._ensure_no_symlink")
@patch("secure_string_cipher.cli_args.Path")
@patch("builtins.open", new_callable=mock_open, read_data=b"SSC2\x00")
def test_decrypt_routing_file_v2(mock_file, mock_path, mock_no_symlink, mock_v2):
    mock_path.return_value.exists.return_value = True

    args = argparse.Namespace(
        text=None,
        file="doc.pdf.enc",
        output=None,
        restore_filename=True,
        vault=None,
        key_file=None,
        force=False,
    )
    cmd_decrypt(args)
    mock_v2.assert_called_once()
    # Third positional arg is now a content-derived rate-limit identifier
    # (see _file_rate_limit_identity), not asserted here — routing only.
    assert mock_v2.call_args.args[:2] == (args, False)


@patch("secure_string_cipher.cli_args._get_v1_password")
@patch("secure_string_cipher.cli_args.decrypt_file")
@patch("secure_string_cipher.cli_args._cmd_decrypt_v2")
@patch("secure_string_cipher.cli_args._ensure_no_symlink")
@patch("secure_string_cipher.cli_args.Path")
@patch("builtins.open", new_callable=mock_open, read_data=b"SSCV2")
def test_decrypt_routing_file_v1(
    mock_file, mock_path, mock_no_symlink, mock_v2, mock_decrypt_file, mock_get_pwd
):
    mock_path.return_value.exists.return_value = True
    mock_get_pwd.return_value = "dummy-password"
    mock_decrypt_file.return_value = ("doc.pdf", None)

    args = argparse.Namespace(
        text=None,
        file="doc.pdf.enc",
        output=None,
        restore_filename=True,
        vault=None,
        key_file=None,
        force=False,
    )
    try:
        cmd_decrypt(args)
    except Exception:
        pass
    mock_v2.assert_not_called()


@patch("secure_string_cipher.cli_args._cmd_decrypt_v2")
def test_decrypt_routing_text_v2(mock_v2):
    args = argparse.Namespace(
        text="-----BEGIN SSC MESSAGE-----\n...",
        file=None,
        output=None,
        restore_filename=True,
        vault=None,
        key_file=None,
        force=False,
    )
    cmd_decrypt(args)
    mock_v2.assert_called_once_with(args, True, "")


@patch("secure_string_cipher.cli_args._cmd_decrypt_v2")
@patch("secure_string_cipher.cli_args.decrypt_text")
@patch("secure_string_cipher.cli_args._get_v1_password")
def test_decrypt_routing_text_v1(mock_get_pwd, mock_decrypt_text, mock_v2):
    args = argparse.Namespace(
        text="U1NDVjI=",
        file=None,
        output=None,
        restore_filename=True,
        vault=None,
        key_file=None,
        force=False,
    )
    try:
        cmd_decrypt(args)
    except Exception:
        pass
    mock_v2.assert_not_called()
    mock_decrypt_text.assert_called_once()
