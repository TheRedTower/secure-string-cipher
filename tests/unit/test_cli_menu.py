"""
Security and functionality tests for CLI menu display and input handling.
Tests for potential exploits, injection attacks, and edge cases.
"""

import io

import pytest
from wcwidth import wcswidth

import secure_string_cipher.cli as cli
from secure_string_cipher.cli import (
    _get_mode,
    _handle_generate_passphrase,
    _handle_generate_passphrase_inline,
    _offer_vault_storage,
)


class TestMenuDisplay:
    """Test menu rendering and display."""

    def test_menu_renders_without_error(self):
        """Menu should render successfully."""
        in_stream = io.StringIO("0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "⚡ AVAILABLE OPERATIONS ⚡" in output
        assert "TEXT & FILE ENCRYPTION" in output
        assert "PASSPHRASE VAULT" in output

    def test_menu_contains_all_options(self):
        """Menu should display all 10 options (0-9)."""
        in_stream = io.StringIO("0\n")
        out_stream = io.StringIO()

        _get_mode(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "[1] Encrypt Text" in output
        assert "[2] Decrypt Text" in output
        assert "[3] Encrypt File" in output
        assert "[4] Decrypt File" in output
        assert "[5] Generate Passphrase" in output
        assert "[6] Store in Vault" in output
        assert "[7] Retrieve from Vault" in output
        assert "[8] List Vault Entries" in output
        assert "[9] Manage Vault" in output
        assert "[0] Exit" in output

    def test_menu_box_drawing_characters(self):
        """Menu should use proper Unicode box-drawing characters."""
        in_stream = io.StringIO("0\n")
        out_stream = io.StringIO()

        _get_mode(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "┏" in output  # Top-left corner
        assert "┓" in output  # Top-right corner
        assert "┗" in output  # Bottom-left corner
        assert "┛" in output  # Bottom-right corner
        assert "┃" in output  # Vertical line
        assert "━" in output  # Horizontal line
        assert "┣" in output  # Left separator
        assert "┫" in output  # Right separator

    def test_menu_right_border_alignment(self):
        """All menu border lines should render to the same terminal width."""
        in_stream = io.StringIO("0\n")
        out_stream = io.StringIO()

        _get_mode(in_stream, out_stream)

        output = out_stream.getvalue()
        border_lines = [
            line
            for line in output.splitlines()
            if line.startswith(("┏", "┣", "┗", "┃"))
        ]
        assert {wcswidth(line) for line in border_lines} == {70}
        assert "SECURITY TOOLS" in output
        assert "🛡" not in output

    def test_menu_emojis_display(self):
        """Menu should display emojis correctly."""
        in_stream = io.StringIO("0\n")
        out_stream = io.StringIO()

        _get_mode(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "📝" in output  # Text emoji
        assert "🔑" in output  # Key emoji
        assert "⚡" in output  # Lightning emoji


class TestValidInputs:
    """Test all valid input options (0-9)."""

    @pytest.mark.parametrize(
        "choice", ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    )
    def test_valid_single_digit_choices(self, choice):
        """All single-digit choices 0-9 should be accepted."""
        in_stream = io.StringIO(f"{choice}\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == int(choice)

    def test_choice_with_whitespace_rejected(self):
        """Input with leading/trailing whitespace should be rejected."""
        in_stream = io.StringIO("  5  \n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        # Whitespace is not stripped, so this is invalid and hits EOF
        assert result is None


class TestInvalidInputs:
    """Test rejection of invalid/malicious inputs."""

    def test_invalid_number_rejected(self):
        """Numbers outside 0-11 range should be rejected."""
        in_stream = io.StringIO("12\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_negative_number_rejected(self):
        """Negative numbers should be rejected."""
        in_stream = io.StringIO("-1\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_alphabetic_input_rejected(self):
        """Alphabetic characters should be rejected."""
        in_stream = io.StringIO("abc\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_special_characters_rejected(self):
        """Special characters should be rejected."""
        in_stream = io.StringIO("!@#$\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_empty_input_defaults_to_1(self):
        """Empty input should default to option 1 (Encrypt Text)."""
        in_stream = io.StringIO("\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 1  # Default behavior


class TestSecurityExploits:
    """Test potential security exploits and injection attacks."""

    def test_sql_injection_attempt_rejected(self):
        """SQL injection patterns should be rejected."""
        in_stream = io.StringIO("1' OR '1'='1\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_command_injection_attempt_rejected(self):
        """Command injection patterns should be rejected."""
        in_stream = io.StringIO("1; rm -rf /\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_format_string_injection_rejected(self):
        """Format string injection patterns should be rejected."""
        in_stream = io.StringIO("%s%s%s%s\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_path_traversal_attempt_rejected(self):
        """Path traversal patterns should be rejected."""
        in_stream = io.StringIO("../../etc/passwd\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_null_byte_injection_rejected(self):
        """Null byte injection should be rejected."""
        in_stream = io.StringIO("1\x00\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_unicode_normalization_attack_rejected(self):
        """Unicode normalization attacks should be rejected."""
        in_stream = io.StringIO("\u0031\u0301\n0\n")  # 1 with combining accent
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_buffer_overflow_attempt_rejected(self):
        """Very long input should be rejected without crashing."""
        long_input = "A" * 10000 + "\n0\n"
        in_stream = io.StringIO(long_input)
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_script_tag_injection_rejected(self):
        """Script tag injection should be rejected."""
        in_stream = io.StringIO("<script>alert('xss')</script>\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_newline_injection_rejected(self):
        """Newline injection should be rejected."""
        in_stream = io.StringIO("1\n9\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        # Should only process first valid input
        assert result == 1

    def test_carriage_return_not_stripped(self):
        """Carriage return in input makes it invalid."""
        in_stream = io.StringIO("1\r\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        # \r is not stripped, so "1\r" is invalid input, hits EOF
        assert result is None


class TestEOFHandling:
    """Test EOF and stream closure handling."""

    def test_eof_returns_none(self):
        """EOF should return None."""
        in_stream = io.StringIO("")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result is None

    def test_eof_after_invalid_input_returns_none(self):
        """EOF after invalid input should return None."""
        in_stream = io.StringIO("invalid\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result is None


class TestReprompting:
    """Test menu reprompting on invalid input."""

    def test_reprompts_after_invalid_input(self):
        """Menu should reprompt after invalid input."""
        in_stream = io.StringIO("invalid\n5\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 5
        output = out_stream.getvalue()
        assert output.count("Select operation [0-11]:") == 2

    def test_reprompts_multiple_times(self):
        """Menu should reprompt multiple times if needed."""
        in_stream = io.StringIO("bad1\nbad2\nbad3\n7\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 7
        output = out_stream.getvalue()
        assert output.count("Invalid choice") == 3
        assert output.count("Select operation [0-11]:") == 4


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_only_whitespace_rejected(self):
        """Input with only whitespace should be rejected."""
        in_stream = io.StringIO("   \n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_tab_characters_rejected(self):
        """Tab characters should be rejected."""
        in_stream = io.StringIO("\t\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_mixed_valid_invalid_characters_rejected(self):
        """Mixed valid/invalid characters should be rejected."""
        in_stream = io.StringIO("1abc\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_decimal_number_rejected(self):
        """Decimal numbers should be rejected."""
        in_stream = io.StringIO("1.5\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output

    def test_hexadecimal_rejected(self):
        """Hexadecimal input should be rejected."""
        in_stream = io.StringIO("0x1\n0\n")
        out_stream = io.StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 0
        output = out_stream.getvalue()
        assert "Invalid choice" in output


class TestVaultStoragePrompt:
    """Ensure freshly generated passphrases can be stored immediately."""

    def test_offer_vault_storage_saves_when_inputs_provided(
        self, tmp_path, monkeypatch
    ):
        """User can immediately store a generated passphrase in the vault."""

        class DummyVault:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, str]] = []
                self.path = tmp_path / "vault.enc"

            def store_passphrase(
                self, label: str, passphrase: str, master: str
            ) -> None:
                self.calls.append((label, passphrase, master))

            def get_vault_path(self) -> str:
                return str(self.path)

        dummy_vault = DummyVault()
        monkeypatch.setattr(cli, "PassphraseVault", lambda: dummy_vault)

        in_stream = io.StringIO("y\nbackup\nMasterPassword!\n")
        out_stream = io.StringIO()

        result = _offer_vault_storage("auto-generated-pass", in_stream, out_stream)

        assert dummy_vault.calls == [
            ("backup", "auto-generated-pass", "MasterPassword!")
        ]
        assert result is True

        output = out_stream.getvalue()
        assert "stored in vault" in output
        assert str(dummy_vault.path) in output

    def test_offer_vault_storage_requires_label(self, monkeypatch):
        """Empty labels are rejected and nothing is stored."""

        class DummyVault:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, str]] = []

            def store_passphrase(
                self, label: str, passphrase: str, master: str
            ) -> None:
                self.calls.append((label, passphrase, master))

            def get_vault_path(self) -> str:  # pragma: no cover - unused in this test
                return "unused"

        dummy_vault = DummyVault()
        monkeypatch.setattr(cli, "PassphraseVault", lambda: dummy_vault)

        in_stream = io.StringIO("y\n\n")
        out_stream = io.StringIO()

        result = _offer_vault_storage("pass", in_stream, out_stream)

        assert dummy_vault.calls == []
        assert result is False
        output = out_stream.getvalue()
        assert "Label is required" in output

    def test_offer_vault_storage_requires_master_password(self, monkeypatch):
        """Skipping master password cancels storage."""

        class DummyVault:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, str]] = []

            def store_passphrase(
                self, label: str, passphrase: str, master: str
            ) -> None:
                self.calls.append((label, passphrase, master))

            def get_vault_path(self) -> str:  # pragma: no cover - unused in this test
                return "unused"

        dummy_vault = DummyVault()
        monkeypatch.setattr(cli, "PassphraseVault", lambda: dummy_vault)

        in_stream = io.StringIO("y\nproject\n\n")
        out_stream = io.StringIO()

        result = _offer_vault_storage("pass", in_stream, out_stream)

        assert dummy_vault.calls == []
        assert result is False
        output = out_stream.getvalue()
        assert "Master password is required" in output

    def test_offer_vault_storage_decline_skips_prompt(self, monkeypatch):
        """Declining storage returns without creating a vault instance."""

        def _fail_ctor():  # pragma: no cover - used to ensure not constructed
            raise AssertionError("PassphraseVault should not be instantiated")

        monkeypatch.setattr(cli, "PassphraseVault", _fail_ctor)

        in_stream = io.StringIO("n\n")
        out_stream = io.StringIO()

        result = _offer_vault_storage("pass", in_stream, out_stream)

        output = out_stream.getvalue()
        assert result is False
        assert "Store this passphrase" in output


class TestGeneratePassphraseHandlers:
    """Ensure both generation paths surface the inline vault prompt."""

    def test_inline_generation_offers_vault_storage(self, monkeypatch):
        """Inline helper should always offer to store the new passphrase."""

        captured: dict[str, str] = {}

        def _fake_generate(strategy: str) -> tuple[str, float]:
            captured["strategy"] = strategy
            return "InlinePass", 150.0

        def _fake_offer(
            passphrase: str, in_stream, out_stream, *, require_storage: bool = False
        ) -> bool:
            captured["offered"] = passphrase
            captured["required"] = str(require_storage)
            out_stream.write("offer-called\n")
            return True

        monkeypatch.setattr(cli, "generate_passphrase", _fake_generate)
        monkeypatch.setattr(cli, "_offer_vault_storage", _fake_offer)

        in_stream = io.StringIO("")
        out_stream = io.StringIO()

        result = _handle_generate_passphrase_inline(in_stream, out_stream)

        assert result == "InlinePass"
        assert captured["strategy"] == "alphanumeric"
        assert captured["offered"] == "InlinePass"
        assert captured["required"] == "True"
        assert "offer-called" in out_stream.getvalue()

    def test_menu_generation_offers_vault_storage(self, monkeypatch):
        """Full-screen generator reuses the inline vault prompt helper."""

        captured: dict[str, str] = {}

        def _fake_generate(strategy: str) -> tuple[str, float]:
            captured["strategy"] = strategy
            return "MenuPass", 128.0

        def _fake_offer(
            passphrase: str, in_stream, out_stream, *, require_storage: bool = False
        ) -> bool:
            captured["offered"] = passphrase
            captured["required"] = str(require_storage)
            out_stream.write("offer-called\n")
            return True

        monkeypatch.setattr(cli, "generate_passphrase", _fake_generate)
        monkeypatch.setattr(cli, "_offer_vault_storage", _fake_offer)

        in_stream = io.StringIO("2\n")  # Choose alphanumeric strategy
        out_stream = io.StringIO()

        _handle_generate_passphrase(in_stream, out_stream)

        assert captured["strategy"] == "alphanumeric"
        assert captured["offered"] == "MenuPass"
        assert captured["required"] == "True"
        assert "offer-called" in out_stream.getvalue()
