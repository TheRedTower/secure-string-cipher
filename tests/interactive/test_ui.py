"""questionary's Ui, driven through a prompt_toolkit pipe, as a terminal
would drive it."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from prompt_toolkit.input import PipeInput, create_pipe_input
from prompt_toolkit.output import DummyOutput

from secure_string_cipher.interactive.ui import Back, QuestionaryUi

DOWN = "\x1b[B"
ENTER = "\r"


@pytest.fixture
def keys() -> Iterator[PipeInput]:
    with create_pipe_input() as pipe:
        yield pipe


@pytest.fixture
def ui(keys: PipeInput) -> QuestionaryUi:
    return QuestionaryUi(input=keys, output=DummyOutput())


def test_arrow_keys_and_enter(ui: QuestionaryUi, keys: PipeInput) -> None:
    keys.send_text(ENTER)
    assert ui.select("Pick", ["a", "b", "c"], default=2) == 2  # Enter takes the default
    keys.send_text(DOWN + ENTER)
    assert ui.select("Pick", ["a", "b", "c"]) == 1
    keys.send_text(" " + DOWN + DOWN + " " + ENTER)
    assert ui.checkbox("Pick", ["a", "b", "c"]) == [0, 2]


def test_text_password_and_confirm(ui: QuestionaryUi, keys: PipeInput) -> None:
    keys.send_text("report.txt" + ENTER)
    assert ui.path("Which file?") == "report.txt"
    keys.send_text(ENTER)
    assert ui.text("Label?", "recovery") == "recovery"
    keys.send_text("hunter22" + ENTER)
    assert ui.password("Password") == "hunter22"
    keys.send_text(ENTER)
    assert ui.confirm("Go?", default=True) is True
    keys.send_text("n")
    assert ui.confirm("Go?", default=True) is False
    ui.say("✓ Wrote report.txt.ssc")


def test_ctrl_c_goes_back(ui: QuestionaryUi, keys: PipeInput) -> None:
    keys.send_text("\x03")
    with pytest.raises(Back):
        ui.select("Pick", ["a", "b"])
