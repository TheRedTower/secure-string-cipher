"""Regression checks for public documentation examples and API coverage."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import secure_string_cipher

REPOSITORY_ROOT = Path(__file__).parents[2]
PYTHON_FENCE = re.compile(
    r"^```python[^\n]*\n(.*?)^```[ \t]*$",
    flags=re.MULTILINE | re.DOTALL,
)


@pytest.mark.parametrize(
    "relative_path",
    [Path("README.md"), Path("docs/API.md")],
    ids=str,
)
def test_public_python_examples_are_syntactically_valid(relative_path: Path) -> None:
    """Keep every advertised Python example valid Python syntax."""
    document = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
    examples = PYTHON_FENCE.findall(document)

    assert examples, f"No Python examples found in {relative_path}"
    for index, example in enumerate(examples, start=1):
        compile(example, f"{relative_path} Python example {index}", "exec")


def test_api_index_covers_every_package_root_export() -> None:
    """Make additions or removals from the public API update its index."""
    document = (REPOSITORY_ROOT / "docs" / "API.md").read_text(encoding="utf-8")
    table = document.split("## Public API at a glance", maxsplit=1)[1].split(
        "## Core Encryption", maxsplit=1
    )[0]
    documented = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", table))

    assert documented == set(secure_string_cipher.__all__)
