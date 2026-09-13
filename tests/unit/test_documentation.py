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
    """Make additions or removals from the public API update its index.

    Reads the table rows only, not the whole section: prose explaining the
    table is free to mention a backticked identifier (a deprecation notice
    naming `DeprecationWarning`, say) without that counting as a documented
    export, which would otherwise make this fail for writing about the API.
    """
    document = (REPOSITORY_ROOT / "docs" / "API.md").read_text(encoding="utf-8")
    section = document.split("## Public API at a glance", maxsplit=1)[1].split(
        "## Core Encryption", maxsplit=1
    )[0]
    rows = [line for line in section.splitlines() if line.lstrip().startswith("|")]
    documented = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", "\n".join(rows)))

    assert documented == set(secure_string_cipher.__all__)


def test_docs_readme_indexes_every_file_in_the_docs_directory() -> None:
    """Make an addition under docs/ show up in its own index.

    #113 found six of thirteen files in docs/ absent from docs/README.md's
    index -- including two that are still current (MIGRATION.md, the
    refined implementation spec) and were simply missed, not deliberately
    excluded. This does not require every file to be linked with a specific
    description; it only requires the filename to appear *somewhere* in the
    index, so a file can be covered by a general historical-evidence bullet
    without a dedicated line of its own.
    """
    docs_dir = REPOSITORY_ROOT / "docs"
    readme = (docs_dir / "README.md").read_text(encoding="utf-8")

    markdown_files = {
        path.name for path in docs_dir.glob("*.md") if path.name != "README.md"
    }
    assert markdown_files, "expected at least one markdown file under docs/"

    missing = {name for name in markdown_files if name not in readme}
    assert not missing, f"docs/README.md does not mention: {sorted(missing)}"
