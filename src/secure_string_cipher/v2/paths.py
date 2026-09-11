"""Path checks for local managed-key and lock files."""

from pathlib import Path


def reject_symlink_components(path: Path) -> None:
    """Reject a symlink at the destination or any lexical parent component."""
    absolute = path.expanduser().absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise OSError(f"{component} is a symlink, which is not permitted")
