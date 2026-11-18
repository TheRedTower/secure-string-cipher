"""Path checks for local managed-key and lock files."""

from pathlib import Path

# Some OS installs make a stable system path a symlink (macOS's
# /var -> /private/var, notably). Rejecting every symlinked ancestor
# unconditionally would reject ordinary paths under those roots — including
# macOS's own temp directory, which is rooted at /var/folders. This mirrors
# core.py's v1 copy rather than importing it: v1 and v2 are separate parallel
# implementations by design (see docs/V2_MANAGED_KEYS_ARCHITECTURE.md).
SYSTEM_SYMLINK_ALLOWLIST = frozenset({Path("/var")})


def is_allowed_system_symlink(component: Path) -> bool:
    """Report whether a symlinked path component is a known-benign OS symlink.

    Only the literal allowlisted path is exempt. Matching on the symlink's
    *target* instead would exempt any attacker-created symlink that happens
    to point at an allowlisted path: on a system where /var is an ordinary
    directory (i.e. Linux), `evil -> /var` would let `evil/tmp/key.ssckey`
    redirect a keyfile or lock write into /var/tmp. The exemption exists only
    because a platform ships /var as a symlink itself, which this comparison
    covers.
    """
    return component in SYSTEM_SYMLINK_ALLOWLIST


def reject_symlink_components(path: Path) -> None:
    """Reject a symlink at the destination or any lexical parent component.

    Known-benign OS symlinks are permitted, matching the same allowlist
    v2/output.py applies to container writes. Without that exception a
    `.ssckey` or lock file could not be placed anywhere under macOS's
    /var-rooted temporary directory, while a `.ssc` container in the same
    directory would be accepted — an inconsistency within v2, not a policy.
    """
    absolute = path.expanduser().absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink() and not is_allowed_system_symlink(component):
            raise OSError(f"{component} is a symlink, which is not permitted")
