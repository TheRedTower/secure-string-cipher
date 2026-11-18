"""The test vectors are frozen (Phase 1, step 5).

Changing a vector means changing the spec. These tests fail on any edit to a
vector file, and on any vector added or removed, unless the manifest and the
pinned manifest hash below change with it, in a reviewed PR.
"""

import hashlib
import json
from pathlib import Path

VECTORS = Path(__file__).parent / "vectors"
MANIFEST_SHA256 = "1d70c9c7b8c64483f770146f4aa413e7902906bf6c355d23be896f59576163ef"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_the_frozen_one() -> None:
    assert sha256(VECTORS / "manifest.json") == MANIFEST_SHA256


def test_every_vector_file_matches_the_manifest() -> None:
    manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
    hashed = {v["file"]: v["sha256"] for v in manifest["valid"] + manifest["reject"]}
    hashed[manifest["vault"]["file"]] = manifest["vault"]["sha256"]
    hashed |= {k["file"]: k["sha256"] for k in manifest["keyfiles"]}
    for name, digest in hashed.items():
        assert sha256(VECTORS / name) == digest, name

    listed = set(hashed) | {"manifest.json"}
    on_disk = {p.name for p in VECTORS.iterdir()}
    assert on_disk == listed
