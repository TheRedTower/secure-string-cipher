"""Every frozen vector is tested whole: the Phase 2 gate. A vector cannot
drop out of the suite unnoticed."""

from __future__ import annotations

from tests import vectorkit
from tests.engine import test_access_vectors as whole


def test_every_vector_is_covered() -> None:
    names = [v["name"] for v in vectorkit.manifest()["valid"]]
    names += [v["name"] for v in vectorkit.manifest()["reject"]]
    assert sorted([*whole.OPENS, *whole.REJECTS]) == sorted(names)
