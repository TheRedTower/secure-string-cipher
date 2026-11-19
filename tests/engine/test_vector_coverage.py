"""Every frozen vector is tested whole, or is named as pending with the step
that will test it. A vector cannot drop out of the suite unnoticed."""

from __future__ import annotations

from tests import vectorkit
from tests.engine import test_access_vectors as whole


def test_every_vector_is_covered_or_pending() -> None:
    names = [v["name"] for v in vectorkit.manifest()["valid"]]
    names += [v["name"] for v in vectorkit.manifest()["reject"]]
    covered = [*whole.OPENS, *whole.REJECTS]
    pending = [name for names in whole.PENDING.values() for name in names]
    assert sorted(covered + pending) == sorted(names)
    assert not set(covered) & set(pending)
