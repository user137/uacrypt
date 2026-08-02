"""Correctness gate: `dstu_core.selftest()` re-verifies one official vector per primitive
(Kalyna, Kupyna, Strumok, DSTU 4145) against this exact compiled extension - `docs/TASKS.md`
T-161. Every other test file in this suite adds its own correctness/rejection/misuse coverage on
top of this baseline (D-64/D-65).
"""

import dstu_core as d


def test_selftest_passes() -> None:
    d.selftest()  # raises DstuError on any mismatch
