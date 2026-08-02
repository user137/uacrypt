"""Python bindings for dstu-core (Ukrainian DSTU cryptographic standards).

Provisional - not yet published to PyPI, not independently audited. See the root
project's docs/SECURITY.md and docs/DECISIONS.md for the full threat model and
per-construction status (docs/bindings-strategy.md T-49).
"""

from ._dstu_core import selftest

__all__ = ["selftest"]
