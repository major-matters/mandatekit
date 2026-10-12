"""
Usage state for the 0.2 limits.

A mandate's `limits` (max uses, cumulative amount, per-window counts) can only
be enforced against a record of what the mandate has already been used for.
`verify()` is stateless by itself, so a mandate that declares `limits` is
denied unless the caller passes a store; this module holds the store contract
and an in-memory reference implementation.

The contract is two methods, duck-typed:

    store.uses(mandate_id) -> iterable of use records
    store.record(mandate_id, use) -> None

A use record is a plain dict: ``{"at": <seconds since the epoch, int or float>,
"action": <verb or None>, "amount": {"value": int, "currency": str} or None}``.
`record_use()` in the verifier module writes one for every mandate id in a
delegation chain (the leaf and each ancestor), so a parent's limits bind all
of its children. The verifier only reads; the caller records after it has
acted on an "allow", which keeps check and act separate, as in BudgetGuard.

Fail closed: a store that raises, or returns a malformed record, is a deny
(`limits_store`), never an exception out of `verify()`.

The in-memory store is single process and per instance; a store that survives
a restart is roadmap work (6.3), not in 0.2.
"""

from typing import Dict, Iterable, List


class InMemoryUsageStore:
    """Reference store: a dict of mandate id to the list of recorded uses."""

    def __init__(self) -> None:
        self._uses: Dict[str, List[Dict]] = {}

    def uses(self, mandate_id: str) -> Iterable[Dict]:
        return list(self._uses.get(mandate_id, []))

    def record(self, mandate_id: str, use: Dict) -> None:
        self._uses.setdefault(mandate_id, []).append(dict(use))

    def clear(self) -> None:
        self._uses.clear()
