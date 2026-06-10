"""
Canonical JSON for signing — RFC 8785 (JSON Canonicalization Scheme).

An object is signed (and, where applicable, hashed for content addressing) over
its canonical byte form so any party can re-serialize the same object and get the
same bytes, hence the same signature/hash.

The primary path uses RFC 8785 (JCS) via the `rfc8785` library (by the RFC's
author), a declared dependency. JCS pins number formatting and key ordering
precisely, so the Python and TypeScript SDKs produce byte-identical output (TS
uses the `canonicalize` npm package, same RFC).

If `rfc8785` is not installed (the zero-dependency "drop the folder in" path),
we fall back to sorted-key compact JSON. Plain json.dumps does NOT match JCS
number formatting for floats or out-of-safe-range integers (e.g. 1.0 vs 1,
-0.0 vs 0, 1e20 vs 100000000000000000000). Emitting those bytes would silently
diverge from JCS and break cross-SDK verification, so the fallback FAILS CLOSED:
it rejects any such value rather than guess. For accepted inputs (strings,
booleans, null, and integers within the IEEE-754 safe range) the fallback is
byte-identical to JCS. Install `rfc8785` to canonicalize the full value space.
"""

import json

try:
    import rfc8785

    _HAVE_JCS = True
except ImportError:  # pragma: no cover - exercised only without the dep
    _HAVE_JCS = False

# RFC 8785 / ECMAScript safe-integer range. Outside this, json.dumps and JCS can
# disagree, so the dependency-free fallback refuses rather than emit guessed bytes.
_MAX_SAFE_INT = 2**53 - 1
_MIN_SAFE_INT = -(2**53 - 1)


def _reject_divergent(obj) -> None:
    """Fail closed on any value whose plain-JSON form could differ from JCS."""
    if obj is None or isinstance(obj, bool) or isinstance(obj, str):
        return
    if isinstance(obj, float):
        raise ValueError(
            "canonicalize fallback cannot safely encode floats (RFC 8785 "
            "divergence); install rfc8785 for full JCS number formatting"
        )
    if isinstance(obj, int):
        if obj < _MIN_SAFE_INT or obj > _MAX_SAFE_INT:
            raise ValueError(
                "canonicalize fallback cannot safely encode integers outside the "
                "IEEE-754 safe range (RFC 8785 divergence); install rfc8785"
            )
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_divergent(v)
        return
    if isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_divergent(v)
        return
    # Unknown type: let json.dumps raise its own TypeError below.


def canonicalize(obj) -> bytes:
    if _HAVE_JCS:
        return rfc8785.dumps(obj)
    _reject_divergent(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
