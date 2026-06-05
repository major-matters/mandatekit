"""
Canonical JSON for signing — RFC 8785 (JSON Canonicalization Scheme).

A mandate is signed over its canonical byte form so any party can re-serialize
the same mandate and get the same bytes, hence the same signature check.

v0 uses RFC 8785 (JCS) via the `rfc8785` library (by the RFC's author). JCS pins
number formatting and key ordering precisely, so the Python and TypeScript SDKs
produce byte-identical output (TS uses the `canonicalize` npm package, same RFC).

If `rfc8785` is not installed, we fall back to sorted-key compact JSON, which is
byte-identical to JCS for the v0 schema (integer amounts, ASCII keys). The fallback
keeps the "drop the folder in" path working; install `rfc8785` for full JCS.
"""

import json

try:
    import rfc8785

    _HAVE_JCS = True
except ImportError:  # pragma: no cover - exercised only without the dep
    _HAVE_JCS = False


def canonicalize(obj) -> bytes:
    if _HAVE_JCS:
        return rfc8785.dumps(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
