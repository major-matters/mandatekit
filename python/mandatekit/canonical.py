"""
Canonical JSON for signing.

A mandate is signed over its canonical byte form so that any party can
re-serialize the same mandate and get the same bytes, hence the same signature
check. v0 uses sorted keys + compact separators. This is deliberately simple and
documented; a 1.0 would adopt RFC 8785 (JCS) for full number-canonicalization
guarantees. The TypeScript port produces byte-identical output.
"""

import json


def canonicalize(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
