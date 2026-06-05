"""
Property-based tests (Hypothesis) for the security-critical paths.

Separate from test_mandatekit.py because it needs `hypothesis`. Run:

    pip install hypothesis
    PYTHONPATH=. python3 tests/test_properties.py      # or: pytest tests/test_properties.py

These generate inputs rather than hand-pick them, to flush out edge cases in
signing, canonicalization, the amount boundary, forgery rejection, and
robustness against hostile input.
"""

from datetime import datetime, timezone

from hypothesis import given, settings, strategies as st

from mandatekit import ed25519
from mandatekit.canonical import canonicalize
from mandatekit.mandate import build_mandate
from mandatekit.signing import _b64, _public_from_seed, sign_mandate, verify_signature
from mandatekit.verifier import verify

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
FAR = datetime(2099, 1, 1, tzinfo=timezone.utc)

seeds = st.binary(min_size=32, max_size=32)
amounts = st.integers(min_value=0, max_value=10 ** 12)
currencies = st.sampled_from(["USD", "GBP", "EUR", "JPY"])
# Arbitrary JSON-ish values for hostile-input testing.
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda c: st.lists(c, max_size=5) | st.dictionaries(st.text(max_size=8), c, max_size=5),
    max_leaves=40,
)


@given(seeds, st.text(min_size=0, max_size=200))
def test_sign_verify_roundtrip(seed, intent):
    m = build_mandate(agent_id="a", intent=intent or None,
                      max_amount={"value": 100, "currency": "USD"},
                      issued_at=NOW, expires_at=FAR)
    signed = sign_mandate(m, seed)
    assert verify_signature(signed) is True


@given(seeds, amounts.filter(lambda x: x != 100))
def test_tamper_breaks_signature(seed, new_cap):
    m = build_mandate(agent_id="a", max_amount={"value": 100, "currency": "USD"},
                      issued_at=NOW, expires_at=FAR)
    signed = sign_mandate(m, seed)
    # new_cap != 100, so this is a genuine change to the signed mandate.
    signed["mandate"]["constraints"]["max_amount"]["value"] = new_cap
    assert verify_signature(signed) is False


@given(st.dictionaries(st.text(min_size=1, max_size=8),
                       st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1), max_size=8))
def test_canonical_key_order_invariant(d):
    # Re-inserting the same keys in reverse order must canonicalize identically.
    reordered = {k: d[k] for k in reversed(list(d))}
    assert canonicalize(d) == canonicalize(reordered)


@given(seeds, amounts, amounts, currencies)
def test_amount_boundary(seed, cap, value, currency):
    m = build_mandate(agent_id="a", categories=["apparel"],
                      max_amount={"value": cap, "currency": currency},
                      issued_at=NOW, expires_at=FAR)
    signed = sign_mandate(m, seed)
    pub = _b64(_public_from_seed(seed))
    txn = {"merchant": "X", "category": "apparel", "amount": {"value": value, "currency": currency}}
    v = verify(signed, txn, now=NOW, trusted_keys=[pub])
    # In scope on every other axis, so the decision is exactly the amount check.
    assert (v["decision"] == "allow") == (value <= cap)


@given(seeds, seeds)
def test_forgery_denied_under_pinning(signer_seed, trusted_seed):
    m = build_mandate(agent_id="a", categories=["apparel"],
                      max_amount={"value": 1000, "currency": "USD"},
                      issued_at=NOW, expires_at=FAR)
    signed = sign_mandate(m, signer_seed)
    trusted = _b64(_public_from_seed(trusted_seed))
    txn = {"merchant": "X", "category": "apparel", "amount": {"value": 1, "currency": "USD"}}
    v = verify(signed, txn, now=NOW, trusted_keys=[trusted])
    # Allowed only if the signer IS the trusted key (i.e. same seed -> same pubkey).
    same_key = _public_from_seed(signer_seed) == _public_from_seed(trusted_seed)
    assert (v["decision"] == "allow") == same_key


@settings(max_examples=200)
@given(json_values, json_values)
def test_verify_never_raises_on_garbage(mandate_like, txn_like):
    # Hostile / malformed input must produce a verdict, never an exception.
    v = verify({"mandate": mandate_like, "signature": txn_like},
               txn_like if isinstance(txn_like, dict) else {},
               now=NOW, trusted_keys=["AAAA"])
    assert v["decision"] in ("allow", "deny")


@given(seeds, st.text(max_size=30), st.text(max_size=30))
def test_ed25519_reference_roundtrip(seed, a, b):
    # The pure-Python fallback must stay self-consistent for any messages.
    pub = ed25519.publickey(seed)
    sig = ed25519.sign(a.encode(), seed, pub)
    assert ed25519.verify(sig, a.encode(), pub) is True
    if a != b:
        assert ed25519.verify(sig, b.encode(), pub) is False


if __name__ == "__main__":
    import sys

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:
            failures += 1
            print(f"  FAIL  {t.__name__}: {type(e).__name__}: {str(e)[:200]}")
    print(f"\n{len(tests) - failures}/{len(tests)} property tests passed")
    sys.exit(1 if failures else 0)
