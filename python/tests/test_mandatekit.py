"""
MandateKit v0 test suite.

Runs under pytest, or standalone: `python tests/test_mandatekit.py`.

Includes a regression block for the five attacks found in security review:
forgery (no issuer pinning), allow-all on empty constraints, fail-open empty
allow-lists, unenforceable constraints, and DoS via nested JSON.
"""

import copy
from datetime import datetime, timezone

import mandatekit
from mandatekit import ed25519, mandate as mandate_mod
from mandatekit.compiler import compile, rule_based_parser
from mandatekit.mandate import build_mandate
from mandatekit.signing import _b64, sign_mandate, verify_signature
from mandatekit.verifier import verify

# Fixed key so tests are deterministic. NEVER use a hardcoded key in production.
KEY = bytes(range(32))
PUB = _b64(ed25519.publickey(KEY))            # trusted issuer key (base64)
NOW = datetime(2026, 6, 5, 12, 0, 0, tzinfo=timezone.utc)
CANON = (
    "Allow this agent to buy running shoes from any apparel retailer "
    "up to $500 per transaction, expires June 30"
)


def _signed():
    return compile(CANON, agent_id="agent-7", private_key=KEY, now=NOW)


def vrf(signed, txn, **kw):
    """verify() pinned to the test issuer key unless a test overrides."""
    kw.setdefault("trusted_keys", [PUB])
    kw.setdefault("now", NOW)
    return verify(signed, txn, **kw)


# --- crypto -----------------------------------------------------------------

def test_ed25519_roundtrip():
    pk = ed25519.publickey(KEY)
    sig = ed25519.sign(b"hello", KEY, pk)
    assert ed25519.verify(sig, b"hello", pk)
    assert not ed25519.verify(sig, b"hellp", pk)


def test_ed25519_regression_vector():
    assert (
        ed25519.publickey(KEY).hex()
        == "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    )


# --- compiler ---------------------------------------------------------------

def test_compile_canonical_example():
    parsed = rule_based_parser(CANON, now=NOW)
    assert parsed["intent"] == "buy running shoes"
    assert parsed["categories"] == ["apparel"]
    assert parsed["max_amount"] == {"value": 500, "currency": "USD"}
    assert parsed["expires_at"] == datetime(2026, 6, 30, 23, 59, 59, tzinfo=timezone.utc)


def test_compile_produces_valid_signed_mandate():
    signed = _signed()
    assert verify_signature(signed)
    assert mandate_mod.validate(signed["mandate"]) == []
    assert signed["mandate"]["subject"]["agent_id"] == "agent-7"
    assert signed["signature"]["alg"] == "Ed25519"


def test_currency_symbols():
    assert rule_based_parser("up to £200")["max_amount"] == {"value": 200, "currency": "GBP"}
    assert rule_based_parser("under 50 euros")["max_amount"] == {"value": 50, "currency": "EUR"}


def test_iso_expiry():
    parsed = rule_based_parser("buy one coffee, expires 2026-12-31")
    assert parsed["expires_at"] == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


# --- verifier: the happy path -----------------------------------------------

def test_verify_allows_in_scope():
    v = vrf(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                        "amount": {"value": 240, "currency": "USD"}})
    assert v["decision"] == "allow"
    assert v["signature_valid"] is True
    assert not v["failed"]


def test_verify_denies_over_amount():
    v = vrf(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                        "amount": {"value": 600, "currency": "USD"}})
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "amount" for c in v["failed"])


def test_verify_denies_wrong_category():
    v = vrf(_signed(), {"merchant": "BestBuy", "category": "electronics",
                        "amount": {"value": 100, "currency": "USD"}})
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "category" for c in v["failed"])


def test_verify_denies_wrong_currency():
    v = vrf(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                        "amount": {"value": 100, "currency": "GBP"}})
    assert v["decision"] == "deny"


def test_verify_denies_expired():
    later = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
    v = vrf(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                        "amount": {"value": 100, "currency": "USD"}}, now=later)
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "not_expired" for c in v["failed"])


def test_verify_rejects_tampered_mandate():
    tampered = copy.deepcopy(_signed())
    tampered["mandate"]["constraints"]["max_amount"]["value"] = 100000
    v = vrf(tampered, {"merchant": "X", "category": "apparel",
                       "amount": {"value": 9000, "currency": "USD"}})
    assert v["decision"] == "deny"
    assert v["signature_valid"] is False
    assert "signature invalid" in v["rationale"]


def test_merchant_allow_list():
    signed = compile("buy coffee only from Blue Bottle up to $20",
                     agent_id="a", private_key=KEY, now=NOW)
    ok = vrf(signed, {"merchant": "Blue Bottle", "amount": {"value": 5, "currency": "USD"}})
    bad = vrf(signed, {"merchant": "Starbucks", "amount": {"value": 5, "currency": "USD"}})
    assert ok["decision"] == "allow"
    assert bad["decision"] == "deny"


def test_injected_intent_scorer_can_deny():
    txn = {"merchant": "Fleet Feet", "category": "apparel",
           "amount": {"value": 240, "currency": "USD"}, "description": "garden hose"}
    low = vrf(_signed(), txn, intent_scorer=lambda i, t: 0.1)
    high = vrf(_signed(), txn, intent_scorer=lambda i, t: 0.95)
    assert low["decision"] == "deny"
    assert low["intent_alignment"] == 0.1
    assert high["decision"] == "allow"


def test_intent_scorer_error_does_not_crash():
    def boom(intent, t):
        raise RuntimeError("model down")
    v = vrf(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                        "amount": {"value": 240, "currency": "USD"}}, intent_scorer=boom)
    assert v["decision"] == "allow"  # a model outage must not deny a valid txn


# --- SECURITY REGRESSION (the five attacks) ---------------------------------

BIG = {"merchant": "Rolex", "category": "jewelry", "amount": {"value": 1_000_000, "currency": "USD"}}


def test_attack1_forgery_rejected_by_issuer_pinning():
    atk = bytes(range(1, 33))  # attacker's own key
    forged = compile("buy running shoes from any apparel retailer up to $9000000",
                     agent_id="agent-7", private_key=atk, now=NOW)
    v = vrf(forged, BIG)  # pinned to the victim PUB
    assert v["decision"] == "deny"
    assert v["signature_valid"] is True               # crypto is fine...
    assert any(c["constraint"] == "issuer_trusted" for c in v["failed"])  # ...but not trusted


def test_unverified_issuer_default_fails_closed():
    # No trusted_keys and no opt-in flag -> deny, even for a legit mandate.
    v = verify(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                           "amount": {"value": 240, "currency": "USD"}}, now=NOW)
    assert v["decision"] == "deny"
    assert "trusted issuer" in v["rationale"]


def test_allow_unverified_issuer_opt_in():
    v = verify(_signed(), {"merchant": "Fleet Feet", "category": "apparel",
                           "amount": {"value": 240, "currency": "USD"}},
               now=NOW, allow_unverified_issuer=True)
    assert v["decision"] == "allow"


def test_attack2_empty_constraints_denied():
    signed = sign_mandate(build_mandate(agent_id="agent-7", issued_at=NOW), KEY)
    v = vrf(signed, BIG)
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "has_scope" for c in v["failed"])


def test_attack3_empty_category_list_denied():
    m = build_mandate(agent_id="a", max_amount={"value": 500, "currency": "USD"}, issued_at=NOW)
    m["constraints"]["categories"] = []  # "allow nothing"
    signed = sign_mandate(m, KEY)
    v = vrf(signed, {"merchant": "X", "category": "electronics",
                     "amount": {"value": 10, "currency": "USD"}})
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "category" for c in v["failed"])


def test_attack4_unenforceable_constraint_denied():
    m = build_mandate(agent_id="a", max_amount={"value": 500, "currency": "USD"}, issued_at=NOW)
    m["constraints"]["max_uses"] = 1  # a constraint v0 cannot enforce
    signed = sign_mandate(m, KEY)
    v = vrf(signed, {"merchant": "X", "amount": {"value": 5, "currency": "USD"}})
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "constraints_enforceable" for c in v["failed"])


def test_attack5_nested_dos_rejected_without_crash():
    deep = {"a": 1}
    for _ in range(2000):
        deep = {"x": deep}
    bad = {"mandate": {"version": "mandatekit/v0", "constraints": deep},
           "signature": {"alg": "Ed25519", "public_key": "AA==", "value": "AA=="}}
    v = verify(bad, {"amount": {"value": 1, "currency": "USD"}}, now=NOW, trusted_keys=[PUB])
    assert v["decision"] == "deny"
    assert "size/nesting" in v["rationale"]


def test_float_amount_rejected_at_build():
    try:
        build_mandate(agent_id="a", max_amount={"value": 19.99, "currency": "USD"}, issued_at=NOW)
        assert False, "expected ValueError for float amount"
    except ValueError:
        pass


def test_float_txn_amount_denied():
    signed = compile("buy shoes from any apparel store up to $500",
                     agent_id="a", private_key=KEY, now=NOW)
    v = vrf(signed, {"merchant": "X", "category": "apparel",
                     "amount": {"value": 19.99, "currency": "USD"}})
    assert v["decision"] == "deny"


# --- LLM layer (offline: parsing logic, no network/key) ---------------------

from mandatekit import llm  # noqa: E402


def test_extract_json_variants():
    assert llm._extract_json('{"a": 1}') == {"a": 1}
    assert llm._extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm._extract_json('```\n{"a": 1}\n```') == {"a": 1}
    assert llm._extract_json('Sure, here you go:\n{"a": 1}\nhope that helps') == {"a": 1}


def test_constraints_from_data_maps_and_drops_nulls():
    data = {"intent": "buy shoes", "categories": ["apparel"],
            "max_amount": {"value": 500, "currency": "USD"},
            "merchants": None, "expires_at": "2026-06-30"}
    out = llm._constraints_from_data(data)
    assert out["intent"] == "buy shoes"
    assert out["categories"] == ["apparel"]
    assert out["max_amount"] == {"value": 500, "currency": "USD"}
    assert "merchants" not in out  # null dropped
    assert out["expires_at"].year == 2026


def test_anthropic_parser_offline_with_stubbed_client():
    """Exercise the full parser composition without network, by stubbing _client."""
    class _Msg:
        text = '```json\n{"intent":"buy shoes","max_amount":{"value":500,"currency":"USD"}}\n```'

    class _Resp:
        content = [_Msg()]

    class _Messages:
        def create(self, **kw):
            return _Resp()

    class _Client:
        messages = _Messages()

    original = llm._client
    llm._client = lambda: _Client()
    try:
        parsed = llm.anthropic_parser("buy me some shoes please")
    finally:
        llm._client = original
    assert parsed["intent"] == "buy shoes"
    assert parsed["max_amount"] == {"value": 500, "currency": "USD"}
    # and it must compose into a valid signed mandate
    signed = compile("buy me some shoes", agent_id="a", private_key=KEY,
                     parser=lambda t, now=None: parsed, now=NOW)
    assert verify_signature(signed)


# --- standalone runner ------------------------------------------------------

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
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
