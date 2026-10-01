"""
Action verbs, approval (step-up) rules, step mandates and the RFC 9396
cross-walk. Added for the Mandate Sandbox (2026-10-01). Mirrors
typescript/test/stepup.test.ts check for check.

Runs under pytest, or standalone: `PYTHONPATH=. python3 tests/test_stepup.py`.

Note the v0 rule this inherits: under a max_amount cap every transaction states
its amount, so non-monetary verbs (cancel, read, submit) carry a zero amount
rather than none. A missing amount under a cap is a deny.
"""

import copy
from datetime import datetime, timedelta, timezone

from mandatekit import ed25519
from mandatekit.crosswalk import to_authorization_details
from mandatekit.mandate import build_mandate, step_mandate, validate
from mandatekit.signing import _b64, sign_mandate
from mandatekit.verifier import verify

ISSUER = bytes(range(32))
STRANGER = bytes(99 - i for i in range(32))
PUB = _b64(ed25519.publickey(ISSUER))
NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
ZERO = {"value": 0, "currency": "GBP"}


def bank_mandate(**extra):
    kw = dict(
        agent_id="agent-tidy",
        intent="life admin for Alex",
        categories=["4900", "4814", "4899"],
        merchants={"allow": ["MID-10231", "MID-10477", "MID-30905"]},
        max_amount={"value": 150000, "currency": "GBP"},
        actions=["read", "draft", "submit", "pay", "cancel"],
        approval={"actions": ["cancel"], "above": {"value": 20000, "currency": "GBP"}},
        issued_at=NOW,
        ttl_days=7,
    )
    kw.update(extra)
    return build_mandate(**kw)


def vrf(signed, txn, **kw):
    kw.setdefault("trusted_keys", [PUB])
    kw.setdefault("now", NOW)
    return verify(signed, txn, **kw)


PAY_SMALL = {"action": "pay", "merchant": "MID-10231", "category": "4900",
             "amount": {"value": 11840, "currency": "GBP"}}
CANCEL = {"action": "cancel", "merchant": "MID-30905", "category": "4899", "amount": ZERO}


def test_build_carries_actions_and_approval():
    m = bank_mandate()
    assert m["constraints"]["actions"] == ["read", "draft", "submit", "pay", "cancel"]
    assert m["constraints"]["approval"] == {"actions": ["cancel"], "above": {"value": 20000, "currency": "GBP"}}
    assert validate(m) == []


def test_build_rejects_non_integer_threshold():
    try:
        bank_mandate(approval={"above": {"value": 50.5, "currency": "GBP"}})
    except ValueError as e:
        assert "integer" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_allowed_verb_under_threshold_is_allowed():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), PAY_SMALL)
    assert v["decision"] == "allow", v["rationale"]
    assert any(c["constraint"] == "action" for c in v["matched"])


def test_verb_outside_allow_list_is_denied():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), dict(PAY_SMALL, action="share"))
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "action" for c in v["failed"])


def test_missing_verb_is_denied_when_actions_constrained():
    txn = {k: v for k, v in PAY_SMALL.items() if k != "action"}
    assert vrf(sign_mandate(bank_mandate(), ISSUER), txn)["decision"] == "deny"


def test_empty_actions_allows_nothing():
    assert vrf(sign_mandate(bank_mandate(actions=[]), ISSUER), PAY_SMALL)["decision"] == "deny"


def test_verb_needing_approval_returns_ask():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), CANCEL)
    assert v["decision"] == "ask", v["rationale"]
    assert v["signature_valid"] is True
    assert v["rationale"].startswith("needs approval")
    assert len(v["failed"]) == 1 and v["failed"][0]["constraint"] == "approval"


def test_amount_above_threshold_under_cap_returns_ask():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), dict(PAY_SMALL, amount={"value": 50000, "currency": "GBP"}))
    assert v["decision"] == "ask"
    assert "approval threshold" in v["rationale"]


def test_over_cap_is_deny_not_ask():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), dict(PAY_SMALL, amount={"value": 200000, "currency": "GBP"}))
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "amount" for c in v["failed"])


def test_ask_never_masks_another_failure():
    v = vrf(sign_mandate(bank_mandate(), ISSUER), dict(CANCEL, merchant="MID-99999"))
    assert v["decision"] == "deny"


def test_step_mandate_turns_ask_into_allow():
    parent = bank_mandate()
    signed_parent = sign_mandate(parent, ISSUER)
    txn = dict(CANCEL, description="cancel StreamBox")
    assert vrf(signed_parent, txn)["decision"] == "ask"

    step = step_mandate(parent, txn, issued_at=NOW)
    assert validate(step) == []
    assert step["constraints"]["actions"] == ["cancel"]
    assert step["constraints"]["merchants"] == {"allow": ["MID-30905"]}
    assert step["subject"]["agent_id"] == "agent-tidy"
    assert parent["mandate_id"] in step["constraints"]["intent"]

    v = vrf(signed_parent, dict(txn, approval=sign_mandate(step, ISSUER)))
    assert v["decision"] == "allow", v["rationale"]
    assert any(c["constraint"] == "approval" and "step mandate" in c["detail"] for c in v["matched"])


def test_step_mandate_from_untrusted_key_does_not_approve():
    parent = bank_mandate()
    step = sign_mandate(step_mandate(parent, CANCEL, issued_at=NOW), STRANGER)
    v = vrf(sign_mandate(parent, ISSUER), dict(CANCEL, approval=step))
    assert v["decision"] == "deny"
    assert "step mandate rejected" in v["rationale"]


def test_step_mandate_for_different_agent_does_not_approve():
    parent = bank_mandate()
    other = copy.deepcopy(parent)
    other["subject"] = {"agent_id": "someone-else"}
    step = sign_mandate(step_mandate(other, CANCEL, issued_at=NOW), ISSUER)
    v = vrf(sign_mandate(parent, ISSUER), dict(CANCEL, approval=step))
    assert v["decision"] == "deny"
    assert "different agent" in v["rationale"]


def test_expired_step_mandate_does_not_approve():
    parent = bank_mandate()
    step = sign_mandate(step_mandate(parent, CANCEL, issued_at=NOW - timedelta(hours=1), ttl_minutes=5), ISSUER)
    v = vrf(sign_mandate(parent, ISSUER), dict(CANCEL, approval=step))
    assert v["decision"] == "deny"
    assert "expired" in v["rationale"]


def test_step_mandate_for_another_transaction_does_not_approve_this_one():
    parent = bank_mandate()
    approved = dict(PAY_SMALL, amount={"value": 50000, "currency": "GBP"})
    step = sign_mandate(step_mandate(parent, approved, issued_at=NOW), ISSUER)
    v = vrf(sign_mandate(parent, ISSUER), dict(approved, amount={"value": 60000, "currency": "GBP"}, approval=step))
    assert v["decision"] == "deny"


def test_malformed_approval_envelope_is_deny_never_ask():
    parent = sign_mandate(bank_mandate(), ISSUER)
    for bad in (42, "x", [], {}, {"mandate": None}, {"mandate": "nope"}):
        v = vrf(parent, dict(CANCEL, approval=bad))
        assert v["decision"] == "deny", bad


def test_actions_alone_are_not_scope():
    m = build_mandate(agent_id="agent-tidy", actions=["read"], issued_at=NOW)
    v = vrf(sign_mandate(m, ISSUER), {"action": "read"})
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "has_scope" for c in v["failed"])


def test_unknown_constraint_still_fails_closed():
    m = bank_mandate()
    m["constraints"]["velocity"] = {"per_day": 3}
    v = vrf(sign_mandate(m, ISSUER), PAY_SMALL)
    assert v["decision"] == "deny"
    assert any(c["constraint"] == "constraints_enforceable" for c in v["failed"])


def test_step_mandate_refuses_unscoped_target():
    try:
        step_mandate(bank_mandate(), {"action": "read"})
    except ValueError as e:
        assert "scoped to" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_crosswalk_to_authorization_details():
    m = bank_mandate()
    (d,) = to_authorization_details(m)
    assert d["type"] == "mandatekit:mandate:v0"
    assert d["identifier"] == m["mandate_id"]
    assert d["actions"] == ["read", "draft", "submit", "pay", "cancel"]
    assert d["locations"] == ["MID-10231", "MID-10477", "MID-30905"]
    assert d["datatypes"] == ["4900", "4814", "4899"]
    assert d["max_amount"] == {"value": 150000, "currency": "GBP"}
    assert d["approval"] == {"actions": ["cancel"], "above": {"value": 20000, "currency": "GBP"}}
    assert d["valid_from"] == m["issued_at"] and d["valid_until"] == m["expires_at"]
    assert d["subject"] == {"agent_id": "agent-tidy"}
    d["actions"].append("share")
    assert len(m["constraints"]["actions"]) == 5


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
