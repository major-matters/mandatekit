"""
MandateKit 0.2: per-verb counterparty scope, time windows, usage limits against
a state store, issuer-signed revocation lists, delegation chains, and the wire
version bump. Mirrors typescript/test/v02.test.ts check for check; both suites
also replay fixtures/verdict-matrix.json so the two implementations are proven
to agree verdict for verdict on envelopes signed by this SDK.

Every verify() here passes an explicit `now`; nothing touches the wall clock.

Runs under pytest, or standalone: `PYTHONPATH=. python3 tests/test_v02.py`.
"""

import copy
import json
import os
from datetime import datetime, timedelta, timezone

import mandatekit
from mandatekit import (
    MANDATE_SCHEMA,
    REASON_CODES,
    SUPPORTED_VERSIONS,
    VERSION,
    InMemoryUsageStore,
    build_mandate,
    build_revocation_list,
    delegate_mandate,
    record_use,
    sign_mandate,
    sign_revocation_list,
    to_authorization_details,
    validate,
    verify,
    verify_revocation_list_signature,
)
from mandatekit.signing import _b64, _public_from_seed

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fixtures", "verdict-matrix.json")

ISSUER = bytes(range(32))
DELEGATE = bytes(range(32, 64))
STRANGER = bytes(99 - i for i in range(32))
PUB = _b64(_public_from_seed(ISSUER))
DPUB_RAW = _public_from_seed(DELEGATE)
NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
ISSUED = NOW - timedelta(days=1)
EXPIRES = NOW + timedelta(days=7)

BANK, THAMES = "harbourline", "MID-10231"
SCOPE = {BANK: ["read", "submit", "transfer"], THAMES: ["read", "draft", "pay"]}


def gbp(v):
    return {"value": v, "currency": "GBP"}


def txn(action, merchant, category, value):
    return {"action": action, "merchant": merchant, "category": category, "amount": gbp(value)}


PAY_THAMES = txn("pay", THAMES, "4900", 11840)
PAY_BANK = txn("pay", BANK, "bank", 8400)
READ_BANK = txn("read", BANK, "bank", 0)


def root(**over):
    kw = dict(agent_id="agent-tidy", agent_public_key=DPUB_RAW, intent="pay the energy bill",
              categories=["bank", "4900"], counterparties=SCOPE, max_amount=gbp(15000),
              actions=["read", "draft", "submit", "pay", "transfer"], approval={"actions": ["submit"]},
              issued_at=ISSUED, expires_at=EXPIRES)
    kw.update(over)
    return build_mandate(**kw)


def vrf(signed, t, **kw):
    kw.setdefault("trusted_keys", [PUB])
    kw.setdefault("now", NOW)
    return verify(signed, t, **kw)


def codes(v):
    return sorted(c["constraint"] for c in v["failed"])


def raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc as e:
        return e
    raise AssertionError(f"expected {exc.__name__}")


# --- versions, builders, validation -----------------------------------------------

def test_versions_are_aligned():
    assert mandatekit.__version__ == "0.2.0"
    assert VERSION == "mandatekit/v0.2"
    assert SUPPORTED_VERSIONS == ("mandatekit/v0", "mandatekit/v0.2")
    assert MANDATE_SCHEMA["properties"]["version"]["enum"] == ["mandatekit/v0", "mandatekit/v0.2"]
    assert len(set(REASON_CODES)) == len(REASON_CODES)


def test_build_carries_the_new_fields_and_validate_accepts_them():
    m = root(not_before=NOW, limits={"actions": ["pay"], "max_uses": 1},
             revocation={"list_id": "rl-1", "max_age_seconds": 3600}, delegation={"max_depth": 1}, mandate_id="m")
    c = m["constraints"]
    assert m["version"] == "mandatekit/v0.2"
    assert m["subject"] == {"agent_id": "agent-tidy", "public_key": _b64(DPUB_RAW)}
    assert c["counterparties"] == SCOPE
    assert c["not_before"] == "2026-10-12T12:00:00Z"
    assert c["limits"] == {"actions": ["pay"], "max_uses": 1}
    assert c["revocation"] == {"list_id": "rl-1", "max_age_seconds": 3600}
    assert c["delegation"] == {"max_depth": 1}
    assert validate(m) == []
    old = copy.deepcopy(m)
    old["version"] = "mandatekit/v0"
    assert validate(old) == []                      # the old wire version still validates


def test_build_rejects_bad_inputs():
    raises(ValueError, root, counterparties={BANK: "read"})
    raises(ValueError, root, counterparties=[BANK])
    raises(ValueError, root, limits={"max_uses_per_window": 1})          # no window
    raises(ValueError, root, limits={"window_seconds": 60})              # no limit
    raises(ValueError, root, limits={"max_uses": 1, "per_day": 3})       # unknown key
    raises(ValueError, root, limits={"max_uses": 1.5})
    raises(ValueError, root, limits={"max_amount_per_window": {"value": 1.5, "currency": "GBP"}, "window_seconds": 60})
    raises(ValueError, root, revocation={"list_id": ""})
    raises(ValueError, root, revocation={"list_id": "x", "url": "https://example.test"})
    raises(ValueError, root, delegation={"max_depth": -1})
    raises(ValueError, root, delegation={"max_depth": 1}, agent_public_key=None)
    raises(ValueError, root, delegation={"parent": {}})
    raises(ValueError, root, agent_public_key=b"short")


def test_validate_reports_malformed_new_fields():
    m = root(mandate_id="m")
    m["constraints"]["counterparties"] = {BANK: "read"}
    m["constraints"]["not_before"] = "soon"
    m["constraints"]["limits"] = {"max_uses": "1"}
    m["constraints"]["revocation"] = {"list_id": 7}
    m["constraints"]["delegation"] = {"extra": 1}
    m["subject"]["public_key"] = ""
    problems = validate(m)
    for needle in ("counterparties", "not_before", "max_uses", "list_id", "delegation", "public_key"):
        assert any(needle in p for p in problems), (needle, problems)


# --- per-verb counterparty scope ------------------------------------------------------

def test_pay_to_the_bank_is_denied_by_counterparty_scope():
    s = sign_mandate(root(mandate_id="m"), ISSUER)
    assert vrf(s, PAY_THAMES)["decision"] == "allow"
    v = vrf(s, PAY_BANK)
    assert v["decision"] == "deny" and codes(v) == ["counterparty_scope"]
    assert v["failed"][0]["detail"] == "'harbourline' is scoped to [read, submit, transfer]; pay is not allowed there"
    assert vrf(s, txn("transfer", BANK, "bank", 8400))["decision"] == "allow"
    assert vrf(s, txn("submit", BANK, "bank", 0))["decision"] == "ask"
    unlisted = vrf(s, txn("pay", "MID-41120", "4900", 100))
    assert codes(unlisted) == ["counterparty_scope"]
    assert unlisted["failed"][0]["detail"] == "'MID-41120' is not a listed counterparty"


def test_flat_allow_list_still_means_every_allowed_verb():
    s = sign_mandate(root(mandate_id="m", counterparties=None, merchants={"allow": [BANK, THAMES]}), ISSUER)
    assert vrf(s, PAY_BANK)["decision"] == "allow"


def test_counterparties_count_as_scope():
    m = build_mandate(agent_id="a", counterparties={BANK: ["read"]}, issued_at=ISSUED, expires_at=EXPIRES)
    v = vrf(sign_mandate(m, ISSUER), {"action": "read", "merchant": BANK})
    assert v["decision"] == "allow"
    assert any(c["constraint"] == "has_scope" for c in v["matched"])


# --- time window ------------------------------------------------------------------------

def test_not_before_and_expiry_have_distinct_codes():
    s = sign_mandate(root(mandate_id="m", not_before=NOW + timedelta(hours=1)), ISSUER)
    early = vrf(s, READ_BANK)
    assert early["decision"] == "deny" and codes(early) == ["not_before"]
    assert "window opens at 2026-10-12T13:00:00Z" in early["rationale"]
    assert vrf(s, READ_BANK, now=NOW + timedelta(hours=1))["decision"] == "allow"
    late = vrf(s, READ_BANK, now=NOW + timedelta(days=8))
    assert codes(late) == ["not_expired"]


def test_malformed_not_before_denies():
    m = root(mandate_id="m")
    m["constraints"]["not_before"] = "30 June 2026"
    assert codes(vrf(sign_mandate(m, ISSUER), READ_BANK)) == ["not_before"]


# --- wire version -----------------------------------------------------------------------

def test_version_gates_the_new_keys():
    v0 = root(mandate_id="m", counterparties=None, merchants={"allow": [THAMES]})
    v0["version"] = "mandatekit/v0"
    assert vrf(sign_mandate(v0, ISSUER), PAY_THAMES)["decision"] == "allow"
    v0_new = root(mandate_id="m")
    v0_new["version"] = "mandatekit/v0"
    v = vrf(sign_mandate(v0_new, ISSUER), PAY_THAMES)
    assert codes(v) == ["constraints_enforceable"] and "need mandate version mandatekit/v0.2" in v["rationale"]
    v9 = root(mandate_id="m")
    v9["version"] = "mandatekit/v9"
    assert codes(vrf(sign_mandate(v9, ISSUER), PAY_THAMES)) == ["version"]


# --- usage limits -----------------------------------------------------------------------

def limited(limits, **over):
    kw = dict(agent_id="a", counterparties={"shop": ["read", "pay"]}, max_amount=gbp(15000), limits=limits,
              issued_at=ISSUED, expires_at=EXPIRES, mandate_id="lim")
    kw.update(over)
    return sign_mandate(build_mandate(**kw), ISSUER)


PAY_SHOP = {"action": "pay", "merchant": "shop", "amount": gbp(2500)}
READ_SHOP = {"action": "read", "merchant": "shop", "amount": gbp(0)}


def test_limits_require_a_store():
    s = limited({"actions": ["pay"], "max_uses": 1})
    v = vrf(s, PAY_SHOP)
    assert v["decision"] == "deny" and codes(v) == ["limits_store"]
    assert "no state store was supplied" in v["rationale"]


def test_max_uses_counts_only_the_filtered_verbs():
    s = limited({"actions": ["pay"], "max_uses": 1})
    store = InMemoryUsageStore()
    v = vrf(s, PAY_SHOP, store=store)
    assert v["decision"] == "allow"
    assert any(c["constraint"] == "limits" and "1 counted use" in c["detail"] for c in v["matched"])
    assert record_use(s, PAY_SHOP, store, now=NOW) == ["lim"]
    v = vrf(s, PAY_SHOP, store=store, now=NOW + timedelta(seconds=1))
    assert codes(v) == ["max_uses"] and "2 uses would exceed max_uses 1" in v["rationale"]
    assert vrf(s, READ_SHOP, store=store)["decision"] == "allow"
    assert store.uses("lim")[0] == {"at": NOW.timestamp(), "action": "pay", "amount": gbp(2500)}


def test_window_limits_slide():
    s = limited({"window_seconds": 3600, "max_uses_per_window": 2, "max_amount_per_window": gbp(20000)})
    store = InMemoryUsageStore()
    record_use(s, {"action": "pay", "merchant": "shop", "amount": gbp(15000)}, store, now=NOW - timedelta(seconds=3600))
    record_use(s, {"action": "pay", "merchant": "shop", "amount": gbp(15000)}, store, now=NOW - timedelta(seconds=10))
    assert vrf(s, {"action": "pay", "merchant": "shop", "amount": gbp(5000)}, store=store)["decision"] == "allow"
    v = vrf(s, {"action": "pay", "merchant": "shop", "amount": gbp(5001)}, store=store)
    assert codes(v) == ["max_amount_per_window"]
    record_use(s, READ_SHOP, store, now=NOW - timedelta(seconds=5))
    v = vrf(s, READ_SHOP, store=store)
    assert codes(v) == ["max_uses_per_window"] and "3 uses in 3600s" in v["rationale"]
    assert vrf(s, READ_SHOP, store=store, now=NOW + timedelta(seconds=3600))["decision"] == "allow"


def test_malformed_limits_deny_with_a_store():
    for bad in ({"max_uses": "1"}, {"max_uses_per_window": 1}, {"max_uses": 1, "per_day": 3}, {}, [], 3):
        m = build_mandate(agent_id="a", counterparties={"shop": ["pay"]}, max_amount=gbp(15000), issued_at=ISSUED, expires_at=EXPIRES)
        m["constraints"]["limits"] = bad
        v = vrf(sign_mandate(m, ISSUER), PAY_SHOP, store=InMemoryUsageStore())
        assert v["decision"] == "deny" and codes(v) == ["limits"], bad


def test_store_failures_are_denials_not_exceptions():
    s = limited({"max_uses": 5})

    class Broken:
        def uses(self, mandate_id):
            raise RuntimeError("db down")

        def record(self, mandate_id, use):
            pass

    v = vrf(s, PAY_SHOP, store=Broken())
    assert codes(v) == ["limits_store"] and "state store error: RuntimeError" in v["rationale"]
    store = InMemoryUsageStore()
    store.record("lim", {"at": "yesterday", "action": "pay", "amount": None})
    v = vrf(s, PAY_SHOP, store=store)
    assert codes(v) == ["limits_store"] and "malformed usage record" in v["rationale"]


def test_record_use_rejects_garbage_and_walks_the_chain():
    raises(ValueError, record_use, {"mandate": "x"}, PAY_SHOP, InMemoryUsageStore(), now=NOW)
    parent = sign_mandate(root(mandate_id="root", delegation={"max_depth": 1}, limits={"actions": ["pay"], "max_uses": 1}), ISSUER)
    child = sign_mandate(delegate_mandate(parent, agent_id="sub", limits=None, approval=None, actions=["read", "pay"],
                                          counterparties={THAMES: ["read", "pay"]}, mandate_id="child"), DELEGATE)
    store = InMemoryUsageStore()
    assert record_use(child, PAY_THAMES, store, now=NOW) == ["child", "root"]
    assert len(store.uses("root")) == 1 and len(store.uses("child")) == 1
    v = vrf(child, PAY_THAMES, store=store, now=NOW + timedelta(seconds=1))
    assert codes(v) == ["max_uses"]        # the parent's limit, enforced through the child


# --- revocation -----------------------------------------------------------------------------

def rlist(revoked, signer=ISSUER, issued_at=None, list_id="rl-1"):
    body = build_revocation_list(list_id=list_id, revoked=revoked, issued_at=issued_at or NOW - timedelta(minutes=5))
    return sign_revocation_list(body, signer)


def test_revocation_list_round_trip_and_signature():
    lst = rlist(["x"])
    assert lst["list"]["version"] == "mandatekit/revocation-list/v0.2"
    assert verify_revocation_list_signature(lst)
    bad = copy.deepcopy(lst)
    bad["list"]["revoked"] = []
    assert not verify_revocation_list_signature(bad)
    assert not verify_revocation_list_signature({"list": lst["list"]})
    raises(ValueError, build_revocation_list, list_id="", revoked=[])
    raises(ValueError, build_revocation_list, list_id="rl", revoked="m")


def test_revocation_paths():
    s = sign_mandate(root(mandate_id="m", revocation={"list_id": "rl-1", "max_age_seconds": 3600}), ISSUER)
    v = vrf(s, READ_BANK)
    assert codes(v) == ["revocation_list"] and "was not supplied" in v["rationale"]
    assert vrf(s, READ_BANK, revocation_lists=[rlist(["other"])])["decision"] == "allow"
    assert vrf(s, READ_BANK, revocation_lists=rlist(["other"]))["decision"] == "allow"   # a single list, not wrapped
    v = vrf(s, READ_BANK, revocation_lists=[rlist(["m"])])
    assert codes(v) == ["revoked"] and "mandate m is revoked in list 'rl-1'" in v["rationale"]
    assert codes(vrf(s, READ_BANK, revocation_lists=[rlist([], signer=STRANGER)])) == ["revocation_list"]
    stale = vrf(s, READ_BANK, revocation_lists=[rlist([], issued_at=NOW - timedelta(hours=2))])
    assert codes(stale) == ["revocation_list"] and "older than max_age_seconds 3600" in stale["rationale"]
    tampered = rlist(["m"])
    tampered["list"]["revoked"] = []
    assert codes(vrf(s, READ_BANK, revocation_lists=[tampered])) == ["revocation_list"]
    assert codes(vrf(s, READ_BANK, revocation_lists=[rlist([], list_id="rl-2")])) == ["revocation_list"]
    # A trusted key other than the issuer may revoke; an untrusted delegate may not.
    by_delegate = rlist(["m"], signer=DELEGATE)
    assert codes(vrf(s, READ_BANK, revocation_lists=[by_delegate], trusted_keys=[PUB, _b64(DPUB_RAW)])) == ["revoked"]
    assert codes(vrf(s, READ_BANK, revocation_lists=[by_delegate])) == ["revocation_list"]


# --- delegation ------------------------------------------------------------------------------

ROOT = sign_mandate(root(mandate_id="root-1", delegation={"max_depth": 1}), ISSUER)
PAY_40 = txn("pay", THAMES, "4900", 4000)


def child(parent=ROOT, signer=DELEGATE, **over):
    kw = dict(agent_id="sub-agent", counterparties={THAMES: ["read", "pay"]}, max_amount=gbp(5000),
              actions=["read", "pay"], approval=None, expires_at=NOW + timedelta(days=1), issued_at=ISSUED,
              mandate_id="child-1")
    kw.update(over)
    return sign_mandate(delegate_mandate(parent, **kw), signer)


def test_a_narrower_child_verifies_against_the_root_issuer():
    c = child()
    v = vrf(c, PAY_40)
    assert v["decision"] == "allow", v["rationale"]
    assert any(ch["constraint"] == "delegation" and "2 links roots in root-1" in ch["detail"] for ch in v["matched"])
    assert any(ch["constraint"] == "issuer_trusted" for ch in v["matched"])
    assert codes(vrf(c, txn("pay", THAMES, "4900", 6000))) == ["amount"]
    assert codes(vrf(c, PAY_40, trusted_keys=[_b64(_public_from_seed(STRANGER))])) == ["issuer_trusted"]
    assert verify(c, PAY_40, now=NOW)["decision"] == "deny"           # no trusted keys: fail closed


def test_delegate_mandate_inherits_unless_told_otherwise():
    m = delegate_mandate(ROOT, agent_id="sub", mandate_id="c")
    pc = ROOT["mandate"]["constraints"]
    for key in ("intent", "categories", "counterparties", "max_amount", "actions", "approval"):
        assert m["constraints"][key] == pc[key], key
    assert m["constraints"]["delegation"] == {"parent": ROOT}
    assert m["expires_at"] == ROOT["mandate"]["expires_at"]
    assert "revocation" not in m["constraints"]
    narrowed = delegate_mandate(ROOT, agent_id="sub", approval=None, max_amount=gbp(1), mandate_id="c")
    assert "approval" not in narrowed["constraints"] and narrowed["constraints"]["max_amount"] == gbp(1)
    raises(ValueError, delegate_mandate, ROOT, agent_id="sub", max_depth=1)     # needs a key to delegate further
    raises(ValueError, delegate_mandate, {"mandate": None}, agent_id="sub")


def test_widening_is_denied_with_the_field_named():
    read_thames = txn("read", THAMES, "4900", 0)
    cases = {
        "max_amount": (child(max_amount=gbp(20000)), read_thames),
        "actions: child adds [cancel]": (child(counterparties={THAMES: ["read", "cancel"]}, actions=["read", "cancel"]), read_thames),
        "counterparties: child adds 'MID-41120'": (child(counterparties={THAMES: ["read"], "MID-41120": ["pay"]}), read_thames),
        "counterparties: child adds [pay] at 'harbourline'": (child(counterparties={BANK: ["read", "pay"]}, actions=["read", "pay"]), READ_BANK),
        "expires_at": (child(expires_at=EXPIRES + timedelta(days=1)), read_thames),
        "categories: child adds [5411]": (child(categories=["bank", "4900", "5411"]), read_thames),
        "approval: parent asks before 'submit'": (child(counterparties={BANK: ["submit"]}, actions=["submit"]), txn("submit", BANK, "bank", 0)),
    }
    for needle, (c, t) in cases.items():
        v = vrf(c, t)
        assert v["decision"] == "deny" and codes(v) == ["delegation_scope", "issuer_trusted"], (needle, codes(v))
        assert needle in v["rationale"], (needle, v["rationale"])


def test_window_narrowing():
    wroot = sign_mandate(root(mandate_id="root-w", delegation={"max_depth": 1}, not_before=NOW - timedelta(hours=1)), ISSUER)
    assert codes(vrf(child(parent=wroot, not_before=None), PAY_40)) == ["delegation_scope", "issuer_trusted"]
    assert codes(vrf(child(parent=wroot, not_before=NOW - timedelta(hours=2)), PAY_40)) == ["delegation_scope", "issuer_trusted"]
    inside = child(parent=wroot, not_before=NOW - timedelta(minutes=30))
    assert vrf(inside, PAY_40)["decision"] == "allow"
    assert codes(vrf(inside, PAY_40, now=NOW - timedelta(minutes=45))) == ["not_before"]


def test_chain_structure_failures():
    assert codes(vrf(child(signer=STRANGER), PAY_40)) == ["delegation", "issuer_trusted"]
    assert codes(vrf(child(signer=ISSUER), PAY_40)) == ["delegation", "issuer_trusted"]
    no_opt_in = sign_mandate(root(mandate_id="root-plain"), ISSUER)
    v = vrf(child(parent=no_opt_in), PAY_40)
    assert codes(v) == ["delegation", "issuer_trusted"] and "does not allow delegation" in v["rationale"]
    nokey = root(mandate_id="root-nokey", delegation={"max_depth": 1})
    del nokey["subject"]["public_key"]
    v = vrf(child(parent=sign_mandate(nokey, ISSUER)), PAY_40)
    assert "no subject.public_key" in v["rationale"]
    too_deep = sign_mandate(delegate_mandate(ROOT, agent_id="s", agent_public_key=DPUB_RAW, max_depth=1, approval=None,
                                             actions=["read"], counterparties={THAMES: ["read"]}, mandate_id="deep"), DELEGATE)
    v = vrf(too_deep, txn("read", THAMES, "4900", 0))
    assert codes(v) == ["delegation_scope", "issuer_trusted"] and "exceeds the parent's remaining depth 0" in v["rationale"]
    grandchild = sign_mandate(delegate_mandate(child(), agent_id="g", mandate_id="g"), DELEGATE)
    assert codes(vrf(grandchild, PAY_40)) == ["delegation", "issuer_trusted"]
    garbage = root(mandate_id="g")
    garbage["constraints"]["delegation"] = {"parent": {"mandate": "nope"}}
    assert codes(vrf(sign_mandate(garbage, DELEGATE), PAY_THAMES)) == ["delegation", "issuer_trusted"]


def test_tampering_anywhere_in_the_chain_breaks_the_leaf_signature():
    c = child()
    edited_parent = copy.deepcopy(c)
    edited_parent["mandate"]["constraints"]["delegation"]["parent"]["mandate"]["constraints"]["max_amount"]["value"] = 999999
    v = vrf(edited_parent, PAY_40)
    assert v["decision"] == "deny" and v["signature_valid"] is False
    edited_child = copy.deepcopy(c)
    edited_child["mandate"]["constraints"]["max_amount"]["value"] = 999999
    assert vrf(edited_child, PAY_40)["signature_valid"] is False


def test_three_links():
    root2 = sign_mandate(root(mandate_id="root-2", delegation={"max_depth": 2}), ISSUER)
    gk = bytes(range(64, 96))
    mid = sign_mandate(delegate_mandate(root2, agent_id="mid", agent_public_key=_public_from_seed(gk), max_depth=1,
                                        counterparties={THAMES: ["read", "pay"]}, max_amount=gbp(5000),
                                        actions=["read", "pay"], approval=None, mandate_id="mid"), DELEGATE)
    leaf = sign_mandate(delegate_mandate(mid, agent_id="leaf", counterparties={THAMES: ["read"]}, actions=["read"],
                                         max_amount=gbp(0), mandate_id="leaf"), gk)
    v = vrf(leaf, txn("read", THAMES, "4900", 0))
    assert v["decision"] == "allow", v["rationale"]
    assert any("3 links roots in root-2" in ch["detail"] for ch in v["matched"])
    assert record_use(leaf, txn("read", THAMES, "4900", 0), InMemoryUsageStore(), now=NOW) == ["leaf", "mid", "root-2"]


def test_revoked_parent_takes_the_children_with_it():
    rroot = sign_mandate(root(mandate_id="root-rev", delegation={"max_depth": 1}, revocation={"list_id": "rl-root"}), ISSUER)
    c = child(parent=rroot)
    assert codes(vrf(c, PAY_40)) == ["revocation_list"]
    assert codes(vrf(c, PAY_40, revocation_lists=[rlist(["root-rev"], list_id="rl-root")])) == ["revoked"]
    assert vrf(c, PAY_40, revocation_lists=[rlist([], list_id="rl-root")])["decision"] == "allow"


# --- cross-walk ---------------------------------------------------------------------------------

def test_crosswalk_carries_the_new_fields():
    m = root(mandate_id="m", not_before=NOW, limits={"max_uses": 3}, revocation={"list_id": "rl-1"}, delegation={"max_depth": 1})
    (d,) = to_authorization_details(m)
    assert d["type"] == "mandatekit:mandate:v0.2"
    assert d["valid_from"] == "2026-10-12T12:00:00Z" and d["valid_until"] == m["expires_at"]
    assert d["locations"] == ["MID-10231", "harbourline"]                 # sorted counterparty ids
    assert d["counterparties"] == SCOPE and d["limits"] == {"max_uses": 3}
    assert d["revocation"] == {"list_id": "rl-1"} and d["delegation"] == {"max_depth": 1}
    assert d["subject"] == {"agent_id": "agent-tidy", "public_key": _b64(DPUB_RAW)}
    d["counterparties"][BANK].append("pay")
    assert m["constraints"]["counterparties"][BANK] == ["read", "submit", "transfer"]
    c = delegate_mandate(ROOT, agent_id="sub", mandate_id="c")
    (dc,) = to_authorization_details(c)
    assert dc["delegation"] == {"parent": "root-1"}
    plain = build_mandate(agent_id="a", max_amount=gbp(1), issued_at=ISSUED, expires_at=EXPIRES)
    (dp,) = to_authorization_details(plain)
    assert dp["valid_from"] == plain["issued_at"] and "locations" not in dp


# --- robustness -----------------------------------------------------------------------------------

def test_hostile_new_fields_never_raise():
    base = root(mandate_id="m")
    store = InMemoryUsageStore()
    hostile = [
        {"counterparties": None}, {"counterparties": {BANK: None}}, {"counterparties": {BANK: [1, {}]}},
        {"not_before": 12}, {"not_before": None}, {"limits": None}, {"limits": {"window_seconds": -1, "max_uses_per_window": 1}},
        {"limits": {"max_uses": True}}, {"revocation": None}, {"revocation": {"list_id": "x", "max_age_seconds": "1"}},
        {"delegation": None}, {"delegation": {"parent": None}}, {"delegation": {"parent": {"mandate": {"constraints": []}}}},
        {"delegation": {"max_depth": "1"}}, {"delegation": []},
    ]
    for extra in hostile:
        m = copy.deepcopy(base)
        m["constraints"].update(extra)
        for signed in (sign_mandate(m, ISSUER), {"mandate": m, "signature": {"alg": "Ed25519", "public_key": PUB, "value": "AA=="}}):
            v = verify(signed, PAY_THAMES, now=NOW, trusted_keys=[PUB], store=store,
                       revocation_lists=[{"list": extra}, 42, None, {"list": {"list_id": "x"}}])
            assert v["decision"] == "deny", extra


# --- cross-language fixture -------------------------------------------------------------------------

def test_cross_language_fixture():
    with open(FIXTURE) as fh:
        fixture = json.load(fh)
    seeds = {k: bytes.fromhex(v) for k, v in fixture["seeds"].items()}
    keys = fixture["keys"]
    assert fixture["cases"], "fixture has no cases"
    default_now = datetime.fromisoformat(fixture["now"].replace("Z", "+00:00"))
    verdicts = 0
    emitted = set()
    for c in fixture["cases"]:
        store = InMemoryUsageStore() if c["store"] else None
        trusted = [keys[k] for k in c["trusted"]] or None
        lists = [l["envelope"] for l in c["revocation_lists"]]
        # The envelopes in the file were signed by this SDK; re-signing must reproduce the bytes.
        if c["signer"] is not None:
            again = sign_mandate(c["mandate"]["mandate"], seeds[c["signer"]])
            assert again["signature"] == c["mandate"]["signature"], c["name"]
        for l in c["revocation_lists"]:
            if l["signer"] is not None:
                assert sign_revocation_list(l["envelope"]["list"], seeds[l["signer"]])["signature"] == l["envelope"]["signature"]
        for i, step in enumerate(c["steps"]):
            where = f"{c['name']} / step {i}"
            now = datetime.fromisoformat(step["now"].replace("Z", "+00:00")) if "now" in step else default_now
            if step["op"] == "record":
                record_use(c["mandate"], step["transaction"], store, now=now)
            elif step["op"] == "record_raw":
                store.record(step["mandate_id"], step["use"])
            elif step["op"] == "verify":
                v = verify(c["mandate"], step["transaction"], now=now, trusted_keys=trusted, store=store, revocation_lists=lists)
                exp = step["expect"]
                assert v["decision"] == exp["decision"], f"{where}: {v['decision']} != {exp['decision']}: {v['rationale']}"
                assert codes(v) == exp["failed"], f"{where}: {codes(v)} != {exp['failed']}: {v['rationale']}"
                if "signature_valid" in exp:
                    assert v["signature_valid"] == exp["signature_valid"], where
                emitted.update(ch["constraint"] for ch in v["matched"] + v["failed"])
                verdicts += 1
            else:
                raise AssertionError(f"{where}: unknown op {step['op']!r}")
    assert verdicts >= 100, f"only {verdicts} fixture verdicts ran"
    assert emitted <= set(REASON_CODES), emitted - set(REASON_CODES)


# --- standalone runner ------------------------------------------------------------------------------

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
