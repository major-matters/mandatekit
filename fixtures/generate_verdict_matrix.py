"""
Generate fixtures/verdict-matrix.json, the 0.2 verdict matrix both test suites
replay (python/tests/test_v02.py and typescript/test/v02.test.ts).

Every expectation below is written by hand, then checked against the Python
verifier before the file is written, so the fixture is a matrix of intended
behavior, not a snapshot of whatever the code did. The TypeScript suite verifies
the Python-signed envelopes (cross-language verification of every new field)
and re-signs each one with the same seed to prove the signatures are
byte-identical.

Run from the repository root:

    PYTHONPATH=python python3 fixtures/generate_verdict_matrix.py

Deterministic: fixed seeds, fixed clock, fixed mandate ids. Nothing here is a
real key.
"""

import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from mandatekit import (
    InMemoryUsageStore,
    build_mandate,
    build_revocation_list,
    delegate_mandate,
    record_use,
    sign_mandate,
    sign_revocation_list,
    verify,
    verify_revocation_list_signature,
    verify_signature,
)
from mandatekit.mandate import iso
from mandatekit.signing import _b64, _public_from_seed

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verdict-matrix.json")

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
ISSUED = NOW - timedelta(days=1)
EXPIRES = NOW + timedelta(days=7)

SEEDS = {
    "issuer": bytes(range(32)),
    "delegate": bytes(range(32, 64)),
    "grandchild": bytes(range(64, 96)),
    "stranger": bytes(99 - i for i in range(32)),
}
KEYS = {name: _b64(_public_from_seed(seed)) for name, seed in SEEDS.items()}
PUB = {name: _public_from_seed(seed) for name, seed in SEEDS.items()}


def gbp(value):
    return {"value": value, "currency": "GBP"}


def txn(action, merchant, category, value, currency="GBP"):
    t = {"merchant": merchant, "category": category, "amount": {"value": value, "currency": currency}}
    if action is not None:
        t["action"] = action
    return t


THAMES, BANK, GREENCART = "MID-10231", "harbourline", "MID-41120"
PAY_THAMES = txn("pay", THAMES, "4900", 11840)
PAY_BANK = txn("pay", BANK, "bank", 8400)          # the slip in Bench entries two and three
READ_BANK = txn("read", BANK, "bank", 0)
SUBMIT_BANK = txn("submit", BANK, "bank", 0)

SCOPE = {BANK: ["read", "submit", "transfer"], THAMES: ["read", "draft", "pay"]}
ACTIONS = ["read", "draft", "submit", "pay", "transfer"]


def root(**over):
    kw = dict(
        agent_id="agent-tidy", agent_public_key=PUB["delegate"], intent="pay the energy bill",
        categories=["bank", "4900"], counterparties=SCOPE, max_amount=gbp(15000), actions=ACTIONS,
        approval={"actions": ["submit"]}, issued_at=ISSUED, expires_at=EXPIRES,
    )
    kw.update(over)
    return build_mandate(**kw)


def signed(mandate, signer="issuer"):
    return sign_mandate(mandate, SEEDS[signer])


def rlist(list_id, revoked, signer="issuer", issued_at=None):
    body = build_revocation_list(list_id=list_id, revoked=revoked, issued_at=issued_at or NOW - timedelta(minutes=5))
    return {"signer": signer, "envelope": sign_revocation_list(body, SEEDS[signer])}


def signer_of(envelope, verifier) -> "str | None":
    """Name of the test seed whose key signed `envelope`, or None when the
    envelope does not verify (tampered) or the key is not one of ours. The
    suites re-sign every named envelope with that seed and expect the same
    bytes, so the label has to be derived, never typed by hand."""
    if not verifier(envelope):
        return None
    key = envelope["signature"]["public_key"]
    return next((name for name, k in KEYS.items() if k == key), None)


# --- step builders -------------------------------------------------------------

def V(transaction, decision, failed, now=None, signature_valid=None, note=None):
    step = {"op": "verify", "transaction": transaction,
            "expect": {"decision": decision, "failed": sorted(failed)}}
    if now is not None:
        step["now"] = iso(now)
    if signature_valid is not None:
        step["expect"]["signature_valid"] = signature_valid
    if note:
        step["note"] = note
    return step


def R(transaction, now=None):
    step = {"op": "record", "transaction": transaction}
    if now is not None:
        step["now"] = iso(now)
    return step


def RAW(mandate_id, use):
    return {"op": "record_raw", "mandate_id": mandate_id, "use": use}


CASES = []


def case(name, envelope, steps, *, trusted=("issuer",), store=False, lists=()):
    CASES.append({
        "name": name,
        "signer": signer_of(envelope, verify_signature),
        "mandate": envelope,
        "trusted": list(trusted),
        "store": store,
        "revocation_lists": [
            {"signer": signer_of(l["envelope"], verify_revocation_list_signature), "envelope": l["envelope"]}
            for l in lists
        ],
        "steps": steps,
    })


# --- A. per-verb counterparty scope -----------------------------------------------

scoped = signed(root(mandate_id="m-scoped"))
case("per-verb scope: the bank is a counterparty for read, submit and transfer, never a payee", scoped, [
    V(PAY_THAMES, "allow", []),
    V(PAY_BANK, "deny", ["counterparty_scope"], note="the slip from Bench entries two and three"),
    V(txn("transfer", BANK, "bank", 8400), "allow", []),
    V(SUBMIT_BANK, "ask", ["approval"]),
    V(READ_BANK, "allow", []),
    V(txn("pay", GREENCART, "5411", 1000), "deny", ["category", "counterparty_scope"]),
    V(txn(None, THAMES, "4900", 11840), "deny", ["action", "counterparty_scope"], note="no verb at all"),
    V(txn("transfer", THAMES, "4900", 100), "deny", ["counterparty_scope"]),
    V(txn("PAY", THAMES, "4900", 100), "allow", [], note="verbs compare case-insensitively"),
])

flat = signed(root(mandate_id="m-flat", counterparties=None, merchants={"allow": [BANK, THAMES]}))
case("0.1 flat allow list still works and means every allowed verb (why the slip happened)", flat, [
    V(PAY_BANK, "allow", []),
    V(PAY_THAMES, "allow", []),
    V(txn("pay", GREENCART, "5411", 1000), "deny", ["category", "merchant_allow"]),
])

both = signed(root(mandate_id="m-both", merchants={"allow": [THAMES]}, counterparties={BANK: ["read"], THAMES: ["pay"]}))
case("flat list and per-verb scope together: both must pass", both, [
    V(txn("read", BANK, "bank", 0), "deny", ["merchant_allow"]),
    V(txn("pay", THAMES, "4900", 100), "allow", []),
    V(txn("read", THAMES, "4900", 0), "deny", ["counterparty_scope"]),
])

empty_verbs = signed(root(mandate_id="m-empty-verbs", counterparties={BANK: []}))
case("an empty verb list allows nothing at that counterparty", empty_verbs, [
    V(READ_BANK, "deny", ["counterparty_scope"]),
])

bad_cps = root(mandate_id="m-bad-cps")
bad_cps["constraints"]["counterparties"] = [BANK, THAMES]
case("malformed counterparties (a list) is a deny, never an exception", signed(bad_cps), [
    V(READ_BANK, "deny", ["counterparty_scope"]),
])

# --- B. time window ----------------------------------------------------------------

window = signed(root(mandate_id="m-window", not_before=NOW + timedelta(hours=1)))
case("not_before: denied before the window opens, allowed inside, denied after expiry", window, [
    V(READ_BANK, "deny", ["not_before"], now=NOW),
    V(READ_BANK, "allow", [], now=NOW + timedelta(hours=1), note="the boundary instant is inside"),
    V(READ_BANK, "allow", [], now=NOW + timedelta(hours=2)),
    V(READ_BANK, "deny", ["not_expired"], now=NOW + timedelta(days=8)),
])

bad_nb = root(mandate_id="m-bad-nb")
bad_nb["constraints"]["not_before"] = "next tuesday"
case("a non-ISO not_before is a deny", signed(bad_nb), [
    V(READ_BANK, "deny", ["not_before"]),
])

never = signed(root(mandate_id="m-never", not_before=NOW + timedelta(days=30)))
case("a window that never opens denies on both edges", never, [
    V(READ_BANK, "deny", ["not_before"], now=NOW),
    V(READ_BANK, "deny", ["not_before", "not_expired"], now=NOW + timedelta(days=8)),
])

# --- C. wire version ------------------------------------------------------------------

v0_plain = root(mandate_id="m-v0", counterparties=None, merchants={"allow": [BANK, THAMES]})
v0_plain["version"] = "mandatekit/v0"
case("a mandatekit/v0 mandate with v0 keys verifies", signed(v0_plain), [
    V(PAY_THAMES, "allow", []),
])

v0_new_keys = root(mandate_id="m-v0-newkeys")
v0_new_keys["version"] = "mandatekit/v0"
case("a mandatekit/v0 mandate carrying 0.2 keys is unenforceable under its version", signed(v0_new_keys), [
    V(PAY_THAMES, "deny", ["constraints_enforceable"]),
])

v9 = root(mandate_id="m-v9")
v9["version"] = "mandatekit/v9"
case("an unknown wire version is denied", signed(v9), [
    V(PAY_THAMES, "deny", ["version"]),
])

noversion = root(mandate_id="m-noversion")
del noversion["version"]
case("a missing wire version is denied", signed(noversion), [
    V(PAY_THAMES, "deny", ["version"]),
])

# --- D. usage limits ------------------------------------------------------------------

LIM_SCOPE = {"shop": ["read", "pay"]}
PAY_SHOP = txn("pay", "shop", "5411", 2500)
READ_SHOP = txn("read", "shop", "5411", 0)


def limited(mandate_id, limits, **over):
    kw = dict(agent_id="agent-shop", counterparties=LIM_SCOPE, categories=["5411"], max_amount=gbp(15000),
              limits=limits, issued_at=ISSUED, expires_at=EXPIRES, mandate_id=mandate_id)
    kw.update(over)
    return signed(build_mandate(**kw))


uses1 = limited("m-uses", {"actions": ["pay"], "max_uses": 1})
case("limits declared but no store supplied: deny", uses1, [
    V(PAY_SHOP, "deny", ["limits_store"]),
    V(READ_SHOP, "deny", ["limits_store"], note="even for a verb the limit does not count"),
], store=False)

case("max_uses: one pay per mandate; reads do not count", uses1, [
    V(PAY_SHOP, "allow", []),
    R(PAY_SHOP),
    V(PAY_SHOP, "deny", ["max_uses"], now=NOW + timedelta(seconds=10), note="the second in-cap payment (entry three's warranty)"),
    V(READ_SHOP, "allow", [], now=NOW + timedelta(seconds=10)),
    R(READ_SHOP, now=NOW + timedelta(seconds=10)),
    V(PAY_SHOP, "deny", ["max_uses"], now=NOW + timedelta(days=1)),
], store=True)

win_uses = limited("m-win-uses", {"window_seconds": 3600, "max_uses_per_window": 2})
case("max_uses_per_window: a use counts while it is less than window_seconds old", win_uses, [
    R(READ_SHOP, now=NOW - timedelta(seconds=3600)),
    R(READ_SHOP, now=NOW - timedelta(seconds=3000)),
    V(READ_SHOP, "allow", [], now=NOW, note="the use at exactly 3600s has aged out"),
    R(READ_SHOP, now=NOW - timedelta(seconds=100)),
    V(READ_SHOP, "deny", ["max_uses_per_window"], now=NOW),
    V(READ_SHOP, "allow", [], now=NOW + timedelta(seconds=700)),
], store=True)

win_amount = limited("m-win-amount", {"window_seconds": 3600, "max_amount_per_window": gbp(20000)})
case("max_amount_per_window: cumulative amount in the window, boundary inclusive", win_amount, [
    R(txn("pay", "shop", "5411", 15000), now=NOW - timedelta(seconds=60)),
    V(txn("pay", "shop", "5411", 5000), "allow", [], now=NOW),
    V(txn("pay", "shop", "5411", 5001), "deny", ["max_amount_per_window"], now=NOW),
    V(txn("pay", "shop", "5411", 15000), "allow", [], now=NOW + timedelta(seconds=3540), note="the recorded pay is 3600s old"),
    V({"action": "pay", "merchant": "shop", "category": "5411"}, "deny", ["amount", "max_amount_per_window"], now=NOW, note="no amount"),
    V(txn("pay", "shop", "5411", 100, "USD"), "deny", ["amount", "max_amount_per_window"], now=NOW, note="currency mismatch"),
    V(READ_SHOP, "allow", [], now=NOW, note="a zero-amount read adds nothing"),
], store=True)

total = limited("m-total", {"max_total_amount": gbp(20000)})
case("max_total_amount: cumulative over the mandate's life", total, [
    R(txn("pay", "shop", "5411", 15000), now=NOW - timedelta(days=1)),
    V(txn("pay", "shop", "5411", 5000), "allow", []),
    V(txn("pay", "shop", "5411", 5001), "deny", ["max_total_amount"]),
], store=True)

bad_lim = build_mandate(agent_id="agent-shop", counterparties=LIM_SCOPE, max_amount=gbp(15000),
                        issued_at=ISSUED, expires_at=EXPIRES, mandate_id="m-bad-limits")
bad_lim["constraints"]["limits"] = {"max_uses": "3"}
case("malformed limits (a string count) is a deny even with a store", signed(bad_lim), [
    V(PAY_SHOP, "deny", ["limits"]),
], store=True)

no_window = copy.deepcopy(bad_lim)
no_window["mandate_id"] = "m-no-window"
no_window["constraints"]["limits"] = {"max_uses_per_window": 1}
case("a per-window limit without window_seconds is malformed", signed(no_window), [
    V(PAY_SHOP, "deny", ["limits"]),
], store=True)

unknown_lim = copy.deepcopy(bad_lim)
unknown_lim["mandate_id"] = "m-unknown-limit"
unknown_lim["constraints"]["limits"] = {"max_uses": 1, "per_day": 3}
case("an unknown key inside limits is malformed (fail closed)", signed(unknown_lim), [
    V(PAY_SHOP, "deny", ["limits"]),
], store=True)

case("a malformed record in the store is a deny", uses1, [
    RAW("m-uses", {"at": "yesterday", "action": "pay", "amount": None}),
    V(PAY_SHOP, "deny", ["limits_store"]),
], store=True)

# --- E. revocation ----------------------------------------------------------------------

revocable = signed(root(mandate_id="m-revocable", revocation={"list_id": "rl-alex"}))
clean = rlist("rl-alex", ["someone-else"])
revoked = rlist("rl-alex", ["m-revocable", "someone-else"])
forged = rlist("rl-alex", [], signer="stranger")
tampered_list = copy.deepcopy(revoked)
tampered_list["signer"] = None
tampered_list["envelope"]["list"]["revoked"] = ["someone-else"]
other_id = rlist("rl-other", [])
malformed_list = copy.deepcopy(clean)
malformed_list["signer"] = None
malformed_list["envelope"]["list"]["revoked"] = "m-revocable"

case("revocation: a declared list that is not supplied is a deny", revocable, [V(READ_BANK, "deny", ["revocation_list"])])
case("revocation: a clean issuer-signed list allows", revocable, [V(READ_BANK, "allow", [])], lists=[clean])
case("revocation: the mandate's id on the list is a deny", revocable, [V(READ_BANK, "deny", ["revoked"])], lists=[revoked])
case("revocation: a list signed by a stranger is unavailable", revocable, [V(READ_BANK, "deny", ["revocation_list"])], lists=[forged])
case("revocation: a list edited after signing is unavailable", revocable, [V(READ_BANK, "deny", ["revocation_list"])], lists=[tampered_list])
case("revocation: a list with another id does not satisfy the declaration", revocable, [V(READ_BANK, "deny", ["revocation_list"])], lists=[other_id])
case("revocation: a malformed list body is unavailable", revocable, [V(READ_BANK, "deny", ["revocation_list"])], lists=[malformed_list])
case("revocation: any valid copy that lists the mandate wins", revocable, [V(READ_BANK, "deny", ["revoked"])], lists=[clean, revoked])
case("revocation: a pinned trusted key other than the issuer may also revoke", revocable,
     [V(READ_BANK, "deny", ["revoked"])], trusted=("issuer", "delegate"),
     lists=[rlist("rl-alex", ["m-revocable"], signer="delegate")])
case("revocation: the delegate's list is not accepted when the delegate is not trusted", revocable,
     [V(READ_BANK, "deny", ["revocation_list"])], lists=[rlist("rl-alex", ["m-revocable"], signer="delegate")])

fresh = signed(root(mandate_id="m-fresh", revocation={"list_id": "rl-alex", "max_age_seconds": 3600}))
case("revocation with max_age_seconds: a stale list is unavailable, a fresh one allows", fresh, [
    V(READ_BANK, "allow", []),
], lists=[clean])
case("revocation with max_age_seconds: stale", fresh, [
    V(READ_BANK, "deny", ["revocation_list"]),
], lists=[rlist("rl-alex", [], issued_at=NOW - timedelta(hours=2))])

bad_rev = root(mandate_id="m-bad-rev")
bad_rev["constraints"]["revocation"] = {"list_id": ""}
case("a malformed revocation declaration is a deny", signed(bad_rev), [V(READ_BANK, "deny", ["revocation_list"])], lists=[clean])

# --- F. delegation ----------------------------------------------------------------------

ROOT = signed(root(mandate_id="root-1", delegation={"max_depth": 1}))
CHILD_SCOPE = {THAMES: ["read", "pay"]}
PAY_40 = txn("pay", THAMES, "4900", 4000)


def child(parent, mandate_id, signer="delegate", **over):
    kw = dict(agent_id="sub-agent", counterparties=CHILD_SCOPE, max_amount=gbp(5000), actions=["read", "pay"],
              approval=None, expires_at=NOW + timedelta(days=1), issued_at=ISSUED, mandate_id=mandate_id)
    kw.update(over)
    return signed(delegate_mandate(parent, **kw), signer)


narrow = child(ROOT, "child-1")
case("delegation: a narrower child signed by the delegate verifies against the root issuer", narrow, [
    V(PAY_40, "allow", []),
    V(txn("pay", THAMES, "4900", 6000), "deny", ["amount"], note="the child's own cap"),
    V(READ_BANK, "deny", ["counterparty_scope"], note="the bank is outside the child's scope (categories were inherited)"),
    V(txn("submit", THAMES, "4900", 0), "deny", ["action", "counterparty_scope"], note="submit is not reachable, so dropping the approval rule was fine"),
])
case("delegation: the chain roots in an untrusted key", narrow, [
    V(PAY_40, "deny", ["issuer_trusted"]),
], trusted=("stranger",))
case("delegation: no trusted keys at all fails closed", narrow, [
    V(PAY_40, "deny", []),
], trusted=())

keep_all = signed(delegate_mandate(ROOT, agent_id="sub-agent", mandate_id="child-keep"), "delegate")
case("delegation: a child that inherits everything is equal scope, which narrows", keep_all, [
    V(READ_BANK, "allow", []),
    V(SUBMIT_BANK, "ask", ["approval"], note="the inherited approval rule still asks"),
    V(PAY_BANK, "deny", ["counterparty_scope"]),
])

case("delegation_scope: a child cap above the parent's", child(ROOT, "child-cap", max_amount=gbp(20000)), [
    V(PAY_40, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child with no cap under a capped parent",
     signed(delegate_mandate(ROOT, agent_id="sub-agent", max_amount=None, approval=None, actions=["read"],
                             counterparties={THAMES: ["read"]}, mandate_id="child-nocap"), "delegate"), [
    V(txn("read", THAMES, "4900", 0), "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child adds a verb the parent never allowed",
     child(ROOT, "child-verb", counterparties={THAMES: ["read", "cancel"]}, actions=["read", "cancel"]), [
    V(txn("read", THAMES, "4900", 0), "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child allows a verb at a counterparty the parent scoped more tightly",
     child(ROOT, "child-bank-pay", counterparties={BANK: ["read", "pay"]}, actions=["read", "pay"]), [
    V(READ_BANK, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child adds a counterparty",
     child(ROOT, "child-cp", counterparties={THAMES: ["read"], GREENCART: ["pay"]}), [
    V(txn("read", THAMES, "4900", 0), "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child that replaces the per-verb map with a flat list widens it",
     child(ROOT, "child-flat", counterparties=None, merchants={"allow": [BANK]}, actions=["read", "pay"]), [
    V(READ_BANK, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child expiring after its parent",
     child(ROOT, "child-late", expires_at=EXPIRES + timedelta(days=1)), [
    V(PAY_40, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child adds a category",
     child(ROOT, "child-cat", categories=["bank", "4900", "5411"]), [
    V(PAY_40, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child drops an approval rule for a verb it can still reach",
     child(ROOT, "child-drop-approval", counterparties={BANK: ["submit"]}, actions=["submit"], approval=None), [
    V(SUBMIT_BANK, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation_scope: a child declares a depth the parent has not got",
     signed(delegate_mandate(ROOT, agent_id="sub-agent", agent_public_key=PUB["grandchild"], max_depth=1,
                             approval=None, actions=["read"], counterparties={THAMES: ["read"]}, mandate_id="child-deep"), "delegate"), [
    V(txn("read", THAMES, "4900", 0), "deny", ["delegation_scope", "issuer_trusted"]),
])

windowed_root = signed(root(mandate_id="root-window", delegation={"max_depth": 1}, not_before=NOW - timedelta(hours=1)))
case("delegation_scope: a child without not_before under a parent that has one",
     child(windowed_root, "child-no-nb", not_before=None), [
    V(PAY_40, "deny", ["delegation_scope", "issuer_trusted"]),
])
case("delegation: a child whose window sits inside the parent's",
     child(windowed_root, "child-nb", not_before=NOW - timedelta(minutes=30)), [
    V(PAY_40, "allow", []),
    V(PAY_40, "deny", ["not_before"], now=NOW - timedelta(minutes=45), note="the child's own window start"),
])

case("delegation: a child signed by a key other than the parent's subject key",
     child(ROOT, "child-stranger", signer="stranger"), [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"]),
])
case("delegation: the child signed by the issuer itself is not the delegate either",
     child(ROOT, "child-issuer", signer="issuer"), [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"]),
])
nodeleg_root = signed(root(mandate_id="root-nodeleg"))
case("delegation: a parent that never opted in", child(nodeleg_root, "child-nodeleg"), [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"]),
])
nokey_root = root(mandate_id="root-nokey", delegation={"max_depth": 1})
del nokey_root["subject"]["public_key"]
case("delegation: a parent with no subject key cannot have delegates", child(signed(nokey_root), "child-nokey"), [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"]),
])
grand_under_1 = signed(delegate_mandate(narrow, agent_id="grand", mandate_id="grand-under-1"), "grandchild")
case("delegation: a grandchild under a child that may not delegate", grand_under_1, [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"]),
])
garbage_parent = root(mandate_id="child-garbage")
garbage_parent["constraints"]["delegation"] = {"parent": {"mandate": "nope"}}
case("delegation: a garbage parent envelope", signed(garbage_parent, "delegate"), [
    V(PAY_THAMES, "deny", ["delegation", "issuer_trusted"]),
])
extra_key = delegate_mandate(ROOT, agent_id="sub-agent", mandate_id="child-extra")
extra_key["constraints"]["delegation"]["extra"] = True
case("delegation: an unknown key inside the child's delegation object", signed(extra_key, "delegate"), [
    V(READ_BANK, "deny", ["delegation", "issuer_trusted"]),
])
bad_root_deleg = root(mandate_id="root-bad-deleg")
bad_root_deleg["constraints"]["delegation"] = {"max_depth": -1}
case("delegation: a malformed delegation object on a root", signed(bad_root_deleg), [
    V(PAY_THAMES, "deny", ["delegation"]),
])

tampered_child = copy.deepcopy(narrow)
tampered_child["mandate"]["constraints"]["max_amount"]["value"] = 999999
case("delegation: a child edited after signing fails its signature", tampered_child, [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"], signature_valid=False),
])
tampered_parent = copy.deepcopy(narrow)
tampered_parent["mandate"]["constraints"]["delegation"]["parent"]["mandate"]["constraints"]["max_amount"]["value"] = 999999
case("delegation: the embedded parent edited after signing breaks the child's signature too", tampered_parent, [
    V(PAY_40, "deny", ["delegation", "issuer_trusted"], signature_valid=False),
])

# A revoked parent takes its children with it.
rev_root = signed(root(mandate_id="root-rev", delegation={"max_depth": 1}, revocation={"list_id": "rl-root"}))
rev_child = child(rev_root, "child-of-rev")
case("delegation: a revoked parent takes its children with it", rev_child, [
    V(PAY_40, "deny", ["revoked"]),
], lists=[rlist("rl-root", ["root-rev"])])
case("delegation: the parent's clean list, and no list at all", rev_child, [
    V(PAY_40, "allow", []),
], lists=[rlist("rl-root", [])])
case("delegation: the parent's declared list missing denies the child", rev_child, [
    V(PAY_40, "deny", ["revocation_list"]),
])

# A parent's limits bind every child.
lim_root = signed(root(mandate_id="root-lim", delegation={"max_depth": 1}, limits={"actions": ["pay"], "max_uses": 1}))
lim_child = child(lim_root, "child-of-lim", limits=None)
case("delegation: a parent's max_uses counts the children's uses", lim_child, [
    V(PAY_40, "allow", []),
    R(PAY_40),
    V(PAY_40, "deny", ["max_uses"], now=NOW + timedelta(seconds=5), note="the root link's limit, the child has none of its own"),
    V(txn("read", THAMES, "4900", 0), "allow", [], now=NOW + timedelta(seconds=5)),
], store=True)
case("delegation: limits anywhere in the chain need a store", lim_child, [
    V(PAY_40, "deny", ["limits_store"]),
], store=False)

# Three links.
ROOT2 = signed(root(mandate_id="root-2", delegation={"max_depth": 2}))
mid = signed(delegate_mandate(ROOT2, agent_id="mid-agent", agent_public_key=PUB["grandchild"], max_depth=1,
                              counterparties={THAMES: ["read", "pay"]}, max_amount=gbp(5000), actions=["read", "pay"],
                              approval=None, mandate_id="mid-1"), "delegate")
leaf = signed(delegate_mandate(mid, agent_id="leaf-agent", counterparties={THAMES: ["read"]}, actions=["read"],
                               max_amount=gbp(0), mandate_id="leaf-1"), "grandchild")
case("delegation: a three-link chain, each link narrower, roots in the issuer", leaf, [
    V(txn("read", THAMES, "4900", 0), "allow", []),
    V(PAY_40, "deny", ["action", "amount", "counterparty_scope"]),
])
wide_leaf = signed(delegate_mandate(mid, agent_id="leaf-agent", counterparties={THAMES: ["read", "pay", "transfer"]},
                                    actions=["read", "pay", "transfer"], mandate_id="leaf-wide"), "grandchild")
case("delegation_scope: the third link widens the second", wide_leaf, [
    V(txn("read", THAMES, "4900", 0), "deny", ["delegation_scope", "issuer_trusted"]),
])

# --- G. 0.1 anchors, unchanged ------------------------------------------------------------

tampered_root = copy.deepcopy(scoped)
tampered_root["mandate"]["constraints"]["max_amount"]["value"] = 999999
case("anchor: a mandate edited after signing", tampered_root, [
    V(PAY_THAMES, "deny", [], signature_valid=False),
])
case("anchor: a mandate signed by a key outside the trusted set", signed(root(mandate_id="m-stranger"), "stranger"), [
    V(PAY_THAMES, "deny", ["issuer_trusted"], signature_valid=True),
])
case("anchor: over the cap", scoped, [
    V(txn("pay", THAMES, "4900", 24000), "deny", ["amount"]),
])
unbounded = signed(build_mandate(agent_id="agent-tidy", actions=["read"], issued_at=ISSUED, expires_at=EXPIRES, mandate_id="m-unbounded"))
case("anchor: actions alone are not scope", unbounded, [
    V(txn("read", THAMES, "4900", 0), "deny", ["has_scope"]),
])


# --- self-check against the Python verifier, then write ---------------------------------------

def run_case(c):
    store = InMemoryUsageStore() if c["store"] else None
    trusted = [KEYS[k] for k in c["trusted"]] or None
    lists = [l["envelope"] for l in c["revocation_lists"]]
    verdicts = 0
    for i, step in enumerate(c["steps"]):
        now = datetime.fromisoformat(step["now"].replace("Z", "+00:00")) if "now" in step else NOW
        where = f"{c['name']} / step {i}"
        if step["op"] == "record":
            record_use(c["mandate"], step["transaction"], store, now=now)
        elif step["op"] == "record_raw":
            store.record(step["mandate_id"], step["use"])
        elif step["op"] == "verify":
            v = verify(c["mandate"], step["transaction"], now=now, trusted_keys=trusted, store=store, revocation_lists=lists)
            got = {"decision": v["decision"], "failed": sorted(ch["constraint"] for ch in v["failed"])}
            exp = step["expect"]
            assert got["decision"] == exp["decision"], f"{where}: decision {got} != {exp}\n  {v['rationale']}"
            assert got["failed"] == exp["failed"], f"{where}: failed {got} != {exp}\n  {v['rationale']}"
            if "signature_valid" in exp:
                assert v["signature_valid"] == exp["signature_valid"], f"{where}: signature_valid"
            verdicts += 1
        else:
            raise AssertionError(f"{where}: unknown op")
    return verdicts


def main():
    total = sum(run_case(c) for c in CASES)
    fixture = {
        "description": (
            "MandateKit 0.2 verdict matrix. Both test suites (python/tests/test_v02.py and "
            "typescript/test/v02.test.ts) replay every case: build a fresh in-memory store when "
            "`store` is true, pin the named trusted keys, supply the listed revocation lists, run the "
            "steps in order, and compare the decision and the sorted reason codes in `failed` (and "
            "`signature_valid` where given). Envelopes were signed by the Python SDK; the TypeScript "
            "suite re-signs each one with the same seed and checks the bytes match. Every step carries "
            "an explicit `now` or uses the fixture's; nothing depends on a wall clock. Seeds are test "
            "values, never real keys."
        ),
        "generated_by": "fixtures/generate_verdict_matrix.py",
        "now": iso(NOW),
        "seeds": {k: v.hex() for k, v in SEEDS.items()},
        "keys": KEYS,
        "cases": CASES,
    }
    with open(OUT, "w") as fh:
        json.dump(fixture, fh, indent=1)
        fh.write("\n")
    print(f"wrote {OUT}: {len(CASES)} cases, {total} verdicts, all as expected")


if __name__ == "__main__":
    sys.exit(main())
