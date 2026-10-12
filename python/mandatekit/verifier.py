"""
The deterministic verifier.

Given a signed mandate and a candidate transaction, decide whether the
transaction is in scope. Everything here is deterministic: same inputs, same
output, every time, with a human-readable rationale. No model is involved in the
core decision.

SECURITY MODEL — read this. A valid signature proves *integrity* (the mandate was
not altered) and that *whoever holds the signing key* authorized it. It does NOT
prove the signer is someone you trust. You must pin the issuer:

    verify(signed, txn, trusted_keys=[issuer_public_key])   # recommended

If you pass neither `trusted_keys` nor `allow_unverified_issuer=True`, verify
FAILS CLOSED and denies — because trusting any self-signed mandate means anyone
can mint one. `allow_unverified_issuer=True` opts into integrity-only checking
and should be rare.

Other deliberate postures:
  * Absent scope is denied. A mandate with no category / merchant / counterparty
    / amount limit is unbounded and refused. Empty allow-lists ([]) mean "allow
    nothing", not "no constraint".
  * Unknown constraint keys are denied (fail-closed on anything we cannot
    enforce), so a future or hostile constraint is never silently ignored. The
    same applies to a mandate whose `version` this verifier does not know, and
    to a `mandatekit/v0` mandate that carries 0.2 keys.
  * Amounts must be integers, compared like-for-like (the caller picks the unit
    and uses it consistently for cap and transaction), to avoid float
    canonicalization divergence across languages.
  * Stateful rules need state. A mandate that declares `limits` is denied
    (`limits_store`) unless the caller passes `store=`; a mandate that declares
    a revocation list is denied (`revocation_list`) unless the caller passes
    that list, signature-verified, in `revocation_lists=`.
  * A delegated mandate is verified as a chain back to a pinned issuer, and
    every link must only narrow its parent (`delegation_scope`).
  * Intent-basket alignment is OPTIONAL and injected via `intent_scorer=`; a
    missing or failing model never turns a deny into an allow.

A transaction is a dict:

    {
      "merchant": "Fleet Feet",
      "category": "apparel",
      "amount": {"value": 240, "currency": "USD"},   # integer value
      "description": "Brooks Ghost 16 running shoes",
      "action": "pay",                                # optional verb, checked against constraints.actions
                                                      #   and the counterparty's per-verb scope
      "approval": {...signed step mandate...}         # optional, satisfies an "ask" verdict
    }

Verdicts are "allow", "ask" or "deny". "ask" means every scope check passed
but the mandate's approval rules want a fresh issuer-signed step mandate for
this transaction (see `step_mandate`) before it may run. Treat anything other
than "allow" as not allowed.

Each entry in `matched` / `failed` names the check that produced it in
`constraint`; those names are the stable reason codes (see REASON_CODES).
"""

import base64
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from .mandate import (
    DELEGATION_KEYS,
    LIMIT_KEYS,
    MAX_SAFE_INT,
    REVOCATION_KEYS,
    REVOCATION_LIST_VERSION,
    SUPPORTED_VERSIONS,
    VERSION,
    VERSION_V0,
    parse_iso,
)
from .signing import verify_revocation_list_signature, verify_signature

IntentScorer = Callable[[str, Dict], float]
TrustedKeys = Union[str, bytes, Iterable[Union[str, bytes]]]

# Constraint keys the verifier can actually enforce, per wire version. Anything
# else is denied. A mandatekit/v0 mandate may use only the v0 keys.
V0_CONSTRAINT_KEYS = {"intent", "categories", "merchants", "max_amount", "actions", "approval"}
V02_CONSTRAINT_KEYS = V0_CONSTRAINT_KEYS | {"counterparties", "not_before", "limits", "revocation", "delegation"}
KNOWN_CONSTRAINT_KEYS = V02_CONSTRAINT_KEYS
# At least one of these "hard" scope limiters must be present, or the mandate is
# unbounded and refused. (intent is fuzzy/advisory, so it does not count, and
# neither does `actions`: an allow-list of verbs with no category, merchant or
# amount limit is still unbounded in what it can reach.)
SCOPING_KEYS = {"categories", "merchants", "counterparties", "max_amount"}

# Stable reason codes: the `constraint` field of every check the verifier can
# emit. Documented in the README; the Bench counts verdicts by these names.
REASON_CODES = (
    "version",
    "issuer_trusted",
    "constraints_enforceable",
    "has_scope",
    "not_expired",
    "not_before",
    "category",
    "merchant_allow",
    "merchant_deny",
    "counterparty_scope",
    "amount",
    "action",
    "approval",
    "revocation_list",
    "revoked",
    "limits",
    "limits_store",
    "max_uses",
    "max_total_amount",
    "max_uses_per_window",
    "max_amount_per_window",
    "delegation",
    "delegation_scope",
    "intent_alignment",
)

# DoS guards for hostile JSON.
MAX_DEPTH = 64
MAX_NODES = 10000
# A delegation chain longer than this is refused outright.
MAX_CHAIN_LINKS = 8


def _check(name: str, passed: bool, detail: str) -> Dict:
    return {"constraint": name, "passed": passed, "detail": detail}


def _within_limits(obj, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> bool:
    """Iterative (non-recursive) bound check so a deeply nested payload cannot
    blow the stack before we ever canonicalize it."""
    stack = [(obj, 1)]
    nodes = 0
    while stack:
        cur, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            return False
        if isinstance(cur, dict):
            for v in cur.values():
                stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, depth + 1))
    return True


def _normalize_trusted(trusted_keys: Optional[TrustedKeys]) -> Optional[Set[str]]:
    if trusted_keys is None:
        return None
    if isinstance(trusted_keys, (str, bytes)):
        trusted_keys = [trusted_keys]
    out: Set[str] = set()
    for k in trusted_keys:
        out.add(base64.b64encode(k).decode("ascii") if isinstance(k, (bytes, bytearray)) else k)
    return out


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and v == v and v not in (float("inf"), float("-inf"))


def _amount_ok(a) -> bool:
    return (isinstance(a, dict) and _is_int(a.get("value")) and 0 <= a["value"] <= MAX_SAFE_INT
            and isinstance(a.get("currency"), str) and bool(a["currency"]))


def _lower_list(x) -> List[str]:
    return [str(v).lower() for v in x] if isinstance(x, list) else []


def _fmt(items: Iterable[str]) -> str:
    return "[" + ", ".join(items) + "]"


def _epoch(dt: datetime) -> float:
    return dt.timestamp()


def _try_parse(s) -> Optional[datetime]:
    if not isinstance(s, str):
        return None
    try:
        return parse_iso(s)
    except Exception:
        return None


def _constraint_keys_for(version) -> Optional[Set[str]]:
    if version == VERSION:
        return V02_CONSTRAINT_KEYS
    if version == VERSION_V0:
        return V0_CONSTRAINT_KEYS
    return None


def _verdict(decision, *, signature_valid, checks, mandate, intent_alignment=None, rationale):
    passed = [c for c in checks if c["passed"]]
    failed = [c for c in checks if not c["passed"]]
    score = round(len(passed) / len(checks), 4) if checks else 0.0
    return {
        "decision": decision,
        "signature_valid": signature_valid,
        "scope_match_score": score,
        "intent_alignment": intent_alignment,
        "matched": passed,
        "failed": failed,
        "rationale": rationale,
        "mandate_id": mandate.get("mandate_id") if isinstance(mandate, dict) else None,
    }


# --- limits ---------------------------------------------------------------------

def _parse_limits(lim) -> Optional[Dict]:
    """Normalize a `limits` object, or return None if it is malformed."""
    if not isinstance(lim, dict) or set(lim) - set(LIMIT_KEYS):
        return None
    out: Dict = {}
    if "actions" in lim:
        acts = lim["actions"]
        if not isinstance(acts, list) or not all(isinstance(a, str) for a in acts):
            return None
        out["actions"] = [a.lower() for a in acts]
    for key in ("max_uses", "max_uses_per_window"):
        if key in lim:
            if not _is_int(lim[key]) or lim[key] < 0 or lim[key] > MAX_SAFE_INT:
                return None
            out[key] = lim[key]
    if "window_seconds" in lim:
        w = lim["window_seconds"]
        if not _is_int(w) or w < 1 or w > MAX_SAFE_INT:
            return None
        out["window_seconds"] = w
    for key in ("max_total_amount", "max_amount_per_window"):
        if key in lim:
            if not _amount_ok(lim[key]):
                return None
            out[key] = {"value": lim[key]["value"], "currency": lim[key]["currency"]}
    if ("max_uses_per_window" in out or "max_amount_per_window" in out) and "window_seconds" not in out:
        return None
    if not any(k in out for k in ("max_uses", "max_total_amount", "max_uses_per_window", "max_amount_per_window")):
        return None
    return out


def _use_ok(use) -> bool:
    if not isinstance(use, dict) or not _is_num(use.get("at")):
        return False
    action = use.get("action")
    if action is not None and not isinstance(action, str):
        return False
    amount = use.get("amount")
    return amount is None or _amount_ok(amount)


def _check_limits(mandate: Dict, transaction: Dict, now_s: float, store, checks: List[Dict]) -> None:
    """Evaluate one link's `limits` against the store. Appends one passing check
    named `limits`, or one failing check per limit that would be exceeded."""
    constraints = mandate.get("constraints") or {}
    lim = _parse_limits(constraints.get("limits"))
    if lim is None:
        checks.append(_check("limits", False, "malformed limits constraint"))
        return
    mandate_id = mandate.get("mandate_id")
    try:
        uses = list(store.uses(mandate_id))
    except Exception as e:  # a broken store is a deny, never an exception
        checks.append(_check("limits_store", False, f"state store error: {e.__class__.__name__}"))
        return
    if not all(_use_ok(u) for u in uses):
        checks.append(_check("limits_store", False, "state store returned a malformed usage record"))
        return

    filt = lim.get("actions")
    txn_act = transaction.get("action")
    txn_act = txn_act.lower() if isinstance(txn_act, str) else ""

    def counts(action) -> bool:
        return filt is None or (action or "").lower() in filt

    counted = [u for u in uses if counts(u.get("action"))]
    proposed = counts(txn_act)
    txn_amount = transaction.get("amount") if isinstance(transaction.get("amount"), dict) else None
    failures: List[Dict] = []

    total_uses = len(counted) + (1 if proposed else 0)
    if "max_uses" in lim and total_uses > lim["max_uses"]:
        failures.append(_check("max_uses", False,
                               f"{total_uses} uses would exceed max_uses {lim['max_uses']}"))

    def summed(records, limit_name: str, cap: Dict):
        """Sum recorded amounts plus the proposed one in the cap's currency, or
        return a failing check when something cannot be compared."""
        total = 0
        for u in records:
            amt = u.get("amount")
            if amt is None:
                continue
            if amt["currency"] != cap["currency"]:
                return None, _check(limit_name, False,
                                    f"recorded use in {amt['currency']} cannot be compared with {limit_name} in {cap['currency']}")
            total += amt["value"]
        if proposed:
            if txn_amount is None or txn_amount.get("value") is None:
                return None, _check(limit_name, False, "transaction has no amount")
            if not _is_int(txn_amount.get("value")) or txn_amount.get("currency") != cap["currency"]:
                return None, _check(limit_name, False,
                                    f"transaction amount cannot be compared with {limit_name} in {cap['currency']}")
            total += txn_amount["value"]
        return total, None

    if "max_total_amount" in lim:
        cap = lim["max_total_amount"]
        total, bad = summed(counted, "max_total_amount", cap)
        if bad is not None:
            failures.append(bad)
        elif total > cap["value"]:
            failures.append(_check("max_total_amount", False,
                                   f"{total} {cap['currency']} would exceed max_total_amount {cap['value']} {cap['currency']}"))

    if "window_seconds" in lim:
        w = lim["window_seconds"]
        in_window = [u for u in counted if now_s - u["at"] < w]
        if "max_uses_per_window" in lim:
            n = len(in_window) + (1 if proposed else 0)
            if n > lim["max_uses_per_window"]:
                failures.append(_check("max_uses_per_window", False,
                                       f"{n} uses in {w}s would exceed max_uses_per_window {lim['max_uses_per_window']}"))
        if "max_amount_per_window" in lim:
            cap = lim["max_amount_per_window"]
            total, bad = summed(in_window, "max_amount_per_window", cap)
            if bad is not None:
                failures.append(bad)
            elif total > cap["value"]:
                failures.append(_check("max_amount_per_window", False,
                                       f"{total} {cap['currency']} in {w}s would exceed max_amount_per_window {cap['value']} {cap['currency']}"))

    if failures:
        checks.extend(failures)
    else:
        checks.append(_check("limits", True,
                             f"within usage limits ({total_uses} counted use{'s' if total_uses != 1 else ''} including this one)"
                             if proposed else
                             f"within usage limits (this {txn_act or 'action'} does not count; {len(counted)} recorded)"))


# --- revocation -----------------------------------------------------------------

def _normalize_lists(revocation_lists) -> List:
    if revocation_lists is None:
        return []
    if isinstance(revocation_lists, dict):
        return [revocation_lists]
    if isinstance(revocation_lists, (list, tuple)):
        return list(revocation_lists)
    return []


def _check_revocation(signed: Dict, now: datetime, trusted: Optional[Set[str]],
                      revocation_lists: List, checks: List[Dict]) -> None:
    mandate = signed["mandate"]
    constraints = mandate.get("constraints") or {}
    rev = constraints.get("revocation")
    if (not isinstance(rev, dict) or set(rev) - set(REVOCATION_KEYS)
            or not isinstance(rev.get("list_id"), str) or not rev["list_id"]):
        checks.append(_check("revocation_list", False, "malformed revocation constraint"))
        return
    max_age = rev.get("max_age_seconds")
    if "max_age_seconds" in rev and (not _is_int(max_age) or max_age < 1):
        checks.append(_check("revocation_list", False, "malformed revocation constraint"))
        return
    list_id = rev["list_id"]
    sig_obj = signed.get("signature")
    issuer_key = sig_obj.get("public_key") if isinstance(sig_obj, dict) else None

    candidates = [l for l in revocation_lists
                  if isinstance(l, dict) and isinstance(l.get("list"), dict) and l["list"].get("list_id") == list_id]
    if not candidates:
        checks.append(_check("revocation_list", False, f"declared revocation list '{list_id}' was not supplied"))
        return

    valid: List[Dict] = []
    problem = "revocation list is malformed"
    for cand in candidates:
        body = cand["list"]
        if body.get("version") != REVOCATION_LIST_VERSION or not isinstance(body.get("revoked"), list) \
                or not all(isinstance(r, str) for r in body["revoked"]):
            problem = f"revocation list '{list_id}' is malformed"
            continue
        if not verify_revocation_list_signature(cand):
            problem = f"revocation list '{list_id}' signature invalid"
            continue
        signer = cand["signature"].get("public_key")
        if signer != issuer_key and not (trusted is not None and signer in trusted):
            problem = f"revocation list '{list_id}' is not signed by the mandate's issuer or a trusted key"
            continue
        if max_age is not None:
            issued = _try_parse(body.get("issued_at"))
            if issued is None or _epoch(now) - _epoch(issued) > max_age:
                problem = f"revocation list '{list_id}' is older than max_age_seconds {max_age}"
                continue
        valid.append(body)
    if not valid:
        checks.append(_check("revocation_list", False, problem))
        return
    mandate_id = mandate.get("mandate_id")
    if any(mandate_id in body["revoked"] for body in valid):
        checks.append(_check("revoked", False, f"mandate {mandate_id} is revoked in list '{list_id}'"))
    else:
        checks.append(_check("revocation_list", True, f"not revoked in list '{list_id}'"))


# --- delegation -----------------------------------------------------------------

def _verb_scope(c: Dict) -> Optional[Dict[str, Optional[Set[str]]]]:
    """Effective per-counterparty verb scope: {id: verbs} where verbs None means
    every verb; None overall means the mandate does not bound counterparties."""
    acts = set(_lower_list(c["actions"])) if "actions" in c else None
    merchants = c.get("merchants") if isinstance(c.get("merchants"), dict) else {}
    allow = set(str(x) for x in merchants["allow"]) if isinstance(merchants.get("allow"), list) else None
    if "allow" in merchants and allow is None:
        allow = set()
    if "counterparties" in c:
        cps = c["counterparties"] if isinstance(c["counterparties"], dict) else {}
        out: Dict[str, Optional[Set[str]]] = {}
        for cid, verbs in cps.items():
            if allow is not None and cid not in allow:
                continue
            vs = set(_lower_list(verbs))
            out[cid] = vs & acts if acts is not None else vs
        return out
    if allow is not None:
        return {cid: acts for cid in allow}
    return None


def _widening(child: Dict, parent: Dict) -> Optional[str]:
    """Return a description of the first way `child` is wider than `parent`, or
    None when every axis narrows or stays equal."""
    cc = child.get("constraints") if isinstance(child.get("constraints"), dict) else {}
    pc = parent.get("constraints") if isinstance(parent.get("constraints"), dict) else {}

    # Window: the child's must sit inside the parent's.
    c_exp, p_exp = _try_parse(child.get("expires_at")), _try_parse(parent.get("expires_at"))
    if c_exp is None or p_exp is None:
        return "expires_at: unparseable"
    if c_exp > p_exp:
        return f"expires_at {child.get('expires_at')} is after the parent's {parent.get('expires_at')}"
    if "not_before" in pc:
        p_nb = _try_parse(pc["not_before"])
        if p_nb is None:
            return "not_before: the parent's is unparseable"
        if "not_before" not in cc:
            return f"not_before: parent opens at {pc['not_before']}, child has no not_before"
        c_nb = _try_parse(cc["not_before"])
        if c_nb is None:
            return "not_before: unparseable"
        if c_nb < p_nb:
            return f"not_before: child opens at {cc['not_before']}, before the parent's {pc['not_before']}"

    # Categories.
    if "categories" in pc:
        if "categories" not in cc:
            return "categories: parent limits categories, child has none"
        extra = sorted(set(_lower_list(cc["categories"])) - set(_lower_list(pc["categories"])))
        if extra:
            return f"categories: child adds {_fmt(extra)}"

    # Cap.
    if "max_amount" in pc:
        p_ma = pc["max_amount"]
        if not _amount_ok(p_ma):
            return "max_amount: the parent's is malformed"
        if "max_amount" not in cc:
            return f"max_amount: parent caps at {p_ma['value']} {p_ma['currency']}, child has no cap"
        c_ma = cc["max_amount"]
        if not _amount_ok(c_ma):
            return "max_amount: the child's is malformed"
        if c_ma["currency"] != p_ma["currency"]:
            return f"max_amount: currency {c_ma['currency']} differs from the parent's {p_ma['currency']}"
        if c_ma["value"] > p_ma["value"]:
            return f"max_amount: child cap {c_ma['value']} exceeds the parent's {p_ma['value']}"

    # Verbs and counterparties, on effective scope.
    p_acts = set(_lower_list(pc["actions"])) if "actions" in pc else None
    c_acts = set(_lower_list(cc["actions"])) if "actions" in cc else None
    p_scope, c_scope = _verb_scope(pc), _verb_scope(cc)
    if p_acts is not None:
        if c_acts is not None:
            extra = sorted(c_acts - p_acts)
            if extra:
                return f"actions: child adds {_fmt(extra)}"
        else:
            if c_scope is None:
                return f"actions: parent limits verbs to {_fmt(sorted(p_acts))}, child has no actions"
            for cid, verbs in c_scope.items():
                if verbs is None:
                    return f"actions: child allows every verb at '{cid}', parent limits verbs to {_fmt(sorted(p_acts))}"
                extra = sorted(verbs - p_acts)
                if extra:
                    return f"actions: child adds {_fmt(extra)} at '{cid}'"
    if p_scope is not None:
        if c_scope is None:
            return "counterparties: parent limits counterparties, child has none"
        for cid, verbs in c_scope.items():
            if cid not in p_scope:
                return f"counterparties: child adds '{cid}'"
            pv = p_scope[cid]
            if pv is not None:
                if verbs is None:
                    return f"counterparties: child allows every verb at '{cid}', parent allows {_fmt(sorted(pv))}"
                extra = sorted(verbs - pv)
                if extra:
                    return f"counterparties: child adds {_fmt(extra)} at '{cid}'"

    # Deny list: everything the parent denies stays unreachable.
    p_merch = pc.get("merchants") if isinstance(pc.get("merchants"), dict) else {}
    if "deny" in p_merch:
        c_merch = cc.get("merchants") if isinstance(cc.get("merchants"), dict) else {}
        c_deny = set(str(x) for x in c_merch["deny"]) if isinstance(c_merch.get("deny"), list) else set()
        for d in (p_merch["deny"] if isinstance(p_merch["deny"], list) else []):
            d = str(d)
            if d not in c_deny and not (c_scope is not None and d not in c_scope):
                return f"merchants.deny: child does not deny '{d}'"

    # Approval: the child asks at least where the parent asks.
    if "approval" in pc:
        pa = pc["approval"]
        if not isinstance(pa, dict):
            return "approval: the parent's is malformed"
        ca = cc.get("approval") if isinstance(cc.get("approval"), dict) else {}
        c_ask = set(_lower_list(ca.get("actions")))
        for v in _lower_list(pa.get("actions")):
            if v in c_ask:
                continue
            reachable = (c_acts is None or v in c_acts) and (
                c_scope is None or any(verbs is None or v in verbs for verbs in c_scope.values()))
            if reachable:
                return f"approval: parent asks before '{v}', child does not"
        if "above" in pa:
            p_ab = pa["above"]
            if not _amount_ok(p_ab):
                return "approval.above: the parent's is malformed"
            c_ab = ca.get("above")
            c_ma = cc.get("max_amount")
            ok = (_amount_ok(c_ab) and c_ab["currency"] == p_ab["currency"] and c_ab["value"] <= p_ab["value"]) or (
                _amount_ok(c_ma) and c_ma["currency"] == p_ab["currency"] and c_ma["value"] <= p_ab["value"])
            if not ok:
                return f"approval.above: parent asks above {p_ab['value']} {p_ab['currency']}, child does not"
    return None


def _walk_chain(signed: Dict) -> Dict:
    """Walk a child mandate up to its root. Returns {"ok", "code", "detail",
    "links": [leaf, parent, ..., root], "root_key"}. Structural, signature and
    narrowing failures all land here; issuer trust of the root is the caller's."""
    links: List[Dict] = [signed]
    cur = signed
    for _ in range(MAX_CHAIN_LINKS):
        constraints = cur["mandate"].get("constraints") or {}
        deleg = constraints.get("delegation") if isinstance(constraints, dict) else None
        if not isinstance(deleg, dict) or "parent" not in deleg:
            break
        parent = deleg["parent"]
        if not (isinstance(parent, dict) and isinstance(parent.get("mandate"), dict)
                and isinstance(parent["mandate"].get("constraints") or {}, dict)):
            return {"ok": False, "code": "delegation", "detail": f"malformed parent mandate at depth {len(links)}",
                    "links": [signed], "root_key": None}
        links.append(parent)
        cur = parent
    else:
        return {"ok": False, "code": "delegation", "detail": f"delegation chain exceeds {MAX_CHAIN_LINKS} links",
                "links": [signed], "root_key": None}

    def fail(code: str, detail: str) -> Dict:
        return {"ok": False, "code": code, "detail": detail, "links": [signed], "root_key": None}

    for i in range(len(links) - 1):
        child, parent = links[i], links[i + 1]
        cm, pm = child["mandate"], parent["mandate"]
        pid = pm.get("mandate_id")
        if not verify_signature(child):
            return fail("delegation", f"signature of link {i} ({cm.get('mandate_id')}) is invalid")
        p_keys = _constraint_keys_for(pm.get("version"))
        pc = pm.get("constraints") or {}
        if p_keys is None:
            return fail("delegation", f"parent {pid} has unsupported version {pm.get('version')!r}")
        if set(pc) - p_keys:
            return fail("delegation", f"parent {pid} carries constraint(s) its version cannot enforce: {_fmt(sorted(set(pc) - p_keys))}")
        if not any(k in pc for k in SCOPING_KEYS):
            return fail("delegation", f"parent {pid} has no scope")
        c_deleg = (cm.get("constraints") or {}).get("delegation")
        if not isinstance(c_deleg, dict) or set(c_deleg) - set(DELEGATION_KEYS):
            return fail("delegation", f"malformed delegation constraint on link {i}")
        p_deleg = pc.get("delegation")
        p_max = p_deleg.get("max_depth") if isinstance(p_deleg, dict) else None
        if not isinstance(p_deleg, dict) or set(p_deleg) - set(DELEGATION_KEYS) or not _is_int(p_max) or p_max < 1:
            return fail("delegation", f"parent {pid} does not allow delegation")
        c_max = c_deleg.get("max_depth", 0)
        if not _is_int(c_max) or c_max < 0 or c_max > p_max - 1:
            return fail("delegation_scope", f"child {cm.get('mandate_id')} max_depth {c_max!r} exceeds the parent's remaining depth {p_max - 1}")
        subject = pm.get("subject")
        p_key = subject.get("public_key") if isinstance(subject, dict) else None
        if not isinstance(p_key, str) or not p_key:
            return fail("delegation", f"parent {pid} has no subject.public_key, so no delegate can sign under it")
        c_sig = child.get("signature")
        c_key = c_sig.get("public_key") if isinstance(c_sig, dict) else None
        if c_key != p_key:
            return fail("delegation", f"link {i} ({cm.get('mandate_id')}) is not signed by its parent's subject key")
        problem = _widening(cm, pm)
        if problem is not None:
            return fail("delegation_scope", f"child {cm.get('mandate_id')} widens parent {pid}: {problem}")

    root = links[-1]
    if not verify_signature(root):
        return fail("delegation", f"root signature ({root['mandate'].get('mandate_id')}) is invalid")
    root_sig = root.get("signature")
    root_key = root_sig.get("public_key") if isinstance(root_sig, dict) else None
    return {"ok": True, "code": "delegation",
            "detail": f"delegation chain of {len(links)} links roots in {root['mandate'].get('mandate_id')}",
            "links": links, "root_key": root_key}


def _chain_ids(signed) -> List[str]:
    """Mandate ids from the leaf to the root, or [] if the envelope is malformed."""
    ids: List[str] = []
    cur = signed
    for _ in range(MAX_CHAIN_LINKS + 1):
        if not isinstance(cur, dict) or not isinstance(cur.get("mandate"), dict):
            return []
        mid = cur["mandate"].get("mandate_id")
        if not isinstance(mid, str):
            return []
        ids.append(mid)
        constraints = cur["mandate"].get("constraints")
        deleg = constraints.get("delegation") if isinstance(constraints, dict) else None
        if not isinstance(deleg, dict) or "parent" not in deleg:
            return ids
        cur = deleg["parent"]
    return []


def record_use(signed: Dict, transaction: Dict, store, *, now: Optional[datetime] = None) -> List[str]:
    """Record that `transaction` was carried out under `signed`, for the limits.

    Writes one use record under the mandate's id and under every ancestor in
    its delegation chain, so a parent's limits bind all its children. Call it
    after acting on an "allow"; the verifier itself never writes. Returns the
    ids written. Raises ValueError on a malformed envelope rather than silently
    recording nothing, since a missed record would loosen the limits.
    """
    ids = _chain_ids(signed)
    if not ids:
        raise ValueError("record_use: malformed signed mandate")
    now = now or datetime.now(timezone.utc)
    transaction = transaction if isinstance(transaction, dict) else {}
    action = transaction.get("action")
    amount = transaction.get("amount")
    use = {
        "at": _epoch(now),
        "action": action.lower() if isinstance(action, str) else None,
        "amount": {"value": amount["value"], "currency": amount["currency"]} if _amount_ok(amount) else None,
    }
    for mid in ids:
        store.record(mid, dict(use))
    return ids


# --- the verifier ---------------------------------------------------------------

def verify(
    signed: Dict,
    transaction: Dict,
    *,
    now: Optional[datetime] = None,
    intent_scorer: Optional[IntentScorer] = None,
    intent_threshold: float = 0.6,
    trusted_keys: Optional[TrustedKeys] = None,
    allow_unverified_issuer: bool = False,
    store=None,
    revocation_lists=None,
) -> Dict:
    """Return a structured verdict for `transaction` against `signed` mandate.

    `store` supplies usage state for mandates that declare `limits` (see
    `mandatekit.store`); `revocation_lists` supplies the signed lists mandates
    declare under `revocation`. Both are required only when a mandate uses the
    feature, and their absence then denies.
    """
    now = now or datetime.now(timezone.utc)

    # Structural / DoS guards before we touch the payload.
    if not isinstance(signed, dict) or not isinstance(signed.get("mandate"), dict):
        return _verdict("deny", signature_valid=False, checks=[], mandate={},
                        rationale="malformed envelope: missing mandate object")
    if not _within_limits(signed):
        return _verdict("deny", signature_valid=False, checks=[], mandate=signed["mandate"],
                        rationale="mandate rejected: exceeds size/nesting limits")

    mandate = signed["mandate"]
    constraints = mandate.get("constraints") or {}
    if not isinstance(constraints, dict):
        return _verdict("deny", signature_valid=False, checks=[], mandate=mandate,
                        rationale="malformed mandate: constraints must be an object")
    if not isinstance(transaction, dict):
        transaction = {}

    signature_valid = verify_signature(signed)
    checks: List[Dict] = []

    # --- Wire version --------------------------------------------------------
    version = mandate.get("version")
    known_keys = _constraint_keys_for(version)
    if known_keys is None:
        checks.append(_check("version", False,
                             f"unsupported mandate version {version!r}; this verifier supports {_fmt(SUPPORTED_VERSIONS)}"))
        known_keys = V02_CONSTRAINT_KEYS

    # --- Issuer trust (the critical check), through the chain for a child ----
    trusted = _normalize_trusted(trusted_keys)
    if trusted is None and not allow_unverified_issuer:
        # Fail closed: refusing to treat an unpinned self-signed mandate as authority.
        return _verdict(
            "deny", signature_valid=signature_valid, checks=[], mandate=mandate,
            rationale="no trusted issuer keys supplied: pass trusted_keys=[...] "
                      "(recommended) or allow_unverified_issuer=True to accept any signer",
        )
    delegation = constraints.get("delegation")
    is_child = isinstance(delegation, dict) and "parent" in delegation
    links: List[Dict] = [signed]
    if is_child:
        chain = _walk_chain(signed)
        checks.append(_check(chain["code"], chain["ok"], chain["detail"]))
        if chain["ok"]:
            links = chain["links"]
        if trusted is not None:
            root_ok = isinstance(chain["root_key"], str) and chain["root_key"] in trusted
            checks.append(_check("issuer_trusted", root_ok,
                                 "delegation chain roots in a trusted issuer key" if root_ok
                                 else "delegation chain does not root in a trusted issuer key"))
    else:
        if "delegation" in constraints and (
                not isinstance(delegation, dict) or not delegation or set(delegation) - set(DELEGATION_KEYS)
                or not _is_int(delegation.get("max_depth")) or delegation["max_depth"] < 0):
            checks.append(_check("delegation", False, "malformed delegation constraint"))
        if trusted is not None:
            sig_obj = signed.get("signature")
            env_key = sig_obj.get("public_key") if isinstance(sig_obj, dict) else None
            issuer_ok = isinstance(env_key, str) and env_key in trusted
            checks.append(_check(
                "issuer_trusted", issuer_ok,
                "signed by a trusted issuer key" if issuer_ok
                else "signing key is not in the trusted-issuer set",
            ))

    # --- Constraint sanity ---------------------------------------------------
    unknown = set(constraints) - V02_CONSTRAINT_KEYS
    needs_v02 = set(constraints) - known_keys - unknown
    if unknown:
        checks.append(_check("constraints_enforceable", False,
                             f"unenforceable constraint(s) present: {sorted(unknown)}"))
    elif needs_v02:
        checks.append(_check("constraints_enforceable", False,
                             f"constraint(s) {_fmt(sorted(needs_v02))} need mandate version {VERSION}; this mandate declares {version!r}"))

    has_scope = any(k in constraints for k in SCOPING_KEYS)
    checks.append(_check("has_scope", has_scope,
                         "mandate defines spending limits" if has_scope
                         else "mandate has no spending constraints (unbounded); refused"))

    # --- Expiry --------------------------------------------------------------
    try:
        expired = now > parse_iso(mandate["expires_at"])
    except Exception:
        expired = True
    checks.append(_check("not_expired", not expired,
                         "within validity window" if not expired else "mandate has expired"))

    # --- Window start (0.2) --------------------------------------------------
    if "not_before" in constraints:
        nb = _try_parse(constraints["not_before"])
        if nb is None:
            checks.append(_check("not_before", False, "malformed not_before"))
        else:
            ok = now >= nb
            checks.append(_check("not_before", ok,
                                 f"window open since {constraints['not_before']}" if ok
                                 else f"mandate is not yet valid: window opens at {constraints['not_before']}"))

    # --- Category (presence-based; empty list allows nothing) ----------------
    if "categories" in constraints:
        cats = constraints["categories"]
        cats = cats if isinstance(cats, list) else []
        txn_cat = transaction.get("category")
        txn_cat = txn_cat.lower() if isinstance(txn_cat, str) else ""
        ok = txn_cat in [str(c).lower() for c in cats]
        checks.append(_check("category", ok,
                             f"{txn_cat or '(none)'} {'in' if ok else 'not in'} {cats}"))

    # --- Merchant allow / deny (presence-based) ------------------------------
    merchants = constraints.get("merchants")
    merchants = merchants if isinstance(merchants, dict) else {}
    merchant = transaction.get("merchant") or ""
    if "allow" in merchants:
        allow = merchants.get("allow")
        allow = allow if isinstance(allow, list) else []
        ok = merchant in allow
        checks.append(_check("merchant_allow", ok,
                             f"{merchant!r} {'is' if ok else 'is not'} on the allow-list"))
    if "deny" in merchants:
        deny = merchants.get("deny")
        deny = deny if isinstance(deny, list) else []
        ok = merchant not in deny
        checks.append(_check("merchant_deny", ok,
                             f"{merchant!r} {'is not' if ok else 'is'} on the deny-list"))

    # --- Per-verb counterparty scope (0.2) -----------------------------------
    if "counterparties" in constraints:
        cps = constraints["counterparties"]
        txn_act = transaction.get("action")
        txn_act = txn_act.lower() if isinstance(txn_act, str) else ""
        if not isinstance(cps, dict) or not all(isinstance(v, list) for v in cps.values()):
            checks.append(_check("counterparty_scope", False, "malformed counterparties constraint"))
        elif not isinstance(merchant, str) or merchant not in cps:
            checks.append(_check("counterparty_scope", False, f"'{merchant}' is not a listed counterparty"))
        else:
            verbs = _lower_list(cps[merchant])
            ok = txn_act in verbs
            checks.append(_check("counterparty_scope", ok,
                                 f"'{merchant}' is scoped to {_fmt(verbs)}; {txn_act or '(none)'} is{'' if ok else ' not'} allowed there"))

    # --- Amount (integers only, compared like-for-like) ----------------------
    max_amount = constraints.get("max_amount")
    if max_amount is not None and not isinstance(max_amount, dict):
        checks.append(_check("amount", False, "malformed max_amount constraint"))
        max_amount = None
    if max_amount is not None:
        cap = max_amount.get("value")
        txn_amount = transaction.get("amount")
        txn_amount = txn_amount if isinstance(txn_amount, dict) else {}
        value = txn_amount.get("value")
        currency = txn_amount.get("currency")
        if not _is_int(cap):
            checks.append(_check("amount", False, "mandate cap must be an integer"))
        elif value is None or currency is None:
            checks.append(_check("amount", False, "transaction has no amount"))
        elif not _is_int(value):
            checks.append(_check("amount", False, "transaction amount must be an integer"))
        elif currency != max_amount.get("currency"):
            checks.append(_check("amount", False,
                                 f"currency {currency} != mandate currency {max_amount.get('currency')}"))
        else:
            ok = value <= cap
            checks.append(_check("amount", ok,
                                 f"{value} {currency} {'<=' if ok else '>'} cap {cap} {currency}"))

    # --- Action verb (presence-based; empty list allows nothing) -------------
    if "actions" in constraints:
        acts = constraints["actions"]
        acts = acts if isinstance(acts, list) else []
        txn_act = (transaction.get("action") or "")
        txn_act = txn_act.lower() if isinstance(txn_act, str) else ""
        ok = txn_act in [str(a).lower() for a in acts]
        checks.append(_check("action", ok,
                             f"action {txn_act or '(none)'} {'in' if ok else 'not in'} {acts}"))

    # --- Approval (step-up): some verbs or amounts need a step mandate -------
    approval_required = False
    if "approval" in constraints:
        approval = constraints["approval"]
        if not isinstance(approval, dict):
            checks.append(_check("approval", False, "malformed approval constraint"))
        else:
            reasons: List[str] = []
            ask_acts = approval.get("actions")
            ask_acts = ask_acts if isinstance(ask_acts, list) else []
            txn_act = (transaction.get("action") or "")
            txn_act = txn_act.lower() if isinstance(txn_act, str) else ""
            if txn_act in [str(a).lower() for a in ask_acts]:
                reasons.append(f"action {txn_act} needs approval")
            above = approval.get("above")
            if above is not None:
                amt = transaction.get("amount")
                amt = amt if isinstance(amt, dict) else {}
                if not isinstance(above, dict) or not _is_int(above.get("value")) or not above.get("currency"):
                    reasons.append("malformed approval.above")
                elif amt.get("value") is not None:
                    if not _is_int(amt.get("value")) or amt.get("currency") != above["currency"]:
                        reasons.append(
                            f"amount {amt.get('value')} {amt.get('currency')} cannot be compared "
                            f"with approval threshold {above['value']} {above['currency']}")
                    elif amt["value"] > above["value"]:
                        reasons.append(
                            f"{amt['value']} {amt['currency']} > approval threshold "
                            f"{above['value']} {above['currency']}")
            if reasons:
                step = transaction.get("approval")
                if step is None:
                    approval_required = True
                    checks.append(_check("approval", False, "approval required: " + "; ".join(reasons)))
                else:
                    target = {k: v for k, v in transaction.items() if k != "approval"}
                    if isinstance(step, dict) and isinstance(step.get("mandate"), dict) and _within_limits(step):
                        inner = verify(step, target, now=now, trusted_keys=trusted_keys,
                                       allow_unverified_issuer=allow_unverified_issuer,
                                       store=store, revocation_lists=revocation_lists)
                    else:
                        inner = _verdict("deny", signature_valid=False, checks=[], mandate={},
                                         rationale="malformed step mandate")
                    step_mandate = step.get("mandate") if isinstance(step, dict) else None
                    step_subject = step_mandate.get("subject") if isinstance(step_mandate, dict) else None
                    step_agent = step_subject.get("agent_id") if isinstance(step_subject, dict) else None
                    own_subject = mandate.get("subject")
                    own_agent = own_subject.get("agent_id") if isinstance(own_subject, dict) else None
                    same_agent = step_agent is not None and step_agent == own_agent
                    if inner["decision"] == "allow" and same_agent:
                        checks.append(_check("approval", True,
                                             f"step mandate {inner['mandate_id']} approves this transaction"))
                    elif inner["decision"] == "allow":
                        checks.append(_check("approval", False, "step mandate is for a different agent"))
                    else:
                        checks.append(_check("approval", False,
                                             f"step mandate rejected: {inner['rationale']}"))

    # --- Revocation (0.2), every link of the chain ---------------------------
    lists = _normalize_lists(revocation_lists)
    for link in links:
        link_constraints = link["mandate"].get("constraints") or {}
        if isinstance(link_constraints, dict) and "revocation" in link_constraints:
            _check_revocation(link, now, trusted, lists, checks)

    # --- Usage limits (0.2), every link of the chain, against the store ------
    limited = [link for link in links
               if isinstance(link["mandate"].get("constraints") or {}, dict)
               and "limits" in (link["mandate"].get("constraints") or {})]
    if limited:
        if store is None:
            checks.append(_check("limits_store", False,
                                 "mandate declares usage limits but no state store was supplied; pass store="))
        else:
            now_s = _epoch(now)
            for link in limited:
                _check_limits(link["mandate"], transaction, now_s, store, checks)

    # --- Intent-basket alignment (optional, injected) ------------------------
    intent_alignment: Optional[float] = None
    intent = constraints.get("intent")
    if intent and intent_scorer is not None:
        try:
            intent_alignment = float(intent_scorer(intent, transaction))
            ok = intent_alignment >= intent_threshold
            checks.append(_check("intent_alignment", ok,
                                 f"alignment {intent_alignment:.2f} {'>=' if ok else '<'} threshold {intent_threshold}"))
        except Exception as e:  # a model error must not crash verification
            checks.append(_check("intent_alignment", True, f"scorer unavailable ({e}); skipped"))

    # --- Decision ------------------------------------------------------------
    failed = [c for c in checks if not c["passed"]]
    if not signature_valid:
        return _verdict("deny", signature_valid=False, checks=checks, mandate=mandate,
                        intent_alignment=intent_alignment,
                        rationale="signature invalid: the mandate was not signed by its claimed key or was altered after signing")
    if len(failed) == 1 and approval_required and failed[0]["constraint"] == "approval":
        return _verdict("ask", signature_valid=True, checks=checks, mandate=mandate,
                        intent_alignment=intent_alignment,
                        rationale="needs approval: " + failed[0]["detail"])
    if failed:
        return _verdict("deny", signature_valid=True, checks=checks, mandate=mandate,
                        intent_alignment=intent_alignment,
                        rationale="out of scope: " + "; ".join(c["detail"] for c in failed))
    return _verdict("allow", signature_valid=True, checks=checks, mandate=mandate,
                    intent_alignment=intent_alignment,
                    rationale="in scope: " + "; ".join(c["detail"] for c in checks))
