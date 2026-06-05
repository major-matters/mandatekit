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
  * Absent scope is denied. A mandate with no category / merchant / amount limit
    is unbounded and refused. Empty allow-lists ([]) mean "allow nothing", not
    "no constraint".
  * Unknown constraint keys are denied (fail-closed on anything we cannot
    enforce), so a future or hostile constraint is never silently ignored.
  * Amounts must be integers, compared like-for-like (the caller picks the unit
    and uses it consistently for cap and transaction), to avoid float
    canonicalization divergence across languages.
  * Intent-basket alignment is OPTIONAL and injected via `intent_scorer=`; a
    missing or failing model never turns a deny into an allow.

A transaction is a dict:

    {
      "merchant": "Fleet Feet",
      "category": "apparel",
      "amount": {"value": 240, "currency": "USD"},   # integer value
      "description": "Brooks Ghost 16 running shoes"
    }
"""

import base64
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Set, Union

from .mandate import parse_iso
from .signing import verify_signature

IntentScorer = Callable[[str, Dict], float]
TrustedKeys = Union[str, bytes, Iterable[Union[str, bytes]]]

# Constraint keys the verifier can actually enforce. Anything else is denied.
KNOWN_CONSTRAINT_KEYS = {"intent", "categories", "merchants", "max_amount"}
# At least one of these "hard" scope limiters must be present, or the mandate is
# unbounded and refused. (intent is fuzzy/advisory, so it does not count.)
SCOPING_KEYS = {"categories", "merchants", "max_amount"}

# DoS guards for hostile JSON.
MAX_DEPTH = 64
MAX_NODES = 10000


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


def verify(
    signed: Dict,
    transaction: Dict,
    *,
    now: Optional[datetime] = None,
    intent_scorer: Optional[IntentScorer] = None,
    intent_threshold: float = 0.6,
    trusted_keys: Optional[TrustedKeys] = None,
    allow_unverified_issuer: bool = False,
) -> Dict:
    """Return a structured verdict for `transaction` against `signed` mandate."""
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

    signature_valid = verify_signature(signed)
    checks: List[Dict] = []

    # --- Issuer trust (the critical check) -----------------------------------
    trusted = _normalize_trusted(trusted_keys)
    env_key = (signed.get("signature") or {}).get("public_key")
    if trusted is not None:
        issuer_ok = isinstance(env_key, str) and env_key in trusted
        checks.append(_check(
            "issuer_trusted", issuer_ok,
            "signed by a trusted issuer key" if issuer_ok
            else "signing key is not in the trusted-issuer set",
        ))
    elif not allow_unverified_issuer:
        # Fail closed: refusing to treat an unpinned self-signed mandate as authority.
        return _verdict(
            "deny", signature_valid=signature_valid, checks=[], mandate=mandate,
            rationale="no trusted issuer keys supplied: pass trusted_keys=[...] "
                      "(recommended) or allow_unverified_issuer=True to accept any signer",
        )

    # --- Constraint sanity ---------------------------------------------------
    unknown = set(constraints) - KNOWN_CONSTRAINT_KEYS
    if unknown:
        checks.append(_check("constraints_enforceable", False,
                             f"unenforceable constraint(s) present: {sorted(unknown)}"))

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

    # --- Category (presence-based; empty list allows nothing) ----------------
    if "categories" in constraints:
        cats = constraints["categories"] or []
        txn_cat = (transaction.get("category") or "").lower()
        ok = txn_cat in [str(c).lower() for c in cats]
        checks.append(_check("category", ok,
                             f"{txn_cat or '(none)'} {'in' if ok else 'not in'} {cats}"))

    # --- Merchant allow / deny (presence-based) ------------------------------
    merchants = constraints.get("merchants") or {}
    merchant = transaction.get("merchant") or ""
    if "allow" in merchants:
        allow = merchants.get("allow") or []
        ok = merchant in allow
        checks.append(_check("merchant_allow", ok,
                             f"{merchant!r} {'is' if ok else 'is not'} on the allow-list"))
    if "deny" in merchants:
        deny = merchants.get("deny") or []
        ok = merchant not in deny
        checks.append(_check("merchant_deny", ok,
                             f"{merchant!r} {'is not' if ok else 'is'} on the deny-list"))

    # --- Amount (integers only, compared like-for-like) ----------------------
    max_amount = constraints.get("max_amount")
    if max_amount is not None:
        cap = max_amount.get("value")
        txn_amount = transaction.get("amount") or {}
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
    if failed:
        return _verdict("deny", signature_valid=True, checks=checks, mandate=mandate,
                        intent_alignment=intent_alignment,
                        rationale="out of scope: " + "; ".join(c["detail"] for c in failed))
    return _verdict("allow", signature_valid=True, checks=checks, mandate=mandate,
                    intent_alignment=intent_alignment,
                    rationale="in scope: " + "; ".join(c["detail"] for c in checks))
