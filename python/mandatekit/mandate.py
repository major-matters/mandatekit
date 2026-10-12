"""
The mandate data model.

A mandate is a plain JSON-serializable dict so it travels over any transport and
signs deterministically. This module builds well-formed mandates, exposes the
JSON Schema, and provides a dependency-free structural validator.

Shape (tracks the AP2 Verifiable Intent draft; field names are MandateKit's own
until the spec finalizes):

    {
      "version": "mandatekit/v0.2",
      "spec": "AP2-draft-2026Q2",
      "mandate_id": "uuid4",
      "subject": {"agent_id": "...", "public_key": "<base64, optional>"},
      "issued_at": "2026-06-05T12:00:00Z",
      "expires_at": "2026-06-30T23:59:59Z",
      "constraints": {
        "intent": "buy running shoes",          # natural-language intent basket
        "categories": ["apparel"],               # allowed merchant categories
        "merchants": {"allow": [...], "deny": [...]},   # optional flat lists (0.1)
        "counterparties": {                      # optional per-verb scope (0.2)
          "harbourline": ["read", "submit", "transfer"],
          "MID-10231": ["read", "pay"]
        },
        "max_amount": {"value": 500, "currency": "USD"},  # value: integer, caller-chosen unit
        "actions": ["read", "draft", "pay"],             # optional allow-list of verbs
        "approval": {                                    # optional step-up rules
          "actions": ["cancel"],                         #   these verbs need a step mandate
          "above": {"value": 200, "currency": "USD"}     #   and so do amounts above this
        },
        "not_before": "2026-06-06T09:00:00Z",            # optional window start (0.2)
        "limits": {                                      # optional usage limits (0.2)
          "actions": ["pay"],                            #   which verbs count (default: all)
          "max_uses": 1,
          "max_total_amount": {"value": 500, "currency": "USD"},
          "window_seconds": 3600,
          "max_uses_per_window": 1,
          "max_amount_per_window": {"value": 200, "currency": "USD"}
        },
        "revocation": {"list_id": "rl-2026-10", "max_age_seconds": 86400},  # optional (0.2)
        "delegation": {"max_depth": 1}                   # optional: may be delegated (0.2);
                                                         #   a child carries {"parent": <signed parent>}
      }
    }

`actions` is a filter, not a scope: it never makes an otherwise unbounded
mandate acceptable. `approval` turns an in-scope transaction into an "ask"
verdict until the issuer signs a step mandate for it (see `step_mandate`).

The 0.2 fields live under `constraints`, not beside `issued_at`, on purpose: a
0.1 verifier never reads the version field but does refuse constraint keys it
cannot enforce, so a 0.2 mandate fails closed on old code instead of having its
window start, usage limits, revocation list or delegation chain ignored.
"""

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

VERSION = "mandatekit/v0.2"
VERSION_V0 = "mandatekit/v0"
SUPPORTED_VERSIONS = (VERSION_V0, VERSION)
SPEC = "AP2-draft-2026Q2"

REVOCATION_LIST_VERSION = "mandatekit/revocation-list/v0.2"

# Amounts must fit JS's safe-integer range so RFC 8785 (JCS) can canonicalize
# them identically across languages.
MAX_SAFE_INT = 2 ** 53 - 1

# Keys allowed inside `limits`, `revocation` and `delegation`. Anything else is
# malformed (fail closed), like an unknown constraint key.
LIMIT_KEYS = (
    "actions",
    "max_uses",
    "max_total_amount",
    "window_seconds",
    "max_uses_per_window",
    "max_amount_per_window",
)
REVOCATION_KEYS = ("list_id", "max_age_seconds")
DELEGATION_KEYS = ("parent", "max_depth")

# Sentinel for delegate_mandate: "inherit the parent's value".
INHERIT: Any = object()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """UTC ISO-8601 with a trailing Z, second precision."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _checked_amount(name: str, amount: Dict) -> Dict:
    if not isinstance(amount, dict):
        raise ValueError(f"{name} must be {{value: integer, currency: string}}")
    value = amount.get("value")
    if not _is_int(value):
        raise ValueError(
            f"{name}.value must be an integer (amounts are compared like-for-like; "
            "pick a unit, e.g. cents or whole units, and use it consistently); "
            "floats are rejected to keep signatures canonical across languages"
        )
    if not 0 <= value <= MAX_SAFE_INT:
        raise ValueError(
            f"{name}.value must be between 0 and {MAX_SAFE_INT} (JS-safe integer range)"
        )
    return {"value": value, "currency": amount.get("currency", "USD")}


def _checked_counterparties(cps: Dict) -> Dict[str, List[str]]:
    if not isinstance(cps, dict):
        raise ValueError("counterparties must be an object mapping counterparty id to a list of verbs")
    out: Dict[str, List[str]] = {}
    for cid, verbs in cps.items():
        if not isinstance(cid, str) or not cid:
            raise ValueError("counterparties keys must be non-empty strings")
        if not isinstance(verbs, list) or not all(isinstance(v, str) for v in verbs):
            raise ValueError(f"counterparties[{cid!r}] must be a list of verb strings")
        out[cid] = list(verbs)
    return out


def _checked_limits(limits: Dict) -> Dict:
    if not isinstance(limits, dict):
        raise ValueError("limits must be an object")
    unknown = sorted(set(limits) - set(LIMIT_KEYS))
    if unknown:
        raise ValueError(f"limits has unknown key(s): {unknown}")
    out: Dict = {}
    if "actions" in limits:
        acts = limits["actions"]
        if not isinstance(acts, list) or not all(isinstance(a, str) for a in acts):
            raise ValueError("limits.actions must be a list of verb strings")
        out["actions"] = list(acts)
    for key in ("max_uses", "max_uses_per_window"):
        if key in limits:
            v = limits[key]
            if not _is_int(v) or v < 0 or v > MAX_SAFE_INT:
                raise ValueError(f"limits.{key} must be a non-negative integer")
            out[key] = v
    if "window_seconds" in limits:
        w = limits["window_seconds"]
        if not _is_int(w) or w < 1 or w > MAX_SAFE_INT:
            raise ValueError("limits.window_seconds must be a positive integer")
        out["window_seconds"] = w
    for key in ("max_total_amount", "max_amount_per_window"):
        if key in limits:
            out[key] = _checked_amount(f"limits.{key}", limits[key])
    if ("max_uses_per_window" in out or "max_amount_per_window" in out) and "window_seconds" not in out:
        raise ValueError("limits: per-window limits need window_seconds")
    if not any(k in out for k in LIMIT_KEYS if k not in ("actions", "window_seconds")):
        raise ValueError("limits must declare at least one limit")
    return out


def _checked_revocation(rev: Dict) -> Dict:
    if not isinstance(rev, dict):
        raise ValueError("revocation must be an object")
    unknown = sorted(set(rev) - set(REVOCATION_KEYS))
    if unknown:
        raise ValueError(f"revocation has unknown key(s): {unknown}")
    list_id = rev.get("list_id")
    if not isinstance(list_id, str) or not list_id:
        raise ValueError("revocation.list_id must be a non-empty string")
    out: Dict = {"list_id": list_id}
    if "max_age_seconds" in rev:
        age = rev["max_age_seconds"]
        if not _is_int(age) or age < 1 or age > MAX_SAFE_INT:
            raise ValueError("revocation.max_age_seconds must be a positive integer")
        out["max_age_seconds"] = age
    return out


def _checked_max_depth(depth) -> int:
    if not _is_int(depth) or depth < 0 or depth > MAX_SAFE_INT:
        raise ValueError("delegation.max_depth must be a non-negative integer")
    return depth


def _public_key_b64(key) -> str:
    if isinstance(key, (bytes, bytearray)):
        if len(key) != 32:
            raise ValueError("agent_public_key must be a raw 32-byte Ed25519 public key or its base64")
        return base64.b64encode(bytes(key)).decode("ascii")
    if isinstance(key, str) and key:
        return key
    raise ValueError("agent_public_key must be bytes or a base64 string")


def _subject(agent_id: str, agent_public_key) -> Dict:
    subject: Dict = {"agent_id": agent_id}
    if agent_public_key is not None:
        subject["public_key"] = _public_key_b64(agent_public_key)
    return subject


def _constraints(
    *,
    intent=None,
    categories=None,
    merchants=None,
    counterparties=None,
    max_amount=None,
    actions=None,
    approval=None,
    not_before=None,
    limits=None,
    revocation=None,
) -> Dict:
    constraints: Dict = {}
    if intent:
        constraints["intent"] = intent
    if categories:
        constraints["categories"] = list(categories)
    if merchants and (merchants.get("allow") or merchants.get("deny")):
        constraints["merchants"] = {
            k: list(v) for k, v in merchants.items() if v
        }
    if counterparties is not None:
        constraints["counterparties"] = _checked_counterparties(counterparties)
    if max_amount:
        constraints["max_amount"] = _checked_amount("max_amount", max_amount)
    if actions is not None:
        constraints["actions"] = list(actions)
    if approval and (approval.get("actions") or approval.get("above")):
        constraints["approval"] = {}
        if approval.get("actions"):
            constraints["approval"]["actions"] = list(approval["actions"])
        if approval.get("above"):
            constraints["approval"]["above"] = _checked_amount("approval.above", approval["above"])
    if not_before is not None:
        constraints["not_before"] = not_before if isinstance(not_before, str) else iso(not_before)
    if limits is not None:
        constraints["limits"] = _checked_limits(limits)
    if revocation is not None:
        constraints["revocation"] = _checked_revocation(revocation)
    return constraints


def build_mandate(
    *,
    agent_id: str,
    intent: Optional[str] = None,
    categories: Optional[List[str]] = None,
    merchants: Optional[Dict[str, List[str]]] = None,
    counterparties: Optional[Dict[str, List[str]]] = None,
    max_amount: Optional[Dict] = None,
    actions: Optional[List[str]] = None,
    approval: Optional[Dict] = None,
    not_before: Optional[datetime] = None,
    limits: Optional[Dict] = None,
    revocation: Optional[Dict] = None,
    delegation: Optional[Dict] = None,
    agent_public_key=None,
    issued_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    ttl_days: int = 30,
    mandate_id: Optional[str] = None,
) -> Dict:
    """Build a root mandate (one the issuer signs directly).

    `counterparties` scopes verbs per counterparty: `{"harbourline": ["read",
    "submit", "transfer"]}` lets the agent read from and submit to the bank
    without the bank becoming a valid payee. `merchants.allow` (0.1) still
    works and means "every allowed verb" at those merchants.

    `delegation={"max_depth": n}` lets the subject sign up to `n` levels of
    child mandates with the key in `agent_public_key`; without it the mandate
    cannot be delegated. See `delegate_mandate`.
    """
    issued = issued_at or _now()
    expires = expires_at or (issued + timedelta(days=ttl_days))

    constraints = _constraints(
        intent=intent, categories=categories, merchants=merchants,
        counterparties=counterparties, max_amount=max_amount, actions=actions,
        approval=approval, not_before=not_before, limits=limits, revocation=revocation,
    )
    if delegation is not None:
        if not isinstance(delegation, dict) or set(delegation) != {"max_depth"}:
            raise ValueError("a root mandate's delegation must be {max_depth: integer}; children come from delegate_mandate")
        if agent_public_key is None:
            raise ValueError("a delegable mandate needs agent_public_key, the key its subject will sign children with")
        constraints["delegation"] = {"max_depth": _checked_max_depth(delegation["max_depth"])}

    return {
        "version": VERSION,
        "spec": SPEC,
        "mandate_id": mandate_id or str(uuid.uuid4()),
        "subject": _subject(agent_id, agent_public_key),
        "issued_at": iso(issued),
        "expires_at": iso(expires),
        "constraints": constraints,
    }


def delegate_mandate(
    parent: Dict,
    *,
    agent_id: str,
    agent_public_key=None,
    max_depth: Optional[int] = None,
    intent=INHERIT,
    categories=INHERIT,
    merchants=INHERIT,
    counterparties=INHERIT,
    max_amount=INHERIT,
    actions=INHERIT,
    approval=INHERIT,
    not_before=INHERIT,
    limits=INHERIT,
    revocation=None,
    issued_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    mandate_id: Optional[str] = None,
) -> Dict:
    """Build a child mandate under a signed parent, for the parent's subject to sign.

    Every scope argument left at INHERIT copies the parent's value, so a child
    with no overrides has exactly the parent's scope; pass a value to narrow it
    or None to drop it. The verifier refuses a child that widens its parent on
    any axis, so narrowing here is a convenience, not the enforcement.
    `expires_at` defaults to the parent's. The child's `delegation` is
    `{"parent": <the signed parent>}` plus `max_depth` when it may delegate
    further (needs `agent_public_key`).
    """
    if not isinstance(parent, dict) or not isinstance(parent.get("mandate"), dict):
        raise ValueError("delegate_mandate needs the signed parent envelope")
    pm = parent["mandate"]
    pc = pm.get("constraints") if isinstance(pm.get("constraints"), dict) else {}

    def pick(value, key):
        return pc.get(key) if value is INHERIT else value

    issued = issued_at or _now()
    expires = expires_at or parse_iso(pm["expires_at"])
    constraints = _constraints(
        intent=pick(intent, "intent"),
        categories=pick(categories, "categories"),
        merchants=pick(merchants, "merchants"),
        counterparties=pick(counterparties, "counterparties"),
        max_amount=pick(max_amount, "max_amount"),
        actions=pick(actions, "actions"),
        approval=pick(approval, "approval"),
        not_before=pick(not_before, "not_before"),
        limits=pick(limits, "limits"),
        revocation=revocation,
    )
    delegation: Dict = {"parent": parent}
    if max_depth is not None:
        if agent_public_key is None:
            raise ValueError("a child that may delegate further needs agent_public_key")
        delegation["max_depth"] = _checked_max_depth(max_depth)
    constraints["delegation"] = delegation
    return {
        "version": VERSION,
        "spec": SPEC,
        "mandate_id": mandate_id or str(uuid.uuid4()),
        "subject": _subject(agent_id, agent_public_key),
        "issued_at": iso(issued),
        "expires_at": iso(expires),
        "constraints": constraints,
    }


def build_revocation_list(
    *,
    list_id: str,
    revoked: List[str],
    issued_at: Optional[datetime] = None,
) -> Dict:
    """An issuer-signed list of revoked mandate ids. Sign it with
    `sign_revocation_list` using the key that signed the mandates it revokes."""
    if not isinstance(list_id, str) or not list_id:
        raise ValueError("list_id must be a non-empty string")
    if not isinstance(revoked, (list, tuple)) or not all(isinstance(r, str) for r in revoked):
        raise ValueError("revoked must be a list of mandate id strings")
    return {
        "version": REVOCATION_LIST_VERSION,
        "list_id": list_id,
        "issued_at": iso(issued_at or _now()),
        "revoked": list(revoked),
    }


_AMOUNT_SCHEMA = {
    "type": "object",
    "required": ["value", "currency"],
    "properties": {
        "value": {"type": "integer", "description": "caller-chosen unit, used consistently for cap and transaction"},
        "currency": {"type": "string"},
    },
}

MANDATE_SCHEMA: Dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "MandateKit mandate (v0.2)",
    "type": "object",
    "required": [
        "version",
        "spec",
        "mandate_id",
        "subject",
        "issued_at",
        "expires_at",
        "constraints",
    ],
    "properties": {
        "version": {"enum": list(SUPPORTED_VERSIONS)},
        "spec": {"type": "string"},
        "mandate_id": {"type": "string"},
        "subject": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {"type": "string"},
                "public_key": {"type": "string", "description": "base64 Ed25519 key the subject signs child mandates with"},
            },
        },
        "issued_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "constraints": {
            "type": "object",
            "properties": {
                "intent": {"type": "string"},
                "categories": {"type": "array", "items": {"type": "string"}},
                "merchants": {
                    "type": "object",
                    "properties": {
                        "allow": {"type": "array", "items": {"type": "string"}},
                        "deny": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "counterparties": {
                    "type": "object",
                    "additionalProperties": {"type": "array", "items": {"type": "string"}},
                    "description": "counterparty id to the verbs allowed there",
                },
                "max_amount": _AMOUNT_SCHEMA,
                "actions": {"type": "array", "items": {"type": "string"}},
                "approval": {
                    "type": "object",
                    "properties": {
                        "actions": {"type": "array", "items": {"type": "string"}},
                        "above": _AMOUNT_SCHEMA,
                    },
                },
                "not_before": {"type": "string", "format": "date-time"},
                "limits": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "actions": {"type": "array", "items": {"type": "string"}},
                        "max_uses": {"type": "integer", "minimum": 0},
                        "max_total_amount": _AMOUNT_SCHEMA,
                        "window_seconds": {"type": "integer", "minimum": 1},
                        "max_uses_per_window": {"type": "integer", "minimum": 0},
                        "max_amount_per_window": _AMOUNT_SCHEMA,
                    },
                },
                "revocation": {
                    "type": "object",
                    "required": ["list_id"],
                    "additionalProperties": False,
                    "properties": {
                        "list_id": {"type": "string"},
                        "max_age_seconds": {"type": "integer", "minimum": 1},
                    },
                },
                "delegation": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "parent": {"type": "object", "description": "the signed parent envelope"},
                        "max_depth": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
    },
}


def validate(mandate: Dict) -> List[str]:
    """Dependency-free structural check. Returns a list of problems ([] == valid)."""
    errors: List[str] = []
    if not isinstance(mandate, dict):
        return ["mandate must be an object"]
    for field in MANDATE_SCHEMA["required"]:
        if field not in mandate:
            errors.append(f"missing required field: {field}")
    if mandate.get("version") not in SUPPORTED_VERSIONS:
        errors.append(f"version must be one of {list(SUPPORTED_VERSIONS)!r}")
    subject = mandate.get("subject")
    if not isinstance(subject, dict) or not subject.get("agent_id"):
        errors.append("subject.agent_id is required")
    elif "public_key" in subject and (not isinstance(subject["public_key"], str) or not subject["public_key"]):
        errors.append("subject.public_key must be a base64 string")
    for field in ("issued_at", "expires_at"):
        if field in mandate:
            try:
                parse_iso(mandate[field])
            except Exception:
                errors.append(f"{field} is not a valid ISO-8601 datetime")
    c = mandate.get("constraints")
    if not isinstance(c, dict):
        errors.append("constraints must be an object")
    else:
        ma = c.get("max_amount")
        if ma is not None and not _amount_ok(ma):
            errors.append(
                "max_amount must be {value:integer in [0, 2**53-1], currency:string}"
            )
        ap = c.get("approval")
        ab = ap.get("above") if isinstance(ap, dict) else None
        if ab is not None and not _amount_ok(ab):
            errors.append(
                "approval.above must be {value:integer in [0, 2**53-1], currency:string}"
            )
        if "counterparties" in c:
            try:
                _checked_counterparties(c["counterparties"])
            except ValueError as e:
                errors.append(str(e))
        if "not_before" in c:
            try:
                parse_iso(c["not_before"])
            except Exception:
                errors.append("not_before is not a valid ISO-8601 datetime")
        if "limits" in c:
            try:
                _checked_limits(c["limits"])
            except ValueError as e:
                errors.append(str(e))
        if "revocation" in c:
            try:
                _checked_revocation(c["revocation"])
            except ValueError as e:
                errors.append(str(e))
        if "delegation" in c:
            d = c["delegation"]
            if not isinstance(d, dict) or not d or set(d) - set(DELEGATION_KEYS):
                errors.append("delegation must be {parent?: signed mandate, max_depth?: integer}")
            else:
                if "max_depth" in d and not (_is_int(d["max_depth"]) and 0 <= d["max_depth"] <= MAX_SAFE_INT):
                    errors.append("delegation.max_depth must be a non-negative integer")
                if "parent" in d and not (isinstance(d["parent"], dict) and isinstance(d["parent"].get("mandate"), dict)):
                    errors.append("delegation.parent must be a signed mandate envelope")
    return errors


def _amount_ok(a) -> bool:
    if not isinstance(a, dict):
        return False
    v = a.get("value")
    return (
        _is_int(v)
        and 0 <= v <= MAX_SAFE_INT
        and bool(a.get("currency"))
    )


def step_mandate(
    parent: Dict,
    target: Dict,
    *,
    issued_at: Optional[datetime] = None,
    ttl_minutes: int = 15,
    mandate_id: Optional[str] = None,
) -> Dict:
    """Narrow a parent mandate to exactly one transaction.

    The result is an ordinary mandate for the same agent whose scope is the
    target's action, merchant, category and amount, with a short validity
    window. The issuer signs it, and the agent presents it as
    ``transaction["approval"]`` to satisfy an "ask" verdict. This is the
    human-present confirmation of AP2 (an intent mandate narrowed to a cart)
    and the step-up of a payment flow, in the kit's own format.
    """
    if ttl_minutes <= 0:
        raise ValueError("ttl_minutes must be positive")
    issued = issued_at or _now()
    constraints: Dict = {}
    if target.get("action"):
        constraints["actions"] = [target["action"]]
    if target.get("merchant"):
        constraints["merchants"] = {"allow": [target["merchant"]]}
    if target.get("category"):
        constraints["categories"] = [target["category"]]
    if target.get("amount"):
        constraints["max_amount"] = _checked_amount("amount", target["amount"])
    if not any(k in constraints for k in ("merchants", "categories", "max_amount")):
        raise ValueError("a step mandate needs a merchant, category or amount to be scoped to")
    what = target.get("description")
    if what is None:
        what = " ".join(x for x in (target.get("action"), target.get("merchant")) if x)
    constraints["intent"] = f"approve {parent['mandate_id']}" + (f": {what}" if what else "")
    return {
        "version": VERSION,
        "spec": SPEC,
        "mandate_id": mandate_id or str(uuid.uuid4()),
        "subject": {"agent_id": parent["subject"]["agent_id"]},
        "issued_at": iso(issued),
        "expires_at": iso(issued + timedelta(minutes=ttl_minutes)),
        "constraints": constraints,
    }
