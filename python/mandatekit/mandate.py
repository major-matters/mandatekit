"""
The mandate data model.

A mandate is a plain JSON-serializable dict so it travels over any transport and
signs deterministically. This module builds well-formed mandates, exposes the
JSON Schema, and provides a dependency-free structural validator.

Shape (tracks the AP2 Verifiable Intent draft; field names are MandateKit's own
until the spec finalizes):

    {
      "version": "mandatekit/v0",
      "spec": "AP2-draft-2026Q2",
      "mandate_id": "uuid4",
      "subject": {"agent_id": "..."},
      "issued_at": "2026-06-05T12:00:00Z",
      "expires_at": "2026-06-30T23:59:59Z",
      "constraints": {
        "intent": "buy running shoes",          # natural-language intent basket
        "categories": ["apparel"],               # allowed merchant categories
        "merchants": {"allow": [...], "deny": [...]},   # optional
        "max_amount": {"value": 500, "currency": "USD"},  # value: integer, caller-chosen unit
        "actions": ["read", "draft", "pay"],             # optional allow-list of verbs
        "approval": {                                    # optional step-up rules
          "actions": ["cancel"],                         #   these verbs need a step mandate
          "above": {"value": 200, "currency": "USD"}     #   and so do amounts above this
        }
      }
    }

`actions` is a filter, not a scope: it never makes an otherwise unbounded
mandate acceptable. `approval` turns an in-scope transaction into an "ask"
verdict until the issuer signs a step mandate for it (see `step_mandate`).
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

VERSION = "mandatekit/v0"
SPEC = "AP2-draft-2026Q2"

# Amounts must fit JS's safe-integer range so RFC 8785 (JCS) can canonicalize
# them identically across languages.
MAX_SAFE_INT = 2 ** 53 - 1


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


def _checked_amount(name: str, amount: Dict) -> Dict:
    value = amount["value"]
    if not isinstance(value, int) or isinstance(value, bool):
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


def build_mandate(
    *,
    agent_id: str,
    intent: Optional[str] = None,
    categories: Optional[List[str]] = None,
    merchants: Optional[Dict[str, List[str]]] = None,
    max_amount: Optional[Dict] = None,
    actions: Optional[List[str]] = None,
    approval: Optional[Dict] = None,
    issued_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    ttl_days: int = 30,
    mandate_id: Optional[str] = None,
) -> Dict:
    issued = issued_at or _now()
    expires = expires_at or (issued + timedelta(days=ttl_days))

    constraints: Dict = {}
    if intent:
        constraints["intent"] = intent
    if categories:
        constraints["categories"] = list(categories)
    if merchants and (merchants.get("allow") or merchants.get("deny")):
        constraints["merchants"] = {
            k: list(v) for k, v in merchants.items() if v
        }
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

    return {
        "version": VERSION,
        "spec": SPEC,
        "mandate_id": mandate_id or str(uuid.uuid4()),
        "subject": {"agent_id": agent_id},
        "issued_at": iso(issued),
        "expires_at": iso(expires),
        "constraints": constraints,
    }


MANDATE_SCHEMA: Dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "MandateKit mandate (v0)",
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
        "version": {"const": VERSION},
        "spec": {"type": "string"},
        "mandate_id": {"type": "string"},
        "subject": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {"agent_id": {"type": "string"}},
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
                "max_amount": {
                    "type": "object",
                    "required": ["value", "currency"],
                    "properties": {
                        "value": {"type": "integer", "description": "caller-chosen unit, used consistently for cap and transaction"},
                        "currency": {"type": "string"},
                    },
                },
                "actions": {"type": "array", "items": {"type": "string"}},
                "approval": {
                    "type": "object",
                    "properties": {
                        "actions": {"type": "array", "items": {"type": "string"}},
                        "above": {
                            "type": "object",
                            "required": ["value", "currency"],
                            "properties": {
                                "value": {"type": "integer"},
                                "currency": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    },
}


def validate(mandate: Dict) -> List[str]:
    """Dependency-free structural check. Returns a list of problems ([] == valid)."""
    errors: List[str] = []
    for field in MANDATE_SCHEMA["required"]:
        if field not in mandate:
            errors.append(f"missing required field: {field}")
    if mandate.get("version") != VERSION:
        errors.append(f"version must be {VERSION!r}")
    subject = mandate.get("subject")
    if not isinstance(subject, dict) or not subject.get("agent_id"):
        errors.append("subject.agent_id is required")
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
    return errors


def _amount_ok(a) -> bool:
    if not isinstance(a, dict):
        return False
    v = a.get("value")
    return (
        isinstance(v, int)
        and not isinstance(v, bool)
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
