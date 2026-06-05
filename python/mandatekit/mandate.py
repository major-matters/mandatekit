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
        "max_amount": {"value": 500, "currency": "USD"}   # value: integer, caller-chosen unit
      }
    }
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

VERSION = "mandatekit/v0"
SPEC = "AP2-draft-2026Q2"


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


def build_mandate(
    *,
    agent_id: str,
    intent: Optional[str] = None,
    categories: Optional[List[str]] = None,
    merchants: Optional[Dict[str, List[str]]] = None,
    max_amount: Optional[Dict] = None,
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
        value = max_amount["value"]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(
                "max_amount.value must be an integer (amounts are compared like-for-like; "
                "pick a unit, e.g. cents or whole units, and use it consistently); "
                "floats are rejected to keep signatures canonical across languages"
            )
        constraints["max_amount"] = {
            "value": value,
            "currency": max_amount.get("currency", "USD"),
        }

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
        if ma is not None and (
            not isinstance(ma, dict)
            or not isinstance(ma.get("value"), int)
            or isinstance(ma.get("value"), bool)
            or not ma.get("currency")
        ):
            errors.append("max_amount must be {value:integer, currency:string}")
    return errors
