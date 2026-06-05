"""
Optional off-the-shelf LLM layer.

Two helpers, both backed by a stock Claude model (no fine-tuning, no custom
weights). They are entirely optional: the compiler works with the deterministic
`rule_based_parser`, and the verifier works without intent scoring. Import this
only when you want natural-language flexibility.

    from mandatekit.llm import anthropic_parser, anthropic_intent_scorer
    signed = compile(text, agent_id=..., private_key=..., parser=anthropic_parser)
    verdict = verify(signed, txn, intent_scorer=anthropic_intent_scorer)

Requires `anthropic` installed and ANTHROPIC_API_KEY set. The import of
`anthropic` is lazy so the rest of MandateKit stays dependency-free.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict

from .mandate import parse_iso

DEFAULT_MODEL = "claude-haiku-4-5-20251001"

_PARSE_SYSTEM = """You convert a natural-language spending instruction into a strict JSON constraints object for an AI-agent payment mandate. Output ONLY JSON, no prose.

Schema:
{
  "intent": string | null,                 // the natural-language purchase intent, e.g. "buy running shoes"
  "categories": string[] | null,           // allowed merchant categories, lowercase singular nouns
  "merchants": {"allow": string[], "deny": string[]} | null,
  "max_amount": {"value": integer, "currency": "USD"|"GBP"|"EUR"|...} | null,   // integer in the unit stated
  "expires_at": string | null              // ISO-8601 date or datetime, or null
}

Omit a field (use null) when the instruction does not mention it. Do not invent constraints. max_amount.value must be an integer in the unit the user stated; do NOT convert units (e.g. "$500" -> 500). If the amount has sub-unit precision (e.g. "$4.99"), round to the nearest integer."""


def _client():
    import anthropic  # lazy

    return anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def _extract_json(raw: str) -> Dict:
    """Pull a JSON object out of a model response, tolerating code fences and
    surrounding prose. Pure and offline-testable (the fragile part of the path)."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw[3:]
        if raw[:4].lower() == "json":
            raw = raw[4:]
        if "```" in raw:
            raw = raw[: raw.rindex("```")]
        raw = raw.strip()
    if not raw.startswith("{"):
        start, end = raw.find("{"), raw.rfind("}")
        if start != -1 and end > start:
            raw = raw[start : end + 1]
    return json.loads(raw)


def _constraints_from_data(data: Dict) -> Dict:
    """Map a parsed JSON object to the constraints dict `rule_based_parser` returns."""
    out: Dict = {}
    for key in ("intent", "categories", "merchants", "max_amount"):
        if data.get(key):
            out[key] = data[key]
    if data.get("expires_at"):
        try:
            out["expires_at"] = parse_iso(data["expires_at"])
        except Exception:
            pass
    return out


def anthropic_parser(text: str, model: str = DEFAULT_MODEL) -> Dict:
    """LLM parse of arbitrary phrasing into the same dict `rule_based_parser` returns."""
    # The model has no clock: anchor relative dates ("end of July") to today, or
    # it defaults to its training era and emits an already-expired mandate.
    today = datetime.now(timezone.utc).date().isoformat()
    system = (
        _PARSE_SYSTEM
        + f"\n\nToday's date is {today} (UTC). Resolve every relative date "
        "(e.g. 'end of July', 'next Friday', 'in 30 days') against it, and never "
        "return a date in the past."
    )
    resp = _client().messages.create(
        model=model,
        max_tokens=512,
        system=system,
        messages=[{"role": "user", "content": text}],
    )
    return _constraints_from_data(_extract_json(resp.content[0].text))


_SCORE_SYSTEM = """You score how well a transaction matches a stated purchase intent for an AI agent. Return ONLY a number between 0 and 1, where 1 means the purchase clearly fulfils the intent and 0 means it is unrelated. No prose."""


def anthropic_intent_scorer(
    intent: str, transaction: Dict, model: str = DEFAULT_MODEL
) -> float:
    """Off-the-shelf intent-basket alignment score in [0, 1]."""
    desc = transaction.get("description") or transaction.get("merchant") or ""
    user = f"Intent: {intent}\nTransaction: {desc} (merchant: {transaction.get('merchant')}, category: {transaction.get('category')})"
    resp = _client().messages.create(
        model=model,
        max_tokens=8,
        system=_SCORE_SYSTEM,
        messages=[{"role": "user", "content": user}],
    )
    try:
        return max(0.0, min(1.0, float(resp.content[0].text.strip().split()[0])))
    except Exception:
        return 0.0
