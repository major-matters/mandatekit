"""
The compiler: natural language -> mandate -> signed payload.

    "Allow this agent to buy running shoes from any apparel retailer
     up to $500 per transaction, expires June 30"

becomes a signed mandate the protocol can accept.

Two parsing paths share one output shape:

  * `rule_based_parser` (default) - deterministic regex parsing. Zero
    dependencies, no network, handles the common constraint patterns. Good
    enough for tests, demos, and offline use.
  * an LLM parser (see `mandatekit.llm.anthropic_parser`) - an off-the-shelf
    model call for arbitrary phrasing. Pass it as `parser=`. No fine-tuned model
    is involved; the LLM only turns prose into the same constraints dict.

Either way the parsed constraints are assembled into a mandate and signed
locally. The signing key never leaves the device.
"""

import re
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

from .mandate import build_mandate
from .signing import sign_mandate

ParsedConstraints = Dict
Parser = Callable[[str], ParsedConstraints]

_CURRENCY_SYMBOLS = {"$": "USD", "£": "GBP", "€": "EUR"}
_CURRENCY_WORDS = {
    "dollar": "USD",
    "dollars": "USD",
    "usd": "USD",
    "pound": "GBP",
    "pounds": "GBP",
    "gbp": "GBP",
    "euro": "EUR",
    "euros": "EUR",
    "eur": "EUR",
}
_CATEGORY_WORDS = {
    "apparel",
    "clothing",
    "electronics",
    "groceries",
    "grocery",
    "travel",
    "software",
    "books",
    "food",
    "hardware",
    "office",
}
_CATEGORY_ALIASES = {"clothing": "apparel", "grocery": "groceries"}
_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        [
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
        ]
    )
}


def _parse_amount(text: str) -> Optional[Dict]:
    m = re.search(
        r"(?:up to|under|max(?:imum)?(?: of)?|no more than|≤|<=|below)\s*"
        r"([$£€])?\s*([\d,]+(?:\.\d{1,2})?)\s*([a-zA-Z]{3}|dollars?|pounds?|euros?)?",
        text,
        re.IGNORECASE,
    )
    if not m:
        return None
    symbol, number, word = m.groups()
    value = float(number.replace(",", ""))
    if value.is_integer():
        value = int(value)
    currency = "USD"
    if symbol:
        currency = _CURRENCY_SYMBOLS.get(symbol, "USD")
    elif word:
        currency = _CURRENCY_WORDS.get(word.lower(), word.upper()[:3])
    return {"value": value, "currency": currency}


def _parse_expiry(text: str, now: datetime) -> Optional[datetime]:
    m = re.search(
        r"expir\w*\s+(?:on\s+|by\s+|at\s+)?([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.I
    )
    if m:
        d = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        return d.replace(hour=23, minute=59, second=59)

    m = re.search(
        r"expir\w*\s+(?:on\s+|by\s+|at\s+)?"
        r"(?:(\d{1,2})\s+([A-Za-z]+)|([A-Za-z]+)\s+(\d{1,2}))",
        text,
        re.I,
    )
    if m:
        if m.group(1):
            day, month_name = int(m.group(1)), m.group(2)
        else:
            month_name, day = m.group(3), int(m.group(4))
        month = _MONTHS.get(month_name.lower())
        if month:
            year = now.year
            candidate = datetime(
                year, month, day, 23, 59, 59, tzinfo=timezone.utc
            )
            if candidate < now:  # a bare month/day in the past means next year
                candidate = candidate.replace(year=year + 1)
            return candidate
    return None


def _parse_categories(text: str):
    cats = []
    for m in re.finditer(
        r"any\s+([a-zA-Z]+)\s+(?:retailer|retailers|store|stores|merchant|merchants|shop|shops)",
        text,
        re.I,
    ):
        cats.append(m.group(1).lower())
    for word in _CATEGORY_WORDS:
        if re.search(rf"\b{word}\b", text, re.I):
            cats.append(word)
    normed = []
    for c in cats:
        c = _CATEGORY_ALIASES.get(c, c)
        if c not in normed:
            normed.append(c)
    return normed


# A merchant name is one or more consecutive Capitalized words ("Blue Bottle").
_NAME = r"[A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*)*"


def _parse_merchants(text: str):
    allow, deny = [], []
    m = re.search(rf"only (?:from|at)\s+({_NAME}(?:(?:,|\s+and)\s+{_NAME})*)", text)
    if m:
        allow = [s.strip() for s in re.split(r",\s*|\s+and\s+", m.group(1).strip()) if s.strip()]
    for m in re.finditer(rf"(?:not|never|except)\s+(?:from|at)\s+({_NAME})", text):
        deny.append(m.group(1).strip())
    return {"allow": allow, "deny": deny}


def _parse_intent(text: str) -> Optional[str]:
    m = re.search(
        r"\b(?:to\s+)?(buy|purchase|order|book|pay for|rent|subscribe to)\s+"
        r"(.+?)(?:\s+from\b|\s+at\b|\s+up to\b|\s+under\b|\s+expir|,|\.|$)",
        text,
        re.I,
    )
    if m:
        return f"{m.group(1).lower()} {m.group(2).strip()}".strip()
    return None


def rule_based_parser(text: str, now: Optional[datetime] = None) -> ParsedConstraints:
    """Deterministic, dependency-free parse of common constraint phrasings."""
    now = now or datetime.now(timezone.utc)
    out: ParsedConstraints = {}
    intent = _parse_intent(text)
    if intent:
        out["intent"] = intent
    cats = _parse_categories(text)
    if cats:
        out["categories"] = cats
    merchants = _parse_merchants(text)
    if merchants["allow"] or merchants["deny"]:
        out["merchants"] = merchants
    amount = _parse_amount(text)
    if amount:
        out["max_amount"] = amount
    expiry = _parse_expiry(text, now)
    if expiry:
        out["expires_at"] = expiry
    return out


def compile(
    text: str,
    *,
    agent_id: str,
    private_key: bytes,
    parser: Optional[Parser] = None,
    ttl_days: int = 30,
    now: Optional[datetime] = None,
) -> Dict:
    """Compile natural-language `text` into a signed mandate envelope."""
    parser = parser or rule_based_parser
    parsed = parser(text)
    mandate = build_mandate(
        agent_id=agent_id,
        intent=parsed.get("intent"),
        categories=parsed.get("categories"),
        merchants=parsed.get("merchants"),
        max_amount=parsed.get("max_amount"),
        issued_at=now,
        expires_at=parsed.get("expires_at"),
        ttl_days=ttl_days,
    )
    return sign_mandate(mandate, private_key)
