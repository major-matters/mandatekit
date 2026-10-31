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
    # Bounded repetition throughout (mirrors compiler.ts), and the amount must start with a
    # digit: "up to , 500" used to match "," alone, which crashed here (float("")) and gave
    # the TypeScript port a zero cap (Number("")).
    m = re.search(
        r"(?:up to|under|max(?:imum)?(?: of)?|no more than|≤|<=|below)\s{0,5}"
        r"([$£€])?\s{0,5}(\d[\d,]{0,19}(?:\.\d{1,2})?)\s{0,5}([a-zA-Z]{3}|dollars?|pounds?|euros?)?",
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
        r"expir\w{0,10}\s{1,5}(?:(?:on|by|at)\s{1,5})?(\d{4}-\d{2}-\d{2})", text, re.I
    )
    if m:
        try:
            d = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:  # "2026-13-45": not a calendar date; no expiry rather than a crash
            return None
        return d.replace(hour=23, minute=59, second=59)

    m = re.search(
        r"expir\w{0,10}\s{1,5}(?:(?:on|by|at)\s{1,5})?"
        r"(?:(\d{1,2})\s{1,5}([A-Za-z]{1,12})|([A-Za-z]{1,12})\s{1,5}(\d{1,2}))",
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
            try:
                candidate = datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
            except ValueError:  # "February 31"
                return None
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


# A merchant name is one to six consecutive Capitalized words ("Blue Bottle"), each up to 40
# characters. The bounds keep every regex built from it linear in the input length
# (same bounds as compiler.ts).
_NAME = r"[A-Z][\w&.'-]{0,40}(?:\s{1,3}[A-Z][\w&.'-]{0,40}){0,5}"


def _parse_merchants(text: str):
    allow, deny = [], []
    # No repeated groups: capture one bounded run of name characters, then walk it in code. The
    # run ends at the first lowercase word that is not "and" (for example "up", "under", "expiring").
    m = re.search(r"only (?:from|at)\s{1,5}([A-Z][\w&.,' -]{0,200})", text)
    if m:
        kept = []
        for w in m.group(1).split(" "):
            if w == "" or w == "and" or re.match(r"[A-Z]", w):
                kept.append(w)
            else:
                break
        # Plain string splits, no regex: commas and the word "and" separate names.
        joined = " ".join(w for w in kept if w != "")
        for part in joined.split(","):
            for name in part.split(" and "):
                t = name.strip()
                if t.endswith(" and"):
                    t = t[:-4].strip()
                if t:
                    allow.append(t)
    for dm in re.finditer(rf"(?:not|never|except)\s{{1,5}}(?:from|at)\s{{1,5}}({_NAME})", text):
        deny.append(dm.group(1).strip())
    return {"allow": allow, "deny": deny}


def _parse_intent(text: str) -> Optional[str]:
    m = re.search(
        r"\b(?:to\s{1,5})?(buy|purchase|order|book|pay for|rent|subscribe to)\s{1,5}"
        r"(.{1,200}?)(?:\s{1,5}from\b|\s{1,5}at\b|\s{1,5}up to\b|\s{1,5}under\b|\s{1,5}expir|,|\.|$)",
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
    # The default parser resolves relative dates ("expires June 30") against
    # `now` so a pinned clock gives a deterministic mandate. A custom parser
    # owns its own clock: the Parser contract stays single-argument.
    if parser is None:
        parsed = rule_based_parser(text, now=now)
    else:
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
