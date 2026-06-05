"""
Live smoke test for the optional LLM layer (mandatekit.llm).

This is NOT part of the default test run: it needs network and a real key, so it
stays out of `pytest` / the standalone runner. Run it deliberately:

    ANTHROPIC_API_KEY=sk-... PYTHONPATH=. python3 tests/smoke_llm.py

It exercises the two off-the-shelf-LLM paths end to end:
  1. anthropic_parser  — free-form phrasing the rule-based parser would miss
  2. anthropic_intent_scorer — intent-basket alignment used by verify()
and proves compile()+verify() work with them, with issuer pinning.
"""

import os
import sys
from datetime import datetime, timezone

from mandatekit import compile, generate_keypair, verify
from mandatekit.mandate import validate
from mandatekit.signing import _b64
from mandatekit import ed25519
from mandatekit.llm import anthropic_parser, anthropic_intent_scorer

NOW = datetime(2026, 6, 5, 12, 0, 0, tzinfo=timezone.utc)


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("SKIP: set ANTHROPIC_API_KEY to run the live LLM smoke test")
        return 0

    priv, pub = generate_keypair()
    pinned = dict(now=NOW, trusted_keys=[pub])
    failures = 0

    def check(name, cond, detail=""):
        nonlocal failures
        print(f"  {'PASS' if cond else 'FAIL'}  {name}  {detail}")
        if not cond:
            failures += 1

    print("1. anthropic_parser on free-form phrasing the rule parser would miss")
    text = ("let the assistant pick up groceries from Whole Foods or Trader Joe's, "
            "nothing over 75 dollars, good through the end of July")
    parsed = anthropic_parser(text)
    print(f"     parsed: {parsed}")
    check("returns categories or merchants", bool(parsed.get("categories") or parsed.get("merchants")))
    check("captured the $75 cap", (parsed.get("max_amount") or {}).get("value") == 75,
          f"got {(parsed.get('max_amount') or {}).get('value')}")
    exp = parsed.get("expires_at")
    check("relative expiry resolves to the future, not a past year",
          exp is not None and exp > datetime.now(timezone.utc), f"got {exp}")

    print("2. compile() with the LLM parser -> valid signed mandate")
    signed = compile(text, agent_id="agent-7", private_key=priv, parser=anthropic_parser, now=NOW)
    check("mandate validates", validate(signed["mandate"]) == [])
    check("signature pins issuer", signed["signature"]["public_key"] == _b64(ed25519.publickey(priv)))

    print("3. anthropic_intent_scorer returns a sane [0,1] alignment")
    intent = "buy running shoes"
    aligned = anthropic_intent_scorer(intent, {"merchant": "Fleet Feet", "category": "apparel",
                                               "description": "Brooks Ghost 16 running shoes"})
    unaligned = anthropic_intent_scorer(intent, {"merchant": "Home Depot", "category": "hardware",
                                                 "description": "a garden hose"})
    print(f"     aligned={aligned}  unaligned={unaligned}")
    check("scores in [0,1]", 0.0 <= aligned <= 1.0 and 0.0 <= unaligned <= 1.0)
    check("aligned scores higher than unaligned", aligned > unaligned, f"{aligned} > {unaligned}")

    print("4. end-to-end: LLM-compiled mandate + LLM intent scorer through verify()")
    shoe_mandate = compile("buy running shoes from any apparel retailer up to 500 dollars",
                           agent_id="a", private_key=priv, parser=anthropic_parser, now=NOW)
    good = verify(shoe_mandate, {"merchant": "Fleet Feet", "category": "apparel",
                                 "amount": {"value": 240, "currency": "USD"},
                                 "description": "Brooks Ghost 16 running shoes"},
                  intent_scorer=anthropic_intent_scorer, **pinned)
    bad = verify(shoe_mandate, {"merchant": "Fleet Feet", "category": "apparel",
                                "amount": {"value": 240, "currency": "USD"},
                                "description": "a garden hose"},
                 intent_scorer=anthropic_intent_scorer, **pinned)
    print(f"     shoes -> {good['decision']} (intent {good['intent_alignment']});  "
          f"garden hose -> {bad['decision']} (intent {bad['intent_alignment']})")
    check("genuine shoe purchase allowed", good["decision"] == "allow")
    check("off-intent purchase denied by intent score", bad["decision"] == "deny")

    print(f"\n{'ALL LLM SMOKE CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
