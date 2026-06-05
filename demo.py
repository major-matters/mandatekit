"""
MandateKit v0 - narrated end-to-end demo.

Run from the python package dir so `mandatekit` is importable:

    cd python && PYTHONPATH=. python3 ../demo.py

It compiles one natural-language instruction into a signed mandate, then runs a
handful of transactions past the verifier so you can see allow vs deny and why.
Nothing here touches the network; the LLM layer is not used.
"""

import json
from datetime import datetime, timezone

from mandatekit import compile, generate_keypair, verify

LINE = "-" * 72


def show(title):
    print(f"\n{LINE}\n{title}\n{LINE}")


# A fixed "now" so the demo output is stable.
NOW = datetime(2026, 6, 5, 12, 0, 0, tzinfo=timezone.utc)

show("1. Generate a signing key (the private half never leaves this machine)")
private_key, public_key = generate_keypair()
print(f"  public key:  {public_key.hex()[:32]}...  (shareable)")
print(f"  private key: {private_key.hex()[:16]}...           (kept local)")

show("2. Compile a plain-English instruction into a signed mandate")
instruction = (
    "Allow this agent to buy running shoes from any apparel retailer "
    "up to $500 per transaction, expires June 30"
)
print(f'  instruction: "{instruction}"')
signed = compile(instruction, agent_id="agent-7", private_key=private_key, now=NOW)
print("\n  signed mandate:")
print("\n".join("    " + ln for ln in json.dumps(signed, indent=2).splitlines()))

show("3. Verify transactions against the mandate")
transactions = [
    ("in scope", {"merchant": "Fleet Feet", "category": "apparel",
                  "amount": {"value": 240, "currency": "USD"},
                  "description": "Brooks Ghost 16 running shoes"}),
    ("over the $500 cap", {"merchant": "Fleet Feet", "category": "apparel",
                           "amount": {"value": 600, "currency": "USD"}}),
    ("wrong category", {"merchant": "BestBuy", "category": "electronics",
                        "amount": {"value": 100, "currency": "USD"}}),
]
for label, txn in transactions:
    v = verify(signed, txn, now=NOW, trusted_keys=[public_key])
    flag = "ALLOW" if v["decision"] == "allow" else "DENY "
    print(f"  [{flag}] {label:<20} score={v['scope_match_score']:<4}  {v['rationale']}")

show("4. Tamper with a signed mandate -> signature check catches it")
tampered = json.loads(json.dumps(signed))
tampered["mandate"]["constraints"]["max_amount"]["value"] = 100000
v = verify(tampered, {"merchant": "Anywhere", "category": "apparel",
                      "amount": {"value": 9000, "currency": "USD"}},
           now=NOW, trusted_keys=[public_key])
print(f"  raised the cap to $100,000 after signing -> decision: {v['decision'].upper()}")
print(f"  {v['rationale']}")

show("5. Optional intent-basket alignment (here a stub; in practice an LLM call)")
txn = {"merchant": "Fleet Feet", "category": "apparel",
       "amount": {"value": 240, "currency": "USD"}, "description": "a garden hose"}
for score in (0.1, 0.9):
    v = verify(signed, txn, now=NOW, trusted_keys=[public_key],
               intent_scorer=lambda intent, t: score)
    print(f"  intent alignment {score} -> {v['decision'].upper()}  ({v['rationale']})")

print(f"\n{LINE}\nThat is MandateKit v0: compile -> sign -> verify, deterministic and local.\n{LINE}")
