# MandateKit (Python) · v0

Sign and verify **scope-bound mandates for AI agents**. A mandate says, in
signed and machine-checkable form, exactly what an agent is allowed to spend on.
Before an agent's transaction clears, you verify it against the mandate.

> **v0, tracks the [AP2](https://github.com/google-agentic-commerce/AP2) Verifiable Intent draft** (finalization expected Q3 2026). Field names and scoring are MandateKit's own and will move as the spec settles. Expect breaking changes.

Signing uses the vetted, constant-time **`cryptography`** library and **RFC 8785**
canonicalization (`rfc8785`); pure-Python fallbacks keep it runnable with zero
deps for experimentation. The signing key never leaves your machine.

## Install

Not yet on PyPI (v0). Install from source:

```bash
git clone https://github.com/major-matters/mandatekit
pip install -e mandatekit/python              # core only
pip install -e "mandatekit/python[llm]"       # + off-the-shelf LLM parsing/scoring
```

Or just drop the `mandatekit/` folder next to your code — the core has no required deps.

## Quick start

```python
from mandatekit import generate_keypair, compile, verify

private_key, public_key = generate_keypair()      # private_key stays local

signed = compile(
    "Allow this agent to buy running shoes from any apparel retailer "
    "up to $500 per transaction, expires June 30",
    agent_id="agent-7",
    private_key=private_key,
)

verdict = verify(
    signed,
    {
        "merchant": "Fleet Feet",
        "category": "apparel",
        "amount": {"value": 240, "currency": "USD"},   # integer, same unit as the cap
        "description": "Brooks Ghost 16 running shoes",
    },
    trusted_keys=[public_key],   # pin the issuer — see Security below
)

print(verdict["decision"])           # "allow"
print(verdict["scope_match_score"])  # 1.0
print(verdict["rationale"])          # "in scope: within validity window; ..."
```

A $600 charge, an electronics merchant, an expired mandate, a payload edited
after signing, or a mandate signed by a key you did not pin all return `"deny"`
with a rationale naming the failed constraint.

## Security model (read this)

A valid signature proves **integrity**, not **authority** — it says the mandate
was not altered and that whoever holds the signing key signed it, not that you
trust that key. So:

- **Pin the issuer.** Pass `trusted_keys=[...]`. With neither `trusted_keys` nor
  an explicit `allow_unverified_issuer=True`, `verify()` **fails closed** and
  denies — otherwise anyone could mint a valid mandate by signing their own.
- **Absent scope is denied.** A mandate with no category/merchant/amount limit is
  unbounded and refused. An empty allow-list (`[]`) means "allow nothing".
- **Unknown constraint keys are denied** (fail-closed on anything v0 cannot
  enforce).
- **Amounts are integers**, compared like-for-like. Pick a unit (cents or whole
  units) and use it consistently for the cap and the transaction; the SDK does not
  interpret the unit. Floats are rejected so signatures stay canonical across
  Python and TypeScript.
- **No replay protection in v0.** `max_uses` and usage/velocity limits need the
  (roadmap) stateful registry; they are intentionally not in v0 rather than
  parsed-but-ignored.
- The pure-Python Ed25519 is the reference impl (not constant-time); swap in
  libsodium/`cryptography` for production.

## The two pieces

**The compiler** turns natural language into a signed mandate:
`natural language → JSON-Schema mandate → EdDSA-signed payload`. Parsing uses a
deterministic rule-based parser by default; pass `parser=anthropic_parser` (from
`mandatekit.llm`) for arbitrary phrasing via a stock LLM. Signing is always local.

**The verifier** is deterministic: same mandate + transaction → same verdict,
every time, with a human-readable rationale. It checks signature, expiry,
category, merchant allow/deny, and amount cap. The one fuzzy check —
intent-basket alignment ("do running shoes satisfy this intent?") — is optional
and injected via `intent_scorer=`; without it the verifier never lets a missing
model turn a deny into an allow.

**No fine-tuned model anywhere.** Where an LLM is used it is off-the-shelf and
optional. A fine-tuned verifier model is deliberately out of v0 scope.

## CLI

```bash
python -m mandatekit keygen > agent.key        # prints the public key to stderr
python -m mandatekit compile "buy coffee only from Blue Bottle up to $20, expires 2026-12-31" \
    --agent agent-7 --key agent.key > mandate.json
echo '{"merchant":"Blue Bottle","amount":{"value":5,"currency":"USD"}}' \
    | python -m mandatekit verify mandate.json - --trust <ISSUER_PUBKEY_B64>
```

`verify` fails closed without `--trust <pubkey>` (or `--allow-unverified-issuer`).

## Tests

```bash
PYTHONPATH=. python3 tests/test_mandatekit.py     # standalone, no pytest needed
# or
pytest
```

## License

MIT.
