# MandateKit (Python) · v0

Sign and verify **scope-bound mandates for AI agents**. A mandate says, in
signed and machine-checkable form, exactly what an agent is allowed to spend on.
Before an agent's transaction clears, you verify it against the mandate.

> **v0, tracks the [AP2](https://github.com/google-agentic-commerce/AP2) Verifiable Intent draft** (finalization expected Q3 2026). Field names and scoring are MandateKit's own and will move as the spec settles. Expect breaking changes.

Signing uses the vetted, constant-time **`cryptography`** library and **RFC 8785**
canonicalization (`rfc8785`); pure-Python fallbacks keep it runnable with zero
deps for experimentation. The signing key never leaves your machine.

## Install

```bash
pip install mandatekit            # core
pip install "mandatekit[llm]"     # + off-the-shelf LLM parsing/scoring
```

Or from source:

```bash
git clone https://github.com/major-matters/mandatekit
pip install -e mandatekit/python
```

Or just drop the `mandatekit/` folder next to your code: the core runs with zero deps (pure-Python fallbacks).

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
- **Stateful rules need state (0.2).** A mandate that declares `limits` is
  denied unless you pass `store=`; one that declares `revocation` is denied
  unless you pass the signed list in `revocation_lists=`. Nothing is skipped
  for want of state. A mandate without `limits` has no replay protection; the
  reference store is in memory and per process.
- **Unknown wire versions are denied**, and a `mandatekit/v0` mandate that
  carries 0.2 keys is denied as unenforceable under its version.
- The pure-Python Ed25519 is the reference impl (not constant-time); swap in
  libsodium/`cryptography` for production.

## Scope, time, limits, revocation and delegation (0.2.0)

All five live under `constraints`; see the [root README](../README.md#scope-time-limits-revocation-and-delegation-020)
for the design and the reason codes. In Python:

```python
from datetime import datetime, timedelta, timezone
from mandatekit import (build_mandate, delegate_mandate, sign_mandate, verify, record_use,
                        InMemoryUsageStore, build_revocation_list, sign_revocation_list)

now = datetime.now(timezone.utc)
mandate = build_mandate(
    agent_id="agent-tidy",
    agent_public_key=delegate_public_key,                 # the key the agent may delegate with
    categories=["bank", "4900"],
    counterparties={"harbourline": ["read", "submit", "transfer"],   # the bank, never a payee
                    "MID-10231": ["read", "draft", "pay"]},
    actions=["read", "draft", "submit", "pay", "transfer"],
    max_amount={"value": 15000, "currency": "GBP"},
    not_before=now + timedelta(hours=1),                   # window start
    limits={"actions": ["pay"], "max_uses": 1},             # one payment per mandate
    revocation={"list_id": "rl-alex-2026-10", "max_age_seconds": 86400},
    delegation={"max_depth": 1},                           # may be delegated one level
    ttl_days=7,
)
signed = sign_mandate(mandate, issuer_seed)

store = InMemoryUsageStore()
revocation_list = sign_revocation_list(build_revocation_list(list_id="rl-alex-2026-10", revoked=[]), issuer_seed)
pay = {"action": "pay", "merchant": "MID-10231", "category": "4900", "amount": {"value": 11840, "currency": "GBP"}}
verdict = verify(signed, pay, trusted_keys=[issuer_public_key], now=now + timedelta(hours=2),
                 store=store, revocation_lists=[revocation_list])
if verdict["decision"] == "allow":
    ...  # act, then
    record_use(signed, pay, store, now=now + timedelta(hours=2))

# pay the bank: deny, counterparty_scope. A second pay: deny, max_uses.
# Before the window: deny, not_before. Without the store: deny, limits_store.
# Without the list: deny, revocation_list. On the list: deny, revoked.

child = delegate_mandate(signed, agent_id="sub-agent", counterparties={"MID-10231": ["read", "pay"]},
                         max_amount={"value": 5000, "currency": "GBP"}, actions=["read", "pay"], approval=None)
signed_child = sign_mandate(child, delegate_seed)     # verifies against trusted_keys=[issuer_public_key]
```

`verify(...)` never raises; a malformed mandate, store record, list or chain is
a deny with the reason named. `record_use` raises `ValueError` on a malformed
envelope rather than silently recording nothing.

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
`--revocation-list FILE` (repeatable) supplies a signed list the mandate
declares. The CLI holds no usage state, so a mandate with `limits` is denied
from the CLI by design; enforce limits from code with a store, or through
`mandatekit-mcp`, which keeps one for the session.

## Tests

```bash
PYTHONPATH=. python3 tests/test_mandatekit.py     # standalone, no pytest needed
PYTHONPATH=. python3 tests/test_stepup.py         # 0.1: actions, approval, step mandates
PYTHONPATH=. python3 tests/test_v02.py            # 0.2: scope, windows, limits, revocation, delegation + fixture
PYTHONPATH=. python3 -m unittest tests.test_mcp   # the MCP proxy
PYTHONPATH=. python3 tests/test_properties.py     # Hypothesis
# or
pytest
```

## License

MIT.
