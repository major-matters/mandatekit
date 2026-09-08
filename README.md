# MandateKit · v0

[![CI](https://github.com/major-matters/mandatekit/actions/workflows/ci.yml/badge.svg)](https://github.com/major-matters/mandatekit/actions/workflows/ci.yml)

> ⚠️ **Experimental — unaudited, not for production.** A v0 research prototype with
> no third-party security audit. **Do not use it to authorize real funds.** Published
> to [PyPI](https://pypi.org/project/mandatekit/) and [npm](https://www.npmjs.com/package/mandatekit)
> as `mandatekit`. The API and on-the-wire format will change.

**Sign and verify scope-bound mandates for AI agents.**

When an AI agent acts on someone's behalf — buys something, books something, pays
for something — the hard question is *was it allowed to do that?* A **mandate** is
the answer in signed, machine-checkable form: a small document that says exactly
what an agent may spend on, who issued it, and when it expires. Before a
transaction clears, you verify it against the mandate and get a yes/no with a
reason.

MandateKit is the open-source SDK for producing and checking those mandates. It
ships in **Python** and **TypeScript**, with byte-compatible signatures across the
two (a mandate signed in one verifies in the other).

> **v0 status.** This tracks the [AP2](https://github.com/google-agentic-commerce/AP2)
> Verifiable Intent **draft**, contributed to the FIDO Alliance in May 2026 and under
> community standardization there. Field names and
> scoring are MandateKit's own until the spec settles. Treat it as a working
> prototype, not a stable API — expect breaking changes.

## The two pieces

### 1. The compiler — natural language → signed mandate

```
"Allow this agent to buy running shoes from any apparel retailer
 up to $500 per transaction, expires June 30"
```

becomes

```
natural language  →  JSON-Schema mandate  →  Ed25519-signed payload
```

Parsing has two modes: a **deterministic rule-based parser** (default, zero
dependencies, no network) and an **off-the-shelf LLM parser** you inject for
free-form phrasing. Signing is always **local** — the private key never leaves
the device.

### 2. The verifier — deterministic scope check

Given a signed mandate and a candidate transaction, it returns a verdict:

```json
{
  "decision": "allow",
  "signature_valid": true,
  "scope_match_score": 1.0,
  "matched": [ ... ],
  "failed": [],
  "rationale": "in scope: within validity window; apparel in [apparel]; 240 USD <= cap 500 USD"
}
```

It checks signature, expiry, category, merchant allow/deny, and amount cap —
**deterministically**: same inputs, same verdict, every time. The one fuzzy check,
intent-basket alignment ("do running shoes satisfy the stated intent?"), is
**optional and injected**; a missing or failing model never turns a deny into an
allow.

## Gate an MCP server

The fastest way to put a mandate to work is not a payment flow, it is a tool
call. `mandatekit-mcp` wraps any MCP server (stdio transport) and checks every
`tools/call` against a signed mandate before the server sees it:

```bash
pip install mandatekit
mandatekit-mcp --mandate signed.json --trust @issuer.pub -- python -m your_mcp_server
```

The mapping is the mandate's own vocabulary: the mandate's `categories` list is
the signed tool allowlist (the tool name is the transaction category),
`--server-name` matches the merchant allow/deny lists so a mandate can be pinned
to one server, and a `{"value": <int>, "currency": "<str>"}` amount in the tool
arguments is capped by `max_amount`. Denials return to the agent as a normal MCP
tool result with `isError: true` and the reason, so sessions survive a refusal.

Fail-closed like the rest of the kit: an unparseable or unverifiable tool call
is denied, never forwarded, and the proxy refuses to start without a pinned
issuer key. Every other MCP message (`initialize`, `tools/list`, resources,
notifications) passes through untouched. Python only for now; stdlib only, no
model, no network.

## Security model

A valid signature proves **integrity, not authority**: that the mandate was not
altered and that whoever holds the key signed it — not that you trust that key.
So `verify()` requires you to **pin the issuer** with `trusted_keys` / `trustedKeys`,
and **fails closed** (denies) if you supply neither that nor an explicit
`allow_unverified_issuer` opt-in. It also denies unbounded mandates (no scope),
empty allow-lists, and unknown constraint keys, and requires integer amounts
(compared like-for-like; the caller picks the unit) so signatures stay canonical
across both languages. These rules are
covered by a security-regression test block in each SDK. There is **no replay
protection in v0** — usage/velocity limits need the roadmap registry, so they are
omitted rather than parsed-and-ignored. Full notes in
[`python/README.md`](python/README.md#security-model-read-this).

## Design choices (and non-goals)

- **Vetted crypto and canonicalization.** Signing uses the `cryptography` library
  (constant-time Ed25519) and RFC 8785 (JCS) canonicalization (`rfc8785`); the
  TypeScript SDK uses Node's built-in crypto and the `canonicalize` package, so
  the two are byte-identical. Pure-Python / sorted-JSON fallbacks keep it runnable
  with zero deps for experimentation. The key stays on the device.
- **Tested adversarially.** Property-based tests (Hypothesis / fast-check) fuzz
  the crypto and the verifier; CodeQL, Semgrep, and Bandit run in CI. Not a
  substitute for a third-party audit, which it has not had.
- **No fine-tuned model.** Where an LLM is used (NL parsing, intent scoring) it is
  off-the-shelf and optional. A fine-tuned verifier model is deliberately **out of
  v0 scope** — it's a separate, high-cost ML project.
- **Deferred to roadmap, not in this repo:** the hosted mandate registry,
  revocation propagation, the audit-log service, billing tiers, and stateful
  replay/usage enforcement. v0 is the local library only.

## Layout

```
mandatekit/
  python/        # pip-installable package + standalone tests
  typescript/    # npm package, runs on Node 22+ via built-in type-stripping
  LICENSE        # MIT
```

Per-language quick starts: [`python/README.md`](python/README.md) ·
[`typescript/README.md`](typescript/README.md).

## Try it in 10 seconds

```bash
# Python (no install needed)
cd python && PYTHONPATH=. python3 ../demo.py

# Python tests
cd python && PYTHONPATH=. python3 tests/test_mandatekit.py

# TypeScript tests (Node 22+)
cd typescript && npm test
```

---

## The accountability stack, September 2026

This year's frontier launches arrived alongside rogue-agent incidents that investigators struggled to attribute, and a written admission from inside the labs that runtime monitoring is degrading. The accountability primitives those events call for are what this suite implements:

> **[IdentityKit](https://github.com/major-matters/identitykit)** says who the agent is. **[MandateKit](https://github.com/major-matters/mandatekit)** says what it may do. **[BudgetGuard](https://github.com/major-matters/budget-guard)** caps what it spends. **[WitnessKit](https://github.com/major-matters/witnesskit)** proves what it did. **[RememberKit](https://github.com/major-matters/rememberkit)** governs what it remembers.

The [MM Control Stack Compact](https://www.majormatters.co/p/open-letter-control-stack-compact) (September 2026) proposes six verifiable commitments for frontier-AI accountability. Attributable agents and contractually bounded authority need running code, not pledges. This suite is a working v0 of that layer.

## License

MIT.
