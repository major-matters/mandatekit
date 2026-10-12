# MandateKit · v0

[![MCP Surface Check: low surface](https://img.shields.io/badge/MCP_Surface_Check-low-4FA86A)](https://majorlabs.co/security)

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

It checks signature, issuer, wire version, window (start and expiry), category,
merchant allow/deny, per-verb counterparty scope, amount cap, verb, approval
rules, revocation, usage limits and the delegation chain, and it does so
**deterministically**: same inputs, same verdict, every time. The one fuzzy check,
intent-basket alignment ("do running shoes satisfy the stated intent?"), is
**optional and injected**; a missing or failing model never turns a deny into an
allow.

## Actions, approval and step mandates (0.1.0)

A payments mandate has three outcomes, not two: allowed without asking,
step-up, declined. 0.1.0 adds that third state and the vocabulary a bank or a
customer actually uses to delegate:

```json
"constraints": {
  "categories": ["4900", "4814"],
  "merchants": {"allow": ["MID-10231", "MID-10477"]},
  "max_amount": {"value": 150000, "currency": "GBP"},
  "actions": ["read", "draft", "submit", "pay", "cancel"],
  "approval": {"actions": ["cancel"], "above": {"value": 20000, "currency": "GBP"}}
}
```

- **`actions`** is an allow-list of verbs the agent may perform (the
  transaction carries `"action": "pay"`). Presence-based like the other lists:
  an empty list allows nothing, a missing verb is a deny. It is a filter, not a
  scope: on its own it never makes an unbounded mandate acceptable.
- **`approval`** names the verbs, and the amount threshold, that need a fresh
  decision from the issuer. A transaction that passes every scope check but
  trips an approval rule gets the verdict **`ask`** instead of `allow`. Treat
  anything other than `allow` as not allowed.
- **A step mandate** satisfies an `ask`. `step_mandate(parent, transaction)` /
  `stepMandate(parent, transaction)` narrows the parent to exactly that
  action, merchant, category and amount with a short validity window (15
  minutes by default). The issuer signs it, the agent presents it as
  `transaction["approval"]`, and the verifier re-checks it under the same
  pinned keys: wrong signer, wrong agent, expired, or narrowed to a different
  transaction all fail. This is AP2's human-present confirmation (an intent
  mandate narrowed to a cart) and a payment flow's step-up, in the kit's own
  format.

Under a `max_amount` cap every transaction states its amount, so non-monetary
verbs (cancel, read, submit) carry `{"value": 0, "currency": "..."}` rather
than nothing. Verifiers older than 0.1.0 refuse mandates that use these keys,
by design (unknown constraints fail closed).

**Cross-walk to OAuth RAR.** `to_authorization_details(mandate)` /
`toAuthorizationDetails(mandate)` renders a mandate as an RFC 9396
`authorization_details` entry, the shape open-banking consent already rides
on, so a bank's existing consent stack can read it. Draft mapping; the `type`
(`mandatekit:mandate:v0.2`) is MandateKit's own until a registry assigns one.
`valid_from` is `not_before` when the mandate has one; `locations` is the
merchant allow list or, for a per-verb scoped mandate, the sorted counterparty
ids; the per-verb map, limits, revocation list id and a delegation summary
travel as type-specific fields.

## Scope, time, limits, revocation and delegation (0.2.0)

The Bench found the gap. In entries two and three the one action that slipped
past every layer was `pay harbourline £84.00`: the bank was on every job's
allow list because the agent had to read from it and submit to it, so a
payment to the bank passed the merchant check. 0.2 closes that gap and the
four next to it. Every new field lives under `constraints`, so a 0.1 verifier
refuses a 0.2 mandate outright (unknown constraint keys fail closed) instead of
ignoring the part it cannot enforce. The wire version is `mandatekit/v0.2`;
the verifier still accepts `mandatekit/v0` mandates that use only 0.1 keys.

**Per-verb counterparty scope.** `counterparties` maps each counterparty to
the verbs allowed there. A `pay` to a counterparty scoped to read, submit and
transfer is denied with `counterparty_scope`. The 0.1 flat `merchants.allow`
still works and means "every allowed verb at these merchants".

```json
"constraints": {
  "counterparties": {
    "harbourline": ["read", "submit", "transfer"],
    "MID-10231": ["read", "draft", "pay"]
  },
  "actions": ["read", "draft", "submit", "pay", "transfer"],
  "max_amount": {"value": 15000, "currency": "GBP"}
}
```

**Time windows.** `not_before` beside the existing `expires_at`. Before the
window opens the verdict is `deny` with `not_before`; after it closes,
`not_expired`, as before.

```json
"constraints": {"not_before": "2026-10-13T09:00:00Z", "max_amount": {"value": 15000, "currency": "GBP"}}
```

**Usage limits.** `limits` declares `max_uses` and `max_total_amount` over
the mandate's life and, per `window_seconds`, `max_uses_per_window` and
`max_amount_per_window`; `actions` says which verbs count (so one `pay` per
job leaves the reads alone). Limits are stateful, so `verify` **requires a
store** when a mandate declares them and denies with `limits_store` when
none is passed. The verifier only reads; after acting on an `allow` you call
`record_use(signed, txn, store, now=...)` / `recordUse(...)`, which writes a
use under the mandate and every ancestor in its chain. `InMemoryUsageStore`
ships as the reference store (per process; a persistent store is roadmap
work). The clock is injected through `now`, as in BudgetGuard.

```json
"constraints": {
  "limits": {"actions": ["pay"], "max_uses": 1, "window_seconds": 3600, "max_amount_per_window": {"value": 20000, "currency": "GBP"}},
  "counterparties": {"shop": ["read", "pay"]}, "max_amount": {"value": 15000, "currency": "GBP"}
}
```

```python
store = InMemoryUsageStore()
v = verify(signed, pay, trusted_keys=[pub], store=store, now=now)      # allow
record_use(signed, pay, store, now=now)
verify(signed, pay, trusted_keys=[pub], store=store, now=now)          # deny, max_uses
```

**Revocation.** `revocation` names an issuer-signed list the mandate must be
checked against. You supply the list in `revocation_lists=` /
`revocationLists:`; the verifier accepts it only if its signature verifies and
it was signed by the mandate's issuer or a pinned trusted key (and, with
`max_age_seconds`, is fresh enough). The mandate's id on the list is
`revoked`; a declared list that is missing, forged, altered, stale or under
another id is `revocation_list`, a deny.

```json
"constraints": {"revocation": {"list_id": "rl-alex-2026-10", "max_age_seconds": 86400}, "max_amount": {"value": 15000, "currency": "GBP"}}
```

```python
lst = sign_revocation_list(build_revocation_list(list_id="rl-alex-2026-10", revoked=[mandate_id]), issuer_seed)
verify(signed, txn, trusted_keys=[pub], revocation_lists=[lst])         # deny, revoked
```

**Delegation.** A root opts in with `delegation: {"max_depth": n}` and names
the delegate's key in `subject.public_key`. The delegate builds a child with
`delegate_mandate(parent_signed, agent_id=..., ...)` / `delegateMandate`,
signs it with that key, and the child carries `delegation: {"parent":
<signed parent>}`. `verify` walks the chain to the root, which must be
signed by a trusted key, and denies unless every link is signed by its
parent's subject key, the parent opted in with depth to spare, and the child
only narrows: a subset of counterparties and verbs, lower or equal caps, a
window inside the parent's, no new verbs or categories, the parent's deny
list and approval rules kept where they still apply. Structure and signature
failures are `delegation`; widening is `delegation_scope`, with the field
named. Each link's revocation list and limits apply, so a revoked parent
takes its children with it. Because the parent travels inside the child's
signed bytes, editing any link breaks the leaf's signature.

```json
{
  "subject": {"agent_id": "sub-agent-9"},
  "constraints": {
    "counterparties": {"MID-10231": ["read", "pay"]},
    "max_amount": {"value": 5000, "currency": "GBP"},
    "actions": ["read", "pay"],
    "delegation": {"parent": {"mandate": {"...": "the signed root, max_depth 1, subject.public_key = this child's signer"}, "signature": {"...": "..."}}}
  }
}
```

**Reason codes.** The `constraint` field of every entry in `matched` /
`failed` is one of these, exported as `REASON_CODES`:

| Code | Means |
|---|---|
| `version` | the mandate's wire version is not one this verifier knows |
| `issuer_trusted` | the signer (or, for a chain, the root's signer) is not a pinned key |
| `constraints_enforceable` | an unknown constraint key, or a 0.2 key on a `mandatekit/v0` mandate |
| `has_scope` | no category, merchant, counterparty or amount bound at all |
| `not_expired`, `not_before` | outside the window, after and before |
| `category`, `merchant_allow`, `merchant_deny`, `amount`, `action` | the 0.1 scope checks |
| `counterparty_scope` | the counterparty is not listed, or the verb is not allowed there |
| `approval` | a step mandate is needed (verdict `ask`) or the one presented was rejected |
| `revocation_list`, `revoked` | the declared list is unavailable or invalid; the mandate is on it |
| `limits`, `limits_store` | a malformed `limits` object; no store supplied, or the store failed |
| `max_uses`, `max_total_amount`, `max_uses_per_window`, `max_amount_per_window` | the limit that would be crossed |
| `delegation`, `delegation_scope` | the chain is malformed, unsigned by the right key or not permitted; a child widens its parent |
| `intent_alignment` | the injected scorer's verdict |

Both SDKs replay `fixtures/verdict-matrix.json` (71 cases, 108 verdicts) and
the TypeScript suite re-signs every Python-signed envelope in it, so the two
implementations agree verdict for verdict and byte for byte. Still not in
0.2: a store that survives a restart or is shared across processes, replay
protection for a mandate with no `limits` (declare `max_uses` if you want
it), the MCP proxy mapping tool calls onto `actions`, and any third-party
audit.

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
empty allow-lists, unknown constraint keys and unknown wire versions, and requires
integer amounts (compared like-for-like; the caller picks the unit) so signatures
stay canonical across both languages. These rules are covered by a
security-regression test block in each SDK. **Stateful rules need state:** since
0.2 a mandate can declare usage and velocity limits (`limits`) and a revocation
list (`revocation`), and `verify()` denies when the caller does not supply the
store or the signed list they need, rather than skipping the check. A mandate
without `limits` has no replay protection, by declaration rather than by
omission; the store is in memory and per process in 0.2. Full notes in
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
- **Deferred to roadmap, not in this repo:** a store that survives a restart
  or is shared across processes, distribution of revocation lists (0.2 checks
  a list you hand it; fetching one is yours), the hosted mandate registry, and
  the audit-log service. v0 is the local library only.

## Layout

```
mandatekit/
  python/        # pip-installable package + standalone tests
  typescript/    # npm package, runs on Node 22+ via built-in type-stripping
  fixtures/      # verdict-matrix.json, replayed by both suites, and its generator
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
cd python && PYTHONPATH=. python3 tests/test_v02.py          # 0.2 features + the shared fixture

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
