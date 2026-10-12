# MandateKit (TypeScript) · v0

Sign and verify **scope-bound mandates for AI agents**. TypeScript port of
[MandateKit](../README.md); mandates are wire-compatible with the Python SDK.

> **v0, tracks the AP2 Verifiable Intent draft** (finalization expected Q3 2026).
> Expect breaking changes.

Crypto uses Node's built-in Ed25519; canonicalization uses the **`canonicalize`**
package (RFC 8785), byte-identical to the Python SDK's `rfc8785` output.

## Requirements

Node **22.6+**. The source runs `.ts` directly through Node's built-in type
stripping, so there is no build step for local use. Type stripping is on by
default from Node **22.18**; on 22.6 to 22.17 it needs the
`--experimental-strip-types` flag, which the npm scripts pass, so `npm test`
and `npm run demo` work on any 22.x. If you run a `.ts` file directly on an
older 22.x, add the flag yourself: `node --experimental-strip-types demo.ts`.
`npm run build` compiles to `dist/` with type declarations for bundlers and
for the npm package, which needs no flag.

## Install

```bash
npm install mandatekit
```

Or clone and build from source:

```bash
git clone https://github.com/major-matters/mandatekit
cd mandatekit/typescript && npm install && npm run build
npm run demo          # one mandate, four transactions, a step mandate, the RFC 9396 export
```

## Quick start

```ts
import { generateKeypair, compile, verify } from "mandatekit";

const { privateKey, publicKey } = generateKeypair();   // privateKey stays local

const signed = compile(
  "Allow this agent to buy running shoes from any apparel retailer " +
    "up to $500 per transaction, expires June 30",
  { agentId: "agent-7", privateKey },
);

const verdict = verify(
  signed,
  {
    merchant: "Fleet Feet",
    category: "apparel",
    amount: { value: 240, currency: "USD" },   // integer, same unit as the cap
    description: "Brooks Ghost 16 running shoes",
  },
  { trustedKeys: [publicKey] },   // pin the issuer — see Security below
);

console.log(verdict.decision);          // "allow"
console.log(verdict.scope_match_score); // 1
console.log(verdict.rationale);
```

A $600 charge, an electronics merchant, an expired mandate, a payload edited
after signing, or a mandate signed by a key you did not pin all return `"deny"`.

## Security model

A valid signature proves **integrity, not authority**. Pin the issuer with
`trustedKeys`; with neither `trustedKeys` nor `allowUnverifiedIssuer: true`,
`verify()` **fails closed**. Absent scope is denied, empty allow-lists mean
"allow nothing", unknown constraint keys and wire versions are denied, and
amounts must be integers (compared like-for-like; caller picks the unit).
Stateful rules need state (0.2): a mandate that declares `limits` is denied
without `store`, one that declares `revocation` is denied without the signed
list in `revocationLists`. A mandate without `limits` has no replay
protection; the reference store is in memory and per process. Same model as
the Python SDK; see [`../python/README.md`](../python/README.md).

## Scope, time, limits, revocation and delegation (0.2.0)

All five live under `constraints`; see the [root README](../README.md#scope-time-limits-revocation-and-delegation-020)
for the design and the reason codes. In TypeScript:

```ts
import {
  buildMandate, delegateMandate, signMandate, verify, recordUse,
  InMemoryUsageStore, buildRevocationList, signRevocationList,
} from "mandatekit";

const now = new Date();
const mandate = buildMandate({
  agentId: "agent-tidy",
  agentPublicKey: delegatePublicKey,                   // the key the agent may delegate with
  categories: ["bank", "4900"],
  counterparties: { harbourline: ["read", "submit", "transfer"],   // the bank, never a payee
                    "MID-10231": ["read", "draft", "pay"] },
  actions: ["read", "draft", "submit", "pay", "transfer"],
  maxAmount: { value: 15000, currency: "GBP" },
  notBefore: new Date(now.getTime() + 3600_000),         // window start
  limits: { actions: ["pay"], max_uses: 1 },             // one payment per mandate
  revocation: { list_id: "rl-alex-2026-10", max_age_seconds: 86400 },
  delegation: { max_depth: 1 },                          // may be delegated one level
  ttlDays: 7,
});
const signed = signMandate(mandate, issuerSeed);

const store = new InMemoryUsageStore();
const list = signRevocationList(buildRevocationList({ listId: "rl-alex-2026-10", revoked: [] }), issuerSeed);
const pay = { action: "pay", merchant: "MID-10231", category: "4900", amount: { value: 11840, currency: "GBP" } };
const later = new Date(now.getTime() + 7200_000);
const verdict = verify(signed, pay, { trustedKeys: [issuerPublicKey], now: later, store, revocationLists: [list] });
if (verdict.decision === "allow") {
  // act, then
  recordUse(signed, pay, store, { now: later });
}

// pay the bank: deny, counterparty_scope. A second pay: deny, max_uses.
// Before the window: deny, not_before. Without the store: deny, limits_store.
// Without the list: deny, revocation_list. On the list: deny, revoked.

const child = delegateMandate(signed, { agentId: "sub-agent", counterparties: { "MID-10231": ["read", "pay"] },
  maxAmount: { value: 5000, currency: "GBP" }, actions: ["read", "pay"], approval: null });
const signedChild = signMandate(child, delegateSeed);   // verifies against trustedKeys: [issuerPublicKey]
```

In `delegateMandate`, a scope option left `undefined` inherits the parent's
value, a value narrows it, and `null` drops it. `verify()` never throws; a
malformed mandate, store record, list or chain is a deny with the reason
named. `recordUse` throws on a malformed envelope rather than silently
recording nothing.

## The two pieces

**The compiler** (`compile`) turns natural language into a signed mandate. Parsing
defaults to a deterministic `ruleBasedParser`; pass your own `parser` (e.g. an
off-the-shelf LLM call) for free-form phrasing. Signing is always local.

**The verifier** (`verify`) is deterministic. Inject an `intentScorer` for
intent-basket alignment; without it, intent is left unscored and a missing model
never turns a deny into an allow. No fine-tuned model anywhere.

**LLM layer (v0 note).** The bundled off-the-shelf-LLM helpers live in the Python
SDK (`mandatekit.llm`). They are Python-first in v0 because `compile()` and
`verify()` take synchronous callbacks while Node's Anthropic SDK is async. In
TypeScript, pre-compute and inject: `const parsed = await yourLLM(text);
compile(text, { ..., parser: () => parsed })`, and likewise pass a pre-scored
`intentScorer: () => score`. A native async path is on the roadmap.

## Tests

```bash
npm test          # node --test; includes v02.test.ts, which replays fixtures/verdict-matrix.json
```

## License

MIT.
