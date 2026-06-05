# MandateKit (TypeScript) · v0

Sign and verify **scope-bound mandates for AI agents**. TypeScript port of
[MandateKit](../README.md); mandates are wire-compatible with the Python SDK.

> **v0, tracks the AP2 Verifiable Intent draft** (finalization expected Q3 2026).
> Expect breaking changes.

Crypto uses Node's built-in Ed25519; canonicalization uses the **`canonicalize`**
package (RFC 8785), byte-identical to the Python SDK's `rfc8785` output.

## Requirements

Node **22.6+** (the source runs `.ts` directly via Node's built-in type
stripping, so there is no build step for local use). `npm run build` compiles to
`dist/` with type declarations for bundlers and npm publishing.

## Install

Not yet on npm (v0). For now, clone and build from source:

```bash
git clone https://github.com/major-matters/mandatekit
cd mandatekit/typescript && npm install && npm run build
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
"allow nothing", unknown constraint keys are denied, and amounts must be integers
(compared like-for-like; caller picks the unit). No replay protection in v0
(`max_uses` is out, not ignored). Same
model as the Python SDK — see [`../python/README.md`](../python/README.md).

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
npm test          # node --test, no dev dependencies
```

## License

MIT.
