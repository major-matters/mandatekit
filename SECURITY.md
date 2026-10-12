# MandateKit — Security

## Threat model

MandateKit issues and checks **mandates**: signed statements of what an AI agent
may spend on. The verifier sits in front of a payment authorization, so the
adversary's goal is to get a transaction approved that the legitimate issuer did
not authorize — by forging a mandate, widening scope, replaying a one-shot
mandate, or crashing the verifier.

A valid signature proves **integrity** (the bytes were not altered) and that the
holder of a key signed it. It does **not** prove the signer is trusted. Authority
comes from the integrator pinning which issuer keys they accept.

## v0 review (2026-06-05)

An adversarial review found five issues; all are fixed and locked by a
security-regression test block in both SDKs (`test_attack*` / `attack N` tests).

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| 1 | Critical | `verify()` trusted the public key embedded in the envelope — anyone could sign their own mandate and be allowed | `verify()` requires `trusted_keys`/`trustedKeys`; **fails closed** without it (or an explicit `allow_unverified_issuer` opt-in) |
| 2 | High | Empty `constraints` → allow-all | Deny unless ≥1 hard scope constraint (`categories`/`merchants`/`max_amount`) is present |
| 3 | High | Empty allow-list (`[]`) silently skipped → fail-open | Presence-based checks; an empty allow-list allows nothing |
| 4 | High | `max_uses` parsed and stored but never enforced (replayable) | Removed from v0; unknown/unenforceable constraint keys now **deny** |
| 5 | Medium | Deeply nested JSON crashed `verify()` (`RecursionError`) | Iterative depth/size bound (`MAX_DEPTH`/`MAX_NODES`) before canonicalizing |
| — | Medium | Float amounts diverge in cross-language canonicalization | Amounts must be integers (compared like-for-like, caller-chosen unit); floats rejected at build and verify |

## Hardening pass (2026-06-05)

Following the review, MandateKit moved onto vetted primitives and added automated
and property-based testing:

- **Constant-time, vetted Ed25519.** Signing/verification use the `cryptography`
  library by default. The pure-Python RFC 8032 reference remains only as a
  zero-dependency fallback (not constant-time) and warns at import.
- **RFC 8785 (JCS) canonicalization** via the `rfc8785` (Python) and
  `canonicalize` (TypeScript) libraries — byte-identical across both SDKs.
- **Amounts bounded** to the JS-safe integer range `[0, 2**53-1]`, so JCS can
  canonicalize them identically everywhere.
- **`verify()` never throws.** Property-based tests (Hypothesis / fast-check)
  fuzz it with arbitrary hostile input; signature checking and every constraint
  path tolerate malformed types and return a verdict.
- **CI security gates:** CodeQL, Semgrep, and Bandit run on every push, plus a
  job that exercises the dependency-free fallback path.

## Known limitations (by design, v0)

- **Usage and velocity limits need a store you supply.** Since 0.2 a mandate
  can declare `limits`; `verify()` denies such a mandate unless the caller
  passes a store, and denies when the store fails or returns a malformed
  record. The reference store is in memory, single process and per instance:
  two processes each see only their own uses. A mandate with no `limits` has
  no replay protection. A store that survives a restart is roadmap work.
- **Revocation lists are checked, not fetched.** The verifier accepts a list
  only from the mandate's own issuer or a pinned trusted key, and denies when
  a declared list is missing, forged, altered or (with `max_age_seconds`)
  stale. Getting a current list to the verifier is the integrator's job.
- **Not independently audited.** Automated tooling and property tests are not a
  substitute for a third-party audit.
- **Intent-basket alignment fails open** (a scorer error does not deny) by
  deliberate choice; integrators wanting fail-closed should enforce it themselves.

## 0.2.0 (2026-10-12)

New fail-closed paths, each covered by a test in both SDKs and by the shared
`fixtures/verdict-matrix.json`:

- **Field placement.** The 0.2 fields (`counterparties`, `not_before`,
  `limits`, `revocation`, `delegation`) live under `constraints`, not beside
  `issued_at`. A 0.1 verifier never reads the version field but does refuse
  constraint keys it cannot enforce, so a 0.2 mandate fails closed on old code
  instead of having its window start, limits, list or chain silently ignored.
- **Wire version.** `mandatekit/v0.2`. Unknown versions deny; a `v0` mandate
  that carries 0.2 keys denies as unenforceable under its version.
- **Delegation.** The chain is walked to a root that must be signed by a
  pinned key; each link must be signed by its parent's `subject.public_key`,
  the parent must have opted in with `max_depth` to spare, and the child must
  only narrow (effective per-counterparty verb scope, caps, categories,
  windows, deny lists, approval rules still reachable). A parent travels
  inside the child's signed bytes, so editing any link invalidates the leaf.
  Chains over eight links are refused. Each link's revocation list and limits
  apply.
- **Hostile input.** Property tests in both languages fuzz the new keys, a
  garbage parent chain, garbage revocation lists and garbage store records;
  `verify()` returns a verdict in every case.

## Reporting

This is a pre-release v0 prototype. Do not use it to authorize real funds.

## Audit status (v0)

This is a v0 release. It has been independently hardened — CodeQL, bandit, semgrep, property-based tests, and adversarial tier 1-2 reviews, all passing in CI — but it has **not** had a third-party security audit. Treat it accordingly for anything high-stakes.

## Security review welcome

We actively want researcher eyes on this. If you find a fail-open, a signature bypass, an SSRF path, or any way to defeat a guarantee in this document, please open an issue. Credit given. The shared crypto core (Ed25519 + RFC 8785 canonicalization) and the verifier's fail-closed paths are the highest-value targets.

## v0.0.2 hardening (2026-06-10 internal audit)

- **Expiry parsing unified.** The TypeScript verifier no longer uses the lenient `Date.parse` (which accepted strings like "30 June 2026" and read naive timestamps as local time). It now uses a strict ISO-8601 parser matching Python's `fromisoformat`, with naive timestamps anchored to UTC, so the same signed mandate yields the same verdict in both SDKs.
- **Scope vs amount (clarification).** A mandate is "scoped" if it sets any one of `categories`, `merchants`, or `max_amount`. A mandate without `max_amount` therefore carries **no spending ceiling**; if you need one, set `max_amount` explicitly or enforce a cap out of band.
- **Canonicalization fallback** now fails closed on floats / out-of-safe-range integers (see the shared crypto core note).
