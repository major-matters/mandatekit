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

## Known limitations (by design, v0)

- **No replay / velocity / usage enforcement.** The verifier is stateless. These
  require the roadmap registry. `max_uses` is omitted rather than ignored.
- **Pure-Python Ed25519 is the reference implementation** — correct (RFC 8032,
  cross-checked against Node) but not constant-time and not strict about
  non-canonical encodings. Use libsodium / `cryptography` in production.
- **Canonicalization is sorted-key JSON, not RFC 8785 (JCS).** Safe for the v0
  schema (ASCII keys, integer amounts); a 1.0 should adopt JCS.
- **Intent-basket alignment fails open** (a scorer error does not deny) by
  deliberate choice; integrators wanting fail-closed should enforce it themselves.

## Reporting

This is a pre-release v0 prototype. Do not use it to authorize real funds.
