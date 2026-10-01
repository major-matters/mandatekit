# Changelog

Notable changes to this repository.

## 0.1.0 (2026-10-01)

Built for the Mandate Sandbox, the bank-facing demo of the five-kit suite.
Both SDKs, byte-compatible (a mandate or step mandate signed in one verifies
in the other; signatures over the same bytes are identical).

- New constraint `actions`: an allow-list of verbs (`read`, `draft`, `submit`,
  `pay`, `cancel`, `share`, ...). Transactions carry `action`. Presence-based;
  empty allows nothing; a missing verb is a deny. Not a scoping key.
- New constraint `approval`: `{actions: [...], above: {value, currency}}`.
  A transaction that passes every scope check but trips an approval rule now
  gets a third verdict, **`ask`**. `ask` never masks another failure: any
  other failing check is still `deny`.
- New `step_mandate` / `stepMandate(parent, transaction)`: narrows a mandate
  to one transaction with a short TTL. Presented as `transaction.approval`,
  it is verified recursively under the same trusted keys and must be for the
  same agent, unexpired and in scope for the transaction. Malformed approval
  envelopes are `deny`, never `ask`.
- New `to_authorization_details` / `toAuthorizationDetails`: cross-walk to
  RFC 9396 (OAuth Rich Authorization Requests) `authorization_details`.
- Hardening: a non-string `category` or `action` on a transaction no longer
  throws in either SDK (found by fuzzing the new paths; 3,000 hostile inputs
  per language, zero exceptions).
- Tests: 20 new per language (`test_stepup.py`, `stepup.test.ts`).
- Not changed: the MCP proxy does not yet map tool calls onto `actions`; a
  mandate with `actions` denies every proxied tool call (fail closed) until it
  does.

## 2026-09-08 (later)

- New: `mandatekit-mcp`, an MCP gating proxy (stdio transport). Wraps any MCP
  server and verifies every tools/call against a signed mandate before it
  executes: categories = signed tool allowlist, --server-name = merchant
  pinning, argument amounts capped by max_amount. Fail-closed; denials return
  as isError tool results. Python only; 10 unit tests + e2e smoke.
- Fix: `compile(now=...)` now passes `now` through to the default parser, so
  relative dates ("expires June 30") resolve deterministically against the
  pinned clock instead of the wall clock. Surfaced by a date-dependent test
  that began failing once real time crossed the phrase's date.

## 2026-09-08

- README: install from PyPI/npm (live since 2026-06-10); AP2 Verifiable Intent note
  updated for FIDO Alliance contribution (May 2026).
- README: added "The accountability stack, September 2026" positioning section
  linking the suite to the MM Control Stack Compact.
