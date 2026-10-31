# Changelog

Notable changes to this repository.

## 0.2.1 (2026-10-31)

Both packages. Verdicts and envelopes are unchanged for every well-formed
mandate; the shared verdict matrix grows by four expiry cases, ten compiler
cases and twelve ISO-8601 cases, and both suites replay all of them.

- Rule-based compiler, both ports: every regex uses bounded repetition
  (merchant names are one to six capitalized words of up to 40 characters,
  whitespace runs are capped, amounts are at most 20 digits, the intent phrase
  at most 200 characters, and the "only from" merchant list is captured once
  and walked in code). The TypeScript bounds landed on 2026-10-29 and closed
  five code-scanning warnings; the Python port now has the same ones. An amount
  must start with a digit, so "up to , 500" is no amount at all (it crashed the
  Python parser and gave the TypeScript parser a zero cap). An ISO-looking
  expiry that is not a calendar date ("2026-13-45") means no expiry in both
  ports (Python raised, TypeScript rolled the date over).
- `parse_iso` (Python) now applies the same strict ISO-8601 grammar as the
  TypeScript verifier before parsing: a full date-time with seconds, optional
  fraction, optional `Z` or `+-HH:MM`. A bare date or a prose date is rejected,
  as it already was in TypeScript, so a mandate with `expires_at: "2026-10-19"`
  is denied (`not_expired`) in both SDKs instead of being read as midnight by
  Python alone.
- `mandatekit-mcp`: a frame longer than 1 MiB is dropped unparsed, and a frame
  that makes the JSON parser raise `RecursionError` or `MemoryError` is dropped
  too; both are logged to stderr. Nothing is forwarded on either path.
- `python/LICENSE` is in the package directory, so sdists and wheels carry it.
- Shared Ed25519 reference file: the docstring is generic (the same bytes serve
  all four signing kits); CI pins the SHA-256 of `ed25519.py`, `canonical.py`
  and `canonical.ts`.
- Repository: CI runs every file under `python/tests` through pytest, installs
  with `npm ci`, pins every action to a commit SHA, declares read-only
  permissions and pins the Semgrep image; Dependabot for npm, pip and Actions;
  a tag-driven Release workflow with Trusted Publishing; SECURITY.md points to
  private vulnerability reporting; CITATION.cff carries the version.

## 0.2.0 (2026-10-12)

Per-verb counterparty scope, time windows, usage limits, revocation and
delegation, in Python and TypeScript with identical verdicts and reason codes:
both suites replay the same `fixtures/verdict-matrix.json` (71 cases, 108
verdicts), and the TypeScript suite re-signs every Python-signed envelope in it
to prove the signatures are byte-identical. Built from the Bench evidence: in
entries two and three the one action that slipped past every layer was
`pay harbourline £84.00`, because the bank sat on every job's flat allow list.

- Wire version `mandatekit/v0.2`. The verifier accepts `mandatekit/v0` and
  `mandatekit/v0.2`; any other version is denied (`version`), and a `v0`
  mandate that carries a 0.2 key is denied as unenforceable under its version
  (`constraints_enforceable`). `validate` and the JSON Schema accept both.
  Every 0.2 field lives under `constraints`, so a 0.1 verifier refuses a 0.2
  mandate (unknown constraint keys) rather than ignoring its window start,
  limits, revocation list or chain.
- New constraint `counterparties`: `{"<id>": ["read", "submit", ...]}`, the
  verbs allowed at each counterparty. A verb not in the list, or a
  counterparty not in the map, is denied with `counterparty_scope`. The bank
  can be a counterparty for read, submit and transfer without becoming a valid
  payee. The 0.1 flat `merchants.allow` still works and means every allowed
  verb; when both are present both must pass. Counts as scope.
- New constraint `not_before`: denied before the window opens (`not_before`),
  as before after it closes (`not_expired`). Malformed is a deny.
- New constraint `limits`: `max_uses`, `max_total_amount`, and per
  `window_seconds` `max_uses_per_window` and `max_amount_per_window`, with an
  optional `actions` filter saying which verbs count (so one `pay` per job
  leaves reads alone). Enforced only against a caller-supplied store
  (`store=` / `store:`); a mandate that declares limits with no store is
  denied (`limits_store`), as is a store that throws or returns a malformed
  record. The limit that would be crossed is the reason code (`max_uses`,
  `max_total_amount`, `max_uses_per_window`, `max_amount_per_window`); a
  malformed `limits` object is `limits`. A use counts while it is less than
  `window_seconds` old. `record_use` / `recordUse(signed, txn, store, now)`
  writes a use under the mandate's id and every ancestor's; the verifier only
  reads. `InMemoryUsageStore` is the reference store. Time is injected: every
  `verify` and `record_use` in the tests passes `now`.
- New constraint `revocation`: `{"list_id": ..., "max_age_seconds"?: ...}`.
  The caller supplies signed lists in `revocation_lists=` /
  `revocationLists:`; the verifier accepts a copy only if its signature
  verifies and the signer is the mandate's own issuer or a pinned trusted key,
  and (with `max_age_seconds`) it is fresh enough. The mandate's id on a valid
  copy is `revoked`; a declared list that is missing, forged, altered, stale,
  malformed or under another id is `revocation_list`. New
  `build_revocation_list`, `sign_revocation_list`,
  `verify_revocation_list_signature` and their camelCase twins; the list
  envelope is the mandate envelope under the key `list`, version
  `mandatekit/revocation-list/v0.2`.
- New constraint `delegation`. A root opts in with `{"max_depth": n}` and
  names the delegate's key in `subject.public_key`; a child, built with
  `delegate_mandate` / `delegateMandate(parentSigned, ...)` and signed by that
  key, carries `{"parent": <signed parent>}`. `verify` walks the chain to the
  root, which must be signed by a trusted key, and denies unless every link is
  signed by its parent's subject key, the parent opted in with depth to
  spare, and the child only narrows: categories, caps, counterparties and
  verbs (on effective per-counterparty scope, so a flat list under a per-verb
  parent is a widening), deny lists, approval rules for verbs the child can
  still reach, and a window inside the parent's (`delegation` for structure
  and signatures, `delegation_scope` for widening, with the field named).
  Each link's revocation list and limits apply, so a revoked parent takes its
  children with it and a parent's `max_uses` counts the children's uses.
  Editing any link breaks the leaf's signature, since the parent travels
  inside the child's signed bytes. Chains longer than eight links are refused.
- Reason codes are stable and exported as `REASON_CODES`; the README lists
  them. New: `version`, `counterparty_scope`, `not_before`, `limits`,
  `limits_store`, `max_uses`, `max_total_amount`, `max_uses_per_window`,
  `max_amount_per_window`, `revocation_list`, `revoked`, `delegation`,
  `delegation_scope`.
- RFC 9396 export: `type` is now `mandatekit:mandate:v0.2`; `valid_from` is
  `not_before` when present; `locations` falls back to the sorted counterparty
  ids; `counterparties`, `limits`, `revocation`, `subject.public_key` and a
  `delegation` summary (the parent's id, `max_depth`) travel as type-specific
  fields.
- `mandatekit-mcp` keeps an in-memory store for the session and records every
  forwarded call, so `limits` hold across a session; `--revocation-list`
  (repeatable) supplies signed lists. The CLI's `verify` gains
  `--revocation-list`; it holds no state, so a mandate with `limits` is
  denied there by design.
- Tests: Python 67 to 100 (new `test_v02.py` with 29, two more property tests,
  two MCP tests), TypeScript 47 to 149 (new `v02.test.ts`, which also replays
  the fixture case by case, two more property tests). CI runs every Python
  file standalone, including the dependency-free job.
- Versions aligned at 0.2.0: pyproject.toml, `__version__`, package.json, the
  exported `__version__`, and the package-lock root entry (which still read
  0.0.1).
- Not changed: the MCP proxy still does not map tool calls onto `actions`
  (6.4); intent alignment still fails open; a step mandate is still signed by
  a trusted key, including for a delegated child; the store is in memory and
  per process (a persistent store is 6.3); the CLI cannot enforce limits.

## 0.1.1 (2026-10-07)

TypeScript package only; no change to the mandate format or the verifier.
From a reviewer's run on Node 22.14.

- `npm test`, `npm run test:build` and `npm run demo` now pass
  `--experimental-strip-types`, so they work on Node 22.6 to 22.17 as the
  README promised (type stripping is unflagged only from 22.18). The engines
  field stays `>=22.6`.
- `demo.ts` added: the `demo` script pointed at a file that was not in the
  repository. One mandate, four transactions (allow, ask, deny), a
  customer-signed step mandate, a tampered mandate, an untrusted key, and the
  RFC 9396 export.
- README: install from npm (the package has been there since 0.0.2; the
  README still said it was not), and the Node version note above.
- Published to npm as 0.1.1 (0.1.0 was tagged but never published; npm had
  0.0.2 until this release).

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
