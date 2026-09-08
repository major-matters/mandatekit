# Changelog

Notable changes to this repository.

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
