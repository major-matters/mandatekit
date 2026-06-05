/**
 * Canonical JSON for signing — RFC 8785 (JSON Canonicalization Scheme), via the
 * `canonicalize` package (by the RFC's author). Byte-identical to the Python
 * SDK's output (Python uses the `rfc8785` library, same RFC), so a mandate signed
 * in one SDK verifies in the other.
 */

import jcs from "canonicalize";

export function canonicalize(obj: unknown): Buffer {
  const s = jcs(obj);
  if (s === undefined) {
    throw new Error("canonicalize: value cannot be canonicalized");
  }
  return Buffer.from(s, "utf8");
}
