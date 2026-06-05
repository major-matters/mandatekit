/**
 * Canonical JSON for signing. Sorted keys + compact separators, byte-identical
 * to the Python port's `canonicalize`. See the Python module for the rationale
 * and the v0-vs-JCS note.
 */

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortValue((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

export function canonicalize(obj: unknown): Buffer {
  // JSON.stringify uses no whitespace and ',' / ':' separators by default,
  // matching Python's compact separators.
  return Buffer.from(JSON.stringify(sortValue(obj)), "utf8");
}
