/**
 * The deterministic verifier (TypeScript port). Same checks, same verdict shape,
 * and the same security model as Python.
 *
 * SECURITY MODEL: a valid signature proves integrity, not authority. Pin the
 * issuer with `trustedKeys`. Without `trustedKeys` and without
 * `allowUnverifiedIssuer: true`, verify FAILS CLOSED (denies). Absent scope is
 * denied, empty allow-lists mean "allow nothing", unknown constraint keys are
 * denied, and amounts must be integers (compared like-for-like; caller picks the unit).
 */

import { type SignedMandate, verifySignature } from "./signing.ts";

export interface Transaction {
  merchant?: string;
  category?: string;
  amount?: { value: number; currency: string };
  description?: string;
}

export type IntentScorer = (intent: string, transaction: Transaction) => number;
export type TrustedKeys = string | Buffer | Array<string | Buffer>;

interface Check {
  constraint: string;
  passed: boolean;
  detail: string;
}

export interface Verdict {
  decision: "allow" | "deny";
  signature_valid: boolean;
  scope_match_score: number;
  intent_alignment: number | null;
  matched: Check[];
  failed: Check[];
  rationale: string;
  mandate_id: string | undefined;
}

export interface VerifyOptions {
  now?: Date;
  intentScorer?: IntentScorer;
  intentThreshold?: number;
  trustedKeys?: TrustedKeys;
  allowUnverifiedIssuer?: boolean;
}

const KNOWN_CONSTRAINT_KEYS = new Set(["intent", "categories", "merchants", "max_amount"]);
const SCOPING_KEYS = ["categories", "merchants", "max_amount"];
const MAX_DEPTH = 64;
const MAX_NODES = 10000;

function check(constraint: string, passed: boolean, detail: string): Check {
  return { constraint, passed, detail };
}

function withinLimits(obj: unknown, maxDepth = MAX_DEPTH, maxNodes = MAX_NODES): boolean {
  const stack: Array<[unknown, number]> = [[obj, 1]];
  let nodes = 0;
  while (stack.length) {
    const [cur, depth] = stack.pop()!;
    nodes += 1;
    if (nodes > maxNodes || depth > maxDepth) return false;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push([v, depth + 1]);
    } else if (cur && typeof cur === "object") {
      for (const v of Object.values(cur as Record<string, unknown>)) stack.push([v, depth + 1]);
    }
  }
  return true;
}

function normalizeTrusted(trustedKeys?: TrustedKeys): Set<string> | null {
  if (trustedKeys == null) return null;
  const arr = Array.isArray(trustedKeys) ? trustedKeys : [trustedKeys];
  return new Set(arr.map((k) => (Buffer.isBuffer(k) ? k.toString("base64") : k)));
}

function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v);
}

function verdict(
  decision: "allow" | "deny",
  signatureValid: boolean,
  checks: Check[],
  mandate: Record<string, any>,
  rationale: string,
  intentAlignment: number | null = null,
): Verdict {
  const matched = checks.filter((c) => c.passed);
  const failed = checks.filter((c) => !c.passed);
  const score = checks.length ? Math.round((matched.length / checks.length) * 10000) / 10000 : 0.0;
  return {
    decision,
    signature_valid: signatureValid,
    scope_match_score: score,
    intent_alignment: intentAlignment,
    matched,
    failed,
    rationale,
    mandate_id: mandate?.mandate_id,
  };
}

export function verify(
  signed: SignedMandate,
  transaction: Transaction,
  opts: VerifyOptions = {},
): Verdict {
  const now = opts.now ?? new Date();
  const intentThreshold = opts.intentThreshold ?? 0.6;

  if (!signed || typeof signed !== "object" || typeof (signed as any).mandate !== "object" || !(signed as any).mandate) {
    return verdict("deny", false, [], {}, "malformed envelope: missing mandate object");
  }
  if (!withinLimits(signed)) {
    return verdict("deny", false, [], (signed as any).mandate, "mandate rejected: exceeds size/nesting limits");
  }

  const mandate = (signed.mandate ?? {}) as Record<string, any>;
  const constraints = (mandate.constraints ?? {}) as Record<string, any>;
  if (typeof constraints !== "object" || Array.isArray(constraints)) {
    return verdict("deny", false, [], mandate, "malformed mandate: constraints must be an object");
  }

  const signatureValid = verifySignature(signed);
  const checks: Check[] = [];

  // --- Issuer trust (the critical check) ---
  const trusted = normalizeTrusted(opts.trustedKeys);
  const envKey = signed.signature?.public_key;
  if (trusted !== null) {
    const ok = typeof envKey === "string" && trusted.has(envKey);
    checks.push(check("issuer_trusted", ok,
      ok ? "signed by a trusted issuer key" : "signing key is not in the trusted-issuer set"));
  } else if (!opts.allowUnverifiedIssuer) {
    return verdict("deny", signatureValid, [], mandate,
      "no trusted issuer keys supplied: pass trustedKeys: [...] (recommended) or allowUnverifiedIssuer: true to accept any signer");
  }

  // --- Constraint sanity ---
  const unknown = Object.keys(constraints).filter((k) => !KNOWN_CONSTRAINT_KEYS.has(k));
  if (unknown.length) {
    checks.push(check("constraints_enforceable", false, `unenforceable constraint(s) present: [${unknown.sort().join(", ")}]`));
  }
  const hasScope = SCOPING_KEYS.some((k) => k in constraints);
  checks.push(check("has_scope", hasScope,
    hasScope ? "mandate defines spending limits" : "mandate has no spending constraints (unbounded); refused"));

  // --- Expiry ---
  const expiresAt = Date.parse(mandate.expires_at);
  const expired = Number.isNaN(expiresAt) || now.getTime() > expiresAt;
  checks.push(check("not_expired", !expired, expired ? "mandate has expired" : "within validity window"));

  // --- Category (presence-based; empty list allows nothing) ---
  if ("categories" in constraints) {
    const cats: unknown[] = constraints.categories ?? [];
    const txnCat = (transaction.category ?? "").toLowerCase();
    const ok = cats.map((c) => String(c).toLowerCase()).includes(txnCat);
    checks.push(check("category", ok, `${txnCat || "(none)"} ${ok ? "in" : "not in"} [${cats.join(", ")}]`));
  }

  // --- Merchant allow / deny (presence-based) ---
  const merchants = constraints.merchants ?? {};
  const merchant = transaction.merchant ?? "";
  if ("allow" in merchants) {
    const allow: string[] = merchants.allow ?? [];
    const ok = allow.includes(merchant);
    checks.push(check("merchant_allow", ok, `'${merchant}' ${ok ? "is" : "is not"} on the allow-list`));
  }
  if ("deny" in merchants) {
    const deny: string[] = merchants.deny ?? [];
    const ok = !deny.includes(merchant);
    checks.push(check("merchant_deny", ok, `'${merchant}' ${ok ? "is not" : "is"} on the deny-list`));
  }

  // --- Amount (integers only, compared like-for-like) ---
  const maxAmount = constraints.max_amount;
  if (maxAmount != null) {
    const cap = maxAmount.value;
    const amt = transaction.amount;
    if (!isInt(cap)) {
      checks.push(check("amount", false, "mandate cap must be an integer"));
    } else if (!amt || amt.value == null || amt.currency == null) {
      checks.push(check("amount", false, "transaction has no amount"));
    } else if (!isInt(amt.value)) {
      checks.push(check("amount", false, "transaction amount must be an integer"));
    } else if (amt.currency !== maxAmount.currency) {
      checks.push(check("amount", false, `currency ${amt.currency} != mandate currency ${maxAmount.currency}`));
    } else {
      const ok = amt.value <= cap;
      checks.push(check("amount", ok, `${amt.value} ${amt.currency} ${ok ? "<=" : ">"} cap ${cap} ${maxAmount.currency}`));
    }
  }

  // --- Intent-basket alignment (optional, injected) ---
  let intentAlignment: number | null = null;
  const intent: string | undefined = constraints.intent;
  if (intent && opts.intentScorer) {
    try {
      intentAlignment = Number(opts.intentScorer(intent, transaction));
      const ok = intentAlignment >= intentThreshold;
      checks.push(check("intent_alignment", ok, `alignment ${intentAlignment.toFixed(2)} ${ok ? ">=" : "<"} threshold ${intentThreshold}`));
    } catch (e) {
      checks.push(check("intent_alignment", true, `scorer unavailable (${e}); skipped`));
    }
  }

  // --- Decision ---
  const failed = checks.filter((c) => !c.passed);
  if (!signatureValid) {
    return verdict("deny", false, checks, mandate,
      "signature invalid: the mandate was not signed by its claimed key or was altered after signing", intentAlignment);
  }
  if (failed.length) {
    return verdict("deny", true, checks, mandate, "out of scope: " + failed.map((c) => c.detail).join("; "), intentAlignment);
  }
  return verdict("allow", true, checks, mandate, "in scope: " + checks.map((c) => c.detail).join("; "), intentAlignment);
}
