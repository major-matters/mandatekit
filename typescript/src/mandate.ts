/**
 * The mandate data model (TypeScript port). Mirrors the Python module's shape
 * exactly so mandates are interchangeable across the two SDKs.
 */

import { randomUUID } from "node:crypto";

export const VERSION = "mandatekit/v0";
export const SPEC = "AP2-draft-2026Q2";

export interface Amount {
  value: number;
  currency: string;
}

/** Step-up rules: which actions, or amounts above what, need a fresh
 *  issuer-signed step mandate before they may proceed (verdict "ask"). */
export interface Approval {
  actions?: string[];
  above?: Amount;
}

export interface Constraints {
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  max_amount?: Amount;
  /** Allow-list of action verbs (e.g. read, draft, submit, pay, cancel, share).
   *  Presence-based: an empty list allows nothing. A filter, not a scope: it
   *  does not on its own make an otherwise unbounded mandate acceptable. */
  actions?: string[];
  approval?: Approval;
}

export interface Mandate {
  version: string;
  spec: string;
  mandate_id: string;
  subject: { agent_id: string };
  issued_at: string;
  expires_at: string;
  constraints: Constraints;
}

export function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function parseIso(s: string): Date {
  return new Date(s);
}

export interface BuildOptions {
  agentId: string;
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  maxAmount?: Amount;
  actions?: string[];
  approval?: Approval;
  issuedAt?: Date;
  expiresAt?: Date;
  ttlDays?: number;
  mandateId?: string;
}

function checkedAmount(name: string, amount: Amount): Amount {
  if (!Number.isInteger(amount.value)) {
    throw new Error(
      `${name}.value must be an integer (amounts are compared like-for-like; ` +
        "pick a unit, e.g. cents or whole units, and use it consistently); " +
        "floats are rejected to keep signatures canonical across languages",
    );
  }
  if (amount.value < 0 || amount.value > Number.MAX_SAFE_INTEGER) {
    throw new Error(`${name}.value must be between 0 and Number.MAX_SAFE_INTEGER`);
  }
  return { value: amount.value, currency: amount.currency ?? "USD" };
}

export function buildMandate(opts: BuildOptions): Mandate {
  const issued = opts.issuedAt ?? new Date();
  const ttlDays = opts.ttlDays ?? 30;
  const expires =
    opts.expiresAt ?? new Date(issued.getTime() + ttlDays * 86400000);

  const constraints: Constraints = {};
  if (opts.intent) constraints.intent = opts.intent;
  if (opts.categories && opts.categories.length) {
    constraints.categories = [...opts.categories];
  }
  if (opts.merchants && (opts.merchants.allow?.length || opts.merchants.deny?.length)) {
    constraints.merchants = {};
    if (opts.merchants.allow?.length) constraints.merchants.allow = [...opts.merchants.allow];
    if (opts.merchants.deny?.length) constraints.merchants.deny = [...opts.merchants.deny];
  }
  if (opts.maxAmount) {
    constraints.max_amount = checkedAmount("maxAmount", opts.maxAmount);
  }
  if (opts.actions) {
    constraints.actions = [...opts.actions];
  }
  if (opts.approval && (opts.approval.actions?.length || opts.approval.above)) {
    constraints.approval = {};
    if (opts.approval.actions?.length) constraints.approval.actions = [...opts.approval.actions];
    if (opts.approval.above) constraints.approval.above = checkedAmount("approval.above", opts.approval.above);
  }

  return {
    version: VERSION,
    spec: SPEC,
    mandate_id: opts.mandateId ?? randomUUID(),
    subject: { agent_id: opts.agentId },
    issued_at: iso(issued),
    expires_at: iso(expires),
    constraints,
  };
}

export function validate(m: Mandate): string[] {
  const errors: string[] = [];
  const required = [
    "version",
    "spec",
    "mandate_id",
    "subject",
    "issued_at",
    "expires_at",
    "constraints",
  ];
  for (const f of required) {
    if (!(f in (m as unknown as Record<string, unknown>))) errors.push(`missing required field: ${f}`);
  }
  if (m.version !== VERSION) errors.push(`version must be '${VERSION}'`);
  if (!m.subject || !m.subject.agent_id) errors.push("subject.agent_id is required");
  for (const f of ["issued_at", "expires_at"] as const) {
    if (m[f] && Number.isNaN(Date.parse(m[f]))) {
      errors.push(`${f} is not a valid ISO-8601 datetime`);
    }
  }
  const ma = m.constraints?.max_amount;
  if (ma && (!Number.isInteger(ma.value) || ma.value < 0 || ma.value > Number.MAX_SAFE_INTEGER || !ma.currency)) {
    errors.push("max_amount must be {value:integer in [0, Number.MAX_SAFE_INTEGER], currency:string}");
  }
  const ab = m.constraints?.approval?.above;
  if (ab && (!Number.isInteger(ab.value) || ab.value < 0 || ab.value > Number.MAX_SAFE_INTEGER || !ab.currency)) {
    errors.push("approval.above must be {value:integer in [0, Number.MAX_SAFE_INTEGER], currency:string}");
  }
  return errors;
}

/** The transaction a step mandate is narrowed to. Structurally the verifier's
 *  Transaction minus the approval envelope. */
export interface StepTarget {
  action?: string;
  merchant?: string;
  category?: string;
  amount?: Amount;
  description?: string;
}

export interface StepOptions {
  issuedAt?: Date;
  ttlMinutes?: number;
  mandateId?: string;
}

/**
 * Narrow a parent mandate to exactly one transaction. The result is an ordinary
 * mandate for the same agent whose scope is the given action, merchant,
 * category and amount, with a short validity window. The issuer signs it, and
 * the agent presents it as `transaction.approval` to satisfy an "ask" verdict.
 * This is the human-present confirmation of AP2 (an intent mandate narrowed to
 * a cart) and the step-up of a payment flow, in the kit's own format.
 */
export function stepMandate(parent: Mandate, target: StepTarget, opts: StepOptions = {}): Mandate {
  const issued = opts.issuedAt ?? new Date();
  const ttl = opts.ttlMinutes ?? 15;
  if (!(ttl > 0)) throw new Error("ttlMinutes must be positive");
  const constraints: Constraints = {};
  if (target.action) constraints.actions = [target.action];
  if (target.merchant) constraints.merchants = { allow: [target.merchant] };
  if (target.category) constraints.categories = [target.category];
  if (target.amount) constraints.max_amount = checkedAmount("amount", target.amount);
  if (!constraints.merchants && !constraints.categories && !constraints.max_amount) {
    throw new Error("a step mandate needs a merchant, category or amount to be scoped to");
  }
  const what = target.description ?? [target.action, target.merchant].filter(Boolean).join(" ");
  constraints.intent = `approve ${parent.mandate_id}${what ? ": " + what : ""}`;
  return {
    version: VERSION,
    spec: SPEC,
    mandate_id: opts.mandateId ?? randomUUID(),
    subject: { agent_id: parent.subject.agent_id },
    issued_at: iso(issued),
    expires_at: iso(new Date(issued.getTime() + ttl * 60000)),
    constraints,
  };
}
