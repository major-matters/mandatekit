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

export interface Constraints {
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  max_amount?: Amount;
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
  issuedAt?: Date;
  expiresAt?: Date;
  ttlDays?: number;
  mandateId?: string;
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
    if (!Number.isInteger(opts.maxAmount.value)) {
      throw new Error(
        "maxAmount.value must be an integer (amounts are compared like-for-like; " +
          "pick a unit, e.g. cents or whole units, and use it consistently); " +
          "floats are rejected to keep signatures canonical across languages",
      );
    }
    constraints.max_amount = {
      value: opts.maxAmount.value,
      currency: opts.maxAmount.currency ?? "USD",
    };
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
  if (ma && (!Number.isInteger(ma.value) || !ma.currency)) {
    errors.push("max_amount must be {value:integer, currency:string}");
  }
  return errors;
}
