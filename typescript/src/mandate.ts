/**
 * The mandate data model (TypeScript port). Mirrors the Python module's shape
 * exactly so mandates are interchangeable across the two SDKs.
 *
 * The 0.2 fields (`counterparties`, `not_before`, `limits`, `revocation`,
 * `delegation`) live under `constraints`, not beside `issued_at`, on purpose:
 * a 0.1 verifier never reads the version field but does refuse constraint keys
 * it cannot enforce, so a 0.2 mandate fails closed on old code instead of
 * having its window start, usage limits, revocation list or delegation chain
 * ignored.
 */

import { randomUUID } from "node:crypto";
import type { SignedMandate } from "./signing.ts";

export const VERSION = "mandatekit/v0.2";
export const VERSION_V0 = "mandatekit/v0";
export const SUPPORTED_VERSIONS: readonly string[] = [VERSION_V0, VERSION];
export const SPEC = "AP2-draft-2026Q2";
export const REVOCATION_LIST_VERSION = "mandatekit/revocation-list/v0.2";

export const LIMIT_KEYS = [
  "actions",
  "max_uses",
  "max_total_amount",
  "window_seconds",
  "max_uses_per_window",
  "max_amount_per_window",
] as const;
export const REVOCATION_KEYS = ["list_id", "max_age_seconds"] as const;
export const DELEGATION_KEYS = ["parent", "max_depth"] as const;

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

/** Usage limits (0.2). Enforced only against a caller-supplied store; a
 *  mandate that declares them is denied when verify() gets no store. */
export interface Limits {
  /** Which verbs count as a use (default: every transaction). */
  actions?: string[];
  max_uses?: number;
  max_total_amount?: Amount;
  /** Required when either per-window limit is set. */
  window_seconds?: number;
  max_uses_per_window?: number;
  max_amount_per_window?: Amount;
}

/** The issuer-signed revocation list this mandate must be checked against. */
export interface Revocation {
  list_id: string;
  /** Deny when the supplied list is older than this at verification time. */
  max_age_seconds?: number;
}

/** A root declares `max_depth` (how many levels below it may be delegated);
 *  a child carries the signed `parent` it narrows. */
export interface Delegation {
  parent?: SignedMandate;
  max_depth?: number;
}

export interface Constraints {
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  /** Per-verb counterparty scope (0.2): counterparty id to the verbs allowed
   *  there. The flat `merchants.allow` list still works and means "every
   *  allowed verb" at those merchants. */
  counterparties?: Record<string, string[]>;
  max_amount?: Amount;
  /** Allow-list of action verbs (e.g. read, draft, submit, pay, cancel, share).
   *  Presence-based: an empty list allows nothing. A filter, not a scope: it
   *  does not on its own make an otherwise unbounded mandate acceptable. */
  actions?: string[];
  approval?: Approval;
  /** Window start (0.2): verification denies before this instant. */
  not_before?: string;
  limits?: Limits;
  revocation?: Revocation;
  delegation?: Delegation;
}

export interface Subject {
  agent_id: string;
  /** Base64 Ed25519 key the subject signs child mandates with. */
  public_key?: string;
}

export interface Mandate {
  version: string;
  spec: string;
  mandate_id: string;
  subject: Subject;
  issued_at: string;
  expires_at: string;
  constraints: Constraints;
}

export interface RevocationList {
  version: string;
  list_id: string;
  issued_at: string;
  revoked: string[];
}

export function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function parseIso(s: string): Date {
  return new Date(s);
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v);
}

function checkedAmount(name: string, amount: Amount): Amount {
  if (!amount || typeof amount !== "object") {
    throw new Error(`${name} must be {value: integer, currency: string}`);
  }
  if (!Number.isInteger(amount.value)) {
    throw new Error(
      `${name}.value must be an integer (amounts are compared like-for-like; ` +
        "pick a unit, e.g. cents or whole units, and use it consistently); " +
        "floats are rejected to keep signatures canonical across languages",
    );
  }
  if (amount.value < 0 || amount.value > MAX_SAFE) {
    throw new Error(`${name}.value must be between 0 and Number.MAX_SAFE_INTEGER`);
  }
  return { value: amount.value, currency: amount.currency ?? "USD" };
}

function checkedCounterparties(cps: Record<string, string[]>): Record<string, string[]> {
  if (!cps || typeof cps !== "object" || Array.isArray(cps)) {
    throw new Error("counterparties must be an object mapping counterparty id to a list of verbs");
  }
  const out: Record<string, string[]> = {};
  for (const [cid, verbs] of Object.entries(cps)) {
    if (!cid) throw new Error("counterparties keys must be non-empty strings");
    if (!Array.isArray(verbs) || !verbs.every((v) => typeof v === "string")) {
      throw new Error(`counterparties['${cid}'] must be a list of verb strings`);
    }
    out[cid] = [...verbs];
  }
  return out;
}

function checkedLimits(limits: Limits): Limits {
  if (!limits || typeof limits !== "object" || Array.isArray(limits)) throw new Error("limits must be an object");
  const unknown = Object.keys(limits).filter((k) => !(LIMIT_KEYS as readonly string[]).includes(k)).sort();
  if (unknown.length) throw new Error(`limits has unknown key(s): [${unknown.join(", ")}]`);
  const out: Limits = {};
  if (limits.actions !== undefined) {
    if (!Array.isArray(limits.actions) || !limits.actions.every((a) => typeof a === "string")) {
      throw new Error("limits.actions must be a list of verb strings");
    }
    out.actions = [...limits.actions];
  }
  for (const key of ["max_uses", "max_uses_per_window"] as const) {
    if (limits[key] !== undefined) {
      const v = limits[key];
      if (!isInt(v) || v < 0 || v > MAX_SAFE) throw new Error(`limits.${key} must be a non-negative integer`);
      out[key] = v;
    }
  }
  if (limits.window_seconds !== undefined) {
    const w = limits.window_seconds;
    if (!isInt(w) || w < 1 || w > MAX_SAFE) throw new Error("limits.window_seconds must be a positive integer");
    out.window_seconds = w;
  }
  for (const key of ["max_total_amount", "max_amount_per_window"] as const) {
    if (limits[key] !== undefined) out[key] = checkedAmount(`limits.${key}`, limits[key] as Amount);
  }
  if ((out.max_uses_per_window !== undefined || out.max_amount_per_window !== undefined) && out.window_seconds === undefined) {
    throw new Error("limits: per-window limits need window_seconds");
  }
  if (out.max_uses === undefined && out.max_total_amount === undefined && out.max_uses_per_window === undefined && out.max_amount_per_window === undefined) {
    throw new Error("limits must declare at least one limit");
  }
  return out;
}

function checkedRevocation(rev: Revocation): Revocation {
  if (!rev || typeof rev !== "object" || Array.isArray(rev)) throw new Error("revocation must be an object");
  const unknown = Object.keys(rev).filter((k) => !(REVOCATION_KEYS as readonly string[]).includes(k)).sort();
  if (unknown.length) throw new Error(`revocation has unknown key(s): [${unknown.join(", ")}]`);
  if (typeof rev.list_id !== "string" || !rev.list_id) throw new Error("revocation.list_id must be a non-empty string");
  const out: Revocation = { list_id: rev.list_id };
  if (rev.max_age_seconds !== undefined) {
    const age = rev.max_age_seconds;
    if (!isInt(age) || age < 1 || age > MAX_SAFE) throw new Error("revocation.max_age_seconds must be a positive integer");
    out.max_age_seconds = age;
  }
  return out;
}

function checkedMaxDepth(depth: unknown): number {
  if (!isInt(depth) || depth < 0 || depth > MAX_SAFE) throw new Error("delegation.max_depth must be a non-negative integer");
  return depth;
}

function publicKeyB64(key: Buffer | string): string {
  if (Buffer.isBuffer(key)) {
    if (key.length !== 32) throw new Error("agentPublicKey must be a raw 32-byte Ed25519 public key or its base64");
    return key.toString("base64");
  }
  if (typeof key === "string" && key) return key;
  throw new Error("agentPublicKey must be a Buffer or a base64 string");
}

function subject(agentId: string, agentPublicKey?: Buffer | string): Subject {
  const s: Subject = { agent_id: agentId };
  if (agentPublicKey !== undefined) s.public_key = publicKeyB64(agentPublicKey);
  return s;
}

interface ConstraintInputs {
  intent?: string | null;
  categories?: string[] | null;
  merchants?: { allow?: string[]; deny?: string[] } | null;
  counterparties?: Record<string, string[]> | null;
  maxAmount?: Amount | null;
  actions?: string[] | null;
  approval?: Approval | null;
  notBefore?: Date | string | null;
  limits?: Limits | null;
  revocation?: Revocation | null;
}

function constraintsFrom(i: ConstraintInputs): Constraints {
  const constraints: Constraints = {};
  if (i.intent) constraints.intent = i.intent;
  if (i.categories && i.categories.length) constraints.categories = [...i.categories];
  if (i.merchants && (i.merchants.allow?.length || i.merchants.deny?.length)) {
    constraints.merchants = {};
    if (i.merchants.allow?.length) constraints.merchants.allow = [...i.merchants.allow];
    if (i.merchants.deny?.length) constraints.merchants.deny = [...i.merchants.deny];
  }
  if (i.counterparties != null) constraints.counterparties = checkedCounterparties(i.counterparties);
  if (i.maxAmount) constraints.max_amount = checkedAmount("maxAmount", i.maxAmount);
  if (i.actions != null) constraints.actions = [...i.actions];
  if (i.approval && (i.approval.actions?.length || i.approval.above)) {
    constraints.approval = {};
    if (i.approval.actions?.length) constraints.approval.actions = [...i.approval.actions];
    if (i.approval.above) constraints.approval.above = checkedAmount("approval.above", i.approval.above);
  }
  if (i.notBefore != null) constraints.not_before = typeof i.notBefore === "string" ? i.notBefore : iso(i.notBefore);
  if (i.limits != null) constraints.limits = checkedLimits(i.limits);
  if (i.revocation != null) constraints.revocation = checkedRevocation(i.revocation);
  return constraints;
}

export interface BuildOptions {
  agentId: string;
  /** The key the subject will sign child mandates with (raw 32 bytes or base64). */
  agentPublicKey?: Buffer | string;
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  counterparties?: Record<string, string[]>;
  maxAmount?: Amount;
  actions?: string[];
  approval?: Approval;
  notBefore?: Date | string;
  limits?: Limits;
  revocation?: Revocation;
  /** `{ max_depth: n }` lets the subject delegate up to n levels; needs agentPublicKey. */
  delegation?: { max_depth: number };
  issuedAt?: Date;
  expiresAt?: Date;
  ttlDays?: number;
  mandateId?: string;
}

/** Build a root mandate (one the issuer signs directly). */
export function buildMandate(opts: BuildOptions): Mandate {
  const issued = opts.issuedAt ?? new Date();
  const ttlDays = opts.ttlDays ?? 30;
  const expires =
    opts.expiresAt ?? new Date(issued.getTime() + ttlDays * 86400000);

  const constraints = constraintsFrom(opts);
  if (opts.delegation !== undefined) {
    const d = opts.delegation as Record<string, unknown>;
    if (!d || typeof d !== "object" || Object.keys(d).join() !== "max_depth") {
      throw new Error("a root mandate's delegation must be {max_depth: integer}; children come from delegateMandate");
    }
    if (opts.agentPublicKey === undefined) {
      throw new Error("a delegable mandate needs agentPublicKey, the key its subject will sign children with");
    }
    constraints.delegation = { max_depth: checkedMaxDepth(d.max_depth) };
  }

  return {
    version: VERSION,
    spec: SPEC,
    mandate_id: opts.mandateId ?? randomUUID(),
    subject: subject(opts.agentId, opts.agentPublicKey),
    issued_at: iso(issued),
    expires_at: iso(expires),
    constraints,
  };
}

export interface DelegateOptions {
  agentId: string;
  agentPublicKey?: Buffer | string;
  /** How many further levels this child may delegate; needs agentPublicKey. */
  maxDepth?: number;
  /** Scope fields: leave undefined to inherit the parent's value, pass a value
   *  to narrow it, or null to drop it. */
  intent?: string | null;
  categories?: string[] | null;
  merchants?: { allow?: string[]; deny?: string[] } | null;
  counterparties?: Record<string, string[]> | null;
  maxAmount?: Amount | null;
  actions?: string[] | null;
  approval?: Approval | null;
  notBefore?: Date | string | null;
  limits?: Limits | null;
  /** Not inherited: a child's list must be signed by the child's own issuer. */
  revocation?: Revocation;
  issuedAt?: Date;
  /** Defaults to the parent's expiry. */
  expiresAt?: Date;
  mandateId?: string;
}

/**
 * Build a child mandate under a signed parent, for the parent's subject to sign.
 * Every scope option left undefined copies the parent's value, so a child with
 * no overrides has exactly the parent's scope. The verifier refuses a child
 * that widens its parent on any axis, so narrowing here is a convenience, not
 * the enforcement.
 */
export function delegateMandate(parent: SignedMandate, opts: DelegateOptions): Mandate {
  if (!parent || typeof parent !== "object" || !parent.mandate || typeof parent.mandate !== "object") {
    throw new Error("delegateMandate needs the signed parent envelope");
  }
  const pm = parent.mandate as unknown as Mandate;
  const pc: Constraints = pm.constraints && typeof pm.constraints === "object" ? pm.constraints : {};
  const pick = <T>(value: T | null | undefined, inherited: T | undefined): T | null | undefined =>
    value === undefined ? inherited : value;

  const issued = opts.issuedAt ?? new Date();
  const expires = opts.expiresAt ?? parseIso(pm.expires_at);
  const constraints = constraintsFrom({
    intent: pick(opts.intent, pc.intent),
    categories: pick(opts.categories, pc.categories),
    merchants: pick(opts.merchants, pc.merchants),
    counterparties: pick(opts.counterparties, pc.counterparties),
    maxAmount: pick(opts.maxAmount, pc.max_amount),
    actions: pick(opts.actions, pc.actions),
    approval: pick(opts.approval, pc.approval),
    notBefore: pick(opts.notBefore, pc.not_before),
    limits: pick(opts.limits, pc.limits),
    revocation: opts.revocation,
  });
  const delegation: Delegation = { parent };
  if (opts.maxDepth !== undefined) {
    if (opts.agentPublicKey === undefined) throw new Error("a child that may delegate further needs agentPublicKey");
    delegation.max_depth = checkedMaxDepth(opts.maxDepth);
  }
  constraints.delegation = delegation;
  return {
    version: VERSION,
    spec: SPEC,
    mandate_id: opts.mandateId ?? randomUUID(),
    subject: subject(opts.agentId, opts.agentPublicKey),
    issued_at: iso(issued),
    expires_at: iso(expires),
    constraints,
  };
}

export interface RevocationListOptions {
  listId: string;
  revoked: string[];
  issuedAt?: Date;
}

/** An issuer-signed list of revoked mandate ids. Sign it with
 *  `signRevocationList` using the key that signed the mandates it revokes. */
export function buildRevocationList(opts: RevocationListOptions): RevocationList {
  if (typeof opts.listId !== "string" || !opts.listId) throw new Error("listId must be a non-empty string");
  if (!Array.isArray(opts.revoked) || !opts.revoked.every((r) => typeof r === "string")) {
    throw new Error("revoked must be a list of mandate id strings");
  }
  return {
    version: REVOCATION_LIST_VERSION,
    list_id: opts.listId,
    issued_at: iso(opts.issuedAt ?? new Date()),
    revoked: [...opts.revoked],
  };
}

function amountOk(a: unknown): boolean {
  const x = a as Amount | null;
  return !!x && typeof x === "object" && isInt(x.value) && x.value >= 0 && x.value <= MAX_SAFE && !!x.currency;
}

export function validate(m: Mandate): string[] {
  const errors: string[] = [];
  if (!m || typeof m !== "object") return ["mandate must be an object"];
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
  if (!SUPPORTED_VERSIONS.includes(m.version)) errors.push(`version must be one of [${SUPPORTED_VERSIONS.join(", ")}]`);
  if (!m.subject || !m.subject.agent_id) errors.push("subject.agent_id is required");
  else if ("public_key" in m.subject && (typeof m.subject.public_key !== "string" || !m.subject.public_key)) {
    errors.push("subject.public_key must be a base64 string");
  }
  for (const f of ["issued_at", "expires_at"] as const) {
    if (m[f] && Number.isNaN(Date.parse(m[f]))) {
      errors.push(`${f} is not a valid ISO-8601 datetime`);
    }
  }
  const c = m.constraints;
  if (!c || typeof c !== "object" || Array.isArray(c)) {
    errors.push("constraints must be an object");
    return errors;
  }
  const ma = c.max_amount;
  if (ma && !amountOk(ma)) {
    errors.push("max_amount must be {value:integer in [0, Number.MAX_SAFE_INTEGER], currency:string}");
  }
  const ab = c.approval?.above;
  if (ab && !amountOk(ab)) {
    errors.push("approval.above must be {value:integer in [0, Number.MAX_SAFE_INTEGER], currency:string}");
  }
  const attempt = (fn: () => void) => {
    try { fn(); } catch (e) { errors.push((e as Error).message); }
  };
  if (c.counterparties !== undefined) attempt(() => checkedCounterparties(c.counterparties!));
  if (c.not_before !== undefined && (typeof c.not_before !== "string" || Number.isNaN(Date.parse(c.not_before)))) {
    errors.push("not_before is not a valid ISO-8601 datetime");
  }
  if (c.limits !== undefined) attempt(() => checkedLimits(c.limits!));
  if (c.revocation !== undefined) attempt(() => checkedRevocation(c.revocation!));
  if (c.delegation !== undefined) {
    const d = c.delegation as Record<string, unknown> | null;
    if (!d || typeof d !== "object" || Array.isArray(d) || !Object.keys(d).length
      || Object.keys(d).some((k) => !(DELEGATION_KEYS as readonly string[]).includes(k))) {
      errors.push("delegation must be {parent?: signed mandate, max_depth?: integer}");
    } else {
      if ("max_depth" in d && !(isInt(d.max_depth) && d.max_depth >= 0 && d.max_depth <= MAX_SAFE)) {
        errors.push("delegation.max_depth must be a non-negative integer");
      }
      const p = d.parent as { mandate?: unknown } | undefined;
      if ("parent" in d && !(p && typeof p === "object" && p.mandate && typeof p.mandate === "object")) {
        errors.push("delegation.parent must be a signed mandate envelope");
      }
    }
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
