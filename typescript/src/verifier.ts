/**
 * The deterministic verifier (TypeScript port). Same checks, same verdict shape,
 * same reason codes and the same security model as Python.
 *
 * SECURITY MODEL: a valid signature proves integrity, not authority. Pin the
 * issuer with `trustedKeys`. Without `trustedKeys` and without
 * `allowUnverifiedIssuer: true`, verify FAILS CLOSED (denies). Absent scope is
 * denied, empty allow-lists mean "allow nothing", unknown constraint keys and
 * unknown wire versions are denied, and amounts must be integers (compared
 * like-for-like; caller picks the unit).
 *
 * Stateful rules need state: a mandate that declares `limits` is denied
 * (`limits_store`) unless `store` is passed; one that declares a revocation
 * list is denied (`revocation_list`) unless that list, signature-verified, is
 * passed in `revocationLists`. A delegated mandate is verified as a chain back
 * to a pinned issuer and every link must only narrow its parent
 * (`delegation_scope`).
 */

import {
  DELEGATION_KEYS,
  LIMIT_KEYS,
  REVOCATION_KEYS,
  REVOCATION_LIST_VERSION,
  SUPPORTED_VERSIONS,
  VERSION,
  VERSION_V0,
} from "./mandate.ts";
import { type SignedMandate, type SignedRevocationList, verifyRevocationListSignature, verifySignature } from "./signing.ts";
import type { UsageStore, Use } from "./store.ts";

export interface Transaction {
  merchant?: string;
  category?: string;
  amount?: { value: number; currency: string };
  description?: string;
  /** The verb the agent wants to perform (read, draft, submit, pay, cancel,
   *  share, ...). Checked against `constraints.actions` and, when present, the
   *  counterparty's per-verb scope. */
  action?: string;
  /** A signed step mandate from the issuer, narrowed to this transaction,
   *  presented to satisfy an "ask" verdict. See `stepMandate()`. */
  approval?: SignedMandate;
}

export type IntentScorer = (intent: string, transaction: Transaction) => number;
export type TrustedKeys = string | Buffer | Array<string | Buffer>;

export interface Check {
  constraint: string;
  passed: boolean;
  detail: string;
}

/** "ask" means every scope check passed but the mandate's approval rules want
 *  a fresh issuer-signed step mandate for this transaction before it may run.
 *  Treat anything other than "allow" as not allowed. */
export type Decision = "allow" | "ask" | "deny";

export interface Verdict {
  decision: Decision;
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
  /** Usage state for mandates that declare `limits`. Required by them. */
  store?: UsageStore;
  /** The signed lists mandates declare under `revocation`. Required by them. */
  revocationLists?: SignedRevocationList | SignedRevocationList[];
}

// Constraint keys the verifier can actually enforce, per wire version. Anything
// else is denied. A mandatekit/v0 mandate may use only the v0 keys.
const V0_CONSTRAINT_KEYS = new Set(["intent", "categories", "merchants", "max_amount", "actions", "approval"]);
const V02_CONSTRAINT_KEYS = new Set([...V0_CONSTRAINT_KEYS, "counterparties", "not_before", "limits", "revocation", "delegation"]);
// `actions` is deliberately not a scoping key: an allow-list of verbs with no
// category, merchant or amount limit is still unbounded in what it can reach.
const SCOPING_KEYS = ["categories", "merchants", "counterparties", "max_amount"];
const MAX_DEPTH = 64;
const MAX_NODES = 10000;
// A delegation chain longer than this is refused outright.
const MAX_CHAIN_LINKS = 8;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** Stable reason codes: the `constraint` field of every check the verifier can
 *  emit. Documented in the README; the Bench counts verdicts by these names. */
export const REASON_CODES: readonly string[] = [
  "version",
  "issuer_trusted",
  "constraints_enforceable",
  "has_scope",
  "not_expired",
  "not_before",
  "category",
  "merchant_allow",
  "merchant_deny",
  "counterparty_scope",
  "amount",
  "action",
  "approval",
  "revocation_list",
  "revoked",
  "limits",
  "limits_store",
  "max_uses",
  "max_total_amount",
  "max_uses_per_window",
  "max_amount_per_window",
  "delegation",
  "delegation_scope",
  "intent_alignment",
];

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

function isNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function isObj(v: unknown): v is Record<string, any> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function amountOk(a: unknown): a is { value: number; currency: string } {
  return isObj(a) && isInt(a.value) && a.value >= 0 && a.value <= MAX_SAFE && typeof a.currency === "string" && !!a.currency;
}

function lowerList(x: unknown): string[] {
  return Array.isArray(x) ? x.map((v) => String(v).toLowerCase()) : [];
}

function fmt(items: Iterable<string>): string {
  return `[${[...items].join(", ")}]`;
}

function epoch(d: Date): number {
  return d.getTime() / 1000;
}

const ISO_8601 = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;

/** Strict ISO-8601 instant parser mirroring Python's parse_iso. Returns epoch
 *  milliseconds, or NaN if the string is not a valid ISO-8601 date-time. A naive
 *  timestamp (no offset) is treated as UTC, matching the Python SDK. */
function parseIsoStrict(s: unknown): number {
  if (typeof s !== "string") return NaN;
  const m = ISO_8601.exec(s);
  if (!m) return NaN;
  const offset = m[8] && m[8] !== "Z" ? m[8] : "Z"; // naive or "Z" -> UTC
  return Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}${offset}`);
}

function constraintKeysFor(version: unknown): Set<string> | null {
  if (version === VERSION) return V02_CONSTRAINT_KEYS;
  if (version === VERSION_V0) return V0_CONSTRAINT_KEYS;
  return null;
}

function setDiff(a: Iterable<string>, b: Set<string>): string[] {
  return [...a].filter((x) => !b.has(x));
}

function verdict(
  decision: Decision,
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

// --- limits ---------------------------------------------------------------------

interface ParsedLimits {
  actions?: string[];
  max_uses?: number;
  max_total_amount?: { value: number; currency: string };
  window_seconds?: number;
  max_uses_per_window?: number;
  max_amount_per_window?: { value: number; currency: string };
}

/** Normalize a `limits` object, or return null if it is malformed. */
function parseLimits(lim: unknown): ParsedLimits | null {
  if (!isObj(lim) || Object.keys(lim).some((k) => !(LIMIT_KEYS as readonly string[]).includes(k))) return null;
  const out: ParsedLimits = {};
  if ("actions" in lim) {
    if (!Array.isArray(lim.actions) || !lim.actions.every((a: unknown) => typeof a === "string")) return null;
    out.actions = lim.actions.map((a: string) => a.toLowerCase());
  }
  for (const key of ["max_uses", "max_uses_per_window"] as const) {
    if (key in lim) {
      if (!isInt(lim[key]) || lim[key] < 0 || lim[key] > MAX_SAFE) return null;
      out[key] = lim[key];
    }
  }
  if ("window_seconds" in lim) {
    const w = lim.window_seconds;
    if (!isInt(w) || w < 1 || w > MAX_SAFE) return null;
    out.window_seconds = w;
  }
  for (const key of ["max_total_amount", "max_amount_per_window"] as const) {
    if (key in lim) {
      if (!amountOk(lim[key])) return null;
      out[key] = { value: lim[key].value, currency: lim[key].currency };
    }
  }
  if ((out.max_uses_per_window !== undefined || out.max_amount_per_window !== undefined) && out.window_seconds === undefined) return null;
  if (out.max_uses === undefined && out.max_total_amount === undefined && out.max_uses_per_window === undefined && out.max_amount_per_window === undefined) return null;
  return out;
}

function useOk(use: unknown): use is Use {
  if (!isObj(use) || !isNum(use.at)) return false;
  if (use.action != null && typeof use.action !== "string") return false;
  return use.amount == null || amountOk(use.amount);
}

/** Evaluate one link's `limits` against the store. Appends one passing check
 *  named `limits`, or one failing check per limit that would be exceeded. */
function checkLimits(mandate: Record<string, any>, transaction: Transaction, nowS: number, store: UsageStore, checks: Check[]): void {
  const constraints = mandate.constraints ?? {};
  const lim = parseLimits(constraints.limits);
  if (lim === null) {
    checks.push(check("limits", false, "malformed limits constraint"));
    return;
  }
  let uses: unknown[];
  try {
    uses = [...store.uses(mandate.mandate_id)];
  } catch (e) {
    checks.push(check("limits_store", false, `state store error: ${(e as Error)?.constructor?.name ?? "Error"}`));
    return;
  }
  if (!uses.every(useOk)) {
    checks.push(check("limits_store", false, "state store returned a malformed usage record"));
    return;
  }
  const records = uses as Use[];
  const filt = lim.actions;
  const txnAct = typeof transaction.action === "string" ? transaction.action.toLowerCase() : "";
  const counts = (action: string | null | undefined) => filt === undefined || filt.includes((action ?? "").toLowerCase());
  const counted = records.filter((u) => counts(u.action));
  const proposed = counts(txnAct);
  const txnAmount = isObj(transaction.amount) ? transaction.amount : null;
  const failures: Check[] = [];

  const totalUses = counted.length + (proposed ? 1 : 0);
  if (lim.max_uses !== undefined && totalUses > lim.max_uses) {
    failures.push(check("max_uses", false, `${totalUses} uses would exceed max_uses ${lim.max_uses}`));
  }

  /** Sum recorded amounts plus the proposed one in the cap's currency, or
   *  return a failing check when something cannot be compared. */
  const summed = (recs: Use[], limitName: string, cap: { value: number; currency: string }): [number | null, Check | null] => {
    let total = 0;
    for (const u of recs) {
      const amt = u.amount;
      if (amt == null) continue;
      if (amt.currency !== cap.currency) {
        return [null, check(limitName, false, `recorded use in ${amt.currency} cannot be compared with ${limitName} in ${cap.currency}`)];
      }
      total += amt.value;
    }
    if (proposed) {
      if (txnAmount === null || txnAmount.value == null) return [null, check(limitName, false, "transaction has no amount")];
      if (!isInt(txnAmount.value) || txnAmount.currency !== cap.currency) {
        return [null, check(limitName, false, `transaction amount cannot be compared with ${limitName} in ${cap.currency}`)];
      }
      total += txnAmount.value;
    }
    return [total, null];
  };

  if (lim.max_total_amount !== undefined) {
    const cap = lim.max_total_amount;
    const [total, bad] = summed(counted, "max_total_amount", cap);
    if (bad !== null) failures.push(bad);
    else if ((total as number) > cap.value) {
      failures.push(check("max_total_amount", false, `${total} ${cap.currency} would exceed max_total_amount ${cap.value} ${cap.currency}`));
    }
  }

  if (lim.window_seconds !== undefined) {
    const w = lim.window_seconds;
    const inWindow = counted.filter((u) => nowS - u.at < w);
    if (lim.max_uses_per_window !== undefined) {
      const n = inWindow.length + (proposed ? 1 : 0);
      if (n > lim.max_uses_per_window) {
        failures.push(check("max_uses_per_window", false, `${n} uses in ${w}s would exceed max_uses_per_window ${lim.max_uses_per_window}`));
      }
    }
    if (lim.max_amount_per_window !== undefined) {
      const cap = lim.max_amount_per_window;
      const [total, bad] = summed(inWindow, "max_amount_per_window", cap);
      if (bad !== null) failures.push(bad);
      else if ((total as number) > cap.value) {
        failures.push(check("max_amount_per_window", false, `${total} ${cap.currency} in ${w}s would exceed max_amount_per_window ${cap.value} ${cap.currency}`));
      }
    }
  }

  if (failures.length) {
    checks.push(...failures);
  } else {
    checks.push(check("limits", true,
      proposed
        ? `within usage limits (${totalUses} counted use${totalUses !== 1 ? "s" : ""} including this one)`
        : `within usage limits (this ${txnAct || "action"} does not count; ${counted.length} recorded)`));
  }
}

// --- revocation -----------------------------------------------------------------

function normalizeLists(lists: unknown): unknown[] {
  if (lists == null) return [];
  if (Array.isArray(lists)) return [...lists];
  if (typeof lists === "object") return [lists];
  return [];
}

function checkRevocation(signed: SignedMandate, now: Date, trusted: Set<string> | null, lists: unknown[], checks: Check[]): void {
  const mandate = signed.mandate as Record<string, any>;
  const constraints = mandate.constraints ?? {};
  const rev = constraints.revocation;
  if (!isObj(rev) || Object.keys(rev).some((k) => !(REVOCATION_KEYS as readonly string[]).includes(k))
    || typeof rev.list_id !== "string" || !rev.list_id) {
    checks.push(check("revocation_list", false, "malformed revocation constraint"));
    return;
  }
  const maxAge = rev.max_age_seconds;
  if ("max_age_seconds" in rev && (!isInt(maxAge) || maxAge < 1)) {
    checks.push(check("revocation_list", false, "malformed revocation constraint"));
    return;
  }
  const listId: string = rev.list_id;
  const issuerKey = signed.signature?.public_key;

  const candidates = lists.filter((l): l is SignedRevocationList =>
    isObj(l) && isObj(l.list) && l.list.list_id === listId);
  if (!candidates.length) {
    checks.push(check("revocation_list", false, `declared revocation list '${listId}' was not supplied`));
    return;
  }

  const valid: Record<string, any>[] = [];
  let problem = "revocation list is malformed";
  for (const cand of candidates) {
    const body = cand.list as Record<string, any>;
    if (body.version !== REVOCATION_LIST_VERSION || !Array.isArray(body.revoked) || !body.revoked.every((r: unknown) => typeof r === "string")) {
      problem = `revocation list '${listId}' is malformed`;
      continue;
    }
    if (!verifyRevocationListSignature(cand)) {
      problem = `revocation list '${listId}' signature invalid`;
      continue;
    }
    const signer = cand.signature?.public_key;
    if (signer !== issuerKey && !(trusted !== null && trusted.has(signer))) {
      problem = `revocation list '${listId}' is not signed by the mandate's issuer or a trusted key`;
      continue;
    }
    if (maxAge !== undefined) {
      const issued = parseIsoStrict(body.issued_at);
      if (Number.isNaN(issued) || epoch(now) - issued / 1000 > maxAge) {
        problem = `revocation list '${listId}' is older than max_age_seconds ${maxAge}`;
        continue;
      }
    }
    valid.push(body);
  }
  if (!valid.length) {
    checks.push(check("revocation_list", false, problem));
    return;
  }
  const mandateId = mandate.mandate_id;
  if (valid.some((body) => (body.revoked as string[]).includes(mandateId))) {
    checks.push(check("revoked", false, `mandate ${mandateId} is revoked in list '${listId}'`));
  } else {
    checks.push(check("revocation_list", true, `not revoked in list '${listId}'`));
  }
}

// --- delegation -----------------------------------------------------------------

type VerbScope = Map<string, Set<string> | null>;

/** Effective per-counterparty verb scope: id to verbs, where null verbs means
 *  every verb; null overall means the mandate does not bound counterparties. */
function verbScope(c: Record<string, any>): VerbScope | null {
  const acts = "actions" in c ? new Set(lowerList(c.actions)) : null;
  const merchants = isObj(c.merchants) ? c.merchants : {};
  let allow: Set<string> | null = null;
  if ("allow" in merchants) allow = new Set(Array.isArray(merchants.allow) ? merchants.allow.map(String) : []);
  if ("counterparties" in c) {
    const cps = isObj(c.counterparties) ? c.counterparties : {};
    const out: VerbScope = new Map();
    for (const [cid, verbs] of Object.entries(cps)) {
      if (allow !== null && !allow.has(cid)) continue;
      const vs = new Set(lowerList(verbs));
      out.set(cid, acts !== null ? new Set([...vs].filter((v) => acts.has(v))) : vs);
    }
    return out;
  }
  if (allow !== null) {
    const out: VerbScope = new Map();
    for (const cid of allow) out.set(cid, acts);
    return out;
  }
  return null;
}

const sorted = (s: Iterable<string>) => [...s].sort();

/** Return a description of the first way `child` is wider than `parent`, or
 *  null when every axis narrows or stays equal. */
function widening(child: Record<string, any>, parent: Record<string, any>): string | null {
  const cc: Record<string, any> = isObj(child.constraints) ? child.constraints : {};
  const pc: Record<string, any> = isObj(parent.constraints) ? parent.constraints : {};

  // Window: the child's must sit inside the parent's.
  const cExp = parseIsoStrict(child.expires_at);
  const pExp = parseIsoStrict(parent.expires_at);
  if (Number.isNaN(cExp) || Number.isNaN(pExp)) return "expires_at: unparseable";
  if (cExp > pExp) return `expires_at ${child.expires_at} is after the parent's ${parent.expires_at}`;
  if ("not_before" in pc) {
    const pNb = parseIsoStrict(pc.not_before);
    if (Number.isNaN(pNb)) return "not_before: the parent's is unparseable";
    if (!("not_before" in cc)) return `not_before: parent opens at ${pc.not_before}, child has no not_before`;
    const cNb = parseIsoStrict(cc.not_before);
    if (Number.isNaN(cNb)) return "not_before: unparseable";
    if (cNb < pNb) return `not_before: child opens at ${cc.not_before}, before the parent's ${pc.not_before}`;
  }

  // Categories.
  if ("categories" in pc) {
    if (!("categories" in cc)) return "categories: parent limits categories, child has none";
    const pCats = new Set(lowerList(pc.categories));
    const extra = sorted(new Set(lowerList(cc.categories).filter((x) => !pCats.has(x))));
    if (extra.length) return `categories: child adds ${fmt(extra)}`;
  }

  // Cap.
  if ("max_amount" in pc) {
    const pMa = pc.max_amount;
    if (!amountOk(pMa)) return "max_amount: the parent's is malformed";
    if (!("max_amount" in cc)) return `max_amount: parent caps at ${pMa.value} ${pMa.currency}, child has no cap`;
    const cMa = cc.max_amount;
    if (!amountOk(cMa)) return "max_amount: the child's is malformed";
    if (cMa.currency !== pMa.currency) return `max_amount: currency ${cMa.currency} differs from the parent's ${pMa.currency}`;
    if (cMa.value > pMa.value) return `max_amount: child cap ${cMa.value} exceeds the parent's ${pMa.value}`;
  }

  // Verbs and counterparties, on effective scope.
  const pActs = "actions" in pc ? new Set(lowerList(pc.actions)) : null;
  const cActs = "actions" in cc ? new Set(lowerList(cc.actions)) : null;
  const pScope = verbScope(pc);
  const cScope = verbScope(cc);
  if (pActs !== null) {
    if (cActs !== null) {
      const extra = sorted([...cActs].filter((v) => !pActs.has(v)));
      if (extra.length) return `actions: child adds ${fmt(extra)}`;
    } else {
      if (cScope === null) return `actions: parent limits verbs to ${fmt(sorted(pActs))}, child has no actions`;
      for (const [cid, verbs] of cScope) {
        if (verbs === null) return `actions: child allows every verb at '${cid}', parent limits verbs to ${fmt(sorted(pActs))}`;
        const extra = sorted([...verbs].filter((v) => !pActs.has(v)));
        if (extra.length) return `actions: child adds ${fmt(extra)} at '${cid}'`;
      }
    }
  }
  if (pScope !== null) {
    if (cScope === null) return "counterparties: parent limits counterparties, child has none";
    for (const [cid, verbs] of cScope) {
      if (!pScope.has(cid)) return `counterparties: child adds '${cid}'`;
      const pv = pScope.get(cid)!;
      if (pv !== null) {
        if (verbs === null) return `counterparties: child allows every verb at '${cid}', parent allows ${fmt(sorted(pv))}`;
        const extra = sorted([...verbs].filter((v) => !pv.has(v)));
        if (extra.length) return `counterparties: child adds ${fmt(extra)} at '${cid}'`;
      }
    }
  }

  // Deny list: everything the parent denies stays unreachable.
  const pMerch = isObj(pc.merchants) ? pc.merchants : {};
  if ("deny" in pMerch) {
    const cMerch = isObj(cc.merchants) ? cc.merchants : {};
    const cDeny = new Set<string>(Array.isArray(cMerch.deny) ? cMerch.deny.map(String) : []);
    for (const d0 of Array.isArray(pMerch.deny) ? pMerch.deny : []) {
      const d = String(d0);
      if (!cDeny.has(d) && !(cScope !== null && !cScope.has(d))) return `merchants.deny: child does not deny '${d}'`;
    }
  }

  // Approval: the child asks at least where the parent asks.
  if ("approval" in pc) {
    const pa = pc.approval;
    if (!isObj(pa)) return "approval: the parent's is malformed";
    const ca = isObj(cc.approval) ? cc.approval : {};
    const cAsk = new Set(lowerList(ca.actions));
    for (const v of lowerList(pa.actions)) {
      if (cAsk.has(v)) continue;
      const reachable = (cActs === null || cActs.has(v)) &&
        (cScope === null || [...cScope.values()].some((verbs) => verbs === null || verbs.has(v)));
      if (reachable) return `approval: parent asks before '${v}', child does not`;
    }
    if ("above" in pa) {
      const pAb = pa.above;
      if (!amountOk(pAb)) return "approval.above: the parent's is malformed";
      const cAb = ca.above;
      const cMa = cc.max_amount;
      const ok = (amountOk(cAb) && cAb.currency === pAb.currency && cAb.value <= pAb.value) ||
        (amountOk(cMa) && cMa.currency === pAb.currency && cMa.value <= pAb.value);
      if (!ok) return `approval.above: parent asks above ${pAb.value} ${pAb.currency}, child does not`;
    }
  }
  return null;
}

interface ChainResult {
  ok: boolean;
  code: string;
  detail: string;
  links: SignedMandate[];
  rootKey: string | null;
}

/** Walk a child mandate up to its root. Structural, signature and narrowing
 *  failures all land here; issuer trust of the root is the caller's. */
function walkChain(signed: SignedMandate): ChainResult {
  const links: SignedMandate[] = [signed];
  let cur: SignedMandate = signed;
  let reachedRoot = false;
  for (let i = 0; i < MAX_CHAIN_LINKS; i++) {
    const constraints = (cur.mandate as Record<string, any>).constraints ?? {};
    const deleg = isObj(constraints) ? constraints.delegation : null;
    if (!isObj(deleg) || !("parent" in deleg)) { reachedRoot = true; break; }
    const parent = deleg.parent;
    if (!(isObj(parent) && isObj(parent.mandate) && (parent.mandate.constraints == null || isObj(parent.mandate.constraints)))) {
      return { ok: false, code: "delegation", detail: `malformed parent mandate at depth ${links.length}`, links: [signed], rootKey: null };
    }
    links.push(parent as SignedMandate);
    cur = parent as SignedMandate;
  }
  if (!reachedRoot) {
    return { ok: false, code: "delegation", detail: `delegation chain exceeds ${MAX_CHAIN_LINKS} links`, links: [signed], rootKey: null };
  }
  const fail = (code: string, detail: string): ChainResult => ({ ok: false, code, detail, links: [signed], rootKey: null });

  for (let i = 0; i < links.length - 1; i++) {
    const child = links[i];
    const parent = links[i + 1];
    const cm = child.mandate as Record<string, any>;
    const pm = parent.mandate as Record<string, any>;
    const pid = pm.mandate_id;
    if (!verifySignature(child)) return fail("delegation", `signature of link ${i} (${cm.mandate_id}) is invalid`);
    const pKeys = constraintKeysFor(pm.version);
    const pc: Record<string, any> = pm.constraints ?? {};
    if (pKeys === null) return fail("delegation", `parent ${pid} has unsupported version ${JSON.stringify(pm.version)}`);
    const bad = setDiff(Object.keys(pc), pKeys);
    if (bad.length) return fail("delegation", `parent ${pid} carries constraint(s) its version cannot enforce: ${fmt(sorted(bad))}`);
    if (!SCOPING_KEYS.some((k) => k in pc)) return fail("delegation", `parent ${pid} has no scope`);
    const cDeleg = (cm.constraints ?? {}).delegation;
    if (!isObj(cDeleg) || Object.keys(cDeleg).some((k) => !(DELEGATION_KEYS as readonly string[]).includes(k))) {
      return fail("delegation", `malformed delegation constraint on link ${i}`);
    }
    const pDeleg = pc.delegation;
    const pMax = isObj(pDeleg) ? pDeleg.max_depth : undefined;
    if (!isObj(pDeleg) || Object.keys(pDeleg).some((k) => !(DELEGATION_KEYS as readonly string[]).includes(k)) || !isInt(pMax) || pMax < 1) {
      return fail("delegation", `parent ${pid} does not allow delegation`);
    }
    const cMax = "max_depth" in cDeleg ? cDeleg.max_depth : 0;
    if (!isInt(cMax) || cMax < 0 || cMax > pMax - 1) {
      return fail("delegation_scope", `child ${cm.mandate_id} max_depth ${JSON.stringify(cMax)} exceeds the parent's remaining depth ${pMax - 1}`);
    }
    const pKey = isObj(pm.subject) ? pm.subject.public_key : undefined;
    if (typeof pKey !== "string" || !pKey) return fail("delegation", `parent ${pid} has no subject.public_key, so no delegate can sign under it`);
    const cKey = isObj(child.signature) ? child.signature.public_key : undefined;
    if (cKey !== pKey) return fail("delegation", `link ${i} (${cm.mandate_id}) is not signed by its parent's subject key`);
    const problem = widening(cm, pm);
    if (problem !== null) return fail("delegation_scope", `child ${cm.mandate_id} widens parent ${pid}: ${problem}`);
  }

  const root = links[links.length - 1];
  const rm = root.mandate as Record<string, any>;
  if (!verifySignature(root)) return fail("delegation", `root signature (${rm.mandate_id}) is invalid`);
  const rootKey = isObj(root.signature) ? root.signature.public_key : null;
  return {
    ok: true,
    code: "delegation",
    detail: `delegation chain of ${links.length} links roots in ${rm.mandate_id}`,
    links,
    rootKey: typeof rootKey === "string" ? rootKey : null,
  };
}

/** Mandate ids from the leaf to the root, or [] if the envelope is malformed. */
function chainIds(signed: unknown): string[] {
  const ids: string[] = [];
  let cur: unknown = signed;
  for (let i = 0; i <= MAX_CHAIN_LINKS; i++) {
    if (!isObj(cur) || !isObj(cur.mandate)) return [];
    const mid = cur.mandate.mandate_id;
    if (typeof mid !== "string") return [];
    ids.push(mid);
    const constraints = cur.mandate.constraints;
    const deleg = isObj(constraints) ? constraints.delegation : null;
    if (!isObj(deleg) || !("parent" in deleg)) return ids;
    cur = deleg.parent;
  }
  return [];
}

/**
 * Record that `transaction` was carried out under `signed`, for the limits.
 * Writes one use record under the mandate's id and under every ancestor in its
 * delegation chain, so a parent's limits bind all its children. Call it after
 * acting on an "allow"; the verifier itself never writes. Returns the ids
 * written. Throws on a malformed envelope rather than silently recording
 * nothing, since a missed record would loosen the limits.
 */
export function recordUse(signed: SignedMandate, transaction: Transaction, store: UsageStore, opts: { now?: Date } = {}): string[] {
  const ids = chainIds(signed);
  if (!ids.length) throw new Error("recordUse: malformed signed mandate");
  const now = opts.now ?? new Date();
  const txn: Transaction = transaction && typeof transaction === "object" ? transaction : {};
  const use: Use = {
    at: epoch(now),
    action: typeof txn.action === "string" ? txn.action.toLowerCase() : null,
    amount: amountOk(txn.amount) ? { value: txn.amount.value, currency: txn.amount.currency } : null,
  };
  for (const mid of ids) store.record(mid, { ...use });
  return ids;
}

// --- the verifier ---------------------------------------------------------------

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
  if (!transaction || typeof transaction !== "object") {
    transaction = {} as Transaction;
  }

  const signatureValid = verifySignature(signed);
  const checks: Check[] = [];

  // --- Wire version ---
  const version = mandate.version;
  let knownKeys = constraintKeysFor(version);
  if (knownKeys === null) {
    checks.push(check("version", false,
      `unsupported mandate version ${JSON.stringify(version)}; this verifier supports ${fmt(SUPPORTED_VERSIONS)}`));
    knownKeys = V02_CONSTRAINT_KEYS;
  }

  // --- Issuer trust (the critical check), through the chain for a child ---
  const trusted = normalizeTrusted(opts.trustedKeys);
  if (trusted === null && !opts.allowUnverifiedIssuer) {
    return verdict("deny", signatureValid, [], mandate,
      "no trusted issuer keys supplied: pass trustedKeys: [...] (recommended) or allowUnverifiedIssuer: true to accept any signer");
  }
  const delegation = constraints.delegation;
  const isChild = isObj(delegation) && "parent" in delegation;
  let links: SignedMandate[] = [signed];
  if (isChild) {
    const chain = walkChain(signed);
    checks.push(check(chain.code, chain.ok, chain.detail));
    if (chain.ok) links = chain.links;
    if (trusted !== null) {
      const rootOk = typeof chain.rootKey === "string" && trusted.has(chain.rootKey);
      checks.push(check("issuer_trusted", rootOk,
        rootOk ? "delegation chain roots in a trusted issuer key" : "delegation chain does not root in a trusted issuer key"));
    }
  } else {
    if ("delegation" in constraints && (
      !isObj(delegation) || !Object.keys(delegation).length
      || Object.keys(delegation).some((k) => !(DELEGATION_KEYS as readonly string[]).includes(k))
      || !isInt(delegation.max_depth) || delegation.max_depth < 0)) {
      checks.push(check("delegation", false, "malformed delegation constraint"));
    }
    if (trusted !== null) {
      const envKey = signed.signature?.public_key;
      const ok = typeof envKey === "string" && trusted.has(envKey);
      checks.push(check("issuer_trusted", ok,
        ok ? "signed by a trusted issuer key" : "signing key is not in the trusted-issuer set"));
    }
  }

  // --- Constraint sanity ---
  const unknown = setDiff(Object.keys(constraints), V02_CONSTRAINT_KEYS);
  const needsV02 = setDiff(Object.keys(constraints), knownKeys).filter((k) => !unknown.includes(k));
  if (unknown.length) {
    checks.push(check("constraints_enforceable", false, `unenforceable constraint(s) present: [${unknown.sort().join(", ")}]`));
  } else if (needsV02.length) {
    checks.push(check("constraints_enforceable", false,
      `constraint(s) ${fmt(sorted(needsV02))} need mandate version ${VERSION}; this mandate declares ${JSON.stringify(version)}`));
  }
  const hasScope = SCOPING_KEYS.some((k) => k in constraints);
  checks.push(check("has_scope", hasScope,
    hasScope ? "mandate defines spending limits" : "mandate has no spending constraints (unbounded); refused"));

  // --- Expiry ---
  // Strict ISO-8601 only, matching Python's parse_iso (datetime.fromisoformat).
  // Date.parse is too lenient: it accepts "30 June 2026" and reads naive
  // timestamps as LOCAL time, so the same signed mandate could be allowed in TS
  // while denied in Python (audit 2026-06-10 finding #4). A naive timestamp is
  // anchored to UTC here, exactly as Python does.
  const expiresAt = parseIsoStrict(mandate.expires_at);
  const expired = Number.isNaN(expiresAt) || now.getTime() > expiresAt;
  checks.push(check("not_expired", !expired, expired ? "mandate has expired" : "within validity window"));

  // --- Window start (0.2) ---
  if ("not_before" in constraints) {
    const nb = parseIsoStrict(constraints.not_before);
    if (Number.isNaN(nb)) {
      checks.push(check("not_before", false, "malformed not_before"));
    } else {
      const ok = now.getTime() >= nb;
      checks.push(check("not_before", ok,
        ok ? `window open since ${constraints.not_before}` : `mandate is not yet valid: window opens at ${constraints.not_before}`));
    }
  }

  // --- Category (presence-based; empty list allows nothing) ---
  if ("categories" in constraints) {
    const cats: unknown[] = Array.isArray(constraints.categories) ? constraints.categories : [];
    const txnCat = typeof transaction.category === "string" ? transaction.category.toLowerCase() : "";
    const ok = cats.map((c) => String(c).toLowerCase()).includes(txnCat);
    checks.push(check("category", ok, `${txnCat || "(none)"} ${ok ? "in" : "not in"} [${cats.join(", ")}]`));
  }

  // --- Merchant allow / deny (presence-based) ---
  const rawMerchants = constraints.merchants;
  const merchants = isObj(rawMerchants) ? rawMerchants : {};
  const merchant = transaction.merchant ?? "";
  if ("allow" in merchants) {
    const allow: string[] = Array.isArray(merchants.allow) ? merchants.allow : [];
    const ok = allow.includes(merchant);
    checks.push(check("merchant_allow", ok, `'${merchant}' ${ok ? "is" : "is not"} on the allow-list`));
  }
  if ("deny" in merchants) {
    const deny: string[] = Array.isArray(merchants.deny) ? merchants.deny : [];
    const ok = !deny.includes(merchant);
    checks.push(check("merchant_deny", ok, `'${merchant}' ${ok ? "is not" : "is"} on the deny-list`));
  }

  // --- Per-verb counterparty scope (0.2) ---
  if ("counterparties" in constraints) {
    const cps = constraints.counterparties;
    const txnAct = typeof transaction.action === "string" ? transaction.action.toLowerCase() : "";
    if (!isObj(cps) || !Object.values(cps).every((v) => Array.isArray(v))) {
      checks.push(check("counterparty_scope", false, "malformed counterparties constraint"));
    } else if (typeof merchant !== "string" || !Object.prototype.hasOwnProperty.call(cps, merchant)) {
      checks.push(check("counterparty_scope", false, `'${merchant}' is not a listed counterparty`));
    } else {
      const verbs = lowerList(cps[merchant]);
      const ok = verbs.includes(txnAct);
      checks.push(check("counterparty_scope", ok,
        `'${merchant}' is scoped to ${fmt(verbs)}; ${txnAct || "(none)"} is${ok ? "" : " not"} allowed there`));
    }
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

  // --- Action verb (presence-based; empty list allows nothing) ---
  if ("actions" in constraints) {
    const acts: unknown[] = Array.isArray(constraints.actions) ? constraints.actions : [];
    const txnAct = typeof transaction.action === "string" ? transaction.action.toLowerCase() : "";
    const ok = acts.map((a) => String(a).toLowerCase()).includes(txnAct);
    checks.push(check("action", ok, `action ${txnAct || "(none)"} ${ok ? "in" : "not in"} [${acts.join(", ")}]`));
  }

  // --- Approval (step-up): some verbs or amounts need a step mandate ---
  let approvalRequired = false;
  if ("approval" in constraints) {
    const rawApproval = constraints.approval;
    const approval = isObj(rawApproval) ? rawApproval : null;
    if (approval === null) {
      checks.push(check("approval", false, "malformed approval constraint"));
    } else {
      const reasons: string[] = [];
      const askActs: unknown[] = Array.isArray(approval.actions) ? approval.actions : [];
      const txnAct = typeof transaction.action === "string" ? transaction.action.toLowerCase() : "";
      if (askActs.map((a) => String(a).toLowerCase()).includes(txnAct)) {
        reasons.push(`action ${txnAct} needs approval`);
      }
      const above = approval.above;
      if (above != null) {
        const amt = transaction.amount;
        if (!isInt(above.value) || !above.currency) {
          reasons.push("malformed approval.above");
        } else if (amt && amt.value != null) {
          if (!isInt(amt.value) || amt.currency !== above.currency) {
            reasons.push(`amount ${amt.value} ${amt.currency} cannot be compared with approval threshold ${above.value} ${above.currency}`);
          } else if (amt.value > above.value) {
            reasons.push(`${amt.value} ${amt.currency} > approval threshold ${above.value} ${above.currency}`);
          }
        }
      }
      if (reasons.length) {
        const step = transaction.approval;
        if (step == null) {
          approvalRequired = true;
          checks.push(check("approval", false, `approval required: ${reasons.join("; ")}`));
        } else {
          const { approval: _omit, ...target } = transaction;
          void _omit;
          const inner = withinLimits(step) && step && typeof step === "object" && (step as any).mandate
            ? verify(step, target, {
              now, trustedKeys: opts.trustedKeys, allowUnverifiedIssuer: opts.allowUnverifiedIssuer,
              store: opts.store, revocationLists: opts.revocationLists,
            })
            : verdict("deny", false, [], {}, "malformed step mandate");
          const stepAgent = (step as any)?.mandate?.subject?.agent_id;
          const sameAgent = stepAgent != null && stepAgent === mandate?.subject?.agent_id;
          if (inner.decision === "allow" && sameAgent) {
            checks.push(check("approval", true, `step mandate ${inner.mandate_id} approves this transaction`));
          } else if (inner.decision === "allow") {
            checks.push(check("approval", false, "step mandate is for a different agent"));
          } else {
            checks.push(check("approval", false, `step mandate rejected: ${inner.rationale}`));
          }
        }
      }
    }
  }

  // --- Revocation (0.2), every link of the chain ---
  const lists = normalizeLists(opts.revocationLists);
  for (const link of links) {
    const lc = (link.mandate as Record<string, any>).constraints ?? {};
    if (isObj(lc) && "revocation" in lc) checkRevocation(link, now, trusted, lists, checks);
  }

  // --- Usage limits (0.2), every link of the chain, against the store ---
  const limited = links.filter((link) => {
    const lc = (link.mandate as Record<string, any>).constraints ?? {};
    return isObj(lc) && "limits" in lc;
  });
  if (limited.length) {
    if (opts.store == null) {
      checks.push(check("limits_store", false, "mandate declares usage limits but no state store was supplied; pass store:"));
    } else {
      const nowS = epoch(now);
      for (const link of limited) checkLimits(link.mandate as Record<string, any>, transaction, nowS, opts.store, checks);
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
  if (failed.length === 1 && approvalRequired && failed[0].constraint === "approval") {
    return verdict("ask", true, checks, mandate, "needs approval: " + failed[0].detail, intentAlignment);
  }
  if (failed.length) {
    return verdict("deny", true, checks, mandate, "out of scope: " + failed.map((c) => c.detail).join("; "), intentAlignment);
  }
  return verdict("allow", true, checks, mandate, "in scope: " + checks.map((c) => c.detail).join("; "), intentAlignment);
}
