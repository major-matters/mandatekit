/**
 * Cross-walk from a mandate onto OAuth 2.0 Rich Authorization Requests
 * (RFC 9396) `authorization_details`. Banks already express fine-grained
 * consent this way (open banking payment-initiation and account-access
 * consents ride on it), so a mandate that can be read as an authorization
 * detail is one a bank's existing consent stack can reason about.
 *
 * One mandate becomes one authorization detail. The RFC's common fields carry
 * what they can: `actions` from the mandate's action allow-list, `locations`
 * from the merchant allow-list or, for a per-verb scoped mandate, the sorted
 * counterparty ids, `datatypes` from the categories, `identifier` from the
 * mandate id. Everything with no common-field home (amount cap, approval
 * rules, denied merchants, the per-verb counterparty map, usage limits, the
 * revocation list id, the parent of a delegated mandate, the intent sentence)
 * travels as type-specific fields, which the RFC permits. `valid_from` is
 * `not_before` when the mandate has one, else `issued_at`. The mapping is a
 * draft; the `type` is MandateKit's own until a registry assigns one.
 */

import type { Amount, Limits, Mandate, Revocation } from "./mandate.ts";

export const AUTHORIZATION_DETAIL_TYPE = "mandatekit:mandate:v0.2";

export interface AuthorizationDetail {
  type: string;
  identifier: string;
  actions?: string[];
  locations?: string[];
  datatypes?: string[];
  subject: { agent_id: string; public_key?: string };
  valid_from: string;
  valid_until: string;
  intent?: string;
  max_amount?: Amount;
  denied_locations?: string[];
  approval?: { actions?: string[]; above?: Amount };
  counterparties?: Record<string, string[]>;
  limits?: Limits;
  revocation?: Revocation;
  delegation?: { parent?: string; max_depth?: number };
}

export function toAuthorizationDetails(mandate: Mandate): AuthorizationDetail[] {
  const c = mandate.constraints ?? {};
  const d: AuthorizationDetail = {
    type: AUTHORIZATION_DETAIL_TYPE,
    identifier: mandate.mandate_id,
    subject: { agent_id: mandate.subject.agent_id },
    valid_from: typeof c.not_before === "string" ? c.not_before : mandate.issued_at,
    valid_until: mandate.expires_at,
  };
  if (typeof mandate.subject.public_key === "string") d.subject.public_key = mandate.subject.public_key;
  if (c.actions) d.actions = [...c.actions];
  if (c.merchants?.allow) d.locations = [...c.merchants.allow];
  else if (c.counterparties && typeof c.counterparties === "object") d.locations = Object.keys(c.counterparties).sort();
  if (c.merchants?.deny) d.denied_locations = [...c.merchants.deny];
  if (c.categories) d.datatypes = [...c.categories];
  if (c.intent) d.intent = c.intent;
  if (c.max_amount) d.max_amount = { ...c.max_amount };
  if (c.approval) {
    d.approval = {};
    if (c.approval.actions) d.approval.actions = [...c.approval.actions];
    if (c.approval.above) d.approval.above = { ...c.approval.above };
  }
  if (c.counterparties && typeof c.counterparties === "object") {
    d.counterparties = Object.fromEntries(Object.entries(c.counterparties).map(([k, v]) => [k, [...v]]));
  }
  if (c.limits && typeof c.limits === "object") d.limits = JSON.parse(JSON.stringify(c.limits));
  if (c.revocation && typeof c.revocation === "object") d.revocation = { ...c.revocation };
  if (c.delegation && typeof c.delegation === "object") {
    const out: { parent?: string; max_depth?: number } = {};
    const pm = c.delegation.parent?.mandate as Record<string, unknown> | undefined;
    if (pm && typeof pm === "object" && "mandate_id" in pm) out.parent = pm.mandate_id as string;
    if ("max_depth" in c.delegation) out.max_depth = c.delegation.max_depth;
    if (Object.keys(out).length) d.delegation = out;
  }
  return [d];
}
