/**
 * Cross-walk from a mandate onto OAuth 2.0 Rich Authorization Requests
 * (RFC 9396) `authorization_details`. Banks already express fine-grained
 * consent this way (open banking payment-initiation and account-access
 * consents ride on it), so a mandate that can be read as an authorization
 * detail is one a bank's existing consent stack can reason about.
 *
 * One mandate becomes one authorization detail. The RFC's common fields carry
 * what they can: `actions` from the mandate's action allow-list, `locations`
 * from the merchant allow-list, `datatypes` from the categories, `identifier`
 * from the mandate id. Everything with no common-field home (amount cap,
 * approval rules, denied merchants, validity window, the intent sentence)
 * travels as type-specific fields, which the RFC permits. The mapping is a
 * draft; the `type` is MandateKit's own until a registry assigns one.
 */

import type { Mandate } from "./mandate.ts";

export const AUTHORIZATION_DETAIL_TYPE = "mandatekit:mandate:v0";

export interface AuthorizationDetail {
  type: string;
  identifier: string;
  actions?: string[];
  locations?: string[];
  datatypes?: string[];
  subject: { agent_id: string };
  valid_from: string;
  valid_until: string;
  intent?: string;
  max_amount?: { value: number; currency: string };
  denied_locations?: string[];
  approval?: { actions?: string[]; above?: { value: number; currency: string } };
}

export function toAuthorizationDetails(mandate: Mandate): AuthorizationDetail[] {
  const c = mandate.constraints ?? {};
  const d: AuthorizationDetail = {
    type: AUTHORIZATION_DETAIL_TYPE,
    identifier: mandate.mandate_id,
    subject: { agent_id: mandate.subject.agent_id },
    valid_from: mandate.issued_at,
    valid_until: mandate.expires_at,
  };
  if (c.actions) d.actions = [...c.actions];
  if (c.merchants?.allow) d.locations = [...c.merchants.allow];
  if (c.merchants?.deny) d.denied_locations = [...c.merchants.deny];
  if (c.categories) d.datatypes = [...c.categories];
  if (c.intent) d.intent = c.intent;
  if (c.max_amount) d.max_amount = { ...c.max_amount };
  if (c.approval) {
    d.approval = {};
    if (c.approval.actions) d.approval.actions = [...c.approval.actions];
    if (c.approval.above) d.approval.above = { ...c.approval.above };
  }
  return [d];
}
