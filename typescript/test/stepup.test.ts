/**
 * Action verbs, approval (step-up) rules, step mandates and the RFC 9396
 * cross-walk. Added for the Mandate Sandbox (2026-10-01). Run with: npm test.
 *
 * Note the v0 rule this inherits: under a max_amount cap every transaction
 * states its amount, so non-monetary verbs (cancel, read, submit) carry a
 * zero amount rather than none. A missing amount under a cap is a deny.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { verify, type Transaction } from "../src/verifier.ts";
import { signMandate, publicKeyFromSeed } from "../src/signing.ts";
import { buildMandate, stepMandate, validate } from "../src/mandate.ts";
import { toAuthorizationDetails } from "../src/crosswalk.ts";

const ISSUER = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const STRANGER = Buffer.from(Array.from({ length: 32 }, (_, i) => 99 - i));
const PUB = publicKeyFromSeed(ISSUER).toString("base64");
const NOW = new Date("2026-10-01T12:00:00Z");

function bankMandate(extra: Partial<Parameters<typeof buildMandate>[0]> = {}) {
  return buildMandate({
    agentId: "agent-tidy",
    intent: "life admin for Alex",
    categories: ["4900", "4814", "4899"],
    merchants: { allow: ["MID-10231", "MID-10477", "MID-30905"] },
    maxAmount: { value: 150000, currency: "GBP" },
    actions: ["read", "draft", "submit", "pay", "cancel"],
    approval: { actions: ["cancel"], above: { value: 20000, currency: "GBP" } },
    issuedAt: NOW,
    ttlDays: 7,
    ...extra,
  });
}

const vrf = (s: any, txn: Transaction, opts: any = {}) =>
  verify(s, txn, { trustedKeys: [PUB], now: NOW, ...opts });

const PAY_SMALL: Transaction = { action: "pay", merchant: "MID-10231", category: "4900", amount: { value: 11840, currency: "GBP" } };

test("buildMandate carries actions and approval; validate accepts them", () => {
  const m = bankMandate();
  assert.deepEqual(m.constraints.actions, ["read", "draft", "submit", "pay", "cancel"]);
  assert.deepEqual(m.constraints.approval, { actions: ["cancel"], above: { value: 20000, currency: "GBP" } });
  assert.deepEqual(validate(m), []);
});

test("buildMandate rejects a non-integer approval threshold", () => {
  assert.throws(() => bankMandate({ approval: { above: { value: 50.5, currency: "GBP" } } }), /integer/);
});

test("an allowed verb under the threshold is allowed outright", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), PAY_SMALL);
  assert.equal(v.decision, "allow");
  assert.ok(v.matched.some((c) => c.constraint === "action"));
});

test("a verb outside the allow-list is denied", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), { ...PAY_SMALL, action: "share" });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "action"));
});

test("a transaction with no verb is denied when actions are constrained (fail closed)", () => {
  const { action: _a, ...noVerb } = PAY_SMALL;
  void _a;
  const v = vrf(signMandate(bankMandate() as any, ISSUER), noVerb);
  assert.equal(v.decision, "deny");
});

test("an empty actions list allows nothing", () => {
  const v = vrf(signMandate(bankMandate({ actions: [] }) as any, ISSUER), PAY_SMALL);
  assert.equal(v.decision, "deny");
});

test("a verb that needs approval returns ask, not deny", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" } });
  assert.equal(v.decision, "ask");
  assert.equal(v.signature_valid, true);
  assert.match(v.rationale, /needs approval/);
  assert.equal(v.failed.length, 1);
  assert.equal(v.failed[0].constraint, "approval");
});

test("an amount above the approval threshold but under the cap returns ask", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), { ...PAY_SMALL, amount: { value: 50000, currency: "GBP" } });
  assert.equal(v.decision, "ask");
  assert.match(v.rationale, /approval threshold/);
});

test("over the cap is deny even though it is also above the approval threshold", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), { ...PAY_SMALL, amount: { value: 200000, currency: "GBP" } });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "amount"));
});

test("ask never masks another failure: wrong merchant plus approval needed is deny", () => {
  const v = vrf(signMandate(bankMandate() as any, ISSUER), { action: "cancel", merchant: "MID-99999", category: "4899", amount: { value: 0, currency: "GBP" } });
  assert.equal(v.decision, "deny");
});

test("a step mandate from the issuer turns ask into allow", () => {
  const parent = bankMandate();
  const signedParent = signMandate(parent as any, ISSUER);
  const txn: Transaction = { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" }, description: "cancel StreamBox" };
  assert.equal(vrf(signedParent, txn).decision, "ask");

  const step = stepMandate(parent, txn, { issuedAt: NOW });
  assert.deepEqual(validate(step), []);
  assert.deepEqual(step.constraints.actions, ["cancel"]);
  assert.deepEqual(step.constraints.merchants, { allow: ["MID-30905"] });
  assert.equal(step.subject.agent_id, "agent-tidy");
  assert.match(step.constraints.intent ?? "", new RegExp(parent.mandate_id));

  const v = vrf(signedParent, { ...txn, approval: signMandate(step as any, ISSUER) });
  assert.equal(v.decision, "allow");
  assert.ok(v.matched.some((c) => c.constraint === "approval" && /step mandate/.test(c.detail)));
});

test("a step mandate signed by an untrusted key does not approve", () => {
  const parent = bankMandate();
  const txn: Transaction = { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" } };
  const step = signMandate(stepMandate(parent, txn, { issuedAt: NOW }) as any, STRANGER);
  const v = vrf(signMandate(parent as any, ISSUER), { ...txn, approval: step });
  assert.equal(v.decision, "deny");
  assert.match(v.rationale, /step mandate rejected/);
});

test("a step mandate for a different agent does not approve", () => {
  const parent = bankMandate();
  const txn: Transaction = { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" } };
  const step = stepMandate({ ...parent, subject: { agent_id: "someone-else" } }, txn, { issuedAt: NOW });
  const v = vrf(signMandate(parent as any, ISSUER), { ...txn, approval: signMandate(step as any, ISSUER) });
  assert.equal(v.decision, "deny");
  assert.match(v.rationale, /different agent/);
});

test("an expired step mandate does not approve", () => {
  const parent = bankMandate();
  const txn: Transaction = { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" } };
  const step = stepMandate(parent, txn, { issuedAt: new Date(NOW.getTime() - 3600_000), ttlMinutes: 5 });
  const v = vrf(signMandate(parent as any, ISSUER), { ...txn, approval: signMandate(step as any, ISSUER) });
  assert.equal(v.decision, "deny");
  assert.match(v.rationale, /expired/);
});

test("a step mandate narrowed to a different transaction does not approve this one", () => {
  const parent = bankMandate();
  const approvedTxn: Transaction = { action: "pay", merchant: "MID-10231", category: "4900", amount: { value: 50000, currency: "GBP" } };
  const step = signMandate(stepMandate(parent, approvedTxn, { issuedAt: NOW }) as any, ISSUER);
  // Same step mandate presented for a bigger payment.
  const v = vrf(signMandate(parent as any, ISSUER), { ...approvedTxn, amount: { value: 60000, currency: "GBP" }, approval: step });
  assert.equal(v.decision, "deny");
});

test("a malformed approval envelope is deny, never ask", () => {
  const parent = bankMandate();
  const txn: Transaction = { action: "cancel", merchant: "MID-30905", category: "4899", amount: { value: 0, currency: "GBP" } };
  for (const bad of [42, "x", [], {}, { mandate: null }, { mandate: "nope" }] as any[]) {
    const v = vrf(signMandate(parent as any, ISSUER), { ...txn, approval: bad });
    assert.equal(v.decision, "deny", `approval=${JSON.stringify(bad)}`);
  }
});

test("actions alone do not count as scope (unbounded mandate still refused)", () => {
  const m = buildMandate({ agentId: "agent-tidy", actions: ["read"], issuedAt: NOW });
  const v = vrf(signMandate(m as any, ISSUER), { action: "read" });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "has_scope"));
});

test("a verifier that does not know these keys fails closed (documented behaviour)", () => {
  // Simulated by presenting a constraint key this verifier does not know.
  const m = bankMandate();
  (m.constraints as any).velocity = { per_day: 3 };
  const v = vrf(signMandate(m as any, ISSUER), PAY_SMALL);
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "constraints_enforceable"));
});

test("stepMandate refuses a target with nothing to scope to", () => {
  assert.throws(() => stepMandate(bankMandate(), { action: "read" }), /scoped to/);
});

test("cross-walk to RFC 9396 authorization_details", () => {
  const m = bankMandate();
  const [d] = toAuthorizationDetails(m);
  assert.equal(d.type, "mandatekit:mandate:v0");
  assert.equal(d.identifier, m.mandate_id);
  assert.deepEqual(d.actions, ["read", "draft", "submit", "pay", "cancel"]);
  assert.deepEqual(d.locations, ["MID-10231", "MID-10477", "MID-30905"]);
  assert.deepEqual(d.datatypes, ["4900", "4814", "4899"]);
  assert.deepEqual(d.max_amount, { value: 150000, currency: "GBP" });
  assert.deepEqual(d.approval, { actions: ["cancel"], above: { value: 20000, currency: "GBP" } });
  assert.equal(d.valid_from, m.issued_at);
  assert.equal(d.valid_until, m.expires_at);
  assert.equal(d.subject.agent_id, "agent-tidy");
  // Output is JSON-safe and independent of the input object.
  d.actions!.push("share");
  assert.equal(m.constraints.actions!.length, 5);
});
