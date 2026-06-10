/**
 * MandateKit v0 (TypeScript) test suite. Run with: npm test  (node --test).
 * Includes the five security-review attack regressions.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { compile, ruleBasedParser } from "../src/compiler.ts";
import { verify, type Transaction, type VerifyOptions } from "../src/verifier.ts";
import { verifySignature, signMandate, publicKeyFromSeed } from "../src/signing.ts";
import { validate, buildMandate } from "../src/mandate.ts";

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const PUB = publicKeyFromSeed(KEY).toString("base64");
const NOW = new Date("2026-06-05T12:00:00Z");
const CANON =
  "Allow this agent to buy running shoes from any apparel retailer " +
  "up to $500 per transaction, expires June 30";

function signed() {
  return compile(CANON, { agentId: "agent-7", privateKey: KEY, now: NOW });
}

// verify() pinned to the test issuer key unless a test overrides.
function vrf(s: any, txn: Transaction, opts: VerifyOptions = {}) {
  return verify(s, txn, { trustedKeys: [PUB], now: NOW, ...opts });
}

const BIG: Transaction = { merchant: "Rolex", category: "jewelry", amount: { value: 1_000_000, currency: "USD" } };

test("rule-based parser handles the canonical example", () => {
  const p = ruleBasedParser(CANON, NOW);
  assert.equal(p.intent, "buy running shoes");
  assert.deepEqual(p.categories, ["apparel"]);
  assert.deepEqual(p.max_amount, { value: 500, currency: "USD" });
  assert.equal(p.expires_at?.toISOString(), "2026-06-30T23:59:59.000Z");
});

test("compile produces a valid, signed mandate", () => {
  const s = signed();
  assert.equal(verifySignature(s), true);
  assert.deepEqual(validate(s.mandate as any), []);
  assert.equal((s.mandate as any).subject.agent_id, "agent-7");
});

test("currency symbols", () => {
  assert.deepEqual(ruleBasedParser("up to £200").max_amount, { value: 200, currency: "GBP" });
  assert.deepEqual(ruleBasedParser("under 50 euros").max_amount, { value: 50, currency: "EUR" });
});

test("verify allows an in-scope transaction", () => {
  const v = vrf(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 240, currency: "USD" } });
  assert.equal(v.decision, "allow");
  assert.equal(v.signature_valid, true);
});

test("verify denies an over-cap amount", () => {
  const v = vrf(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 600, currency: "USD" } });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "amount"));
});

test("verify denies the wrong category", () => {
  const v = vrf(signed(), { merchant: "BestBuy", category: "electronics", amount: { value: 100, currency: "USD" } });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "category"));
});

test("verify denies an expired mandate", () => {
  const v = vrf(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 100, currency: "USD" } }, { now: new Date("2026-07-01T00:00:00Z") });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "not_expired"));
});

test("verify rejects a tampered mandate", () => {
  const tampered = JSON.parse(JSON.stringify(signed()));
  tampered.mandate.constraints.max_amount.value = 100000;
  const v = vrf(tampered, { merchant: "X", category: "apparel", amount: { value: 9000, currency: "USD" } });
  assert.equal(v.decision, "deny");
  assert.equal(v.signature_valid, false);
  assert.match(v.rationale, /signature invalid/);
});

test("merchant allow-list", () => {
  const s = compile("buy coffee only from Blue Bottle up to $20", { agentId: "a", privateKey: KEY, now: NOW });
  assert.equal(vrf(s, { merchant: "Blue Bottle", amount: { value: 5, currency: "USD" } }).decision, "allow");
  assert.equal(vrf(s, { merchant: "Starbucks", amount: { value: 5, currency: "USD" } }).decision, "deny");
});

test("injected intent scorer can deny, and a scorer error never denies", () => {
  const txn: Transaction = { merchant: "Fleet Feet", category: "apparel", amount: { value: 240, currency: "USD" }, description: "garden hose" };
  assert.equal(vrf(signed(), txn, { intentScorer: () => 0.1 }).decision, "deny");
  assert.equal(vrf(signed(), txn, { intentScorer: () => 0.95 }).decision, "allow");
  const boom = vrf(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 240, currency: "USD" } }, {
    intentScorer: () => { throw new Error("model down"); },
  });
  assert.equal(boom.decision, "allow");
});

// --- SECURITY REGRESSION (the five attacks) ---

test("attack 1: forgery rejected by issuer pinning", () => {
  const atk = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const forged = compile("buy running shoes from any apparel retailer up to $9000000", { agentId: "agent-7", privateKey: atk, now: NOW });
  const v = vrf(forged, BIG); // pinned to victim PUB
  assert.equal(v.decision, "deny");
  assert.equal(v.signature_valid, true);
  assert.ok(v.failed.some((c) => c.constraint === "issuer_trusted"));
});

test("unverified issuer default fails closed", () => {
  const v = verify(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 240, currency: "USD" } }, { now: NOW });
  assert.equal(v.decision, "deny");
  assert.match(v.rationale, /trusted issuer/);
});

test("allowUnverifiedIssuer opt-in", () => {
  const v = verify(signed(), { merchant: "Fleet Feet", category: "apparel", amount: { value: 240, currency: "USD" } }, { now: NOW, allowUnverifiedIssuer: true });
  assert.equal(v.decision, "allow");
});

test("attack 2: empty constraints denied", () => {
  const s = signMandate(buildMandate({ agentId: "agent-7", issuedAt: NOW }) as any, KEY);
  const v = vrf(s, BIG);
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "has_scope"));
});

test("attack 3: empty category list denied", () => {
  const m: any = buildMandate({ agentId: "a", maxAmount: { value: 500, currency: "USD" }, issuedAt: NOW });
  m.constraints.categories = [];
  const s = signMandate(m, KEY);
  const v = vrf(s, { merchant: "X", category: "electronics", amount: { value: 10, currency: "USD" } });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "category"));
});

test("attack 4: unenforceable constraint denied", () => {
  const m: any = buildMandate({ agentId: "a", maxAmount: { value: 500, currency: "USD" }, issuedAt: NOW });
  m.constraints.max_uses = 1;
  const s = signMandate(m, KEY);
  const v = vrf(s, { merchant: "X", amount: { value: 5, currency: "USD" } });
  assert.equal(v.decision, "deny");
  assert.ok(v.failed.some((c) => c.constraint === "constraints_enforceable"));
});

test("attack 5: nested DoS rejected without crash", () => {
  let deep: any = { a: 1 };
  for (let i = 0; i < 2000; i++) deep = { x: deep };
  const bad: any = { mandate: { version: "mandatekit/v0", constraints: deep }, signature: { alg: "Ed25519", public_key: "AA==", value: "AA==" } };
  const v = verify(bad, { amount: { value: 1, currency: "USD" } }, { now: NOW, trustedKeys: [PUB] });
  assert.equal(v.decision, "deny");
  assert.match(v.rationale, /size\/nesting/);
});

test("float amount rejected at build", () => {
  assert.throws(() => buildMandate({ agentId: "a", maxAmount: { value: 19.99, currency: "USD" }, issuedAt: NOW }));
});

test("float transaction amount denied", () => {
  const s = compile("buy shoes from any apparel store up to $500", { agentId: "a", privateKey: KEY, now: NOW });
  const v = vrf(s, { merchant: "X", category: "apparel", amount: { value: 19.99, currency: "USD" } });
  assert.equal(v.decision, "deny");
});

// --- expiry parsing (audit 2026-06-10 finding #4) ---------------------------

function signedWithExpiry(expires: string) {
  const m: any = buildMandate({ agentId: "agent-7", maxAmount: { value: 500, currency: "USD" }, issuedAt: NOW });
  m.expires_at = expires;
  return signMandate(m, KEY);
}

const GOOD_TXN: Transaction = { amount: { value: 100, currency: "USD" } };

test("non-ISO expiry is denied (no Date.parse leniency)", () => {
  for (const bad of ["30 June 2026", "June 30 2026", "2026-13-01T00:00:00Z", "next year"]) {
    const v = vrf(signedWithExpiry(bad), GOOD_TXN);
    assert.equal(v.decision, "deny", `non-ISO expiry not denied: ${bad}`);
  }
});

test("canonical future expiry is allowed", () => {
  assert.equal(vrf(signedWithExpiry("2026-12-31T23:59:59Z"), GOOD_TXN).decision, "allow");
});

test("naive expiry is treated as UTC (matches Python)", () => {
  assert.equal(vrf(signedWithExpiry("2026-12-31 23:59:59"), GOOD_TXN).decision, "allow");
});
