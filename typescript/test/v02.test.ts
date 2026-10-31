/**
 * MandateKit 0.2: per-verb counterparty scope, time windows, usage limits
 * against a state store, issuer-signed revocation lists, delegation chains,
 * and the wire version bump. Mirrors python/tests/test_v02.py check for check;
 * both suites also replay fixtures/verdict-matrix.json so the two
 * implementations are proven to agree verdict for verdict, and this suite
 * re-signs every Python-signed envelope to prove the signatures are
 * byte-identical.
 *
 * Every verify() here passes an explicit `now`; nothing touches the wall clock.
 * Run with: npm test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  buildMandate,
  buildRevocationList,
  delegateMandate,
  InMemoryUsageStore,
  REASON_CODES,
  recordUse,
  signMandate,
  signRevocationList,
  SUPPORTED_VERSIONS,
  toAuthorizationDetails,
  validate,
  verify,
  verifyRevocationListSignature,
  VERSION,
  publicKeyFromSeed,
  type Mandate,
  type SignedMandate,
  type Transaction,
  type Use,
  type VerifyOptions,
} from "../src/index.ts";
import { __version__ as pkgVersion } from "../src/index.ts";
import { ruleBasedParser } from "../src/compiler.ts";
import { iso } from "../src/mandate.ts";
import { parseIsoStrict } from "../src/verifier.ts";
import pkg from "../package.json" with { type: "json" };

const FIXTURE = new URL("../../fixtures/verdict-matrix.json", import.meta.url);

const ISSUER = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const DELEGATE = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32));
const STRANGER = Buffer.from(Array.from({ length: 32 }, (_, i) => 99 - i));
const PUB = publicKeyFromSeed(ISSUER).toString("base64");
const DPUB_RAW = publicKeyFromSeed(DELEGATE);
const NOW = new Date("2026-10-12T12:00:00Z");
const ISSUED = new Date(NOW.getTime() - 86400_000);
const EXPIRES = new Date(NOW.getTime() + 7 * 86400_000);
const plus = (d: Date, seconds: number) => new Date(d.getTime() + seconds * 1000);

const BANK = "harbourline";
const THAMES = "MID-10231";
const SCOPE = { [BANK]: ["read", "submit", "transfer"], [THAMES]: ["read", "draft", "pay"] };

const gbp = (value: number) => ({ value, currency: "GBP" });
const txn = (action: string, merchant: string, category: string, value: number): Transaction =>
  ({ action, merchant, category, amount: gbp(value) });
const PAY_THAMES = txn("pay", THAMES, "4900", 11840);
const PAY_BANK = txn("pay", BANK, "bank", 8400);
const READ_BANK = txn("read", BANK, "bank", 0);

type BuildOpts = Parameters<typeof buildMandate>[0];
function root(over: Partial<BuildOpts> = {}): Mandate {
  return buildMandate({
    agentId: "agent-tidy", agentPublicKey: DPUB_RAW, intent: "pay the energy bill",
    categories: ["bank", "4900"], counterparties: SCOPE, maxAmount: gbp(15000),
    actions: ["read", "draft", "submit", "pay", "transfer"], approval: { actions: ["submit"] },
    issuedAt: ISSUED, expiresAt: EXPIRES,
    ...over,
  });
}
const sign = (m: Mandate, seed: Buffer = ISSUER) => signMandate(m as unknown as Record<string, unknown>, seed);
const vrf = (s: SignedMandate, t: Transaction, opts: VerifyOptions = {}) =>
  verify(s, t, { trustedKeys: [PUB], now: NOW, ...opts });
const codes = (v: ReturnType<typeof verify>) => v.failed.map((c) => c.constraint).sort();

// --- versions, builders, validation -----------------------------------------------

test("versions are aligned", () => {
  assert.equal(pkgVersion, "0.2.1");
  assert.equal(pkg.version, "0.2.1");
  assert.equal(VERSION, "mandatekit/v0.2");
  assert.deepEqual([...SUPPORTED_VERSIONS], ["mandatekit/v0", "mandatekit/v0.2"]);
  assert.equal(new Set(REASON_CODES).size, REASON_CODES.length);
});

test("buildMandate carries the new fields and validate accepts them", () => {
  const m = root({ notBefore: NOW, limits: { actions: ["pay"], max_uses: 1 },
    revocation: { list_id: "rl-1", max_age_seconds: 3600 }, delegation: { max_depth: 1 }, mandateId: "m" });
  const c = m.constraints;
  assert.equal(m.version, "mandatekit/v0.2");
  assert.deepEqual(m.subject, { agent_id: "agent-tidy", public_key: DPUB_RAW.toString("base64") });
  assert.deepEqual(c.counterparties, SCOPE);
  assert.equal(c.not_before, "2026-10-12T12:00:00Z");
  assert.deepEqual(c.limits, { actions: ["pay"], max_uses: 1 });
  assert.deepEqual(c.revocation, { list_id: "rl-1", max_age_seconds: 3600 });
  assert.deepEqual(c.delegation, { max_depth: 1 });
  assert.deepEqual(validate(m), []);
  const old = JSON.parse(JSON.stringify(m));
  old.version = "mandatekit/v0";
  assert.deepEqual(validate(old), []); // the old wire version still validates
});

test("buildMandate rejects bad inputs", () => {
  const bad: Array<Partial<BuildOpts>> = [
    { counterparties: { [BANK]: "read" as any } },
    { counterparties: [BANK] as any },
    { limits: { max_uses_per_window: 1 } }, // no window
    { limits: { window_seconds: 60 } }, // no limit
    { limits: { max_uses: 1, per_day: 3 } as any }, // unknown key
    { limits: { max_uses: 1.5 } },
    { limits: { max_amount_per_window: { value: 1.5, currency: "GBP" }, window_seconds: 60 } },
    { revocation: { list_id: "" } },
    { revocation: { list_id: "x", url: "https://example.test" } as any },
    { delegation: { max_depth: -1 } },
    { delegation: { max_depth: 1 }, agentPublicKey: undefined },
    { delegation: { parent: {} } as any },
    { agentPublicKey: Buffer.from("short") },
  ];
  bad.forEach((over, i) => assert.throws(() => root(over), Error, `case ${i}: ${JSON.stringify(over)}`));
});

test("validate reports malformed new fields", () => {
  const m: any = root({ mandateId: "m" });
  m.constraints.counterparties = { [BANK]: "read" };
  m.constraints.not_before = "soon";
  m.constraints.limits = { max_uses: "1" };
  m.constraints.revocation = { list_id: 7 };
  m.constraints.delegation = { extra: 1 };
  m.subject.public_key = "";
  const problems = validate(m);
  for (const needle of ["counterparties", "not_before", "max_uses", "list_id", "delegation", "public_key"]) {
    assert.ok(problems.some((p) => p.includes(needle)), `${needle}: ${problems.join(" | ")}`);
  }
});

// --- per-verb counterparty scope ------------------------------------------------------

test("a pay to the bank is denied by counterparty_scope", () => {
  const s = sign(root({ mandateId: "m" }));
  assert.equal(vrf(s, PAY_THAMES).decision, "allow");
  const v = vrf(s, PAY_BANK);
  assert.equal(v.decision, "deny");
  assert.deepEqual(codes(v), ["counterparty_scope"]);
  assert.equal(v.failed[0].detail, "'harbourline' is scoped to [read, submit, transfer]; pay is not allowed there");
  assert.equal(vrf(s, txn("transfer", BANK, "bank", 8400)).decision, "allow");
  assert.equal(vrf(s, txn("submit", BANK, "bank", 0)).decision, "ask");
  const unlisted = vrf(s, txn("pay", "MID-41120", "4900", 100));
  assert.deepEqual(codes(unlisted), ["counterparty_scope"]);
  assert.equal(unlisted.failed[0].detail, "'MID-41120' is not a listed counterparty");
});

test("the flat allow list still means every allowed verb", () => {
  const s = sign(root({ mandateId: "m", counterparties: undefined, merchants: { allow: [BANK, THAMES] } }));
  assert.equal(vrf(s, PAY_BANK).decision, "allow");
});

test("counterparties count as scope", () => {
  const m = buildMandate({ agentId: "a", counterparties: { [BANK]: ["read"] }, issuedAt: ISSUED, expiresAt: EXPIRES });
  const v = vrf(sign(m), { action: "read", merchant: BANK });
  assert.equal(v.decision, "allow");
  assert.ok(v.matched.some((c) => c.constraint === "has_scope"));
});

// --- time window ------------------------------------------------------------------------

test("not_before and expiry have distinct codes", () => {
  const s = sign(root({ mandateId: "m", notBefore: plus(NOW, 3600) }));
  const early = vrf(s, READ_BANK);
  assert.equal(early.decision, "deny");
  assert.deepEqual(codes(early), ["not_before"]);
  assert.match(early.rationale, /window opens at 2026-10-12T13:00:00Z/);
  assert.equal(vrf(s, READ_BANK, { now: plus(NOW, 3600) }).decision, "allow");
  assert.deepEqual(codes(vrf(s, READ_BANK, { now: plus(NOW, 8 * 86400) })), ["not_expired"]);
});

test("a malformed not_before denies", () => {
  const m: any = root({ mandateId: "m" });
  m.constraints.not_before = "30 June 2026";
  assert.deepEqual(codes(vrf(sign(m), READ_BANK)), ["not_before"]);
});

// --- wire version -----------------------------------------------------------------------

test("the version gates the new keys", () => {
  const v0: any = root({ mandateId: "m", counterparties: undefined, merchants: { allow: [THAMES] } });
  v0.version = "mandatekit/v0";
  assert.equal(vrf(sign(v0), PAY_THAMES).decision, "allow");
  const v0new: any = root({ mandateId: "m" });
  v0new.version = "mandatekit/v0";
  const v = vrf(sign(v0new), PAY_THAMES);
  assert.deepEqual(codes(v), ["constraints_enforceable"]);
  assert.match(v.rationale, /need mandate version mandatekit\/v0\.2/);
  const v9: any = root({ mandateId: "m" });
  v9.version = "mandatekit/v9";
  assert.deepEqual(codes(vrf(sign(v9), PAY_THAMES)), ["version"]);
});

// --- usage limits -----------------------------------------------------------------------

const limited = (limits: NonNullable<BuildOpts["limits"]>, over: Partial<BuildOpts> = {}) =>
  sign(buildMandate({ agentId: "a", counterparties: { shop: ["read", "pay"] }, maxAmount: gbp(15000), limits,
    issuedAt: ISSUED, expiresAt: EXPIRES, mandateId: "lim", ...over }));
const PAY_SHOP: Transaction = { action: "pay", merchant: "shop", amount: gbp(2500) };
const READ_SHOP: Transaction = { action: "read", merchant: "shop", amount: gbp(0) };

test("limits require a store", () => {
  const s = limited({ actions: ["pay"], max_uses: 1 });
  const v = vrf(s, PAY_SHOP);
  assert.equal(v.decision, "deny");
  assert.deepEqual(codes(v), ["limits_store"]);
  assert.match(v.rationale, /no state store was supplied/);
});

test("max_uses counts only the filtered verbs", () => {
  const s = limited({ actions: ["pay"], max_uses: 1 });
  const store = new InMemoryUsageStore();
  let v = vrf(s, PAY_SHOP, { store });
  assert.equal(v.decision, "allow");
  assert.ok(v.matched.some((c) => c.constraint === "limits" && c.detail.includes("1 counted use")));
  assert.deepEqual(recordUse(s, PAY_SHOP, store, { now: NOW }), ["lim"]);
  v = vrf(s, PAY_SHOP, { store, now: plus(NOW, 1) });
  assert.deepEqual(codes(v), ["max_uses"]);
  assert.match(v.rationale, /2 uses would exceed max_uses 1/);
  assert.equal(vrf(s, READ_SHOP, { store }).decision, "allow");
  assert.deepEqual(store.uses("lim")[0], { at: NOW.getTime() / 1000, action: "pay", amount: gbp(2500) });
});

test("window limits slide", () => {
  const s = limited({ window_seconds: 3600, max_uses_per_window: 2, max_amount_per_window: gbp(20000) });
  const store = new InMemoryUsageStore();
  recordUse(s, { action: "pay", merchant: "shop", amount: gbp(15000) }, store, { now: plus(NOW, -3600) });
  recordUse(s, { action: "pay", merchant: "shop", amount: gbp(15000) }, store, { now: plus(NOW, -10) });
  assert.equal(vrf(s, { action: "pay", merchant: "shop", amount: gbp(5000) }, { store }).decision, "allow");
  let v = vrf(s, { action: "pay", merchant: "shop", amount: gbp(5001) }, { store });
  assert.deepEqual(codes(v), ["max_amount_per_window"]);
  recordUse(s, READ_SHOP, store, { now: plus(NOW, -5) });
  v = vrf(s, READ_SHOP, { store });
  assert.deepEqual(codes(v), ["max_uses_per_window"]);
  assert.match(v.rationale, /3 uses in 3600s/);
  assert.equal(vrf(s, READ_SHOP, { store, now: plus(NOW, 3600) }).decision, "allow");
});

test("malformed limits deny with a store", () => {
  for (const bad of [{ max_uses: "1" }, { max_uses_per_window: 1 }, { max_uses: 1, per_day: 3 }, {}, [], 3]) {
    const m: any = buildMandate({ agentId: "a", counterparties: { shop: ["pay"] }, maxAmount: gbp(15000), issuedAt: ISSUED, expiresAt: EXPIRES });
    m.constraints.limits = bad;
    const v = vrf(sign(m), PAY_SHOP, { store: new InMemoryUsageStore() });
    assert.equal(v.decision, "deny", JSON.stringify(bad));
    assert.deepEqual(codes(v), ["limits"], JSON.stringify(bad));
  }
});

test("store failures are denials, not exceptions", () => {
  const s = limited({ max_uses: 5 });
  const broken = { uses(): Use[] { throw new RangeError("db down"); }, record() { /* noop */ } };
  let v = vrf(s, PAY_SHOP, { store: broken });
  assert.deepEqual(codes(v), ["limits_store"]);
  assert.match(v.rationale, /state store error: RangeError/);
  const store = new InMemoryUsageStore();
  store.record("lim", { at: "yesterday" as any, action: "pay", amount: null });
  v = vrf(s, PAY_SHOP, { store });
  assert.deepEqual(codes(v), ["limits_store"]);
  assert.match(v.rationale, /malformed usage record/);
});

test("recordUse rejects garbage and walks the chain", () => {
  assert.throws(() => recordUse({ mandate: "x" } as any, PAY_SHOP, new InMemoryUsageStore(), { now: NOW }), /malformed/);
  const parent = sign(root({ mandateId: "root", delegation: { max_depth: 1 }, limits: { actions: ["pay"], max_uses: 1 } }));
  const child = sign(delegateMandate(parent, { agentId: "sub", limits: null, approval: null, actions: ["read", "pay"],
    counterparties: { [THAMES]: ["read", "pay"] }, mandateId: "child" }), DELEGATE);
  const store = new InMemoryUsageStore();
  assert.deepEqual(recordUse(child, PAY_THAMES, store, { now: NOW }), ["child", "root"]);
  assert.equal(store.uses("root").length, 1);
  assert.equal(store.uses("child").length, 1);
  const v = vrf(child, PAY_THAMES, { store, now: plus(NOW, 1) });
  assert.deepEqual(codes(v), ["max_uses"]); // the parent's limit, enforced through the child
});

// --- revocation -----------------------------------------------------------------------------

const rlist = (revoked: string[], signer: Buffer = ISSUER, issuedAt?: Date, listId = "rl-1") =>
  signRevocationList(buildRevocationList({ listId, revoked, issuedAt: issuedAt ?? plus(NOW, -300) }) as unknown as Record<string, unknown>, signer);

test("revocation list round trip and signature", () => {
  const lst = rlist(["x"]);
  assert.equal(lst.list.version, "mandatekit/revocation-list/v0.2");
  assert.equal(verifyRevocationListSignature(lst), true);
  const bad = JSON.parse(JSON.stringify(lst));
  bad.list.revoked = [];
  assert.equal(verifyRevocationListSignature(bad), false);
  assert.equal(verifyRevocationListSignature({ list: lst.list } as any), false);
  assert.throws(() => buildRevocationList({ listId: "", revoked: [] }));
  assert.throws(() => buildRevocationList({ listId: "rl", revoked: "m" as any }));
});

test("revocation paths", () => {
  const s = sign(root({ mandateId: "m", revocation: { list_id: "rl-1", max_age_seconds: 3600 } }));
  let v = vrf(s, READ_BANK);
  assert.deepEqual(codes(v), ["revocation_list"]);
  assert.match(v.rationale, /was not supplied/);
  assert.equal(vrf(s, READ_BANK, { revocationLists: [rlist(["other"])] }).decision, "allow");
  assert.equal(vrf(s, READ_BANK, { revocationLists: rlist(["other"]) }).decision, "allow"); // a single list, not wrapped
  v = vrf(s, READ_BANK, { revocationLists: [rlist(["m"])] });
  assert.deepEqual(codes(v), ["revoked"]);
  assert.match(v.rationale, /mandate m is revoked in list 'rl-1'/);
  assert.deepEqual(codes(vrf(s, READ_BANK, { revocationLists: [rlist([], STRANGER)] })), ["revocation_list"]);
  const stale = vrf(s, READ_BANK, { revocationLists: [rlist([], ISSUER, plus(NOW, -7200))] });
  assert.deepEqual(codes(stale), ["revocation_list"]);
  assert.match(stale.rationale, /older than max_age_seconds 3600/);
  const tampered = rlist(["m"]);
  (tampered.list as any).revoked = [];
  assert.deepEqual(codes(vrf(s, READ_BANK, { revocationLists: [tampered] })), ["revocation_list"]);
  assert.deepEqual(codes(vrf(s, READ_BANK, { revocationLists: [rlist([], ISSUER, undefined, "rl-2")] })), ["revocation_list"]);
  const byDelegate = rlist(["m"], DELEGATE);
  assert.deepEqual(codes(vrf(s, READ_BANK, { revocationLists: [byDelegate], trustedKeys: [PUB, DPUB_RAW.toString("base64")] })), ["revoked"]);
  assert.deepEqual(codes(vrf(s, READ_BANK, { revocationLists: [byDelegate] })), ["revocation_list"]);
});

// --- delegation ------------------------------------------------------------------------------

const ROOT = sign(root({ mandateId: "root-1", delegation: { max_depth: 1 } }));
const PAY_40 = txn("pay", THAMES, "4900", 4000);
type DelegateOpts = Parameters<typeof delegateMandate>[1];
const child = (over: Partial<DelegateOpts> = {}, parent: SignedMandate = ROOT, signer: Buffer = DELEGATE) =>
  sign(delegateMandate(parent, { agentId: "sub-agent", counterparties: { [THAMES]: ["read", "pay"] }, maxAmount: gbp(5000),
    actions: ["read", "pay"], approval: null, expiresAt: plus(NOW, 86400), issuedAt: ISSUED, mandateId: "child-1", ...over }), signer);

test("a narrower child verifies against the root issuer", () => {
  const c = child();
  const v = vrf(c, PAY_40);
  assert.equal(v.decision, "allow", v.rationale);
  assert.ok(v.matched.some((ch) => ch.constraint === "delegation" && ch.detail.includes("2 links roots in root-1")));
  assert.ok(v.matched.some((ch) => ch.constraint === "issuer_trusted"));
  assert.deepEqual(codes(vrf(c, txn("pay", THAMES, "4900", 6000))), ["amount"]);
  assert.deepEqual(codes(vrf(c, PAY_40, { trustedKeys: [publicKeyFromSeed(STRANGER).toString("base64")] })), ["issuer_trusted"]);
  assert.equal(verify(c, PAY_40, { now: NOW }).decision, "deny"); // no trusted keys: fail closed
});

test("delegateMandate inherits unless told otherwise", () => {
  const m = delegateMandate(ROOT, { agentId: "sub", mandateId: "c" });
  const pc = (ROOT.mandate as unknown as Mandate).constraints as Record<string, unknown>;
  for (const key of ["intent", "categories", "counterparties", "max_amount", "actions", "approval"]) {
    assert.deepEqual((m.constraints as Record<string, unknown>)[key], pc[key], key);
  }
  assert.deepEqual(m.constraints.delegation, { parent: ROOT });
  assert.equal(m.expires_at, (ROOT.mandate as any).expires_at);
  assert.ok(!("revocation" in m.constraints));
  const narrowed = delegateMandate(ROOT, { agentId: "sub", approval: null, maxAmount: gbp(1), mandateId: "c" });
  assert.ok(!("approval" in narrowed.constraints));
  assert.deepEqual(narrowed.constraints.max_amount, gbp(1));
  assert.throws(() => delegateMandate(ROOT, { agentId: "sub", maxDepth: 1 })); // needs a key to delegate further
  assert.throws(() => delegateMandate({ mandate: null } as any, { agentId: "sub" }));
});

test("widening is denied with the field named", () => {
  const readThames = txn("read", THAMES, "4900", 0);
  const cases: Record<string, [SignedMandate, Transaction]> = {
    "max_amount": [child({ maxAmount: gbp(20000) }), readThames],
    "actions: child adds [cancel]": [child({ counterparties: { [THAMES]: ["read", "cancel"] }, actions: ["read", "cancel"] }), readThames],
    "counterparties: child adds 'MID-41120'": [child({ counterparties: { [THAMES]: ["read"], "MID-41120": ["pay"] } }), readThames],
    "counterparties: child adds [pay] at 'harbourline'": [child({ counterparties: { [BANK]: ["read", "pay"] }, actions: ["read", "pay"] }), READ_BANK],
    "expires_at": [child({ expiresAt: plus(EXPIRES, 86400) }), readThames],
    "categories: child adds [5411]": [child({ categories: ["bank", "4900", "5411"] }), readThames],
    "approval: parent asks before 'submit'": [child({ counterparties: { [BANK]: ["submit"] }, actions: ["submit"] }), txn("submit", BANK, "bank", 0)],
  };
  for (const [needle, [c, t]] of Object.entries(cases)) {
    const v = vrf(c, t);
    assert.equal(v.decision, "deny", needle);
    assert.deepEqual(codes(v), ["delegation_scope", "issuer_trusted"], `${needle}: ${codes(v).join(",")}`);
    assert.ok(v.rationale.includes(needle), `${needle}: ${v.rationale}`);
  }
});

test("window narrowing", () => {
  const wroot = sign(root({ mandateId: "root-w", delegation: { max_depth: 1 }, notBefore: plus(NOW, -3600) }));
  assert.deepEqual(codes(vrf(child({ notBefore: null }, wroot), PAY_40)), ["delegation_scope", "issuer_trusted"]);
  assert.deepEqual(codes(vrf(child({ notBefore: plus(NOW, -7200) }, wroot), PAY_40)), ["delegation_scope", "issuer_trusted"]);
  const inside = child({ notBefore: plus(NOW, -1800) }, wroot);
  assert.equal(vrf(inside, PAY_40).decision, "allow");
  assert.deepEqual(codes(vrf(inside, PAY_40, { now: plus(NOW, -2700) })), ["not_before"]);
});

test("chain structure failures", () => {
  assert.deepEqual(codes(vrf(child({}, ROOT, STRANGER), PAY_40)), ["delegation", "issuer_trusted"]);
  assert.deepEqual(codes(vrf(child({}, ROOT, ISSUER), PAY_40)), ["delegation", "issuer_trusted"]);
  const noOptIn = sign(root({ mandateId: "root-plain" }));
  let v = vrf(child({}, noOptIn), PAY_40);
  assert.deepEqual(codes(v), ["delegation", "issuer_trusted"]);
  assert.match(v.rationale, /does not allow delegation/);
  const nokey: any = root({ mandateId: "root-nokey", delegation: { max_depth: 1 } });
  delete nokey.subject.public_key;
  v = vrf(child({}, sign(nokey)), PAY_40);
  assert.match(v.rationale, /no subject\.public_key/);
  const tooDeep = sign(delegateMandate(ROOT, { agentId: "s", agentPublicKey: DPUB_RAW, maxDepth: 1, approval: null,
    actions: ["read"], counterparties: { [THAMES]: ["read"] }, mandateId: "deep" }), DELEGATE);
  v = vrf(tooDeep, txn("read", THAMES, "4900", 0));
  assert.deepEqual(codes(v), ["delegation_scope", "issuer_trusted"]);
  assert.match(v.rationale, /exceeds the parent's remaining depth 0/);
  const grandchild = sign(delegateMandate(child(), { agentId: "g", mandateId: "g" }), DELEGATE);
  assert.deepEqual(codes(vrf(grandchild, PAY_40)), ["delegation", "issuer_trusted"]);
  const garbage: any = root({ mandateId: "g" });
  garbage.constraints.delegation = { parent: { mandate: "nope" } };
  assert.deepEqual(codes(vrf(sign(garbage, DELEGATE), PAY_THAMES)), ["delegation", "issuer_trusted"]);
});

test("tampering anywhere in the chain breaks the leaf signature", () => {
  const c = child();
  const editedParent = JSON.parse(JSON.stringify(c));
  editedParent.mandate.constraints.delegation.parent.mandate.constraints.max_amount.value = 999999;
  const v = vrf(editedParent, PAY_40);
  assert.equal(v.decision, "deny");
  assert.equal(v.signature_valid, false);
  const editedChild = JSON.parse(JSON.stringify(c));
  editedChild.mandate.constraints.max_amount.value = 999999;
  assert.equal(vrf(editedChild, PAY_40).signature_valid, false);
});

test("three links", () => {
  const root2 = sign(root({ mandateId: "root-2", delegation: { max_depth: 2 } }));
  const gk = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 64));
  const mid = sign(delegateMandate(root2, { agentId: "mid", agentPublicKey: publicKeyFromSeed(gk), maxDepth: 1,
    counterparties: { [THAMES]: ["read", "pay"] }, maxAmount: gbp(5000), actions: ["read", "pay"], approval: null, mandateId: "mid" }), DELEGATE);
  const leaf = sign(delegateMandate(mid, { agentId: "leaf", counterparties: { [THAMES]: ["read"] }, actions: ["read"],
    maxAmount: gbp(0), mandateId: "leaf" }), gk);
  const v = vrf(leaf, txn("read", THAMES, "4900", 0));
  assert.equal(v.decision, "allow", v.rationale);
  assert.ok(v.matched.some((ch) => ch.detail.includes("3 links roots in root-2")));
  assert.deepEqual(recordUse(leaf, txn("read", THAMES, "4900", 0), new InMemoryUsageStore(), { now: NOW }), ["leaf", "mid", "root-2"]);
});

test("a revoked parent takes the children with it", () => {
  const rroot = sign(root({ mandateId: "root-rev", delegation: { max_depth: 1 }, revocation: { list_id: "rl-root" } }));
  const c = child({}, rroot);
  assert.deepEqual(codes(vrf(c, PAY_40)), ["revocation_list"]);
  assert.deepEqual(codes(vrf(c, PAY_40, { revocationLists: [rlist(["root-rev"], ISSUER, undefined, "rl-root")] })), ["revoked"]);
  assert.equal(vrf(c, PAY_40, { revocationLists: [rlist([], ISSUER, undefined, "rl-root")] }).decision, "allow");
});

// --- cross-walk ---------------------------------------------------------------------------------

test("the cross-walk carries the new fields", () => {
  const m = root({ mandateId: "m", notBefore: NOW, limits: { max_uses: 3 }, revocation: { list_id: "rl-1" }, delegation: { max_depth: 1 } });
  const [d] = toAuthorizationDetails(m);
  assert.equal(d.type, "mandatekit:mandate:v0.2");
  assert.equal(d.valid_from, "2026-10-12T12:00:00Z");
  assert.equal(d.valid_until, m.expires_at);
  assert.deepEqual(d.locations, ["MID-10231", "harbourline"]); // sorted counterparty ids
  assert.deepEqual(d.counterparties, SCOPE);
  assert.deepEqual(d.limits, { max_uses: 3 });
  assert.deepEqual(d.revocation, { list_id: "rl-1" });
  assert.deepEqual(d.delegation, { max_depth: 1 });
  assert.deepEqual(d.subject, { agent_id: "agent-tidy", public_key: DPUB_RAW.toString("base64") });
  d.counterparties![BANK].push("pay");
  assert.deepEqual(m.constraints.counterparties![BANK], ["read", "submit", "transfer"]);
  const [dc] = toAuthorizationDetails(delegateMandate(ROOT, { agentId: "sub", mandateId: "c" }));
  assert.deepEqual(dc.delegation, { parent: "root-1" });
  const plain = buildMandate({ agentId: "a", maxAmount: gbp(1), issuedAt: ISSUED, expiresAt: EXPIRES });
  const [dp] = toAuthorizationDetails(plain);
  assert.equal(dp.valid_from, plain.issued_at);
  assert.ok(!("locations" in dp));
});

// --- robustness -----------------------------------------------------------------------------------

test("hostile new fields never throw", () => {
  const base = root({ mandateId: "m" });
  const store = new InMemoryUsageStore();
  const hostile: Array<Record<string, unknown>> = [
    { counterparties: null }, { counterparties: { [BANK]: null } }, { counterparties: { [BANK]: [1, {}] } },
    { not_before: 12 }, { not_before: null }, { limits: null }, { limits: { window_seconds: -1, max_uses_per_window: 1 } },
    { limits: { max_uses: true } }, { revocation: null }, { revocation: { list_id: "x", max_age_seconds: "1" } },
    { delegation: null }, { delegation: { parent: null } }, { delegation: { parent: { mandate: { constraints: [] } } } },
    { delegation: { max_depth: "1" } }, { delegation: [] },
  ];
  for (const extra of hostile) {
    const m: any = JSON.parse(JSON.stringify(base));
    Object.assign(m.constraints, extra);
    for (const signed of [sign(m), { mandate: m, signature: { alg: "Ed25519", public_key: PUB, value: "AA==" } } as any]) {
      const v = verify(signed, PAY_THAMES, { now: NOW, trustedKeys: [PUB], store,
        revocationLists: [{ list: extra }, 42, null, { list: { list_id: "x" } }] as any });
      assert.equal(v.decision, "deny", JSON.stringify(extra));
    }
  }
});

// --- cross-language fixture -------------------------------------------------------------------------

interface FixtureStep {
  op: "verify" | "record" | "record_raw";
  now?: string;
  transaction?: Transaction;
  mandate_id?: string;
  use?: Use;
  expect?: { decision: string; failed: string[]; signature_valid?: boolean };
}
interface FixtureCase {
  name: string;
  signer: string | null;
  mandate: SignedMandate;
  trusted: string[];
  store: boolean;
  revocation_lists: Array<{ signer: string | null; envelope: any }>;
  steps: FixtureStep[];
}
interface Fixture { now: string; seeds: Record<string, string>; keys: Record<string, string>; cases: FixtureCase[] }

const fixture = JSON.parse(readFileSync(FIXTURE, "utf8")) as Fixture;
assert.ok(fixture.cases.length > 0, "fixture has no cases");
const seeds = Object.fromEntries(Object.entries(fixture.seeds).map(([k, v]) => [k, Buffer.from(v, "hex")]));
const defaultNow = new Date(fixture.now);
let fixtureVerdicts = 0;
const emitted = new Set<string>();

for (const c of fixture.cases) {
  test(`fixture: ${c.name}`, () => {
    const store = c.store ? new InMemoryUsageStore() : undefined;
    const trustedKeys = c.trusted.length ? c.trusted.map((k) => fixture.keys[k]) : undefined;
    const revocationLists = c.revocation_lists.map((l) => l.envelope);
    // The envelopes were signed by the Python SDK; re-signing here must reproduce the bytes.
    if (c.signer !== null) {
      const again = signMandate(c.mandate.mandate, seeds[c.signer]);
      assert.deepEqual(again.signature, c.mandate.signature, "byte-identical signature");
    }
    for (const l of c.revocation_lists) {
      if (l.signer !== null) {
        assert.deepEqual(signRevocationList(l.envelope.list, seeds[l.signer]).signature, l.envelope.signature, "byte-identical list signature");
      }
    }
    c.steps.forEach((step, i) => {
      const where = `${c.name} / step ${i}`;
      const now = step.now ? new Date(step.now) : defaultNow;
      if (step.op === "record") {
        recordUse(c.mandate, step.transaction!, store!, { now });
      } else if (step.op === "record_raw") {
        store!.record(step.mandate_id!, step.use!);
      } else if (step.op === "verify") {
        const v = verify(c.mandate, step.transaction!, { now, trustedKeys, store, revocationLists });
        const exp = step.expect!;
        assert.equal(v.decision, exp.decision, `${where}: ${v.rationale}`);
        assert.deepEqual(codes(v), exp.failed, `${where}: ${v.rationale}`);
        if ("signature_valid" in exp) assert.equal(v.signature_valid, exp.signature_valid, where);
        for (const ch of [...v.matched, ...v.failed]) emitted.add(ch.constraint);
        fixtureVerdicts++;
      } else {
        throw new Error(`${where}: unknown op ${JSON.stringify((step as FixtureStep).op)}`);
      }
    });
  });
}

test("the fixture exercised enough verdicts and only documented reason codes", () => {
  assert.ok(fixtureVerdicts >= 100, `only ${fixtureVerdicts} fixture verdicts ran`);
  for (const code of emitted) assert.ok(REASON_CODES.includes(code), `undocumented reason code ${code}`);
});

// Audit 2026-10-31. The fixture also carries the rule-based compiler's cases (M3) and the
// ISO-8601 strings both verifiers must accept or reject alike (L4).
interface ParserCase { name: string; text: string; expect: Record<string, unknown> }
interface IsoCase { input: string; valid: boolean; normalized: string | null }
const extra = fixture as unknown as { parser_cases: ParserCase[]; iso_cases: IsoCase[] };

test("fixture: the rule-based parser reads every parser case as the Python compiler does", () => {
  assert.ok(extra.parser_cases.length > 0, "fixture has no parser cases");
  for (const c of extra.parser_cases) {
    const got: Record<string, unknown> = { ...ruleBasedParser(c.text, defaultNow) };
    if (got.expires_at instanceof Date) got.expires_at = iso(got.expires_at);
    assert.deepEqual(got, c.expect, c.name);
  }
});

test("fixture: the strict ISO-8601 parser accepts and rejects the same strings as Python", () => {
  assert.ok(extra.iso_cases.length > 0, "fixture has no ISO cases");
  for (const c of extra.iso_cases) {
    const ms = parseIsoStrict(c.input);
    if (c.valid) assert.equal(iso(new Date(ms)), c.normalized, c.input);
    else assert.ok(Number.isNaN(ms), `accepted ${JSON.stringify(c.input)}`);
  }
});
