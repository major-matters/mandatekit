/** MandateKit demo. Run: npm run demo  (node --experimental-strip-types demo.ts; the flag is a
 *  no-op from Node 22.18). Builds one mandate the way a bank customer would, signs it, and
 *  puts four transactions through verify(): allow, ask, deny, and ask turned into allow by a
 *  customer-signed step mandate. No network, no real money. */

import {
  buildMandate, signMandate, stepMandate, verify, toAuthorizationDetails,
  generateKeypair, type Transaction,
} from "./src/index.ts";

const LINE = "-".repeat(64);
const banner = (t: string) => console.log(`\n${LINE}\n  ${t}\n${LINE}`);
const gbp = (pence: number) => ({ value: pence, currency: "GBP" });

// The customer's key signs the mandate; the verifier trusts only that key.
const customer = generateKeypair();
const trustedKeys = [customer.publicKey];

banner("1. The mandate: pay the energy bill, and nothing else");
const mandate = buildMandate({
  agentId: "did:key:demo-agent",
  intent: "Pay the energy bill",
  categories: ["bank", "4900"],                       // the bank and Utilities
  merchants: { allow: ["harbourline", "MID-10231"] }, // the bank and Thames Energy
  maxAmount: gbp(15000),                               // £150.00 per transaction
  actions: ["read", "draft", "submit", "pay"],         // no cancel, no share, no transfer
  approval: { actions: ["submit"] },                   // submit needs the customer's yes
  issuedAt: new Date(),
  ttlDays: 1,
  mandateId: "demo-pay-bill",
});
const signed = signMandate(mandate, customer.privateKey);
console.log(`  mandate ${mandate.mandate_id}: actions ${mandate.constraints.actions?.join(", ")}; cap £${(mandate.constraints.max_amount!.value / 100).toFixed(2)}; expires ${mandate.expires_at}`);

const txn = (action: string, merchant: string, category: string, pence: number): Transaction =>
  ({ action, merchant, category, amount: gbp(pence), description: `${action} ${merchant}` } as Transaction);
const show = (label: string, t: Transaction, opts: Parameters<typeof verify>[2] = { trustedKeys }) => {
  const v = verify(signed, t, opts);
  const failed = v.failed.map((c) => c.constraint).join(", ");
  console.log(`  ${label.padEnd(44)} -> ${v.decision.toUpperCase().padEnd(5)} ${failed ? `(${failed})` : ""}`);
  return v;
};

banner("2. Four transactions through verify()");
show("pay £118.40 to Thames Energy", txn("pay", "MID-10231", "4900", 11840));
show("submit the auto-pay form to Thames Energy", txn("submit", "MID-10231", "4900", 0));
show("pay £240.00 to Thames Energy (over the cap)", txn("pay", "MID-10231", "4900", 24000));
show("pay £10.00 to GreenCart Groceries (not listed)", txn("pay", "MID-41120", "5411", 1000));
show("cancel the Thames Energy account (verb not allowed)", txn("cancel", "MID-10231", "4900", 0));

banner("3. The customer says yes: a step mandate turns ASK into ALLOW");
const ask = txn("submit", "MID-10231", "4900", 0);
const step = signMandate(stepMandate(mandate, ask, { issuedAt: new Date(), mandateId: "demo-step-1" }), customer.privateKey);
show("the same submit, with the customer's signed step", { ...ask, approval: step } as Transaction);
console.log("  (the step mandate is narrowed to that one transaction and expires in minutes)");

banner("4. The mandate altered after signing, and a key nobody trusts");
const tampered = JSON.parse(JSON.stringify(signed));
tampered.mandate.constraints.max_amount.value = 99900;
const t = verify(tampered, txn("pay", "MID-10231", "4900", 11840), { trustedKeys });
console.log(`  cap raised to £999 after signing                -> ${t.decision.toUpperCase()}  (signature valid: ${t.signature_valid})`);
const stranger = generateKeypair();
const foreign = signMandate(mandate, stranger.privateKey);
const f = verify(foreign, txn("pay", "MID-10231", "4900", 11840), { trustedKeys });
console.log(`  signed by a key outside the trusted set         -> ${f.decision.toUpperCase()}  (${f.failed.map((c) => c.constraint).join(", ")})`);
const n = verify(signed, txn("pay", "MID-10231", "4900", 11840), {});
console.log(`  verify() with no trusted keys at all            -> ${n.decision.toUpperCase()}  (fails closed)`);

banner("5. The same mandate as RFC 9396 authorization_details");
console.log(JSON.stringify(toAuthorizationDetails(mandate), null, 2).split("\n").map((l) => "  " + l).join("\n"));

banner("Mandate before the action. BudgetGuard during it. Witness after.");
console.log("  github.com/major-matters  ·  majorlabs.co\n");
