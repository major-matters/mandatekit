/**
 * Property-based tests (fast-check) for the security-critical paths. Mirrors the
 * Python Hypothesis suite: roundtrip, tamper detection, amount boundary, forgery
 * rejection under issuer pinning, and never-throw on hostile input.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { buildMandate } from "../src/mandate.ts";
import { signMandate, verifySignature, publicKeyFromSeed } from "../src/signing.ts";
import { verify } from "../src/verifier.ts";

const NOW = new Date("2026-01-01T00:00:00Z");
const FAR = new Date("2099-01-01T00:00:00Z");
const seed = () => fc.uint8Array({ minLength: 32, maxLength: 32 }).map((a) => Buffer.from(a));
const amount = () => fc.integer({ min: 0, max: 1_000_000_000 });
const currency = () => fc.constantFrom("USD", "GBP", "EUR", "JPY");
// Arbitrary JSON-ish values for hostile-input testing.
const jsonValue = fc.jsonValue();

test("property: sign -> verify roundtrip", () => {
  fc.assert(fc.property(seed(), (s) => {
    const m = buildMandate({ agentId: "a", maxAmount: { value: 100, currency: "USD" }, issuedAt: NOW, expiresAt: FAR });
    return verifySignature(signMandate(m as any, s)) === true;
  }));
});

test("property: any change to a signed mandate breaks the signature", () => {
  fc.assert(fc.property(seed(), amount().filter((x) => x !== 100), (s, newCap) => {
    const m = buildMandate({ agentId: "a", maxAmount: { value: 100, currency: "USD" }, issuedAt: NOW, expiresAt: FAR });
    const signed = signMandate(m as any, s) as any;
    signed.mandate.constraints.max_amount.value = newCap;
    return verifySignature(signed) === false;
  }));
});

test("property: amount boundary is exactly value <= cap", () => {
  fc.assert(fc.property(seed(), amount(), amount(), currency(), (s, cap, value, cur) => {
    const m = buildMandate({ agentId: "a", categories: ["apparel"], maxAmount: { value: cap, currency: cur }, issuedAt: NOW, expiresAt: FAR });
    const signed = signMandate(m as any, s);
    const pub = publicKeyFromSeed(s).toString("base64");
    const v = verify(signed, { merchant: "X", category: "apparel", amount: { value, currency: cur } }, { now: NOW, trustedKeys: [pub] });
    return (v.decision === "allow") === (value <= cap);
  }));
});

test("property: forgery denied unless the signer is the pinned key", () => {
  fc.assert(fc.property(seed(), seed(), (signerSeed, trustedSeed) => {
    const m = buildMandate({ agentId: "a", categories: ["apparel"], maxAmount: { value: 1000, currency: "USD" }, issuedAt: NOW, expiresAt: FAR });
    const signed = signMandate(m as any, signerSeed);
    const trusted = publicKeyFromSeed(trustedSeed).toString("base64");
    const v = verify(signed, { merchant: "X", category: "apparel", amount: { value: 1, currency: "USD" } }, { now: NOW, trustedKeys: [trusted] });
    const sameKey = publicKeyFromSeed(signerSeed).equals(publicKeyFromSeed(trustedSeed));
    return (v.decision === "allow") === sameKey;
  }));
});

test("property: verify never throws on hostile input", () => {
  fc.assert(fc.property(jsonValue, jsonValue, (mandateLike, txnLike) => {
    const v = verify(
      { mandate: mandateLike, signature: txnLike } as any,
      (txnLike && typeof txnLike === "object" ? txnLike : {}) as any,
      { now: NOW, trustedKeys: ["AAAA"] },
    );
    return v.decision === "allow" || v.decision === "deny";
  }));
});
