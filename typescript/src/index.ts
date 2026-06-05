/**
 * MandateKit v0 (TypeScript) - sign and verify scope-bound mandates for AI agents.
 * v0 tracks the AP2 Verifiable Intent draft. See the README.
 */

export { compile, ruleBasedParser } from "./compiler.ts";
export type { CompileOptions, Parser, ParsedConstraints } from "./compiler.ts";
export { verify } from "./verifier.ts";
export type { IntentScorer, Transaction, VerifyOptions, Verdict } from "./verifier.ts";
export {
  generateKeypair,
  signMandate,
  verifySignature,
  publicKeyFromSeed,
} from "./signing.ts";
export type { SignedMandate } from "./signing.ts";
export {
  buildMandate,
  validate,
  VERSION,
  SPEC,
} from "./mandate.ts";
export type { Mandate, Constraints, Amount } from "./mandate.ts";

export const __version__ = "0.0.1";
