/**
 * MandateKit v0 (TypeScript) - sign and verify scope-bound mandates for AI agents.
 * v0 tracks the AP2 Verifiable Intent draft. See the README.
 */

export { compile, ruleBasedParser } from "./compiler.ts";
export type { CompileOptions, Parser, ParsedConstraints } from "./compiler.ts";
export { verify } from "./verifier.ts";
export type { IntentScorer, Transaction, VerifyOptions, Verdict, Decision } from "./verifier.ts";
export {
  generateKeypair,
  signMandate,
  verifySignature,
  publicKeyFromSeed,
} from "./signing.ts";
export type { SignedMandate } from "./signing.ts";
export {
  buildMandate,
  stepMandate,
  validate,
  VERSION,
  SPEC,
} from "./mandate.ts";
export type { Mandate, Constraints, Amount, Approval, StepTarget, StepOptions } from "./mandate.ts";
export { toAuthorizationDetails } from "./crosswalk.ts";
export type { AuthorizationDetail } from "./crosswalk.ts";

export const __version__ = "0.1.1";
