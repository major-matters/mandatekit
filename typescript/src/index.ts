/**
 * MandateKit v0 (TypeScript) - sign and verify scope-bound mandates for AI agents.
 * v0 tracks the AP2 Verifiable Intent draft. See the README.
 *
 * 0.2 adds per-verb counterparty scope, a window start (`not_before`), usage
 * limits enforced against a caller-supplied store, issuer-signed revocation
 * lists, and delegation chains.
 */

export { compile, ruleBasedParser } from "./compiler.ts";
export type { CompileOptions, Parser, ParsedConstraints } from "./compiler.ts";
export { verify, recordUse, REASON_CODES } from "./verifier.ts";
export type { IntentScorer, Transaction, VerifyOptions, Verdict, Decision, Check } from "./verifier.ts";
export {
  generateKeypair,
  signMandate,
  verifySignature,
  signRevocationList,
  verifyRevocationListSignature,
  publicKeyFromSeed,
} from "./signing.ts";
export type { SignedMandate, SignedRevocationList, Signature } from "./signing.ts";
export {
  buildMandate,
  delegateMandate,
  stepMandate,
  buildRevocationList,
  validate,
  VERSION,
  VERSION_V0,
  SUPPORTED_VERSIONS,
  SPEC,
  REVOCATION_LIST_VERSION,
} from "./mandate.ts";
export type {
  Mandate,
  Constraints,
  Amount,
  Approval,
  Limits,
  Revocation,
  Delegation,
  Subject,
  RevocationList,
  BuildOptions,
  DelegateOptions,
  RevocationListOptions,
  StepTarget,
  StepOptions,
} from "./mandate.ts";
export { toAuthorizationDetails, AUTHORIZATION_DETAIL_TYPE } from "./crosswalk.ts";
export type { AuthorizationDetail } from "./crosswalk.ts";
export { InMemoryUsageStore } from "./store.ts";
export type { UsageStore, Use } from "./store.ts";

export const __version__ = "0.2.0";
