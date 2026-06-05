/**
 * Mandate signing and verification, backed by Node's built-in Ed25519 (no
 * external crypto dependency). Keys are raw 32-byte values, wire-compatible with
 * the Python port: same canonical bytes, same RFC-8032 signatures, same base64
 * envelope.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import { canonicalize } from "./canonical.ts";

// Fixed DER prefixes for a raw Ed25519 seed / public key.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface SignedMandate {
  mandate: Record<string, unknown>;
  signature: { alg: "Ed25519"; public_key: string; value: string };
}

export function generateKeypair(): { privateKey: Buffer; publicKey: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { privateKey: Buffer.from(seed), publicKey: Buffer.from(pub) };
}

function privFromSeed(seed: Buffer) {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function pubFromRaw(pub: Buffer) {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, pub]),
    format: "der",
    type: "spki",
  });
}

export function publicKeyFromSeed(seed: Buffer): Buffer {
  const der = createPublicKey(privFromSeed(seed))
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return Buffer.from(der);
}

export function signMandate(
  mandate: Record<string, unknown>,
  seed: Buffer,
): SignedMandate {
  const publicKey = publicKeyFromSeed(seed);
  const signature = nodeSign(null, canonicalize(mandate), privFromSeed(seed));
  return {
    mandate,
    signature: {
      alg: "Ed25519",
      public_key: publicKey.toString("base64"),
      value: Buffer.from(signature).toString("base64"),
    },
  };
}

export function verifySignature(signed: SignedMandate): boolean {
  const sig = signed?.signature;
  if (!sig || sig.alg !== "Ed25519") return false;
  try {
    const pub = pubFromRaw(Buffer.from(sig.public_key, "base64"));
    return nodeVerify(
      null,
      canonicalize(signed.mandate),
      pub,
      Buffer.from(sig.value, "base64"),
    );
  } catch {
    return false;
  }
}
