"""
MandateKit CLI - compile and verify mandates from the shell.

    # make a keypair (hex seed -> stdout; public key -> stderr, that's your issuer key)
    python -m mandatekit keygen > agent.key        # note the "public key:" line it prints

    # compile a natural-language instruction into a signed mandate
    python -m mandatekit compile "buy running shoes from any apparel retailer up to $500, expires June 30" \
        --agent agent-7 --key agent.key > mandate.json

    # verify a transaction, pinning the issuer's public key (else it fails closed)
    echo '{"merchant":"Fleet Feet","category":"apparel","amount":{"value":240,"currency":"USD"}}' \
        | python -m mandatekit verify mandate.json - --trust <ISSUER_PUBKEY_B64>
"""

import argparse
import json
import sys

from . import compile as compile_mandate
from . import generate_keypair, verify
from .signing import _b64  # reuse encoder


def _read_json(path: str):
    data = sys.stdin.read() if path == "-" else open(path).read()
    return json.loads(data)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mandatekit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="generate a new Ed25519 signing seed (hex)")

    pc = sub.add_parser("compile", help="natural language -> signed mandate")
    pc.add_argument("text")
    pc.add_argument("--agent", required=True, help="agent_id the mandate authorizes")
    pc.add_argument("--key", required=True, help="file with a hex signing seed")
    pc.add_argument("--ttl-days", type=int, default=30)

    pv = sub.add_parser("verify", help="check a transaction against a signed mandate")
    pv.add_argument("mandate", help="signed mandate JSON file (or - for stdin)")
    pv.add_argument("transaction", help="transaction JSON file (or - for stdin)")
    pv.add_argument("--trust", action="append", default=[], metavar="PUBKEY_B64",
                    help="trusted issuer public key, base64 (from keygen). Repeatable.")
    pv.add_argument("--allow-unverified-issuer", action="store_true",
                    help="accept any signer (integrity only). Use with care.")

    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        seed, public_key = generate_keypair()
        sys.stderr.write(f"public key (share freely): {_b64(public_key)}\n")
        print(seed.hex())
        return 0

    if args.cmd == "compile":
        private_key = bytes.fromhex(open(args.key).read().strip())
        signed = compile_mandate(
            args.text,
            agent_id=args.agent,
            private_key=private_key,
            ttl_days=args.ttl_days,
        )
        print(json.dumps(signed, indent=2))
        return 0

    if args.cmd == "verify":
        signed = _read_json(args.mandate)
        transaction = _read_json(args.transaction)
        verdict = verify(
            signed,
            transaction,
            trusted_keys=args.trust or None,
            allow_unverified_issuer=args.allow_unverified_issuer,
        )
        print(json.dumps(verdict, indent=2))
        return 0 if verdict["decision"] == "allow" else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
