"""
MandateKit v0 - sign and verify scope-bound mandates for AI agents.

v0 tracks the AP2 Verifiable Intent draft spec (finalization expected Q3 2026).
Field names and scoring are MandateKit's own and will move with the spec.

Public surface:

    from mandatekit import generate_keypair, compile, verify

    private_key, public_key = generate_keypair()
    signed = compile(
        "Allow this agent to buy running shoes from any apparel retailer "
        "up to $500 per transaction, expires June 30",
        agent_id="agent-7",
        private_key=private_key,
    )
    verdict = verify(signed, {
        "merchant": "Fleet Feet",
        "category": "apparel",
        "amount": {"value": 240, "currency": "USD"},
        "description": "Brooks Ghost 16 running shoes",
    })
    print(verdict["decision"])          # "allow"
"""

from .compiler import compile, rule_based_parser
from .mandate import (
    MANDATE_SCHEMA,
    SPEC,
    VERSION,
    build_mandate,
    validate,
)
from .signing import generate_keypair, sign_mandate, verify_signature
from .verifier import verify

__version__ = "0.0.1"

__all__ = [
    "compile",
    "verify",
    "generate_keypair",
    "sign_mandate",
    "verify_signature",
    "build_mandate",
    "validate",
    "rule_based_parser",
    "MANDATE_SCHEMA",
    "SPEC",
    "VERSION",
    "__version__",
]
