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
    }, trusted_keys=[public_key])
    print(verdict["decision"])          # "allow"

0.2 adds per-verb counterparty scope, a window start (`not_before`), usage
limits enforced against a caller-supplied store, issuer-signed revocation
lists, and delegation chains. See the README.
"""

from .compiler import compile, rule_based_parser
from .crosswalk import to_authorization_details
from .mandate import (
    INHERIT,
    MANDATE_SCHEMA,
    REVOCATION_LIST_VERSION,
    SPEC,
    SUPPORTED_VERSIONS,
    VERSION,
    build_mandate,
    build_revocation_list,
    delegate_mandate,
    step_mandate,
    validate,
)
from .signing import (
    generate_keypair,
    sign_mandate,
    sign_revocation_list,
    verify_revocation_list_signature,
    verify_signature,
)
from .store import InMemoryUsageStore
from .verifier import REASON_CODES, record_use, verify

__version__ = "0.2.1"

__all__ = [
    "compile",
    "verify",
    "record_use",
    "generate_keypair",
    "sign_mandate",
    "verify_signature",
    "sign_revocation_list",
    "verify_revocation_list_signature",
    "build_mandate",
    "delegate_mandate",
    "step_mandate",
    "build_revocation_list",
    "to_authorization_details",
    "validate",
    "rule_based_parser",
    "InMemoryUsageStore",
    "INHERIT",
    "MANDATE_SCHEMA",
    "REASON_CODES",
    "REVOCATION_LIST_VERSION",
    "SPEC",
    "SUPPORTED_VERSIONS",
    "VERSION",
    "__version__",
]
