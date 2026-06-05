"""
Mandate signing and signature verification.

The signing key is a 32-byte Ed25519 seed that stays on the caller's machine.
`sign_mandate` attaches a detached signature plus the public key so a verifier
needs nothing but the signed document itself.
"""

import base64
import os
from typing import Dict, Tuple

from . import ed25519
from .canonical import canonicalize


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_seed, public_key) as raw 32-byte values."""
    seed = os.urandom(32)
    return seed, ed25519.publickey(seed)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def sign_mandate(mandate: Dict, private_key: bytes) -> Dict:
    """Wrap a mandate dict in a signed envelope."""
    public_key = ed25519.publickey(private_key)
    signature = ed25519.sign(canonicalize(mandate), private_key, public_key)
    return {
        "mandate": mandate,
        "signature": {
            "alg": "Ed25519",
            "public_key": _b64(public_key),
            "value": _b64(signature),
        },
    }


def verify_signature(signed: Dict) -> bool:
    """True iff the envelope's signature matches its mandate. Never raises."""
    sig = signed.get("signature") or {}
    if sig.get("alg") != "Ed25519":
        return False
    try:
        public_key = _unb64(sig["public_key"])
        value = _unb64(sig["value"])
    except Exception:
        return False
    return ed25519.verify(value, canonicalize(signed["mandate"]), public_key)
