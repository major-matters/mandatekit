"""
Mandate signing and signature verification.

Signing uses Ed25519. By default it runs on the vetted, constant-time
implementation from the `cryptography` library. If that is not installed, it
falls back to the pure-Python reference in `ed25519.py` — correct (RFC 8032) but
NOT constant-time — and emits a warning. Install `cryptography` for any real use.

The signing key is a 32-byte Ed25519 seed that stays on the caller's machine.
`sign_mandate` attaches a detached signature plus the public key so a verifier
needs nothing but the signed document itself.
"""

import base64
import os
import warnings
from typing import Dict, Tuple

from .canonical import canonicalize

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _BACKEND = "cryptography"
except ImportError:  # pragma: no cover - exercised only without the dep
    from . import ed25519 as _ref

    _BACKEND = "pure-python"
    warnings.warn(
        "mandatekit: 'cryptography' is not installed; falling back to a pure-Python "
        "Ed25519 reference that is NOT constant-time. Install 'cryptography' for "
        "production use.",
        RuntimeWarning,
        stacklevel=2,
    )


def _public_from_seed(seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return _ref.publickey(seed)


def _sign(message: bytes, seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return _ref.sign(message, seed, _ref.publickey(seed))


def _verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if _BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except Exception:
            return False
    return _ref.verify(signature, message, public_key)


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_seed, public_key) as raw 32-byte values."""
    seed = os.urandom(32)
    return seed, _public_from_seed(seed)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def sign_mandate(mandate: Dict, private_key: bytes) -> Dict:
    """Wrap a mandate dict in a signed envelope."""
    public_key = _public_from_seed(private_key)
    signature = _sign(canonicalize(mandate), private_key)
    return {
        "mandate": mandate,
        "signature": {
            "alg": "Ed25519",
            "public_key": _b64(public_key),
            "value": _b64(signature),
        },
    }


def verify_signature(signed: Dict) -> bool:
    """True iff the envelope's signature matches its mandate. Never raises —
    malformed input (bad base64, non-canonicalizable values, etc.) returns False."""
    sig = signed.get("signature") or {}
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
        return False
    try:
        public_key = _unb64(sig["public_key"])
        value = _unb64(sig["value"])
        return _verify(value, canonicalize(signed["mandate"]), public_key)
    except Exception:
        return False
