"""
Pure-Python Ed25519 (RFC 8032), zero dependencies.

This is the well-known slow reference implementation. It is here so MandateKit
signs and verifies with no third-party crypto dependency: the user's signing key
never has to leave the device, and there is nothing to `pip install` to try it.

It is RFC 8032 compatible (see the test vector in the test suite), so signatures
produced here verify against any conforming Ed25519 implementation, including the
TypeScript port (which uses Node's built-in crypto).

For production you would swap this for libsodium / `cryptography`. The signing and
verifying surface in `signing.py` is the only thing the rest of MandateKit touches,
so that swap is a one-file change.
"""

import hashlib

b = 256
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(z: int) -> int:
    return pow(z, q - 2, q)


d = -121665 * _inv(121666) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5) % q
_Bx = _xrecover(_By)
B = (_Bx % q, _By % q, 1, (_Bx * _By) % q)


def _edwards_add(P, Q):
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = (y1 - x1) * (y2 - x2) % q
    bb = (y1 + x1) * (y2 + x2) % q
    c = t1 * 2 * d * t2 % q
    dd = z1 * 2 * z2 % q
    e = bb - a
    f = dd - c
    g = dd + c
    h = bb + a
    return (e * f % q, g * h % q, f * g % q, e * h % q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return y.to_bytes(b // 8, "little")


def _encodepoint(P) -> bytes:
    (x, y, z, t) = P
    zi = _inv(z)
    x = x * zi % q
    y = y * zi % q
    out = bytearray(_encodeint(y))
    out[-1] |= (x & 1) << 7
    return bytes(out)


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _isoncurve(P) -> bool:
    (x, y, z, t) = P
    return (
        z % q != 0
        and x * y % q == z * t % q
        and (y * y - x * x - z * z - d * t * t) % q == 0
    )


def _decodepoint(s: bytes):
    y = _decodeint(s) & ((1 << (b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, b - 1):
        x = q - x
    P = (x, y, 1, (x * y) % q)
    if not _isoncurve(P):
        raise ValueError("point is not on the curve")
    return P


def _secret_scalar_and_prefix(sk: bytes):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    return a, h[b // 8 : b // 4]


def publickey(sk: bytes) -> bytes:
    """32-byte secret seed -> 32-byte public key."""
    a, _ = _secret_scalar_and_prefix(sk)
    return _encodepoint(_scalarmult(B, a))


def _Hint(m: bytes) -> int:
    return _decodeint(_H(m)) % (2 ** (2 * b))


def sign(message: bytes, sk: bytes, pk: bytes) -> bytes:
    """Return a 64-byte Ed25519 signature over `message`."""
    a, prefix = _secret_scalar_and_prefix(sk)
    r = _Hint(prefix + message)
    R = _scalarmult(B, r)
    Renc = _encodepoint(R)
    S = (r + _Hint(Renc + pk + message) * a) % L
    return Renc + _encodeint(S)


def verify(signature: bytes, message: bytes, pk: bytes) -> bool:
    """Verify a 64-byte signature. Returns True/False, never raises on bad sig."""
    if len(signature) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(pk)
    except ValueError:
        return False
    S = _decodeint(signature[32:])
    if S >= L:
        return False
    h = _Hint(signature[:32] + pk + message)
    x1, y1, z1, _ = _scalarmult(B, S)
    x2, y2, z2, _ = _edwards_add(R, _scalarmult(A, h))
    return (x1 * z2 - x2 * z1) % q == 0 and (y1 * z2 - y2 * z1) % q == 0
