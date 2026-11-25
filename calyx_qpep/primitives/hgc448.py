"""
HGC-448 (448-bit Goldilocks X448 Diffie-Hellman & Ed448 Edwards Signatures) Hybrid Combiner
(Official Release 1.2.8 / v1.2.8).

Security Hardening:
  - Full RFC 7748 X448 contributory validation: rejects non-canonical u >= p encodings,
    all Curve448 & twist low-order points (u mod p in {0, 1, p-1}), and constant-time all-zero
    shared-secret rejection.
  - Strict RFC 8032 Ed448 verification (`strict_ed448_verify`, also invoked by `ed448_verify`):
    enforces canonical point decoding for both public key A and nonce commitment R (y < p,
    unused bits 448..454 == 0, no -0, on-curve check), rejects all 4 small-order torsion points
    E[4] (closing OpenSSL's cofactored order-4 S=0 forgery), and enforces canonical scalar
    0 <= S < L (blocking S + L signature malleability).
  - Mandatory Verify-Before-Emit Fault-Guard (`QPEPFaultGuardError`) on `ed448_sign` and
    `SecretBuffer` RAM scrubbing on every private-key operation.
"""
import os
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from ..exceptions import QPEPFaultGuardError
from .consttime import ct_eq
from .zeroize import SecretBuffer

# RFC 7748 / RFC 8032 Curve448 / Ed448 Goldilocks domain parameters
CURVE448_P: int = (1 << 448) - (1 << 224) - 1
ED448_ORDER_L: int = (1 << 446) - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
ED448_D: int = (CURVE448_P - 39081) % CURVE448_P
_P448_SQRT_EXP: int = (CURVE448_P + 1) // 4

_ZERO_56: bytes = b"\x00" * 56

# Complete Curve448 & quadratic-twist low-order u-coordinates: u in {0, 1, p-1}
X448_LOW_ORDER_POINTS: Tuple[bytes, ...] = (
    (0).to_bytes(56, "little"),
    (1).to_bytes(56, "little"),
    (CURVE448_P - 1).to_bytes(56, "little"),
)

# Complete Ed448 torsion subgroup E[4] canonical 57-byte encodings:
#   (0, 1) [order 1], (0, p-1) [order 2], (1, 0) [order 4], (p-1, 0) [order 4]
ED448_SMALL_ORDER_POINTS: Tuple[bytes, ...] = (
    (1).to_bytes(56, "little") + b"\x00",
    (CURVE448_P - 1).to_bytes(56, "little") + b"\x00",
    (0).to_bytes(56, "little") + b"\x80",
    (0).to_bytes(56, "little") + b"\x00",
)


def is_x448_low_order_point(pub_bytes: bytes) -> bool:
    """Constant-time check whether a 56-byte X448 public key encodes a Curve448/twist low-order point."""
    if not isinstance(pub_bytes, (bytes, bytearray, memoryview)) or len(pub_bytes) != 56:
        return True
    u_mod = int.from_bytes(bytes(pub_bytes), "little") % CURVE448_P
    u_canon = u_mod.to_bytes(56, "little")
    bad = False
    for low_pt in X448_LOW_ORDER_POINTS:
        if ct_eq(u_canon, low_pt):
            bad = True
    return bad


def validate_x448_public_key(pub_bytes: bytes, *, strict_canonical: bool = True) -> bool:
    """
    Validates a 56-byte RFC 7748 X448 public key:
      - Exact length 56 bytes.
      - When `strict_canonical=True`, rejects non-canonical u >= p encodings (anti-substitution).
      - Rejects all Curve448 and twist low-order points (u mod p in {0, 1, p-1}).
    """
    if not isinstance(pub_bytes, (bytes, bytearray, memoryview)) or len(pub_bytes) != 56:
        return False
    raw = bytes(pub_bytes)
    u = int.from_bytes(raw, "little")
    if strict_canonical and u >= CURVE448_P:
        return False
    return not is_x448_low_order_point(raw)


def is_ed448_small_order_point(point57: bytes) -> bool:
    """Constant-time check whether a 57-byte Ed448 encoding is one of the 4 small-order torsion points E[4]."""
    if not isinstance(point57, (bytes, bytearray, memoryview)) or len(point57) != 57:
        return True
    raw = bytes(point57)
    bad = False
    for pt in ED448_SMALL_ORDER_POINTS:
        if ct_eq(raw, pt):
            bad = True
    return bad


def _decode_ed448_point_strict(point57: bytes) -> Optional[Tuple[int, int]]:
    """
    Strictly decodes an RFC 8032 Section 5.2.3 57-byte Ed448 curve point:
      - Rejects non-zero padding bits (bits 448..454).
      - Rejects non-canonical y >= p.
      - Computes x = sqrt((y^2 - 1) / (d*y^2 - 1)) mod p and verifies x^2 matches.
      - Rejects non-canonical negative zero (x == 0 with sign_bit == 1).
      - Verifies Edwards curve equation x^2 + y^2 == 1 + d*x^2*y^2 (mod p).
    """
    if not isinstance(point57, (bytes, bytearray, memoryview)) or len(point57) != 57:
        return None
    raw = bytes(point57)
    if (raw[56] & 0x7F) != 0:
        return None
    sign_bit = (raw[56] >> 7) & 1
    y = int.from_bytes(raw[:56], "little")
    if y >= CURVE448_P:
        return None
    y2 = (y * y) % CURVE448_P
    u = (y2 - 1) % CURVE448_P
    v = (ED448_D * y2 - 1) % CURVE448_P
    if v == 0:
        return None
    x2 = (u * pow(v, -1, CURVE448_P)) % CURVE448_P
    x = pow(x2, _P448_SQRT_EXP, CURVE448_P)
    if (x * x) % CURVE448_P != x2:
        return None
    if x == 0 and sign_bit == 1:
        return None
    if (x & 1) != sign_bit:
        x = CURVE448_P - x
    if (x * x + y2) % CURVE448_P != (1 + ED448_D * x * x * y2) % CURVE448_P:
        return None
    return x, y


def validate_ed448_point(point57: bytes, *, reject_small_order: bool = True) -> bool:
    """Returns True iff `point57` is a canonical on-curve Ed448 point (and non-small-order when requested)."""
    if _decode_ed448_point_strict(point57) is None:
        return False
    if reject_small_order and is_ed448_small_order_point(point57):
        return False
    return True


def x448_keygen() -> Tuple[bytes, bytes]:
    with SecretBuffer(os.urandom(56)) as seed_buf:
        priv = X448PrivateKey.from_private_bytes(seed_buf.as_bytes())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def x448_exchange(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    """
    Executes RFC 7748 X448 Diffie-Hellman with full contributory validation:
      - Rejects invalid, non-canonical (u >= p), or low-order peer public keys.
      - Rejects all-zero shared secrets in constant time.
      - Scrubs private scalar and intermediate shared secret via `SecretBuffer`.
    """
    if not isinstance(priv_bytes, (bytes, bytearray, memoryview)) or len(priv_bytes) != 56:
        raise ValueError("X448 private key must be exactly 56 bytes.")
    if not validate_x448_public_key(peer_pub_bytes, strict_canonical=True):
        raise ValueError("X448 invalid, non-canonical, or low-order peer public key rejected (RFC 7748).")
    with SecretBuffer(priv_bytes) as sb:
        priv = X448PrivateKey.from_private_bytes(sb.as_bytes())
        peer_pub = X448PublicKey.from_public_bytes(bytes(peer_pub_bytes))
        with SecretBuffer(priv.exchange(peer_pub)) as shared_buf:
            # RFC 7748 Section 6.2: reject all-zero low-order shared secret in constant time
            if ct_eq(shared_buf.as_bytes(), _ZERO_56):
                raise ValueError("X448 low-order contributor point rejected (all-zero shared secret).")
            return shared_buf.as_bytes()


def ed448_keygen() -> Tuple[bytes, bytes]:
    with SecretBuffer(os.urandom(57)) as seed_buf:
        priv = Ed448PrivateKey.from_private_bytes(seed_buf.as_bytes())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pub_bytes, priv_bytes


def ed448_public_from_private(priv_bytes: bytes) -> bytes:
    with SecretBuffer(priv_bytes) as sb:
        priv = Ed448PrivateKey.from_private_bytes(sb.as_bytes())
        return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed448_sign(priv_bytes: bytes, data: bytes) -> bytes:
    """
    Signs `data` with RFC 8032 Ed448 and enforces mandatory Verify-Before-Emit Fault-Guard
    (`QPEPFaultGuardError`) using `strict_ed448_verify` to defeat differential fault attacks.
    """
    with SecretBuffer(priv_bytes) as sb:
        priv = Ed448PrivateKey.from_private_bytes(sb.as_bytes())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = priv.sign(bytes(data))
    if not ed448_verify(pub_bytes, sig, data):
        raise QPEPFaultGuardError("HGC-448 Ed448 Fault-Injection Guard triggered: signature failed internal verification.")
    return sig


def strict_ed448_verify(pub_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """
    Strict RFC 8032 Ed448 signature verifier:
      1. Enforces exact lengths (57-byte public key, 114-byte signature).
      2. Enforces canonical on-curve encoding AND rejects all 4 small-order torsion points E[4]
         for BOTH public key A and signature commitment R (defeating small-order S=0 forgeries).
      3. Enforces canonical scalar 0 <= S < L with top byte 0x00 (defeating S + L malleability).
      4. Verifies signature algebraically via Ed448PublicKey.verify().
    """
    try:
        if (
            not isinstance(pub_bytes, (bytes, bytearray, memoryview))
            or not isinstance(signature, (bytes, bytearray, memoryview))
            or not isinstance(data, (bytes, bytearray, memoryview))
            or len(pub_bytes) != 57
            or len(signature) != 114
        ):
            return False
        pub = bytes(pub_bytes)
        sig = bytes(signature)
        r_bytes = sig[:57]
        s_bytes = sig[57:114]

        # Enforce canonical non-small-order public key A and commitment R
        if not validate_ed448_point(pub, reject_small_order=True):
            return False
        if not validate_ed448_point(r_bytes, reject_small_order=True):
            return False

        # Enforce RFC 8032 canonical scalar 0 <= S < L (byte 56 must be 0x00)
        if s_bytes[56] != 0:
            return False
        s_int = int.from_bytes(s_bytes, "little")
        if s_int >= ED448_ORDER_L:
            return False

        Ed448PublicKey.from_public_bytes(pub).verify(sig, bytes(data))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def ed448_verify(pub_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Canonical Ed448 verifier delegating directly to `strict_ed448_verify`."""
    return strict_ed448_verify(pub_bytes, signature, data)
