"""
Branchless Constant-Time Cryptographic Primitives (Official Release 1.2.8 / v1.2.8).
Provides constant-time byte/string/int equality, branchless byte-array conditional move (ct_cmov)
for Fujisaki-Okamoto implicit-rejection multiplexing, and division-free Barrett/Montgomery modular
reduction helpers aligned bit-for-bit across Python, C99, and Rust.
"""
import hmac
from typing import Tuple

from ..native.loader import native_ct_cmov, native_ct_cswap, native_ct_mem_bounds_ok

_QLX_Q = 3329
_QVS_Q = 8380417
_BARRETT_3329_M36 = (1 << 36) // _QLX_Q   # 20642678 — exact for |x| <= 2^35 (~34B)
_BARRETT_QVS_M50 = (1 << 50) // _QVS_Q    # 134348876 — exact for |x| <= 2^47 (~140T >> QVS_Q^2)


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string comparison."""
    if not isinstance(a, (bytes, bytearray, memoryview)) or not isinstance(b, (bytes, bytearray, memoryview)):
        return False
    return hmac.compare_digest(a, b)


def ct_eq_str(a: object, b: object) -> bool:
    """Constant-time UTF-8 string comparison for key hashes, digests, commitments, and tokens."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def ct_eq_int(a: object, b: object) -> bool:
    """Constant-time bounded integer equality comparison."""
    if not isinstance(a, int) or isinstance(a, bool) or not isinstance(b, int) or isinstance(b, bool):
        return False
    return hmac.compare_digest(str(a).encode("ascii"), str(b).encode("ascii"))


def ct_select_int(cond: int, a: int, b: int) -> int:
    """Branchless integer select: returns a if cond != 0 else b."""
    mask = -(1 if cond else 0)
    return (a & mask) | (b & ~mask)


def ct_cmov(cond: bool, a: bytes, b: bytes) -> bytes:
    """
    Branchless constant-time conditional move over equal-length byte buffers.
    Dispatches transparently to Native C99 `openqpep_ct_cmov` with bit-exact Pure-Python fallback.
    """
    if len(a) != len(b):
        raise ValueError("ct_cmov requires equal-length byte buffers.")
    nat = native_ct_cmov(bool(cond), a, b)
    if nat is not None:
        return nat
    mask = 0xFF if cond else 0x00
    inv_mask = mask ^ 0xFF
    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = (a[i] & mask) | (b[i] & inv_mask)
    return bytes(out)


def ct_cswap(cond: bool, a: bytes, b: bytes) -> Tuple[bytes, bytes]:
    """
    Branchless constant-time conditional swap over equal-length byte buffers.
    Dispatches transparently to Native C99 `openqpep_ct_cswap` with bit-exact Pure-Python fallback.
    """
    if len(a) != len(b):
        raise ValueError("ct_cswap requires equal-length byte buffers.")
    nat = native_ct_cswap(bool(cond), a, b)
    if nat is not None:
        return nat
    mask = 0xFF if cond else 0x00
    out_a = bytearray(a)
    out_b = bytearray(b)
    for i in range(len(out_a)):
        diff = (out_a[i] ^ out_b[i]) & mask
        out_a[i] ^= diff
        out_b[i] ^= diff
    return bytes(out_a), bytes(out_b)


def ct_mem_bounds_ok(offset: int, span: int, total: int) -> bool:
    """
    Overflow-safe constant-time memory bounds check (`offset <= total` and `span <= total - offset`).
    Dispatches to Native C99 `openqpep_ct_mem_bounds_ok` when available.
    """
    if (
        isinstance(offset, bool) or isinstance(span, bool) or isinstance(total, bool)
        or not isinstance(offset, int) or not isinstance(span, int) or not isinstance(total, int)
    ):
        return False
    if offset < 0 or span < 0 or total < 0:
        return False
    if offset < (1 << 64) and span < (1 << 64) and total < (1 << 64):
        nat = native_ct_mem_bounds_ok(offset, span, total)
        if nat is not None:
            return nat
    return offset <= total and span <= (total - offset)


def ct_caddq_3329(a: int) -> int:
    """Branchless conditional add of QLX_Q=3329 when a < 0 (matches C99/Rust ct_caddq_3329)."""
    return a + ((a >> 31) & _QLX_Q)


def ct_csubq_3329(a: int) -> int:
    """Branchless conditional subtract of QLX_Q=3329 when a >= 3329 (matches C99/Rust ct_csubq_3329)."""
    d = a - _QLX_Q
    return d + ((d >> 31) & _QLX_Q)


def ct_caddq_qvs(a: int) -> int:
    """Branchless conditional add of QVS_Q=8380417 when a < 0."""
    return a + ((a >> 31) & _QVS_Q)


def ct_csubq_qvs(a: int) -> int:
    """Branchless conditional subtract of QVS_Q=8380417 when a >= 8380417."""
    d = a - _QVS_Q
    return d + ((d >> 31) & _QVS_Q)


def barrett_reduce_3329(x: int) -> int:
    """
    Division-free branchless Barrett modular reduction modulo QLX_Q = 3329.
    Exact canonical output in [0, 3328] for all |x| <= 2^35 (matches C99/Rust ct_barrett_3329).
    """
    t = (x * _BARRETT_3329_M36) >> 36
    r = x - t * _QLX_Q
    r = ct_caddq_3329(r)
    return ct_csubq_3329(r)


def montgomery_reduce_3329(a: int) -> int:
    """Division-free Montgomery reduction modulo QLX_Q = 3329 with R = 2^16 (q^-1 mod 2^16 = 62209)."""
    t = (a * 62209) & 0xFFFF
    u = (a - t * _QLX_Q) >> 16
    return barrett_reduce_3329(u)


def barrett_reduce_qvs(x: int) -> int:
    """
    Division-free branchless Barrett modular reduction modulo QVS_Q = 8380417.
    Exact canonical output in [0, 8380416] for all |x| <= 2^47 (covers +/- QVS_Q^2).
    """
    t = (x * _BARRETT_QVS_M50) >> 50
    r = x - t * _QVS_Q
    r = ct_caddq_qvs(r)
    return ct_csubq_qvs(r)
