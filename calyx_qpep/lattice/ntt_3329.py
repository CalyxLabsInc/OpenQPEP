# OpenQPEP Official Release 1.2.0 (v1.2.0)
"""
7-Layer Cooley-Tukey / Gentleman-Sande Number Theoretic Transform over Z_3329[X]/(X^256+1).
Automatically dispatches through libopenqpep (C99/AVX2/NEON) when available, with
bit-exact pure-Python fallback.
"""
from typing import List
from ..constants import QLX_Q, QLX_N, QLX_ZETA
from ..native.loader import (
    native_inv_ntt_3329,
    native_ntt_3329,
    native_ntt_base_mul_3329,
    native_poly_add_3329,
    native_poly_sub_3329,
)
from ..primitives.consttime import barrett_reduce_3329, ct_caddq_3329, ct_csubq_3329

def _bitrev7(x: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_3329 = [pow(QLX_ZETA, _bitrev7(i), QLX_Q) for i in range(128)]
_ZETAS_BASE_3329 = [pow(QLX_ZETA, 2 * _bitrev7(i) + 1, QLX_Q) for i in range(128)]
_INV_128_3329 = pow(128, QLX_Q - 2, QLX_Q)


def ntt_3329(poly: List[int]) -> List[int]:
    """Forward 7-layer Number Theoretic Transform in Z_3329[X]/(X^256 + 1)."""
    res = native_ntt_3329(poly)
    if res is not None:
        return res
    p = list(poly)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS_3329[k]
            k += 1
            for j in range(start, start + length):
                t = barrett_reduce_3329(zeta * p[j + length])
                u = p[j]
                p[j + length] = ct_caddq_3329(u - t)
                p[j] = ct_csubq_3329(u + t)
        length >>= 1
    return p


def inv_ntt_3329(poly_hat: List[int]) -> List[int]:
    """Inverse 7-layer Number Theoretic Transform in Z_3329[X]/(X^256 + 1)."""
    res = native_inv_ntt_3329(poly_hat)
    if res is not None:
        return res
    p = list(poly_hat)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = QLX_Q - _ZETAS_3329[k]
            k -= 1
            for j in range(start, start + length):
                t = p[j]
                u = p[j + length]
                p[j] = ct_csubq_3329(t + u)
                p[j + length] = barrett_reduce_3329(zeta * ct_caddq_3329(t - u))
        length <<= 1
    return [barrett_reduce_3329(x * _INV_128_3329) for x in p]


def ntt_base_mul_3329(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Multiplies two NTT-domain polynomials modulo X^2 - zeta^(2*br7(i)+1) in Z_3329."""
    res = native_ntt_base_mul_3329(a_hat, b_hat)
    if res is not None:
        return res
    out = [0] * 256
    for i in range(128):
        a0, a1 = a_hat[2 * i], a_hat[2 * i + 1]
        b0, b1 = b_hat[2 * i], b_hat[2 * i + 1]
        gamma = _ZETAS_BASE_3329[i]
        out[2 * i] = barrett_reduce_3329(a0 * b0 + barrett_reduce_3329(a1 * b1) * gamma)
        out[2 * i + 1] = barrett_reduce_3329(a0 * b1 + a1 * b0)
    return out


def poly_add_3329(a: List[int], b: List[int]) -> List[int]:
    res = native_poly_add_3329(a, b)
    if res is not None:
        return res
    return [ct_csubq_3329(x + y) for x, y in zip(a, b)]


def poly_sub_3329(a: List[int], b: List[int]) -> List[int]:
    res = native_poly_sub_3329(a, b)
    if res is not None:
        return res
    return [ct_caddq_3329(x - y) for x, y in zip(a, b)]
