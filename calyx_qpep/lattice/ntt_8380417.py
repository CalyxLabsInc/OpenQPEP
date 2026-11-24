# OpenQPEP Official Release 1.2.0 (v1.2.0)
"""
8-Layer Complete Number Theoretic Transform & HighBits/LowBits Decomposition over Z_8380417[X]/(X^256+1).
Automatically dispatches through libopenqpep (C99/AVX2/NEON) when available, with
bit-exact pure-Python fallback.
"""
from typing import List, Tuple
from ..constants import QVS_Q, QVS_ZETA, QVS_GAMMA2, QVS_ALPHA
from ..native.loader import native_inv_ntt_qvs, native_ntt_qvs
from ..primitives.consttime import barrett_reduce_qvs, ct_caddq_qvs, ct_csubq_qvs

_QVS_HALF_Q = QVS_Q >> 1  # 4190208
# Exact reciprocal ceil(2^44 / 523776) = 33587233; exact for all r <= 34,671,784 >> QVS_Q
_QVS_ALPHA_M44 = ((1 << 44) + QVS_ALPHA - 1) // QVS_ALPHA

def _bitrev8(x: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_QVS = [pow(QVS_ZETA, _bitrev8(i), QVS_Q) for i in range(256)]
_INV_256_QVS = pow(256, QVS_Q - 2, QVS_Q)


def ntt_qvs(poly: List[int]) -> List[int]:
    """Forward 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    res = native_ntt_qvs(poly)
    if res is not None:
        return res
    p = list(poly)
    k = 0
    length = 128
    while length >= 1:
        for start in range(0, 256, 2 * length):
            k += 1
            zeta = _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = barrett_reduce_qvs(zeta * p[j + length])
                u = p[j]
                p[j + length] = ct_caddq_qvs(u - t)
                p[j] = ct_csubq_qvs(u + t)
        length >>= 1
    return p


def inv_ntt_qvs(poly_hat: List[int]) -> List[int]:
    """Inverse 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    res = native_inv_ntt_qvs(poly_hat)
    if res is not None:
        return res
    p = list(poly_hat)
    k = 256
    length = 1
    while length < 256:
        for start in range(0, 256, 2 * length):
            k -= 1
            zeta = QVS_Q - _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = p[j]
                u = p[j + length]
                p[j] = ct_csubq_qvs(t + u)
                p[j + length] = barrett_reduce_qvs(zeta * ct_caddq_qvs(t - u))
        length <<= 1
    return [barrett_reduce_qvs(x * _INV_256_QVS) for x in p]


def center_qvs(x: int) -> int:
    """Division-free branchless centered representative in [-(Q-1)/2, (Q-1)/2]."""
    r = barrett_reduce_qvs(x)
    return r - (((_QVS_HALF_Q - r) >> 31) & QVS_Q)


def decompose_qvs(r: int) -> Tuple[int, int]:
    """
    Division-free branchless HighBits/LowBits decomposition of r mod Q into (r1, r0)
    such that r == r1 * (2 * gamma2) + r0 (mod Q), proven bit-exact across all 8,380,417 residues.
    """
    r = barrett_reduce_qvs(r)
    q1 = (r * _QVS_ALPHA_M44) >> 44
    r0 = r - q1 * QVS_ALPHA
    gt = (QVS_GAMMA2 - r0) >> 31
    r0 -= gt & QVS_ALPHA
    r1 = q1 - gt
    is16 = (15 - r1) >> 31
    r1 &= ~is16
    r0 += is16
    return r1, r0
