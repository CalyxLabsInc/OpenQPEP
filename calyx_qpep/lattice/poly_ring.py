# OpenQPEP Official Release 1.2.4 (v1.2.4)
"""
Constant-Time Polynomial Ring Sampling (NTT Rejection, CBD_1, CBD_2, Ball Challenge) &
Division-Free Bit-Packing / Compression Codecs (KyberSlash-Free Barrett Arithmetic).

Security Guarantees:
  - Zero secret-dependent integer divisions (`//`, `%`) in `compress_poly`, `decompress_poly`,
    `byte_encode_12`, `byte_decode_12`, `sample_cbd1_3329`, `sample_cbd2_3329`, `sample_eta_qvs`,
    `sample_mask_y_qvs`, `pack_poly24_qvs`, and `unpack_poly24_qvs`.
  - KyberSlash-free fixed-point reciprocal compression: `(((x << d) + 1664) * 20642679) >> 36`,
    proven 100% bit-exact over all (x in 0..3328, d in 1..12).
  - Bit-for-bit identical branchless `ct_caddq` / `ct_csubq` / `barrett_reduce` arithmetic across
    Python, C99 (`libopenqpep`), and Rust (`openqpep-core`), with `SecretBuffer` scrubbing of
    noise-sampling PRF buffers.
"""
from typing import List

from ..constants import QLX_Q, QVS_GAMMA1, QVS_Q
from ..native.loader import (
    native_byte_decode_12,
    native_byte_encode_12,
    native_cbd1_3329,
    native_cbd2_3329,
    native_cbd2_qvs,
    native_poly_compress_3329,
    native_poly_decompress_3329,
    native_qlx_sample_ntt_3329,
    native_qvs_pack_poly24,
    native_qvs_sample_in_ball,
    native_qvs_sample_mask_y,
    native_qvs_sample_ntt,
    native_qvs_unpack_poly24,
)
from ..primitives.consttime import (
    barrett_reduce_3329,
    barrett_reduce_qvs,
    ct_caddq_3329,
    ct_caddq_qvs,
    ct_csubq_3329,
    ct_csubq_qvs,
)
from ..primitives.qsponge import qsponge_var
from ..primitives.zeroize import SecretBuffer

# Fixed-point reciprocal ceil(2^36 / 3329) = 20642679; exact for all N <= 41,522,342 (covers d = 1..12)
_COMPRESS_RECIP_3329 = 20642679
_QLX_HALF_Q = QLX_Q >> 1  # 1664


def compress_coeff_3329(c: int, d: int) -> int:
    """
    Division-free constant-time coefficient compression mod 3329 to `d` bits (1 <= d <= 12).
    Replaces variable-time `((x << d) + 1664) // 3329` (KyberSlash) with exact multiply-and-shift.
    """
    x = barrett_reduce_3329(c)
    return ((((x << d) + _QLX_HALF_Q) * _COMPRESS_RECIP_3329) >> 36) & ((1 << d) - 1)


def decompress_coeff_3329(val: int, d: int) -> int:
    """Division-free constant-time coefficient decompression from `d` bits (1 <= d <= 12) into [0, 3328]."""
    return ((val * QLX_Q) + (1 << (d - 1))) >> d


def sample_ntt_3329(rho: bytes, row: int, col: int) -> List[int]:
    """Rejection-samples a uniform public NTT-domain polynomial in R_3329 from seed rho || col || row."""
    res = native_qlx_sample_ntt_3329(rho, row, col)
    if res is not None:
        return res
    stream = qsponge_var(b"CALYX-QLX-MAT-A|" + rho + bytes([col, row]), 840)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < 256:
        d1 = stream[idx] + ((stream[idx + 1] & 0x0F) << 8)
        d2 = (stream[idx + 1] >> 4) + (stream[idx + 2] << 4)
        idx += 3
        if d1 < QLX_Q:
            coeffs.append(d1)
        if d2 < QLX_Q and len(coeffs) < 256:
            coeffs.append(d2)
    return coeffs


def sample_cbd2_3329(sigma: bytes, nonce: int) -> List[int]:
    """Branchless Centered Binomial Distribution CBD_2 sampler over R_3329 (bit-exact with C99 cbd.c)."""
    with SecretBuffer(qsponge_var(b"CALYX-QLX-CBD2|" + sigma + bytes([nonce]), 128)) as buf_sb:
        raw = buf_sb.as_bytes()
        res = native_cbd2_3329(raw)
        if res is not None:
            return res
        coeffs = [0] * 256
        for i in range(128):
            b = raw[i]
            a0 = (b & 1) + ((b >> 1) & 1)
            b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
            a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
            b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
            coeffs[2 * i] = ct_caddq_3329(a0 - b0)
            coeffs[2 * i + 1] = ct_caddq_3329(a1 - b1)
        return coeffs


def sample_cbd1_3329(sigma: bytes, nonce: int) -> List[int]:
    """
    Branchless unit-variance Centered Binomial Distribution CBD_1 sampler
    (coefficients in {-1, 0, 1}, variance sigma^2 = 0.5) over R_3329 for QLX-16384,
    bit-exact with C99 openqpep_cbd1_3329.
    """
    with SecretBuffer(qsponge_var(b"CALYX-QLX-CBD1|" + sigma + nonce.to_bytes(2, "little"), 64)) as buf_sb:
        raw = buf_sb.as_bytes()
        res = native_cbd1_3329(raw)
        if res is not None:
            return res
        coeffs = [0] * 256
        for i in range(64):
            b = raw[i]
            for j in range(4):
                a = (b >> (2 * j)) & 1
                c = (b >> (2 * j + 1)) & 1
                coeffs[4 * i + j] = ct_caddq_3329(a - c)
        return coeffs


def sample_cbd_eta_3329(sigma: bytes, nonce: int, eta: int = 2) -> List[int]:
    """Dispatches branchless CBD_eta sampling over R_3329 for eta in {1, 2}."""
    if eta == 1:
        return sample_cbd1_3329(sigma, nonce)
    if eta == 2:
        return sample_cbd2_3329(sigma, nonce)
    raise ValueError(f"Unsupported CBD eta={eta}; expected 1 or 2.")


def byte_encode_12(poly: List[int]) -> bytes:
    """Division-free branchless packing of 256 12-bit coefficients in Z_3329 into 384 bytes."""
    if len(poly) != 256:
        raise ValueError(f"byte_encode_12 requires exactly 256 coefficients, got {len(poly)}.")
    res = native_byte_encode_12(poly)
    if res is not None:
        return res
    out = bytearray(384)
    for i in range(128):
        c0 = barrett_reduce_3329(poly[2 * i])
        c1 = barrett_reduce_3329(poly[2 * i + 1])
        out[3 * i] = c0 & 0xFF
        out[3 * i + 1] = ((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4)
        out[3 * i + 2] = (c1 >> 4) & 0xFF
    return bytes(out)


def byte_decode_12(data: bytes) -> List[int]:
    """Division-free branchless unpacking of 384 bytes into 256 canonical coefficients in [0, 3328]."""
    if len(data) != 384:
        raise ValueError(f"byte_decode_12 requires exactly 384 bytes, got {len(data)}.")
    res = native_byte_decode_12(data)
    if res is not None:
        return res
    poly = [0] * 256
    for i in range(128):
        b0, b1, b2 = data[3 * i], data[3 * i + 1], data[3 * i + 2]
        poly[2 * i] = ct_csubq_3329(b0 | ((b1 & 0x0F) << 8))
        poly[2 * i + 1] = ct_csubq_3329((b1 >> 4) | (b2 << 4))
    return poly


def compress_poly(poly: List[int], d: int) -> bytes:
    """
    Division-free, KyberSlash-immune compression of 256 coefficients mod 3329 to `d` bits
    each (`1 <= d <= 12`), packed tightly into `32 * d` bytes.
    """
    if len(poly) != 256:
        raise ValueError(f"compress_poly requires exactly 256 coefficients, got {len(poly)}.")
    if d < 1 or d > 12:
        raise ValueError(f"compress_poly bit width d must be in 1..12, got {d}.")
    res = native_poly_compress_3329(poly, d)
    if res is not None:
        return res
    mask = (1 << d) - 1
    bits = 0
    bit_len = 0
    out = bytearray(32 * d)
    out_idx = 0
    for c in poly:
        x = barrett_reduce_3329(c)
        val = ((((x << d) + _QLX_HALF_Q) * _COMPRESS_RECIP_3329) >> 36) & mask
        bits |= val << bit_len
        bit_len += d
        while bit_len >= 8:
            out[out_idx] = bits & 0xFF
            out_idx += 1
            bits >>= 8
            bit_len -= 8
    return bytes(out)


def decompress_poly(data: bytes, d: int) -> List[int]:
    """
    Division-free constant-time unpacking of `32 * d` bytes (`1 <= d <= 12`) into
    256 canonical coefficients in [0, 3328].
    """
    if d < 1 or d > 12:
        raise ValueError(f"decompress_poly bit width d must be in 1..12, got {d}.")
    if len(data) != 32 * d:
        raise ValueError(f"decompress_poly requires exactly {32 * d} bytes for d={d}, got {len(data)}.")
    res = native_poly_decompress_3329(data, d)
    if res is not None:
        return res
    mask = (1 << d) - 1
    half = 1 << (d - 1)
    bits = 0
    bit_len = 0
    idx = 0
    poly = [0] * 256
    for i in range(256):
        while bit_len < d:
            bits |= data[idx] << bit_len
            idx += 1
            bit_len += 8
        val = bits & mask
        bits >>= d
        bit_len -= d
        poly[i] = (val * QLX_Q + half) >> d
    return poly


def sample_ntt_qvs(rho: bytes, row: int, col: int) -> List[int]:
    """Rejection-samples a uniform public NTT-domain polynomial in R_Q (Q = 8380417)."""
    res = native_qvs_sample_ntt(rho, row, col)
    if res is not None:
        return res
    stream = qsponge_var(b"CALYX-QVS-MAT-A|" + rho + bytes([row, col]), 1024)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < 256:
        val = (stream[idx] | (stream[idx + 1] << 8) | (stream[idx + 2] << 16)) & 0x7FFFFF
        idx += 3
        if val < QVS_Q:
            coeffs.append(val)
    return coeffs


def sample_eta_qvs(seed: bytes, nonce: int) -> List[int]:
    """Branchless short secret polynomial sampler with coefficients in [-2, 2] mod QVS_Q (bit-exact with C99)."""
    with SecretBuffer(qsponge_var(b"CALYX-QVS-ETA2|" + seed + bytes([nonce]), 128)) as buf_sb:
        raw = buf_sb.as_bytes()
        res = native_cbd2_qvs(raw)
        if res is not None:
            return res
        coeffs = [0] * 256
        for i in range(128):
            b = raw[i]
            a0 = (b & 1) + ((b >> 1) & 1)
            b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
            a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
            b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
            coeffs[2 * i] = ct_caddq_qvs(a0 - b0)
            coeffs[2 * i + 1] = ct_caddq_qvs(a1 - b1)
        return coeffs


def sample_mask_y_qvs(seed: bytes, nonce: int) -> List[int]:
    """Branchless masking polynomial y sampler with coefficients in [-gamma_1 + 1, gamma_1] mod QVS_Q."""
    res = native_qvs_sample_mask_y(seed, nonce)
    if res is not None:
        return res
    with SecretBuffer(qsponge_var(b"CALYX-QVS-MASK-Y|" + seed + nonce.to_bytes(2, "little"), 768)) as buf_sb:
        raw_buf = buf_sb.as_bytes()
        coeffs = [0] * 256
        for i in range(256):
            raw = (raw_buf[3 * i] | (raw_buf[3 * i + 1] << 8) | (raw_buf[3 * i + 2] << 16)) & 0xFFFFF
            coeffs[i] = ct_caddq_qvs(QVS_GAMMA1 - raw)
        return coeffs


def sample_in_ball_qvs(c_tilde: bytes, tau: int) -> List[int]:
    """Samples sparse public challenge polynomial c in R_Q with exactly tau coefficients in {-1, +1}."""
    res = native_qvs_sample_in_ball(c_tilde, tau)
    if res is not None:
        return res
    stream = qsponge_var(b"CALYX-QVS-BALL|" + c_tilde, 256)
    sign_bits = int.from_bytes(stream[:8], "little")
    idx = 8
    c = [0] * 256
    for i in range(256 - tau, 256):
        while True:
            j = stream[idx]
            idx += 1
            if j <= i:
                break
        c[i] = c[j]
        neg_mask = -(sign_bits & 1)
        c[j] = ((QVS_Q - 1) & neg_mask) | (1 & ~neg_mask)
        sign_bits >>= 1
    return c


def pack_poly24_qvs(poly: List[int]) -> bytes:
    """Division-free branchless packing of 256 QVS coefficients mod 8380417 into 768 bytes."""
    if len(poly) != 256:
        raise ValueError(f"pack_poly24_qvs requires exactly 256 coefficients, got {len(poly)}.")
    res = native_qvs_pack_poly24(poly)
    if res is not None:
        return res
    out = bytearray(768)
    for i, c in enumerate(poly):
        v = barrett_reduce_qvs(c)
        out[3 * i] = v & 0xFF
        out[3 * i + 1] = (v >> 8) & 0xFF
        out[3 * i + 2] = (v >> 16) & 0xFF
    return bytes(out)


def unpack_poly24_qvs(data: bytes) -> List[int]:
    """Division-free branchless unpacking of 768 bytes into 256 canonical QVS coefficients in [0, 8380416]."""
    if len(data) != 768:
        raise ValueError(f"unpack_poly24_qvs requires exactly 768 bytes, got {len(data)}.")
    res = native_qvs_unpack_poly24(data)
    if res is not None:
        return res
    poly = [0] * 256
    for i in range(256):
        raw = data[3 * i] | (data[3 * i + 1] << 8) | (data[3 * i + 2] << 16)
        # raw in [0, 16777215] < 3 * QVS_Q (25141251), so two branchless conditional subtracts are exact
        poly[i] = ct_csubq_qvs(ct_csubq_qvs(raw))
    return poly
