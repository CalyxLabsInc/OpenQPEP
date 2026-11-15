"""
OpenQPEP (CALYX-QPEP) – Calyx Quantum Proof Encryption Protocol
Copyright © 2026 Calyx Labs Inc. Developed by Tristen Martinez. All rights reserved.
(https://github.com/CalyxLabsInc/OpenQPEP/)

Calyx QPEP Quantum Lattice Exchange (QLX-768 / QLX-1024 / QLX-2048) &
Quantum Vector Signature (QVS-65 / QVS-87 / QVS-128) Mathematical Engine.

Implements:
1. qSponge-512 & qSponge-XOF: 1600-bit Keccak sponge (SHA3-512 / SHAKE-256) with
   domain-separated duplex framing (zero SHA-256 usage).
2. QLXEngine (Module-LWE over R_q = Z_3329[X]/(X^256 + 1)):
   - 7-layer Cooley-Tukey / Gentleman-Sande Number Theoretic Transform (NTT) with
     primitive 256th root of unity zeta = 17 mod 3329.
   - Centered Binomial Distribution (CBD_2) noise and secret polynomial sampling.
   - 12-bit lossless ring serialization and d_u / d_v lossy ciphertext compression.
   - Full Fujisaki-Okamoto (FO) IND-CCA2 transform with re-encryption verification
     and implicit rejection on decapsulation.
3. QVSEngine (Lattice Fiat-Shamir with Aborts over R_Q = Z_8380417[X]/(X^256 + 1)):
   - 8-layer complete Number Theoretic Transform (NTT) with primitive 512th root
     of unity zeta_Q = 1753 mod 8380417.
   - Rejection sampling over masking vectors y in [-gamma_1 + 1, gamma_1]^l ensuring
     ||z||_inf < gamma_1 - beta and HighBits(A*z - c*t, 2*gamma_2) == HighBits(w, 2*gamma_2)
     so signatures leak zero statistical information about secret vectors (s_1, s_2).
"""
import os
import hmac
import hashlib
from typing import Tuple, List

# ============================================================================
# 1. qSponge-512 & qSponge-XOF (1600-Bit Keccak Sponge Primitives)
# ============================================================================
def qsponge_var(data: bytes, length: int) -> bytes:
    """Variable-length extendable output function (XOF) over Keccak-f[1600]."""
    h = hashlib.shake_256()
    h.update(b"CALYX-QSPONGE-XOF-v1|")
    h.update(data)
    return h.digest(length)


def qsponge_512(data: bytes) -> bytes:
    """512-bit cryptographic sponge digest over Keccak-f[1600] (SHA3-512)."""
    h = hashlib.sha3_512()
    h.update(b"CALYX-QSPONGE-512-v1|")
    h.update(data)
    return h.digest()


# ============================================================================
# 2. QLX MODULE-LWE RING ALGEBRA OVER R_3329 = Z_3329[X]/(X^256 + 1)
# ============================================================================
QLX_Q = 3329
QLX_N = 256
QLX_ZETA = 17


def _bitrev7(x: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_3329 = [pow(QLX_ZETA, _bitrev7(i), QLX_Q) for i in range(128)]
_ZETAS_BASE_3329 = [pow(QLX_ZETA, 2 * _bitrev7(i) + 1, QLX_Q) for i in range(128)]
_INV_128_3329 = pow(128, QLX_Q - 2, QLX_Q)

QLX_TIERS = {
    "QLX-768": {
        "k": 3,
        "du": 10,
        "dv": 4,
        "pk_bytes": 384 * 3 + 32,              # 1184
        "sk_bytes": 384 * 3 + (384 * 3 + 32) + 64,  # 2400
        "ct_bytes": 320 * 3 + 128,             # 1088
        "qvs_tier": "QVS-65",
    },
    "QLX-1024": {
        "k": 4,
        "du": 11,
        "dv": 5,
        "pk_bytes": 384 * 4 + 32,              # 1568
        "sk_bytes": 384 * 4 + (384 * 4 + 32) + 64,  # 3168
        "ct_bytes": 352 * 4 + 160,             # 1568
        "qvs_tier": "QVS-87",
    },
    "QLX-2048": {
        "k": 8,
        "du": 11,
        "dv": 5,
        "pk_bytes": 384 * 8 + 32,              # 3104
        "sk_bytes": 384 * 8 + (384 * 8 + 32) + 64,  # 6240
        "ct_bytes": 352 * 8 + 160,             # 2976
        "qvs_tier": "QVS-128",
    },
}


def ntt_3329(poly: List[int]) -> List[int]:
    """Forward 7-layer Number Theoretic Transform in Z_3329[X]/(X^256 + 1)."""
    p = list(poly)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS_3329[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * p[j + length]) % QLX_Q
                p[j + length] = (p[j] - t) % QLX_Q
                p[j] = (p[j] + t) % QLX_Q
        length >>= 1
    return p


def inv_ntt_3329(poly_hat: List[int]) -> List[int]:
    """Inverse 7-layer Number Theoretic Transform in Z_3329[X]/(X^256 + 1)."""
    p = list(poly_hat)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = QLX_Q - _ZETAS_3329[k]
            k -= 1
            for j in range(start, start + length):
                t = p[j]
                p[j] = (t + p[j + length]) % QLX_Q
                p[j + length] = (zeta * (t - p[j + length])) % QLX_Q
        length <<= 1
    return [(x * _INV_128_3329) % QLX_Q for x in p]


def ntt_base_mul_3329(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Multiplies two NTT-domain polynomials modulo X^2 - zeta^(2*br7(i)+1) in Z_3329."""
    out = [0] * 256
    for i in range(128):
        a0, a1 = a_hat[2 * i], a_hat[2 * i + 1]
        b0, b1 = b_hat[2 * i], b_hat[2 * i + 1]
        gamma = _ZETAS_BASE_3329[i]
        out[2 * i] = (a0 * b0 + a1 * b1 * gamma) % QLX_Q
        out[2 * i + 1] = (a0 * b1 + a1 * b0) % QLX_Q
    return out


def poly_add_3329(a: List[int], b: List[int]) -> List[int]:
    return [(x + y) % QLX_Q for x, y in zip(a, b)]


def poly_sub_3329(a: List[int], b: List[int]) -> List[int]:
    return [(x - y) % QLX_Q for x, y in zip(a, b)]


def sample_ntt_3329(rho: bytes, row: int, col: int) -> List[int]:
    """Rejection-samples a uniform NTT-domain polynomial in R_3329 from seed rho || col || row."""
    stream = qsponge_var(b"CALYX-QLX-MAT-A|" + rho + bytes([col, row]), 840)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < 256:
        d1 = stream[idx] + 256 * (stream[idx + 1] & 0x0F)
        d2 = (stream[idx + 1] >> 4) + 16 * stream[idx + 2]
        idx += 3
        if d1 < QLX_Q:
            coeffs.append(d1)
        if d2 < QLX_Q and len(coeffs) < 256:
            coeffs.append(d2)
    return coeffs


def sample_cbd2_3329(sigma: bytes, nonce: int) -> List[int]:
    """Samples a polynomial from the Centered Binomial Distribution CBD_2 over R_3329."""
    buf = qsponge_var(b"CALYX-QLX-CBD2|" + sigma + bytes([nonce]), 128)
    coeffs = [0] * 256
    for i in range(128):
        b = buf[i]
        a0 = (b & 1) + ((b >> 1) & 1)
        b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
        a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
        b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
        coeffs[2 * i] = (a0 - b0) % QLX_Q
        coeffs[2 * i + 1] = (a1 - b1) % QLX_Q
    return coeffs


def byte_encode_12(poly: List[int]) -> bytes:
    """Packs 256 12-bit coefficients in Z_3329 into 384 bytes."""
    out = bytearray(384)
    for i in range(128):
        c0 = poly[2 * i] % QLX_Q
        c1 = poly[2 * i + 1] % QLX_Q
        out[3 * i] = c0 & 0xFF
        out[3 * i + 1] = ((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4)
        out[3 * i + 2] = (c1 >> 4) & 0xFF
    return bytes(out)


def byte_decode_12(data: bytes) -> List[int]:
    """Unpacks 384 bytes into 256 12-bit coefficients in Z_3329."""
    poly = [0] * 256
    for i in range(128):
        b0, b1, b2 = data[3 * i], data[3 * i + 1], data[3 * i + 2]
        poly[2 * i] = (b0 | ((b1 & 0x0F) << 8)) % QLX_Q
        poly[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) % QLX_Q
    return poly


def compress_poly(poly: List[int], d: int) -> bytes:
    """Compresses 256 coefficients mod 3329 to d bits each and packs into 32*d bytes."""
    mask = (1 << d) - 1
    bits = 0
    bit_len = 0
    out = bytearray()
    for c in poly:
        val = (((c % QLX_Q) << d) + (QLX_Q // 2)) // QLX_Q
        val &= mask
        bits |= val << bit_len
        bit_len += d
        while bit_len >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            bit_len -= 8
    return bytes(out)


def decompress_poly(data: bytes, d: int) -> List[int]:
    """Unpacks 32*d bytes of d-bit integers and decompresses to 256 coefficients mod 3329."""
    mask = (1 << d) - 1
    bits = 0
    bit_len = 0
    idx = 0
    poly: List[int] = []
    for _ in range(256):
        while bit_len < d:
            bits |= data[idx] << bit_len
            idx += 1
            bit_len += 8
        val = bits & mask
        bits >>= d
        bit_len -= d
        coeff = (val * QLX_Q + (1 << (d - 1))) >> d
        poly.append(coeff % QLX_Q)
    return poly


class QLXEngine:
    """
    Multi-tier Quantum Lattice Exchange (Module-LWE) Engine supporting QLX-768, QLX-1024, and QLX-2048.
    """

    @staticmethod
    def _indcpa_enc(ek: bytes, msg32: bytes, coins: bytes, tier: str) -> bytes:
        spec = QLX_TIERS[tier]
        k, du, dv = spec["k"], spec["du"], spec["dv"]
        rho = ek[-32:]
        t_hat = [byte_decode_12(ek[384 * i : 384 * (i + 1)]) for i in range(k)]
        a_hat = [[sample_ntt_3329(rho, i, j) for j in range(k)] for i in range(k)]

        r_vec = [ntt_3329(sample_cbd2_3329(coins, i)) for i in range(k)]
        e1_vec = [sample_cbd2_3329(coins, k + i) for i in range(k)]
        e2_poly = sample_cbd2_3329(coins, 2 * k)

        # u = NTT^-1(A^T * r_vec) + e1
        u_chunks = []
        for i in range(k):
            acc = [0] * 256
            for j in range(k):
                acc = poly_add_3329(acc, ntt_base_mul_3329(a_hat[j][i], r_vec[j]))
            u_i = poly_add_3329(inv_ntt_3329(acc), e1_vec[i])
            u_chunks.append(compress_poly(u_i, du))

        # v = NTT^-1(t^T * r_vec) + e2 + Decompress_1(msg32)
        v_acc = [0] * 256
        for j in range(k):
            v_acc = poly_add_3329(v_acc, ntt_base_mul_3329(t_hat[j], r_vec[j]))
        v_poly = poly_add_3329(inv_ntt_3329(v_acc), e2_poly)
        m_poly = decompress_poly(msg32, 1)
        v_poly = poly_add_3329(v_poly, m_poly)
        v_bytes = compress_poly(v_poly, dv)
        return b"".join(u_chunks) + v_bytes

    @staticmethod
    def keygen(tier: str = "QLX-1024", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QLX key generation requires a 64-byte QPKD-Argon passphrase policy witness.")
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        k = spec["k"]

        seed_d = os.urandom(32)
        seed_z = os.urandom(32)
        g_out = qsponge_512(b"CALYX-QLX-KEYGEN|" + tier.encode("ascii") + seed_d + policy_witness)
        rho, sigma = g_out[:32], g_out[32:]

        a_hat = [[sample_ntt_3329(rho, i, j) for j in range(k)] for i in range(k)]
        s_hat = [ntt_3329(sample_cbd2_3329(sigma, i)) for i in range(k)]
        e_hat = [ntt_3329(sample_cbd2_3329(sigma, k + i)) for i in range(k)]

        # t_hat = A_hat o s_hat + e_hat (mod 3329)
        t_hat = []
        for i in range(k):
            acc = [0] * 256
            for j in range(k):
                acc = poly_add_3329(acc, ntt_base_mul_3329(a_hat[i][j], s_hat[j]))
            t_hat.append(poly_add_3329(acc, e_hat[i]))

        ek = b"".join(byte_encode_12(p) for p in t_hat) + rho
        s_bytes = b"".join(byte_encode_12(p) for p in s_hat)
        h_ek = qsponge_var(b"CALYX-QLX-H-EK|" + ek, 32)
        dk = s_bytes + ek + h_ek + seed_z
        return ek, dk

    @staticmethod
    def encaps(ek: bytes, tier: str = "QLX-1024") -> Tuple[bytes, bytes]:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        if len(ek) != spec["pk_bytes"]:
            raise ValueError(f"Invalid {tier} public key length: {len(ek)}")

        msg32 = os.urandom(32)
        h_ek = qsponge_var(b"CALYX-QLX-H-EK|" + ek, 32)
        kr = qsponge_512(b"CALYX-QLX-FO-G|" + msg32 + h_ek)
        k_shared, r_coins = kr[:32], kr[32:]
        ct = QLXEngine._indcpa_enc(ek, msg32, r_coins, tier)
        return ct, k_shared

    @staticmethod
    def decaps(dk: bytes, ct: bytes, tier: str = "QLX-1024") -> bytes:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        k, du, dv = spec["k"], spec["du"], spec["dv"]
        pk_len, sk_len, ct_len = spec["pk_bytes"], spec["sk_bytes"], spec["ct_bytes"]
        if len(dk) != sk_len or len(ct) != ct_len:
            raise ValueError(f"Invalid {tier} secret key or ciphertext length.")

        s_bytes_len = 384 * k
        s_hat = [byte_decode_12(dk[384 * i : 384 * (i + 1)]) for i in range(k)]
        ek = dk[s_bytes_len : s_bytes_len + pk_len]
        h_ek = dk[s_bytes_len + pk_len : s_bytes_len + pk_len + 32]
        seed_z = dk[s_bytes_len + pk_len + 32 :]

        u_step = 32 * du
        u_vec = [decompress_poly(ct[i * u_step : (i + 1) * u_step], du) for i in range(k)]
        v_poly = decompress_poly(ct[k * u_step :], dv)

        # w = v - NTT^-1(s_hat^T * NTT(u)) (mod 3329)
        su_hat = [0] * 256
        for j in range(k):
            su_hat = poly_add_3329(su_hat, ntt_base_mul_3329(s_hat[j], ntt_3329(u_vec[j])))
        w_poly = poly_sub_3329(v_poly, inv_ntt_3329(su_hat))
        m_prime = compress_poly(w_poly, 1)

        # Fujisaki-Okamoto CCA2 re-encryption check
        kr_prime = qsponge_512(b"CALYX-QLX-FO-G|" + m_prime + h_ek)
        k_candidate, r_prime = kr_prime[:32], kr_prime[32:]
        ct_prime = QLXEngine._indcpa_enc(ek, m_prime, r_prime, tier)

        if hmac.compare_digest(ct, ct_prime):
            return k_candidate
        return qsponge_var(b"CALYX-QLX-FO-REJECT|" + seed_z + ct, 32)


# ============================================================================
# 3. QVS LATTICE FIAT-SHAMIR WITH ABORTS OVER R_8380417 = Z_8380417[X]/(X^256+1)
# ============================================================================
QVS_Q = 8380417
QVS_ZETA = 1753
QVS_GAMMA1 = 1 << 19          # 524288
QVS_GAMMA2 = (QVS_Q - 1) // 32  # 261888
QVS_ALPHA = 2 * QVS_GAMMA2    # 523776


def _bitrev8(x: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


_ZETAS_QVS = [pow(QVS_ZETA, _bitrev8(i), QVS_Q) for i in range(256)]
_INV_256_QVS = pow(256, QVS_Q - 2, QVS_Q)

QVS_TIERS = {
    "QVS-65": {
        "k": 3,
        "l": 2,
        "eta": 2,
        "tau": 39,
        "beta": 78,
        "pk_bytes": 32 + 3 * 256 * 3,                  # 2336
        "sk_bytes": 128 + (2 + 3) * 256 + 3 * 256 * 3, # 3712
        "sig_bytes": 64 + 2 * 256 * 3,                 # 1600
    },
    "QVS-87": {
        "k": 4,
        "l": 3,
        "eta": 2,
        "tau": 49,
        "beta": 98,
        "pk_bytes": 32 + 4 * 256 * 3,                  # 3104
        "sk_bytes": 128 + (3 + 4) * 256 + 4 * 256 * 3, # 4992
        "sig_bytes": 64 + 3 * 256 * 3,                 # 2368
    },
    "QVS-128": {
        "k": 6,
        "l": 5,
        "eta": 2,
        "tau": 60,
        "beta": 120,
        "pk_bytes": 32 + 6 * 256 * 3,                  # 4640
        "sk_bytes": 128 + (5 + 6) * 256 + 6 * 256 * 3, # 7552
        "sig_bytes": 64 + 5 * 256 * 3,                 # 3904
    },
}


def ntt_qvs(poly: List[int]) -> List[int]:
    """Forward 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    p = list(poly)
    k = 0
    length = 128
    while length >= 1:
        for start in range(0, 256, 2 * length):
            k += 1
            zeta = _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = (zeta * p[j + length]) % QVS_Q
                p[j + length] = (p[j] - t) % QVS_Q
                p[j] = (p[j] + t) % QVS_Q
        length >>= 1
    return p


def inv_ntt_qvs(poly_hat: List[int]) -> List[int]:
    """Inverse 8-layer complete NTT in Z_8380417[X]/(X^256 + 1)."""
    p = list(poly_hat)
    k = 256
    length = 1
    while length < 256:
        for start in range(0, 256, 2 * length):
            k -= 1
            zeta = QVS_Q - _ZETAS_QVS[k]
            for j in range(start, start + length):
                t = p[j]
                p[j] = (t + p[j + length]) % QVS_Q
                p[j + length] = (zeta * (t - p[j + length])) % QVS_Q
        length <<= 1
    return [(x * _INV_256_QVS) % QVS_Q for x in p]


def center_qvs(x: int) -> int:
    x %= QVS_Q
    return x - QVS_Q if x > QVS_Q // 2 else x


def decompose_qvs(r: int) -> Tuple[int, int]:
    """Decomposes r mod Q into (r1, r0) such that r == r1 * (2*gamma2) + r0 (mod Q)."""
    r %= QVS_Q
    r0 = r % QVS_ALPHA
    if r0 > QVS_GAMMA2:
        r0 -= QVS_ALPHA
    if r - r0 == QVS_Q - 1:
        return 0, r0 - 1
    return (r - r0) // QVS_ALPHA, r0


def sample_ntt_qvs(rho: bytes, row: int, col: int) -> List[int]:
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
    """Samples a short secret polynomial with coefficients in [-2, 2] mod Q."""
    buf = qsponge_var(b"CALYX-QVS-ETA2|" + seed + bytes([nonce]), 128)
    coeffs = [0] * 256
    for i in range(128):
        b = buf[i]
        a0 = (b & 1) + ((b >> 1) & 1)
        b0 = ((b >> 2) & 1) + ((b >> 3) & 1)
        a1 = ((b >> 4) & 1) + ((b >> 5) & 1)
        b1 = ((b >> 6) & 1) + ((b >> 7) & 1)
        coeffs[2 * i] = (a0 - b0) % QVS_Q
        coeffs[2 * i + 1] = (a1 - b1) % QVS_Q
    return coeffs


def sample_mask_y_qvs(seed: bytes, nonce: int) -> List[int]:
    """Samples masking polynomial y with coefficients in [-gamma_1 + 1, gamma_1] mod Q."""
    buf = qsponge_var(b"CALYX-QVS-MASK-Y|" + seed + nonce.to_bytes(2, "little"), 768)
    coeffs = [0] * 256
    for i in range(256):
        raw = (buf[3 * i] | (buf[3 * i + 1] << 8) | (buf[3 * i + 2] << 16)) & 0xFFFFF
        val = QVS_GAMMA1 - raw
        coeffs[i] = val % QVS_Q
    return coeffs


def sample_in_ball_qvs(c_tilde: bytes, tau: int) -> List[int]:
    """Samples sparse challenge polynomial c in R_Q with exactly tau coefficients in {-1, +1}."""
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
        c[j] = (QVS_Q - 1) if (sign_bits & 1) else 1
        sign_bits >>= 1
    return c


def pack_poly24_qvs(poly: List[int]) -> bytes:
    out = bytearray(768)
    for i, c in enumerate(poly):
        v = c % QVS_Q
        out[3 * i] = v & 0xFF
        out[3 * i + 1] = (v >> 8) & 0xFF
        out[3 * i + 2] = (v >> 16) & 0xFF
    return bytes(out)


def unpack_poly24_qvs(data: bytes) -> List[int]:
    return [
        (data[3 * i] | (data[3 * i + 1] << 8) | (data[3 * i + 2] << 16)) % QVS_Q
        for i in range(256)
    ]


class QVSEngine:
    """
    Multi-tier Quantum Vector Signature (Lattice Fiat-Shamir with Aborts) Engine
    supporting QVS-65, QVS-87, and QVS-128 over R_Q = Z_8380417[X]/(X^256 + 1).
    """

    @staticmethod
    def keygen(tier: str = "QVS-87", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QVS key generation requires a 64-byte QPKD-Argon passphrase policy witness.")
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        k, l = spec["k"], spec["l"]

        seed_xi = os.urandom(32)
        expanded = qsponge_var(b"CALYX-QVS-KEYGEN|" + tier.encode("ascii") + seed_xi + policy_witness, 128)
        rho, rho_prime, k_sign = expanded[:32], expanded[32:96], expanded[96:128]

        a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
        s1 = [sample_eta_qvs(rho_prime, j) for j in range(l)]
        s2 = [sample_eta_qvs(rho_prime, l + i) for i in range(k)]
        s1_hat = [ntt_qvs(p) for p in s1]

        # t = NTT^-1(A_hat o s1_hat) + s2 (mod Q)
        t_vec = []
        for i in range(k):
            acc = [0] * 256
            for j in range(l):
                acc = [(acc[m] + a_hat[i][j][m] * s1_hat[j][m]) % QVS_Q for m in range(256)]
            t_i = [(inv_ntt_qvs(acc)[m] + s2[i][m]) % QVS_Q for m in range(256)]
            t_vec.append(t_i)

        t_bytes = b"".join(pack_poly24_qvs(p) for p in t_vec)
        pk = rho + t_bytes
        tr = qsponge_var(b"CALYX-QVS-TR|" + pk, 64)

        s1_bytes = b"".join(bytes((center_qvs(c) + 2) & 0xFF for c in p) for p in s1)
        s2_bytes = b"".join(bytes((center_qvs(c) + 2) & 0xFF for c in p) for p in s2)
        sk = rho + k_sign + tr + s1_bytes + s2_bytes + t_bytes
        return pk, sk

    @staticmethod
    def sign(sk: bytes, pk: bytes, message: bytes, tier: str = "QVS-87") -> bytes:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        k, l, tau, beta = spec["k"], spec["l"], spec["tau"], spec["beta"]
        if len(sk) != spec["sk_bytes"] or len(pk) != spec["pk_bytes"]:
            raise ValueError(f"Invalid {tier} key sizes.")

        rho = sk[:32]
        k_sign = sk[32:64]
        tr = sk[64:128]
        off = 128
        s1 = []
        for _ in range(l):
            chunk = sk[off : off + 256]
            off += 256
            s1.append([((b - 2) % QVS_Q) for b in chunk])
        s2 = []
        for _ in range(k):
            chunk = sk[off : off + 256]
            off += 256
            s2.append([((b - 2) % QVS_Q) for b in chunk])
        t_bytes = sk[off:]

        if not hmac.compare_digest(pk, rho + t_bytes):
            raise ValueError(f"{tier} secret key does not match public key.")

        a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
        s1_hat = [ntt_qvs(p) for p in s1]
        s2_hat = [ntt_qvs(p) for p in s2]

        mu = qsponge_var(b"CALYX-QVS-MU|" + tr + message, 64)
        rho_double_prime = qsponge_var(b"CALYX-QVS-RNDS|" + k_sign + mu, 64)

        nonce = 0
        while True:
            y_vec = [sample_mask_y_qvs(rho_double_prime, nonce + j) for j in range(l)]
            nonce += l
            y_hat = [ntt_qvs(p) for p in y_vec]

            # w = NTT^-1(A_hat o y_hat)
            w_vec = []
            w1_bytes = bytearray()
            for i in range(k):
                acc = [0] * 256
                for j in range(l):
                    acc = [(acc[m] + a_hat[i][j][m] * y_hat[j][m]) % QVS_Q for m in range(256)]
                w_i = inv_ntt_qvs(acc)
                w_vec.append(w_i)
                for coeff in w_i:
                    w1_c, _ = decompose_qvs(coeff)
                    w1_bytes.append(w1_c & 0xFF)

            c_tilde = qsponge_var(b"CALYX-QVS-CHALLENGE|" + mu + bytes(w1_bytes), 64)
            c_poly = sample_in_ball_qvs(c_tilde, tau)
            c_hat = ntt_qvs(c_poly)

            # z = y + c * s1 (mod Q) and check ||z||_inf < gamma1 - beta
            z_vec = []
            reject = False
            for j in range(l):
                cs1 = inv_ntt_qvs([(c_hat[m] * s1_hat[j][m]) % QVS_Q for m in range(256)])
                z_j = [(y_vec[j][m] + cs1[m]) % QVS_Q for m in range(256)]
                for coeff in z_j:
                    if abs(center_qvs(coeff)) >= QVS_GAMMA1 - beta:
                        reject = True
                        break
                if reject:
                    break
                z_vec.append(z_j)
            if reject:
                continue

            # Check ||LowBits(w - c * s2)||_inf < gamma2 - beta AND HighBits(w - c * s2) == w1
            w1_idx = 0
            for i in range(k):
                cs2 = inv_ntt_qvs([(c_hat[m] * s2_hat[i][m]) % QVS_Q for m in range(256)])
                for m in range(256):
                    diff = (w_vec[i][m] - cs2[m]) % QVS_Q
                    r1, r0 = decompose_qvs(diff)
                    if abs(r0) >= QVS_GAMMA2 - beta or r1 != w1_bytes[w1_idx]:
                        reject = True
                        break
                    w1_idx += 1
                if reject:
                    break
            if reject:
                continue

            z_packed = b"".join(pack_poly24_qvs(p) for p in z_vec)
            return c_tilde + z_packed

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes, tier: str = "QVS-87") -> bool:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        k, l, tau, beta = spec["k"], spec["l"], spec["tau"], spec["beta"]
        if len(pk) != spec["pk_bytes"] or len(signature) != spec["sig_bytes"]:
            return False

        rho = pk[:32]
        t_vec = [unpack_poly24_qvs(pk[32 + 768 * i : 32 + 768 * (i + 1)]) for i in range(k)]
        c_tilde = signature[:64]
        z_vec = [unpack_poly24_qvs(signature[64 + 768 * j : 64 + 768 * (j + 1)]) for j in range(l)]

        # 1. Verify norm bound ||z||_inf < gamma1 - beta
        for z_j in z_vec:
            for coeff in z_j:
                if abs(center_qvs(coeff)) >= QVS_GAMMA1 - beta:
                    return False

        # 2. Reconstruct w'_1 = HighBits(A*z - c*t, 2*gamma2)
        a_hat = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
        z_hat = [ntt_qvs(p) for p in z_vec]
        t_hat = [ntt_qvs(p) for p in t_vec]
        c_poly = sample_in_ball_qvs(c_tilde, tau)
        c_hat = ntt_qvs(c_poly)

        w1_prime_bytes = bytearray()
        for i in range(k):
            az_hat = [0] * 256
            for j in range(l):
                az_hat = [(az_hat[m] + a_hat[i][j][m] * z_hat[j][m]) % QVS_Q for m in range(256)]
            ct_hat = [(c_hat[m] * t_hat[i][m]) % QVS_Q for m in range(256)]
            w_prime_i = inv_ntt_qvs([(az_hat[m] - ct_hat[m]) % QVS_Q for m in range(256)])
            for coeff in w_prime_i:
                r1, _ = decompose_qvs(coeff)
                w1_prime_bytes.append(r1 & 0xFF)

        tr = qsponge_var(b"CALYX-QVS-TR|" + pk, 64)
        mu = qsponge_var(b"CALYX-QVS-MU|" + tr + message, 64)
        expected_c_tilde = qsponge_var(b"CALYX-QVS-CHALLENGE|" + mu + bytes(w1_prime_bytes), 64)
        return hmac.compare_digest(c_tilde, expected_c_tilde)
