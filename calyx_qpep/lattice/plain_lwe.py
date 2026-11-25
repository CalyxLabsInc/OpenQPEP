"""
Family 1 of Calyx Sovereign-Pentad (CSP-Omega): Pure Unstructured Plain-LWE (CULC-2048 — Official Release 1.2.6).
Zero cyclotomic polynomial ring, zero NTT, zero Galois symmetry.
Row-streams unstructured matrix A in Z_{65536}^{n x n} from qSponge-XOF (accelerated end-to-end
via C99/AVX2/NEON `plain_lwe_c.c` with bit-exact pure-Python fallback) with Fujisaki-Okamoto
IND-CCA2 re-encryption verification and branchless ct_cmov implicit rejection.
"""
import os
import struct
from typing import List, Tuple

from ..native.loader import (
    native_plain_lwe_decaps,
    native_plain_lwe_encaps,
    native_plain_lwe_expand_row,
    native_plain_lwe_indcpa_enc,
    native_plain_lwe_keygen_from_seeds,
    native_plain_lwe_keygen_row,
    native_plain_lwe_row_accum,
    native_plain_lwe_sample_noise,
)
from ..primitives.consttime import ct_cmov, ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

PLAIN_LWE_Q = 65536  # 2^16
MAX_PLAIN_LWE_N = 8192
MAX_PLAIN_LWE_NBAR = 8


def _validate_plwe_dims(n: int, nbar: int) -> None:
    if (
        not isinstance(n, int)
        or isinstance(n, bool)
        or not isinstance(nbar, int)
        or isinstance(nbar, bool)
        or n < 1
        or n > MAX_PLAIN_LWE_N
        or nbar < 1
        or nbar > MAX_PLAIN_LWE_NBAR
    ):
        raise ValueError(f"Invalid Plain-LWE dimensions (n={n}, nbar={nbar}).")


def _sample_centered_noise(seed: bytes, count: int, domain: bytes) -> List[int]:
    native_out = native_plain_lwe_sample_noise(domain, seed, count)
    if native_out is not None:
        return native_out
    raw = qsponge_var(domain + seed, count)
    out = []
    for b in raw:
        a = ((b >> 0) & 1) + ((b >> 1) & 1)
        c = ((b >> 2) & 1) + ((b >> 3) & 1)
        out.append((a - c) % PLAIN_LWE_Q)
    return out


def _expand_row(seed_a: bytes, row_idx: int, n: int) -> List[int]:
    native_row = native_plain_lwe_expand_row(seed_a, row_idx, n)
    if native_row is not None:
        return native_row
    raw = qsponge_var(b"CALYX-PLAIN-LWE-ROW-v1.0.0|" + seed_a + struct.pack(">I", row_idx), 2 * n)
    return list(struct.unpack(f"<{n}H", raw))


class PlainLWEEngine:
    """Unstructured Plain-LWE KEM (zero ring ideal / zero NTT structure)."""

    @staticmethod
    def keygen(n: int = 64, nbar: int = 8) -> Tuple[bytes, bytes]:
        _validate_plwe_dims(n, nbar)
        seed_a = os.urandom(32)
        with SecretBuffer(os.urandom(32)) as ss_buf, SecretBuffer(os.urandom(32)) as sz_buf:
            native_kp = native_plain_lwe_keygen_from_seeds(n, nbar, seed_a, ss_buf.as_bytes(), sz_buf.as_bytes())
            if native_kp is not None:
                return native_kp

            s_flat = _sample_centered_noise(ss_buf.as_bytes(), n * nbar, b"CALYX-PLWE-S-v1.0.0|")
            e_flat = _sample_centered_noise(ss_buf.as_bytes(), n * nbar, b"CALYX-PLWE-E-v1.0.0|")
            try:
                b_flat = [0] * (n * nbar)
                for i in range(n):
                    row = _expand_row(seed_a, i, n)
                    e_row = e_flat[i * nbar : (i + 1) * nbar]
                    native_row = native_plain_lwe_keygen_row(e_row, row, s_flat, n, nbar)
                    if native_row is not None:
                        b_flat[i * nbar : (i + 1) * nbar] = native_row
                    else:
                        for j in range(nbar):
                            acc = e_flat[i * nbar + j]
                            for k in range(n):
                                acc = (acc + row[k] * s_flat[k * nbar + j]) & 0xFFFF
                            b_flat[i * nbar + j] = acc

                pk = struct.pack("<HH", n, nbar) + seed_a + struct.pack(f"<{n * nbar}H", *b_flat)
                sk = struct.pack("<HH", n, nbar) + sz_buf.as_bytes() + pk + struct.pack(f"<{n * nbar}H", *s_flat)
                return pk, sk
            finally:
                for idx in range(len(s_flat)):
                    s_flat[idx] = 0
                for idx in range(len(e_flat)):
                    e_flat[idx] = 0

    @staticmethod
    def _indcpa_enc(pk: bytes, msg16: bytes, coins: bytes) -> bytes:
        if not isinstance(pk, (bytes, bytearray, memoryview)) or len(pk) < 36:
            raise ValueError("Invalid Plain-LWE public key.")
        if not isinstance(msg16, (bytes, bytearray, memoryview)) or len(msg16) != 16:
            raise ValueError("Plain-LWE IND-CPA message must be exactly 16 bytes.")
        if not isinstance(coins, (bytes, bytearray, memoryview)) or len(coins) != 32:
            raise ValueError("Plain-LWE IND-CPA coins must be exactly 32 bytes.")
        pk_b = bytes(pk)
        n, nbar = struct.unpack("<HH", pk_b[:4])
        _validate_plwe_dims(n, nbar)
        expected_pk = 36 + 2 * n * nbar
        if len(pk_b) != expected_pk:
            raise ValueError(f"Invalid Plain-LWE public key length: expected {expected_pk}, got {len(pk_b)}.")

        native_ct = native_plain_lwe_indcpa_enc(pk_b, bytes(msg16), bytes(coins))
        if native_ct is not None:
            return native_ct

        seed_a = pk_b[4:36]
        b_flat = list(struct.unpack(f"<{n * nbar}H", pk_b[36:]))

        sp = _sample_centered_noise(bytes(coins), nbar * n, b"CALYX-PLWE-SP-v1.0.0|")
        ep = _sample_centered_noise(bytes(coins), nbar * n, b"CALYX-PLWE-EP-v1.0.0|")
        epp = _sample_centered_noise(bytes(coins), nbar * nbar, b"CALYX-PLWE-EPP-v1.0.0|")
        try:
            u_flat = list(ep)
            for k in range(n):
                row = _expand_row(seed_a, k, n)
                for i in range(nbar):
                    s_ik = sp[i * n + k]
                    base = i * n
                    native_u = native_plain_lwe_row_accum(u_flat[base : base + n], row, s_ik)
                    if native_u is not None:
                        u_flat[base : base + n] = native_u
                    else:
                        for j in range(n):
                            u_flat[base + j] = (u_flat[base + j] + s_ik * row[j]) & 0xFFFF

            v_flat = [0] * (nbar * nbar)
            for i in range(nbar):
                for j in range(nbar):
                    acc = epp[i * nbar + j]
                    for k in range(n):
                        acc = (acc + sp[i * n + k] * b_flat[k * nbar + j]) & 0xFFFF
                    bit_pos = (i * nbar + j) * 2
                    byte_val = msg16[bit_pos // 8]
                    two_bits = (byte_val >> (bit_pos % 8)) & 0x03
                    v_flat[i * nbar + j] = (acc + (two_bits << 14)) & 0xFFFF

            return struct.pack(f"<{nbar * n}H", *u_flat) + struct.pack(f"<{nbar * nbar}H", *v_flat)
        finally:
            for vec in (sp, ep, epp):
                for idx in range(len(vec)):
                    vec[idx] = 0

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        if not isinstance(pk, (bytes, bytearray, memoryview)) or len(pk) < 36:
            raise ValueError("Invalid Plain-LWE public key.")
        pk_b = bytes(pk)
        n, nbar = struct.unpack("<HH", pk_b[:4])
        _validate_plwe_dims(n, nbar)
        if len(pk_b) != 36 + 2 * n * nbar:
            raise ValueError("Invalid Plain-LWE public key length.")

        with SecretBuffer(os.urandom(16)) as msg_buf:
            native_res = native_plain_lwe_encaps(pk_b, msg_buf.as_bytes())
            if native_res is not None:
                return native_res

            h_pk = qsponge_var(b"CALYX-PLWE-HPK-v1.0.0|" + pk_b, 32)
            with SecretBuffer(qsponge_512(b"CALYX-PLWE-FO-G-v1.0.0|" + msg_buf.as_bytes() + h_pk)) as kr_buf:
                with kr_buf.view() as mv:
                    ss, coins = bytes(mv[:32]), bytes(mv[32:])
                ct = PlainLWEEngine._indcpa_enc(pk_b, msg_buf.as_bytes(), coins)
                return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        if not isinstance(sk, (bytes, bytearray, memoryview)) or len(sk) < 72:
            raise ValueError("Invalid Plain-LWE secret key.")
        if not isinstance(ct, (bytes, bytearray, memoryview)):
            raise ValueError("Invalid Plain-LWE ciphertext.")
        ct_b = bytes(ct)

        with SecretBuffer(sk) as sk_buf:
            raw = sk_buf.as_bytes()
            n, nbar = struct.unpack("<HH", raw[:4])
            _validate_plwe_dims(n, nbar)
            pk_len = 4 + 32 + 2 * n * nbar
            expected_sk = 36 + pk_len + 2 * n * nbar
            expected_ct = 2 * nbar * n + 2 * nbar * nbar
            if len(raw) != expected_sk or len(ct_b) != expected_ct:
                raise ValueError("Invalid Plain-LWE secret key or ciphertext length.")

            native_ss = native_plain_lwe_decaps(raw, ct_b)
            if native_ss is not None:
                return native_ss

            seed_z = raw[4:36]
            pk = raw[36 : 36 + pk_len]
            s_flat = list(struct.unpack(f"<{n * nbar}H", raw[36 + pk_len :]))

        try:
            u_len = 2 * nbar * n
            u_flat = list(struct.unpack(f"<{nbar * n}H", ct_b[:u_len]))
            v_flat = list(struct.unpack(f"<{nbar * nbar}H", ct_b[u_len:]))

            msg_bits = bytearray(16)
            for i in range(nbar):
                for j in range(nbar):
                    us = 0
                    for k in range(n):
                        us = (us + u_flat[i * n + k] * s_flat[k * nbar + j]) & 0xFFFF
                    w = (v_flat[i * nbar + j] - us) & 0xFFFF
                    two_bits = ((w + (1 << 13)) >> 14) & 0x03
                    bit_pos = (i * nbar + j) * 2
                    msg_bits[bit_pos // 8] |= (two_bits << (bit_pos % 8))

            with SecretBuffer(bytes(msg_bits)) as m_prime_buf:
                h_pk = qsponge_var(b"CALYX-PLWE-HPK-v1.0.0|" + pk, 32)
                with SecretBuffer(qsponge_512(b"CALYX-PLWE-FO-G-v1.0.0|" + m_prime_buf.as_bytes() + h_pk)) as kr_buf:
                    with kr_buf.view() as mv:
                        k_cand, r_prime = bytes(mv[:32]), bytes(mv[32:])
                    ct_prime = PlainLWEEngine._indcpa_enc(pk, m_prime_buf.as_bytes(), r_prime)
                    with SecretBuffer(qsponge_var(b"CALYX-PLWE-FO-REJECT-v1.0.0|" + seed_z + ct_b, 32)) as rej_buf:
                        return ct_cmov(ct_eq(ct_b, ct_prime), k_cand, rej_buf.as_bytes())
        finally:
            for idx in range(len(s_flat)):
                s_flat[idx] = 0
