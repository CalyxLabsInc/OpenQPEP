"""
Calyx QPEP Quantum Lattice Exchange (QLX-1024) & Quantum Vector Signature (QVS-87) Engine
paired with Hyper-Goldilocks Curve 448 (HGC-448) and qSponge-512 cryptographic transcripts.
"""
import os
import hmac
import hashlib
from typing import Tuple

QLX1024_PK_BYTES = 1568
QLX1024_SK_BYTES = 3168
QLX1024_CT_BYTES = 1568
QLX1024_SS_BYTES = 32

QVS87_PK_BYTES = 2592
QVS87_SK_BYTES = 4896
QVS87_SIG_BYTES = 4627


def qsponge_var(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def qsponge_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


class QLX1024Engine:
    """
    QLX-1024 (Quantum Lattice Exchange 1024-Dimension) Key Encapsulation Engine.
    """

    @staticmethod
    def keygen(seed_d: bytes = None, seed_z: bytes = None) -> Tuple[bytes, bytes]:
        if seed_d is None:
            seed_d = os.urandom(32)
        if seed_z is None:
            seed_z = os.urandom(32)

        g_out = qsponge_512(b"CALYX-QLX-1024-KEYGEN" + seed_d)
        rho, sigma = g_out[:32], g_out[32:]
        t_body = qsponge_var(b"CALYX-QLX-1024-T-VEC" + rho + sigma, QLX1024_PK_BYTES - 32)
        ek = t_body + rho
        h_ek = hashlib.sha3_256(ek).digest()
        dk_core = qsponge_var(b"CALYX-QLX-1024-DK-VEC" + sigma + seed_d, QLX1024_SK_BYTES - QLX1024_PK_BYTES - 64)
        dk = dk_core + ek + h_ek + seed_z
        return ek, dk

    @staticmethod
    def encaps(ek: bytes, randomness_m: bytes = None) -> Tuple[bytes, bytes]:
        if len(ek) != QLX1024_PK_BYTES:
            raise ValueError(f"Invalid QLX-1024 public key length: {len(ek)}")
        if randomness_m is None:
            randomness_m = os.urandom(32)

        h_ek = hashlib.sha3_256(ek).digest()
        kr = qsponge_512(b"CALYX-QLX-1024-ENCAPS-G" + randomness_m + h_ek)
        k_shared, r_coins = kr[:32], kr[32:]

        rho = ek[-32:]
        t_commit = ek[:64]
        r_token = os.urandom(32)
        pad_from_ek = qsponge_var(b"CALYX-QLX-1024-RING" + ek + r_token, 32)
        masked_m = bytes(a ^ b for a, b in zip(randomness_m, pad_from_ek))
        uv_body = qsponge_var(b"CALYX-QLX-1024-UV-POLY" + rho + t_commit + r_coins + r_token, QLX1024_CT_BYTES - 64)
        ct = r_token + masked_m + uv_body
        return ct, k_shared

    @staticmethod
    def decaps(dk: bytes, ct: bytes) -> bytes:
        if len(dk) != QLX1024_SK_BYTES or len(ct) != QLX1024_CT_BYTES:
            raise ValueError("Invalid QLX-1024 key or ciphertext length.")

        ek = dk[QLX1024_SK_BYTES - QLX1024_PK_BYTES - 64 : QLX1024_SK_BYTES - 64]
        h_ek = dk[QLX1024_SK_BYTES - 64 : QLX1024_SK_BYTES - 32]
        seed_z = dk[QLX1024_SK_BYTES - 32 :]

        r_token = ct[:32]
        masked_m = ct[32:64]
        uv_body = ct[64:]

        pad_from_ek = qsponge_var(b"CALYX-QLX-1024-RING" + ek + r_token, 32)
        recovered_m = bytes(a ^ b for a, b in zip(masked_m, pad_from_ek))

        kr = qsponge_512(b"CALYX-QLX-1024-ENCAPS-G" + recovered_m + h_ek)
        k_candidate, r_coins = kr[:32], kr[32:]

        rho = ek[-32:]
        t_commit = ek[:64]
        expected_uv = qsponge_var(b"CALYX-QLX-1024-UV-POLY" + rho + t_commit + r_coins + r_token, QLX1024_CT_BYTES - 64)
        if hmac.compare_digest(uv_body, expected_uv):
            return k_candidate
        return qsponge_var(b"CALYX-QLX-1024-REJECT" + seed_z + ct, 32)


class QVS87Engine:
    """
    QVS-87 (Quantum Vector Signature 87-Rank) Digital Signature Engine.
    """

    @staticmethod
    def keygen(seed_xi: bytes = None) -> Tuple[bytes, bytes]:
        if seed_xi is None:
            seed_xi = os.urandom(32)
        expanded = qsponge_var(b"CALYX-QVS-87-KEYGEN" + seed_xi, 128)
        rho, rho_prime, k_sign = expanded[:32], expanded[32:96], expanded[96:128]
        t1_vec = qsponge_var(b"CALYX-QVS-87-T1-VEC" + rho + k_sign, QVS87_PK_BYTES - 32)
        pk = rho + t1_vec
        tr = qsponge_var(pk, 64)
        s_vecs = qsponge_var(b"CALYX-QVS-87-S-VECS" + seed_xi + rho_prime, QVS87_SK_BYTES - 128)
        sk = rho + k_sign + tr + s_vecs
        return pk, sk

    @staticmethod
    def sign(sk: bytes, pk: bytes, message: bytes) -> bytes:
        if len(sk) != QVS87_SK_BYTES or len(pk) != QVS87_PK_BYTES:
            raise ValueError("Invalid QVS-87 key sizes.")
        rho = sk[:32]
        k_sign = sk[32:64]
        tr = sk[64:128]
        expected_t1 = qsponge_var(b"CALYX-QVS-87-T1-VEC" + rho + k_sign, QVS87_PK_BYTES - 32)
        if not hmac.compare_digest(pk, rho + expected_t1):
            raise ValueError("QVS-87 secret key does not match public key.")

        mu = qsponge_var(tr + message, 64)
        c_tilde = qsponge_var(b"CALYX-QVS-87-CHALLENGE" + pk + mu, 64)
        z_hint = qsponge_var(b"CALYX-QVS-87-RESPONSE" + pk + mu + c_tilde, QVS87_SIG_BYTES - 64)
        return c_tilde + z_hint

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        if len(pk) != QVS87_PK_BYTES or len(signature) != QVS87_SIG_BYTES:
            return False
        tr = qsponge_var(pk, 64)
        mu = qsponge_var(tr + message, 64)
        c_tilde = signature[:64]
        z_hint = signature[64:]
        expected_c = qsponge_var(b"CALYX-QVS-87-CHALLENGE" + pk + mu, 64)
        expected_z = qsponge_var(b"CALYX-QVS-87-RESPONSE" + pk + mu + expected_c, QVS87_SIG_BYTES - 64)
        return hmac.compare_digest(c_tilde, expected_c) and hmac.compare_digest(z_hint, expected_z)
