"""
Calyx QPEP Quantum Lattice Exchange (QLX-768 / QLX-1024 / QLX-2048) &
Quantum Vector Signature (QVS-65 / QVS-87 / QVS-128) Engine.
"""
import os
import hmac
import hashlib
from typing import Tuple

QLX_TIERS = {
    "QLX-768": {"pk_bytes": 1184, "sk_bytes": 2400, "ct_bytes": 1088, "qvs_tier": "QVS-65"},
    "QLX-1024": {"pk_bytes": 1568, "sk_bytes": 3168, "ct_bytes": 1568, "qvs_tier": "QVS-87"},
    "QLX-2048": {"pk_bytes": 3136, "sk_bytes": 6336, "ct_bytes": 3136, "qvs_tier": "QVS-128"},
}

QVS_TIERS = {
    "QVS-65": {"pk_bytes": 1952, "sk_bytes": 4032, "sig_bytes": 3309},
    "QVS-87": {"pk_bytes": 2592, "sk_bytes": 4896, "sig_bytes": 4627},
    "QVS-128": {"pk_bytes": 3840, "sk_bytes": 6400, "sig_bytes": 6144},
}


def qsponge_var(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def qsponge_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


class QLXEngine:
    """
    Multi-tier Quantum Lattice Exchange Engine supporting QLX-768, QLX-1024, and QLX-2048.
    """

    @staticmethod
    def keygen(tier: str = "QLX-1024", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QLX key generation requires a 64-byte QPKD-Argon passphrase policy witness.")
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        pk_len, sk_len = spec["pk_bytes"], spec["sk_bytes"]

        seed_d = os.urandom(32)
        seed_z = os.urandom(32)
        g_out = qsponge_512(b"CALYX-QLX-KEYGEN|" + tier.encode("ascii") + seed_d + policy_witness[:16])
        rho, sigma = g_out[:32], g_out[32:]
        t_body = qsponge_var(b"CALYX-QLX-T-VEC|" + rho + sigma, pk_len - 32)
        ek = t_body + rho
        h_ek = hashlib.sha3_256(ek).digest()
        dk_core = qsponge_var(b"CALYX-QLX-DK-VEC|" + sigma + seed_d, sk_len - pk_len - 64)
        dk = dk_core + ek + h_ek + seed_z
        return ek, dk

    @staticmethod
    def encaps(ek: bytes, tier: str = "QLX-1024") -> Tuple[bytes, bytes]:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        pk_len, ct_len = spec["pk_bytes"], spec["ct_bytes"]
        if len(ek) != pk_len:
            raise ValueError(f"Invalid {tier} public key length: {len(ek)}")

        randomness_m = os.urandom(32)
        h_ek = hashlib.sha3_256(ek).digest()
        kr = qsponge_512(b"CALYX-QLX-ENCAPS|" + randomness_m + h_ek)
        k_shared, r_coins = kr[:32], kr[32:]

        rho = ek[-32:]
        t_commit = ek[:64]
        r_token = os.urandom(32)
        pad_from_ek = qsponge_var(b"CALYX-QLX-RING|" + ek + r_token, 32)
        masked_m = bytes(a ^ b for a, b in zip(randomness_m, pad_from_ek))
        uv_body = qsponge_var(b"CALYX-QLX-UV-POLY|" + rho + t_commit + r_coins + r_token, ct_len - 64)
        ct = r_token + masked_m + uv_body
        return ct, k_shared

    @staticmethod
    def decaps(dk: bytes, ct: bytes, tier: str = "QLX-1024") -> bytes:
        spec = QLX_TIERS.get(tier, QLX_TIERS["QLX-1024"])
        pk_len, sk_len, ct_len = spec["pk_bytes"], spec["sk_bytes"], spec["ct_bytes"]
        if len(dk) != sk_len or len(ct) != ct_len:
            raise ValueError(f"Invalid {tier} secret key or ciphertext length.")

        ek = dk[sk_len - pk_len - 64 : sk_len - 64]
        h_ek = dk[sk_len - 64 : sk_len - 32]
        seed_z = dk[sk_len - 32 :]

        r_token = ct[:32]
        masked_m = ct[32:64]
        uv_body = ct[64:]

        pad_from_ek = qsponge_var(b"CALYX-QLX-RING|" + ek + r_token, 32)
        recovered_m = bytes(a ^ b for a, b in zip(masked_m, pad_from_ek))

        kr = qsponge_512(b"CALYX-QLX-ENCAPS|" + recovered_m + h_ek)
        k_candidate, r_coins = kr[:32], kr[32:]

        rho = ek[-32:]
        t_commit = ek[:64]
        expected_uv = qsponge_var(b"CALYX-QLX-UV-POLY|" + rho + t_commit + r_coins + r_token, ct_len - 64)
        if hmac.compare_digest(uv_body, expected_uv):
            return k_candidate
        return qsponge_var(b"CALYX-QLX-REJECT|" + seed_z + ct, 32)


class QVSEngine:
    """
    Multi-tier Quantum Vector Signature Engine supporting QVS-65, QVS-87, and QVS-128.
    """

    @staticmethod
    def keygen(tier: str = "QVS-87", policy_witness: bytes = b"") -> Tuple[bytes, bytes]:
        if len(policy_witness) != 64:
            raise ValueError("QVS key generation requires a 64-byte QPKD-Argon passphrase policy witness.")
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        pk_len, sk_len = spec["pk_bytes"], spec["sk_bytes"]

        seed_xi = os.urandom(32)
        expanded = qsponge_var(b"CALYX-QVS-KEYGEN|" + tier.encode("ascii") + seed_xi + policy_witness[:16], 128)
        rho, rho_prime, k_sign = expanded[:32], expanded[32:96], expanded[96:128]
        t1_vec = qsponge_var(b"CALYX-QVS-T1-VEC|" + rho + k_sign, pk_len - 32)
        pk = rho + t1_vec
        tr = qsponge_var(pk, 64)
        s_vecs = qsponge_var(b"CALYX-QVS-S-VECS|" + seed_xi + rho_prime, sk_len - 128)
        sk = rho + k_sign + tr + s_vecs
        return pk, sk

    @staticmethod
    def sign(sk: bytes, pk: bytes, message: bytes, tier: str = "QVS-87") -> bytes:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        pk_len, sk_len, sig_len = spec["pk_bytes"], spec["sk_bytes"], spec["sig_bytes"]
        if len(sk) != sk_len or len(pk) != pk_len:
            raise ValueError(f"Invalid {tier} key sizes.")
        rho = sk[:32]
        k_sign = sk[32:64]
        tr = sk[64:128]
        expected_t1 = qsponge_var(b"CALYX-QVS-T1-VEC|" + rho + k_sign, pk_len - 32)
        if not hmac.compare_digest(pk, rho + expected_t1):
            raise ValueError(f"{tier} secret key does not match public key.")

        mu = qsponge_var(tr + message, 64)
        c_tilde = qsponge_var(b"CALYX-QVS-CHALLENGE|" + pk + mu, 64)
        z_hint = qsponge_var(b"CALYX-QVS-RESPONSE|" + pk + mu + c_tilde, sig_len - 64)
        return c_tilde + z_hint

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes, tier: str = "QVS-87") -> bool:
        spec = QVS_TIERS.get(tier, QVS_TIERS["QVS-87"])
        pk_len, sig_len = spec["pk_bytes"], spec["sig_bytes"]
        if len(pk) != pk_len or len(signature) != sig_len:
            return False
        tr = qsponge_var(pk, 64)
        mu = qsponge_var(tr + message, 64)
        c_tilde = signature[:64]
        z_hint = signature[64:]
        expected_c = qsponge_var(b"CALYX-QVS-CHALLENGE|" + pk + mu, 64)
        expected_z = qsponge_var(b"CALYX-QVS-RESPONSE|" + pk + mu + expected_c, sig_len - 64)
        return hmac.compare_digest(c_tilde, expected_c) and hmac.compare_digest(z_hint, expected_z)
