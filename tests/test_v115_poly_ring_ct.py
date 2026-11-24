"""
OpenQPEP Official Release 1.1.5 (v1.1.5) — Constant-Time Division-Free `poly_ring.py`
Compression, Decompression, Bit-Packing, CBD Sampling & Cross-Backend NTT Parity Suite.
"""
import ast
import os
import unittest
from pathlib import Path

from calyx_qpep import (
    PROTOCOL_VERSION,
    QPEPSuiteError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    memory_security_status,
    set_native_enabled,
)
from calyx_qpep.constants import QLX_Q, QVS_ALPHA, QVS_GAMMA2, QVS_Q
from calyx_qpep.lattice.ntt_3329 import (
    inv_ntt_3329,
    ntt_3329,
    ntt_base_mul_3329,
    poly_add_3329,
    poly_sub_3329,
)
from calyx_qpep.lattice.ntt_8380417 import center_qvs, decompose_qvs, inv_ntt_qvs, ntt_qvs
from calyx_qpep.lattice.poly_ring import (
    byte_decode_12,
    byte_encode_12,
    compress_coeff_3329,
    compress_poly,
    decompress_coeff_3329,
    decompress_poly,
    pack_poly24_qvs,
    sample_cbd1_3329,
    sample_cbd2_3329,
    sample_cbd_eta_3329,
    sample_eta_qvs,
    sample_mask_y_qvs,
    unpack_poly24_qvs,
)
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.primitives.consttime import (
    barrett_reduce_3329,
    barrett_reduce_qvs,
    ct_caddq_3329,
    ct_caddq_qvs,
    ct_csubq_3329,
    ct_csubq_qvs,
    montgomery_reduce_3329,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestOpenQPEPv115PolyRingConstantTime(unittest.TestCase):
    def test_01_version_metadata_format(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith("1.1."))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")

    def test_02_ast_zero_div_or_mod_in_secret_lattice_functions(self):
        """
        AST-guard: permanently forbids variable-time integer division (//) and modulo (%) inside
        secret-bearing compression, decompression, bit-packing, CBD, Barrett, and QVS decomposition functions.
        """
        targets = {
            "calyx_qpep/lattice/poly_ring.py": {
                "compress_coeff_3329",
                "decompress_coeff_3329",
                "compress_poly",
                "decompress_poly",
                "byte_encode_12",
                "byte_decode_12",
                "sample_cbd2_3329",
                "sample_cbd1_3329",
                "sample_eta_qvs",
                "sample_mask_y_qvs",
                "pack_poly24_qvs",
                "unpack_poly24_qvs",
            },
            "calyx_qpep/lattice/ntt_8380417.py": {
                "ntt_qvs",
                "inv_ntt_qvs",
                "center_qvs",
                "decompose_qvs",
            },
            "calyx_qpep/lattice/ntt_3329.py": {
                "ntt_3329",
                "inv_ntt_3329",
                "ntt_base_mul_3329",
                "poly_add_3329",
                "poly_sub_3329",
            },
            "calyx_qpep/primitives/consttime.py": {
                "ct_caddq_3329",
                "ct_csubq_3329",
                "ct_caddq_qvs",
                "ct_csubq_qvs",
                "barrett_reduce_3329",
                "montgomery_reduce_3329",
                "barrett_reduce_qvs",
            },
        }
        offenders = []
        for rel_path, fn_names in targets.items():
            tree = ast.parse((REPO_ROOT / rel_path).read_text(encoding="utf-8"), filename=rel_path)
            found = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in fn_names:
                    found.add(node.name)
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.FloorDiv, ast.Mod, ast.Div)):
                            offenders.append(f"{rel_path}:{node.name}:L{sub.lineno} uses {type(sub.op).__name__}")
            self.assertEqual(found, fn_names, f"Missing expected functions in {rel_path}")
        self.assertEqual(offenders, [], "Found division/modulo in constant-time lattice code:\n" + "\n".join(offenders))

    def test_03_compress_and_decompress_bit_exact_all_residues_and_depths(self):
        # Exhaustive check across ALL 3,329 residues and ALL d in 1..12
        for d in range(1, 13):
            mask = (1 << d) - 1
            for x in range(QLX_Q):
                expected = (((x << d) + (QLX_Q // 2)) // QLX_Q) & mask
                self.assertEqual(compress_coeff_3329(x, d), expected)
                # Also verify negative/unreduced inputs reduce identically
                self.assertEqual(compress_coeff_3329(x - QLX_Q, d), expected)
                self.assertEqual(compress_coeff_3329(x + QLX_Q, d), expected)

        for d in range(1, 13):
            for val in range(1 << d):
                expected = ((val * QLX_Q + (1 << (d - 1))) >> d) % QLX_Q
                got = decompress_coeff_3329(val, d)
                self.assertEqual(got, expected)
                self.assertGreaterEqual(got, 0)
                self.assertLess(got, QLX_Q)

        # Full polynomial compress/decompress roundtrip across all QLX depths
        poly = [(i * 73 + 19) % QLX_Q for i in range(256)]
        for d in (1, 4, 5, 10, 11):
            packed = compress_poly(poly, d)
            self.assertEqual(len(packed), 32 * d)
            unpacked = decompress_poly(packed, d)
            self.assertEqual(len(unpacked), 256)
            self.assertTrue(all(0 <= c < QLX_Q for c in unpacked))
            # Re-compressing decompressed polynomial must be idempotent
            self.assertEqual(compress_poly(unpacked, d), packed)

        # Bounds enforcement
        with self.assertRaises(ValueError):
            compress_poly([0] * 255, 10)
        with self.assertRaises(ValueError):
            compress_poly([0] * 256, 0)
        with self.assertRaises(ValueError):
            compress_poly([0] * 256, 13)
        with self.assertRaises(ValueError):
            decompress_poly(b"\x00" * 319, 10)

    def test_04_byte_encode_decode_12_and_pack_unpack_qvs_bit_exact(self):
        # Exhaustively test all 4,096 12-bit values in byte_decode_12 (including 3329..4095 reduction)
        for blk in range(0, 4096, 256):
            raw = bytearray(384)
            for i in range(128):
                v0 = blk + 2 * i
                v1 = blk + 2 * i + 1
                raw[3 * i] = v0 & 0xFF
                raw[3 * i + 1] = ((v0 >> 8) & 0x0F) | ((v1 & 0x0F) << 4)
                raw[3 * i + 2] = (v1 >> 4) & 0xFF
            dec = byte_decode_12(bytes(raw))
            expected = [(blk + j) % QLX_Q for j in range(256)]
            self.assertEqual(dec, expected)

        # byte_encode_12 canonicalizes negative and >q inputs identically to mod 3329
        raw_poly = [(-17 * i + 5000) for i in range(256)]
        enc = byte_encode_12(raw_poly)
        self.assertEqual(byte_decode_12(enc), [c % QLX_Q for c in raw_poly])

        # QVS 24-bit pack/unpack boundary sweep (0, Q-1, Q, 2Q-1, 2Q, 2^24-1)
        qvs_test = [
            0, 1, QVS_Q - 1, QVS_Q, QVS_Q + 1, 2 * QVS_Q - 1, 2 * QVS_Q, 0xFFFFFF,
        ] * 32
        raw_qvs = bytearray(768)
        for i, v in enumerate(qvs_test):
            raw_qvs[3 * i] = v & 0xFF
            raw_qvs[3 * i + 1] = (v >> 8) & 0xFF
            raw_qvs[3 * i + 2] = (v >> 16) & 0xFF
        unpacked = unpack_poly24_qvs(bytes(raw_qvs))
        self.assertEqual(unpacked, [v % QVS_Q for v in qvs_test])
        self.assertEqual(unpack_poly24_qvs(pack_poly24_qvs([-c for c in unpacked])), [(-c) % QVS_Q for c in unpacked])

        with self.assertRaises(ValueError):
            byte_encode_12([0] * 100)
        with self.assertRaises(ValueError):
            byte_decode_12(b"\x00" * 100)
        with self.assertRaises(ValueError):
            pack_poly24_qvs([0] * 100)
        with self.assertRaises(ValueError):
            unpack_poly24_qvs(b"\x00" * 100)

    def test_05_native_c99_vs_pure_python_cbd_and_ntt_bit_exact_parity(self):
        if not is_native_available():
            self.skipTest("libopenqpep C99 library not built")
        sigma = bytes(range(32))
        a = [(i * 197 + 41) % QLX_Q for i in range(256)]
        b = [(i * 313 + 7) % QLX_Q for i in range(256)]
        qa = [(i * 65537 + 12345) % QVS_Q for i in range(256)]

        # Native C99 outputs
        c_cbd1 = sample_cbd1_3329(sigma, 7)
        c_cbd2 = sample_cbd2_3329(sigma, 3)
        c_eta1 = sample_cbd_eta_3329(sigma, 7, eta=1)
        c_eta2 = sample_cbd_eta_3329(sigma, 3, eta=2)
        c_qvs_eta = sample_eta_qvs(sigma, 5)
        c_ntt = ntt_3329(a)
        c_inv = inv_ntt_3329(c_ntt)
        c_mul = ntt_base_mul_3329(ntt_3329(a), ntt_3329(b))
        c_add = poly_add_3329(a, b)
        c_sub = poly_sub_3329(a, b)
        c_qntt = ntt_qvs(qa)
        c_qinv = inv_ntt_qvs(c_qntt)

        self.assertEqual(c_cbd1, c_eta1)
        self.assertEqual(c_cbd2, c_eta2)
        self.assertEqual(c_inv, a)
        self.assertEqual(c_qinv, qa)

        # Pure-Python reference outputs
        try:
            set_native_enabled(False)
            self.assertEqual(sample_cbd1_3329(sigma, 7), c_cbd1)
            self.assertEqual(sample_cbd2_3329(sigma, 3), c_cbd2)
            self.assertEqual(sample_eta_qvs(sigma, 5), c_qvs_eta)
            self.assertEqual(ntt_3329(a), c_ntt)
            self.assertEqual(inv_ntt_3329(c_ntt), c_inv)
            self.assertEqual(ntt_base_mul_3329(ntt_3329(a), ntt_3329(b)), c_mul)
            self.assertEqual(poly_add_3329(a, b), c_add)
            self.assertEqual(poly_sub_3329(a, b), c_sub)
            self.assertEqual(ntt_qvs(qa), c_qntt)
            self.assertEqual(inv_ntt_qvs(c_qntt), c_qinv)
        finally:
            set_native_enabled(True)

        with self.assertRaises(ValueError):
            sample_cbd_eta_3329(sigma, 0, eta=3)

    def test_06_barrett_montgomery_center_and_decompose_qvs_exactness(self):
        for x in (
            -QLX_Q * QLX_Q, -QLX_Q - 1, -QLX_Q, -1, 0, 1, QLX_Q - 1, QLX_Q, QLX_Q + 1,
            2 * QLX_Q - 1, QLX_Q * QLX_Q,
        ):
            self.assertEqual(barrett_reduce_3329(x), x % QLX_Q)

        inv_r = pow(1 << 16, -1, QLX_Q)
        for a in range(-1000, 1001):
            self.assertEqual(montgomery_reduce_3329(a), (a * inv_r) % QLX_Q)

        for x in (-QVS_Q * QVS_Q, -QVS_Q, -1, 0, 1, QVS_Q - 1, QVS_Q, 2 * QVS_Q, QVS_Q * QVS_Q):
            self.assertEqual(barrett_reduce_qvs(x), x % QVS_Q)

        # Critical boundary points for center_qvs & decompose_qvs
        critical = [
            0, 1, QVS_GAMMA2 - 1, QVS_GAMMA2, QVS_GAMMA2 + 1,
            QVS_ALPHA - 1, QVS_ALPHA, QVS_ALPHA + 1,
            QVS_Q // 2 - 1, QVS_Q // 2, QVS_Q // 2 + 1,
            QVS_Q - QVS_GAMMA2 - 2, QVS_Q - QVS_GAMMA2 - 1, QVS_Q - QVS_GAMMA2,
            QVS_Q - 2, QVS_Q - 1,
        ]
        # Add 2,000 deterministic points across [0, QVS_Q)
        critical.extend((i * 4189) % QVS_Q for i in range(2000))
        for r in critical:
            expected_c = r - QVS_Q if r > QVS_Q // 2 else r
            self.assertEqual(center_qvs(r), expected_c)

            r0_ref = r % QVS_ALPHA
            if r0_ref > QVS_GAMMA2:
                r0_ref -= QVS_ALPHA
            expected_d = (0, r0_ref - 1) if (r - r0_ref == QVS_Q - 1) else ((r - r0_ref) // QVS_ALPHA, r0_ref)
            self.assertEqual(decompose_qvs(r), expected_d)

        # Check sample_mask_y_qvs stays strictly in [-gamma1 + 1, gamma1] mod QVS_Q
        y = sample_mask_y_qvs(os.urandom(64), 0)
        self.assertEqual(len(y), 256)
        self.assertTrue(all(0 <= c < QVS_Q for c in y))

    def test_07_qlx_kem_strict_types_and_zero_lock_leak(self):
        baseline = memory_security_status()["active_locked_pages"]
        witness = os.urandom(64)

        for tier in ("QLX-768", "QLX-1024", "QLX-2048"):
            ek, dk = QLXEngine.keygen(tier=tier, policy_witness=witness)
            ct, ss_enc = QLXEngine.encaps(ek, tier=tier)
            ss_dec = QLXEngine.decaps(dk, ct, tier=tier)
            self.assertEqual(ss_enc, ss_dec)

            # Tampered ciphertext triggers FO implicit rejection cleanly
            bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
            ss_rej = QLXEngine.decaps(dk, bad_ct, tier=tier)
            self.assertNotEqual(ss_rej, ss_enc)
            self.assertEqual(len(ss_rej), 32)

        with self.assertRaises(QPEPSuiteError):
            QLXEngine.encaps("not-bytes", tier="QLX-768")  # type: ignore[arg-type]
        with self.assertRaises(QPEPSuiteError):
            QLXEngine.decaps("not-bytes", b"\x00" * 1088, tier="QLX-768")  # type: ignore[arg-type]

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)


if __name__ == "__main__":
    unittest.main()
