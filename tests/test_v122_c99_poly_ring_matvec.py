"""
OpenQPEP Official Release 1.2.2 (v1.2.2) — Native C99 Polynomial Ring & Matrix-Vector Engine (QLX + QVS) Test Suite.

Verifies:
  1. ABI v1.2.2 (`0x00010202`) & dynamic export of all 20 new polynomial ring / matvec symbols
     under `-fvisibility=hidden` with zero internal helper leakage.
  2. Bit-exact Native C99 <-> Pure-Python parity for `byte_encode_12`, `byte_decode_12`,
     `compress_poly`, and `decompress_poly` across ALL 3,329 residues and ALL d in 1..12.
  3. Bit-exact Native C99 <-> Pure-Python parity for `sample_ntt_3329`, `ntt_base_mul_acc_3329`,
     streaming `openqpep_qlx_matvec_3329` (normal & transposed), `openqpep_qlx_inner_prod_3329`,
     and cross-backend `QLXEngine` encaps/decaps across all 5 tiers (`QLX-768`..`QLX-16384`).
  4. Bit-exact Native C99 <-> Pure-Python parity for division-free Solinas-Barrett `ntt_qvs`,
     `inv_ntt_qvs`, `ntt_mul_qvs`, `poly_add_qvs`, `poly_sub_qvs`, `decompose_poly_qvs`,
     `pack_poly24_qvs`, `unpack_poly24_qvs`, `sample_ntt_qvs`, `sample_mask_y_qvs`,
     `sample_in_ball_qvs`, `expand_matrix`, `matvec_precomputed`, streaming `qvs_matvec`
     (including l > 16 chunked reduction flush), and deterministic `QVSEngine` sign/verify.
  5. Verified native C99 wall-clock speedup on `QLX-4096` and `QVS-256` vs Pure-Python.
  6. Standalone external C99 consumer compiled with `-std=c99 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying ALL 8,380,417 QVS
     residues through `openqpep_qvs_decompose_poly`, INT32_MIN/MAX codec reductions, matvec engines,
     and NULL/invalid-length error guards.
"""
import os
import platform
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from calyx_qpep import (
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    native_abi_version,
    set_native_enabled,
)
from calyx_qpep.constants import QLX_Q, QVS_Q
from calyx_qpep.lattice.ntt_3329 import ntt_3329, ntt_base_mul_3329, poly_add_3329
from calyx_qpep.lattice.ntt_8380417 import (
    decompose_poly_qvs,
    inv_ntt_qvs,
    ntt_mul_qvs,
    ntt_qvs,
    poly_add_qvs,
    poly_sub_qvs,
)
from calyx_qpep.lattice.poly_ring import (
    byte_decode_12,
    byte_encode_12,
    compress_poly,
    decompress_poly,
    pack_poly24_qvs,
    sample_cbd2_3329,
    sample_eta_qvs,
    sample_in_ball_qvs,
    sample_mask_y_qvs,
    sample_ntt_3329,
    sample_ntt_qvs,
    unpack_poly24_qvs,
)
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.native import (
    native_ntt_base_mul_acc_3329,
    native_qlx_inner_prod_3329,
    native_qlx_matvec_3329,
    native_qvs_expand_matrix,
    native_qvs_matvec,
    native_qvs_matvec_precomputed,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

NEW_V122_SYMBOLS = {
    "openqpep_ntt_base_mul_acc_3329",
    "openqpep_ntt_base_mul_8380417",
    "openqpep_poly_add_qvs",
    "openqpep_poly_sub_qvs",
    "openqpep_qvs_decompose_poly",
    "openqpep_byte_encode_12",
    "openqpep_byte_decode_12",
    "openqpep_poly_compress_3329",
    "openqpep_poly_decompress_3329",
    "openqpep_qlx_sample_ntt_3329",
    "openqpep_qlx_matvec_3329",
    "openqpep_qlx_inner_prod_3329",
    "openqpep_qvs_pack_poly24",
    "openqpep_qvs_unpack_poly24",
    "openqpep_qvs_sample_ntt",
    "openqpep_qvs_sample_mask_y",
    "openqpep_qvs_sample_in_ball",
    "openqpep_qvs_expand_matrix",
    "openqpep_qvs_matvec_precomputed",
    "openqpep_qvs_matvec",
}


class TestOpenQPEPv122C99PolyRingMatvec(unittest.TestCase):
    def test_01_version_metadata_and_exported_v122_symbols(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in NEW_V122_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.2 declaration in openqpep.h: {sym}")

        if is_native_available():
            self.assertGreaterEqual(native_abi_version(), 0x00010202)
            ext = "dylib" if platform.system() == "Darwin" else "so"
            shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
            if shared_lib.is_file() and shutil.which("nm"):
                res = subprocess.run(
                    ["nm", "-D", "--defined-only", str(shared_lib)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                exported = {
                    line.split()[2].split("@")[0]
                    for line in res.stdout.splitlines()
                    if len(line.split()) >= 3 and line.split()[1] in ("T", "D", "R", "B")
                    and not line.split()[2].startswith("_")
                }
                missing = NEW_V122_SYMBOLS - exported
                self.assertEqual(missing, set(), f"Missing exported v1.2.2 symbols: {missing}")
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

    def test_02_qlx_codecs_and_compress_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        # Build 14 polynomials covering EVERY single residue 0..3328 plus edge signed inputs
        polys = []
        for blk in range(14):
            polys.append([(blk * 256 + i) % QLX_Q for i in range(256)])
        polys.append([((-1) ** i) * (i * 100003 + 7) for i in range(256)])

        try:
            for poly in polys:
                set_native_enabled(True)
                enc_c = byte_encode_12(poly)
                dec_c = byte_decode_12(enc_c)

                set_native_enabled(False)
                enc_py = byte_encode_12(poly)
                dec_py = byte_decode_12(enc_py)

                self.assertEqual(enc_c, enc_py)
                self.assertEqual(dec_c, dec_py)

                for d in range(1, 13):
                    set_native_enabled(True)
                    comp_c = compress_poly(poly, d)
                    decomp_c = decompress_poly(comp_c, d)

                    set_native_enabled(False)
                    comp_py = compress_poly(poly, d)
                    decomp_py = decompress_poly(comp_py, d)

                    self.assertEqual(comp_c, comp_py, f"compress_poly mismatch at d={d}")
                    self.assertEqual(decomp_c, decomp_py, f"decompress_poly mismatch at d={d}")
        finally:
            set_native_enabled(True)

    def test_03_qlx_matvec_inner_prod_and_all5_tiers_cross_backend(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        rho = bytes(range(32))
        sigma = bytes(range(32, 64))
        try:
            # Verify fused acc, matvec (normal + transposed), and inner_prod across k in (3, 4, 8, 16)
            for k in (3, 4, 8, 16):
                set_native_enabled(True)
                vec = [ntt_3329(sample_cbd2_3329(sigma, i)) for i in range(k)]
                add_v = [ntt_3329(sample_cbd2_3329(sigma, k + i)) for i in range(k)]
                mv_norm_c = native_qlx_matvec_3329(rho, k, False, vec, add_v)
                mv_trans_c = native_qlx_matvec_3329(rho, k, True, vec, None)
                ip_c = native_qlx_inner_prod_3329(vec, add_v)

                set_native_enabled(False)
                a_mat = [[sample_ntt_3329(rho, i, j) for j in range(k)] for i in range(k)]
                mv_norm_py = []
                mv_trans_py = []
                for i in range(k):
                    acc_n = [0] * 256
                    acc_t = [0] * 256
                    for j in range(k):
                        acc_n = poly_add_3329(acc_n, ntt_base_mul_3329(a_mat[i][j], vec[j]))
                        acc_t = poly_add_3329(acc_t, ntt_base_mul_3329(a_mat[j][i], vec[j]))
                    mv_norm_py.append(poly_add_3329(acc_n, add_v[i]))
                    mv_trans_py.append(acc_t)
                ip_py = [0] * 256
                for j in range(k):
                    ip_py = poly_add_3329(ip_py, ntt_base_mul_3329(vec[j], add_v[j]))

                self.assertEqual(mv_norm_c, mv_norm_py, f"QLX matvec normal mismatch at k={k}")
                self.assertEqual(mv_trans_c, mv_trans_py, f"QLX matvec transpose mismatch at k={k}")
                self.assertEqual(ip_c, ip_py, f"QLX inner_prod mismatch at k={k}")

            # Verify fused ntt_base_mul_acc_3329 directly
            set_native_enabled(True)
            acc0 = [(i * 19 + 3) % QLX_Q for i in range(256)]
            p1 = [(i * 41 + 7) % QLX_Q for i in range(256)]
            p2 = [(i * 53 + 11) % QLX_Q for i in range(256)]
            acc_c = native_ntt_base_mul_acc_3329(acc0, p1, p2)
            set_native_enabled(False)
            acc_py = poly_add_3329(acc0, ntt_base_mul_3329(p1, p2))
            self.assertEqual(acc_c, acc_py)

            # Cross-backend QLX KEM encaps/decaps across ALL 5 tiers (QLX-768..QLX-16384)
            witness = b"\x5A" * 64
            for tier in ("QLX-768", "QLX-1024", "QLX-2048", "QLX-4096", "QLX-16384"):
                set_native_enabled(True)
                ek, dk = QLXEngine.keygen(tier=tier, policy_witness=witness)
                ct_c, ss_c = QLXEngine.encaps(ek, tier=tier)
                set_native_enabled(False)
                ss_dec_py = QLXEngine.decaps(dk, ct_c, tier=tier)
                self.assertEqual(ss_dec_py, ss_c, f"{tier}: Native encaps -> Pure-Python decaps failed")

                ct_py, ss_py = QLXEngine.encaps(ek, tier=tier)
                set_native_enabled(True)
                ss_dec_c = QLXEngine.decaps(dk, ct_py, tier=tier)
                self.assertEqual(ss_dec_c, ss_py, f"{tier}: Pure-Python encaps -> Native decaps failed")
        finally:
            set_native_enabled(True)

    def test_04_qvs_solinas_ntt_decompose_matvec_and_deterministic_sign_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        rho = bytes(range(100, 132))
        seed64 = bytes(range(64))
        c_tilde = bytes(range(128, 192))
        try:
            # Boundary-heavy QVS polynomial covering 0, 1, GAMMA2, ALPHA, Q-1, negative values
            edge_poly = [
                0, 1, 2, 261887, 261888, 261889, 523775, 523776, 523777,
                4190208, 4190209, QVS_Q - 2, QVS_Q - 1, -1, -261888, -QVS_Q,
            ] + [((i * 99991 + 13) % QVS_Q) for i in range(240)]
            other_poly = [((i * 65537 + 29) % QVS_Q) for i in range(256)]
            canon_edge = [x % QVS_Q for x in edge_poly]

            set_native_enabled(True)
            ntt_c = ntt_qvs(canon_edge)
            inv_c = inv_ntt_qvs(ntt_c)
            mul_c = ntt_mul_qvs(ntt_c, ntt_qvs(other_poly))
            add_c = poly_add_qvs(edge_poly, other_poly)
            sub_c = poly_sub_qvs(edge_poly, other_poly)
            dec_r1_c, dec_r0_c = decompose_poly_qvs(edge_poly)
            pack_c = pack_poly24_qvs(edge_poly)
            unpack_c = unpack_poly24_qvs(pack_c)
            mask_c = sample_mask_y_qvs(seed64, 17)
            ball_c = sample_in_ball_qvs(c_tilde, 60)

            set_native_enabled(False)
            ntt_py = ntt_qvs(canon_edge)
            inv_py = inv_ntt_qvs(ntt_py)
            mul_py = ntt_mul_qvs(ntt_py, ntt_qvs(other_poly))
            add_py = poly_add_qvs(edge_poly, other_poly)
            sub_py = poly_sub_qvs(edge_poly, other_poly)
            dec_r1_py, dec_r0_py = decompose_poly_qvs(edge_poly)
            pack_py = pack_poly24_qvs(edge_poly)
            unpack_py = unpack_poly24_qvs(pack_py)
            mask_py = sample_mask_y_qvs(seed64, 17)
            ball_py = sample_in_ball_qvs(c_tilde, 60)

            self.assertEqual(ntt_c, ntt_py)
            self.assertEqual(inv_c, inv_py)
            self.assertEqual(inv_c, canon_edge)
            self.assertEqual(mul_c, mul_py)
            self.assertEqual(add_c, add_py)
            self.assertEqual(sub_c, sub_py)
            self.assertEqual((dec_r1_c, dec_r0_c), (dec_r1_py, dec_r0_py))
            self.assertEqual(pack_c, pack_py)
            self.assertEqual(unpack_c, unpack_py)
            self.assertEqual(mask_c, mask_py)
            self.assertEqual(ball_c, ball_py)

            # Verify QVS expand_matrix, matvec_precomputed, and streaming matvec (including l=18 > 16 flush!)
            for (k, l) in ((3, 2), (4, 18)):
                set_native_enabled(True)
                s_vec = [ntt_qvs(sample_eta_qvs(seed64, j)) for j in range(l)]
                s2_vec = [sample_eta_qvs(seed64, l + i) for i in range(k)]
                a_flat = native_qvs_expand_matrix(rho, k, l)
                mv_pre_c = native_qvs_matvec_precomputed(a_flat, k, l, s_vec)
                mv_ntt_c = native_qvs_matvec(rho, k, l, s_vec, add_vec=None, apply_inv_ntt=False)
                mv_inv_c = native_qvs_matvec(rho, k, l, s_vec, add_vec=s2_vec, apply_inv_ntt=True)

                set_native_enabled(False)
                a_py = [[sample_ntt_qvs(rho, i, j) for j in range(l)] for i in range(k)]
                mv_ntt_py = []
                mv_inv_py = []
                for i in range(k):
                    acc = [0] * 256
                    for j in range(l):
                        acc = [(acc[m] + a_py[i][j][m] * s_vec[j][m]) % QVS_Q for m in range(256)]
                    mv_ntt_py.append(acc)
                    t_i = [(inv_ntt_qvs(acc)[m] + s2_vec[i][m]) % QVS_Q for m in range(256)]
                    mv_inv_py.append(t_i)

                self.assertEqual(mv_pre_c, mv_ntt_py)
                self.assertEqual(mv_ntt_c, mv_ntt_py)
                self.assertEqual(mv_inv_c, mv_inv_py)

            # Bit-for-bit identical deterministic QVS sign & cross-backend verify across QVS-65, QVS-256, QVS-1024
            witness = b"\xA5" * 64
            msg = b"OpenQPEP v1.2.2 C99 Polynomial Ring & Matrix-Vector Parity Message"
            for tier in ("QVS-65", "QVS-256", "QVS-1024"):
                set_native_enabled(True)
                pk, sk = QVSEngine.keygen(tier=tier, policy_witness=witness)
                sig_c = QVSEngine.sign(sk, pk, msg, tier=tier, hedged=False)
                set_native_enabled(False)
                sig_py = QVSEngine.sign(sk, pk, msg, tier=tier, hedged=False)
                self.assertEqual(sig_c, sig_py, f"{tier}: Deterministic Native vs Pure-Python signature diverged!")
                self.assertTrue(QVSEngine.verify(pk, msg, sig_c, tier=tier))
                set_native_enabled(True)
                self.assertTrue(QVSEngine.verify(pk, msg, sig_py, tier=tier))
        finally:
            set_native_enabled(True)

    def test_05_verified_speedup_qlx4096_and_qvs256_native_vs_pure_python(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        witness = b"\x3C" * 64
        try:
            set_native_enabled(True)
            ek, _ = QLXEngine.keygen(tier="QLX-4096", policy_witness=witness)
            msg32 = b"\x11" * 32
            coins = b"\x22" * 32

            # Warmup + measure QLX-4096 IND-CPA encrypt (k=16 -> 256 NTT matrix entries)
            ct_c = QLXEngine._indcpa_enc(ek, msg32, coins, "QLX-4096")
            t0 = time.perf_counter()
            for _ in range(3):
                QLXEngine._indcpa_enc(ek, msg32, coins, "QLX-4096")
            native_qlx_s = (time.perf_counter() - t0) / 3.0

            set_native_enabled(False)
            t1 = time.perf_counter()
            ct_py = QLXEngine._indcpa_enc(ek, msg32, coins, "QLX-4096")
            pure_qlx_s = time.perf_counter() - t1

            self.assertEqual(ct_c, ct_py)
            qlx_speedup = pure_qlx_s / max(native_qlx_s, 1e-9)
            self.assertGreater(
                qlx_speedup,
                5.0,
                f"Expected >=5x native speedup on QLX-4096, got {qlx_speedup:.2f}x "
                f"(native={native_qlx_s*1000:.2f}ms vs pure={pure_qlx_s*1000:.2f}ms)",
            )

            # Measure QVS-256 verify (8x7 matrix + NTT + Decompose)
            set_native_enabled(True)
            pk_qvs, sk_qvs = QVSEngine.keygen(tier="QVS-256", policy_witness=witness)
            sig_qvs = QVSEngine.sign(sk_qvs, pk_qvs, b"bench-v122", tier="QVS-256", hedged=False)
            t2 = time.perf_counter()
            for _ in range(3):
                self.assertTrue(QVSEngine.verify(pk_qvs, b"bench-v122", sig_qvs, tier="QVS-256"))
            native_qvs_s = (time.perf_counter() - t2) / 3.0

            set_native_enabled(False)
            t3 = time.perf_counter()
            self.assertTrue(QVSEngine.verify(pk_qvs, b"bench-v122", sig_qvs, tier="QVS-256"))
            pure_qvs_s = time.perf_counter() - t3

            qvs_speedup = pure_qvs_s / max(native_qvs_s, 1e-9)
            self.assertGreater(
                qvs_speedup,
                5.0,
                f"Expected >=5x native speedup on QVS-256 verify, got {qvs_speedup:.2f}x "
                f"(native={native_qvs_s*1000:.2f}ms vs pure={pure_qvs_s*1000:.2f}ms)",
            )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_exhaustive_qvs_decompose_and_matvec_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    /* 1. Exhaustive verification of ALL 8,380,417 residues through openqpep_qvs_decompose_poly */
    int32_t in_poly[256];
    int32_t r1[256];
    int32_t r0[256];
    for (int32_t base = 0; base < OPENQPEP_QVS_Q; base += 256) {
        for (int i = 0; i < 256; i++) {
            int32_t v = base + i;
            in_poly[i] = (v < OPENQPEP_QVS_Q) ? v : 0;
        }
        if (openqpep_qvs_decompose_poly(in_poly, r1, r0) != OPENQPEP_OK) return 1;
        for (int i = 0; i < 256; i++) {
            int32_t r = in_poly[i];
            if (r1[i] < 0 || r1[i] > 15) return 2;
            if (r0[i] < -261888 || r0[i] > 261888) return 3;
            int64_t recon = (int64_t)r1[i] * 523776LL + (int64_t)r0[i];
            int64_t mod = ((recon % (int64_t)OPENQPEP_QVS_Q) + (int64_t)OPENQPEP_QVS_Q) % (int64_t)OPENQPEP_QVS_Q;
            if (mod != (int64_t)r) return 4;
        }
    }

    /* 2. Signed int32_t extreme edge cases (INT32_MIN, INT32_MAX, negatives) for QLX & QVS codecs */
    int32_t extreme[256];
    int32_t decoded[256];
    uint8_t enc12[384];
    uint8_t enc24[768];
    uint8_t comp[384];
    for (int i = 0; i < 256; i++) {
        if (i == 0) extreme[i] = INT32_MIN;
        else if (i == 1) extreme[i] = INT32_MAX;
        else if (i == 2) extreme[i] = -1;
        else if (i == 3) extreme[i] = -OPENQPEP_QLX_Q;
        else if (i == 4) extreme[i] = -OPENQPEP_QVS_Q;
        else extreme[i] = (i % 2 == 0) ? (i * 123456) : (-i * 123456);
    }
    if (openqpep_byte_encode_12(extreme, enc12) != OPENQPEP_OK) return 5;
    if (openqpep_byte_decode_12(enc12, decoded) != OPENQPEP_OK) return 6;
    for (int i = 0; i < 256; i++) {
        int64_t exp = ((int64_t)extreme[i] % 3329LL + 3329LL) % 3329LL;
        if (decoded[i] != (int32_t)exp) return 7;
    }
    for (uint32_t d = 1U; d <= 12U; d++) {
        if (openqpep_poly_compress_3329(extreme, d, comp, (size_t)(32U * d)) != OPENQPEP_OK) return 8;
        if (openqpep_poly_decompress_3329(comp, (size_t)(32U * d), d, decoded) != OPENQPEP_OK) return 9;
        for (int i = 0; i < 256; i++) {
            if (decoded[i] < 0 || decoded[i] >= OPENQPEP_QLX_Q) return 10;
        }
    }
    if (openqpep_qvs_pack_poly24(extreme, enc24) != OPENQPEP_OK) return 11;
    if (openqpep_qvs_unpack_poly24(enc24, decoded) != OPENQPEP_OK) return 12;
    for (int i = 0; i < 256; i++) {
        int64_t exp = ((int64_t)extreme[i] % (int64_t)OPENQPEP_QVS_Q + (int64_t)OPENQPEP_QVS_Q) % (int64_t)OPENQPEP_QVS_Q;
        if (decoded[i] != (int32_t)exp) return 13;
    }

    /* 3. Verify QLX & QVS matvec, base_mul_8380417, and NULL/invalid-len error guards */
    uint8_t rho[32];
    for (size_t i = 0; i < 32; i++) rho[i] = (uint8_t)(i * 7U + 1U);
    int32_t v3[3 * 256];
    int32_t out3[3 * 256];
    int32_t ip_out[256];
    for (int i = 0; i < 3 * 256; i++) v3[i] = (i * 13) % OPENQPEP_QLX_Q;
    if (openqpep_qlx_matvec_3329(rho, 3U, 0, v3, v3, out3) != OPENQPEP_OK) return 14;
    if (openqpep_qlx_inner_prod_3329(v3, out3, 3U, ip_out) != OPENQPEP_OK) return 15;

    int32_t a_flat[3 * 2 * 256];
    int32_t qv2[2 * 256];
    int32_t qout_pre[3 * 256];
    int32_t qout_str[3 * 256];
    for (int i = 0; i < 2 * 256; i++) qv2[i] = (i * 97) % OPENQPEP_QVS_Q;
    if (openqpep_qvs_expand_matrix(rho, 3U, 2U, a_flat) != OPENQPEP_OK) return 16;
    if (openqpep_qvs_matvec_precomputed(a_flat, 3U, 2U, qv2, qout_pre) != OPENQPEP_OK) return 17;
    if (openqpep_qvs_matvec(rho, 3U, 2U, qv2, NULL, 0, qout_str) != OPENQPEP_OK) return 18;
    if (memcmp(qout_pre, qout_str, sizeof(qout_pre)) != 0) return 19;

    int32_t m1[256], m2[256];
    openqpep_ntt_mul_qvs(qout_pre, qout_str, m1);
    openqpep_ntt_base_mul_8380417(qout_pre, qout_str, m2);
    if (memcmp(m1, m2, sizeof(m1)) != 0) return 20;

    if (openqpep_poly_compress_3329(NULL, 4U, comp, 128U) != OPENQPEP_ERR_NULL_PTR) return 21;
    if (openqpep_poly_compress_3329(extreme, 0U, comp, 0U) != OPENQPEP_ERR_INVALID_LEN) return 22;
    if (openqpep_poly_compress_3329(extreme, 4U, comp, 100U) != OPENQPEP_ERR_INVALID_LEN) return 23;
    if (openqpep_qvs_sample_in_ball(rho, 32U, 65U, decoded) != OPENQPEP_ERR_INVALID_LEN) return 24;
    if (openqpep_qlx_matvec_3329(rho, 0U, 0, v3, NULL, out3) != OPENQPEP_ERR_INVALID_LEN) return 25;
    if (openqpep_qvs_decompose_poly(NULL, r1, r0) != OPENQPEP_ERR_NULL_PTR) return 26;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "poly_consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            bin_static = Path(tmpdir) / "poly_static"
            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    "-DOPENQPEP_STATIC", f"-I{CSRC_DIR / 'include'}",
                    str(src_file), str(static_lib), "-o", str(bin_static),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            r_static = subprocess.run([str(bin_static)], capture_output=True, text=True)
            self.assertEqual(r_static.returncode, 0, f"Static C99 poly consumer failed rc={r_static.returncode}")

            bin_shared = Path(tmpdir) / "poly_shared"
            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    f"-I{CSRC_DIR / 'include'}",
                    str(src_file), str(shared_lib),
                    f"-Wl,-rpath,{NATIVE_DIR}",
                    "-o", str(bin_shared),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            r_shared = subprocess.run([str(bin_shared)], capture_output=True, text=True)
            self.assertEqual(r_shared.returncode, 0, f"Shared C99 poly consumer failed rc={r_shared.returncode}")


if __name__ == "__main__":
    unittest.main()
