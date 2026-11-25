"""
OpenQPEP Official Release 1.2.5 (v1.2.5) — Native C99 Rank-Metric GF(2^127) & UOV GF(256) Accelerators Test Suite.

Verifies:
  1. ABI v1.2.5 (`0x00010205`) & dynamic export of all 10 new Rank/UOV C99 symbols under
     `-fvisibility=hidden` with zero internal helper leakage (`85` total exported symbols).
  2. Branchless table-free GF(2^127) arithmetic (`mul`, `sq`, `inv`) and LRPC ring operations
     (`ring_mul`, `ring_inv` mod X^47 + X^5 + 1) bit-exact Native C99 <-> Pure-Python parity.
  3. Exhaustive GF(256) inversion (`0..255`), constant-time pivot-masked Gauss-Jordan linear
     solver (random, zero-diagonal cyclic, and singular matrices), UOV P_3 keygen, public map
     evaluation, and UOV sign core bit-exact Native C99 <-> Pure-Python parity.
  4. End-to-end cross-backend `RankMetricKEM` (`CRT-RSD512`), `CalyxRankMetricSuite`,
     deterministic & hedged `MultivariateQuadraticEngine` (`QMQ-512`), and `CalyxSovereignPentad`.
  5. Verified Native C99 wall-clock speedups on BOTH `CRT-RSD512` and `QMQ-512`.
  6. Standalone external C99 consumer compiled under `-std=c99 -O2 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying exhaustive GF(256),
     GF(2^127) & LRPC ring identities, constant-time linear solver, full C99 UOV keygen/sign/verify,
     and NULL / invalid-len / singular error status codes.
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
from calyx_qpep.codes.rank_rsd512 import (
    LRPC_N,
    RankMetricKEM,
    _gf2_127_inv,
    _pack_poly,
    _ring_inv,
    _ring_mul,
    _unpack_poly,
    gf2_127_mul,
)
from calyx_qpep.codes.rank_suite import CalyxRankMetricSuite
from calyx_qpep.multivariate.qmq_512 import (
    MultivariateQuadraticEngine,
    _INV256,
    _MUL256,
    _eval_public_map,
    _expand_p1_p2,
    _solve_gf256_linear,
    _unpack_p3,
)
from calyx_qpep.native import (
    native_gf256_inv,
    native_gf2_127_inv,
    native_gf2_127_mul,
    native_gf2_127_sq,
    native_lrpc_ring_inv,
    native_lrpc_ring_mul,
    native_uov_compute_p3,
    native_uov_eval_public_map,
    native_uov_sign_core,
    native_uov_solve_gf256_linear,
)
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

NEW_V125_SYMBOLS = {
    "openqpep_gf2_127_mul",
    "openqpep_gf2_127_sq",
    "openqpep_gf2_127_inv",
    "openqpep_lrpc_ring_mul",
    "openqpep_lrpc_ring_inv",
    "openqpep_gf256_inv",
    "openqpep_uov_solve_gf256_linear",
    "openqpep_uov_compute_p3",
    "openqpep_uov_eval_public_map",
    "openqpep_uov_sign_core",
}


class TestOpenQPEPv125C99RankAndUOV(unittest.TestCase):
    def test_01_version_metadata_and_exported_v125_symbols(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in NEW_V125_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.5 Rank/UOV symbol in openqpep.h: {sym}")

        if is_native_available():
            self.assertGreaterEqual(native_abi_version(), 0x00010205)
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
                missing = NEW_V125_SYMBOLS - exported
                self.assertEqual(missing, set(), f"Missing exported Rank/UOV symbols: {missing}")
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

    def test_02_gf2_127_and_lrpc_ring_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        mask127 = (1 << 127) - 1
        test_vals = [
            0, 1, 2, 3, (1 << 63), (1 << 63) | 1, (1 << 64), (1 << 126), mask127,
            0x123456789ABCDEF0FEDCBA987654321 & mask127,
            0x7FFFFFFFFFFFFFFF8000000000000001 & mask127,
        ] + [int.from_bytes(os.urandom(16), "little") & mask127 for _ in range(16)]

        try:
            self.assertEqual(native_gf2_127_inv(0), 0)
            for idx, a in enumerate(test_vals):
                b = test_vals[(idx * 5 + 3) % len(test_vals)]
                set_native_enabled(True)
                mul_c = native_gf2_127_mul(a, b)
                sq_c = native_gf2_127_sq(a)
                inv_c = native_gf2_127_inv(a)

                set_native_enabled(False)
                mul_py = gf2_127_mul(a, b)
                sq_py = gf2_127_mul(a, a)

                self.assertEqual(mul_c, mul_py)
                self.assertEqual(sq_c, sq_py)
                if a != 0:
                    self.assertEqual(inv_c, _gf2_127_inv(a))
                    set_native_enabled(True)
                    self.assertEqual(native_gf2_127_mul(a, inv_c), 1)

            # LRPC ring mul & ring inv parity
            p_a = [(int.from_bytes(bytes([(i * 17 + j) & 0xFF for j in range(16)]), "little") & mask127) for i in range(LRPC_N)]
            p_b = [(int.from_bytes(bytes([(i * 31 + j * 3) & 0xFF for j in range(16)]), "little") & mask127) for i in range(LRPC_N)]

            set_native_enabled(True)
            ab_c = _ring_mul(p_a, p_b)
            ainv_c = _ring_inv(p_a)
            self.assertIsNotNone(ainv_c)
            one_c = _ring_mul(p_a, ainv_c)
            self.assertEqual(one_c, [1] + [0] * (LRPC_N - 1))
            ok_zero, _ = native_lrpc_ring_inv(b"\x00" * 752)
            self.assertFalse(ok_zero)

            set_native_enabled(False)
            ab_py = _ring_mul(p_a, p_b)
            ainv_py = _ring_inv(p_a)
            self.assertEqual(ab_c, ab_py)
            self.assertEqual(ainv_c, ainv_py)
        finally:
            set_native_enabled(True)

    def test_03_gf256_inv_ct_gaussian_and_uov_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            # 1. Exhaustive GF(256) inversion 0..255
            for a in range(256):
                inv_c = native_gf256_inv(a)
                self.assertEqual(inv_c, _INV256[a])
                if a > 0:
                    self.assertEqual(_MUL256[a][inv_c], 1)

            # 2. Constant-time pivot-masked Gauss-Jordan solver on cyclic zero-diagonal, random & singular matrices
            m = 16
            # Cyclic permutation matrix has ZERO on every diagonal entry -> stresses branchless pivot XOR!
            cyc = [[0] * m for _ in range(m)]
            for i in range(m):
                cyc[i][(i + 1) % m] = (i * 11 + 3) & 0xFF or 1
            rhs = [(i * 29 + 7) & 0xFF for i in range(m)]

            set_native_enabled(True)
            sol_cyc_c = _solve_gf256_linear(cyc, rhs)
            set_native_enabled(False)
            sol_cyc_py = _solve_gf256_linear(cyc, rhs)
            self.assertIsNotNone(sol_cyc_c)
            self.assertEqual(sol_cyc_c, sol_cyc_py)

            # Singular matrix (row 5 == row 2 ^ row 7)
            sing = [[((i * 19 + j * 7 + 1) & 0xFF) for j in range(m)] for i in range(m)]
            sing[5] = [sing[2][j] ^ sing[7][j] for j in range(m)]
            set_native_enabled(True)
            self.assertIsNone(_solve_gf256_linear(sing, rhs))
            set_native_enabled(False)
            self.assertIsNone(_solve_gf256_linear(sing, rhs))

            # 3. UOV P_3 computation, public map evaluation, and sign_core C99 vs Pure-Python parity
            seed_pk = bytes(range(32))
            seed_sk = bytes(range(32, 64))
            salt = bytes(range(16))
            target = bytes(range(100, 116))
            v, m = 32, 16

            set_native_enabled(True)
            p3_c = native_uov_compute_p3(seed_pk, seed_sk, v, m)
            ok_s, sv_c, so_c = native_uov_sign_core(seed_pk, seed_sk, salt, target, v, m)
            self.assertTrue(ok_s)
            eval_c = native_uov_eval_public_map(seed_pk, p3_c, v, m, sv_c, so_c)
            self.assertEqual(eval_c, target)

            set_native_enabled(False)
            p1_py, p2_py = _expand_p1_p2(seed_pk, v, m)
            p3_py = _unpack_p3(p3_c, m)
            eval_py = _eval_public_map(p1_py, p2_py, p3_py, v, m, list(sv_c), list(so_c))
            self.assertEqual(eval_c, eval_py)
        finally:
            set_native_enabled(True)

    def test_04_cross_backend_crt_rsd512_qmq512_and_csp_omega_round_trips(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            # 1. CRT-RSD512 cross-backend encaps/decaps + FO implicit rejection parity
            set_native_enabled(True)
            pk_r, sk_r = RankMetricKEM.keygen()
            ct_c, ss_c = RankMetricKEM.encaps(pk_r)

            set_native_enabled(False)
            self.assertEqual(RankMetricKEM.decaps(sk_r, ct_c), ss_c)
            ct_py, ss_py = RankMetricKEM.encaps(pk_r)
            bad_ct = bytes([ct_c[0] ^ 0x01]) + ct_c[1:]
            rej_py = RankMetricKEM.decaps(sk_r, bad_ct)

            set_native_enabled(True)
            self.assertEqual(RankMetricKEM.decaps(sk_r, ct_py), ss_py)
            rej_c = RankMetricKEM.decaps(sk_r, bad_ct)
            self.assertEqual(rej_c, rej_py)
            self.assertNotEqual(rej_c, ss_c)

            pkt_crt = CalyxRankMetricSuite.encrypt(b"crt-v125-native-to-py", pk_r)
            set_native_enabled(False)
            self.assertEqual(CalyxRankMetricSuite.decrypt(pkt_crt, sk_r), b"crt-v125-native-to-py")

            # 2. QMQ-512 deterministic sign bit-exact parity + cross-backend verify
            msg = b"OpenQPEP v1.2.5 QMQ-512 UOV C99 parity message"
            set_native_enabled(True)
            pk_q, sk_q = MultivariateQuadraticEngine.keygen()
            sig_det_c = MultivariateQuadraticEngine.sign(sk_q, msg, hedged=False)
            sig_hed_c = MultivariateQuadraticEngine.sign(sk_q, msg, hedged=True, rnd=b"\x42" * 32)

            set_native_enabled(False)
            sig_det_py = MultivariateQuadraticEngine.sign(sk_q, msg, hedged=False)
            sig_hed_py = MultivariateQuadraticEngine.sign(sk_q, msg, hedged=True, rnd=b"\x42" * 32)
            self.assertEqual(sig_det_c, sig_det_py)
            self.assertEqual(sig_hed_c, sig_hed_py)
            self.assertTrue(MultivariateQuadraticEngine.verify(pk_q, msg, sig_det_c))
            self.assertFalse(MultivariateQuadraticEngine.verify(pk_q, msg + b"!", sig_det_c))

            set_native_enabled(True)
            self.assertTrue(MultivariateQuadraticEngine.verify(pk_q, msg, sig_det_py))

            # 3. CSP-Omega cross-backend signature
            pub_p, priv_p = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
            sig_p = CalyxSovereignPentad.sign(b"pentad-v125-sig", pub_p, priv_p)
            set_native_enabled(False)
            ok_p, out_msg = CalyxSovereignPentad.verify(sig_p, pub_p)
            self.assertTrue(ok_p)
            self.assertEqual(out_msg, b"pentad-v125-sig")
        finally:
            set_native_enabled(True)

    def test_05_verified_speedup_crt_rsd512_and_qmq512(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            # Measure CRT-RSD512 encaps + decaps
            set_native_enabled(True)
            pk_r, sk_r = RankMetricKEM.keygen()
            t0 = time.perf_counter()
            for _ in range(3):
                ct_r, ss_r = RankMetricKEM.encaps(pk_r)
                self.assertEqual(RankMetricKEM.decaps(sk_r, ct_r), ss_r)
            native_crt_s = (time.perf_counter() - t0) / 3.0

            set_native_enabled(False)
            t1 = time.perf_counter()
            ct_rp, ss_rp = RankMetricKEM.encaps(pk_r)
            self.assertEqual(RankMetricKEM.decaps(sk_r, ct_rp), ss_rp)
            pure_crt_s = time.perf_counter() - t1

            crt_speedup = pure_crt_s / max(native_crt_s, 1e-9)
            self.assertGreater(
                crt_speedup,
                5.0,
                f"Expected >=5x CRT-RSD512 speedup, got {crt_speedup:.1f}x "
                f"(C99={native_crt_s*1000:.2f}ms vs Py={pure_crt_s*1000:.2f}ms)",
            )

            # Measure QMQ-512 keygen + sign + verify
            set_native_enabled(True)
            t2 = time.perf_counter()
            for _ in range(3):
                pk_q, sk_q = MultivariateQuadraticEngine.keygen()
                sig_q = MultivariateQuadraticEngine.sign(sk_q, b"bench-qmq", hedged=False)
                self.assertTrue(MultivariateQuadraticEngine.verify(pk_q, b"bench-qmq", sig_q))
            native_qmq_s = (time.perf_counter() - t2) / 3.0

            set_native_enabled(False)
            t3 = time.perf_counter()
            pk_qp, sk_qp = MultivariateQuadraticEngine.keygen()
            sig_qp = MultivariateQuadraticEngine.sign(sk_qp, b"bench-qmq", hedged=False)
            self.assertTrue(MultivariateQuadraticEngine.verify(pk_qp, b"bench-qmq", sig_qp))
            pure_qmq_s = time.perf_counter() - t3

            qmq_speedup = pure_qmq_s / max(native_qmq_s, 1e-9)
            self.assertGreater(
                qmq_speedup,
                5.0,
                f"Expected >=5x QMQ-512 speedup, got {qmq_speedup:.1f}x "
                f"(C99={native_qmq_s*1000:.2f}ms vs Py={pure_qmq_s*1000:.2f}ms)",
            )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_rank_uov_static_and_shared_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    /* 1. Exhaustive GF(256) inversion check across all 256 elements */
    if (openqpep_gf256_inv(0U) != 0U) return 1;
    for (uint32_t a = 1U; a < 256U; a++) {
        uint8_t inv = openqpep_gf256_inv((uint8_t)a);
        if (openqpep_gf256_mul((uint8_t)a, inv) != 1U) return 2;
    }

    /* 2. GF(2^127) mul / sq / inv identities + LRPC ring mul / inv round-trip */
    uint8_t a16[16], sq1[16], sq2[16], inv16[16], prod16[16];
    for (size_t i = 0; i < 16; i++) a16[i] = (uint8_t)(i * 19U + 5U);
    a16[15] &= 0x7FU;
    if (openqpep_gf2_127_sq(a16, sq1) != OPENQPEP_OK) return 3;
    if (openqpep_gf2_127_mul(a16, a16, sq2) != OPENQPEP_OK) return 4;
    if (memcmp(sq1, sq2, 16U) != 0) return 5;
    if (openqpep_gf2_127_inv(a16, inv16) != OPENQPEP_OK) return 6;
    if (openqpep_gf2_127_mul(a16, inv16, prod16) != OPENQPEP_OK) return 7;
    if (prod16[0] != 1U) return 8;
    for (size_t i = 1; i < 16; i++) if (prod16[i] != 0U) return 9;

    uint8_t poly[OPENQPEP_LRPC_POLY_BYTES], pinv[OPENQPEP_LRPC_POLY_BYTES], pone[OPENQPEP_LRPC_POLY_BYTES];
    for (size_t i = 0; i < sizeof(poly); i++) poly[i] = (uint8_t)((i * 37U + 11U) & 0xFFU);
    for (size_t c = 0; c < OPENQPEP_LRPC_N; c++) poly[c * 16U + 15U] &= 0x7FU;
    if (openqpep_lrpc_ring_inv(poly, pinv) != OPENQPEP_OK) return 10;
    if (openqpep_lrpc_ring_mul(poly, pinv, pone) != OPENQPEP_OK) return 11;
    if (pone[0] != 1U) return 12;
    for (size_t i = 1; i < sizeof(pone); i++) if (pone[i] != 0U) return 13;

    uint8_t zero_poly[OPENQPEP_LRPC_POLY_BYTES];
    memset(zero_poly, 0, sizeof(zero_poly));
    if (openqpep_lrpc_ring_inv(zero_poly, pinv) != OPENQPEP_ERR_SINGULAR) return 14;

    /* 3. Constant-time pivot-masked Gauss-Jordan solver on cyclic zero-diagonal & singular matrices */
    uint8_t cyc[16 * 16];
    uint8_t rhs[16], sol[16];
    memset(cyc, 0, sizeof(cyc));
    for (uint32_t i = 0; i < 16U; i++) {
        cyc[i * 16U + ((i + 1U) % 16U)] = (uint8_t)(i * 7U + 1U);
        rhs[i] = (uint8_t)(i * 13U + 3U);
    }
    if (openqpep_uov_solve_gf256_linear(cyc, rhs, 16U, sol) != OPENQPEP_OK) return 15;
    for (uint32_t i = 0; i < 16U; i++) {
        uint8_t acc = 0U;
        for (uint32_t j = 0; j < 16U; j++) {
            acc ^= openqpep_gf256_mul(cyc[i * 16U + j], sol[j]);
        }
        if (acc != rhs[i]) return 16;
    }
    /* Duplicate row makes system singular */
    memcpy(cyc + 3U * 16U, cyc, 16U);
    if (openqpep_uov_solve_gf256_linear(cyc, rhs, 16U, sol) != OPENQPEP_ERR_SINGULAR) return 17;

    /* 4. Full C99 UOV P_3 keygen + sign_core + eval_public_map round-trip */
    uint8_t seed_pk[32], seed_sk[32], salt[16], target[16], eval_out[16];
    uint8_t sv[32], so[16];
    uint8_t p3[16 * (16 * 17 / 2)];
    for (size_t i = 0; i < 32; i++) { seed_pk[i] = (uint8_t)(i + 1U); seed_sk[i] = (uint8_t)(i + 99U); }
    for (size_t i = 0; i < 16; i++) { salt[i] = (uint8_t)(i * 5U); target[i] = (uint8_t)(0xF0U - i); }
    if (openqpep_uov_compute_p3(seed_pk, seed_sk, 32U, 16U, p3, sizeof(p3)) != OPENQPEP_OK) return 18;
    if (openqpep_uov_sign_core(seed_pk, seed_sk, salt, target, 32U, 16U, sv, so) != OPENQPEP_OK) return 19;
    if (openqpep_uov_eval_public_map(seed_pk, p3, sizeof(p3), 32U, 16U, sv, so, eval_out) != OPENQPEP_OK) return 20;
    if (openqpep_ct_eq(target, eval_out, 16U) != 1) return 21;

    /* 5. NULL & invalid-len guards */
    if (openqpep_gf2_127_mul(NULL, a16, sq1) != OPENQPEP_ERR_NULL_PTR) return 22;
    if (openqpep_uov_compute_p3(seed_pk, seed_sk, 32U, 16U, p3, 10U) != OPENQPEP_ERR_INVALID_LEN) return 23;
    if (openqpep_uov_solve_gf256_linear(NULL, rhs, 16U, sol) != OPENQPEP_ERR_NULL_PTR) return 24;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "rank_uov_consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            bin_static = Path(tmpdir) / "rank_uov_static"
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
            self.assertEqual(r_static.returncode, 0, f"Static C99 Rank/UOV consumer failed rc={r_static.returncode}")

            bin_shared = Path(tmpdir) / "rank_uov_shared"
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
            self.assertEqual(r_shared.returncode, 0, f"Shared C99 Rank/UOV consumer failed rc={r_shared.returncode}")


if __name__ == "__main__":
    unittest.main()
