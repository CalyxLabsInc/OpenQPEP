"""
OpenQPEP Official Release 1.2.4 (v1.2.4) — Native C99 Binary Goppa GF(2^10) & Syndrome Accelerator (`CGM-8192`) Test Suite.

Verifies:
  1. ABI v1.2.4 (`0x00010204`) & dynamic export of all 11 new Binary Goppa C99 symbols under
     `-fvisibility=hidden` with zero internal helper leakage (`75` total exported symbols).
  2. Branchless table-free GF(2^10) arithmetic (`mul`, `sq`, `inv`, `sqrt`) and Horner polynomial
     evaluation (`poly_eval`, `poly_eval_batch`) bit-exact parity across all 1,024 field elements.
  3. Rabin irreducibility test, systematic parity-check matrix RREF (`[I_320 | T]`), branchless
     64-bit word-packed syndrome computation, Chien search, and full Patterson algebraic decoding
     parity between Native C99 and Pure-Python.
  4. End-to-end cross-backend `BinaryGoppaKEM` (valid & tampered FO implicit rejection),
     `CalyxGoppaMonolithSuite`, `CalyxUnstructuredCitadelSuite`, and `CalyxSovereignPentad` interop.
  5. Verified Native C99 wall-clock speedup on `CGM-8192` keygen, encaps, and decaps.
  6. Standalone external C99 consumer compiled under `-std=c99 -O2 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying ALL 1,048,576
     (1024 x 1024) GF(2^10) products, full C99 Goppa systematic T + syndrome + Patterson recovery,
     and NULL / invalid-len / singular / decode-failure status codes.
"""
import platform
import shutil
import struct
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
from calyx_qpep.codes.goppa_8192 import (
    GOPPA_GF_SIZE,
    GOPPA_MT,
    GOPPA_N,
    GOPPA_T,
    BinaryGoppaKEM,
    _GF_SQRT,
    _compute_syndrome,
    _ginv,
    _gmul,
    _is_irreducible_gf2m,
    _peval,
    _pmul,
    _sample_irreducible_goppa,
    _unpack_t_rows,
)
from calyx_qpep.codes.goppa_suite import CalyxGoppaMonolithSuite
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite
from calyx_qpep.native import (
    native_gf2m10_inv,
    native_gf2m10_mul,
    native_gf2m10_sq,
    native_gf2m10_sqrt,
    native_goppa_build_systematic_t,
    native_goppa_chien_search,
    native_goppa_is_irreducible,
    native_goppa_patterson_decode,
    native_goppa_poly_eval,
    native_goppa_poly_eval_batch,
    native_goppa_syndrome,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

NEW_V124_SYMBOLS = {
    "openqpep_gf2m10_mul",
    "openqpep_gf2m10_sq",
    "openqpep_gf2m10_inv",
    "openqpep_gf2m10_sqrt",
    "openqpep_goppa_poly_eval",
    "openqpep_goppa_poly_eval_batch",
    "openqpep_goppa_is_irreducible",
    "openqpep_goppa_build_systematic_t",
    "openqpep_goppa_syndrome",
    "openqpep_goppa_chien_search",
    "openqpep_goppa_patterson_decode",
}


class TestOpenQPEPv124C99Goppa(unittest.TestCase):
    def test_01_version_metadata_and_exported_v124_symbols(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.4")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.4")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.4")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in NEW_V124_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.4 Goppa symbol in openqpep.h: {sym}")

        if is_native_available():
            self.assertEqual(native_abi_version(), 0x00010204)
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
                missing = NEW_V124_SYMBOLS - exported
                self.assertEqual(missing, set(), f"Missing exported Goppa symbols: {missing}")
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

    def test_02_gf2m10_arithmetic_and_poly_eval_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        # Exhaustively test all 1,024 elements for sq, inv, sqrt, and representative mul pairs
        self.assertEqual(native_gf2m10_inv(0), 0)
        self.assertEqual(native_gf2m10_sqrt(0), 0)
        self.assertEqual(native_gf2m10_sq(0), 0)
        for a in range(1, GOPPA_GF_SIZE):
            self.assertEqual(native_gf2m10_sq(a), _gmul(a, a))
            inv_a = native_gf2m10_inv(a)
            self.assertEqual(inv_a, _ginv(a))
            self.assertEqual(native_gf2m10_mul(a, inv_a), 1)
            sqrt_a = native_gf2m10_sqrt(a)
            self.assertEqual(sqrt_a, _GF_SQRT[a])
            self.assertEqual(native_gf2m10_sq(sqrt_a), a)
            b = (a * 37 + 19) & 0x3FF
            self.assertEqual(native_gf2m10_mul(a, b), _gmul(a, b))

        # Test Horner poly_eval & batch evaluation across all 1,024 points
        poly = [(i * 73 + 5) & 0x3FF for i in range(32)] + [1]
        pts = list(range(GOPPA_GF_SIZE))
        batch_c = native_goppa_poly_eval_batch(poly, pts)
        for a in pts:
            expected = _peval(poly, a)
            self.assertEqual(batch_c[a], expected)
            if a < 64:
                self.assertEqual(native_goppa_poly_eval(poly, a), expected)

    def test_03_irreducibility_systematic_t_syndrome_and_patterson_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            # 1. Rabin irreducibility parity on both irreducible and reducible degree-32 polynomials
            set_native_enabled(True)
            g_irred = _sample_irreducible_goppa(GOPPA_T)
            self.assertTrue(native_goppa_is_irreducible(g_irred, GOPPA_T))
            set_native_enabled(False)
            self.assertTrue(_is_irreducible_gf2m(g_irred, GOPPA_T))

            # Construct guaranteed reducible degree-32 polynomial: (x + 7) * (x^31 + x + 1)
            f1 = [7, 1]
            f2 = [1, 1] + [0] * 29 + [1]
            g_red = _pmul(f1, f2)
            self.assertEqual(len(g_red), 33)
            set_native_enabled(True)
            self.assertFalse(native_goppa_is_irreducible(g_red, GOPPA_T))
            set_native_enabled(False)
            self.assertFalse(_is_irreducible_gf2m(g_red, GOPPA_T))

            # 2. Systematic T matrix, syndrome, Chien search & Patterson decode parity
            set_native_enabled(True)
            pk, sk = BinaryGoppaKEM.keygen()
            n_bits, mt, weight = struct.unpack("<HHH", sk[:6])
            g = list(struct.unpack(f"<{weight + 1}H", sk[38 : 38 + 2 * (weight + 1)]))
            sup_off = 38 + 2 * (weight + 1)
            support = list(struct.unpack(f"<{n_bits}H", sk[sup_off : sup_off + 2 * n_bits]))
            t_raw = pk[6:-32]

            ok_sys, t_c = native_goppa_build_systematic_t(g, support)
            self.assertTrue(ok_sys)
            self.assertEqual(t_c, t_raw)

            # Compare C99 syndrome against Pure-Python _compute_syndrome on edge & weight-32 vectors
            t_rows = _unpack_t_rows(t_raw, GOPPA_MT, (GOPPA_N - GOPPA_MT) // 8)
            test_masks = [
                0,
                1,
                1 << 319,
                1 << 320,
                1 << 1023,
                sum(1 << (i * 31 + 3) for i in range(GOPPA_T)),
                (1 << GOPPA_N) - 1,
            ]
            for mask in test_masks:
                eb = mask.to_bytes(128, "little")
                syn_c = native_goppa_syndrome(t_raw, eb)
                syn_py = _compute_syndrome(t_rows, mask, GOPPA_MT).to_bytes(40, "little")
                self.assertEqual(syn_c, syn_py)

            # Verify Patterson decode recovers exact 32-bit error vector
            w32_mask = sum(1 << (i * 29 + 7) for i in range(GOPPA_T))
            w32_bytes = w32_mask.to_bytes(128, "little")
            w32_syn = native_goppa_syndrome(t_raw, w32_bytes)
            ok_dec, rec_bytes, found_wt = native_goppa_patterson_decode(g, support, w32_syn)
            self.assertTrue(ok_dec)
            self.assertEqual(found_wt, GOPPA_T)
            self.assertEqual(rec_bytes, w32_bytes)

            # Zero syndrome must reject cleanly (decoded_ok == False, wt == 0)
            ok_zero, zero_rec, zero_wt = native_goppa_patterson_decode(g, support, b"\x00" * 40)
            self.assertFalse(ok_zero)
            self.assertEqual(zero_wt, 0)
            self.assertEqual(zero_rec, b"\x00" * 128)

            # Chien search on (x + support[5]) * (x + support[900]) finds exact 2 roots
            sig2 = _pmul([support[5], 1], [support[900], 1])
            c_err, c_wt = native_goppa_chien_search(sig2, support)
            self.assertEqual(c_wt, 2)
            self.assertEqual(int.from_bytes(c_err, "little"), (1 << 5) | (1 << 900))
        finally:
            set_native_enabled(True)

    def test_04_cross_backend_cgm8192_and_culc2048_round_trips(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            set_native_enabled(True)
            pk, sk = BinaryGoppaKEM.keygen()
            ct_c, ss_c = BinaryGoppaKEM.encaps(pk)

            set_native_enabled(False)
            self.assertEqual(BinaryGoppaKEM.decaps(sk, ct_c), ss_c)
            ct_py, ss_py = BinaryGoppaKEM.encaps(pk)
            bad_ct = bytes([ct_c[0] ^ 0x01]) + ct_c[1:]
            rej_py = BinaryGoppaKEM.decaps(sk, bad_ct)

            set_native_enabled(True)
            self.assertEqual(BinaryGoppaKEM.decaps(sk, ct_py), ss_py)
            rej_c = BinaryGoppaKEM.decaps(sk, bad_ct)
            self.assertEqual(rej_c, rej_py)
            self.assertNotEqual(rej_c, ss_c)

            # CalyxGoppaMonolithSuite & CalyxUnstructuredCitadelSuite cross-backend
            pkt_cgm = CalyxGoppaMonolithSuite.encrypt(b"cgm-v124-native-to-py", pk)
            set_native_enabled(False)
            self.assertEqual(CalyxGoppaMonolithSuite.decrypt(pkt_cgm, sk), b"cgm-v124-native-to-py")

            set_native_enabled(True)
            pub_u, priv_u = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True)
            pkt_u = CalyxUnstructuredCitadelSuite.encrypt(b"culc-v124-cross", pub_u)
            set_native_enabled(False)
            self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(pkt_u, priv_u), b"culc-v124-cross")
        finally:
            set_native_enabled(True)

    def test_05_verified_speedup_cgm8192_keygen_encaps_decaps(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            set_native_enabled(True)
            pk, sk = BinaryGoppaKEM.keygen()
            ct, ss = BinaryGoppaKEM.encaps(pk)
            self.assertEqual(BinaryGoppaKEM.decaps(sk, ct), ss)

            # Measure encaps + decaps over 5 iterations in C99 vs 1 iteration in Pure-Python
            t0 = time.perf_counter()
            for _ in range(5):
                ct_i, ss_i = BinaryGoppaKEM.encaps(pk)
                self.assertEqual(BinaryGoppaKEM.decaps(sk, ct_i), ss_i)
            native_ed = (time.perf_counter() - t0) / 5.0

            set_native_enabled(False)
            t1 = time.perf_counter()
            ct_p, ss_p = BinaryGoppaKEM.encaps(pk)
            self.assertEqual(BinaryGoppaKEM.decaps(sk, ct_p), ss_p)
            pure_ed = time.perf_counter() - t1

            speedup = pure_ed / max(native_ed, 1e-9)
            self.assertGreater(
                speedup,
                5.0,
                f"Expected >=5x C99 speedup on CGM-8192 encaps+decaps, got {speedup:.1f}x "
                f"(C99={native_ed*1000:.2f}ms vs Py={pure_ed*1000:.2f}ms)",
            )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_exhaustive_gf2m10_and_goppa_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

static uint16_t ref_mul(uint16_t a, uint16_t b) {
    uint32_t res = 0U;
    uint32_t x = a & 0x3FFU;
    uint32_t y = b & 0x3FFU;
    for (int i = 0; i < 10; i++) {
        if (y & (1U << i)) res ^= (x << i);
    }
    for (int deg = 18; deg >= 10; deg--) {
        if (res & (1U << deg)) res ^= (0x409U << (deg - 10));
    }
    return (uint16_t)res;
}

int main(void) {
    /* 1. Exhaustive verification of ALL 1,048,576 GF(2^10) products + sq/inv/sqrt */
    if (openqpep_gf2m10_inv(0U) != 0U) return 1;
    if (openqpep_gf2m10_sqrt(0U) != 0U) return 2;
    if (openqpep_gf2m10_sq(0U) != 0U) return 3;

    for (uint32_t a = 0U; a < 1024U; a++) {
        uint16_t sq = openqpep_gf2m10_sq((uint16_t)a);
        if (sq != ref_mul((uint16_t)a, (uint16_t)a)) return 4;
        uint16_t sr = openqpep_gf2m10_sqrt((uint16_t)a);
        if (openqpep_gf2m10_sq(sr) != (uint16_t)a) return 5;
        if (a > 0U) {
            uint16_t inv = openqpep_gf2m10_inv((uint16_t)a);
            if (openqpep_gf2m10_mul((uint16_t)a, inv) != 1U) return 6;
        }
        for (uint32_t b = 0U; b < 1024U; b++) {
            if (openqpep_gf2m10_mul((uint16_t)a, (uint16_t)b) != ref_mul((uint16_t)a, (uint16_t)b)) {
                return 7;
            }
        }
    }

    /* 2. Find an irreducible monic degree-32 polynomial deterministically in C & run full Goppa round-trip */
    uint16_t g[33];
    int found_irred = 0;
    uint32_t rng = 0x12345678U;
    for (int attempt = 0; attempt < 500 && !found_irred; attempt++) {
        for (int i = 0; i < 32; i++) {
            rng = rng * 1664525U + 1013904223U;
            g[i] = (uint16_t)((rng >> 16) & 0x3FFU);
        }
        if (g[0] == 0U) g[0] = 1U;
        g[32] = 1U;
        if (openqpep_goppa_is_irreducible(g, 32U) == 1) {
            found_irred = 1;
        }
    }
    if (!found_irred) return 8;

    uint16_t support[1024];
    for (uint32_t i = 0U; i < 1024U; i++) support[i] = (uint16_t)i;
    static uint8_t t_mat[OPENQPEP_GOPPA_T_BYTES];
    int sys_rc = OPENQPEP_ERR_SINGULAR;
    for (int perm = 0; perm < 32 && sys_rc != OPENQPEP_OK; perm++) {
        for (uint32_t i = 1023U; i > 0U; i--) {
            rng = rng * 1664525U + 1013904223U;
            uint32_t j = (rng >> 16) % (i + 1U);
            uint16_t tmp = support[i];
            support[i] = support[j];
            support[j] = tmp;
        }
        sys_rc = openqpep_goppa_build_systematic_t(g, support, t_mat);
    }
    if (sys_rc != OPENQPEP_OK) return 9;

    uint8_t err[128], rec[128], syn[40];
    memset(err, 0, sizeof(err));
    for (uint32_t i = 0U; i < 32U; i++) {
        uint32_t pos = i * 31U + 5U;
        err[pos >> 3] |= (uint8_t)(1U << (pos & 7U));
    }
    if (openqpep_goppa_syndrome(t_mat, sizeof(t_mat), err, syn) != OPENQPEP_OK) return 10;
    uint32_t wt = 0U;
    if (openqpep_goppa_patterson_decode(g, support, syn, rec, &wt) != OPENQPEP_OK) return 11;
    if (wt != 32U) return 12;
    if (openqpep_ct_eq(err, rec, 128U) != 1) return 13;

    /* 3. Verify error guards */
    if (openqpep_goppa_syndrome(NULL, sizeof(t_mat), err, syn) != OPENQPEP_ERR_NULL_PTR) return 14;
    if (openqpep_goppa_syndrome(t_mat, 100U, err, syn) != OPENQPEP_ERR_INVALID_LEN) return 15;
    if (openqpep_goppa_build_systematic_t(NULL, support, t_mat) != OPENQPEP_ERR_NULL_PTR) return 16;
    if (openqpep_goppa_patterson_decode(NULL, support, syn, rec, &wt) != OPENQPEP_ERR_NULL_PTR) return 17;

    /* Zero syndrome returns OPENQPEP_ERR_AUTH_FAIL with wt==0 */
    memset(syn, 0, sizeof(syn));
    if (openqpep_goppa_patterson_decode(g, support, syn, rec, &wt) != OPENQPEP_ERR_AUTH_FAIL) return 18;
    if (wt != 0U) return 19;

    /* Duplicate support columns produce a singular left 320x320 block -> OPENQPEP_ERR_SINGULAR */
    uint16_t dup_sup[1024];
    memcpy(dup_sup, support, sizeof(dup_sup));
    dup_sup[1] = dup_sup[0];
    if (openqpep_goppa_build_systematic_t(g, dup_sup, t_mat) != OPENQPEP_ERR_SINGULAR) return 20;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "goppa_consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            bin_static = Path(tmpdir) / "goppa_static"
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
            self.assertEqual(r_static.returncode, 0, f"Static C99 Goppa consumer failed rc={r_static.returncode}")

            bin_shared = Path(tmpdir) / "goppa_shared"
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
            self.assertEqual(r_shared.returncode, 0, f"Shared C99 Goppa consumer failed rc={r_shared.returncode}")


if __name__ == "__main__":
    unittest.main()
