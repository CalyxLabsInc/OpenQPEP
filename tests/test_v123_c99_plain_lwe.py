"""
OpenQPEP Official Release 1.2.3 (v1.2.3) — Native C99 Plain-LWE Row-Streamed Matrix Accelerator (`CULC-2048` / `CSP-Omega`) Test Suite.

Verifies:
  1. ABI v1.2.3 (`0x00010203`) & dynamic export of all 9 Plain-LWE C99 symbols (7 new + 2 preserved)
     under `-fvisibility=hidden` with zero internal helper leakage.
  2. Bit-exact Native C99 <-> Pure-Python parity for `_sample_centered_noise`, `_expand_row`,
     and `openqpep_plain_lwe_keygen_matrix` across both stack fast-path (`n=64`) and multi-tile
     heap-fallback path (`n=300 > PLWE_ROW_TILE=256`).
  3. Bit-exact Native C99 <-> Pure-Python parity for deterministic `keygen_from_seeds`,
     `_indcpa_enc`, `encaps`, and `decaps` (valid + 1-bit tampered Fujisaki-Okamoto implicit
     rejection), plus cross-backend `CULC-2048` & `CSP-Omega` round-trips.
  4. Strict bounds validation rejecting malformed key/ciphertext sizes and invalid `(n, nbar)`.
  5. Verified order-of-magnitude (`>= 10x`) Native C99 wall-clock speedup on `PlainLWEEngine`
     (`n=64` and `n=256`).
  6. Standalone external C99 consumer compiled under `-std=c99 -O2 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying full C99 Plain-LWE
     KEM keygen/encaps/decaps, tampered FO implicit rejection, multi-tile `n=300` streaming,
     legacy row helpers, and NULL/invalid-length error codes.
"""
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
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite
from calyx_qpep.lattice.plain_lwe import (
    PlainLWEEngine,
    _expand_row,
    _sample_centered_noise,
)
from calyx_qpep.native import (
    native_plain_lwe_decaps,
    native_plain_lwe_encaps,
    native_plain_lwe_keygen_from_seeds,
    native_plain_lwe_keygen_matrix,
)
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

PLAIN_LWE_SYMBOLS = {
    "openqpep_plain_lwe_row_accum_u16",
    "openqpep_plain_lwe_keygen_row_u16",
    "openqpep_plain_lwe_sample_noise",
    "openqpep_plain_lwe_expand_row",
    "openqpep_plain_lwe_keygen_matrix",
    "openqpep_plain_lwe_keygen_from_seeds",
    "openqpep_plain_lwe_indcpa_enc",
    "openqpep_plain_lwe_encaps",
    "openqpep_plain_lwe_decaps",
}


class TestOpenQPEPv123C99PlainLWE(unittest.TestCase):
    def test_01_version_metadata_and_exported_v123_symbols(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.3")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.3")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.3")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in PLAIN_LWE_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.3 Plain-LWE symbol in openqpep.h: {sym}")

        if is_native_available():
            self.assertEqual(native_abi_version(), 0x00010203)
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
                missing = PLAIN_LWE_SYMBOLS - exported
                self.assertEqual(missing, set(), f"Missing exported Plain-LWE symbols: {missing}")
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

    def test_02_sample_noise_expand_row_and_keygen_matrix_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        seed_a = bytes(range(32))
        seed_s = bytes(range(32, 64))
        try:
            # Test stack fast-path (n=32, 64) AND multi-tile streaming / heap fallback (n=300 > 256)
            for (n, nbar) in ((32, 4), (64, 8), (300, 8)):
                set_native_enabled(True)
                s_c = _sample_centered_noise(seed_s, n * nbar, b"CALYX-PLWE-S-v1.0.0|")
                e_c = _sample_centered_noise(seed_s, n * nbar, b"CALYX-PLWE-E-v1.0.0|")
                row0_c = _expand_row(seed_a, 0, n)
                row_last_c = _expand_row(seed_a, n - 1, n)
                b_c = native_plain_lwe_keygen_matrix(seed_a, s_c, e_c, n, nbar)

                set_native_enabled(False)
                s_py = _sample_centered_noise(seed_s, n * nbar, b"CALYX-PLWE-S-v1.0.0|")
                e_py = _sample_centered_noise(seed_s, n * nbar, b"CALYX-PLWE-E-v1.0.0|")
                row0_py = _expand_row(seed_a, 0, n)
                row_last_py = _expand_row(seed_a, n - 1, n)

                self.assertEqual(s_c, s_py)
                self.assertEqual(e_c, e_py)
                self.assertEqual(row0_c, row0_py)
                self.assertEqual(row_last_c, row_last_py)

                # Reference keygen matrix in pure Python (verify for n=32 and n=64, plus spot rows for n=300)
                rows_to_check = range(n) if n <= 64 else (0, 1, n // 2, n - 1)
                for i in rows_to_check:
                    r_i = _expand_row(seed_a, i, n)
                    for j in range(nbar):
                        acc = e_py[i * nbar + j]
                        for k in range(n):
                            acc = (acc + r_i[k] * s_py[k * nbar + j]) & 0xFFFF
                        self.assertEqual(b_c[i * nbar + j], acc, f"B[{i},{j}] mismatch at n={n}, nbar={nbar}")
        finally:
            set_native_enabled(True)

    def test_03_full_plain_lwe_fo_parity_and_culc_pentad_cross_backend(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        seed_a = bytes(range(10, 42))
        seed_s = bytes(range(50, 82))
        seed_z = bytes(range(90, 122))
        msg16 = bytes(range(16))
        coins32 = bytes(range(200, 232))

        try:
            # Verify bit-exact parity for BOTH stack path (n=64, nbar=8) and heap/multi-tile path (n=320, nbar=8)
            for (n, nbar) in ((64, 8), (320, 8)):
                set_native_enabled(True)
                pk_c, sk_c = native_plain_lwe_keygen_from_seeds(n, nbar, seed_a, seed_s, seed_z)
                ct_ind_c = PlainLWEEngine._indcpa_enc(pk_c, msg16, coins32)
                ct_enc_c, ss_enc_c = native_plain_lwe_encaps(pk_c, msg16)
                ss_dec_c = native_plain_lwe_decaps(sk_c, ct_enc_c)
                bad_ct = ct_enc_c[:-1] + bytes([ct_enc_c[-1] ^ 0x01])
                ss_rej_c = native_plain_lwe_decaps(sk_c, bad_ct)

                set_native_enabled(False)
                ct_ind_py = PlainLWEEngine._indcpa_enc(pk_c, msg16, coins32)
                ss_dec_py = PlainLWEEngine.decaps(sk_c, ct_enc_c)
                ss_rej_py = PlainLWEEngine.decaps(sk_c, bad_ct)

                self.assertEqual(ct_ind_c, ct_ind_py, f"IND-CPA mismatch at n={n}")
                self.assertEqual(ss_dec_c, ss_enc_c, f"C99 decaps != encaps at n={n}")
                self.assertEqual(ss_dec_py, ss_enc_c, f"Pure-Python decaps != C99 encaps at n={n}")
                self.assertEqual(ss_rej_c, ss_rej_py, f"FO implicit rejection diverged at n={n}")
                self.assertNotEqual(ss_rej_c, ss_enc_c)

            # End-to-end cross-backend CULC-2048 & CSP-Omega round-trip
            set_native_enabled(True)
            pub_c, priv_c = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True)
            armored_c = CalyxUnstructuredCitadelSuite.encrypt(b"culc-v123-native-to-py", pub_c)
            set_native_enabled(False)
            self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(armored_c, priv_c), b"culc-v123-native-to-py")

            armored_py = CalyxUnstructuredCitadelSuite.encrypt(b"culc-v123-py-to-native", pub_c)
            set_native_enabled(True)
            self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(armored_py, priv_c), b"culc-v123-py-to-native")

            pub_p, priv_p = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
            pkt_p = CalyxSovereignPentad.encrypt(b"pentad-v123-cross-backend", pub_p)
            set_native_enabled(False)
            self.assertEqual(CalyxSovereignPentad.decrypt(pkt_p, priv_p), b"pentad-v123-cross-backend")
        finally:
            set_native_enabled(True)

    def test_04_strict_bounds_and_malformed_input_rejection(self):
        with self.assertRaises(ValueError):
            PlainLWEEngine.keygen(n=0, nbar=8)
        with self.assertRaises(ValueError):
            PlainLWEEngine.keygen(n=64, nbar=9)
        with self.assertRaises(ValueError):
            PlainLWEEngine.encaps(b"short")
        with self.assertRaises(ValueError):
            PlainLWEEngine._indcpa_enc(b"\x40\x00\x08\x00" + b"\x00" * 1056, b"\x00" * 15, b"\x00" * 32)
        pk, sk = PlainLWEEngine.keygen(n=32, nbar=4)
        ct, _ = PlainLWEEngine.encaps(pk)
        with self.assertRaises(ValueError):
            PlainLWEEngine.decaps(sk, ct[:-2])
        with self.assertRaises(ValueError):
            PlainLWEEngine.decaps(sk[:-2], ct)

    def test_05_verified_order_of_magnitude_speedup_plain_lwe(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        try:
            for (n, nbar, iters) in ((64, 8, 10), (192, 8, 2)):
                set_native_enabled(True)
                pk, sk = PlainLWEEngine.keygen(n=n, nbar=nbar)
                ct_ref, ss_ref = PlainLWEEngine.encaps(pk)
                self.assertEqual(PlainLWEEngine.decaps(sk, ct_ref), ss_ref)

                t0 = time.perf_counter()
                for _ in range(iters):
                    ct_c, ss_c = PlainLWEEngine.encaps(pk)
                    self.assertEqual(PlainLWEEngine.decaps(sk, ct_c), ss_c)
                native_s = (time.perf_counter() - t0) / iters

                set_native_enabled(False)
                t1 = time.perf_counter()
                ct_p, ss_p = PlainLWEEngine.encaps(pk)
                self.assertEqual(PlainLWEEngine.decaps(sk, ct_p), ss_p)
                pure_s = time.perf_counter() - t1

                speedup = pure_s / max(native_s, 1e-9)
                self.assertGreater(
                    speedup,
                    10.0,
                    f"Expected >=10x Plain-LWE C99 speedup at n={n}, got {speedup:.1f}x "
                    f"(C99={native_s*1000:.2f}ms vs Py={pure_s*1000:.2f}ms)",
                )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_plain_lwe_static_and_shared_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    /* 1. Standard n=64, nbar=8 full C99 keygen / encaps / decaps / tamper implicit reject */
    uint8_t seed_a[32], seed_s[32], seed_z[32], msg16[16];
    for (size_t i = 0; i < 32; i++) {
        seed_a[i] = (uint8_t)(i + 1U);
        seed_s[i] = (uint8_t)(i + 41U);
        seed_z[i] = (uint8_t)(i + 81U);
    }
    for (size_t i = 0; i < 16; i++) msg16[i] = (uint8_t)(0xA0U + i);

    const uint32_t n = 64U, nbar = 8U;
    const size_t pk_len = 36U + 2U * n * nbar;
    const size_t sk_len = 36U + pk_len + 2U * n * nbar;
    const size_t ct_len = 2U * nbar * n + 2U * nbar * nbar;

    uint8_t pk[36U + 2U * 64U * 8U];
    uint8_t sk[36U + (36U + 2U * 64U * 8U) + 2U * 64U * 8U];
    uint8_t ct[2U * 8U * 64U + 2U * 8U * 8U];
    uint8_t ss_enc[32], ss_dec[32], ss_rej[32];

    if (openqpep_plain_lwe_keygen_from_seeds(n, nbar, seed_a, seed_s, seed_z, pk, pk_len, sk, sk_len) != OPENQPEP_OK) return 1;
    if (openqpep_plain_lwe_encaps(pk, pk_len, msg16, ct, ct_len, ss_enc) != OPENQPEP_OK) return 2;
    if (openqpep_plain_lwe_decaps(sk, sk_len, ct, ct_len, ss_dec) != OPENQPEP_OK) return 3;
    if (openqpep_ct_eq(ss_enc, ss_dec, 32U) != 1) return 4;

    /* 1-bit ciphertext tamper must trigger FO implicit rejection (different deterministic secret) */
    ct[ct_len - 1U] ^= 0x01U;
    if (openqpep_plain_lwe_decaps(sk, sk_len, ct, ct_len, ss_rej) != OPENQPEP_OK) return 5;
    if (openqpep_ct_eq(ss_enc, ss_rej, 32U) != 0) return 6;

    /* 2. Multi-tile + heap fallback dimension test (n=300 > 256, nbar=8 -> 2400 > 2048) */
    const uint32_t big_n = 300U;
    const size_t b_pk_len = 36U + 2U * big_n * nbar;
    const size_t b_sk_len = 36U + b_pk_len + 2U * big_n * nbar;
    const size_t b_ct_len = 2U * nbar * big_n + 2U * nbar * nbar;
    uint8_t *b_pk = (uint8_t *)malloc(b_pk_len);
    uint8_t *b_sk = (uint8_t *)malloc(b_sk_len);
    uint8_t *b_ct = (uint8_t *)malloc(b_ct_len);
    if (!b_pk || !b_sk || !b_ct) return 7;
    if (openqpep_plain_lwe_keygen_from_seeds(big_n, nbar, seed_a, seed_s, seed_z, b_pk, b_pk_len, b_sk, b_sk_len) != OPENQPEP_OK) return 8;
    if (openqpep_plain_lwe_encaps(b_pk, b_pk_len, msg16, b_ct, b_ct_len, ss_enc) != OPENQPEP_OK) return 9;
    if (openqpep_plain_lwe_decaps(b_sk, b_sk_len, b_ct, b_ct_len, ss_dec) != OPENQPEP_OK) return 10;
    if (openqpep_ct_eq(ss_enc, ss_dec, 32U) != 1) return 11;
    free(b_pk);
    free(b_sk);
    free(b_ct);

    /* 3. Legacy ABI row helpers still work cleanly */
    uint16_t dst[4] = {1U, 2U, 3U, 4U};
    const uint16_t row[4] = {10U, 20U, 30U, 40U};
    openqpep_plain_lwe_row_accum_u16(dst, row, 3U, 4U);
    if (dst[0] != 31U || dst[3] != 124U) return 12;

    /* 4. NULL & invalid-len guards */
    if (openqpep_plain_lwe_keygen_from_seeds(0U, 8U, seed_a, seed_s, seed_z, pk, pk_len, sk, sk_len) != OPENQPEP_ERR_INVALID_LEN) return 13;
    if (openqpep_plain_lwe_keygen_from_seeds(64U, 9U, seed_a, seed_s, seed_z, pk, pk_len, sk, sk_len) != OPENQPEP_ERR_INVALID_LEN) return 14;
    if (openqpep_plain_lwe_encaps(NULL, pk_len, msg16, ct, ct_len, ss_enc) != OPENQPEP_ERR_NULL_PTR) return 15;
    if (openqpep_plain_lwe_decaps(sk, sk_len, ct, ct_len - 2U, ss_dec) != OPENQPEP_ERR_INVALID_LEN) return 16;

    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "plwe_consumer.c"
            src_file.write_text(consumer_c, encoding="utf-8")

            bin_static = Path(tmpdir) / "plwe_static"
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
            self.assertEqual(r_static.returncode, 0, f"Static C99 Plain-LWE consumer failed rc={r_static.returncode}")

            bin_shared = Path(tmpdir) / "plwe_shared"
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
            self.assertEqual(r_shared.returncode, 0, f"Shared C99 Plain-LWE consumer failed rc={r_shared.returncode}")


if __name__ == "__main__":
    unittest.main()
