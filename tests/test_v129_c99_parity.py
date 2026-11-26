"""
OpenQPEP Official Release 1.2.9 (v1.2.9) — Phase 2 Consolidation Gate:
Performance Benchmark Refresh & 100% Native C99 / Pure-Python Parity Gate.

Consolidates and locks every Phase 2 (`v1.2.0` -> `v1.2.9`) C99/SIMD SDK invariant:
  1. Stable ABI v1.2.9 (`0x00010209`), complete SDK artifacts (`libopenqpep.so`, `libopenqpep.a`,
     `openqpep.pc`, `include/openqpep.h`), and 108/108 dynamically exported `openqpep_*` symbols
     with zero internal symbol leakage.
  2. 10/10 Deterministic Golden KAT verification bit-for-bit under BOTH Native C99 (`libopenqpep`)
     and Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`) with zero `mlock` page leaks.
  3. Full bidirectional Native C99 <-> Pure-Python encrypt/decrypt & sign/verify cross-backend
     interoperability across ALL 10 canonical suites (`QLX-768..16384`, `CIF-SQI-512`, `CRT-RSD512`,
     `CGM-8192`, `CULC-2048`, `CSP-Omega`).
  4. Byte-for-byte deterministic keygen, encaps/decaps, signing (hedged + deterministic), Wire v5,
     Compact TLV v5.1, and `CC-512` CMT-4 / SIV equality under `deterministic_urandom`.
  5. Refreshed 10-suite `benchmarks/benchmark_results.json` schema, Peak RSS ceilings, and
     verified Native C99/SIMD vs Pure-Python speedup ratios across Phase 2 accelerated families.
  6. Live comparative benchmark execution & Markdown export (`bench_suites.py`).
  7. Standalone C99 self-test harness (`12/12` suites, `108/108` APIs) + 5-language interop matrix.
  8. CI pipeline enforcement of Phase 1, Phase 2 parity, and ASan+UBSan sanitizer gates.
"""
import json
import os
import platform
import shutil
import subprocess
import unittest
from pathlib import Path

from benchmarks.bench_suites import (
    ALL_BENCH_SUITE_IDS,
    format_comparative_markdown_table,
    format_markdown_table,
    run_comparative_benchmarks,
)
from calyx_qpep import (
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    cc512_decrypt,
    cc512_encrypt,
    cc512_siv_decrypt,
    cc512_siv_encrypt,
    is_native_available,
    memory_security_status,
    native_abi_version,
    set_native_enabled,
)
from calyx_qpep.audit import run_cross_language_interop_matrix
from calyx_qpep.codes.goppa_8192 import BinaryGoppaKEM
from calyx_qpep.codes.goppa_suite import CalyxGoppaMonolithSuite
from calyx_qpep.codes.rank_rsd512 import RankMetricKEM
from calyx_qpep.codes.rank_suite import CalyxRankMetricSuite
from calyx_qpep.hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from calyx_qpep.isogeny.isogeny_suite import CalyxIsogenyForgeSuite
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite
from calyx_qpep.lattice.plain_lwe import PlainLWEEngine
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.multivariate.qmq_512 import MultivariateQuadraticEngine
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad
from calyx_qpep.vectors import deterministic_urandom, verify_all_kats
from calyx_qpep.wire.compact_v51 import pack_compact_v51, unpack_compact_v51
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
VECTORS_DIR = REPO_ROOT / "vectors"
BENCH_JSON_PATH = REPO_ROOT / "benchmarks" / "benchmark_results.json"
CI_YML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class TestOpenQPEPv129Phase2ParityGate(unittest.TestCase):
    def test_01_phase2_abi_v129_108_symbols_and_sdk_artifacts(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")
        self.assertTrue((CSRC_DIR / "include" / "openqpep.h").is_file())
        self.assertTrue((CSRC_DIR / "openqpep.pc.in").is_file())
        self.assertTrue((CSRC_DIR / "test_openqpep_c.c").is_file())

        if is_native_available():
            self.assertGreaterEqual(native_abi_version(), 0x00010209)
            ext = "dylib" if platform.system() == "Darwin" else "so"
            shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
            static_lib = NATIVE_DIR / "libopenqpep.a"
            pc_file = NATIVE_DIR / "openqpep.pc"
            self.assertTrue(shared_lib.is_file(), f"Missing shared library: {shared_lib}")
            self.assertTrue(static_lib.is_file(), f"Missing static library: {static_lib}")
            self.assertTrue(pc_file.is_file(), f"Missing pkg-config file: {pc_file}")

            if shutil.which("nm"):
                res = subprocess.run(
                    ["nm", "-D", "--defined-only", str(shared_lib)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                exported = {
                    line.split()[2].split("@")[0]
                    for line in res.stdout.splitlines()
                    if len(line.split()) >= 3
                    and line.split()[1] in ("T", "D", "R", "B")
                    and not line.split()[2].startswith("_")
                }
                self.assertGreaterEqual(len(exported), 108)
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked non-openqpep symbols: {leaked}")

    def test_02_10_of_10_golden_kats_bit_exact_native_c99_and_pure_python(self):
        prev_native = is_native_available()
        baseline_locks = memory_security_status()["active_locked_pages"]
        try:
            modes = [True, False] if prev_native else [False]
            reports = {}
            for native_mode in modes:
                set_native_enabled(native_mode)
                ok, report = verify_all_kats(VECTORS_DIR)
                self.assertTrue(ok, f"Golden KAT failure under native={native_mode}:\n" + "\n".join(report))
                self.assertEqual(len(report), 10)
                reports[native_mode] = report
            if prev_native:
                self.assertEqual(reports[True], reports[False], "Native C99 and Pure-Python KAT reports diverged.")
            self.assertEqual(
                memory_security_status()["active_locked_pages"],
                baseline_locks,
                "mlock page leak detected after dual-backend Golden KAT verification.",
            )
        finally:
            set_native_enabled(prev_native)

    def test_03_cross_backend_encrypt_decrypt_and_sign_verify_all_10_suites(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        witness = b"\xC9" * 64
        msg = b"OpenQPEP v1.2.9 Phase 2 All-10-Suite Bidirectional Cross-Backend Parity Payload"
        try:
            # 1-5. All 5 Lattice Module-LWE + QVS tiers (including QLX-16384 + QVS-1024)
            for qlx_tier, qvs_tier in (
                ("QLX-768", "QVS-65"),
                ("QLX-1024", "QVS-87"),
                ("QLX-2048", "QVS-128"),
                ("QLX-4096", "QVS-256"),
                ("QLX-16384", "QVS-1024"),
            ):
                set_native_enabled(True)
                ek, dk = QLXEngine.keygen(qlx_tier, witness)
                pk_s, sk_s = QVSEngine.keygen(qvs_tier, witness)
                ct_c, ss_c = QLXEngine.encaps(ek, qlx_tier)
                sig_c = QVSEngine.sign(sk_s, pk_s, msg, tier=qvs_tier)

                set_native_enabled(False)
                self.assertEqual(QLXEngine.decaps(dk, ct_c, qlx_tier), ss_c, f"{qlx_tier} C99->Py decaps mismatch")
                self.assertTrue(QVSEngine.verify(pk_s, msg, sig_c, tier=qvs_tier), f"{qvs_tier} C99->Py verify failed")
                ct_p, ss_p = QLXEngine.encaps(ek, qlx_tier)
                sig_p = QVSEngine.sign(sk_s, pk_s, msg, tier=qvs_tier)

                set_native_enabled(True)
                self.assertEqual(QLXEngine.decaps(dk, ct_p, qlx_tier), ss_p, f"{qlx_tier} Py->C99 decaps mismatch")
                self.assertTrue(QVSEngine.verify(pk_s, msg, sig_p, tier=qvs_tier), f"{qvs_tier} Py->C99 verify failed")

            # 6. CIF-SQI-512 + QHS-512
            set_native_enabled(True)
            iso_pub, iso_priv = CalyxIsogenyForgeSuite.keygen()
            iso_ct_c = CalyxIsogenyForgeSuite.encrypt(msg, iso_pub)
            iso_sig_c = CalyxIsogenyForgeSuite.sign(msg, iso_priv)
            set_native_enabled(False)
            self.assertEqual(CalyxIsogenyForgeSuite.decrypt(iso_ct_c, iso_priv), msg)
            ok, out = CalyxIsogenyForgeSuite.verify(iso_sig_c, iso_pub)
            self.assertTrue(ok and out == msg)
            iso_ct_p = CalyxIsogenyForgeSuite.encrypt(msg, iso_pub)
            iso_sig_p = CalyxIsogenyForgeSuite.sign(msg, iso_priv)
            set_native_enabled(True)
            self.assertEqual(CalyxIsogenyForgeSuite.decrypt(iso_ct_p, iso_priv), msg)
            ok, out = CalyxIsogenyForgeSuite.verify(iso_sig_p, iso_pub)
            self.assertTrue(ok and out == msg)

            # 7. CRT-RSD512 + QMQ-512
            set_native_enabled(True)
            rm_pk, rm_sk = CalyxRankMetricSuite.keygen()
            mq_pk, mq_sk = MultivariateQuadraticEngine.keygen()
            rm_ct_c = CalyxRankMetricSuite.encrypt(msg, rm_pk)
            mq_sig_c = MultivariateQuadraticEngine.sign(mq_sk, msg)
            set_native_enabled(False)
            self.assertEqual(CalyxRankMetricSuite.decrypt(rm_ct_c, rm_sk), msg)
            self.assertTrue(MultivariateQuadraticEngine.verify(mq_pk, msg, mq_sig_c))
            rm_ct_p = CalyxRankMetricSuite.encrypt(msg, rm_pk)
            mq_sig_p = MultivariateQuadraticEngine.sign(mq_sk, msg)
            set_native_enabled(True)
            self.assertEqual(CalyxRankMetricSuite.decrypt(rm_ct_p, rm_sk), msg)
            self.assertTrue(MultivariateQuadraticEngine.verify(mq_pk, msg, mq_sig_p))

            # 8. CGM-8192 + QHS-512
            set_native_enabled(True)
            gm_pk, gm_sk = CalyxGoppaMonolithSuite.keygen()
            qhs_pk, qhs_sk = QHS512HypertreeEngine.keygen(height=4)
            gm_ct_c = CalyxGoppaMonolithSuite.encrypt(msg, gm_pk)
            qhs_sig_c = QHS512HypertreeEngine.sign(qhs_sk, msg)
            set_native_enabled(False)
            self.assertEqual(CalyxGoppaMonolithSuite.decrypt(gm_ct_c, gm_sk), msg)
            self.assertTrue(QHS512HypertreeEngine.verify(qhs_pk, msg, qhs_sig_c))
            gm_ct_p = CalyxGoppaMonolithSuite.encrypt(msg, gm_pk)
            qhs_sig_p = QHS512HypertreeEngine.sign(qhs_sk, msg)
            set_native_enabled(True)
            self.assertEqual(CalyxGoppaMonolithSuite.decrypt(gm_ct_p, gm_sk), msg)
            self.assertTrue(QHS512HypertreeEngine.verify(qhs_pk, msg, qhs_sig_p))

            # 9. CULC-2048 + CGM-8192
            set_native_enabled(True)
            cit_pub, cit_priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True)
            cit_ct_c = CalyxUnstructuredCitadelSuite.encrypt(msg, cit_pub)
            cit_sig_c = CalyxUnstructuredCitadelSuite.sign(msg, cit_priv)
            set_native_enabled(False)
            self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(cit_ct_c, cit_priv), msg)
            ok, out = CalyxUnstructuredCitadelSuite.verify(cit_sig_c, cit_pub)
            self.assertTrue(ok and out == msg)
            cit_ct_p = CalyxUnstructuredCitadelSuite.encrypt(msg, cit_pub)
            cit_sig_p = CalyxUnstructuredCitadelSuite.sign(msg, cit_priv)
            set_native_enabled(True)
            self.assertEqual(CalyxUnstructuredCitadelSuite.decrypt(cit_ct_p, cit_priv), msg)
            ok, out = CalyxUnstructuredCitadelSuite.verify(cit_sig_p, cit_pub)
            self.assertTrue(ok and out == msg)

            # 10. CSP-Omega + QHS-512
            set_native_enabled(True)
            p_pub, p_priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
            p_ct_c = CalyxSovereignPentad.encrypt(msg, p_pub)
            p_sig_c = CalyxSovereignPentad.sign(msg, p_pub, p_priv)
            set_native_enabled(False)
            self.assertEqual(CalyxSovereignPentad.decrypt(p_ct_c, p_priv), msg)
            ok, out = CalyxSovereignPentad.verify(p_sig_c, p_pub)
            self.assertTrue(ok and out == msg)
            p_ct_p = CalyxSovereignPentad.encrypt(msg, p_pub)
            p_sig_p = CalyxSovereignPentad.sign(msg, p_pub, p_priv)
            set_native_enabled(True)
            self.assertEqual(CalyxSovereignPentad.decrypt(p_ct_p, p_priv), msg)
            ok, out = CalyxSovereignPentad.verify(p_sig_p, p_pub)
            self.assertTrue(ok and out == msg)
        finally:
            set_native_enabled(True)

    def test_04_deterministic_byte_exact_c99_vs_pure_python_all_primitives(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        seed = b"OpenQPEP-v129-Phase2-DRBG-Seed!!"
        witness = b"\x37" * 64
        msg = b"Deterministic Native C99 vs Pure-Python Byte-Exact Parity Check"
        key64 = bytes(range(64))
        nonce24 = bytes(range(24))

        def _capture_all(native_flag: bool):
            set_native_enabled(native_flag)
            with deterministic_urandom(seed):
                ek_q, dk_q = QLXEngine.keygen("QLX-768", witness)
                ct_q, ss_q = QLXEngine.encaps(ek_q, "QLX-768")
                dec_q = QLXEngine.decaps(dk_q, ct_q, "QLX-768")

                pk_v, sk_v = QVSEngine.keygen("QVS-65", witness)
                sig_v_h = QVSEngine.sign(sk_v, pk_v, msg, tier="QVS-65", hedged=True)
                sig_v_d = QVSEngine.sign(sk_v, pk_v, msg, tier="QVS-65", hedged=False)

                pk_l, sk_l = PlainLWEEngine.keygen(n=64, nbar=8)
                ct_l, ss_l = PlainLWEEngine.encaps(pk_l)
                rej_l = PlainLWEEngine.decaps(sk_l, bytes([ct_l[0] ^ 0x01]) + ct_l[1:])

                pk_g, sk_g = BinaryGoppaKEM.keygen()
                ct_g, ss_g = BinaryGoppaKEM.encaps(pk_g)
                rej_g = BinaryGoppaKEM.decaps(sk_g, bytes([ct_g[0] ^ 0x01]) + ct_g[1:])

                pk_r, sk_r = RankMetricKEM.keygen()
                ct_r, ss_r = RankMetricKEM.encaps(pk_r)
                rej_r = RankMetricKEM.decaps(sk_r, bytes([ct_r[0] ^ 0x01]) + ct_r[1:])

                pk_m, sk_m = MultivariateQuadraticEngine.keygen()
                sig_m_h = MultivariateQuadraticEngine.sign(sk_m, msg, hedged=True)
                sig_m_d = MultivariateQuadraticEngine.sign(sk_m, msg, hedged=False)

                pk_h, sk_h = QHS512HypertreeEngine.keygen(height=4)
                sig_h_h = QHS512HypertreeEngine.sign(sk_h, msg, hedged=True)
                sig_h_d = QHS512HypertreeEngine.sign(sk_h, msg, hedged=False)

                w5 = pack_wire_frame(msg, "CALYX QPEP MESSAGE", packet_type=1, flags=0)
                w5_pt, _ = unpack_wire_frame(w5, "CALYX QPEP MESSAGE")
                w51 = pack_compact_v51({1: b"v1.2.9", 2: msg}, "CALYX QPEP COMPACT")
                w51_f, _, _ = unpack_compact_v51(w51, "CALYX QPEP COMPACT")

                aead_ct = cc512_encrypt(key64, nonce24, msg, b"aad-v129")
                aead_pt = cc512_decrypt(key64, nonce24, aead_ct, b"aad-v129")
                siv_ct = cc512_siv_encrypt(key64, msg, b"aad-v129", nonce=nonce24[:16])
                siv_pt = cc512_siv_decrypt(key64, siv_ct, b"aad-v129", nonce=nonce24[:16])

            return {
                "qlx": (ek_q, dk_q, ct_q, ss_q, dec_q),
                "qvs": (pk_v, sk_v, sig_v_h, sig_v_d),
                "plwe": (pk_l, sk_l, ct_l, ss_l, rej_l),
                "goppa": (pk_g, sk_g, ct_g, ss_g, rej_g),
                "rank": (pk_r, sk_r, ct_r, ss_r, rej_r),
                "uov": (pk_m, sk_m, sig_m_h, sig_m_d),
                "qhs": (pk_h, sk_h, sig_h_h, sig_h_d),
                "wire": (w5, w5_pt, w51, w51_f),
                "cc512": (aead_ct, aead_pt, siv_ct, siv_pt),
            }

        try:
            native_out = _capture_all(True)
            pure_out = _capture_all(False)
            for key in native_out:
                self.assertEqual(
                    native_out[key],
                    pure_out[key],
                    f"Deterministic Native C99 vs Pure-Python byte mismatch in subsystem: {key}",
                )
        finally:
            set_native_enabled(True)

    def test_05_phase2_benchmark_results_json_schema_and_verified_speedups(self):
        self.assertTrue(BENCH_JSON_PATH.is_file(), f"Missing {BENCH_JSON_PATH}")
        data = json.loads(BENCH_JSON_PATH.read_text(encoding="utf-8"))
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 10, f"Expected all 10 suites in benchmark_results.json, got {len(data)}")

        by_id = {}
        for row in data:
            for req in (
                "release",
                "suite_id",
                "suite",
                "hardware_tier",
                "backend",
                "keygen_ms",
                "encaps_ms",
                "decaps_ms",
                "sign_ms",
                "verify_ms",
                "total_ms",
                "peak_rss_mib",
                "pure_python",
                "speedup_vs_pure_python",
            ):
                self.assertIn(req, row, f"Missing key `{req}` in benchmark row: {row.get('suite')}")
            self.assertEqual(row["backend"], "native_c99")
            self.assertGreater(row["total_ms"], 0.0)
            self.assertGreater(row["peak_rss_mib"], 0.0)
            self.assertLess(row["peak_rss_mib"], 512.0, f"Excessive Peak RSS in {row['suite_id']}")
            self.assertGreater(row["pure_python"]["total_ms"], 0.0)
            self.assertGreater(row["speedup_vs_pure_python"]["total_x"], 0.0)
            by_id[row["suite_id"]] = row

        self.assertEqual(list(by_id.keys()), ALL_BENCH_SUITE_IDS)

        # Concrete Phase 2 C99/SIMD speedup gates on recorded benchmark results:
        # All 5 structured lattice suites, CRT-RSD512+QMQ-512, CGM-8192+QHS-512, and CULC-2048
        # have full C99 acceleration; CIF-SQI-512 & CSP-Omega accelerate QHS-512/Goppa/Rank/UOV/PLWE
        # while CSIDH-512 512-bit big-int isogeny remains Pure Python until Phase 3 (v1.3.2).
        for sid in ("QLX-768", "QLX-1024", "QLX-2048", "QLX-4096", "QLX-16384"):
            self.assertGreaterEqual(by_id[sid]["speedup_vs_pure_python"]["total_x"], 10.0, f"{sid} total speedup too low")
            self.assertGreaterEqual(by_id[sid]["speedup_vs_pure_python"]["keygen_x"], 50.0, f"{sid} keygen speedup too low")
        self.assertGreaterEqual(by_id["CRT-RSD512"]["speedup_vs_pure_python"]["total_x"], 25.0)
        self.assertGreaterEqual(by_id["CRT-RSD512"]["speedup_vs_pure_python"]["keygen_x"], 50.0)
        self.assertGreaterEqual(by_id["CGM-8192"]["speedup_vs_pure_python"]["total_x"], 10.0)
        self.assertGreaterEqual(by_id["CGM-8192"]["speedup_vs_pure_python"]["keygen_x"], 10.0)
        self.assertGreaterEqual(by_id["CULC-2048"]["speedup_vs_pure_python"]["total_x"], 5.0)
        self.assertGreaterEqual(by_id["CULC-2048"]["speedup_vs_pure_python"]["keygen_x"], 5.0)
        self.assertGreaterEqual(by_id["CIF-SQI-512"]["speedup_vs_pure_python"]["sign_x"], 2.0)
        self.assertGreaterEqual(by_id["CIF-SQI-512"]["speedup_vs_pure_python"]["verify_x"], 1.5)
        self.assertGreaterEqual(by_id["CSP-Omega"]["speedup_vs_pure_python"]["keygen_x"], 1.2)
        self.assertGreaterEqual(by_id["CSP-Omega"]["speedup_vs_pure_python"]["total_x"], 1.2)

    def test_06_live_comparative_benchmark_and_markdown_export(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        rows = run_comparative_benchmarks(include_heavy=False, suite_ids=["QLX-768", "CRT-RSD512"])
        self.assertEqual([r["suite_id"] for r in rows], ["QLX-768", "CRT-RSD512"])
        md_std = format_markdown_table(rows)
        md_cmp = format_comparative_markdown_table(rows)
        self.assertIn("Peak RSS (MiB)", md_std)
        self.assertIn("Total Speedup", md_cmp)
        self.assertIn("QLX-768", md_cmp)
        self.assertIn("CRT-RSD512", md_cmp)

        by_id = {r["suite_id"]: r for r in rows}
        self.assertGreater(by_id["QLX-768"]["speedup_vs_pure_python"]["total_x"], 2.0)
        self.assertGreater(by_id["CRT-RSD512"]["speedup_vs_pure_python"]["keygen_x"], 10.0)

    def test_07_c99_selftest_and_5_language_interop_matrix_gate(self):
        iop = run_cross_language_interop_matrix()
        self.assertTrue(iop["all_passed"])
        self.assertTrue(iop["zero_byte_tolerance"])
        self.assertEqual(len(iop["suites_verified"]), 10)
        self.assertGreaterEqual(len(iop["languages_verified"]), 5)

        test_bin = CSRC_DIR / "build" / "test_openqpep_c"
        if not test_bin.is_file() and shutil.which("make"):
            subprocess.run(["make", "-C", str(CSRC_DIR), "test"], check=True, capture_output=True)
        if test_bin.is_file():
            res = subprocess.run([str(test_bin)], capture_output=True, text=True, check=True)
            self.assertIn("12/12 suites, 108/108 APIs", res.stdout)

    def test_08_ci_pipeline_enforces_phase2_parity_and_sanitizer_gates(self):
        ci = CI_YML_PATH.read_text(encoding="utf-8")
        for req in (
            "c99-sanitizers",
            "make -C calyx_qpep/native/csrc test-san",
            "make -C calyx_qpep/native/csrc test-san-portable",
            "OPENQPEP_ENABLE_SANITIZERS=ON",
            "python3 -m calyx_qpep.cli verify-vectors",
            "OPENQPEP_DISABLE_NATIVE=1 python3 -m calyx_qpep.cli verify-vectors",
            "test_v119_phase1_audit.py",
            "test_v129_c99_parity.py",
        ):
            self.assertIn(req, ci, f"CI pipeline missing required Phase 2 gate: {req}")


if __name__ == "__main__":
    unittest.main()
