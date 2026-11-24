"""
OpenQPEP Official Release 1.1.9 (v1.1.9) — Phase 1 Security Regression Gate & v1.1.x Consolidation Audit.

Consolidates and cross-verifies every Phase 1 (v1.1.1 -> v1.1.9) security invariant across BOTH
Native C99 (`libopenqpep`) and Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`) execution paths:
  - v1.1.1: Constant-time comparisons (`ct_eq`/`ct_eq_str`/`ct_eq_int`), zero broad `except Exception:`, typed errors
  - v1.1.2: Reference-counted `SecretBuffer` mlock/munlock, `LockedMemoryBuffer` guard pages, zero leaked mlock pages
  - v1.1.3: CMT-4 `CC-512` AEAD + nonce-misuse-resistant `CC-512-SIV` encrypt/decrypt & key-wrap
  - v1.1.4: FIPS 204-style hedged signatures & universal Verify-Before-Emit Fault-Guard across suites
  - v1.1.5: KyberSlash-immune division-free branchless lattice math + Native C99 <-> Pure-Python bit-exact parity
  - v1.1.6: RFC 7748 X448 contributory + RFC 8032 Ed448 `strict_ed448_verify` E[4] small-order & canonical-S defense
  - v1.1.7: Bit-exact RFC 9106 `QPKD-Argon2id` multi-backend parity, memory-ceiling safety bounds & calibration
  - v1.1.8: RFC 4648 §3.5 canonical Base64, iterative JSON depth/node limits, 200:1 zip-bomb defense, armor/TLV ceilings
  - v1.1.9: Full 9-threat adversarial `run_all_attack_simulations()`, 5-language interop matrix, wire fuzzer, & CLI `audit`
"""
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from calyx_qpep import (
    CC512SIV,
    LockedMemoryBuffer,
    MANDATORY_KDF_VERSION,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPFaultGuardError,
    QPEPMacVerificationError,
    QPEPSuiteError,
    QPEPWireFormatError,
    SecretBuffer,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    cc512_siv_unwrap_key,
    cc512_siv_wrap_key,
    ct_cmov,
    ct_eq,
    is_native_available,
    memory_security_status,
    safe_zlib_decompress,
    set_native_enabled,
    strict_b64decode,
    strict_ed448_verify,
    strict_json_loads,
    validate_x448_public_key,
    verify_argon2id_backend_parity,
)
from calyx_qpep.audit import (
    fuzz_wire_parsers,
    run_all_attack_simulations,
    run_cross_language_interop_matrix,
    simulate_ed448_small_order_and_x448_low_order_attack,
    simulate_fo_cca2_malleability,
    simulate_json_duplicate_key_and_depth_bomb_attack,
    simulate_multi_suite_fault_injection_attack,
    simulate_non_canonical_base64_and_armor_dos_attack,
    simulate_qvs_fault_injection,
    simulate_replay_and_zip_bomb_attack,
    simulate_stream_truncation_and_reorder,
    simulate_suite_downgrade_attack,
)
from calyx_qpep.cli import main as cli_main
from calyx_qpep.kdf import calibrate_kdf_for_device, compute_safe_memory_ceiling_kib, enforce_passphrase_policy
from calyx_qpep.lattice.ntt_3329 import inv_ntt_3329, ntt_3329
from calyx_qpep.lattice.ntt_8380417 import inv_ntt_qvs, ntt_qvs
from calyx_qpep.lattice.poly_ring import sample_cbd1_3329, sample_cbd2_3329
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.primitives.consttime import ct_eq_int, ct_eq_str


class TestOpenQPEPv119Phase1ConsolidationGate(unittest.TestCase):
    PASS = "Calyx!@#$_2026v119Aa99"

    def test_01_version_metadata_is_119(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.9")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.9")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.9")
        self.assertEqual(MANDATORY_KDF_VERSION, 4)

    def test_02_all_9_adversarial_attack_simulations_pass_native_and_pure_python(self):
        prev_native = is_native_available()
        expected_attacks = {
            "FO_CCA2_Malleability",
            "QVS_Fault_Injection",
            "Stream_Truncation_Reorder_Injection",
            "Suite_And_Protocol_Downgrade",
            "Ed448_SmallOrder_And_X448_LowOrder",
            "NonCanonical_Base64_Armor_And_TLV_DoS",
            "JSON_DuplicateKey_DepthBomb_And_Homograph_UID",
            "Replay_CMT4_KDFBomb_And_ZipBomb",
            "Universal_MultiSuite_Fault_Injection",
        }
        try:
            modes = [False, True] if prev_native else [False]
            for native_mode in modes:
                set_native_enabled(native_mode)
                baseline_locks = memory_security_status()["active_locked_pages"]
                rep = run_all_attack_simulations()
                self.assertTrue(rep["all_passed"], f"Attack simulation failed under native={native_mode}: {rep}")
                self.assertEqual(rep["simulation_count"], 9)
                self.assertEqual(rep["total_defended"], rep["total_trials"])
                self.assertGreaterEqual(rep["total_trials"], 60)
                seen = {sim["attack"] for sim in rep["simulations"]}
                self.assertEqual(seen, expected_attacks)
                self.assertEqual(
                    memory_security_status()["active_locked_pages"],
                    baseline_locks,
                    f"mlock page leak detected under native={native_mode}",
                )
        finally:
            set_native_enabled(prev_native)

    def test_03_phase1_v111_v112_consttime_memory_locking_and_zero_leak(self):
        baseline = memory_security_status()["active_locked_pages"]
        self.assertTrue(ct_eq(b"phase1", b"phase1"))
        self.assertFalse(ct_eq(b"phase1", b"phase2"))
        self.assertTrue(ct_eq_str("ABC123", "ABC123"))
        self.assertFalse(ct_eq_str("ABC123", "ABC124"))
        self.assertTrue(ct_eq_int(3329, 3329))
        self.assertFalse(ct_eq_int(3329, 3328))
        self.assertEqual(ct_cmov(True, b"AAAA", b"BBBB"), b"AAAA")
        self.assertEqual(ct_cmov(False, b"AAAA", b"BBBB"), b"BBBB")

        with SecretBuffer(b"phase1-secret-material") as sb:
            self.assertEqual(sb.as_bytes(), b"phase1-secret-material")
        self.assertTrue(sb.is_wiped)

        with LockedMemoryBuffer(64) as lmb:
            lmb.write(b"guard-paged-phase1-key")
            self.assertEqual(lmb.as_bytes()[:22], b"guard-paged-phase1-key")
        self.assertTrue(lmb.is_wiped)
        self.assertTrue(lmb.verified_zeroed_on_wipe)
        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)

    def test_04_phase1_v113_v114_cc512_siv_and_hedged_fault_guard(self):
        baseline = memory_security_status()["active_locked_pages"]
        key64 = os.urandom(64)
        with CC512SIV(key64) as siv:
            # Nonce-misuse resistance: identical nonce + different plaintext produces completely different SIV & ciphertext
            ct1 = siv.encrypt(b"plaintext-alpha", aad=b"phase1", nonce=b"\x11" * 24)
            ct2 = siv.encrypt(b"plaintext-beta!", aad=b"phase1", nonce=b"\x11" * 24)
            self.assertNotEqual(ct1[:32], ct2[:32])
            self.assertEqual(siv.decrypt(ct1, aad=b"phase1", nonce=b"\x11" * 24), b"plaintext-alpha")
            self.assertEqual(siv.decrypt(ct2, aad=b"phase1", nonce=b"\x11" * 24), b"plaintext-beta!")

        wrapped = cc512_siv_wrap_key(key64, b"K" * 32, aad=b"phase1-wrap")
        self.assertEqual(cc512_siv_unwrap_key(key64, wrapped, aad=b"phase1-wrap"), b"K" * 32)
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_unwrap_key(key64, wrapped, aad=b"wrong-context")

        # Hedged signing immunity to stuck all-zero RNG + deterministic repeatability + fault guard
        pk, sk = QVSEngine.keygen("QVS-65", os.urandom(64))
        with patch("os.urandom", return_value=b"\x00" * 32):
            sig_a = QVSEngine.sign(sk, pk, b"msg-1", tier="QVS-65", hedged=True)
            sig_b = QVSEngine.sign(sk, pk, b"msg-2", tier="QVS-65", hedged=True)
        self.assertNotEqual(sig_a, sig_b)
        self.assertTrue(QVSEngine.verify(pk, b"msg-1", sig_a, tier="QVS-65"))
        self.assertTrue(QVSEngine.verify(pk, b"msg-2", sig_b, tier="QVS-65"))

        with patch.object(QVSEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                QVSEngine.sign(sk, pk, b"fault-msg", tier="QVS-65")

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)

    def test_05_phase1_v115_v116_native_vs_pure_python_bit_exact_lattice_and_hgc448(self):
        prev_native = is_native_available()
        poly_qlx = [(i * 41 + 13) % 3329 for i in range(256)]
        poly_qvs = [(i * 19937 + 91) % 8380417 for i in range(256)]
        seed32 = b"\x5A" * 32
        witness64 = b"\xA5" * 64
        try:
            set_native_enabled(False)
            py_ntt_3329 = ntt_3329(poly_qlx)
            py_inv_3329 = inv_ntt_3329(py_ntt_3329)
            py_ntt_qvs = ntt_qvs(poly_qvs)
            py_inv_qvs = inv_ntt_qvs(py_ntt_qvs)
            py_cbd1 = sample_cbd1_3329(seed32, 1)
            py_cbd2 = sample_cbd2_3329(seed32, 2)
            with patch("os.urandom", side_effect=[b"\x11" * 32, b"\x22" * 32, b"\x33" * 32]):
                py_ek, py_dk = QLXEngine.keygen("QLX-768", witness64)
                py_ct, py_ss = QLXEngine.encaps(py_ek, "QLX-768")
            py_ss_dec = QLXEngine.decaps(py_dk, py_ct, "QLX-768")
            self.assertEqual(py_ss, py_ss_dec)

            if prev_native:
                set_native_enabled(True)
                self.assertEqual(ntt_3329(poly_qlx), py_ntt_3329)
                self.assertEqual(inv_ntt_3329(py_ntt_3329), py_inv_3329)
                self.assertEqual(ntt_qvs(poly_qvs), py_ntt_qvs)
                self.assertEqual(inv_ntt_qvs(py_ntt_qvs), py_inv_qvs)
                self.assertEqual(sample_cbd1_3329(seed32, 1), py_cbd1)
                self.assertEqual(sample_cbd2_3329(seed32, 2), py_cbd2)
                with patch("os.urandom", side_effect=[b"\x11" * 32, b"\x22" * 32, b"\x33" * 32]):
                    c_ek, c_dk = QLXEngine.keygen("QLX-768", witness64)
                    c_ct, c_ss = QLXEngine.encaps(c_ek, "QLX-768")
                c_ss_dec = QLXEngine.decaps(c_dk, c_ct, "QLX-768")
                self.assertEqual((c_ek, c_dk, c_ct, c_ss, c_ss_dec), (py_ek, py_dk, py_ct, py_ss, py_ss_dec))
        finally:
            set_native_enabled(prev_native)

        # v1.1.6 HGC-448 checks
        self.assertTrue(simulate_ed448_small_order_and_x448_low_order_attack()["passed"])
        self.assertFalse(validate_x448_public_key(b"\x00" * 56))
        self.assertFalse(strict_ed448_verify(b"\x00" * 56 + b"\x80", b"\x00" * 56 + b"\x80" + b"\x00" * 57, b"x"))

    def test_06_phase1_v117_v118_kdf_parity_calibration_and_parser_ceilings(self):
        parity = verify_argon2id_backend_parity()
        self.assertTrue(parity["parity_verified"])
        self.assertEqual(compute_safe_memory_ceiling_kib(512), 131072)
        cal = calibrate_kdf_for_device("QLX-768", target_ms=100.0, max_memory_kib=16384)
        self.assertEqual(cal["calibrated_kdf_params"]["m_kib"], 16384)
        self.assertEqual(len(enforce_passphrase_policy(self.PASS)), 64)

        # v1.1.8 canonical Base64, JSON depth, zip-bomb
        with self.assertRaises(QPEPWireFormatError):
            strict_b64decode("YR==")
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads('{"a":' * 100 + "1" + "}" * 100)
        with self.assertRaises(QPEPWireFormatError):
            safe_zlib_decompress(b"")

    def test_07_cross_language_interop_matrix_and_wire_fuzzer_phase1_gate(self):
        iop = run_cross_language_interop_matrix()
        self.assertTrue(iop["all_passed"])
        self.assertTrue(iop["zero_byte_tolerance"])
        self.assertEqual(len(iop["suites_verified"]), 10)
        self.assertGreaterEqual(len(iop["languages_verified"]), 5)

        fuzz = fuzz_wire_parsers(iterations=200, seed=0x119)
        self.assertTrue(fuzz["passed"])
        self.assertEqual(fuzz["unhandled_crashes"], 0)
        self.assertEqual(fuzz["false_accepts"], 0)

    def test_08_cli_audit_subcommand_end_to_end_exit_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["audit"])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertTrue(report["all_passed"])
        self.assertTrue(report["attack_simulations"]["all_passed"])
        self.assertEqual(report["attack_simulations"]["simulation_count"], 9)
        self.assertTrue(report["interop_matrix"]["all_passed"])


if __name__ == "__main__":
    unittest.main()
