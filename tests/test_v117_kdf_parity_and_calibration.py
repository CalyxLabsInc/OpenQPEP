"""
OpenQPEP Official Release 1.1.7 (v1.1.7) Test Suite:
Hardened QPKD-Argon2id Pure-Python & C-Backend Parity + Auto-Calibration & Passphrase Policy.

Verifies:
  1. Official RFC 9106 Section 5.3 Argon2id test vector bit-exact match across Pure-Python and C backends.
  2. Multi-parameter differential parity across all available C backends (argon2-cffi / OpenSSL 3.2+)
     vs. Pure-Python RFC 9106 (including multi-lane, multi-pass, non-aligned m_kib, seg_len > 128
     multi-address-block Argon2i indexing, variable out_len, and full derive_qpkrf_keys_v4 + .qpkrf unlock).
  3. Refusal of silent memory downgrade in pure-Python above MAX_PURE_PYTHON_ARGON2_KIB.
  4. Anti-DoS KDF parameter ceilings (OOM-bomb m_kib, CPU-bomb t_cost, bool type confusion, malformed .qpkrf).
  5. Hardware auto-tuner memory-ceiling safety bounds & container cgroup RAM limit awareness.
  6. Calibrated per-device KDF benchmark reporting (benchmark_kdf & calibrate_kdf_for_device) with zero mlock leak.
  7. Hardened passphrase policy (MAX_LENGTH, UTF-8 ceiling, NUL/control/Bidi rejection, witness scrubbing,
     immutable v1.0.0 witness compatibility, and conservative entropy estimation).
"""
import copy
import hashlib
import unittest
from unittest.mock import patch

from calyx_qpep import (
    MANDATORY_KDF_VERSION,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPPassphrasePolicyError,
    QPEPSuiteError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    analyze_passphrase,
    argon2id_raw,
    benchmark_kdf,
    calibrate_kdf_for_device,
    compute_safe_memory_ceiling_kib,
    enforce_kdf_memory_ceiling,
    enforce_passphrase_policy,
    estimate_passphrase_entropy_bits,
    get_active_kdf_backend,
    get_available_kdf_backends,
    memory_security_status,
    select_kdf_profile,
    validate_kdf_params,
    verify_argon2id_backend_parity,
)
from calyx_qpep.kdf import (
    BACKEND_CFFI,
    BACKEND_OPENSSL,
    BACKEND_PURE_PYTHON,
    HARD_CEILING_KDF_MEMORY_KIB,
    MAX_LENGTH,
    MAX_PURE_PYTHON_ARGON2_KIB,
    RFC9106_SECTION_5_3_VECTOR,
    derive_qpkrf_keys_v4,
    detect_system_ram_mib,
)


class TestOpenQPEPv117KDFParityAndCalibration(unittest.TestCase):
    PASS = "Calyx!@#$_2026v117Aa99"

    def test_01_version_metadata_format(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith("1."))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")
        self.assertEqual(MANDATORY_KDF_VERSION, 4)
        self.assertIn(BACKEND_PURE_PYTHON, get_available_kdf_backends())
        self.assertIn(get_active_kdf_backend(), get_available_kdf_backends())

    def test_02_rfc9106_section_5_3_official_test_vector_exact_parity(self):
        vec = RFC9106_SECTION_5_3_VECTOR
        py_out, py_backend = argon2id_raw(
            vec["password"],
            vec["salt"],
            m_kib=vec["memory_cost"],
            t_cost=vec["time_cost"],
            p_lanes=vec["parallelism"],
            out_len=vec["hash_len"],
            associated_data=vec["associated_data"],
            secret=vec["secret"],
            backend=BACKEND_PURE_PYTHON,
        )
        self.assertEqual(py_backend, BACKEND_PURE_PYTHON)
        self.assertEqual(py_out.hex(), vec["expected_hex"])

        if BACKEND_OPENSSL in get_available_kdf_backends():
            ossl_out, ossl_backend = argon2id_raw(
                vec["password"],
                vec["salt"],
                m_kib=vec["memory_cost"],
                t_cost=vec["time_cost"],
                p_lanes=vec["parallelism"],
                out_len=vec["hash_len"],
                associated_data=vec["associated_data"],
                secret=vec["secret"],
                backend=BACKEND_OPENSSL,
            )
            self.assertEqual(ossl_backend, BACKEND_OPENSSL)
            self.assertEqual(ossl_out.hex(), vec["expected_hex"])
            self.assertEqual(ossl_out, py_out)

        report = verify_argon2id_backend_parity()
        self.assertTrue(report["parity_verified"])
        self.assertTrue(report["rfc9106_section_5_3"][BACKEND_PURE_PYTHON])
        self.assertGreaterEqual(report["differential_cases_checked"], 4)

    def test_03_c_backends_vs_pure_python_differential_parity_matrix(self):
        c_backends = [b for b in get_available_kdf_backends() if b != BACKEND_PURE_PYTHON]
        self.assertGreaterEqual(
            len(c_backends),
            1,
            "Expected at least one native C Argon2id backend (argon2-cffi or OpenSSL 3.2+) for parity verification.",
        )

        # Differential test matrix covering:
        # - p=1,2,4; t=1,2,3,4; non-aligned m_kib (37, 100); seg_len > 128 (m=1024, p=1 -> seg_len=256);
        # - variable output lengths (16, 32, 64, 96, 128) exercising H' short and extended modes.
        cases = [
            {"m_kib": 32, "t_cost": 1, "p_lanes": 1, "out_len": 16},
            {"m_kib": 37, "t_cost": 2, "p_lanes": 1, "out_len": 32},
            {"m_kib": 64, "t_cost": 3, "p_lanes": 2, "out_len": 64},
            {"m_kib": 100, "t_cost": 3, "p_lanes": 4, "out_len": 96},
            {"m_kib": 256, "t_cost": 2, "p_lanes": 4, "out_len": 128},
            {"m_kib": 1024, "t_cost": 1, "p_lanes": 1, "out_len": 64},  # seg_len=256 > 128 addresses/block!
        ]
        for idx, params in enumerate(cases):
            pw = f"OpenQPEP-RFC9106-Matrix-Password-{idx}".encode("utf-8")
            salt = bytes([(idx * 29 + i) & 0xFF for i in range(32)])
            py_raw, _ = argon2id_raw(pw, salt, backend=BACKEND_PURE_PYTHON, **params)
            for cb in c_backends:
                c_raw, c_used = argon2id_raw(pw, salt, backend=cb, **params)
                self.assertEqual(c_used, cb)
                self.assertEqual(
                    c_raw,
                    py_raw,
                    f"Bit-exact parity failure between {cb} and pure-Python for params={params}",
                )

        # Full derive_qpkrf_keys_v4 parity (with and without FIDO2-PRF secret)
        salt32 = b"S" * 32
        fido_secret = b"F" * 32
        for hw in (None, fido_secret):
            k_py = derive_qpkrf_keys_v4(
                self.PASS,
                salt32,
                kdf_params={"m_kib": 128, "t_cost": 2, "p_lanes": 2, "backend": BACKEND_PURE_PYTHON},
                fido2_prf_secret=hw,
            )
            for cb in c_backends:
                k_c = derive_qpkrf_keys_v4(
                    self.PASS,
                    salt32,
                    kdf_params={"m_kib": 128, "t_cost": 2, "p_lanes": 2, "backend": cb},
                    fido2_prf_secret=hw,
                )
                self.assertEqual(k_py[:3], k_c[:3])

        # Cross-backend .qpkrf unlock: keyring generated with C backend unlocked via pure-Python (at 128 KiB)
        kr = OpenQPEPProtocol.generate_keypair("ParityUser", "parity@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # Re-encrypt test check using pure-Python-compatible m_kib via a fresh keyring with overridden select_kdf_profile
        with patch("calyx_qpep.kdf.argon2id_cascade.select_kdf_profile") as mock_prof:
            mock_prof.return_value = select_kdf_profile("QLX-768", max_memory_kib=128)
            kr_small = OpenQPEPProtocol.generate_keypair("CrossUser", "cross@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # Unlock under C backend first
        priv_c = OpenQPEPProtocol.unlock_private_keys(kr_small, self.PASS)
        # Switch stored backend hint to pure-Python and unlock the EXACT same ciphertext!
        kr_py = copy.deepcopy(kr_small)
        kr_py.encrypted_private_bundle["kdf_params"]["backend"] = BACKEND_PURE_PYTHON
        priv_py = OpenQPEPProtocol.unlock_private_keys(kr_py, self.PASS)
        self.assertEqual(priv_c["qlx_private"], priv_py["qlx_private"])
        self.assertEqual(priv_c["qvs_private"], priv_py["qvs_private"])
        self.assertEqual(priv_c["hgc_448_private"], priv_py["hgc_448_private"])
        self.assertEqual(priv_c["hgc_sig_private"], priv_py["hgc_sig_private"])
        # Also verify a keyring stamped with BACKEND_CFFI unlocks cleanly on OpenSSL-only hosts
        kr_cffi_tag = copy.deepcopy(kr)
        kr_cffi_tag.encrypted_private_bundle["kdf_params"]["backend"] = BACKEND_CFFI
        priv_cross = OpenQPEPProtocol.unlock_private_keys(kr_cffi_tag, self.PASS)
        self.assertEqual(len(priv_cross["qlx_private"]), 2400)

    def test_04_pure_python_refuses_silent_memory_downgrade_and_backend_validation(self):
        # Must NEVER silently truncate m_kib=65536 to 64 KiB in pure-Python!
        with self.assertRaises(QPEPSuiteError):
            argon2id_raw(
                b"password",
                b"0123456789ABCDEF",
                m_kib=MAX_PURE_PYTHON_ARGON2_KIB + 1024,
                t_cost=1,
                p_lanes=1,
                backend=BACKEND_PURE_PYTHON,
            )

        with self.assertRaises(QPEPSuiteError):
            argon2id_raw(
                b"password",
                b"0123456789ABCDEF",
                m_kib=32,
                t_cost=1,
                p_lanes=1,
                backend="argon2id-unknown-backend",
            )

        # argon2-cffi hash_secret_raw does not support associated_data/secret under strict_backend=True
        with self.assertRaises(QPEPSuiteError):
            argon2id_raw(
                b"password",
                b"0123456789ABCDEF",
                m_kib=32,
                t_cost=1,
                p_lanes=1,
                associated_data=b"extra-ad",
                backend=BACKEND_CFFI,
                strict_backend=True,
            )

    def test_05_kdf_anti_dos_parameter_bounds_and_malicious_qpkrf_defense(self):
        # Memory bomb (> 1 GiB)
        with self.assertRaises(QPEPSuiteError):
            validate_kdf_params(HARD_CEILING_KDF_MEMORY_KIB + 1, 3, 4)
        # CPU bomb (t_cost > 64)
        with self.assertRaises(QPEPSuiteError):
            validate_kdf_params(65536, 65, 4)
        # Excess lanes (> 16)
        with self.assertRaises(QPEPSuiteError):
            validate_kdf_params(65536, 3, 17)
        # Violates RFC 9106 m >= 8 * p
        with self.assertRaises(QPEPSuiteError):
            validate_kdf_params(16, 2, 4)
        # Boolean type confusion
        for bad_args in ((True, 3, 4), (65536, True, 4), (65536, 3, False)):
            with self.assertRaises(QPEPSuiteError):
                validate_kdf_params(*bad_args)

        # Malicious .qpkrf with OOM-bomb m_kib rejected before allocation
        kr = OpenQPEPProtocol.generate_keypair("BombTest", "bomb@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        kr_oom = copy.deepcopy(kr)
        kr_oom.encrypted_private_bundle["kdf_params"]["m_kib"] = 67108864  # 64 GiB attack!
        with self.assertRaises(QPEPSuiteError):
            OpenQPEPProtocol.unlock_private_keys(kr_oom, self.PASS)

        # Malicious .qpkrf with non-dict kdf_params or bool kdf_version rejected cleanly
        kr_bad_params = copy.deepcopy(kr)
        kr_bad_params.encrypted_private_bundle["kdf_params"] = ["not-a-dict"]
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.unlock_private_keys(kr_bad_params, self.PASS)

        kr_bool_ver = copy.deepcopy(kr)
        kr_bool_ver.encrypted_private_bundle["kdf_version"] = True
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.unlock_private_keys(kr_bool_ver, self.PASS)

    def test_06_hardware_tuner_memory_ceiling_and_cgroup_awareness(self):
        # 25% RAM cap on 512 MiB host = 128 MiB = 131072 KiB; 16384 MiB host capped at 512 MiB auto ceiling
        self.assertEqual(compute_safe_memory_ceiling_kib(512), 131072)
        self.assertEqual(compute_safe_memory_ceiling_kib(16384), 524288)
        self.assertEqual(compute_safe_memory_ceiling_kib(64), 16384)

        # Ultra-low RAM host (64 MiB -> 16 MiB ceiling) clamps constrained_32m safely and bumps t_cost
        tiny = select_kdf_profile("QLX-768", override_ram_mib=64, override_cpus=2)
        self.assertTrue(tiny.clamped_by_ceiling)
        self.assertEqual(tiny.m_kib, 16384)
        self.assertEqual(tiny.t_cost, 4)
        self.assertGreaterEqual(tiny.m_kib, 8 * tiny.p_lanes)

        # Explicit caller max_memory_kib clamps QLX-16384 safely
        capped = select_kdf_profile("QLX-16384", override_ram_mib=16384, max_memory_kib=32768)
        self.assertTrue(capped.clamped_by_ceiling)
        self.assertEqual(capped.m_kib, 32768)
        self.assertEqual(capped.t_cost, 5)
        self.assertEqual(capped.memory_ceiling_kib, 32768)

        # Container cgroup limit overrides larger host RAM
        with patch("calyx_qpep.kdf.hardware_tuner._detect_host_physical_ram_mib", return_value=32768):
            with patch("calyx_qpep.kdf.hardware_tuner.detect_cgroup_ram_limit_mib", return_value=512):
                self.assertEqual(detect_system_ram_mib(), 512)
                cg_prof = select_kdf_profile("QLX-16384")
                self.assertEqual(cg_prof.detected_ram_mib, 512)
                self.assertEqual(cg_prof.m_kib, 32768)

        # enforce_kdf_memory_ceiling enforces both caller cap and ram_fraction
        self.assertEqual(enforce_kdf_memory_ceiling(65536, max_memory_kib=65536), 65536)
        with self.assertRaises(QPEPSuiteError):
            enforce_kdf_memory_ceiling(131072, max_memory_kib=65536)
        with self.assertRaises(QPEPSuiteError):
            enforce_kdf_memory_ceiling(262144, ram_mib=512, enforce_ram_fraction=True)

    def test_07_calibrated_per_device_benchmark_and_zero_lock_leak(self):
        baseline = memory_security_status()["active_locked_pages"]

        bench = benchmark_kdf("QLX-768", samples=2, target_ms=250.0, max_memory_kib=16384)
        self.assertEqual(bench["kdf_version"], 4)
        self.assertEqual(bench["m_kib"], 16384)
        self.assertTrue(bench["clamped_by_ceiling"])
        self.assertEqual(bench["samples"], 2)
        self.assertLessEqual(bench["min_ms"], bench["median_ms"])
        self.assertLessEqual(bench["median_ms"], bench["max_ms"])
        self.assertGreater(bench["mib_per_sec"], 0.0)
        self.assertGreaterEqual(bench["recommended_t_cost"], bench["t_cost"])
        self.assertEqual(bench["backend"], get_active_kdf_backend())

        cal = calibrate_kdf_for_device("QLX-768", target_ms=250.0, max_memory_kib=16384)
        cal_params = cal["calibrated_kdf_params"]
        self.assertEqual(cal_params["m_kib"], 16384)
        self.assertGreaterEqual(cal_params["t_cost"], 3)

        # Calibrated params work seamlessly inside derive_qpkrf_keys_v4
        k1, k2, kmac, eff = derive_qpkrf_keys_v4(self.PASS, b"C" * 32, kdf_params=cal_params)
        self.assertEqual((len(k1), len(k2), len(kmac)), (32, 32, 64))
        self.assertEqual(eff["m_kib"], cal_params["m_kib"])
        self.assertEqual(eff["t_cost"], cal_params["t_cost"])

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)

    def test_08_hardened_passphrase_policy_bounds_control_chars_and_entropy(self):
        baseline = memory_security_status()["active_locked_pages"]

        # Reject NUL, control characters, and Unicode Bidi overrides (even if length/classes look filled!)
        for bad_pw in (
            "Calyx\x00\x00\x00\x0026Aa",
            "Calyx!@#$\n2026Aa",
            "Calyx!@#$\t2026Aa",
            "Calyx!@#$\u202e2026Aa",
            "Calyx!@#$_26Aa" + ("x" * MAX_LENGTH),
            "Calyx!@#$_26Aa" + ("\U0001F510" * 1024),  # > 4096 UTF-8 bytes
        ):
            res = analyze_passphrase(bad_pw)
            self.assertFalse(res.is_valid, f"Expected passphrase to be rejected: {bad_pw!r}")
            self.assertEqual(res.strength_tier, "rejected")
            with self.assertRaises(QPEPPassphrasePolicyError):
                enforce_passphrase_policy(bad_pw)

        # Spaces & legitimate NFC Unicode remain valid
        spaced = "Calyx!@# $2026 Passphrase Aa"
        res_spaced = analyze_passphrase(spaced)
        self.assertTrue(res_spaced.is_valid)
        self.assertGreater(res_spaced.entropy_bits, 80.0)
        self.assertIn(res_spaced.strength_tier, ("strong", "sovereign"))

        # Bit-exact backwards compatibility with v1.0.0 witness hash
        expected_witness = hashlib.sha3_512(
            b"CALYX-QPEP-HARDCODED-POLICY-WITNESS-v1.0.0|L>=12:True:True:True:True|"
            + self.PASS.encode("utf-8")
        ).digest()
        actual_witness = enforce_passphrase_policy(self.PASS)
        self.assertEqual(actual_witness, expected_witness)

        # Entropy estimator penalizes repeats/sequences vs high-diversity passphrases
        low_div = estimate_passphrase_entropy_bits("AAaaaa1234!!!!")
        high_div = estimate_passphrase_entropy_bits("Qz9!mX#4kP$7vL%2wR^8")
        self.assertGreater(high_div, low_div)
        self.assertEqual(analyze_passphrase("Qz9!mX#4kP$7vL%2wR^8").strength_tier, "sovereign")

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)


if __name__ == "__main__":
    unittest.main()
