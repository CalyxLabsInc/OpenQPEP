"""
OpenQPEP Official Release 1.1.1 (v1.1.1) — Security Hardening, Strict Input Bounds,
Deterministic Typed Exceptions & Constant-Time Audit Verification Suite.
"""
import ast
import unittest
from pathlib import Path

from calyx_qpep import (
    OpenQPEPError,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPKeyRingError,
    QPEPMacVerificationError,
    QPEPSuiteError,
    QPEPTruncationError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from calyx_qpep.beyond_lwe_bridge import (
    decrypt_beyond_lwe,
    encrypt_beyond_lwe,
    generate_beyond_lwe_material,
    sign_beyond_lwe,
    verify_beyond_lwe,
)
from calyx_qpep.compat_server import (
    SlidingWindowRateLimiter,
    is_legacy_prerelease_version,
    verify_qpkrf_for_directory,
    verify_wire_v5_frame_strict,
)
from calyx_qpep.primitives.consttime import ct_eq, ct_eq_int, ct_eq_str

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestOpenQPEPv111Hardening(unittest.TestCase):
    PASS = "Calyx!@#$_2026v111Aa99"

    def test_01_version_metadata_is_111(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.1")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.1")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.1")

    def test_02_zero_broad_except_exception_in_all_production_modules(self):
        """AST-verify zero broad 'except Exception:' or bare 'except:' in production calyx_qpep modules."""
        offenders = []
        for py_path in sorted((REPO_ROOT / "calyx_qpep").rglob("*.py")):
            rel = str(py_path.relative_to(REPO_ROOT))
            # fuzz_wire.py intentionally catches unhandled crashes after allowed_exc in its fuzzer harness
            if rel == "calyx_qpep/audit/fuzz_wire.py":
                continue
            tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        offenders.append(f"{rel}:L{node.lineno} bare except:")
                    elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                        offenders.append(f"{rel}:L{node.lineno} except Exception:")
        self.assertEqual(offenders, [], "Found broad exception handlers:\n" + "\n".join(offenders))

    def test_03_constant_time_string_and_int_helpers(self):
        self.assertTrue(ct_eq(b"openqpep", b"openqpep"))
        self.assertFalse(ct_eq(b"openqpep", b"openqpeq"))
        self.assertFalse(ct_eq("not-bytes", b"not-bytes"))  # type: ignore[arg-type]

        self.assertTrue(ct_eq_str("ABCDEF0123", "ABCDEF0123"))
        self.assertFalse(ct_eq_str("ABCDEF0123", "ABCDEF0124"))
        self.assertFalse(ct_eq_str(None, "ABCDEF0123"))
        self.assertFalse(ct_eq_str(12345, "12345"))

        self.assertTrue(ct_eq_int(3329, 3329))
        self.assertFalse(ct_eq_int(3329, 3328))
        self.assertFalse(ct_eq_int(True, 1))
        self.assertFalse(ct_eq_int("3329", 3329))

    def test_04_strict_protocol_input_bounds_and_typed_exceptions(self):
        # Reject control characters / header injection / oversized UID fields
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice\r\nInjected", "a@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("", "a@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("A" * 257, "a@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice", "a@calyxmail.org\x00", self.PASS, qlx_tier="QLX-768")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice", "a@calyxmail.org", self.PASS, qlx_tier="QLX-768", comment="C" * 513)

        kr = OpenQPEPProtocol.generate_keypair("HardenedUser", "h@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pub_kr = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(kr, include_private=False))

        # Non-bytes plaintext/sign inputs raise typed QPEPWireFormatError
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.encrypt_bytes("not-bytes", pub_kr, kr, self.PASS)  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.sign_bytes("not-bytes", kr, self.PASS)  # type: ignore[arg-type]

        # Unlocking public-only key raises QPEPKeyRingError (subclass of OpenQPEPError & ValueError)
        with self.assertRaises(QPEPKeyRingError) as ctx_pub:
            OpenQPEPProtocol.unlock_private_keys(pub_kr, self.PASS)
        self.assertIsInstance(ctx_pub.exception, OpenQPEPError)
        self.assertIsInstance(ctx_pub.exception, ValueError)

        # Wrong passphrase raises QPEPMacVerificationError (subclass of OpenQPEPError & ValueError)
        with self.assertRaises(QPEPMacVerificationError) as ctx_pw:
            OpenQPEPProtocol.unlock_private_keys(kr, "Wrong!@#$_2026Zz88")
        self.assertIsInstance(ctx_pw.exception, OpenQPEPError)

        # Packet addressed to another recipient raises QPEPKeyRingError
        kr2 = OpenQPEPProtocol.generate_keypair("OtherUser", "o@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pkt = OpenQPEPProtocol.encrypt_bytes(b"classified-v111", pub_kr, kr, self.PASS)
        with self.assertRaises(QPEPKeyRingError):
            OpenQPEPProtocol.decrypt_packet(pkt, kr2, self.PASS)

    def test_05_beyond_lwe_bridge_bounds_and_suite_substitution_defense(self):
        with self.assertRaises(QPEPSuiteError):
            generate_beyond_lwe_material("INVALID-SUITE")

        pub_crt, priv_crt = generate_beyond_lwe_material("CRT-RSD512")
        # Cross-suite material substitution must raise QPEPSuiteError
        with self.assertRaises(QPEPSuiteError):
            encrypt_beyond_lwe("CGM-8192", b"hello", pub_crt)
        with self.assertRaises(QPEPSuiteError):
            decrypt_beyond_lwe("CGM-8192", "dummy", priv_crt)
        with self.assertRaises(QPEPSuiteError):
            sign_beyond_lwe("CGM-8192", b"hello", pub_crt, priv_crt)

        # Non-bytes payload rejected with QPEPWireFormatError
        with self.assertRaises(QPEPWireFormatError):
            encrypt_beyond_lwe("CRT-RSD512", "not-bytes", pub_crt)  # type: ignore[arg-type]

        # Non-dict key material rejected with QPEPKeyRingError
        with self.assertRaises(QPEPKeyRingError):
            encrypt_beyond_lwe("CRT-RSD512", b"hello", "not-a-dict")  # type: ignore[arg-type]

        # Malformed signature fails cleanly without raising
        ok, msg = verify_beyond_lwe("CRT-RSD512", "garbage", pub_crt)
        self.assertFalse(ok)
        self.assertEqual(msg, b"")

    def test_06_compat_server_bounds_and_rate_limiter_flood_eviction(self):
        # Bounded bucket eviction even when all buckets are active
        rl = SlidingWindowRateLimiter(max_requests=2, window_seconds=60.0, max_buckets=3)
        for i in range(10):
            allowed, _, _ = rl.allow(f"10.0.0.{i}", now=100.0 + i)
            self.assertTrue(allowed)
        self.assertLessEqual(len(rl._buckets), 3)

        # Invalid bucket key rejected with QPEPWireFormatError
        with self.assertRaises(QPEPWireFormatError):
            rl.allow("")
        with self.assertRaises(QPEPWireFormatError):
            rl.allow("x" * 257)

        # Strict compat_server helper validation
        self.assertFalse(is_legacy_prerelease_version("1.1.1"))
        self.assertFalse(is_legacy_prerelease_version("OpenQPEP/1.1.1"))
        self.assertFalse(is_legacy_prerelease_version(None))  # type: ignore[arg-type]
        self.assertTrue(is_legacy_prerelease_version("1.0.0-rc"))
        with self.assertRaises(QPEPWireFormatError):
            verify_wire_v5_frame_strict("not-bytes", "CALYX QPEP MESSAGE")  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            verify_wire_v5_frame_strict(b"\x89QPE\x05\x00", "")
        with self.assertRaises(QPEPWireFormatError):
            verify_qpkrf_for_directory("")


if __name__ == "__main__":
    unittest.main()
