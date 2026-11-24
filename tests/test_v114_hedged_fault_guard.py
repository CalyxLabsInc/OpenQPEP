"""
OpenQPEP Official Release 1.1.4 (v1.1.4) — FIPS 204-Style Hedged Deterministic Signatures
(QVS, QHS-512, QMQ-512, CIF-SQI-512) & Verify-Before-Emit Fault-Guard Across All 10 Suites.
"""
import os
import unittest
from unittest.mock import patch

from calyx_qpep import (
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPFaultGuardError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    memory_security_status,
)
from calyx_qpep import beyond_lwe_bridge as blwe_mod
from calyx_qpep.hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from calyx_qpep.isogeny.sqi_2d_512 import SupersingularIsogenyEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.multivariate.qmq_512 import MultivariateQuadraticEngine
from calyx_qpep.pentad.sovereign_pentad import CalyxSovereignPentad
from calyx_qpep.primitives import hgc448 as hgc448_mod
from calyx_qpep.primitives.hgc448 import ed448_keygen, ed448_sign, ed448_verify


class TestOpenQPEPv114HedgedAndFaultGuard(unittest.TestCase):
    PASS = "Calyx!@#$_2026v114Aa99"

    def test_01_version_metadata_format(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")

    def test_02_qvs_hedged_vs_deterministic_and_stuck_rng_resistance(self):
        witness = os.urandom(64)
        pk, sk = QVSEngine.keygen(tier="QVS-65", policy_witness=witness)
        msg1 = b"OpenQPEP v1.1.4 FIPS-204-style hedged signing payload A"
        msg2 = b"OpenQPEP v1.1.4 FIPS-204-style hedged signing payload B"

        # Default hedged=True produces distinct valid signatures on repeated signing of same message
        h1 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65")
        h2 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65")
        self.assertNotEqual(h1, h2)
        self.assertTrue(QVSEngine.verify(pk, msg1, h1, tier="QVS-65"))
        self.assertTrue(QVSEngine.verify(pk, msg1, h2, tier="QVS-65"))

        # Explicit hedged=False produces bit-exact deterministic signatures (still verified by same verifier)
        d1 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65", hedged=False)
        d2 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65", hedged=False)
        self.assertEqual(d1, d2)
        self.assertNotEqual(d1, h1)
        self.assertTrue(QVSEngine.verify(pk, msg1, d1, tier="QVS-65"))

        # Stuck/all-zero RNG resistance: distinct messages with identical rnd=0x00*32 get distinct valid nonces
        stuck_rnd = b"\x00" * 32
        s_a1 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65", rnd=stuck_rnd)
        s_a2 = QVSEngine.sign(sk, pk, msg1, tier="QVS-65", rnd=stuck_rnd)
        s_b = QVSEngine.sign(sk, pk, msg2, tier="QVS-65", rnd=stuck_rnd)
        self.assertEqual(s_a1, s_a2)
        self.assertNotEqual(s_a1[:64], s_b[:64])
        self.assertTrue(QVSEngine.verify(pk, msg1, s_a1, tier="QVS-65"))
        self.assertTrue(QVSEngine.verify(pk, msg2, s_b, tier="QVS-65"))

        # Invalid rnd size rejected
        with self.assertRaises(ValueError):
            QVSEngine.sign(sk, pk, msg1, tier="QVS-65", rnd=b"short")

        # Fault-guard triggers QPEPFaultGuardError
        with patch.object(QVSEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                QVSEngine.sign(sk, pk, msg1, tier="QVS-65")

    def test_03_ed448_verify_before_emit_fault_guard(self):
        pub, priv = ed448_keygen()
        msg = b"HGC-448 Ed448 Fault-Guard Verification"
        sig = ed448_sign(priv, msg)
        self.assertEqual(len(sig), 114)
        self.assertTrue(ed448_verify(pub, sig, msg))

        with patch.object(hgc448_mod, "ed448_verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                ed448_sign(priv, msg)

    def test_04_qhs512_hedged_opt_rand_stuck_rng_and_fault_guard(self):
        pk, sk = QHS512HypertreeEngine.keygen()
        msg1 = b"QHS-512 hedged message 1"
        msg2 = b"QHS-512 hedged message 2"

        # Default hedged=True produces distinct opt_rand (bytes 4:36) and valid signatures
        s1 = QHS512HypertreeEngine.sign(sk, msg1)
        s2 = QHS512HypertreeEngine.sign(sk, msg1)
        self.assertNotEqual(s1[4:36], s2[4:36])
        self.assertTrue(QHS512HypertreeEngine.verify(pk, msg1, s1))
        self.assertTrue(QHS512HypertreeEngine.verify(pk, msg1, s2))

        # Pure deterministic hedged=False mode
        d1 = QHS512HypertreeEngine.sign(sk, msg1, hedged=False)
        d2 = QHS512HypertreeEngine.sign(sk, msg1, hedged=False)
        self.assertEqual(d1, d2)
        self.assertTrue(QHS512HypertreeEngine.verify(pk, msg1, d1))

        # Stuck RNG defense: identical zero rnd on two different messages still yields distinct opt_rand
        z = b"\x00" * 32
        sa = QHS512HypertreeEngine.sign(sk, msg1, rnd=z)
        sb = QHS512HypertreeEngine.sign(sk, msg2, rnd=z)
        self.assertNotEqual(sa[4:36], sb[4:36])
        self.assertTrue(QHS512HypertreeEngine.verify(pk, msg1, sa))
        self.assertTrue(QHS512HypertreeEngine.verify(pk, msg2, sb))

        # Mandatory Verify-Before-Emit Fault-Guard
        with patch.object(QHS512HypertreeEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                QHS512HypertreeEngine.sign(sk, msg1)

    def test_05_qmq512_hedged_salt_stuck_rng_and_fault_guard(self):
        pk, sk = MultivariateQuadraticEngine.keygen()
        msg1 = b"QMQ-512 UOV message 1"
        msg2 = b"QMQ-512 UOV message 2"

        s1 = MultivariateQuadraticEngine.sign(sk, msg1)
        s2 = MultivariateQuadraticEngine.sign(sk, msg1)
        self.assertNotEqual(s1[:16], s2[:16])
        self.assertTrue(MultivariateQuadraticEngine.verify(pk, msg1, s1))
        self.assertTrue(MultivariateQuadraticEngine.verify(pk, msg1, s2))

        # Deterministic hedged=False mode
        d1 = MultivariateQuadraticEngine.sign(sk, msg1, hedged=False)
        d2 = MultivariateQuadraticEngine.sign(sk, msg1, hedged=False)
        self.assertEqual(d1, d2)
        self.assertTrue(MultivariateQuadraticEngine.verify(pk, msg1, d1))

        # Stuck RNG defense: distinct messages under all-zero rnd get distinct UOV salts (no vinegar reuse!)
        z = b"\x00" * 32
        sa = MultivariateQuadraticEngine.sign(sk, msg1, rnd=z)
        sb = MultivariateQuadraticEngine.sign(sk, msg2, rnd=z)
        self.assertNotEqual(sa[:16], sb[:16])
        self.assertTrue(MultivariateQuadraticEngine.verify(pk, msg1, sa))
        self.assertTrue(MultivariateQuadraticEngine.verify(pk, msg2, sb))

        # Mandatory Verify-Before-Emit Fault-Guard
        with patch.object(MultivariateQuadraticEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                MultivariateQuadraticEngine.sign(sk, msg1)

    def test_06_cif_sqi512_hedged_seasign_and_fault_guard(self):
        pk, sk = SupersingularIsogenyEngine.keygen()
        msg1 = b"CSIDH-512 SeaSign hedged message 1"
        msg2 = b"CSIDH-512 SeaSign hedged message 2"

        s1 = SupersingularIsogenyEngine.sign(sk, pk, msg1)
        s2 = SupersingularIsogenyEngine.sign(sk, pk, msg1)
        self.assertNotEqual(s1, s2)
        self.assertTrue(SupersingularIsogenyEngine.verify(pk, msg1, s1))
        self.assertTrue(SupersingularIsogenyEngine.verify(pk, msg1, s2))

        # Deterministic hedged=False mode
        d1 = SupersingularIsogenyEngine.sign(sk, pk, msg1, hedged=False)
        d2 = SupersingularIsogenyEngine.sign(sk, pk, msg1, hedged=False)
        self.assertEqual(d1, d2)
        self.assertTrue(SupersingularIsogenyEngine.verify(pk, msg1, d1))

        # Stuck RNG defense
        z = b"\x00" * 32
        sa = SupersingularIsogenyEngine.sign(sk, pk, msg1, rnd=z)
        sb = SupersingularIsogenyEngine.sign(sk, pk, msg2, rnd=z)
        self.assertNotEqual(sa[:32], sb[:32])
        self.assertTrue(SupersingularIsogenyEngine.verify(pk, msg1, sa))
        self.assertTrue(SupersingularIsogenyEngine.verify(pk, msg2, sb))

        with patch.object(SupersingularIsogenyEngine, "verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                SupersingularIsogenyEngine.sign(sk, pk, msg1)

    def test_07_csp_omega_bundle_level_fault_guard(self):
        pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True)
        msg = b"CSP-Omega Triple-Family Bundle Fault-Guard"
        sig = CalyxSovereignPentad.sign(msg, pub, priv)
        ok, extracted = CalyxSovereignPentad.verify(sig, pub)
        self.assertTrue(ok)
        self.assertEqual(extracted, msg)

        with patch.object(CalyxSovereignPentad, "verify", return_value=(False, b"")):
            with self.assertRaises(QPEPFaultGuardError):
                CalyxSovereignPentad.sign(msg, pub, priv)

    def test_08_protocol_and_beyond_lwe_bridge_fault_guard_and_zero_lock_leak(self):
        baseline = memory_security_status()["active_locked_pages"]

        # 1. Structured lattice protocol suite: Ed448 + QVS fault-guard
        kr_lat = OpenQPEPProtocol.generate_keypair("FGUser", "fg@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        sig_lat = OpenQPEPProtocol.sign_bytes(b"protocol-hedged-sig", kr_lat, self.PASS)
        ok, extracted, _ = OpenQPEPProtocol.verify_signature(sig_lat, signer_public_keyring=kr_lat)
        self.assertTrue(ok)
        self.assertEqual(extracted, b"protocol-hedged-sig")

        with patch.object(hgc448_mod, "ed448_verify", return_value=False):
            with self.assertRaises(QPEPFaultGuardError):
                OpenQPEPProtocol.sign_bytes(b"ed448-fault", kr_lat, self.PASS)

        # 2. Beyond-LWE bridge suite-level fault-guard across QMQ (CRT-RSD512) & QHS (CGM-8192)
        for suite_id in ("CRT-RSD512", "CGM-8192"):
            pub_b, priv_b = blwe_mod.generate_beyond_lwe_material(suite_id)
            armored = blwe_mod.sign_beyond_lwe(suite_id, b"bridge-msg", pub_b, priv_b)
            ok_b, msg_b = blwe_mod.verify_beyond_lwe(suite_id, armored, pub_b)
            self.assertTrue(ok_b)
            self.assertEqual(msg_b, b"bridge-msg")

            with patch.object(blwe_mod, "verify_beyond_lwe", return_value=(False, b"")):
                with self.assertRaises(QPEPFaultGuardError):
                    blwe_mod.sign_beyond_lwe(suite_id, b"bridge-fault", pub_b, priv_b)

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)


if __name__ == "__main__":
    unittest.main()
