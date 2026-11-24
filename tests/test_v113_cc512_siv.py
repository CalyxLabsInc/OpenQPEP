"""
OpenQPEP Official Release 1.1.3 (v1.1.3) — Constant-Time CMT-4 CC-512 AEAD Hardening &
Nonce-Misuse-Resistant CC-512-SIV Mode Verification Suite.
"""
import os
import unittest
from unittest.mock import patch

from calyx_qpep import (
    CC512SIV,
    OpenQPEPError,
    PROTOCOL_VERSION,
    QPEPMacVerificationError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    cc512_decrypt,
    cc512_encrypt,
    cc512_siv_decrypt,
    cc512_siv_encrypt,
    cc512_siv_unwrap_key,
    cc512_siv_wrap_key,
    memory_security_status,
)
from calyx_qpep.primitives import cc512_aead as cc512_mod
from calyx_qpep.primitives.cc512_aead import (
    CC512_CMT_TAG_BYTES,
    CC512_KEY_BYTES,
    CC512_NONCE_BYTES,
    CC512_OVERHEAD_BYTES,
    CC512_SIV_BYTES,
    CC512_SIV_MAX_NONCE_BYTES,
    CC512_SIV_OVERHEAD_BYTES,
)


class TestOpenQPEPv113CC512SIV(unittest.TestCase):
    def test_01_version_metadata_format(self):
        self.assertTrue(UNIVERSAL_VERSION.startswith(("1.", "2.")))
        self.assertEqual(UNIVERSAL_VERSION_LABEL, f"Official Release {UNIVERSAL_VERSION}")
        self.assertEqual(PROTOCOL_VERSION, f"OpenQPEP/{UNIVERSAL_VERSION}")

    def test_02_wire_v5_cc512_bit_exact_compatibility(self):
        """Wire v5 CC-512 encryption/decryption must remain 100% bit-exact with v1.0.0–v1.1.2."""
        self.assertEqual(CC512_KEY_BYTES, 64)
        self.assertEqual(CC512_NONCE_BYTES, 24)
        self.assertEqual(CC512_CMT_TAG_BYTES, 32)
        self.assertEqual(CC512_OVERHEAD_BYTES, 64)
        self.assertEqual(CC512_SIV_BYTES, 32)
        self.assertEqual(CC512_SIV_OVERHEAD_BYTES, 96)

        key = bytes(range(64))
        nonce = bytes(range(24))
        aad = b"OpenQPEP-Wire-v5-AAD"
        pt = b"Deterministic Wire v5 CC-512 regression payload"

        ct = cc512_encrypt(key, nonce, pt, aad)
        self.assertEqual(len(ct), len(pt) + 64)
        self.assertEqual(cc512_decrypt(key, nonce, ct, aad), pt)

        # Also verify bytearray and memoryview inputs produce identical ciphertext
        ct_ba = cc512_encrypt(bytearray(key), bytearray(nonce), bytearray(pt), bytearray(aad))
        ct_mv = cc512_encrypt(memoryview(key), memoryview(nonce), memoryview(pt), memoryview(aad))
        self.assertEqual(ct, ct_ba)
        self.assertEqual(ct, ct_mv)

        # Empty plaintext works cleanly
        ct_empty = cc512_encrypt(key, nonce, b"", aad)
        self.assertEqual(len(ct_empty), 64)
        self.assertEqual(cc512_decrypt(key, nonce, ct_empty, aad), b"")

    def test_03_strict_key_nonce_and_type_assertions(self):
        good_k = os.urandom(64)
        good_n = os.urandom(24)

        # Invalid key lengths & types
        for bad_k in (b"", b"short", os.urandom(32), os.urandom(63), os.urandom(65), "not-bytes", 12345, None):
            with self.assertRaises(QPEPWireFormatError) as ctx1:
                cc512_encrypt(bad_k, good_n, b"pt", b"aad")  # type: ignore[arg-type]
            self.assertIsInstance(ctx1.exception, OpenQPEPError)
            self.assertIsInstance(ctx1.exception, ValueError)
            with self.assertRaises(QPEPWireFormatError):
                cc512_decrypt(bad_k, good_n, b"\x00" * 64, b"aad")  # type: ignore[arg-type]
            with self.assertRaises(QPEPWireFormatError):
                cc512_siv_encrypt(bad_k, b"pt", b"aad")  # type: ignore[arg-type]
            with self.assertRaises(QPEPWireFormatError):
                cc512_siv_decrypt(bad_k, b"\x00" * 96, b"aad")  # type: ignore[arg-type]

        # Invalid nonce24 lengths & types
        for bad_n in (b"", os.urandom(12), os.urandom(23), os.urandom(25), "not-bytes", None):
            with self.assertRaises(QPEPWireFormatError):
                cc512_encrypt(good_k, bad_n, b"pt", b"aad")  # type: ignore[arg-type]
            with self.assertRaises(QPEPWireFormatError):
                cc512_decrypt(good_k, bad_n, b"\x00" * 64, b"aad")  # type: ignore[arg-type]

        # Non-bytes plaintext / aad / ciphertext / oversized SIV nonce
        with self.assertRaises(QPEPWireFormatError):
            cc512_encrypt(good_k, good_n, "str-pt", b"")  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            cc512_encrypt(good_k, good_n, b"pt", "str-aad")  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            cc512_siv_encrypt(good_k, "str-pt", b"")  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            cc512_siv_encrypt(good_k, b"pt", b"", nonce=b"x" * (CC512_SIV_MAX_NONCE_BYTES + 1))

        # Truncated ciphertexts raise QPEPMacVerificationError
        with self.assertRaises(QPEPMacVerificationError):
            cc512_decrypt(good_k, good_n, b"\x00" * 63, b"")
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(good_k, b"\x00" * 95, b"")

    def test_04_cc512_siv_deterministic_and_hedged_roundtrip(self):
        key = os.urandom(64)
        for pt in (b"", b"a", b"OpenQPEP CC-512-SIV Offline Vault Record", os.urandom(131072)):
            for aad in (b"", b"vault-slot-01|v1.1.3"):
                # Deterministic mode (no nonce)
                ct1 = cc512_siv_encrypt(key, pt, aad)
                ct2 = cc512_siv_encrypt(key, pt, aad, nonce=None)
                self.assertEqual(ct1, ct2)
                self.assertEqual(len(ct1), len(pt) + CC512_SIV_OVERHEAD_BYTES)
                self.assertEqual(cc512_siv_decrypt(key, ct1, aad), pt)
                self.assertEqual(cc512_siv_decrypt(key, ct1, aad, nonce=None), pt)

                # Hedged mode (explicit nonce)
                n = os.urandom(24)
                ct_h = cc512_siv_encrypt(key, pt, aad, nonce=n)
                self.assertNotEqual(ct_h[:32], ct1[:32])
                self.assertEqual(cc512_siv_decrypt(key, ct_h, aad, nonce=n), pt)

    def test_05_cc512_siv_nonce_misuse_resistance(self):
        """
        Repeating the exact same nonce (or omitting nonce completely) on different plaintexts or
        different AADs must produce completely independent 256-bit SIVs and independent ciphertexts
        with zero keystream reuse.
        """
        key = os.urandom(64)
        reused_nonce = b"STUCK-RNG-NONCE-00000000"
        aad = b"fixed-aad"
        pt1 = b"A" * 64 + b"0"
        pt2 = b"A" * 64 + b"1"  # Differs only in final bit!

        # 1. Identical stuck nonce, 1-bit plaintext difference
        ct1 = cc512_siv_encrypt(key, pt1, aad, nonce=reused_nonce)
        ct2 = cc512_siv_encrypt(key, pt2, aad, nonce=reused_nonce)
        self.assertNotEqual(ct1[:32], ct2[:32])
        # Even the first 64 ciphertext body bytes (where plaintexts are identical!) must completely differ
        self.assertNotEqual(ct1[32:96], ct2[32:96])
        self.assertEqual(cc512_siv_decrypt(key, ct1, aad, nonce=reused_nonce), pt1)
        self.assertEqual(cc512_siv_decrypt(key, ct2, aad, nonce=reused_nonce), pt2)

        # 2. Zero nonce, 1-bit AAD difference on identical plaintext
        ct_aad1 = cc512_siv_encrypt(key, pt1, b"aad-0")
        ct_aad2 = cc512_siv_encrypt(key, pt1, b"aad-1")
        self.assertNotEqual(ct_aad1[:32], ct_aad2[:32])
        self.assertNotEqual(ct_aad1[32:96], ct_aad2[32:96])

    def test_06_cc512_siv_injective_framing_boundary_defense(self):
        """Explicit u64be length framing prevents canonicalization collisions between nonce/aad/plaintext."""
        key = os.urandom(64)
        c1 = cc512_siv_encrypt(key, b"c", b"b", nonce=b"a")
        c2 = cc512_siv_encrypt(key, b"c", b"", nonce=b"ab")
        c3 = cc512_siv_encrypt(key, b"bc", b"a", nonce=b"")
        self.assertEqual(len({c1[:32], c2[:32], c3[:32]}), 3)

        # Cross-boundary decryption must fail
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(key, c1, b"", nonce=b"ab")

    def test_07_cc512_siv_forgery_wrong_key_and_siv_recheck_defense(self):
        k1, k2 = os.urandom(64), os.urandom(64)
        nonce = os.urandom(16)
        aad = b"auth-aad"
        pt = b"Critical Post-Quantum Secret Material"
        ct = cc512_siv_encrypt(k1, pt, aad, nonce=nonce)

        # Wrong key rejected (CMT-4 multi-key commitment defense)
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(k2, ct, aad, nonce=nonce)

        # Wrong AAD or wrong nonce rejected
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(k1, ct, b"wrong-aad", nonce=nonce)
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(k1, ct, aad, nonce=b"wrong-nonce")

        # Single-bit flip in SIV prefix, ciphertext body, or CMT-4 tail must be rejected
        for pos in (0, 15, 31, 32, len(ct) // 2, len(ct) - 33, len(ct) - 1):
            tampered = bytearray(ct)
            tampered[pos] ^= 0x01
            with self.assertRaises(QPEPMacVerificationError):
                cc512_siv_decrypt(k1, bytes(tampered), aad, nonce=nonce)

        # Verify constant-time SIV re-check blocks release if inner plaintext were ever altered
        with patch.object(cc512_mod, "cc512_decrypt", return_value=b"FORGED-PLAINTEXT"):
            with self.assertRaises(QPEPMacVerificationError) as ctx:
                cc512_siv_decrypt(k1, ct, aad, nonce=nonce)
            self.assertIn("synthetic IV", str(ctx.exception))

    def test_08_cc512_siv_key_wrap_domain_separation(self):
        kek = os.urandom(64)
        sk = os.urandom(64)
        aad = b"key-id=alpha-2026"

        wrapped = cc512_siv_wrap_key(kek, sk, aad)
        self.assertEqual(len(wrapped), len(sk) + CC512_SIV_OVERHEAD_BYTES)
        self.assertEqual(cc512_siv_unwrap_key(kek, wrapped, aad), sk)

        # Deterministic wrap matches on repeat
        self.assertEqual(cc512_siv_wrap_key(kek, sk, aad), wrapped)

        # Domain separation: raw cc512_siv_encrypt cannot be unwrapped as a key, and vice versa
        raw_ct = cc512_siv_encrypt(kek, sk, aad)
        self.assertNotEqual(raw_ct, wrapped)
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_unwrap_key(kek, raw_ct, aad)
        with self.assertRaises(QPEPMacVerificationError):
            cc512_siv_decrypt(kek, wrapped, aad)

        # Empty secret key cannot be wrapped
        with self.assertRaises(QPEPWireFormatError):
            cc512_siv_wrap_key(kek, b"", aad)

    def test_09_cc512_siv_context_manager_and_zero_lock_leak(self):
        baseline = memory_security_status()["active_locked_pages"]
        key = os.urandom(64)
        secret_key = os.urandom(48)

        with CC512SIV(key) as cipher:
            self.assertFalse(cipher.is_wiped)
            ct = cipher.encrypt(b"vault-entry-1", b"slot-1")
            self.assertEqual(cipher.decrypt(ct, b"slot-1"), b"vault-entry-1")
            wrapped = cipher.wrap_key(secret_key, b"subkey-1")
            self.assertEqual(cipher.unwrap_key(wrapped, b"subkey-1"), secret_key)

        self.assertTrue(cipher.is_wiped)
        self.assertFalse(cipher.is_memory_locked)
        with self.assertRaises(RuntimeError):
            cipher.encrypt(b"after-wipe")
        with self.assertRaises(RuntimeError):
            cipher.decrypt(ct, b"slot-1")

        # Exercise failure paths as well and confirm zero mlock leaks
        for _ in range(16):
            ct_loop = cc512_siv_encrypt(key, os.urandom(128), b"loop-aad", nonce=os.urandom(16))
            with self.assertRaises(QPEPMacVerificationError):
                cc512_siv_decrypt(os.urandom(64), ct_loop, b"loop-aad")
            with self.assertRaises(QPEPMacVerificationError):
                cc512_decrypt(os.urandom(64), os.urandom(24), ct_loop[32:], b"loop-aad")

        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)


if __name__ == "__main__":
    unittest.main()
