"""
OpenQPEP Official Release 1.1.6 (v1.1.6) — Strict Key-Hash Binding, Anti-Substitution,
RFC 7748 X448 Contributory Hardening, RFC 8032 Strict Ed448 Small-Order/Canonical-S Defense,
and .qpkrf Duplicate-JSON / Unicode-Homograph / Armor-Header Parser Hardening Suite.
"""
import copy
import json
import unittest

from calyx_qpep import (
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPKeyRingError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    strict_ed448_verify,
    validate_ed448_point,
    validate_x448_public_key,
)
from calyx_qpep.constants import PACKET_TYPE_KEYRING
from calyx_qpep.primitives.hgc448 import (
    CURVE448_P,
    ED448_ORDER_L,
    ED448_SMALL_ORDER_POINTS,
    X448_LOW_ORDER_POINTS,
    ed448_keygen,
    ed448_sign,
    ed448_verify,
    is_ed448_small_order_point,
    is_x448_low_order_point,
    x448_exchange,
    x448_keygen,
)
from calyx_qpep.protocol import _armor_wrap, _strict_json_loads
from calyx_qpep.wire.armor import armor_unwrap, armor_wrap


class TestOpenQPEPv116HGC448AndQPKRFHardening(unittest.TestCase):
    PASS = "Calyx!@#$_2026v116Aa99"

    def test_01_version_metadata_is_116(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.6")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.6")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.6")

    def test_02_x448_low_order_and_non_canonical_public_key_rejection(self):
        pub_a, priv_a = x448_keygen()
        pub_b, priv_b = x448_keygen()
        self.assertTrue(validate_x448_public_key(pub_a))
        self.assertFalse(is_x448_low_order_point(pub_a))
        self.assertEqual(x448_exchange(priv_a, pub_b), x448_exchange(priv_b, pub_a))

        # All 3 Curve448 & twist low-order points (0, 1, p-1) must be rejected
        for low_pt in X448_LOW_ORDER_POINTS:
            self.assertTrue(is_x448_low_order_point(low_pt))
            self.assertFalse(validate_x448_public_key(low_pt))
            with self.assertRaises(ValueError):
                x448_exchange(priv_a, low_pt)

        # Non-canonical u >= p encodings (p, p+1, p+5) must be rejected in strict canonical mode
        for non_canon_u in (CURVE448_P, CURVE448_P + 1, CURVE448_P + 5):
            enc = non_canon_u.to_bytes(56, "little")
            self.assertFalse(validate_x448_public_key(enc, strict_canonical=True))
            with self.assertRaises(ValueError):
                x448_exchange(priv_a, enc)

        # Wrong length / type rejected
        self.assertFalse(validate_x448_public_key(b"\x05" * 55))
        self.assertFalse(validate_x448_public_key("not-bytes"))  # type: ignore[arg-type]

    def test_03_ed448_small_order_e4_forgery_and_non_canonical_s_rejection(self):
        pub, priv = ed448_keygen()
        msg = b"Strict RFC 8032 Ed448 verification payload"
        sig = ed448_sign(priv, msg)
        self.assertTrue(validate_ed448_point(pub, reject_small_order=True))
        self.assertFalse(is_ed448_small_order_point(pub))
        self.assertTrue(strict_ed448_verify(pub, sig, msg))
        self.assertTrue(ed448_verify(pub, sig, msg))

        # CRITICAL: All 4 small-order torsion points E[4] (including order-4 (1,0) and (p-1,0)
        # where OpenSSL accepts S=0 forgeries!) MUST be hard-rejected!
        for pt in ED448_SMALL_ORDER_POINTS:
            self.assertTrue(is_ed448_small_order_point(pt))
            self.assertFalse(validate_ed448_point(pt, reject_small_order=True))
            forged_sig = pt + (0).to_bytes(57, "little")
            self.assertFalse(strict_ed448_verify(pt, forged_sig, b"ANY ARBITRARY MESSAGE"))
            self.assertFalse(ed448_verify(pt, forged_sig, b"ANY ARBITRARY MESSAGE"))
            # Small-order R with honest pub must also be rejected
            self.assertFalse(strict_ed448_verify(pub, pt + sig[57:], msg))

        # Non-canonical S >= L (signature malleability S' = S + L) must be rejected
        s_int = int.from_bytes(sig[57:], "little")
        malleable_sig = sig[:57] + (s_int + ED448_ORDER_L).to_bytes(57, "little")
        self.assertFalse(strict_ed448_verify(pub, malleable_sig, msg))
        self.assertFalse(ed448_verify(pub, malleable_sig, msg))

        # Non-zero top byte in S (byte 113) rejected
        bad_s_top = sig[:113] + b"\x01"
        self.assertFalse(strict_ed448_verify(pub, bad_s_top, msg))

        # Non-canonical point encodings: y >= p, non-zero padding bits 448..454, and -0 (0, 1) with sign=1
        non_canon_y = CURVE448_P.to_bytes(56, "little") + b"\x00"
        non_zero_pad = pub[:56] + bytes([pub[56] | 0x01])
        neg_zero = (1).to_bytes(56, "little") + b"\x80"  # x=0, y=1 with sign bit 1
        for bad_pt in (non_canon_y, non_zero_pad, neg_zero):
            self.assertFalse(validate_ed448_point(bad_pt, reject_small_order=False))
            self.assertFalse(strict_ed448_verify(bad_pt, sig, msg))

    def test_04_qpkrf_duplicate_json_keys_and_nonstandard_constants_rejected(self):
        # Direct strict JSON duplicate-key & NaN/Infinity rejection
        with self.assertRaises(QPEPWireFormatError):
            _strict_json_loads(b'{"a": 1, "a": 2}')
        with self.assertRaises(QPEPWireFormatError):
            _strict_json_loads(b'{"outer": {"k": "x", "k": "y"}}')
        with self.assertRaises(QPEPWireFormatError):
            _strict_json_loads(b'{"val": NaN}')

        # Crafted .qpkrf with duplicate top-level key_hash inside valid Wire v5 + CRC armor
        kr = OpenQPEPProtocol.generate_keypair("DupJsonUser", "dup@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        dup_json = (
            '{"magic":"QPKRF-v1.0.0","version":"1.1.6","key_hash":"'
            + kr.key_hash
            + '","key_hash":"'
            + ("0" * 64)
            + '"}'
        ).encode("utf-8")
        armored = _armor_wrap(
            "CALYX QPKRF PUBLIC KEY RING",
            {"Protocol": "OpenQPEP by Calyx Labs Inc.", "Key-Hash": kr.key_hash},
            dup_json,
            packet_type=PACKET_TYPE_KEYRING,
        )
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.import_qpkrf(armored)

    def test_05_unicode_homograph_bidi_zero_width_and_non_nfc_uid_defense(self):
        # 1. Mixed-script Cyrillic/Latin homograph ("Аlice" with Cyrillic U+0410)
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("\u0410lice", "alice@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # 2. Mixed-script Greek/Latin homograph ("B\u03bfB" with Greek omicron)
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("B\u03bfb", "bob@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # 3. Non-ASCII email homograph ("alice@c\u0430lyxlabsinc.org")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice", "alice@c\u0430lyxlabsinc.org", self.PASS, qlx_tier="QLX-768")
        # 4. Bidi RLO Trojan Source override (U+202E)
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice\u202eBob", "alice@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        # 5. Zero-width space (U+200B) & BOM (U+FEFF)
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice\u200b", "alice@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Alice", "alice@calyxmail.org", self.PASS, qlx_tier="QLX-768", comment="\ufeffnote")
        # 6. Non-NFC decomposed Unicode ("Jose\u0301")
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.generate_keypair("Jose\u0301", "jose@calyxmail.org", self.PASS, qlx_tier="QLX-768")

        # Legitimate single-script NFC Unicode names MUST still work seamlessly!
        for valid_name in ("José García", "山田太郎", "Иван Петров"):
            kr = OpenQPEPProtocol.generate_keypair(valid_name, "intl@calyxmail.org", self.PASS, qlx_tier="QLX-768")
            self.assertTrue(OpenQPEPProtocol.verify_public_keyring_self_signature(kr))
            exported = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
            imported = OpenQPEPProtocol.import_qpkrf(exported)
            self.assertEqual(imported.name, valid_name)

    def test_06_qpkrf_header_suite_and_ring_type_anti_substitution(self):
        kr = OpenQPEPProtocol.generate_keypair("AntiSub", "as@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        base_env = {
            "magic": "QPKRF-v1.0.0",
            "protocol": "OpenQPEP by Calyx Labs Inc.",
            "version": UNIVERSAL_VERSION,
            "ring_type": "PUBLIC_KEY_RING",
            "suite_id": "QLX-768",
            "key_hash": kr.key_hash,
            "created_at": kr.created_at,
            "identity": {"name": kr.name, "email": kr.email, "comment": kr.comment},
            "public_bundle": kr.public_bundle,
            "integrity_mac": kr.integrity_mac,
        }

        # 1. Armor Key-Hash header mismatch against signed envelope key_hash -> QPEPKeyRingError
        bad_hdr_armor = _armor_wrap(
            "CALYX QPKRF PUBLIC KEY RING",
            {"Protocol": "OpenQPEP by Calyx Labs Inc.", "Key-Hash": "F" * 64},
            json.dumps(base_env).encode("utf-8"),
            packet_type=PACKET_TYPE_KEYRING,
        )
        with self.assertRaises(QPEPKeyRingError):
            OpenQPEPProtocol.import_qpkrf(bad_hdr_armor)

        # 2. Mismatched envelope.suite_id vs public_bundle.suite_id -> QPEPKeyRingError
        bad_suite_env = copy.deepcopy(base_env)
        bad_suite_env["suite_id"] = "QLX-4096"
        bad_suite_armor = _armor_wrap(
            "CALYX QPKRF PUBLIC KEY RING",
            {"Protocol": "OpenQPEP by Calyx Labs Inc.", "Key-Hash": kr.key_hash},
            json.dumps(bad_suite_env).encode("utf-8"),
            packet_type=PACKET_TYPE_KEYRING,
        )
        with self.assertRaises(QPEPKeyRingError):
            OpenQPEPProtocol.import_qpkrf(bad_suite_armor)

        # 3. PUBLIC_KEY_RING smuggling encrypted_private_bundle -> QPEPKeyRingError
        smuggled_env = copy.deepcopy(base_env)
        smuggled_env["encrypted_private_bundle"] = kr.encrypted_private_bundle
        smuggled_armor = _armor_wrap(
            "CALYX QPKRF PUBLIC KEY RING",
            {"Protocol": "OpenQPEP by Calyx Labs Inc.", "Key-Hash": kr.key_hash},
            json.dumps(smuggled_env).encode("utf-8"),
            packet_type=PACKET_TYPE_KEYRING,
        )
        with self.assertRaises(QPEPKeyRingError):
            OpenQPEPProtocol.import_qpkrf(smuggled_armor)

    def test_07_armor_duplicate_oversized_and_bidi_header_rejection(self):
        # Bidi/zero-width characters in armor header rejected on wrap
        with self.assertRaises(QPEPWireFormatError):
            armor_wrap("CALYX QPEP TEST", b"payload", headers={"X-Note": "bad\u202eheader"})
        with self.assertRaises(QPEPWireFormatError):
            armor_wrap("CALYX QPEP TEST", b"payload", headers={"X-Note": "A" * 1025})

        # Duplicate headers (case-insensitive) injected into armor rejected on unwrap
        valid_armor = armor_wrap("CALYX QPEP TEST", b"payload")
        lines = valid_armor.splitlines()
        dup_armor = "\n".join(lines[:2] + ["version: OpenQPEP/1.1.6"] + lines[2:]) + "\n"
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap(dup_armor, "CALYX QPEP TEST")

    def test_08_verify_public_keyring_rejects_low_order_and_mismatched_tier(self):
        kr = OpenQPEPProtocol.generate_keypair("VerifyBounds", "vb@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        self.assertTrue(OpenQPEPProtocol.verify_public_keyring_self_signature(kr))

        # Tampered mismatched qvs_tier
        bad_tier = copy.deepcopy(kr)
        bad_tier.qvs_tier = "QVS-256"
        self.assertFalse(OpenQPEPProtocol.verify_public_keyring_self_signature(bad_tier))

        # Tampered oversized created_at
        bad_ts = copy.deepcopy(kr)
        bad_ts.created_at = "2026-" + ("9" * 100)
        self.assertFalse(OpenQPEPProtocol.verify_public_keyring_self_signature(bad_ts))

        # Tampered homograph name
        bad_uid = copy.deepcopy(kr)
        bad_uid.name = "\u0410lice"
        self.assertFalse(OpenQPEPProtocol.verify_public_keyring_self_signature(bad_uid))


if __name__ == "__main__":
    unittest.main()
