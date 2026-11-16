import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from calyx_qpep import (
    OpenQPEPProtocol,
    CalyxQPEPProtocol,
    QPEPPassphrasePolicyError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from calyx_qpep.cli import interactive_shell


class TestOpenQPEPProtocol(unittest.TestCase):
    def setUp(self):
        self.valid_pass_1 = "Calyx!@#$_26Qp"
        self.valid_pass_2 = "Tristen$%^&99Az"

    def test_universal_version_0_1_6(self):
        self.assertEqual(UNIVERSAL_VERSION, "0.1.6")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Beta Version 0.1.6")

    def test_hardcoded_passphrase_policy(self):
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "")
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "Short1!aA")
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.generate_keypair("User", "u@calyxlabsinc.org", "NoSpecials1234ABCDabcd")

    def test_key_hash_and_public_vs_private_qpkrf_rules(self):
        kr = OpenQPEPProtocol.generate_keypair("Alice", "alice@calyxlabsinc.org", self.valid_pass_1)
        self.assertEqual(len(kr.key_hash), 64)

        pub_str = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)
        self.assertIn("Key-Hash:", pub_str)
        self.assertIn("OpenQPEP by Calyx Labs Inc.", pub_str)
        self.assertIn("Beta Version 0.1.6", pub_str)
        imported_pub = OpenQPEPProtocol.import_qpkrf(pub_str)
        self.assertFalse(imported_pub.has_private_key)
        self.assertEqual(imported_pub.key_hash, kr.key_hash)

        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.export_qpkrf(kr, include_private=True)

        priv_str = OpenQPEPProtocol.export_qpkrf(kr, passphrase=self.valid_pass_1, include_private=True)
        with self.assertRaises(QPEPPassphrasePolicyError):
            OpenQPEPProtocol.import_qpkrf(priv_str)

        imported_priv = OpenQPEPProtocol.import_qpkrf(priv_str, passphrase=self.valid_pass_1)
        self.assertTrue(imported_priv.has_private_key)

    def test_dual_key_encrypt_decrypt_and_attached_signature_verify(self):
        sender_kr = OpenQPEPProtocol.generate_keypair("Sender", "sender@calyxlabsinc.org", self.valid_pass_1)
        recip_kr = OpenQPEPProtocol.generate_keypair("Recip", "recip@calyxlabsinc.org", self.valid_pass_2)

        recip_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(recip_kr, include_private=False))
        sender_pub = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(sender_kr, include_private=False))

        pkt = OpenQPEPProtocol.encrypt_text(
            "Classified OpenQPEP Payload",
            recipient_keyring=recip_pub,
            encrypting_keyring=sender_kr,
            passphrase=self.valid_pass_1,
        )
        pt_bytes, meta = OpenQPEPProtocol.decrypt_packet(
            pkt,
            recipient_private_keyring=recip_kr,
            passphrase=self.valid_pass_2,
            sender_public_keyring=sender_pub,
        )
        self.assertEqual(pt_bytes.decode("utf-8"), "Classified OpenQPEP Payload")
        self.assertEqual(meta["encrypting_key_hash"], sender_kr.key_hash)
        self.assertTrue(meta["signature_verified"])

        sig = OpenQPEPProtocol.sign_text("Signed Announcement", sender_kr, self.valid_pass_1)
        self.assertIn("CALYX QPEP ATTACHED SIGNATURE", sig)

        ok, extracted_msg, matched_kr = OpenQPEPProtocol.verify_text_signature(sig, keyring_pool=[recip_pub, sender_pub])
        self.assertTrue(ok)
        self.assertEqual(extracted_msg, "Signed Announcement")
        self.assertEqual(matched_kr.key_hash, sender_kr.key_hash)

    def test_interactive_english_cli_create_and_export_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ks_path = Path(tmpdir) / "keyring.json"
            pub_export_path = Path(tmpdir) / "Tristen_public.qpkrf"
            priv_export_path = Path(tmpdir) / "Tristen_private.qpkrf"
            simulated_inputs = "\n".join(
                [
                    "Create Key",
                    "1",
                    "Tristen",
                    "tristen@calyxlabsinc.org",
                    "OpenQPEP Lead Architect",
                    self.valid_pass_1,
                    self.valid_pass_1,
                    "no",
                    "List Keys",
                    "Export Public Tristen",
                    str(pub_export_path),
                    "Export Private Tristen",
                    self.valid_pass_1,
                    str(priv_export_path),
                    "Exit",
                ]
            ) + "\n"
            with patch("sys.stdin", io.StringIO(simulated_inputs)), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = interactive_shell(ks_path)
                output = mock_out.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("Specify Key Type:", output)
            self.assertIn("Successfully generated OpenQPEP Key Pair!", output)
            self.assertTrue(pub_export_path.exists())
            self.assertTrue(priv_export_path.exists())


if __name__ == "__main__":
    unittest.main()
