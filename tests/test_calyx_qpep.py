import unittest
import tempfile
from pathlib import Path
from calyx_qpep import (
    CalyxQPEPProtocol,
    enforce_passphrase_policy,
    analyze_passphrase,
    QPEPPassphrasePolicyError,
)


class TestCalyxQPEPProtocol(unittest.TestCase):
    VALID_PASSPHRASE = "Calyx!@#$_26Qp"

    def test_hardcoded_passphrase_policy(self):
        witness = enforce_passphrase_policy(self.VALID_PASSPHRASE)
        self.assertEqual(len(witness), 64)
        with self.assertRaises(QPEPPassphrasePolicyError):
            enforce_passphrase_policy("")
        with self.assertRaises(QPEPPassphrasePolicyError):
            enforce_passphrase_policy("WeakPass1!")

    def test_key_hash_and_public_vs_private_qpkrf_rules(self):
        kr = CalyxQPEPProtocol.generate_keypair(
            name="Tristen Martinez",
            email="tristen@calyxlabsinc.org",
            passphrase=self.VALID_PASSPHRASE,
            qlx_tier="QLX-1024",
        )
        self.assertEqual(len(kr.key_hash), 64)
        self.assertTrue(CalyxQPEPProtocol.verify_public_keyring_self_signature(kr))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pub_path = tmp / "tristen_public.qpkrf"
            priv_path = tmp / "tristen_private.qpkrf"

            # Public key export & import MUST NOT require a passphrase
            CalyxQPEPProtocol.export_qpkrf(kr, include_private=False, output_path=pub_path)
            pub_imported = CalyxQPEPProtocol.import_qpkrf(pub_path)
            self.assertFalse(pub_imported.has_private_key)
            self.assertEqual(pub_imported.key_hash, kr.key_hash)

            # Private key export & import MUST strictly require the passphrase
            with self.assertRaises(QPEPPassphrasePolicyError):
                CalyxQPEPProtocol.export_qpkrf(kr, passphrase=None, include_private=True, output_path=priv_path)

            CalyxQPEPProtocol.export_qpkrf(kr, passphrase=self.VALID_PASSPHRASE, include_private=True, output_path=priv_path)
            with self.assertRaises(QPEPPassphrasePolicyError):
                CalyxQPEPProtocol.import_qpkrf(priv_path, passphrase=None)

            priv_imported = CalyxQPEPProtocol.import_qpkrf(priv_path, passphrase=self.VALID_PASSPHRASE)
            self.assertTrue(priv_imported.has_private_key)

    def test_dual_key_encrypt_decrypt_and_auto_signature_verify(self):
        sender = CalyxQPEPProtocol.generate_keypair("Sender", "sender@calyxlabsinc.org", self.VALID_PASSPHRASE, qlx_tier="QLX-768")
        recip = CalyxQPEPProtocol.generate_keypair("Recipient", "recip@calyxlabsinc.org", self.VALID_PASSPHRASE, qlx_tier="QLX-2048")

        msg = "Calyx QPEP Sovereign Quantum-Proof Payload with Key Hash & Auto Verify."
        pkt = CalyxQPEPProtocol.encrypt_text(msg, recipient_keyring=recip, encrypting_keyring=sender, passphrase=self.VALID_PASSPHRASE)
        recovered = CalyxQPEPProtocol.decrypt_text(pkt, recipient_private_keyring=recip, passphrase=self.VALID_PASSPHRASE, sender_public_keyring=sender)
        self.assertEqual(recovered, msg)

        sig = CalyxQPEPProtocol.sign_text(msg, signer_private_keyring=sender, passphrase=self.VALID_PASSPHRASE)
        # Auto verification across keyring pool
        ok, extracted_msg, matched_kr = CalyxQPEPProtocol.verify_text_signature(sig, keyring_pool=[recip, sender])
        self.assertTrue(ok)
        self.assertEqual(extracted_msg, msg)
        self.assertEqual(matched_kr.key_hash, sender.key_hash)
        # Verification when signing key is NOT in keyring pool must return False
        ok_bad, _, _ = CalyxQPEPProtocol.verify_text_signature(sig, keyring_pool=[recip])
        self.assertFalse(ok_bad)


if __name__ == "__main__":
    unittest.main()
