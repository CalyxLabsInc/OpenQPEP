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

    def test_passphrase_policy_enforcement(self):
        self.assertTrue(analyze_passphrase(self.VALID_PASSPHRASE).is_valid)
        enforce_passphrase_policy(self.VALID_PASSPHRASE)
        with self.assertRaises(QPEPPassphrasePolicyError):
            enforce_passphrase_policy("")
        with self.assertRaises(QPEPPassphrasePolicyError):
            enforce_passphrase_policy("Short1!@a")

    def test_keygen_and_qpkrf_export_import(self):
        kr = CalyxQPEPProtocol.generate_keypair(
            name="Tristen Martinez",
            email="tristen@calyxlabs.io",
            passphrase=self.VALID_PASSPHRASE,
        )
        self.assertEqual(len(kr.key_id), 32)
        self.assertTrue(CalyxQPEPProtocol.verify_public_keyring_self_signature(kr))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pub_path = tmp / "tristen_public.qpkrf"
            priv_path = tmp / "tristen_private.qpkrf"
            CalyxQPEPProtocol.export_qpkrf(kr, self.VALID_PASSPHRASE, include_private=False, output_path=pub_path)
            CalyxQPEPProtocol.export_qpkrf(kr, self.VALID_PASSPHRASE, include_private=True, output_path=priv_path)

            pub_imported = CalyxQPEPProtocol.import_qpkrf(pub_path, self.VALID_PASSPHRASE)
            self.assertFalse(pub_imported.has_private_key)
            priv_imported = CalyxQPEPProtocol.import_qpkrf(priv_path, self.VALID_PASSPHRASE)
            self.assertTrue(priv_imported.has_private_key)

    def test_encrypt_decrypt_and_signatures(self):
        kr = CalyxQPEPProtocol.generate_keypair("Tristen Martinez", "tristen@calyxlabs.io", self.VALID_PASSPHRASE)
        msg = "Calyx QPEP Sovereign Quantum-Proof Payload Test."
        pkt = CalyxQPEPProtocol.encrypt_text(msg, kr, self.VALID_PASSPHRASE, sender_keyring=kr)
        self.assertEqual(CalyxQPEPProtocol.decrypt_text(pkt, kr, self.VALID_PASSPHRASE, sender_public_keyring=kr), msg)
        sig = CalyxQPEPProtocol.sign_text(msg, kr, self.VALID_PASSPHRASE)
        self.assertTrue(CalyxQPEPProtocol.verify_text_signature(msg, sig, kr))


if __name__ == "__main__":
    unittest.main()
