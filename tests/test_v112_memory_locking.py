"""
OpenQPEP Official Release 1.1.2 (v1.1.2) — OS Memory Locking (mlock / MADV_DONTDUMP / PR_SET_DUMPABLE),
Guard-Page Secret Arenas (LockedMemoryBuffer), Compiler-Barrier Zeroization Verification, and
Zero-Leak Protocol Secret-Path Scrubbing Test Suite.
"""
import ctypes
import json
import os
import subprocess
import sys
import unittest

from calyx_qpep import (
    LockedMemoryBuffer,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    SecretBuffer,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    disable_core_dumps,
    harden_process_memory,
    is_native_available,
    memory_security_status,
    zeroize_bytes,
    zeroize_many,
    zeroize_secret_dict,
)
from calyx_qpep.kdf.argon2id_cascade import derive_qpkrf_keys_v4
from calyx_qpep.native.loader import native_is_zeroed
from calyx_qpep.primitives.zeroize import is_addr_zeroed, zeroize_addr


class TestOpenQPEPv112MemoryLocking(unittest.TestCase):
    PASS = "Calyx!@#$_2026v112Aa99"

    def test_01_version_metadata_is_112(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.2")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.2")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.2")

    def test_02_secret_buffer_refcounted_mlock_and_zeroization(self):
        baseline = memory_security_status()["active_locked_pages"]
        status = memory_security_status()

        # Allocate multiple small SecretBuffers likely sharing 4 KiB heap pages
        buffers = [SecretBuffer(os.urandom(64)) for _ in range(12)]
        raw_refs = [sb.raw for sb in buffers]

        if status["mlock_available"] and (
            status["rlimit_memlock_soft"] is None or status["rlimit_memlock_soft"] >= 65536
        ):
            self.assertTrue(all(sb.is_memory_locked for sb in buffers))
            self.assertGreater(memory_security_status()["active_locked_pages"], baseline)

        # Wipe half — remaining buffers must still hold valid secrets and stay locked
        for sb in buffers[:6]:
            sb.wipe()
            self.assertTrue(sb.is_wiped)
            self.assertFalse(sb.is_memory_locked)
        for raw in raw_refs[:6]:
            self.assertEqual(bytes(raw), b"\x00" * 64)
        for sb in buffers[6:]:
            self.assertFalse(sb.is_wiped)
            self.assertEqual(len(sb.as_bytes()), 64)

        # Wipe remaining half — active locked pages must return cleanly to baseline (zero leaks!)
        for sb in buffers[6:]:
            sb.wipe()
        for raw in raw_refs[6:]:
            self.assertEqual(bytes(raw), b"\x00" * 64)
        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)

        # Post-wipe access must raise RuntimeError
        with self.assertRaises(RuntimeError):
            _ = buffers[0].raw
        with self.assertRaises(RuntimeError):
            buffers[0].as_bytes()
        with self.assertRaises(RuntimeError):
            buffers[0].view()

    def test_03_secret_buffer_view_copy_into_empty_and_unlocked_mode(self):
        payload = b"OpenQPEP-v1.1.2-SecretKeyMaterial-0123456789ABCDEF"
        dst = bytearray(len(payload) + 4)
        with SecretBuffer(payload, lock_memory=False) as sb:
            self.assertFalse(sb.is_memory_locked)
            with sb.view() as mv:
                self.assertEqual(bytes(mv), payload)
            sb.copy_into(dst, offset=2)
        self.assertEqual(bytes(dst[2 : 2 + len(payload)]), payload)
        zeroize_bytes(dst)
        self.assertEqual(bytes(dst), b"\x00" * len(dst))

        # Empty SecretBuffer edge case
        with SecretBuffer(b"") as empty_sb:
            self.assertEqual(len(empty_sb), 0)
            self.assertEqual(empty_sb.as_bytes(), b"")
            self.assertFalse(empty_sb.is_memory_locked)
        self.assertTrue(empty_sb.is_wiped)

    def test_04_locked_memory_buffer_guard_pages_mlock_dontdump_and_wipe(self):
        secret = os.urandom(12288 + 137)  # Spans multiple OS pages
        status = memory_security_status()

        with LockedMemoryBuffer(secret, guard_pages=True) as lmb:
            self.assertEqual(len(lmb), len(secret))
            self.assertEqual(lmb.as_bytes(), secret)

            if status["mmap_guard_pages_available"]:
                self.assertTrue(lmb.has_guard_pages)
            if status["madv_dontdump_available"]:
                self.assertTrue(lmb.is_dontdump_active)
            if status["mlock_available"] and (
                status["rlimit_memlock_soft"] is None or status["rlimit_memlock_soft"] >= 65536
            ):
                self.assertTrue(lmb.is_memory_locked)

            # Scoped zero-copy view & copy_into
            with lmb.scoped_view() as mv:
                self.assertEqual(len(mv), len(secret))
                self.assertEqual(bytes(mv[:32]), secret[:32])
            out = bytearray(len(secret))
            lmb.copy_into(out)
            self.assertEqual(bytes(out), secret)
            zeroize_bytes(out)

            # In-place mutation via write()
            patch = b"CALYX-PATCH-112!"
            lmb.write(patch, offset=16)
            self.assertEqual(lmb.as_bytes()[16 : 16 + len(patch)], patch)

        self.assertTrue(lmb.is_wiped)
        self.assertTrue(lmb.verified_zeroed_on_wipe)
        self.assertFalse(lmb.is_memory_locked)
        with self.assertRaises(RuntimeError):
            lmb.as_bytes()
        with self.assertRaises(RuntimeError):
            lmb.write(b"x")

        # Integer zero-initialized allocation and 0-byte allocation
        with LockedMemoryBuffer(64) as zbuf:
            self.assertEqual(zbuf.as_bytes(), b"\x00" * 64)
            zbuf.write(b"A" * 64)
            self.assertEqual(zbuf.as_bytes(), b"A" * 64)
        self.assertTrue(zbuf.verified_zeroed_on_wipe)

        with LockedMemoryBuffer(0) as empty_lmb:
            self.assertEqual(empty_lmb.as_bytes(), b"")
        self.assertTrue(empty_lmb.is_wiped)

    def test_05_native_c99_is_zeroed_and_zeroize_addr(self):
        buf = bytearray(b"\x00" * 256)
        c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
        addr = ctypes.addressof(c_buf)

        self.assertTrue(is_addr_zeroed(addr, len(buf)))
        if is_native_available():
            self.assertIs(native_is_zeroed(addr, len(buf)), True)

        # Single non-zero byte at start, middle, and end must all return False
        for pos in (0, 127, 255):
            buf[pos] = 0x01
            self.assertFalse(is_addr_zeroed(addr, len(buf)))
            if is_native_available():
                self.assertIs(native_is_zeroed(addr, len(buf)), False)
            zeroize_addr(addr, len(buf))
            self.assertTrue(is_addr_zeroed(addr, len(buf)))
            if is_native_available():
                self.assertIs(native_is_zeroed(addr, len(buf)), True)

    def test_06_opt_in_process_hardening_disable_core_dumps_in_subprocess(self):
        code = (
            "import json; "
            "from calyx_qpep import harden_process_memory; "
            "print(json.dumps(harden_process_memory()))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        res = json.loads(proc.stdout.strip())
        if os.name == "posix":
            self.assertTrue(res["rlimit_core_zeroed"])
            self.assertEqual(res["rlimit_core_soft"], 0)
        if sys.platform.startswith("linux") and res["prctl_dumpable_available"]:
            self.assertTrue(res["pr_set_dumpable_zeroed"])
            self.assertEqual(res["pr_dumpable"], 0)

    def test_07_zeroize_many_and_zeroize_secret_dict(self):
        ba1 = bytearray(b"secret-alpha")
        ba2 = bytearray(b"secret-beta")
        sb = SecretBuffer(b"secret-gamma")
        lmb = LockedMemoryBuffer(b"secret-delta")
        scrubbed = zeroize_many(ba1, sb, lmb, None)
        self.assertEqual(scrubbed, 3)
        self.assertEqual(bytes(ba1), b"\x00" * len(ba1))
        self.assertTrue(sb.is_wiped)
        self.assertTrue(lmb.is_wiped)

        poly = [1337, 2048, 3328, 42]
        nested = {
            "buf": ba2,
            "poly": poly,
            "inner": {"sb": SecretBuffer(b"nested-secret")},
            "raw": b"immutable-ref",
        }
        nested_sb = nested["inner"]["sb"]
        cleared = zeroize_secret_dict(nested)
        self.assertGreater(cleared, 0)
        self.assertEqual(nested, {})
        self.assertEqual(bytes(ba2), b"\x00" * len(ba2))
        self.assertEqual(poly, [0, 0, 0, 0])
        self.assertTrue(nested_sb.is_wiped)

    def test_08_end_to_end_kdf_and_protocol_zero_lock_leak(self):
        baseline = memory_security_status()["active_locked_pages"]

        # Verify pure-Python Argon2id path with lane zeroization produces deterministic keys
        salt = b"0123456789ABCDEF0123456789ABCDEF"
        k1_a, k2_a, km_a, p_a = derive_qpkrf_keys_v4(
            self.PASS,
            salt,
            kdf_params={"m_kib": 32, "t_cost": 1, "p_lanes": 1, "backend": "argon2id-rfc9106-pure-python"},
        )
        k1_b, k2_b, km_b, _ = derive_qpkrf_keys_v4(
            self.PASS,
            salt,
            kdf_params={"m_kib": 32, "t_cost": 1, "p_lanes": 1, "backend": "argon2id-rfc9106-pure-python"},
        )
        self.assertEqual((k1_a, k2_a, km_a), (k1_b, k2_b, km_b))
        self.assertEqual(p_a["backend"], "argon2id-rfc9106-pure-python")

        # Full keygen / export / import / encrypt / decrypt / sign / verify roundtrip
        kr = OpenQPEPProtocol.generate_keypair("MemLockUser", "memlock@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        exported = OpenQPEPProtocol.export_qpkrf(kr, passphrase=self.PASS, include_private=True)
        imported = OpenQPEPProtocol.import_qpkrf(exported, passphrase=self.PASS)
        pkt = OpenQPEPProtocol.encrypt_bytes(b"mlock-protected-payload-v1.1.2", imported, imported, self.PASS)
        pt, meta = OpenQPEPProtocol.decrypt_packet(pkt, imported, self.PASS, sender_public_keyring=imported)
        self.assertEqual(pt, b"mlock-protected-payload-v1.1.2")
        self.assertTrue(meta["signature_verified"])

        sig = OpenQPEPProtocol.sign_bytes(b"signed-under-mlock", imported, self.PASS)
        ok, extracted, _ = OpenQPEPProtocol.verify_signature(sig, signer_public_keyring=imported)
        self.assertTrue(ok)
        self.assertEqual(extracted, b"signed-under-mlock")

        # Confirm zero leaked mlock pages after entire cryptographic lifecycle
        self.assertEqual(memory_security_status()["active_locked_pages"], baseline)


if __name__ == "__main__":
    unittest.main()
