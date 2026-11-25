"""
OpenQPEP Official Release 1.2.6 (v1.2.6) — Native C99 CC-512 Whitening, Wire v5/v5.1 Framing &
Constant-Time Helpers Test Suite.

Verifies:
  1. ABI v1.2.6 (`0x00010206`) & dynamic export of all 14 new Wire/CC-512/CT C99 symbols plus
     relocated branchless `openqpep_verify_wire_v5_magic` under `-fvisibility=hidden` (`99` total
     exported `openqpep_*` symbols, zero leaked internal helpers).
  2. Branchless constant-time helpers (`ct_select_u32`, overflow-safe `ct_mem_bounds_ok`, `ct_cmov`,
     `ct_cswap`, `ct_eq`, `verify_wire_v5_magic`) across edge cases and Native <-> Pure-Python parity.
  3. Zero-heap Wire Format v5 (`\x89QPE\x05\x00`), Compact Binary TLV v5.1 (`\x89QPE\x05\x01`),
     streaming XOR whitening, wire MAC, authenticate-then-unwhiten tamper defense, and TLV structural
     validation (canonical order, duplicate tags, max_fields, 32-bit length overflow) across Native
     C99 and Pure-Python.
  4. Zero-heap streaming CC-512 CMT-4 key derivation/tagging/verification and CC-512-SIV synthetic IV
     synthesis across rate-boundary and multi-kilobyte payloads with cross-backend encrypt/decrypt
     and key-wrap parity.
  5. Verified Native C99 wall-clock speedups on 256 KiB Wire v5 framing (`>= 4x`) and `ct_cmov` (`>= 10x`).
  6. Standalone external C99 consumer compiled under `-std=c99 -O2 -Wall -Wextra -Werror -Wpedantic`
     linking BOTH static `libopenqpep.a` and shared `libopenqpep.so` verifying every v1.2.6 API,
     in-place whitening, tamper-untouched unpack output, `SIZE_MAX` overflow bounds safety, and error codes.
"""
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from calyx_qpep import (
    PROTOCOL_VERSION,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    is_native_available,
    native_abi_version,
    set_native_enabled,
)
from calyx_qpep.native import (
    native_cc512_cmt4_tag,
    native_cc512_derive_cmt4_subkeys,
    native_cc512_siv_master_subkeys,
    native_cc512_siv_msg_keys,
    native_cc512_siv_synth,
    native_cc512_verify_cmt4_tag,
    native_ct_cmov,
    native_ct_cswap,
    native_ct_eq,
    native_ct_mem_bounds_ok,
    native_ct_select_u32,
    native_verify_wire_v5_magic,
    native_wire_compute_mac,
    native_wire_v5_pack,
    native_wire_v5_unpack,
    native_wire_validate_tlv,
    native_wire_whiten_xor,
)
from calyx_qpep.primitives.cc512_aead import (
    CC512SIV,
    _compute_cmt4_tag,
    _compute_siv32,
    _derive_cmt4_subkeys,
    _derive_siv_master_subkeys,
    _derive_siv_message_keys,
    cc512_decrypt,
    cc512_encrypt,
    cc512_siv_decrypt,
    cc512_siv_encrypt,
    cc512_siv_unwrap_key,
    cc512_siv_wrap_key,
)
from calyx_qpep.primitives.consttime import ct_cmov, ct_cswap, ct_eq, ct_mem_bounds_ok
from calyx_qpep.wire.compact_v51 import decode_tlv, encode_tlv, pack_compact_v51, unpack_compact_v51
from calyx_qpep.wire.framing import pack_wire_frame, unpack_wire_frame

REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_DIR = REPO_ROOT / "calyx_qpep" / "native"
CSRC_DIR = NATIVE_DIR / "csrc"
HEADER_PATH = CSRC_DIR / "include" / "openqpep.h"

NEW_V126_SYMBOLS = {
    "openqpep_ct_select_u32",
    "openqpep_ct_mem_bounds_ok",
    "openqpep_ct_cswap",
    "openqpep_verify_wire_v5_magic",
    "openqpep_wire_whiten_xor",
    "openqpep_wire_compute_mac",
    "openqpep_wire_v5_pack",
    "openqpep_wire_v5_unpack",
    "openqpep_wire_validate_tlv",
    "openqpep_cc512_derive_cmt4_subkeys",
    "openqpep_cc512_cmt4_tag",
    "openqpep_cc512_verify_cmt4_tag",
    "openqpep_cc512_siv_master_subkeys",
    "openqpep_cc512_siv_synth",
    "openqpep_cc512_siv_msg_keys",
}


class TestOpenQPEPv126C99WireCC512CT(unittest.TestCase):
    def test_01_version_metadata_and_exported_v126_symbols(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.2.6")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.2.6")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.2.6")

        hdr = HEADER_PATH.read_text(encoding="utf-8")
        for sym in NEW_V126_SYMBOLS:
            self.assertIn(sym, hdr, f"Missing v1.2.6 symbol in openqpep.h: {sym}")
        self.assertIn("OPENQPEP_ERR_WIRE_FORMAT", hdr)

        if is_native_available():
            self.assertEqual(native_abi_version(), 0x00010206)

            ext = "dylib" if platform.system() == "Darwin" else "so"
            shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
            if shared_lib.is_file() and shutil.which("nm"):
                res = subprocess.run(
                    ["nm", "-D", "--defined-only", str(shared_lib)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                exported = set()
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ("T", "D", "R", "B"):
                        sym = parts[2].split("@")[0]
                        if not sym.startswith("_"):
                            exported.add(sym)
                self.assertEqual(NEW_V126_SYMBOLS - exported, set())
                leaked = {s for s in exported if not s.startswith("openqpep_")}
                self.assertEqual(leaked, set(), f"Leaked internal symbols: {leaked}")
                self.assertGreaterEqual(len(exported), 99)

    def test_02_constant_time_helpers_and_magic_validator_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        # 1. openqpep_ct_select_u32
        for cond in (0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
            expected = 0xDEADBEEF if cond != 0 else 0xCAFEBABE
            self.assertEqual(native_ct_select_u32(cond, 0xDEADBEEF, 0xCAFEBABE), expected)

        # 2. openqpep_ct_mem_bounds_ok (including 64-bit wraparound attacks)
        u64_max = (1 << 64) - 1
        bounds_cases = [
            (0, 0, 0, True),
            (0, 1, 0, False),
            (5, 0, 4, False),
            (56, 100, 156, True),
            (56, 101, 156, False),
            (10, u64_max, 100, False),
            (u64_max, 0, u64_max, True),
            (u64_max, 1, u64_max, False),
            (u64_max - 10, 10, u64_max, True),
            (u64_max - 10, 11, u64_max, False),
        ]
        for off, span, tot, exp in bounds_cases:
            self.assertEqual(native_ct_mem_bounds_ok(off, span, tot), exp, f"bounds({off},{span},{tot})")
            self.assertEqual(ct_mem_bounds_ok(off, span, tot), exp)
        self.assertFalse(ct_mem_bounds_ok(-1, 0, 10))
        self.assertFalse(ct_mem_bounds_ok(0, True, 10))  # type: ignore[arg-type]

        # 3. ct_cmov & ct_cswap parity across Native C99 vs Pure-Python
        try:
            for sz in (0, 1, 15, 32, 137, 1024):
                a = os.urandom(sz)
                b = os.urandom(sz)
                for cond in (False, True):
                    set_native_enabled(True)
                    cm_c = ct_cmov(cond, a, b)
                    sw_c = ct_cswap(cond, a, b)
                    set_native_enabled(False)
                    cm_p = ct_cmov(cond, a, b)
                    sw_p = ct_cswap(cond, a, b)
                    self.assertEqual(cm_c, cm_p)
                    self.assertEqual(cm_c, a if cond else b)
                    self.assertEqual(sw_c, sw_p)
                    self.assertEqual(sw_c, (b, a) if cond else (a, b))
        finally:
            set_native_enabled(True)

        # 4. Branchless openqpep_verify_wire_v5_magic across every magic class
        magic_cases = [
            (b"\x89QPE\x05\x00\x01\x00", 50),
            (b"\x89QPE\x05\x01\x01\x00", 51),
            (b"\x89QPE\x04\x00", -40),
            (b"\x89QPE\x04\x01", -40),
            (b"\x89QPE\x03\x00", -30),
            (b"\x89QPE\x03\x01", -30),
            (b"\x89QPE\x01\x01", -10),
            (b"\x89QPE\x01\x09", -10),
            (b"\x89QPE\x02\x00", -10),
            (b"\x89QPE\x05\x02", -1),
            (b"\x89QPE\x06\x00", -1),
            (b"\x88QPE\x05\x00", -1),
            (b"\x89QPE\x05", -1),
            (b"", -1),
        ]
        for hdr, exp in magic_cases:
            self.assertEqual(native_verify_wire_v5_magic(hdr), exp, f"magic={hdr!r}")

    def test_03_wire_v5_and_v51_zero_heap_pack_unpack_and_tlv_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        label = "OPENQPEP WIRE V5 PARITY TEST"
        lbl_b = label.encode("ascii")
        nonce = bytes(range(16))

        try:
            # 1. Exact bit-for-bit pack/unpack & whiten/MAC parity across rate boundaries
            for size in (0, 1, 71, 72, 73, 135, 136, 137, 512, 4097, 32768):
                body = os.urandom(size)
                # Direct C99 pack vs Pure-Python pack with fixed nonce
                set_native_enabled(True)
                frame_v5_c = native_wire_v5_pack(body, lbl_b, 0x01, 0x00, nonce, is_v51=False)
                self.assertIsNotNone(frame_v5_c)
                rc_c, out_c, ptype_c, flags_c = native_wire_v5_unpack(frame_v5_c, lbl_b, expect_v51=False)
                self.assertEqual((rc_c, out_c, ptype_c, flags_c), (0, body, 0x01, 0x00))

                # Unpack C99-packed frame in Pure-Python
                set_native_enabled(False)
                out_py, ptype_py = unpack_wire_frame(frame_v5_c, label)
                self.assertEqual((out_py, ptype_py), (body, 0x01))

                # Pack in Pure-Python, unpack in Native C99 (with and without bucket padding)
                frame_py = pack_wire_frame(body, label, packet_type=0x07, bucket_size=4096 if size == 512 else 0)
                set_native_enabled(True)
                out_c2, ptype_c2 = unpack_wire_frame(frame_py, label)
                self.assertEqual((out_c2, ptype_c2), (body, 0x07))

                # Verify standalone whiten_xor + compute_mac match packed frame slices
                hdr8 = frame_v5_c[:8]
                wh = native_wire_whiten_xor(hdr8, nonce, lbl_b, body, is_v51=False)
                self.assertEqual(wh, frame_v5_c[24:-32])
                self.assertEqual(native_wire_whiten_xor(hdr8, nonce, lbl_b, wh, is_v51=False), body)
                mac = native_wire_compute_mac(hdr8, nonce, lbl_b, wh, is_v51=False)
                self.assertEqual(mac, frame_v5_c[-32:])

            # 2. Compact Binary TLV v5.1 cross-backend pack/unpack & structural validation
            fields = {1: b"suite-qlx4096", 2: os.urandom(257), 42: b"", 255: os.urandom(140)}
            set_native_enabled(True)
            v51_c = pack_compact_v51(fields, label, packet_type=0x06)
            set_native_enabled(False)
            dec_py, pt_py, fl_py = unpack_compact_v51(v51_c, label)
            self.assertEqual((dec_py, pt_py, fl_py), (fields, 0x06, 0x00))

            v51_py = pack_compact_v51(fields, label, packet_type=0x08)
            set_native_enabled(True)
            dec_c, pt_c, fl_c = unpack_compact_v51(v51_py, label)
            self.assertEqual((dec_c, pt_c, fl_c), (fields, 0x08, 0x00))

            # TLV structural validator adversarial cases
            valid_tlv = encode_tlv(fields)
            self.assertEqual(native_wire_validate_tlv(valid_tlv), (True, 4))
            self.assertEqual(native_wire_validate_tlv(b""), (True, 0))
            # Duplicate tag
            dup_tlv = b"\x01\x00\x00\x00\x01A\x01\x00\x00\x00\x01B"
            self.assertEqual(native_wire_validate_tlv(dup_tlv, require_canonical_order=False), (False, 0))
            with self.assertRaises(QPEPWireFormatError):
                decode_tlv(dup_tlv, require_canonical_order=False)
            # Out-of-order tag
            ooo_tlv = b"\x05\x00\x00\x00\x01A\x02\x00\x00\x00\x01B"
            self.assertEqual(native_wire_validate_tlv(ooo_tlv, require_canonical_order=True), (False, 0))
            self.assertEqual(native_wire_validate_tlv(ooo_tlv, require_canonical_order=False), (True, 2))
            with self.assertRaises(QPEPWireFormatError):
                decode_tlv(ooo_tlv, require_canonical_order=True)
            # 32-bit length overflow (0xFFFFFFFF)
            ovf_tlv = b"\x01\xFF\xFF\xFF\xFFabc"
            self.assertEqual(native_wire_validate_tlv(ovf_tlv), (False, 0))
            with self.assertRaises(QPEPWireFormatError):
                decode_tlv(ovf_tlv)
            # Max fields limit
            self.assertEqual(native_wire_validate_tlv(valid_tlv, max_fields=3), (False, 0))

            # 3. Adversarial wire rejection: tampered MAC, wrong label, reserved flags, legacy magics
            bad_mac = v51_c[:-1] + bytes([v51_c[-1] ^ 0x01])
            with self.assertRaises(QPEPMacVerificationError):
                unpack_compact_v51(bad_mac, label)
            with self.assertRaises(QPEPMacVerificationError):
                unpack_compact_v51(v51_c, "WRONG LABEL")
            for legacy_magic in (b"\x89QPE\x04\x00", b"\x89QPE\x03\x00", b"\x89QPE\x01\x09"):
                with self.assertRaises(QPEPLegacyProtocolError):
                    unpack_wire_frame(legacy_magic + b"\x00" * 60, label)
                with self.assertRaises(QPEPLegacyProtocolError):
                    unpack_compact_v51(legacy_magic + b"\x00" * 60, label)
            bad_flags_frame = b"\x89QPE\x05\x00\x01\x02" + b"\x00" * 50
            with self.assertRaises(QPEPWireFormatError):
                unpack_wire_frame(bad_flags_frame, label)
        finally:
            set_native_enabled(True)

    def test_04_cc512_cmt4_and_siv_streaming_c99_vs_pure_python_parity(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        key64 = os.urandom(64)
        nonce24 = os.urandom(24)

        try:
            # 1. Subkeys, CMT-4 tag, SIV master/synth/msg keys exact Native <-> Pure-Python parity
            for pt_len in (0, 1, 71, 72, 73, 135, 136, 137, 4096, 32768):
                pt = os.urandom(pt_len)
                aad = os.urandom(19 if pt_len % 2 else 0)
                siv_nonce = os.urandom(24 if pt_len % 3 else 0)

                set_native_enabled(True)
                sub_c = _derive_cmt4_subkeys(key64, nonce24)
                tag_c = _compute_cmt4_tag(sub_c[64:96], nonce24, aad, pt)
                self.assertTrue(native_cc512_verify_cmt4_tag(sub_c[64:96], nonce24, aad, pt, tag_c))
                self.assertFalse(
                    native_cc512_verify_cmt4_tag(
                        sub_c[64:96], nonce24, aad, pt, bytes([tag_c[0] ^ 0x80]) + tag_c[1:]
                    )
                )
                mst_c = _derive_siv_master_subkeys(key64)
                siv_c = _compute_siv32(mst_c[:64], siv_nonce, aad, pt)
                mk_c = _derive_siv_message_keys(mst_c[64:128], siv_c)

                set_native_enabled(False)
                sub_p = _derive_cmt4_subkeys(key64, nonce24)
                tag_p = _compute_cmt4_tag(sub_p[64:96], nonce24, aad, pt)
                mst_p = _derive_siv_master_subkeys(key64)
                siv_p = _compute_siv32(mst_p[:64], siv_nonce, aad, pt)
                mk_p = _derive_siv_message_keys(mst_p[64:128], siv_p)

                self.assertEqual(sub_c, sub_p)
                self.assertEqual(tag_c, tag_p)
                self.assertEqual(mst_c, mst_p)
                self.assertEqual(siv_c, siv_p)
                self.assertEqual(mk_c, mk_p)

            # 2. Cross-backend CC-512 AEAD, CC-512-SIV & key wrap bit-exact parity
            msg = os.urandom(8193)
            aad = b"OpenQPEP v1.2.6 CC-512 cross-backend AAD"

            set_native_enabled(True)
            ct_c = cc512_encrypt(key64, nonce24, msg, aad)
            siv_ct_c = cc512_siv_encrypt(key64, msg, aad, nonce=b"siv-nonce")
            wrap_c = cc512_siv_wrap_key(key64, b"top-secret-key-material-32bytes!", aad)

            set_native_enabled(False)
            ct_p = cc512_encrypt(key64, nonce24, msg, aad)
            siv_ct_p = cc512_siv_encrypt(key64, msg, aad, nonce=b"siv-nonce")
            wrap_p = cc512_siv_wrap_key(key64, b"top-secret-key-material-32bytes!", aad)

            # Bit-for-bit identical ciphertexts across backends!
            self.assertEqual(ct_c, ct_p)
            self.assertEqual(siv_ct_c, siv_ct_p)
            self.assertEqual(wrap_c, wrap_p)

            # Cross-decrypt
            self.assertEqual(cc512_decrypt(key64, nonce24, ct_c, aad), msg)
            self.assertEqual(cc512_siv_decrypt(key64, siv_ct_c, aad, nonce=b"siv-nonce"), msg)
            self.assertEqual(cc512_siv_unwrap_key(key64, wrap_c, aad), b"top-secret-key-material-32bytes!")

            set_native_enabled(True)
            self.assertEqual(cc512_decrypt(key64, nonce24, ct_p, aad), msg)
            self.assertEqual(cc512_siv_decrypt(key64, siv_ct_p, aad, nonce=b"siv-nonce"), msg)
            with CC512SIV(key64) as box:
                self.assertEqual(box.decrypt(siv_ct_p, aad, nonce=b"siv-nonce"), msg)

            # 1-bit tamper rejection on CMT-4 tag & SIV
            with self.assertRaises(QPEPMacVerificationError):
                cc512_decrypt(key64, nonce24, ct_c[:-1] + bytes([ct_c[-1] ^ 0x01]), aad)
            with self.assertRaises(QPEPMacVerificationError):
                cc512_siv_decrypt(key64, bytes([siv_ct_c[0] ^ 0x01]) + siv_ct_c[1:], aad, nonce=b"siv-nonce")
        finally:
            set_native_enabled(True)

    def test_05_verified_speedup_wire_v5_whitening_and_ct_cmov(self):
        if not is_native_available():
            self.skipTest("Native C99 libopenqpep library not available.")

        payload = os.urandom(256 * 1024)  # 256 KiB frame
        label = "OPENQPEP V126 WIRE BENCHMARK"
        buf_a = os.urandom(64 * 1024)
        buf_b = os.urandom(64 * 1024)

        try:
            # Warmup
            set_native_enabled(True)
            f0 = pack_wire_frame(payload, label)
            self.assertEqual(unpack_wire_frame(f0, label)[0], payload)

            t0 = time.perf_counter()
            for _ in range(5):
                fr = pack_wire_frame(payload, label)
                out, _ = unpack_wire_frame(fr, label)
                self.assertEqual(len(out), len(payload))
            native_wire_s = (time.perf_counter() - t0) / 5.0

            set_native_enabled(False)
            t1 = time.perf_counter()
            for _ in range(2):
                fr_p = pack_wire_frame(payload, label)
                out_p, _ = unpack_wire_frame(fr_p, label)
                self.assertEqual(len(out_p), len(payload))
            pure_wire_s = (time.perf_counter() - t1) / 2.0

            wire_speedup = pure_wire_s / max(native_wire_s, 1e-9)
            self.assertGreater(
                wire_speedup,
                4.0,
                f"Expected >=4x Wire v5 framing speedup, got {wire_speedup:.1f}x "
                f"(C99={native_wire_s*1000:.2f}ms vs Py={pure_wire_s*1000:.2f}ms)",
            )

            # ct_cmov 64 KiB speedup
            set_native_enabled(True)
            t2 = time.perf_counter()
            for i in range(20):
                _ = ct_cmov((i & 1) == 0, buf_a, buf_b)
            native_cmov_s = (time.perf_counter() - t2) / 20.0

            set_native_enabled(False)
            t3 = time.perf_counter()
            for i in range(5):
                _ = ct_cmov((i & 1) == 0, buf_a, buf_b)
            pure_cmov_s = (time.perf_counter() - t3) / 5.0

            cmov_speedup = pure_cmov_s / max(native_cmov_s, 1e-9)
            self.assertGreater(
                cmov_speedup,
                10.0,
                f"Expected >=10x ct_cmov speedup, got {cmov_speedup:.1f}x "
                f"(C99={native_cmov_s*1000:.3f}ms vs Py={pure_cmov_s*1000:.3f}ms)",
            )
        finally:
            set_native_enabled(True)

    def test_06_external_c99_consumer_wire_cc512_ct_wpedantic(self):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No C compiler found on PATH.")

        consumer_c = r"""
#include <stdint.h>
#include <string.h>
#include "openqpep.h"

int main(void) {
    /* 1. Constant-time helpers & SIZE_MAX overflow bounds check */
    if (openqpep_ct_select_u32(0U, 0x11111111U, 0x22222222U) != 0x22222222U) return 1;
    if (openqpep_ct_select_u32(0x80000000U, 0x11111111U, 0x22222222U) != 0x11111111U) return 2;
    if (openqpep_ct_mem_bounds_ok(SIZE_MAX, 1U, SIZE_MAX) != 0) return 3;
    if (openqpep_ct_mem_bounds_ok(SIZE_MAX, 0U, SIZE_MAX) != 1) return 4;
    if (openqpep_ct_mem_bounds_ok(56U, 100U, 156U) != 1) return 5;
    if (openqpep_ct_mem_bounds_ok(56U, 101U, 156U) != 0) return 6;

    uint8_t a[16], b[16], a_orig[16], b_orig[16];
    for (size_t i = 0; i < 16; i++) {
        a[i] = a_orig[i] = (uint8_t)(i + 1U);
        b[i] = b_orig[i] = (uint8_t)(0xF0U - i);
    }
    openqpep_ct_cswap(0, a, b, 16U);
    if (!openqpep_ct_eq(a, a_orig, 16U) || !openqpep_ct_eq(b, b_orig, 16U)) return 7;
    openqpep_ct_cswap(-7, a, b, 16U);
    if (!openqpep_ct_eq(a, b_orig, 16U) || !openqpep_ct_eq(b, a_orig, 16U)) return 8;

    /* 2. Branchless Wire v5 / v5.1 magic validator */
    static const uint8_t m_v5[6]   = {0x89U, 'Q', 'P', 'E', 0x05U, 0x00U};
    static const uint8_t m_v51[6]  = {0x89U, 'Q', 'P', 'E', 0x05U, 0x01U};
    static const uint8_t m_rc[6]   = {0x89U, 'Q', 'P', 'E', 0x04U, 0x00U};
    static const uint8_t m_pc[6]   = {0x89U, 'Q', 'P', 'E', 0x03U, 0x01U};
    static const uint8_t m_beta[6] = {0x89U, 'Q', 'P', 'E', 0x01U, 0x09U};
    if (openqpep_verify_wire_v5_magic(m_v5, 6U) != OPENQPEP_WIRE_V5_FULL) return 9;
    if (openqpep_verify_wire_v5_magic(m_v51, 6U) != OPENQPEP_WIRE_V5_1_COMPACT) return 10;
    if (openqpep_verify_wire_v5_magic(m_rc, 6U) != OPENQPEP_WIRE_ERR_LEGACY_RC) return 11;
    if (openqpep_verify_wire_v5_magic(m_pc, 6U) != OPENQPEP_WIRE_ERR_LEGACY_PC) return 12;
    if (openqpep_verify_wire_v5_magic(m_beta, 6U) != OPENQPEP_WIRE_ERR_LEGACY_BETA) return 13;

    /* 3. Zero-heap Wire v5 pack/unpack + in-place whiten + tamper-untouched output */
    static const uint8_t label[] = "C99-WIRE-TEST";
    size_t label_len = sizeof(label) - 1U;
    uint8_t nonce[16];
    uint8_t body[300];
    uint8_t frame[300 + OPENQPEP_WIRE_V5_OVERHEAD];
    uint8_t out[300];
    for (size_t i = 0; i < 16U; i++) nonce[i] = (uint8_t)(i * 7U + 3U);
    for (size_t i = 0; i < 300U; i++) body[i] = (uint8_t)(i * 13U + 1U);

    if (openqpep_wire_v5_pack(body, 300U, label, label_len, 0x01U, 0x00U, nonce, 0, frame, sizeof(frame)) != OPENQPEP_OK) {
        return 14;
    }
    size_t out_len = 0U;
    uint8_t ptype = 0U, flags = 0xFFU;
    if (openqpep_wire_v5_unpack(frame, sizeof(frame), label, label_len, 0, out, sizeof(out), &out_len, &ptype, &flags) != OPENQPEP_OK) {
        return 15;
    }
    if (out_len != 300U || ptype != 0x01U || flags != 0x00U || !openqpep_ct_eq(out, body, 300U)) return 16;

    /* Tamper MAC and verify authenticate-then-unwhiten leaves `out` untouched */
    memset(out, 0xAA, sizeof(out));
    frame[sizeof(frame) - 1U] ^= 0x01U;
    if (openqpep_wire_v5_unpack(frame, sizeof(frame), label, label_len, 0, out, sizeof(out), &out_len, &ptype, &flags) != OPENQPEP_ERR_AUTH_FAIL) {
        return 17;
    }
    for (size_t i = 0; i < sizeof(out); i++) {
        if (out[i] != 0xAAU) return 18;
    }
    frame[sizeof(frame) - 1U] ^= 0x01U;

    /* In-place whiten round-trip */
    memcpy(out, body, 300U);
    if (openqpep_wire_whiten_xor(frame, nonce, label, label_len, 0, out, out, 300U) != OPENQPEP_OK) return 19;
    if (!openqpep_ct_eq(out, frame + 24, 300U)) return 20;
    if (openqpep_wire_whiten_xor(frame, nonce, label, label_len, 0, out, out, 300U) != OPENQPEP_OK) return 21;
    if (!openqpep_ct_eq(out, body, 300U)) return 22;

    /* 4. Compact TLV v5.1 validator */
    static const uint8_t tlv_ok[] = {0x01U, 0, 0, 0, 2, 'O', 'K', 0x05U, 0, 0, 0, 1, 'X'};
    static const uint8_t tlv_dup[] = {0x02U, 0, 0, 0, 1, 'A', 0x02U, 0, 0, 0, 1, 'B'};
    uint32_t fcnt = 0U;
    if (openqpep_wire_validate_tlv(tlv_ok, sizeof(tlv_ok), 1, 16U, &fcnt) != OPENQPEP_OK || fcnt != 2U) return 23;
    if (openqpep_wire_validate_tlv(tlv_dup, sizeof(tlv_dup), 0, 16U, &fcnt) != OPENQPEP_ERR_WIRE_FORMAT) return 24;

    /* 5. Zero-heap CC-512 CMT-4 & SIV helpers */
    uint8_t key64[64], nonce24[24], sub96[96], tag32[32], mst128[128], siv32[32], mk88[88];
    for (size_t i = 0; i < 64U; i++) key64[i] = (uint8_t)(i + 0x20U);
    for (size_t i = 0; i < 24U; i++) nonce24[i] = (uint8_t)(i + 0x80U);
    if (openqpep_cc512_derive_cmt4_subkeys(key64, nonce24, sub96) != OPENQPEP_OK) return 25;
    if (openqpep_cc512_cmt4_tag(sub96 + 64, nonce24, label, label_len, body, 300U, tag32) != OPENQPEP_OK) return 26;
    if (openqpep_cc512_verify_cmt4_tag(sub96 + 64, nonce24, label, label_len, body, 300U, tag32) != OPENQPEP_OK) return 27;
    tag32[0] ^= 0x01U;
    if (openqpep_cc512_verify_cmt4_tag(sub96 + 64, nonce24, label, label_len, body, 300U, tag32) != OPENQPEP_ERR_AUTH_FAIL) return 28;
    if (openqpep_cc512_siv_master_subkeys(key64, mst128) != OPENQPEP_OK) return 29;
    if (openqpep_cc512_siv_synth(mst128, nonce, 16U, label, label_len, body, 300U, siv32) != OPENQPEP_OK) return 30;
    if (openqpep_cc512_siv_msg_keys(mst128 + 64, siv32, mk88) != OPENQPEP_OK) return 31;

    /* NULL pointer guard */
    if (openqpep_wire_v5_pack(NULL, 10U, label, label_len, 1U, 0U, nonce, 0, frame, sizeof(frame)) != OPENQPEP_ERR_NULL_PTR) return 32;
    return 0;
}
"""
        ext = "dylib" if platform.system() == "Darwin" else "so"
        shared_lib = NATIVE_DIR / f"libopenqpep.{ext}"
        static_lib = NATIVE_DIR / "libopenqpep.a"
        if not (shared_lib.is_file() and static_lib.is_file()):
            self.skipTest("Native static/shared libraries not built.")

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test_v126.c"
            bin_static = Path(tmp) / "test_v126_static"
            bin_shared = Path(tmp) / "test_v126_shared"
            src.write_text(consumer_c, encoding="utf-8")

            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    "-DOPENQPEP_STATIC", f"-I{CSRC_DIR / 'include'}",
                    str(src), str(static_lib), "-o", str(bin_static),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(bin_static)], check=True, capture_output=True, text=True)

            subprocess.run(
                [
                    cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                    f"-I{CSRC_DIR / 'include'}",
                    str(src), f"-L{NATIVE_DIR}", "-lopenqpep", f"-Wl,-rpath,{NATIVE_DIR}",
                    "-o", str(bin_shared),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = f"{NATIVE_DIR}:{env.get('LD_LIBRARY_PATH', '')}"
            subprocess.run([str(bin_shared)], env=env, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
