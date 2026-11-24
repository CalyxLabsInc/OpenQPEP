"""
OpenQPEP Official Release 1.1.8 (v1.1.8) Test Suite:
Parser Resource Ceilings, Depth Limits & Zip-Bomb / Algorithmic-Complexity Defenses.

Verifies:
  1. Strict RFC 4648 Section 3.5 canonical Base64 decoding (rejects every non-zero trailing-bit
     malleability variant, URL-safe variants, whitespace, bad length, and non-ASCII).
  2. Strict iterative O(N) JSON recursion-depth (MAX_JSON_DEPTH = 32) and complexity node limits
     (MAX_JSON_NODES = 250,000) without ever raising RecursionError, plus escaped-string accuracy.
  3. Dual zip-bomb decompression defense (hard byte ceiling + 200:1 compression-ratio ceiling
     above 1 MiB + trailing-byte smuggling rejection).
  4. CPU/RAM-bound ASCII armor ceilings (MAX_ARMOR_BODY_LINE_LEN, MAX_ARMOR_BLANK_LINES,
     MAX_ARMOR_LINES, post-CRC body-line rejection, strict 8-char canonical Base64 CRC).
  5. Compact TLV v5.1 canonical ascending tag order, max_fields, bool rejection, and Wire v5
     bucket-size & label bounds.
  6. Streaming AEAD chunk-count / total-bytes ceilings, reserved header flags, and canonical
     is_final_byte in (0, 1) enforcement across decrypt_stream and decrypt_byte_range.
  7. Protocol packet chunk-count ceiling (MAX_PACKET_CHUNKS) and multi-recipient slot-count
     ceiling (MAX_MULTI_RECIPIENT_SLOTS) + end-to-end protocol regression checks.
"""
import base64
import io
import json
import os
import struct
import unittest
import zlib

from calyx_qpep import (
    MANDATORY_KDF_VERSION,
    OpenQPEPProtocol,
    PROTOCOL_VERSION,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPWireFormatError,
    UNIVERSAL_VERSION,
    UNIVERSAL_VERSION_LABEL,
    safe_zlib_decompress,
    strict_b64decode,
    strict_json_loads,
)
from calyx_qpep.protocol import MAX_PACKET_CHUNKS, _armor_unwrap, _armor_wrap
from calyx_qpep.wire import (
    MAX_ARMOR_BLANK_LINES,
    MAX_ARMOR_BODY_LINE_LEN,
    MAX_BUCKET_SIZE,
    MAX_JSON_DEPTH,
    MAX_MULTI_RECIPIENT_SLOTS,
    MULTI_RECIPIENT_ARMOR_LABEL,
    StreamingDecryptor,
    StreamingEncryptor,
    armor_unwrap,
    armor_wrap,
    decode_tlv,
    encode_tlv,
    pack_compact_v51,
    pack_wire_frame,
    pad_to_bucket,
    unpack_compact_v51,
    unpack_wire_frame,
)
from calyx_qpep.wire.streaming import CHUNK_PREFIX_STRUCT, HEADER_STRUCT


class TestOpenQPEPv118ParserResourceCeilings(unittest.TestCase):
    PASS = "Calyx!@#$_2026v118Aa99"

    def test_01_version_metadata_is_118(self):
        self.assertEqual(UNIVERSAL_VERSION, "1.1.8")
        self.assertEqual(UNIVERSAL_VERSION_LABEL, "Official Release 1.1.8")
        self.assertEqual(PROTOCOL_VERSION, "OpenQPEP/1.1.8")
        self.assertEqual(MANDATORY_KDF_VERSION, 4)

    def test_02_strict_canonical_base64_rejects_non_zero_trailing_bits_and_malleability(self):
        # All valid canonical lengths round-trip cleanly
        for n in (0, 1, 2, 3, 4, 5, 15, 16, 31, 32, 63, 64):
            raw = os.urandom(n)
            enc = base64.b64encode(raw).decode("ascii")
            self.assertEqual(strict_b64decode(enc), raw)

        # b"a" -> canonical "YQ==" (sextet 'Q'=16 has 4 low bits == 0).
        # ALL 15 malleable variants ('R'..'f') MUST be rejected!
        self.assertEqual(strict_b64decode("YQ=="), b"a")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for offset in range(1, 16):
            malleated = "Y" + alphabet[16 + offset] + "=="
            # Confirm Python stdlib validate=True WOULD accept it, proving our defense closes a real gap
            self.assertEqual(base64.b64decode(malleated, validate=True), b"a")
            with self.assertRaises(QPEPWireFormatError):
                strict_b64decode(malleated)

        # b"ab" -> canonical "YWI=" (sextet 'I'=8 has 2 low bits == 0).
        # ALL 3 malleable variants ('J', 'K', 'L') MUST be rejected!
        self.assertEqual(strict_b64decode("YWI="), b"ab")
        for bad_ch in ("J", "K", "L"):
            malleated = "YW" + bad_ch + "="
            self.assertEqual(base64.b64decode(malleated, validate=True), b"ab")
            with self.assertRaises(QPEPWireFormatError):
                strict_b64decode(malleated)

        # Reject URL-safe alphabet, internal whitespace, unpadded, non-ASCII, misplaced '='
        for bad_b64 in (
            "YWJj-_==",
            "YWJj\nZA==",
            "YW Jj",
            "YQ",
            "====",
            "YQ=A",
            "Y\u00e9==",
            12345,
        ):
            with self.assertRaises(QPEPWireFormatError):
                strict_b64decode(bad_b64)  # type: ignore[arg-type]

        # Non-canonical Base64 injected into an armored OpenQPEP Wire v5 frame MUST be rejected
        armored = armor_wrap("CALYX QPEP TEST", b"malleability-check-1")
        lines = armored.splitlines()
        # Find the last Base64 body line (just before =CRC)
        b64_idx = next(i for i in range(len(lines) - 1, -1, -1) if lines[i].startswith("=")) - 1
        last_line = lines[b64_idx]
        if last_line.endswith("=="):
            val = alphabet.index(last_line[-3])
            lines[b64_idx] = last_line[:-3] + alphabet[val | 1] + "=="
        elif last_line.endswith("="):
            val = alphabet.index(last_line[-2])
            lines[b64_idx] = last_line[:-2] + alphabet[val | 1] + "="
        else:
            # Force a payload whose frame length mod 3 != 0 (e.g. len 1 -> 57 % 3 == 0, len 2 -> 58 % 3 == 1 -> "==")
            armored = armor_wrap("CALYX QPEP TEST", b"AB")
            lines = armored.splitlines()
            b64_idx = next(i for i in range(len(lines) - 1, -1, -1) if lines[i].startswith("=")) - 1
            last_line = lines[b64_idx]
            self.assertTrue(last_line.endswith("=="))
            val = alphabet.index(last_line[-3])
            lines[b64_idx] = last_line[:-3] + alphabet[val | 1] + "=="
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap("\n".join(lines) + "\n", "CALYX QPEP TEST")

    def test_03_strict_json_depth_and_complexity_node_limits(self):
        # Extreme nesting (depth 2000) MUST raise QPEPWireFormatError cleanly (never RecursionError!)
        deep_obj = '{"a":' * 2000 + "1" + "}" * 2000
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads(deep_obj)

        deep_arr = "[" * 500 + "]" * 500
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads(deep_arr)

        # Exact boundary: depth == MAX_JSON_DEPTH succeeds, MAX_JSON_DEPTH + 1 fails
        exact_ok = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
        self.assertIsInstance(strict_json_loads(exact_ok), list)
        too_deep = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads(too_deep)

        # Braces, quotes, and escaped backslashes inside JSON strings MUST NOT trip depth scanner
        tricky = json.dumps({"s": 'a { [ " \\" \\\\ } ] ' + "{" * 100})
        parsed = strict_json_loads(tricky)
        self.assertIn('\\" \\\\', parsed["s"])

        # Node-count complexity bomb rejected cleanly
        wide_list = "[" + ",".join(["1"] * 150) + "]"
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads(wide_list, max_nodes=100)

        # Duplicate keys and NaN/Infinity remain rejected
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads('{"k":1,"k":2}')
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads('{"x":NaN}')
        with self.assertRaises(QPEPWireFormatError):
            strict_json_loads('{"x":Infinity}')

    def test_04_zip_bomb_ratio_ceiling_and_trailing_data_rejection(self):
        # 5 MiB of zeros compresses to ~5 KiB (~1000:1 ratio) — WELL UNDER 128 MiB max_bytes,
        # yet MUST be caught by the 200:1 zip-bomb ratio ceiling!
        zeros_5m = b"\x00" * (5 * 1024 * 1024)
        bomb = zlib.compress(zeros_5m, level=9)
        self.assertLess(len(bomb), 16384)
        with self.assertRaises(QPEPWireFormatError):
            safe_zlib_decompress(bomb)

        # Trailing garbage smuggled after zlib EOF MUST be rejected
        legit_comp = zlib.compress(b"OpenQPEP v1.1.8 legitimate compressed payload", level=6)
        self.assertEqual(safe_zlib_decompress(legit_comp), b"OpenQPEP v1.1.8 legitimate compressed payload")
        with self.assertRaises(QPEPWireFormatError):
            safe_zlib_decompress(legit_comp + b"SMUGGLED")

        # Corrupt / empty zlib payloads rejected
        with self.assertRaises(QPEPWireFormatError):
            safe_zlib_decompress(b"")
        with self.assertRaises(QPEPWireFormatError):
            safe_zlib_decompress(b"\x78\x9c\xff\xff\xff")

        # Small repetitive payloads (< 1 MiB) and normal-ratio >1 MiB payloads succeed cleanly
        small_rep = zlib.compress(b"A" * 10000, level=9)
        self.assertEqual(safe_zlib_decompress(small_rep), b"A" * 10000)

        randomish_1_2m = os.urandom(1200 * 1024)
        comp_normal = zlib.compress(randomish_1_2m, level=1)
        self.assertEqual(safe_zlib_decompress(comp_normal), randomish_1_2m)

    def test_05_armor_cpu_and_line_ceilings_and_strict_crc(self):
        # Oversized single-line Base64 body (> MAX_ARMOR_BODY_LINE_LEN = 128) rejected
        armored = armor_wrap("CALYX QPEP TEST", b"A" * 256)
        lines = armored.splitlines()
        sep_idx = lines.index("")
        crc_idx = next(i for i, ln in enumerate(lines) if ln.startswith("="))
        joined_body = "".join(lines[sep_idx + 1 : crc_idx])
        self.assertGreater(len(joined_body), MAX_ARMOR_BODY_LINE_LEN)
        single_line_armor = "\n".join(lines[: sep_idx + 1] + [joined_body] + lines[crc_idx:]) + "\n"
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap(single_line_armor, "CALYX QPEP TEST")
        with self.assertRaises(QPEPWireFormatError):
            _armor_unwrap(single_line_armor, expected_label="CALYX QPEP TEST")

        # Excessive blank lines inside armor body rejected
        blank_flood = "\n".join(
            lines[: sep_idx + 1] + [""] * (MAX_ARMOR_BLANK_LINES + 5) + lines[sep_idx + 1 :]
        ) + "\n"
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap(blank_flood, "CALYX QPEP TEST")
        with self.assertRaises(QPEPWireFormatError):
            _armor_unwrap(blank_flood, expected_label="CALYX QPEP TEST")

        # Body line injected after =CRC rejected
        post_crc = "\n".join(lines[: crc_idx + 1] + ["AAAA"] + lines[crc_idx + 1 :]) + "\n"
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap(post_crc, "CALYX QPEP TEST")

        # Wrong-length or non-canonical Base64 CRC rejected with QPEPWireFormatError
        short_crc = "\n".join(("=AAAA" if ln.startswith("=") else ln) for ln in lines) + "\n"
        with self.assertRaises(QPEPWireFormatError):
            armor_unwrap(short_crc, "CALYX QPEP TEST")
        # Canonical 8-char wrong CRC raises QPEPMacVerificationError
        wrong_crc = "\n".join(("=AAAAAAAA" if ln.startswith("=") else ln) for ln in lines) + "\n"
        with self.assertRaises(QPEPMacVerificationError):
            armor_unwrap(wrong_crc, "CALYX QPEP TEST")

        # Legacy Wire v4 frame still raises QPEPLegacyProtocolError deterministically
        legacy_b64 = base64.b64encode(b"\x89QPE\x04\x00" + b"\x00" * 60).decode("ascii")
        legacy_wrapped = "\n".join(legacy_b64[i : i + 64] for i in range(0, len(legacy_b64), 64))
        legacy_armor = (
            "-----BEGIN CALYX QPEP TEST-----\n\n"
            + legacy_wrapped
            + "\n=AAAAAAAA\n"
            + "-----END CALYX QPEP TEST-----\n"
        )
        with self.assertRaises(QPEPLegacyProtocolError):
            armor_unwrap(legacy_armor, "CALYX QPEP TEST")

    def test_06_compact_tlv_v51_canonical_order_and_framing_ceilings(self):
        # Canonical ascending tag order succeeds; out-of-order tags rejected
        canon = encode_tlv({1: b"one", 2: b"two", 10: b"ten"})
        self.assertEqual(decode_tlv(canon), {1: b"one", 2: b"two", 10: b"ten"})

        unordered = encode_tlv({2: b"two"}) + encode_tlv({1: b"one"})
        with self.assertRaises(QPEPWireFormatError):
            decode_tlv(unordered)
        # Explicit opt-out allows unordered if ever needed for diagnostic tooling
        self.assertEqual(decode_tlv(unordered, require_canonical_order=False), {2: b"two", 1: b"one"})

        # max_fields ceiling enforced
        with self.assertRaises(QPEPWireFormatError):
            decode_tlv(canon, max_fields=2)

        # Bool confusion, invalid labels, oversized bucket_size rejected
        with self.assertRaises(QPEPWireFormatError):
            encode_tlv({True: b"bad"})  # type: ignore[dict-item]
        with self.assertRaises(QPEPWireFormatError):
            pack_compact_v51({1: b"x"}, "BAD\nLABEL")
        with self.assertRaises(QPEPWireFormatError):
            pack_compact_v51({1: b"x"}, "OK", packet_type=True)  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            pad_to_bucket(b"x", bucket_size=MAX_BUCKET_SIZE + 1)
        with self.assertRaises(QPEPWireFormatError):
            pad_to_bucket(b"x", bucket_size=True)  # type: ignore[arg-type]
        with self.assertRaises(QPEPWireFormatError):
            pack_wire_frame(b"x", "INVALID\x00LABEL")
        with self.assertRaises(QPEPWireFormatError):
            unpack_wire_frame(pack_wire_frame(b"x", "OK"), "BAD\tLABEL")
        with self.assertRaises(QPEPWireFormatError):
            unpack_compact_v51(pack_compact_v51({1: b"x"}, "OK"), "BAD\rLABEL")

    def test_07_streaming_chunk_count_total_bytes_and_canonical_flags(self):
        key64 = os.urandom(64)
        payload = os.urandom(5000)
        enc_buf = io.BytesIO()
        with StreamingEncryptor(key64, chunk_size=1024, merkle_seekable=True) as enc:
            meta = enc.encrypt_stream(io.BytesIO(payload), enc_buf)
        raw = enc_buf.getvalue()
        self.assertEqual(meta["chunk_count"], 5)

        # Enforces max_chunks ceiling
        with StreamingDecryptor(key64) as dec:
            with self.assertRaises(QPEPWireFormatError):
                dec.decrypt_stream(io.BytesIO(raw), io.BytesIO(), max_chunks=3)

        # Enforces max_total_bytes ceiling
        with StreamingDecryptor(key64) as dec:
            with self.assertRaises(QPEPWireFormatError):
                dec.decrypt_stream(io.BytesIO(raw), io.BytesIO(), max_total_bytes=2048)

        # Rejects non-zero reserved header flags (bit 1)
        bad_flags = bytearray(raw)
        magic, cs, _flags, bn = HEADER_STRUCT.unpack(raw[: HEADER_STRUCT.size])
        bad_flags[: HEADER_STRUCT.size] = HEADER_STRUCT.pack(magic, cs, 0x00000003, bn)
        with StreamingDecryptor(key64) as dec:
            with self.assertRaises(QPEPWireFormatError):
                dec.decrypt_stream(io.BytesIO(bytes(bad_flags)), io.BytesIO())

        # Rejects non-canonical is_final_byte == 2 in chunk prefix
        bad_final = bytearray(raw)
        off0 = meta["chunk_offsets"][0]
        cidx, _isf, clen = CHUNK_PREFIX_STRUCT.unpack(raw[off0 : off0 + CHUNK_PREFIX_STRUCT.size])
        bad_final[off0 : off0 + CHUNK_PREFIX_STRUCT.size] = CHUNK_PREFIX_STRUCT.pack(cidx, 2, clen)
        with StreamingDecryptor(key64) as dec:
            with self.assertRaises(QPEPWireFormatError):
                dec.decrypt_stream(io.BytesIO(bytes(bad_final)), io.BytesIO())
            with self.assertRaises(QPEPWireFormatError):
                dec.decrypt_byte_range(
                    io.BytesIO(bytes(bad_final)),
                    0,
                    64,
                    chunk_offsets=meta["chunk_offsets"],
                    merkle_levels=meta["merkle_levels"],
                    merkle_root=meta["merkle_root"],
                )

    def test_08_protocol_chunk_limit_multi_recipient_slot_ceiling_and_roundtrip(self):
        kr = OpenQPEPProtocol.generate_keypair("CeilUser", "ceil@calyxmail.org", self.PASS, qlx_tier="QLX-768")
        pub_kr = OpenQPEPProtocol.import_qpkrf(OpenQPEPProtocol.export_qpkrf(kr, include_private=False))

        # Standard roundtrip passes under all hardened v1.1.8 parsers
        pkt = OpenQPEPProtocol.encrypt_text("Hardened v1.1.8 roundtrip message!", pub_kr, kr, self.PASS)
        pt, meta = OpenQPEPProtocol.decrypt_packet(pkt, kr, self.PASS, sender_public_keyring=pub_kr)
        self.assertEqual(pt.decode("utf-8"), "Hardened v1.1.8 roundtrip message!")
        self.assertTrue(meta["signature_verified"])

        # Craft packet with MAX_PACKET_CHUNKS + 1 chunks -> rejected before decrypting chunks
        _, _, pkt_json = _armor_unwrap(pkt, expected_label="CALYX QPEP ENCRYPTED PACKET")
        pkt_obj = strict_json_loads(pkt_json)
        pkt_obj["chunks"] = [pkt_obj["chunks"][0]] * (MAX_PACKET_CHUNKS + 1)
        over_chunks_pkt = _armor_wrap(
            "CALYX QPEP ENCRYPTED PACKET",
            {"Protocol": "OpenQPEP"},
            json.dumps(pkt_obj, separators=(",", ":")).encode("utf-8"),
        )
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.decrypt_packet(over_chunks_pkt, kr, self.PASS)

        # Multi-recipient slot ceiling enforced (> MAX_MULTI_RECIPIENT_SLOTS rejected)
        mr_pkt = OpenQPEPProtocol.encrypt_multi_recipient(b"broadcast-v118", [pub_kr])
        mr_pt, _ = OpenQPEPProtocol.decrypt_multi_recipient(mr_pkt, kr, self.PASS)
        self.assertEqual(mr_pt, b"broadcast-v118")

        mr_raw, _ = armor_unwrap(mr_pkt, MULTI_RECIPIENT_ARMOR_LABEL)
        mr_env = strict_json_loads(mr_raw)
        mr_env["slots"] = [mr_env["slots"][0]] * (MAX_MULTI_RECIPIENT_SLOTS + 1)
        mr_bomb = armor_wrap(
            MULTI_RECIPIENT_ARMOR_LABEL,
            json.dumps(mr_env, separators=(",", ":")).encode("utf-8"),
            packet_type=0x02,
        )
        with self.assertRaises(QPEPWireFormatError):
            OpenQPEPProtocol.decrypt_multi_recipient(mr_bomb, kr, self.PASS)


if __name__ == "__main__":
    unittest.main()
