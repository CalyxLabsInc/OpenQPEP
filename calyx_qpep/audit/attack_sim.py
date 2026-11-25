"""
OpenQPEP Active Cryptographic Attack Simulator (Official Release 1.2.7 — Phase 1 Consolidation).
Simulates real-world adversarial attacks across the full Phase 1 security surface:
  1. Ciphertext malleability / chosen-ciphertext attacks against Fujisaki-Okamoto (`QLX`)
  2. Rowhammer/glitch fault injection inside `QVSEngine.sign` (`QPEPFaultGuardError`)
  3. Stream chunk truncation, reordering, trailing-byte injection, reserved flags & non-canonical `is_final`
  4. Suite downgrade attacks against `.qpkrf` `integrity_mac` & Wire v5 MAC + legacy `-rc`/`-pc`/`-beta` downgrade
  5. RFC 8032 Ed448 small-order `E[4]` (`S=0`) torsion forgeries, `S >= L` malleability & RFC 7748 X448 low-order points
  6. RFC 4648 §3.5 non-canonical Base64 trailing-bit malleability, armor DoS ceilings & out-of-order TLV tags
  7. Duplicate JSON key substitution, `NaN`/`Infinity`, 2,000-level JSON depth bombs & Unicode homograph/Bidi UID spoofing
  8. Replay attacks (`QPEP-Ratchet`, `QPEP-MLS`, `Sphinx-PQ`), CMT-4 `CC-512`/`CC-512-SIV` key-commitment forgery,
     KDF OOM-bombs (`64 GiB`), and 1,000:1 zlib zip-bombs
  9. Multi-suite Verify-Before-Emit Fault-Guard verification (`QVS`, `Ed448`, `QHS-512`, `QMQ-512`, `CIF-SQI-512`)
"""
import base64
import copy
import io
import json
import os
import zlib
from typing import Any, Dict
from unittest.mock import patch

from ..constants import ALL_LEGACY_WIRE_MAGICS
from ..exceptions import (
    OpenQPEPError,
    QPEPFaultGuardError,
    QPEPKeyRingError,
    QPEPLegacyProtocolError,
    QPEPMacVerificationError,
    QPEPSuiteError,
    QPEPTruncationError,
    QPEPWireFormatError,
)
from ..group.mls_epoch import QPEPGroupMember, QPEPGroupSession
from ..hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from ..isogeny.sqi_2d_512 import SupersingularIsogenyEngine
from ..kdf.argon2id_cascade import validate_kdf_params
from ..lattice.qlx_kem import QLXEngine
from ..lattice.qvs_dsa import QVSEngine
from ..mixnet.sphinx_pq import MixNode, SphinxPQRouter
from ..multivariate.qmq_512 import MultivariateQuadraticEngine
from ..primitives import hgc448 as hgc448_mod
from ..primitives.cc512_aead import cc512_decrypt, cc512_encrypt, cc512_siv_decrypt, cc512_siv_encrypt
from ..primitives.hgc448 import (
    CURVE448_P,
    ED448_ORDER_L,
    ED448_SMALL_ORDER_POINTS,
    X448_LOW_ORDER_POINTS,
    ed448_keygen,
    ed448_sign,
    strict_ed448_verify,
    validate_x448_public_key,
    x448_exchange,
    x448_keygen,
)
from ..protocol import OpenQPEPProtocol
from ..ratchet.session_state import QPEPRatchetSession
from ..wire.armor import (
    MAX_ARMOR_BLANK_LINES,
    armor_unwrap,
    armor_wrap,
    safe_zlib_decompress,
    strict_b64decode,
    strict_json_loads,
)
from ..wire.compact_v51 import decode_tlv, encode_tlv
from ..wire.framing import unpack_wire_frame
from ..wire.streaming import CHUNK_PREFIX_STRUCT, HEADER_STRUCT, StreamingDecryptor, StreamingEncryptor


def simulate_fo_cca2_malleability(tier: str = "QLX-768", trials: int = 20) -> Dict[str, Any]:
    ek, dk = QLXEngine.keygen(tier, os.urandom(64))
    ct, ss_real = QLXEngine.encaps(ek, tier)
    rejected = 0
    for i in range(trials):
        pos = (i * 53) % len(ct)
        tampered = ct[:pos] + bytes([ct[pos] ^ (1 << (i % 8))]) + ct[pos + 1 :]
        ss_a = QLXEngine.decaps(dk, tampered, tier)
        ss_b = QLXEngine.decaps(dk, tampered, tier)
        if ss_a != ss_real and ss_a == ss_b and len(ss_a) == 32:
            rejected += 1
    return {"attack": "FO_CCA2_Malleability", "tier": tier, "trials": trials, "defended": rejected, "passed": rejected == trials}


def simulate_qvs_fault_injection(tier: str = "QVS-65", trials: int = 5) -> Dict[str, Any]:
    pk, sk = QVSEngine.keygen(tier, os.urandom(64))
    caught = 0
    with patch.object(QVSEngine, "verify", return_value=False):
        for i in range(trials):
            try:
                QVSEngine.sign(sk, pk, f"fault-{i}".encode("utf-8"), tier=tier)
            except QPEPFaultGuardError:
                caught += 1
    return {"attack": "QVS_Fault_Injection", "tier": tier, "trials": trials, "defended": caught, "passed": caught == trials}


def simulate_stream_truncation_and_reorder() -> Dict[str, Any]:
    key64 = os.urandom(64)
    payload = os.urandom(150 * 1024)
    enc_buf = io.BytesIO()
    with StreamingEncryptor(key64, chunk_size=65536, merkle_seekable=True) as enc:
        meta = enc.encrypt_stream(io.BytesIO(payload), enc_buf)
    raw = enc_buf.getvalue()
    offsets = meta["chunk_offsets"]

    defended = 0
    # 1. Truncation before terminal final=1 chunk
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(raw[: offsets[1]]), io.BytesIO())
    except QPEPTruncationError:
        defended += 1

    # 2. Chunk reordering
    swapped = raw[: offsets[0]] + raw[offsets[1] : offsets[2]] + raw[offsets[0] : offsets[1]] + raw[offsets[2] :]
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(swapped), io.BytesIO())
    except QPEPMacVerificationError:
        defended += 1

    # 3. Trailing byte injection after terminal chunk
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(raw + b"\x00"), io.BytesIO())
    except QPEPWireFormatError:
        defended += 1

    # 4. Non-zero reserved stream header flag bit
    bad_hdr = bytearray(raw)
    magic, cs, _flags, bn = HEADER_STRUCT.unpack(raw[: HEADER_STRUCT.size])
    bad_hdr[: HEADER_STRUCT.size] = HEADER_STRUCT.pack(magic, cs, 0x00000002, bn)
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(bytes(bad_hdr)), io.BytesIO())
    except QPEPWireFormatError:
        defended += 1

    # 5. Non-canonical is_final flag byte (2 instead of 0/1)
    bad_final = bytearray(raw)
    cidx, _isf, clen = CHUNK_PREFIX_STRUCT.unpack(raw[offsets[0] : offsets[0] + CHUNK_PREFIX_STRUCT.size])
    bad_final[offsets[0] : offsets[0] + CHUNK_PREFIX_STRUCT.size] = CHUNK_PREFIX_STRUCT.pack(cidx, 2, clen)
    try:
        with StreamingDecryptor(key64) as dec:
            dec.decrypt_stream(io.BytesIO(bytes(bad_final)), io.BytesIO())
    except QPEPWireFormatError:
        defended += 1

    return {"attack": "Stream_Truncation_Reorder_Injection", "trials": 5, "defended": defended, "passed": defended == 5}


def simulate_suite_downgrade_attack() -> Dict[str, Any]:
    pw = "Calyx!@#$_2026DownAa99"
    kr = OpenQPEPProtocol.generate_keypair("DowngradeTarget", "dg@calyxlabsinc.org", pw, qlx_tier="QLX-1024")
    pub_armor = OpenQPEPProtocol.export_qpkrf(kr, include_private=False)

    sep = pub_armor.find("\n\n")
    end = pub_armor.rfind("\n=")
    if end == -1:
        end = pub_armor.rfind("\n-----END ")
    b64_body = "".join(ln for ln in pub_armor[sep + 2 : end].splitlines() if not ln.startswith("="))
    raw = base64.b64decode(b64_body)
    try:
        doc = json.loads(raw.decode("utf-8"))
        doc["qlx_tier"] = "QLX-768"
        tampered_raw = json.dumps(doc).encode("utf-8")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        tampered_raw = bytes([raw[0] ^ 0x01]) + raw[1:]

    tampered_b64 = base64.b64encode(tampered_raw).decode("ascii")
    tampered_wrapped = "\n".join(tampered_b64[i : i + 64] for i in range(0, len(tampered_b64), 64))
    tampered = pub_armor[: sep + 2] + tampered_wrapped + pub_armor[end:]

    trials = 0
    defended = 0

    # 1. Tampered .qpkrf suite downgrade
    trials += 1
    try:
        OpenQPEPProtocol.import_qpkrf(tampered)
    except (OpenQPEPError, ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        defended += 1

    # 2. Legacy wire magic downgrade (-rc, -pc, -beta)
    for legacy_magic in ALL_LEGACY_WIRE_MAGICS:
        trials += 1
        try:
            unpack_wire_frame(legacy_magic + b"\x00" * 64, "CALYX QPEP MESSAGE")
        except QPEPLegacyProtocolError:
            defended += 1

    # 3. Legacy kdf_version < 4 downgrade on private keyring unlock
    for legacy_kdf in (1, 2, 3):
        trials += 1
        kr_leg = copy.deepcopy(kr)
        kr_leg.encrypted_private_bundle["kdf_version"] = legacy_kdf
        kr_leg.encrypted_private_bundle["kdf_params"] = {"kdf_version": legacy_kdf}
        try:
            OpenQPEPProtocol.unlock_private_keys(kr_leg, pw)
        except QPEPLegacyProtocolError:
            defended += 1

    return {"attack": "Suite_And_Protocol_Downgrade", "trials": trials, "defended": defended, "passed": defended == trials}


def simulate_ed448_small_order_and_x448_low_order_attack() -> Dict[str, Any]:
    """Tests RFC 8032 Ed448 E[4] small-order S=0 forgeries, S >= L malleability, and RFC 7748 X448 low-order points."""
    trials = 0
    defended = 0
    msg = b"OpenQPEP Phase 1 Ed448 small-order forgery probe"

    # 1. All 4 Ed448 small-order torsion points E[4] with R=point, S=0
    zero_s = b"\x00" * 57
    for pt in ED448_SMALL_ORDER_POINTS:
        trials += 1
        if not strict_ed448_verify(pt, pt + zero_s, msg):
            defended += 1

    # 2. Non-canonical Ed448 scalar malleability (S' = S + L)
    ed_pk, ed_sk = ed448_keygen()
    good_sig = ed448_sign(ed_sk, msg)
    s_int = int.from_bytes(good_sig[57:], "little")
    malleated_sig = good_sig[:57] + (s_int + ED448_ORDER_L).to_bytes(57, "little")
    trials += 1
    if not strict_ed448_verify(ed_pk, malleated_sig, msg):
        defended += 1

    # 3. RFC 7748 X448 low-order points {0, 1, p-1} and non-canonical u >= p
    _, x_sk = x448_keygen()
    non_canonical_u = (CURVE448_P + 7).to_bytes(56, "little")
    for bad_u in tuple(X448_LOW_ORDER_POINTS) + (non_canonical_u,):
        trials += 1
        if not validate_x448_public_key(bad_u, strict_canonical=True):
            try:
                x448_exchange(x_sk, bad_u)
            except (OpenQPEPError, ValueError):
                defended += 1

    return {
        "attack": "Ed448_SmallOrder_And_X448_LowOrder",
        "trials": trials,
        "defended": defended,
        "passed": defended == trials,
    }


def simulate_non_canonical_base64_and_armor_dos_attack() -> Dict[str, Any]:
    """Tests RFC 4648 §3.5 Base64 trailing-bit malleability, armor DoS ceilings, and TLV tag reordering."""
    trials = 0
    defended = 0

    # 1. Non-canonical Base64 trailing padding bits ('YR==' for b'a', 'YWJ=' for b'ab')
    for bad_b64 in ("YR==", "Yf==", "YWJ=", "YWL=", "YWJj-_=="):
        trials += 1
        try:
            strict_b64decode(bad_b64)
        except QPEPWireFormatError:
            defended += 1

    # 2. Oversized single-line armor body (> 128 chars) & blank-line flood
    armored = armor_wrap("CALYX QPEP AUDIT", b"X" * 200)
    lines = armored.splitlines()
    sep_idx = lines.index("")
    crc_idx = next(i for i, ln in enumerate(lines) if ln.startswith("="))
    single_line = "\n".join(lines[: sep_idx + 1] + ["".join(lines[sep_idx + 1 : crc_idx])] + lines[crc_idx:]) + "\n"
    blank_flood = "\n".join(lines[: sep_idx + 1] + [""] * (MAX_ARMOR_BLANK_LINES + 4) + lines[sep_idx + 1 :]) + "\n"
    dup_hdr = "\n".join([lines[0], "X-Dup: a", "x-dup: b"] + lines[1:]) + "\n"
    bad_crc_len = "\n".join(("=AAAA" if ln.startswith("=") else ln) for ln in lines) + "\n"
    for bad_armor in (single_line, blank_flood, dup_hdr, bad_crc_len):
        trials += 1
        try:
            armor_unwrap(bad_armor, "CALYX QPEP AUDIT")
        except QPEPWireFormatError:
            defended += 1

    # 3. Compact TLV v5.1 duplicate & out-of-order tag malleability
    for bad_tlv in (
        encode_tlv({1: b"a"}) + encode_tlv({1: b"b"}),
        encode_tlv({2: b"b"}) + encode_tlv({1: b"a"}),
    ):
        trials += 1
        try:
            decode_tlv(bad_tlv)
        except QPEPWireFormatError:
            defended += 1

    return {
        "attack": "NonCanonical_Base64_Armor_And_TLV_DoS",
        "trials": trials,
        "defended": defended,
        "passed": defended == trials,
    }


def simulate_json_duplicate_key_and_depth_bomb_attack() -> Dict[str, Any]:
    """Tests duplicate JSON keys, NaN/Infinity, 2,000-level JSON depth bombs, and Unicode homograph/Bidi UID spoofing."""
    trials = 0
    defended = 0

    for bad_json in (
        '{"suite_id":"QLX-4096","suite_id":"QLX-768"}',
        '{"a":{"k":1,"k":2}}',
        '{"v":NaN}',
        '{"v":Infinity}',
        '{"a":' * 2000 + "1" + "}" * 2000,
        "[" + ",".join(["1"] * 150) + "]",
    ):
        trials += 1
        try:
            strict_json_loads(bad_json, max_nodes=100)
        except QPEPWireFormatError:
            defended += 1

    # Mixed-script Cyrillic/Latin homograph & Bidi-override UID spoofing
    pw = "Calyx!@#$_2026UidAa99"
    for spoof_name, spoof_email in (
        ("Al\u0456ce", "alice@calyxmail.org"),          # Cyrillic 'і' mixed with Latin
        ("Alice\u202eAdmin", "alice@calyxmail.org"),    # Unicode RLO Bidi override
        ("Alice", "alice@c\u0430lyxmail.org"),          # Non-ASCII Cyrillic 'а' in email
    ):
        trials += 1
        try:
            OpenQPEPProtocol.generate_keypair(spoof_name, spoof_email, pw, qlx_tier="QLX-768")
        except QPEPWireFormatError:
            defended += 1

    return {
        "attack": "JSON_DuplicateKey_DepthBomb_And_Homograph_UID",
        "trials": trials,
        "defended": defended,
        "passed": defended == trials,
    }


def simulate_replay_and_zip_bomb_attack() -> Dict[str, Any]:
    """Tests Ratchet/MLS/Sphinx replay defenses, CMT-4 CC-512/SIV key commitment, KDF OOM-bombs, and zip-bombs."""
    trials = 0
    defended = 0

    # 1. QPEP-Ratchet message replay defense
    alice, bob = QPEPRatchetSession.create_pair(os.urandom(32), qlx_tier="QLX-768", rekey_interval_messages=4)
    m0 = alice.encrypt(b"ratchet-once")
    pt0, _ = bob.decrypt(m0)
    trials += 1
    if pt0 == b"ratchet-once":
        try:
            bob.decrypt(m0)
        except (OpenQPEPError, ValueError):
            defended += 1

    # 2. QPEP-MLS group message replay defense
    gm_a = QPEPGroupMember.create("alice")
    gm_b = QPEPGroupMember.create("bob")
    grp = QPEPGroupSession("audit-mls", [gm_a, gm_b])
    gpkt = grp.encrypt_group_message("alice", b"mls-once")
    trials += 1
    if grp.decrypt_group_message("bob", gpkt) == b"mls-once":
        try:
            grp.decrypt_group_message("bob", gpkt)
        except (OpenQPEPError, ValueError):
            defended += 1

    # 3. Sphinx-PQ onion replay defense
    hop = MixNode.create("relay-1")
    onion = SphinxPQRouter.build_onion([hop], "bob@calyxmail.org", b"onion-once")
    trials += 1
    _nxt, _pl, _fin = SphinxPQRouter.peel_layer(hop, onion)
    try:
        SphinxPQRouter.peel_layer(hop, onion)
    except (OpenQPEPError, ValueError):
        defended += 1

    # 4. CMT-4 CC-512 & CC-512-SIV cross-key commitment rejection
    k1, k2 = os.urandom(64), os.urandom(64)
    n24 = os.urandom(24)
    ct_v5 = cc512_encrypt(k1, n24, b"secret-commit", b"aad")
    trials += 1
    try:
        cc512_decrypt(k2, n24, ct_v5, b"aad")
    except QPEPMacVerificationError:
        defended += 1

    ct_siv = cc512_siv_encrypt(k1, b"siv-secret-commit", b"aad")
    trials += 1
    try:
        cc512_siv_decrypt(k2, ct_siv, b"aad")
    except QPEPMacVerificationError:
        defended += 1

    # 5. KDF OOM-bomb (64 GiB) & CPU-bomb (t=9999) rejection
    for bad_m, bad_t, bad_p in ((67108864, 3, 4), (65536, 9999, 4)):
        trials += 1
        try:
            validate_kdf_params(bad_m, bad_t, bad_p)
        except QPEPSuiteError:
            defended += 1

    # 6. High-ratio 1,000:1 zlib zip-bomb & trailing-byte smuggling rejection
    bomb = zlib.compress(b"\x00" * (5 * 1024 * 1024), level=9)
    trials += 1
    try:
        safe_zlib_decompress(bomb)
    except QPEPWireFormatError:
        defended += 1

    smuggled = zlib.compress(b"legit", level=6) + b"TRAILING"
    trials += 1
    try:
        safe_zlib_decompress(smuggled)
    except QPEPWireFormatError:
        defended += 1

    return {
        "attack": "Replay_CMT4_KDFBomb_And_ZipBomb",
        "trials": trials,
        "defended": defended,
        "passed": defended == trials,
    }


def simulate_multi_suite_fault_injection_attack() -> Dict[str, Any]:
    """Tests universal Verify-Before-Emit Fault-Guard across QVS, Ed448, QHS-512, QMQ-512, and CIF-SQI-512."""
    trials = 0
    defended = 0
    msg = b"OpenQPEP universal fault-guard test"

    # 1. Ed448 fault guard
    _, ed_sk = ed448_keygen()
    trials += 1
    with patch.object(hgc448_mod, "ed448_verify", return_value=False):
        try:
            ed448_sign(ed_sk, msg)
        except QPEPFaultGuardError:
            defended += 1

    # 2. QHS-512 hash-based hypertree fault guard
    _, qhs_sk = QHS512HypertreeEngine.keygen()
    trials += 1
    with patch.object(QHS512HypertreeEngine, "verify", return_value=False):
        try:
            QHS512HypertreeEngine.sign(qhs_sk, msg)
        except QPEPFaultGuardError:
            defended += 1

    # 3. QMQ-512 multivariate UOV fault guard
    _, qmq_sk = MultivariateQuadraticEngine.keygen()
    trials += 1
    with patch.object(MultivariateQuadraticEngine, "verify", return_value=False):
        try:
            MultivariateQuadraticEngine.sign(qmq_sk, msg)
        except QPEPFaultGuardError:
            defended += 1

    # 4. CIF-SQI-512 supersingular isogeny SeaSign fault guard
    sqi_pk, sqi_sk = SupersingularIsogenyEngine.keygen()
    trials += 1
    with patch.object(SupersingularIsogenyEngine, "verify", return_value=False):
        try:
            SupersingularIsogenyEngine.sign(sqi_sk, sqi_pk, msg)
        except QPEPFaultGuardError:
            defended += 1

    return {
        "attack": "Universal_MultiSuite_Fault_Injection",
        "trials": trials,
        "defended": defended,
        "passed": defended == trials,
    }


def run_all_attack_simulations() -> Dict[str, Any]:
    results = [
        simulate_fo_cca2_malleability(),
        simulate_qvs_fault_injection(),
        simulate_stream_truncation_and_reorder(),
        simulate_suite_downgrade_attack(),
        simulate_ed448_small_order_and_x448_low_order_attack(),
        simulate_non_canonical_base64_and_armor_dos_attack(),
        simulate_json_duplicate_key_and_depth_bomb_attack(),
        simulate_replay_and_zip_bomb_attack(),
        simulate_multi_suite_fault_injection_attack(),
    ]
    return {
        "simulations": results,
        "simulation_count": len(results),
        "total_trials": sum(int(r["trials"]) for r in results),
        "total_defended": sum(int(r["defended"]) for r in results),
        "all_passed": all(r["passed"] for r in results),
    }
