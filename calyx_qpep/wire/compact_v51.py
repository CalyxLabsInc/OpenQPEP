"""
OpenQPEP Compact Binary TLV Wire Format v5.1 (\\x89QPE\\x05\\x01) — Official Release 1.2.2.
Replaces verbose JSON + Base64 inner envelopes with canonical sorted Tag-Length-Value (TLV)
binary records, reducing serialized packet overhead by ~28–35% while retaining full qSponge-XOF
whitening and 256-bit qSponge-512 MAC authentication.

Hard Clean Break: Strictly rejects ALL legacy -rc (\\x04\\x00 / \\x04\\x01), -pc (\\x03\\x00 / \\x03\\x01),
and -beta frames with QPEPLegacyProtocolError.
v1.2.2 Hardening:
  - Strictly rejects duplicate TLV tags, out-of-order (non-canonical) tags, field-count overflow
    (`MAX_TLV_FIELDS = 256`), payload ceilings (`MAX_TLV_PAYLOAD_BYTES`), non-zero reserved flags,
    bool type confusion, invalid labels, and truncated/trailing bytes.
"""
import os
import struct
from typing import Dict, Tuple

from ..constants import (
    ALL_LEGACY_WIRE_MAGICS,
    MAX_WIRE_FRAME_BYTES,
    WIRE_MAGIC_V5_1,
)
from ..exceptions import QPEPLegacyProtocolError, QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from .framing import WIRE_V5_OVERHEAD_BYTES, _validate_frame_label

MAX_TLV_FIELDS = 256
MAX_TLV_PAYLOAD_BYTES = MAX_WIRE_FRAME_BYTES - WIRE_V5_OVERHEAD_BYTES


def encode_tlv(fields: Dict[int, bytes]) -> bytes:
    """Encodes a dict of {tag_u8: raw_bytes} into canonical tag-sorted TLV binary."""
    if not isinstance(fields, dict):
        raise QPEPWireFormatError("TLV fields must be a dictionary.")
    if len(fields) > MAX_TLV_FIELDS:
        raise QPEPWireFormatError(f"TLV field count exceeds maximum ({MAX_TLV_FIELDS}).")
    for tag in fields.keys():
        if isinstance(tag, bool) or not isinstance(tag, int) or not (0 <= tag <= 255):
            raise QPEPWireFormatError(f"TLV tag out of uint8 range or invalid type: {tag!r}")

    out = bytearray()
    for tag in sorted(fields.keys()):
        val = fields[tag]
        if not isinstance(val, (bytes, bytearray)):
            raise QPEPWireFormatError(f"TLV value for tag {tag} must be bytes or bytearray.")
        if len(out) + 5 + len(val) > MAX_TLV_PAYLOAD_BYTES:
            raise QPEPWireFormatError("Encoded TLV payload exceeds maximum Compact Wire v5.1 size ceiling.")
        out.append(tag & 0xFF)
        out.extend(struct.pack(">I", len(val)))
        out.extend(val)
    return bytes(out)


def decode_tlv(
    raw: bytes,
    *,
    require_canonical_order: bool = True,
    max_fields: int = MAX_TLV_FIELDS,
) -> Dict[int, bytes]:
    """
    Decodes binary TLV records, strictly rejecting duplicate tags, non-canonical tag ordering,
    excessive field counts, oversized payloads, and truncated records.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise QPEPWireFormatError("TLV input must be bytes or bytearray.")
    if isinstance(max_fields, bool) or not isinstance(max_fields, int) or not (1 <= max_fields <= MAX_TLV_FIELDS):
        raise QPEPWireFormatError(f"max_fields must be an integer in 1..{MAX_TLV_FIELDS}.")
    raw_b = bytes(raw)
    n = len(raw_b)
    if n > MAX_TLV_PAYLOAD_BYTES:
        raise QPEPWireFormatError("TLV payload exceeds maximum Compact Wire v5.1 size ceiling.")

    out: Dict[int, bytes] = {}
    idx = 0
    prev_tag = -1
    while idx < n:
        if len(out) >= max_fields:
            raise QPEPWireFormatError(f"TLV record count exceeds maximum allowed ({max_fields}).")
        if idx + 5 > n:
            raise QPEPWireFormatError("Truncated TLV header in Compact Wire v5.1.")
        tag = raw_b[idx]
        if tag in out:
            raise QPEPWireFormatError(f"Duplicate TLV tag 0x{tag:02x} rejected in Compact Wire v5.1.")
        if require_canonical_order and tag <= prev_tag:
            raise QPEPWireFormatError(
                f"Non-canonical out-of-order TLV tag 0x{tag:02x} after 0x{prev_tag:02x} rejected."
            )
        prev_tag = tag
        length = struct.unpack(">I", raw_b[idx + 1 : idx + 5])[0]
        idx += 5
        if length > n - idx:
            raise QPEPWireFormatError("Truncated TLV value in Compact Wire v5.1.")
        out[tag] = raw_b[idx : idx + length]
        idx += length
    return out


def pack_compact_v51(fields: Dict[int, bytes], label: str, packet_type: int = 0x01, flags: int = 0x00) -> bytes:
    """Packs canonical TLV fields into Compact Binary Wire Format v5.1 (\\x89QPE\\x05\\x01)."""
    if isinstance(packet_type, bool) or not isinstance(packet_type, int) or not (0 <= packet_type <= 255):
        raise QPEPWireFormatError("Compact Wire v5.1 packet_type must be an integer in 0..255.")
    if isinstance(flags, bool) or not isinstance(flags, int) or flags != 0:
        raise QPEPWireFormatError("Reserved Compact Wire v5.1 flag bits must be zero.")
    lbl = _validate_frame_label(label)
    body = encode_tlv(fields)
    if len(body) > MAX_TLV_PAYLOAD_BYTES:
        raise QPEPWireFormatError("Compact Wire v5.1 payload exceeds maximum frame size.")
    wire_nonce = os.urandom(16)
    hdr = WIRE_MAGIC_V5_1 + bytes([packet_type & 0xFF, 0x00])
    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v51-1.0.0|" + hdr + wire_nonce + lbl, len(body))
    whitened = bytes(a ^ b for a, b in zip(body, mask))
    mac = qsponge_512(b"CALYX-WIRE-MAC-v51-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    return hdr + wire_nonce + whitened + mac


def unpack_compact_v51(frame: bytes, label: str) -> Tuple[Dict[int, bytes], int, int]:
    """Unpacks and verifies a Compact Binary Wire Format v5.1 (\\x89QPE\\x05\\x01) frame."""
    if not isinstance(frame, (bytes, bytearray)):
        raise QPEPWireFormatError("Compact Wire v5.1 frame must be bytes or bytearray.")
    frame_b = bytes(frame)
    lbl = _validate_frame_label(label)
    if len(frame_b) > MAX_WIRE_FRAME_BYTES:
        raise QPEPWireFormatError("Compact Wire v5.1 frame exceeds maximum allowed size.")
    if len(frame_b) < 6:
        raise QPEPWireFormatError("Truncated Compact Wire v5.1 frame.")
    magic = frame_b[:6]
    if magic in ALL_LEGACY_WIRE_MAGICS:
        raise QPEPLegacyProtocolError(
            "Legacy pre-release (-rc / -pc / -beta) compact wire frame rejected in Official Release 1.2.2 "
            "(zero backwards compatibility). Compact TLV v5.1 (\\x89QPE\\x05\\x01) is required."
        )
    if magic != WIRE_MAGIC_V5_1 or len(frame_b) < WIRE_V5_OVERHEAD_BYTES:
        raise QPEPWireFormatError("Invalid or truncated Compact Wire v5.1 frame.")

    hdr = frame_b[:8]
    if hdr[7] != 0:
        raise QPEPWireFormatError("Non-zero reserved flag bits in Compact Wire v5.1 header.")
    wire_nonce = frame_b[8:24]
    whitened = frame_b[24:-32]
    mac = frame_b[-32:]

    expected = qsponge_512(b"CALYX-WIRE-MAC-v51-1.0.0|" + hdr + wire_nonce + lbl + whitened)[:32]
    if not ct_eq(mac, expected):
        raise QPEPMacVerificationError("Compact Wire v5.1 MAC verification failed.")

    mask = qsponge_var(b"CALYX-WIRE-WHITEN-v51-1.0.0|" + hdr + wire_nonce + lbl, len(whitened))
    body = bytes(a ^ b for a, b in zip(whitened, mask))
    return decode_tlv(body), hdr[6], hdr[7]
