"""
OpenQPEP Zero-Metadata ASCII Armor, Canonical Base64, Strict JSON & Anti-Zip-Bomb Codec
(Official Release 1.1.9 / Wire Format v5 \\x89QPE\\x05\\x00).

Security Guarantees:
  - Zero cleartext identity metadata headers (never emits Sender/Recipient/Signer Key Hashes).
  - Mandatory 48-bit qSponge-512 armor CRC checksum (`={crc}`), strictly verified in constant time
    via `ct_eq` on unwrap (missing, non-canonical, or corrupted checksums are rejected!).
  - Strict RFC 4648 Section 3.5 canonical Base64 decoding (`strict_b64decode`): enforces exact
    standard alphabet, multiple-of-4 length, zero internal whitespace, and zero non-canonical
    trailing padding bits (eliminates Base64 malleability).
  - Strict O(N) non-recursive JSON parser (`strict_json_loads`): enforces recursion depth ceiling
    (`MAX_JSON_DEPTH = 32`), node/complexity ceiling (`MAX_JSON_NODES = 250_000`), duplicate-key
    rejection at every depth, and `NaN`/`Infinity` rejection before invoking `json.loads`.
  - Anti-zip-bomb `safe_zlib_decompress`: enforces both hard byte ceiling (`MAX_DECOMPRESSED_BYTES`)
    and compression-ratio ceiling (`MAX_DECOMPRESSION_RATIO = 200` above 1 MiB) plus zero trailing bytes.
  - CPU/RAM-bound armor parser ceilings: `MAX_ARMOR_BYTES`, `MAX_ARMOR_LINES`, `MAX_ARMOR_BLANK_LINES`,
    `MAX_ARMOR_HEADER_COUNT`, `MAX_ARMOR_HEADER_LINE_LEN`, and `MAX_ARMOR_BODY_LINE_LEN`.
  - Strictly enforces Official Wire Format v5 (\\x89QPE\\x05\\x00) and hard-rejects all legacy
    -rc, -pc, and -beta frames with QPEPLegacyProtocolError.
"""
import base64
import binascii
import json
import re
import unicodedata
import zlib
from typing import Any, Dict, List, Optional, Tuple

from ..constants import (
    MAX_ARMOR_BYTES,
    MAX_DECOMPRESSED_BYTES,
    MAX_WIRE_FRAME_BYTES,
    PACKET_TYPE_SINGLE,
    PROTOCOL_VERSION,
    UNIVERSAL_VERSION_LABEL,
)
from ..exceptions import QPEPMacVerificationError, QPEPWireFormatError
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_var
from .framing import pack_wire_frame, unpack_wire_frame

MAX_ARMOR_HEADER_COUNT = 32
MAX_ARMOR_HEADER_LINE_LEN = 1024
MAX_ARMOR_BODY_LINE_LEN = 128
MAX_ARMOR_LINES = 1_500_000
MAX_ARMOR_BLANK_LINES = 64

MAX_BASE64_INPUT_BYTES = 96 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 250_000
MAX_JSON_BYTES = MAX_WIRE_FRAME_BYTES
MAX_DECOMPRESSION_RATIO = 200
MIN_DECOMPRESSION_RATIO_CHECK_BYTES = 1024 * 1024

_FORBIDDEN_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_BIDI_CONTROL_CODEPOINTS = frozenset({
    0x061C, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})

FORBIDDEN_ARMOR_HEADERS = frozenset({
    "sender-key-hash",
    "recipient-key-hash",
    "signer-key-hash",
    "encrypting-key-hash",
})

# Precomputed RFC 4648 standard Base64 sextet lookup table (-1 for non-alphabet bytes)
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_DECODE_VAL = [-1] * 128
for _idx, _ch in enumerate(_B64_ALPHABET):
    _B64_DECODE_VAL[ord(_ch)] = _idx

# Linear-time single-character structural scanner for JSON depth & complexity bounds
_JSON_STRUCT_RE = re.compile(r'["{}\[\],]')


def _has_forbidden_control_or_bidi(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if cp < 32 or cp == 127 or cp in _BIDI_CONTROL_CODEPOINTS:
            return True
        if unicodedata.category(ch) in _FORBIDDEN_UNICODE_CATEGORIES:
            return True
    return False


def strict_b64decode(text: str, *, max_encoded_len: int = MAX_BASE64_INPUT_BYTES) -> bytes:
    """
    Strict RFC 4648 Section 3.5 Canonical Base64 Decoder:
      - Rejects non-str, non-ASCII, oversized input, internal whitespace, and URL-safe variants.
      - Requires length divisible by 4 and canonical '=' / '==' padding at the end only.
      - Rejects non-zero trailing padding bits (eliminating Base64 malleability).
    """
    if not isinstance(text, str):
        raise QPEPWireFormatError("Base64 input must be an ASCII string.")
    n = len(text)
    if n > max_encoded_len:
        raise QPEPWireFormatError(f"Base64 input exceeds maximum allowed length ({max_encoded_len} chars).")
    if n == 0:
        return b""
    if (n & 3) != 0 or not text.isascii():
        raise QPEPWireFormatError("Invalid Base64 length or non-ASCII characters rejected.")

    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise QPEPWireFormatError("Invalid Base64 alphabet or padding rejected.") from exc

    # RFC 4648 Section 3.5: enforce zero trailing padding bits
    if text[-1] == "=":
        if text[-2] == "=":
            # Two padding chars -> last data sextet (text[-3]) carries 2 data bits + 4 zero bits
            val = _B64_DECODE_VAL[ord(text[-3])]
            if val < 0 or (val & 0x0F) != 0:
                raise QPEPWireFormatError(
                    "Non-canonical Base64 encoding rejected (non-zero trailing padding bits before '==')."
                )
        else:
            # One padding char -> last data sextet (text[-2]) carries 4 data bits + 2 zero bits
            val = _B64_DECODE_VAL[ord(text[-2])]
            if val < 0 or (val & 0x03) != 0:
                raise QPEPWireFormatError(
                    "Non-canonical Base64 encoding rejected (non-zero trailing padding bits before '=')."
                )
    return raw


def _reject_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise QPEPWireFormatError(f"Duplicate JSON key '{k}' rejected (anti-substitution defense).")
        obj[k] = v
    return obj


def _reject_json_constant(token: str) -> Any:
    raise QPEPWireFormatError(f"Non-standard JSON constant '{token}' rejected.")


def _scan_json_limits(text: str, *, max_depth: int, max_nodes: int) -> None:
    """
    O(N) iterative, stack-free structural pre-scanner enforcing JSON recursion depth
    and node-count complexity limits BEFORE invoking `json.loads`.
    """
    pos = 0
    n = len(text)
    depth = 0
    nodes = 0
    while pos < n:
        m = _JSON_STRUCT_RE.search(text, pos)
        if m is None:
            break
        ch = m.group(0)
        i = m.start()
        if ch == '"':
            j = text.find('"', i + 1)
            while j != -1:
                bs = 0
                k = j - 1
                while k > i and text[k] == "\\":
                    bs += 1
                    k -= 1
                if (bs & 1) == 0:
                    break
                j = text.find('"', j + 1)
            if j == -1:
                raise QPEPWireFormatError("Unterminated JSON string literal.")
            pos = j + 1
            continue
        if ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                raise QPEPWireFormatError(
                    f"JSON nesting depth exceeds maximum allowed limit ({max_depth})."
                )
            nodes += 1
            if nodes > max_nodes:
                raise QPEPWireFormatError(
                    f"JSON complexity exceeds maximum allowed node count ({max_nodes})."
                )
        elif ch == "}" or ch == "]":
            depth -= 1
            if depth < 0:
                raise QPEPWireFormatError("Unbalanced closing brace/bracket in JSON payload.")
        elif ch == ",":
            nodes += 1
            if nodes > max_nodes:
                raise QPEPWireFormatError(
                    f"JSON complexity exceeds maximum allowed node count ({max_nodes})."
                )
        pos = i + 1
    if depth != 0:
        raise QPEPWireFormatError("Unclosed JSON container in payload.")


def strict_json_loads(
    raw: bytes | bytearray | str,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
    max_bytes: int = MAX_JSON_BYTES,
) -> Any:
    """
    Hardened JSON parser enforcing byte-size ceiling, iterative nesting-depth limit,
    node-count complexity limit, duplicate-key rejection, and NaN/Infinity rejection.
    """
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise QPEPWireFormatError("max_depth must be a positive integer.")
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise QPEPWireFormatError("max_nodes must be a positive integer.")
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > max_bytes:
            raise QPEPWireFormatError(f"JSON payload exceeds maximum allowed size ({max_bytes} bytes).")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise QPEPWireFormatError("Invalid UTF-8 encoding in JSON payload.") from exc
    elif isinstance(raw, str):
        if len(raw) > max_bytes:
            raise QPEPWireFormatError(f"JSON payload exceeds maximum allowed size ({max_bytes} chars).")
        text = raw
    else:
        raise QPEPWireFormatError("JSON payload must be bytes, bytearray, or str.")

    _scan_json_limits(text, max_depth=max_depth, max_nodes=max_nodes)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, QPEPWireFormatError):
            raise
        raise QPEPWireFormatError("Malformed JSON payload inside OpenQPEP frame.") from exc


def safe_zlib_decompress(
    data: bytes,
    max_bytes: int = MAX_DECOMPRESSED_BYTES,
    *,
    max_ratio: int = MAX_DECOMPRESSION_RATIO,
    min_ratio_check_bytes: int = MIN_DECOMPRESSION_RATIO_CHECK_BYTES,
) -> bytes:
    """
    Decompresses a zlib payload with dual zip-bomb defenses:
      1. Hard absolute byte ceiling (`max_bytes`, default 128 MiB).
      2. Compression-ratio ceiling (`max_ratio`, default 200x above `min_ratio_check_bytes` = 1 MiB)
         computed UPFRONT so zip bombs terminate early without allocating multi-megabyte buffers.
      3. Strict EOF & zero-trailing-byte enforcement (`dobj.eof` and `not dobj.unused_data`).
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise QPEPWireFormatError("Compressed payload must be non-empty bytes.")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise QPEPWireFormatError("max_bytes must be a positive integer.")
    if isinstance(max_ratio, bool) or not isinstance(max_ratio, int) or max_ratio <= 0:
        raise QPEPWireFormatError("max_ratio must be a positive integer.")

    raw_bytes = bytes(data)
    ratio_cap = max(int(min_ratio_check_bytes), len(raw_bytes) * int(max_ratio))
    effective_limit = min(max_bytes, ratio_cap)

    dobj = zlib.decompressobj()
    try:
        out = dobj.decompress(raw_bytes, effective_limit + 1)
        if len(out) > effective_limit or dobj.unconsumed_tail:
            raise QPEPWireFormatError(
                f"Decompressed payload exceeds safety/ratio ceiling ({effective_limit:,} bytes); zip bomb rejected."
            )
        tail = dobj.flush(effective_limit + 1 - len(out))
    except zlib.error as exc:
        raise QPEPWireFormatError("Corrupted zlib stream inside OpenQPEP payload.") from exc

    total_len = len(out) + len(tail)
    if total_len > effective_limit or not dobj.eof:
        raise QPEPWireFormatError("Corrupted or oversized compressed OpenQPEP payload.")
    if dobj.unused_data:
        raise QPEPWireFormatError("Unexpected trailing bytes after zlib stream EOF.")
    return out + tail


def _compute_armor_crc(wire_frame: bytes) -> str:
    """Computes canonical 48-bit Base64 qSponge-XOF armor checksum bound to Wire Format v5."""
    return base64.b64encode(
        qsponge_var(b"CALYX-ARMOR-CRC-v5-1.0.0|" + wire_frame, 6)
    ).decode("ascii")


def _verify_armor_crc_strict(checksum_line: Optional[str], wire_frame: bytes) -> None:
    """Enforces mandatory canonical 8-char Base64 48-bit armor CRC verification in constant time."""
    if not checksum_line:
        raise QPEPMacVerificationError("Missing mandatory OpenQPEP ASCII armor checksum line (=CRC).")
    if len(checksum_line) != 8:
        raise QPEPWireFormatError("Malformed OpenQPEP ASCII armor checksum length (expected 8 canonical Base64 chars).")
    decoded_crc = strict_b64decode(checksum_line, max_encoded_len=8)
    if len(decoded_crc) != 6:
        raise QPEPWireFormatError("Malformed OpenQPEP ASCII armor checksum payload (expected 6 decoded bytes).")
    expected_crc = _compute_armor_crc(wire_frame)
    if not ct_eq(checksum_line.encode("ascii"), expected_crc.encode("ascii")):
        raise QPEPMacVerificationError("OpenQPEP ASCII armor checksum verification failed.")


def _validate_header_token(key: str, value: str) -> None:
    if (
        not key
        or len(key) + len(value) + 2 > MAX_ARMOR_HEADER_LINE_LEN
        or ":" in key
        or _has_forbidden_control_or_bidi(key)
        or _has_forbidden_control_or_bidi(value)
    ):
        raise QPEPWireFormatError("Invalid control/bidi character, oversized line, or header injection in ASCII armor header.")


def armor_wrap(
    label: str,
    payload: bytes,
    headers: Optional[Dict[str, str]] = None,
    *,
    packet_type: int = PACKET_TYPE_SINGLE,
    bucket_size: int = 0,
) -> str:
    """Wraps raw payload into Official Wire Format v5 (\\x89QPE\\x05\\x00) and zero-metadata ASCII armor."""
    wire_frame = pack_wire_frame(payload, label, packet_type=packet_type, bucket_size=bucket_size)
    b64 = base64.b64encode(wire_frame).decode("ascii")
    wrapped_lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    crc = _compute_armor_crc(wire_frame)

    hdr_lines = [
        f"Protocol: OpenQPEP ({UNIVERSAL_VERSION_LABEL})",
        f"Version: {PROTOCOL_VERSION}",
    ]
    if headers:
        for k, v in headers.items():
            if k.lower() in FORBIDDEN_ARMOR_HEADERS:
                continue
            if k.lower() in ("protocol", "version"):
                continue
            _validate_header_token(str(k), str(v))
            hdr_lines.append(f"{k}: {v}")

    return (
        f"-----BEGIN {label}-----\n"
        + "\n".join(hdr_lines)
        + "\n\n"
        + "\n".join(wrapped_lines)
        + f"\n={crc}\n"
        + f"-----END {label}-----\n"
    )


def armor_unwrap(armored: str, expected_label: str) -> Tuple[bytes, Dict[str, str]]:
    """
    Parses ASCII armor with strict CPU/RAM resource ceilings, canonical RFC 4648 Base64 validation,
    mandatory constant-time `={crc}` checksum verification, and Official Wire Format v5
    (\\x89QPE\\x05\\x00) authentication. Returns (payload_bytes, headers).
    """
    if not isinstance(armored, str) or not armored or len(armored) > MAX_ARMOR_BYTES:
        raise QPEPWireFormatError("ASCII armor input missing or exceeds maximum allowed size.")
    if armored.count("\n") > MAX_ARMOR_LINES:
        raise QPEPWireFormatError(f"ASCII armor exceeds maximum allowed line count ({MAX_ARMOR_LINES}).")

    begin_marker = f"-----BEGIN {expected_label}-----"
    end_marker = f"-----END {expected_label}-----"
    lines = [ln.strip() for ln in armored.strip().splitlines()]
    if len(lines) > MAX_ARMOR_LINES:
        raise QPEPWireFormatError(f"ASCII armor exceeds maximum allowed line count ({MAX_ARMOR_LINES}).")
    try:
        start_idx = lines.index(begin_marker)
        end_idx = lines.index(end_marker, start_idx + 1)
    except ValueError as exc:
        raise QPEPWireFormatError(f"Missing or mismatched ASCII armor markers for '{expected_label}'.") from exc

    headers: Dict[str, str] = {}
    seen_header_keys = set()
    body_lines: List[str] = []
    checksum_line: Optional[str] = None
    in_body = False
    blank_lines = 0

    for line in lines[start_idx + 1 : end_idx]:
        if not in_body:
            if line == "":
                in_body = True
                blank_lines += 1
                continue
            if ":" in line:
                if len(line) > MAX_ARMOR_HEADER_LINE_LEN:
                    raise QPEPWireFormatError("ASCII armor header line exceeds maximum allowed length.")
                k, v = line.split(":", 1)
                ks, vs = k.strip(), v.strip()
                _validate_header_token(ks, vs)
                k_low = ks.lower()
                if k_low in seen_header_keys:
                    raise QPEPWireFormatError(f"Duplicate ASCII armor header '{ks}' rejected.")
                seen_header_keys.add(k_low)
                if len(seen_header_keys) > MAX_ARMOR_HEADER_COUNT:
                    raise QPEPWireFormatError("Too many ASCII armor headers.")
                headers[ks] = vs
            else:
                in_body = True
                if line.startswith("="):
                    checksum_line = line[1:].strip()
                else:
                    if len(line) > MAX_ARMOR_BODY_LINE_LEN:
                        raise QPEPWireFormatError(
                            f"ASCII armor body line exceeds maximum allowed length ({MAX_ARMOR_BODY_LINE_LEN} chars)."
                        )
                    body_lines.append(line)
        else:
            if not line:
                blank_lines += 1
                if blank_lines > MAX_ARMOR_BLANK_LINES:
                    raise QPEPWireFormatError("Excessive blank lines inside ASCII armor payload.")
                continue
            if line.startswith("="):
                if checksum_line is not None:
                    raise QPEPWireFormatError("Duplicate armor checksum line detected.")
                checksum_line = line[1:].strip()
                continue
            if checksum_line is not None:
                raise QPEPWireFormatError("Unexpected Base64 body line after armor checksum line.")
            if len(line) > MAX_ARMOR_BODY_LINE_LEN:
                raise QPEPWireFormatError(
                    f"ASCII armor body line exceeds maximum allowed length ({MAX_ARMOR_BODY_LINE_LEN} chars)."
                )
            body_lines.append(line)

    if not body_lines:
        raise QPEPWireFormatError("Empty ASCII armor payload.")

    raw_frame = strict_b64decode("".join(body_lines))

    # Unpack wire frame FIRST so legacy -rc / -pc / -beta frames raise QPEPLegacyProtocolError deterministically
    payload, _ptype = unpack_wire_frame(raw_frame, expected_label)

    # Strictly enforce canonical 8-char Base64 & constant-time armor CRC verification
    _verify_armor_crc_strict(checksum_line, raw_frame)

    return payload, headers
