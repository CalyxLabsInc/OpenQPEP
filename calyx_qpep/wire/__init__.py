"""OpenQPEP Official Binary Wire Framing v5, Compact TLV v5.1, Zero-Metadata Armor, Streaming & Multi-Recipient Engine (v1.2.4)."""
from .framing import (
    BUCKET_SIZES,
    MAX_BUCKET_SIZE,
    MAX_FRAME_LABEL_BYTES,
    WIRE_V5_OVERHEAD_BYTES,
    pad_to_bucket,
    unpad_from_bucket,
    pack_wire_frame,
    unpack_wire_frame,
)
from .armor import (
    MAX_ARMOR_BLANK_LINES,
    MAX_ARMOR_BODY_LINE_LEN,
    MAX_ARMOR_HEADER_COUNT,
    MAX_ARMOR_HEADER_LINE_LEN,
    MAX_ARMOR_LINES,
    MAX_BASE64_INPUT_BYTES,
    MAX_DECOMPRESSION_RATIO,
    MAX_JSON_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MIN_DECOMPRESSION_RATIO_CHECK_BYTES,
    armor_wrap,
    armor_unwrap,
    safe_zlib_decompress,
    strict_b64decode,
    strict_json_loads,
)
from .file_registry import SUPPORTED_FILE_EXTENSIONS, detect_file_extension_and_mime
from .multi_recipient import (
    MAX_MULTI_RECIPIENT_SLOTS,
    MULTI_RECIPIENT_ARMOR_LABEL,
    compute_blinded_slot_tag,
    encrypt_multi_recipient,
    decrypt_multi_recipient,
)
from .compact_v51 import (
    MAX_TLV_FIELDS,
    MAX_TLV_PAYLOAD_BYTES,
    encode_tlv,
    decode_tlv,
    pack_compact_v51,
    unpack_compact_v51,
)
from .streaming import (
    STREAM_MAGIC,
    FLAG_MERKLE_SEEKABLE,
    MAX_STREAM_CHUNK_SIZE,
    MAX_STREAM_CHUNKS,
    derive_chunk_nonce24,
    build_chunk_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
    StreamingEncryptor,
    StreamingDecryptor,
)

__all__ = [
    "MAX_TLV_FIELDS", "MAX_TLV_PAYLOAD_BYTES",
    "encode_tlv", "decode_tlv", "pack_compact_v51", "unpack_compact_v51",
    "STREAM_MAGIC", "FLAG_MERKLE_SEEKABLE", "MAX_STREAM_CHUNK_SIZE", "MAX_STREAM_CHUNKS",
    "derive_chunk_nonce24", "build_chunk_merkle_tree", "get_merkle_proof", "verify_merkle_proof",
    "StreamingEncryptor", "StreamingDecryptor",
    "BUCKET_SIZES", "MAX_BUCKET_SIZE", "MAX_FRAME_LABEL_BYTES", "WIRE_V5_OVERHEAD_BYTES",
    "pad_to_bucket", "unpad_from_bucket", "pack_wire_frame", "unpack_wire_frame",
    "MAX_ARMOR_BLANK_LINES", "MAX_ARMOR_BODY_LINE_LEN", "MAX_ARMOR_HEADER_COUNT",
    "MAX_ARMOR_HEADER_LINE_LEN", "MAX_ARMOR_LINES", "MAX_BASE64_INPUT_BYTES",
    "MAX_DECOMPRESSION_RATIO", "MAX_JSON_BYTES", "MAX_JSON_DEPTH", "MAX_JSON_NODES",
    "MIN_DECOMPRESSION_RATIO_CHECK_BYTES",
    "armor_wrap", "armor_unwrap", "strict_b64decode", "strict_json_loads", "safe_zlib_decompress",
    "SUPPORTED_FILE_EXTENSIONS", "detect_file_extension_and_mime",
    "MAX_MULTI_RECIPIENT_SLOTS", "MULTI_RECIPIENT_ARMOR_LABEL", "compute_blinded_slot_tag",
    "encrypt_multi_recipient", "decrypt_multi_recipient",
]
