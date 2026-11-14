"""
Calyx Quantum Proof Encryption Protocol (Calyx QPEP v1.0) Reference Implementation.

Proprietary Calyx QPEP Suite Architecture:
- QLX-1024 + HGC-448 (Quantum Lattice Exchange 1024-Dim + Hyper-Goldilocks Curve 448)
- QVS-87 + qSponge-512 (Quantum Vector Signature 87-Rank + 512-Bit Quantum Sponge Transcript)
- Calyx-Cascade-512 / CC-512 (512-Bit Cascaded Dual-Stream Authenticated Matrix Cipher)
- QPKD-Argon (Quantum-Proof Key Derivation — Mandatory 12+ Char Passphrase Lock)
- .qpkrf (Quantum Proof Key Ring File format)
"""
import os
import json
import zlib
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .passphrase import enforce_passphrase_policy, analyze_passphrase, QPEPPassphrasePolicyError
from .qlx_lattice import (
    QLX1024Engine,
    QVS87Engine,
    QLX1024_PK_BYTES,
    QLX1024_CT_BYTES,
    QVS87_PK_BYTES,
    QVS87_SIG_BYTES,
    qsponge_var,
    qsponge_512,
)

PROTOCOL_VERSION = "CALYX-QPEP/1.0"
SUITE_ID = "CALYX-QPEP-1.0-QLX1024-HGC448-QVS87-QSPONGE512-CC512"
QPKRF_EXTENSION = ".qpkrf"
CHUNK_SIZE = 65536


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _armor_wrap(header_label: str, metadata: Dict[str, str], payload_bytes: bytes) -> str:
    b64_raw = _b64e(payload_bytes)
    lines = [b64_raw[i : i + 64] for i in range(0, len(b64_raw), 64)]
    crc_digest = _b64e(hashlib.sha3_256(payload_bytes).digest()[:6])
    meta_lines = [f"{k}: {v}" for k, v in metadata.items()]
    body = "\n".join(
        [f"-----BEGIN {header_label}-----"]
        + meta_lines
        + [""]
        + lines
        + [f"={crc_digest}", f"-----END {header_label}-----"]
    )
    return body + "\n"


def _armor_unwrap(armored_text: str, expected_label: Optional[str] = None) -> Tuple[str, Dict[str, str], bytes]:
    lines = [line.strip() for line in armored_text.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[-1].startswith("-----END "):
        raise ValueError("Invalid Calyx QPEP armor header/footer.")
    begin_label = lines[0][len("-----BEGIN ") : -len("-----")]
    end_label = lines[-1][len("-----END ") : -len("-----")]
    if begin_label != end_label:
        raise ValueError(f"Mismatched armor labels: {begin_label} vs {end_label}")
    if expected_label and begin_label != expected_label:
        raise ValueError(f"Expected armor label '{expected_label}', got '{begin_label}'")

    metadata: Dict[str, str] = {}
    idx = 1
    while idx < len(lines) - 1 and lines[idx] != "":
        if ":" in lines[idx]:
            k, v = lines[idx].split(":", 1)
            metadata[k.strip()] = v.strip()
        idx += 1
    if idx < len(lines) - 1 and lines[idx] == "":
        idx += 1

    b64_chunks = []
    checksum_line = None
    for line in lines[idx:-1]:
        if line.startswith("="):
            checksum_line = line[1:]
        elif line:
            b64_chunks.append(line)

    payload_bytes = _b64d("".join(b64_chunks))
    if checksum_line:
        expected_crc = _b64e(hashlib.sha3_256(payload_bytes).digest()[:6])
        if not hmac.compare_digest(checksum_line, expected_crc):
            raise ValueError("Calyx QPEP qSponge checksum mismatch (corrupted packet).")
    return begin_label, metadata, payload_bytes


def _qpkd_argon_derive(passphrase: str, salt: bytes) -> Tuple[bytes, bytes, bytes]:
    enforce_passphrase_policy(passphrase)
    scrypt = Scrypt(salt=salt, length=64, n=2**14, r=8, p=1)
    master = scrypt.derive(passphrase.encode("utf-8"))
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=96,
        salt=salt,
        info=b"CALYX-QPEP-v1-QPKD-ARGON-KEYRING-LOCK",
    )
    okm = hkdf.derive(master)
    return okm[:32], okm[32:64], okm[64:96]


def _cc512_encrypt(plaintext: bytes, k_s1: bytes, k_s2: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    n1 = os.urandom(12)
    n2 = os.urandom(12)
    inner_ct = AESGCM(k_s1).encrypt(n1, plaintext, aad)
    outer_ct = ChaCha20Poly1305(k_s2).encrypt(n2, inner_ct, aad)
    return n1, n2, outer_ct


def _cc512_decrypt(outer_ct: bytes, k_s1: bytes, k_s2: bytes, n1: bytes, n2: bytes, aad: bytes) -> bytes:
    inner_ct = ChaCha20Poly1305(k_s2).decrypt(n2, outer_ct, aad)
    return AESGCM(k_s1).decrypt(n1, inner_ct, aad)


@dataclass
class QPEPKeyRing:
    key_id: str
    fingerprint_qsponge_512: str
    created_at: str
    name: str
    email: str
    comment: str
    public_bundle: Dict[str, str]
    encrypted_private_bundle: Optional[Dict[str, Any]]
    export_lock: Dict[str, str]
    integrity_mac: str

    @property
    def has_private_key(self) -> bool:
        return self.encrypted_private_bundle is not None


class CalyxQPEPProtocol:
    """
    Official Reference Implementation of the Calyx Quantum Proof Encryption Protocol (Calyx QPEP).
    """

    @staticmethod
    def generate_keypair(
        name: str,
        email: str,
        passphrase: str,
        comment: str = "Calyx QPEP Client",
    ) -> QPEPKeyRing:
        enforce_passphrase_policy(passphrase)

        hgc_sk = x448.X448PrivateKey.generate()
        hgc_pk = hgc_sk.public_key()
        hgc_sk_bytes = hgc_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        hgc_pk_bytes = hgc_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        hgc_sig_sk = ed448.Ed448PrivateKey.generate()
        hgc_sig_pk = hgc_sig_sk.public_key()
        hgc_sig_sk_bytes = hgc_sig_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        hgc_sig_pk_bytes = hgc_sig_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        qlx_pk, qlx_sk = QLX1024Engine.keygen()
        qvs_pk, qvs_sk = QVS87Engine.keygen()

        fp_hex = qsponge_512(
            b"CALYX-QPEP-FP-v1" + hgc_pk_bytes + qlx_pk + hgc_sig_pk_bytes + qvs_pk
        ).hex().upper()
        key_id = fp_hex[:32]
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cert_transcript = (
            f"CALYX-QPEP-SELFCERT|{key_id}|{created_at}|{name}|{email}|{comment}".encode("utf-8")
            + hgc_pk_bytes
            + qlx_pk
            + hgc_sig_pk_bytes
            + qvs_pk
        )
        sig_part1 = hgc_sig_sk.sign(cert_transcript)
        sig_part2 = QVS87Engine.sign(qvs_sk, qvs_pk, cert_transcript)
        self_sig_blob = sig_part1 + sig_part2

        public_bundle = {
            "hgc_448_public_b64": _b64e(hgc_pk_bytes),
            "qlx_1024_public_b64": _b64e(qlx_pk),
            "hgc_sig_public_b64": _b64e(hgc_sig_pk_bytes),
            "qvs_87_public_b64": _b64e(qvs_pk),
            "self_signature_b64": _b64e(self_sig_blob),
        }

        kdf_salt = os.urandom(32)
        k_s1, k_s2, k_mac = _qpkd_argon_derive(passphrase, kdf_salt)

        private_raw = json.dumps(
            {
                "hgc_448_private_b64": _b64e(hgc_sk_bytes),
                "qlx_1024_private_b64": _b64e(qlx_sk),
                "hgc_sig_private_b64": _b64e(hgc_sig_sk_bytes),
                "qvs_87_private_b64": _b64e(qvs_sk),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        aad = f"CALYX-QPEP-PRIVRING|{key_id}|{fp_hex}".encode("utf-8")
        n1, n2, ct_priv = _cc512_encrypt(private_raw, k_s1, k_s2, aad)

        encrypted_private_bundle = {
            "kdf_salt_b64": _b64e(kdf_salt),
            "kdf_params": {"algorithm": "QPKD-Argon+qSponge-512", "n": 16384, "r": 8, "p": 1},
            "cc512_n1_b64": _b64e(n1),
            "cc512_n2_b64": _b64e(n2),
            "ciphertext_b64": _b64e(ct_priv),
        }

        verifier_salt = os.urandom(16)
        verifier_tag = hmac.new(k_mac, b"CALYX-QPEP-EXPORT-LOCK|" + verifier_salt + key_id.encode("ascii"), hashlib.sha3_512).digest()
        export_lock = {
            "verifier_salt_b64": _b64e(verifier_salt),
            "verifier_tag_b64": _b64e(verifier_tag),
        }

        mac_input = json.dumps(
            {
                "key_id": key_id,
                "fingerprint": fp_hex,
                "created_at": created_at,
                "name": name,
                "email": email,
                "public_bundle": public_bundle,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        integrity_mac = qsponge_512(b"CALYX-QPKRF-INTEGRITY|" + mac_input).hex().upper()

        return QPEPKeyRing(
            key_id=key_id,
            fingerprint_qsponge_512=fp_hex,
            created_at=created_at,
            name=name,
            email=email,
            comment=comment,
            public_bundle=public_bundle,
            encrypted_private_bundle=encrypted_private_bundle,
            export_lock=export_lock,
            integrity_mac=integrity_mac,
        )

    @staticmethod
    def verify_public_keyring_self_signature(keyring: QPEPKeyRing) -> bool:
        hgc_pk_bytes = _b64d(keyring.public_bundle["hgc_448_public_b64"])
        qlx_pk = _b64d(keyring.public_bundle["qlx_1024_public_b64"])
        hgc_sig_pk_bytes = _b64d(keyring.public_bundle["hgc_sig_public_b64"])
        qvs_pk = _b64d(keyring.public_bundle["qvs_87_public_b64"])
        self_sig_blob = _b64d(keyring.public_bundle["self_signature_b64"])

        if len(self_sig_blob) != 114 + QVS87_SIG_BYTES:
            return False
        sig1 = self_sig_blob[:114]
        sig2 = self_sig_blob[114:]

        cert_transcript = (
            f"CALYX-QPEP-SELFCERT|{keyring.key_id}|{keyring.created_at}|{keyring.name}|{keyring.email}|{keyring.comment}".encode("utf-8")
            + hgc_pk_bytes
            + qlx_pk
            + hgc_sig_pk_bytes
            + qvs_pk
        )
        try:
            ed_pk = ed448.Ed448PublicKey.from_public_bytes(hgc_sig_pk_bytes)
            ed_pk.verify(sig1, cert_transcript)
        except Exception:
            return False

        return QVS87Engine.verify(qvs_pk, cert_transcript, sig2)

    @staticmethod
    def unlock_private_keys(keyring: QPEPKeyRing, passphrase: str) -> Dict[str, bytes]:
        enforce_passphrase_policy(passphrase)
        if not keyring.encrypted_private_bundle:
            raise ValueError("This QPKRF key ring contains only a public key.")

        priv_enc = keyring.encrypted_private_bundle
        kdf_salt = _b64d(priv_enc["kdf_salt_b64"])
        k_s1, k_s2, _ = _qpkd_argon_derive(passphrase, kdf_salt)
        aad = f"CALYX-QPEP-PRIVRING|{keyring.key_id}|{keyring.fingerprint_qsponge_512}".encode("utf-8")

        try:
            decrypted_json = _cc512_decrypt(
                outer_ct=_b64d(priv_enc["ciphertext_b64"]),
                k_s1=k_s1,
                k_s2=k_s2,
                n1=_b64d(priv_enc["cc512_n1_b64"]),
                n2=_b64d(priv_enc["cc512_n2_b64"]),
                aad=aad,
            )
        except Exception as exc:
            raise ValueError("Invalid passphrase or tampered QPKRF private key ring.") from exc

        parsed = json.loads(decrypted_json.decode("utf-8"))
        return {
            "hgc_448_private": _b64d(parsed["hgc_448_private_b64"]),
            "qlx_1024_private": _b64d(parsed["qlx_1024_private_b64"]),
            "hgc_sig_private": _b64d(parsed["hgc_sig_private_b64"]),
            "qvs_87_private": _b64d(parsed["qvs_87_private_b64"]),
        }

    @staticmethod
    def export_qpkrf(
        keyring: QPEPKeyRing,
        passphrase: str,
        include_private: bool = False,
        output_path: Optional[str | Path] = None,
    ) -> str:
        enforce_passphrase_policy(passphrase)
        if include_private:
            CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)

        ring_type = "PRIVATE_KEY_RING" if include_private else "PUBLIC_KEY_RING"
        envelope: Dict[str, Any] = {
            "magic": "QPKRF-v1",
            "version": "1.0.0",
            "ring_type": ring_type,
            "suite": SUITE_ID,
            "key_id": keyring.key_id,
            "fingerprint_qsponge_512": keyring.fingerprint_qsponge_512,
            "created_at": keyring.created_at,
            "identity": {
                "name": keyring.name,
                "email": keyring.email,
                "comment": keyring.comment,
            },
            "passphrase_policy": {
                "kdf": "QPKD-Argon",
                "min_length": 12,
                "min_digits": 2,
                "min_special": 4,
                "min_upper": 2,
                "min_lower": 4,
            },
            "public_bundle": keyring.public_bundle,
            "export_lock": keyring.export_lock,
            "integrity_mac": keyring.integrity_mac,
        }
        if include_private:
            envelope["encrypted_private_bundle"] = keyring.encrypted_private_bundle

        payload_bytes = json.dumps(envelope, indent=2).encode("utf-8")
        label = (
            "CALYX QPKRF PRIVATE KEY RING"
            if include_private
            else "CALYX QPKRF PUBLIC KEY RING"
        )
        metadata = {
            "Version": f"{PROTOCOL_VERSION} (Calyx Labs Inc.)",
            "Suite": "QLX-1024+HGC-448 / QVS-87+qSponge-512 / CC-512",
            "Key-ID": keyring.key_id,
            "Identity": f"{keyring.name} <{keyring.email}>",
            "Passphrase-Policy": "QPKD-ARGON-MANDATORY-12CHAR-2NUM-4SPEC-2UPPER-4LOWER",
        }
        armored = _armor_wrap(label, metadata, payload_bytes)

        if output_path is not None:
            out_p = Path(output_path)
            if out_p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Exported key ring files MUST use the '{QPKRF_EXTENSION}' file extension.")
            out_p.write_text(armored, encoding="utf-8")

        return armored

    @staticmethod
    def import_qpkrf(armored_or_path: str | Path, passphrase: str) -> QPEPKeyRing:
        enforce_passphrase_policy(passphrase)
        if isinstance(armored_or_path, Path) or (
            isinstance(armored_or_path, str)
            and "\n" not in armored_or_path
            and Path(armored_or_path).exists()
        ):
            p = Path(armored_or_path)
            if p.suffix.lower() != QPKRF_EXTENSION:
                raise ValueError(f"Key ring file MUST have the '{QPKRF_EXTENSION}' extension.")
            armored_text = p.read_text(encoding="utf-8")
        else:
            armored_text = str(armored_or_path)

        label, _, payload_bytes = _armor_unwrap(armored_text)
        if label not in ("CALYX QPKRF PUBLIC KEY RING", "CALYX QPKRF PRIVATE KEY RING"):
            raise ValueError(f"Unexpected QPKRF armor header: {label}")

        envelope = json.loads(payload_bytes.decode("utf-8"))
        identity = envelope["identity"]
        keyring = QPEPKeyRing(
            key_id=envelope["key_id"],
            fingerprint_qsponge_512=envelope["fingerprint_qsponge_512"],
            created_at=envelope["created_at"],
            name=identity["name"],
            email=identity["email"],
            comment=identity.get("comment", ""),
            public_bundle=envelope["public_bundle"],
            encrypted_private_bundle=envelope.get("encrypted_private_bundle"),
            export_lock=envelope["export_lock"],
            integrity_mac=envelope["integrity_mac"],
        )

        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(keyring):
            raise ValueError("QPKRF self-certification signature verification failed (QVS-87 + HGC-448).")

        if keyring.has_private_key:
            CalyxQPEPProtocol.unlock_private_keys(keyring, passphrase)

        return keyring

    @staticmethod
    def encrypt_bytes(
        plaintext: bytes,
        recipient_keyring: QPEPKeyRing,
        passphrase: str,
        sender_keyring: Optional[QPEPKeyRing] = None,
        filename: Optional[str] = None,
        compress: bool = True,
    ) -> str:
        enforce_passphrase_policy(passphrase)
        if not CalyxQPEPProtocol.verify_public_keyring_self_signature(recipient_keyring):
            raise ValueError("Recipient public key ring self-signature is invalid.")

        recip_hgc_pk_bytes = _b64d(recipient_keyring.public_bundle["hgc_448_public_b64"])
        recip_qlx_pk_bytes = _b64d(recipient_keyring.public_bundle["qlx_1024_public_b64"])
        recip_hgc_pk = x448.X448PublicKey.from_public_bytes(recip_hgc_pk_bytes)

        eph_hgc_sk = x448.X448PrivateKey.generate()
        eph_hgc_pk_bytes = eph_hgc_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ss_hgc = eph_hgc_sk.exchange(recip_hgc_pk)
        ct_qlx, ss_qlx = QLX1024Engine.encaps(recip_qlx_pk_bytes)

        ss_hybrid = qsponge_var(
            b"CALYX-QPEP-KEM-v1"
            + ss_qlx
            + ss_hgc
            + ct_qlx
            + eph_hgc_pk_bytes
            + recip_qlx_pk_bytes
            + recip_hgc_pk_bytes,
            64,
        )

        pkt_salt = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,
            salt=pkt_salt,
            info=b"CALYX-QPEP-CC512-SUBKEYS|" + recipient_keyring.key_id.encode("ascii"),
        )
        okm = hkdf.derive(ss_hybrid)
        k_s1, k_s2, k_transcript_mac = okm[:32], okm[32:64], okm[64:128]

        inner_envelope = {
            "filename": filename or "inline_message.txt",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "plaintext_qsponge_512": qsponge_512(plaintext).hex().upper(),
            "plaintext_size": len(plaintext),
            "compressed": compress,
            "data_b64": _b64e(zlib.compress(plaintext, level=6) if compress else plaintext),
        }

        if sender_keyring is not None:
            sig_armored = CalyxQPEPProtocol.sign_bytes(plaintext, sender_keyring, passphrase)
            inner_envelope["sender_key_id"] = sender_keyring.key_id
            inner_envelope["embedded_signature"] = sig_armored

        serialized_inner = json.dumps(inner_envelope, separators=(",", ":")).encode("utf-8")

        chunks_out = []
        total_len = len(serialized_inner)
        offset = 0
        chunk_idx = 0
        while offset < total_len or (total_len == 0 and chunk_idx == 0):
            piece = serialized_inner[offset : offset + CHUNK_SIZE]
            offset += len(piece)
            is_final = 1 if offset >= total_len else 0
            aad = f"CALYX-QPEP-CC512|recip={recipient_keyring.key_id}|idx={chunk_idx}|final={is_final}".encode("utf-8")
            n1, n2, ct_chunk = _cc512_encrypt(piece, k_s1, k_s2, aad)
            chunks_out.append(
                {
                    "idx": chunk_idx,
                    "final": is_final,
                    "cc512_n1_b64": _b64e(n1),
                    "cc512_n2_b64": _b64e(n2),
                    "ct_b64": _b64e(ct_chunk),
                }
            )
            chunk_idx += 1
            if total_len == 0:
                break

        transcript_bytes = json.dumps(chunks_out, sort_keys=True, separators=(",", ":")).encode("utf-8")
        transcript_tag = hmac.new(k_transcript_mac, b"CALYX-QPEP-TRANSCRIPT|" + transcript_bytes, hashlib.sha3_512).hexdigest().upper()

        packet_obj = {
            "magic": "QPEP-v1",
            "version": "1.0.0",
            "suite": SUITE_ID,
            "recipient_key_id": recipient_keyring.key_id,
            "sender_key_id": sender_keyring.key_id if sender_keyring else None,
            "pkt_salt_b64": _b64e(pkt_salt),
            "ephemeral_hgc_448_pk_b64": _b64e(eph_hgc_pk_bytes),
            "qlx_1024_ct_b64": _b64e(ct_qlx),
            "chunks": chunks_out,
            "transcript_qsponge_512": transcript_tag,
        }

        metadata = {
            "Version": f"{PROTOCOL_VERSION} (Calyx Labs Inc.)",
            "Suite": "QLX-1024+HGC-448 / CC-512",
            "Recipient-Key-ID": recipient_keyring.key_id,
            "Signed": "YES" if sender_keyring else "NO",
        }
        return _armor_wrap("CALYX QPEP ENCRYPTED PACKET", metadata, json.dumps(packet_obj).encode("utf-8"))

    @staticmethod
    def decrypt_packet(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        enforce_passphrase_policy(passphrase)
        priv_keys = CalyxQPEPProtocol.unlock_private_keys(recipient_private_keyring, passphrase)

        _, _, payload_bytes = _armor_unwrap(armored_packet, expected_label="CALYX QPEP ENCRYPTED PACKET")
        packet_obj = json.loads(payload_bytes.decode("utf-8"))

        if packet_obj.get("recipient_key_id") != recipient_private_keyring.key_id:
            raise ValueError("Packet is addressed to a different Key-ID.")

        recip_hgc_pk_bytes = _b64d(recipient_private_keyring.public_bundle["hgc_448_public_b64"])
        recip_qlx_pk_bytes = _b64d(recipient_private_keyring.public_bundle["qlx_1024_public_b64"])

        eph_hgc_pk_bytes = _b64d(packet_obj["ephemeral_hgc_448_pk_b64"])
        ct_qlx = _b64d(packet_obj["qlx_1024_ct_b64"])

        hgc_sk = x448.X448PrivateKey.from_private_bytes(priv_keys["hgc_448_private"])
        eph_hgc_pk = x448.X448PublicKey.from_public_bytes(eph_hgc_pk_bytes)
        ss_hgc = hgc_sk.exchange(eph_hgc_pk)
        ss_qlx = QLX1024Engine.decaps(priv_keys["qlx_1024_private"], ct_qlx)

        ss_hybrid = qsponge_var(
            b"CALYX-QPEP-KEM-v1"
            + ss_qlx
            + ss_hgc
            + ct_qlx
            + eph_hgc_pk_bytes
            + recip_qlx_pk_bytes
            + recip_hgc_pk_bytes,
            64,
        )

        pkt_salt = _b64d(packet_obj["pkt_salt_b64"])
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,
            salt=pkt_salt,
            info=b"CALYX-QPEP-CC512-SUBKEYS|" + recipient_private_keyring.key_id.encode("ascii"),
        )
        okm = hkdf.derive(ss_hybrid)
        k_s1, k_s2, k_transcript_mac = okm[:32], okm[32:64], okm[64:128]

        chunks = packet_obj["chunks"]
        transcript_bytes = json.dumps(chunks, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_tag = hmac.new(k_transcript_mac, b"CALYX-QPEP-TRANSCRIPT|" + transcript_bytes, hashlib.sha3_512).hexdigest().upper()
        if not hmac.compare_digest(expected_tag, packet_obj["transcript_qsponge_512"]):
            raise ValueError("Packet transcript qSponge-512 verification failed.")

        reassembled = bytearray()
        for expected_idx, ch in enumerate(chunks):
            if ch["idx"] != expected_idx:
                raise ValueError("Chunk sequence tampering detected.")
            is_final = ch["final"]
            aad = f"CALYX-QPEP-CC512|recip={recipient_private_keyring.key_id}|idx={expected_idx}|final={is_final}".encode("utf-8")
            pt_piece = _cc512_decrypt(
                outer_ct=_b64d(ch["ct_b64"]),
                k_s1=k_s1,
                k_s2=k_s2,
                n1=_b64d(ch["cc512_n1_b64"]),
                n2=_b64d(ch["cc512_n2_b64"]),
                aad=aad,
            )
            reassembled.extend(pt_piece)

        inner_envelope = json.loads(bytes(reassembled).decode("utf-8"))
        raw_data = _b64d(inner_envelope["data_b64"])
        plaintext = zlib.decompress(raw_data) if inner_envelope.get("compressed") else raw_data

        actual_hash = qsponge_512(plaintext).hex().upper()
        if not hmac.compare_digest(actual_hash, inner_envelope["plaintext_qsponge_512"]):
            raise ValueError("Plaintext qSponge-512 integrity check failed.")

        sig_verified = None
        if "embedded_signature" in inner_envelope and sender_public_keyring is not None:
            sig_verified = CalyxQPEPProtocol.verify_signature(
                plaintext, inner_envelope["embedded_signature"], sender_public_keyring
            )

        meta_info = {
            "filename": inner_envelope.get("filename"),
            "timestamp": inner_envelope.get("timestamp"),
            "plaintext_qsponge_512": actual_hash,
            "plaintext_size": inner_envelope.get("plaintext_size"),
            "sender_key_id": inner_envelope.get("sender_key_id"),
            "signature_verified": sig_verified,
        }
        return plaintext, meta_info

    @staticmethod
    def encrypt_text(
        plaintext: str,
        recipient_keyring: QPEPKeyRing,
        passphrase: str,
        sender_keyring: Optional[QPEPKeyRing] = None,
    ) -> str:
        return CalyxQPEPProtocol.encrypt_bytes(
            plaintext.encode("utf-8"),
            recipient_keyring=recipient_keyring,
            passphrase=passphrase,
            sender_keyring=sender_keyring,
            filename="message.txt",
        )

    @staticmethod
    def decrypt_text(
        armored_packet: str,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> str:
        pt_bytes, _ = CalyxQPEPProtocol.decrypt_packet(
            armored_packet,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        return pt_bytes.decode("utf-8")

    @staticmethod
    def encrypt_file(
        input_path: str | Path,
        output_path: str | Path,
        recipient_keyring: QPEPKeyRing,
        passphrase: str,
        sender_keyring: Optional[QPEPKeyRing] = None,
    ) -> str:
        in_p = Path(input_path)
        data = in_p.read_bytes()
        armored = CalyxQPEPProtocol.encrypt_bytes(
            data,
            recipient_keyring=recipient_keyring,
            passphrase=passphrase,
            sender_keyring=sender_keyring,
            filename=in_p.name,
        )
        Path(output_path).write_text(armored, encoding="utf-8")
        return armored

    @staticmethod
    def decrypt_file(
        input_packet_path: str | Path,
        output_path: str | Path,
        recipient_private_keyring: QPEPKeyRing,
        passphrase: str,
        sender_public_keyring: Optional[QPEPKeyRing] = None,
    ) -> Dict[str, Any]:
        armored = Path(input_packet_path).read_text(encoding="utf-8")
        pt_bytes, meta = CalyxQPEPProtocol.decrypt_packet(
            armored,
            recipient_private_keyring=recipient_private_keyring,
            passphrase=passphrase,
            sender_public_keyring=sender_public_keyring,
        )
        Path(output_path).write_bytes(pt_bytes)
        return meta

    @staticmethod
    def sign_bytes(data: bytes, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        enforce_passphrase_policy(passphrase)
        priv_keys = CalyxQPEPProtocol.unlock_private_keys(signer_private_keyring, passphrase)
        qvs_pk = _b64d(signer_private_keyring.public_bundle["qvs_87_public_b64"])

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg_digest = qsponge_512(data).hex().upper()
        transcript = f"CALYX-QPEP-SIG-v1|{signer_private_keyring.key_id}|{timestamp}|{msg_digest}".encode("utf-8")

        ed_sk = ed448.Ed448PrivateKey.from_private_bytes(priv_keys["hgc_sig_private"])
        sig1 = ed_sk.sign(transcript)
        sig2 = QVS87Engine.sign(priv_keys["qvs_87_private"], qvs_pk, transcript)

        sig_obj = {
            "magic": "QPSIG-v1",
            "version": "1.0.0",
            "suite": "QVS-87+qSponge-512",
            "signer_key_id": signer_private_keyring.key_id,
            "timestamp": timestamp,
            "message_qsponge_512": msg_digest,
            "hgc_signature_b64": _b64e(sig1),
            "qvs_87_signature_b64": _b64e(sig2),
        }
        metadata = {
            "Version": f"{PROTOCOL_VERSION} (Calyx Labs Inc.)",
            "Suite": "QVS-87+qSponge-512",
            "Signer-Key-ID": signer_private_keyring.key_id,
            "Timestamp": timestamp,
        }
        return _armor_wrap("CALYX QPEP SIGNATURE", metadata, json.dumps(sig_obj).encode("utf-8"))

    @staticmethod
    def verify_signature(data: bytes, armored_signature: str, signer_public_keyring: QPEPKeyRing) -> bool:
        try:
            if not CalyxQPEPProtocol.verify_public_keyring_self_signature(signer_public_keyring):
                return False
            _, _, payload_bytes = _armor_unwrap(armored_signature, expected_label="CALYX QPEP SIGNATURE")
            sig_obj = json.loads(payload_bytes.decode("utf-8"))
            if sig_obj.get("signer_key_id") != signer_public_keyring.key_id:
                return False

            actual_digest = qsponge_512(data).hex().upper()
            if not hmac.compare_digest(actual_digest, sig_obj.get("message_qsponge_512", "")):
                return False

            transcript = (
                f"CALYX-QPEP-SIG-v1|{signer_public_keyring.key_id}|{sig_obj['timestamp']}|{actual_digest}".encode("utf-8")
            )
            ed_pk = ed448.Ed448PublicKey.from_public_bytes(_b64d(signer_public_keyring.public_bundle["hgc_sig_public_b64"]))
            ed_pk.verify(_b64d(sig_obj["hgc_signature_b64"]), transcript)

            qvs_pk = _b64d(signer_public_keyring.public_bundle["qvs_87_public_b64"])
            return QVS87Engine.verify(qvs_pk, transcript, _b64d(sig_obj["qvs_87_signature_b64"]))
        except Exception:
            return False

    @staticmethod
    def sign_text(text: str, signer_private_keyring: QPEPKeyRing, passphrase: str) -> str:
        return CalyxQPEPProtocol.sign_bytes(text.encode("utf-8"), signer_private_keyring, passphrase)

    @staticmethod
    def verify_text_signature(text: str, armored_signature: str, signer_public_keyring: QPEPKeyRing) -> bool:
        return CalyxQPEPProtocol.verify_signature(text.encode("utf-8"), armored_signature, signer_public_keyring)
