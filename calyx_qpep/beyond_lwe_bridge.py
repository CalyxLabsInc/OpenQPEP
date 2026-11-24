"""
OpenQPEP Official Release 1.2.0 (v1.2.0) Beyond-LWE Native .qpkrf Persistence & Dispatch Bridge.
Provides unified Wire Format v5 keygen, encrypt, decrypt, sign, and verify dispatch for all 5 Beyond-LWE suites:
  - CIF-SQI-512  (Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512)
  - CRT-RSD512   (Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512)
  - CGM-8192     (Calyx Goppa-Monolith: CGM-8192 + QHS-512)
  - CULC-2048    (Calyx Unstructured-Citadel: CULC-2048 + CGM-8192)
  - CSP-Omega    (Calyx Sovereign-Pentad: CSP-Omega + QHS-512)
"""
import base64
import binascii
import json
from typing import Any, Dict, Tuple

from .constants import MAX_ARMOR_BYTES, PACKET_TYPE_SIGNATURE, PROTOCOL_VERSION, UNIVERSAL_VERSION
from .exceptions import OpenQPEPError, QPEPFaultGuardError, QPEPKeyRingError, QPEPSuiteError, QPEPWireFormatError
from .primitives.consttime import ct_eq, ct_eq_str
from .wire.armor import armor_unwrap, armor_wrap, strict_b64decode, strict_json_loads

BEYOND_LWE_SUITES = ("CIF-SQI-512", "CRT-RSD512", "CGM-8192", "CULC-2048", "CSP-Omega")
CRT_SIG_LABEL = "CALYX QPEP RANK-METRIC SIGNATURE"
CGM_SIG_LABEL = "CALYX QPEP GOPPA-MONOLITH SIGNATURE"
_PARSING_ERRORS = (
    OpenQPEPError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    binascii.Error,
    json.JSONDecodeError,
    UnicodeDecodeError,
)


def _validate_beyond_lwe_suite(suite_id: str) -> str:
    if not isinstance(suite_id, str) or suite_id not in BEYOND_LWE_SUITES:
        raise QPEPSuiteError(f"Unsupported Beyond-LWE suite: {suite_id!r}")
    return suite_id


def _validate_material(suite_id: str, material: Any, required_key: str, role: str) -> Dict[str, Any]:
    if not isinstance(material, dict):
        raise QPEPKeyRingError(f"Beyond-LWE {role} material for {suite_id} must be a dict.")
    declared = material.get("suite_id")
    if declared is not None and not ct_eq_str(declared, suite_id):
        raise QPEPSuiteError(
            f"Beyond-LWE {role} suite mismatch: expected '{suite_id}', got '{declared}'."
        )
    if required_key not in material:
        raise QPEPKeyRingError(f"Beyond-LWE {role} material for {suite_id} missing required key '{required_key}'.")
    return material


def _validate_bytes_payload(data: Any, label: str) -> bytes:
    if isinstance(data, bytearray):
        return bytes(data)
    if not isinstance(data, bytes):
        raise QPEPWireFormatError(f"{label} must be bytes or bytearray.")
    return data


def _engines():
    from .codes.goppa_suite import CalyxGoppaMonolithSuite
    from .codes.rank_suite import CalyxRankMetricSuite
    from .hashsig.qhs_512_hypertree import QHS512HypertreeEngine
    from .isogeny.isogeny_suite import CalyxIsogenyForgeSuite
    from .lattice.citadel_suite import CalyxUnstructuredCitadelSuite
    from .multivariate.qmq_512 import MultivariateQuadraticEngine
    from .pentad import CalyxSovereignPentad
    return (
        CalyxGoppaMonolithSuite, CalyxRankMetricSuite, QHS512HypertreeEngine,
        CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine,
        CalyxSovereignPentad,
    )


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return strict_b64decode(s)


def generate_beyond_lwe_material(suite_id: str, allow_low_ram_override: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generates JSON-serializable (public_dict, private_dict) for any of the 5 Beyond-LWE suites."""
    _validate_beyond_lwe_suite(suite_id)
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        pub, priv = CalyxIsogenyForgeSuite.keygen()
        return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}
    if suite_id == "CRT-RSD512":
        kem_pk, kem_sk = CalyxRankMetricSuite.keygen()
        sig_pk, sig_sk = MultivariateQuadraticEngine.keygen()
        return (
            {"suite_id": suite_id, "kem_pk_b64": _b64e(kem_pk), "sig_pk_b64": _b64e(sig_pk)},
            {"suite_id": suite_id, "kem_sk_b64": _b64e(kem_sk), "sig_sk_b64": _b64e(sig_sk)},
        )
    if suite_id == "CGM-8192":
        kem_pk, kem_sk = CalyxGoppaMonolithSuite.keygen()
        sig_pk, sig_sk = QHS512HypertreeEngine.keygen()
        return (
            {"suite_id": suite_id, "kem_pk_b64": _b64e(kem_pk), "sig_pk_b64": _b64e(sig_pk)},
            {"suite_id": suite_id, "kem_sk_b64": _b64e(kem_sk), "sig_sk_b64": _b64e(sig_sk)},
        )
    if suite_id == "CULC-2048":
        pub, priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=allow_low_ram_override)
        return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}
    pub, priv = CalyxSovereignPentad.keygen(allow_low_ram_override=allow_low_ram_override)
    return {"suite_id": suite_id, "pub": pub}, {"suite_id": suite_id, "priv": priv}


def encrypt_beyond_lwe(suite_id: str, plaintext: bytes, blwe_pub: Dict[str, Any]) -> str:
    _validate_beyond_lwe_suite(suite_id)
    pt = _validate_bytes_payload(plaintext, "plaintext")
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, _QHS, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, _QMQ, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        _validate_material(suite_id, blwe_pub, "pub", "public")
        return CalyxIsogenyForgeSuite.encrypt(pt, blwe_pub["pub"])
    if suite_id == "CRT-RSD512":
        _validate_material(suite_id, blwe_pub, "kem_pk_b64", "public")
        return CalyxRankMetricSuite.encrypt(pt, _b64d(blwe_pub["kem_pk_b64"]))
    if suite_id == "CGM-8192":
        _validate_material(suite_id, blwe_pub, "kem_pk_b64", "public")
        return CalyxGoppaMonolithSuite.encrypt(pt, _b64d(blwe_pub["kem_pk_b64"]))
    if suite_id == "CULC-2048":
        _validate_material(suite_id, blwe_pub, "pub", "public")
        return CalyxUnstructuredCitadelSuite.encrypt(pt, blwe_pub["pub"])
    _validate_material(suite_id, blwe_pub, "pub", "public")
    return CalyxSovereignPentad.encrypt(pt, blwe_pub["pub"])


def decrypt_beyond_lwe(suite_id: str, armored: str, blwe_priv: Dict[str, Any]) -> bytes:
    _validate_beyond_lwe_suite(suite_id)
    if not isinstance(armored, str) or not armored or len(armored) > MAX_ARMOR_BYTES:
        raise QPEPWireFormatError("Invalid or oversized armored Beyond-LWE ciphertext.")
    CalyxGoppaMonolithSuite, CalyxRankMetricSuite, _QHS, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, _QMQ, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        _validate_material(suite_id, blwe_priv, "priv", "private")
        return CalyxIsogenyForgeSuite.decrypt(armored, blwe_priv["priv"])
    if suite_id == "CRT-RSD512":
        _validate_material(suite_id, blwe_priv, "kem_sk_b64", "private")
        return CalyxRankMetricSuite.decrypt(armored, _b64d(blwe_priv["kem_sk_b64"]))
    if suite_id == "CGM-8192":
        _validate_material(suite_id, blwe_priv, "kem_sk_b64", "private")
        return CalyxGoppaMonolithSuite.decrypt(armored, _b64d(blwe_priv["kem_sk_b64"]))
    if suite_id == "CULC-2048":
        _validate_material(suite_id, blwe_priv, "priv", "private")
        return CalyxUnstructuredCitadelSuite.decrypt(armored, blwe_priv["priv"])
    _validate_material(suite_id, blwe_priv, "priv", "private")
    return CalyxSovereignPentad.decrypt(armored, blwe_priv["priv"])


def sign_beyond_lwe(suite_id: str, message: bytes, blwe_pub: Dict[str, Any], blwe_priv: Dict[str, Any]) -> str:
    _validate_beyond_lwe_suite(suite_id)
    msg = _validate_bytes_payload(message, "message")
    _CGM, _CRT, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        _validate_material(suite_id, blwe_pub, "pub", "public")
        _validate_material(suite_id, blwe_priv, "priv", "private")
        armored = CalyxIsogenyForgeSuite.sign(msg, blwe_priv["priv"])
    elif suite_id == "CRT-RSD512":
        _validate_material(suite_id, blwe_pub, "sig_pk_b64", "public")
        _validate_material(suite_id, blwe_priv, "sig_sk_b64", "private")
        sig = MultivariateQuadraticEngine.sign(_b64d(blwe_priv["sig_sk_b64"]), msg)
        bundle = {
            "type": "openqpep-rank-metric-signature",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite_id": "CRT-RSD512",
            "message_b64": _b64e(msg),
            "sig_qmq_b64": _b64e(sig),
        }
        armored = armor_wrap(CRT_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SIGNATURE)
    elif suite_id == "CGM-8192":
        _validate_material(suite_id, blwe_pub, "sig_pk_b64", "public")
        _validate_material(suite_id, blwe_priv, "sig_sk_b64", "private")
        sig = QHS512HypertreeEngine.sign(_b64d(blwe_priv["sig_sk_b64"]), msg)
        bundle = {
            "type": "openqpep-goppa-monolith-signature",
            "version": UNIVERSAL_VERSION,
            "protocol": PROTOCOL_VERSION,
            "suite_id": "CGM-8192",
            "message_b64": _b64e(msg),
            "sig_qhs_b64": _b64e(sig),
        }
        armored = armor_wrap(CGM_SIG_LABEL, json.dumps(bundle, separators=(",", ":")).encode("utf-8"), packet_type=PACKET_TYPE_SIGNATURE)
    elif suite_id == "CULC-2048":
        _validate_material(suite_id, blwe_pub, "pub", "public")
        _validate_material(suite_id, blwe_priv, "priv", "private")
        armored = CalyxUnstructuredCitadelSuite.sign(msg, blwe_priv["priv"])
    else:
        _validate_material(suite_id, blwe_pub, "pub", "public")
        _validate_material(suite_id, blwe_priv, "priv", "private")
        armored = CalyxSovereignPentad.sign(msg, blwe_pub["pub"], blwe_priv["priv"])

    # Mandatory suite-level Verify-Before-Emit Fault-Guard across all 5 Beyond-LWE suites
    ok_fg, verified_msg = verify_beyond_lwe(suite_id, armored, blwe_pub)
    if not ok_fg or not ct_eq(verified_msg, msg):
        raise QPEPFaultGuardError(
            f"Beyond-LWE {suite_id} Fault-Injection Guard triggered: signature bundle failed internal verification."
        )
    return armored


def verify_beyond_lwe(suite_id: str, armored_sig: str, blwe_pub: Dict[str, Any]) -> Tuple[bool, bytes]:
    _validate_beyond_lwe_suite(suite_id)
    if not isinstance(armored_sig, str) or not armored_sig or len(armored_sig) > MAX_ARMOR_BYTES:
        return False, b""
    _CGM, _CRT, QHS512HypertreeEngine, CalyxIsogenyForgeSuite, CalyxUnstructuredCitadelSuite, MultivariateQuadraticEngine, CalyxSovereignPentad = _engines()
    if suite_id == "CIF-SQI-512":
        if not isinstance(blwe_pub, dict) or "pub" not in blwe_pub:
            return False, b""
        return CalyxIsogenyForgeSuite.verify(armored_sig, blwe_pub["pub"])
    if suite_id == "CRT-RSD512":
        try:
            _validate_material(suite_id, blwe_pub, "sig_pk_b64", "public")
            raw, _ = armor_unwrap(armored_sig, CRT_SIG_LABEL)
            bundle = strict_json_loads(raw)
            if not isinstance(bundle, dict) or not ct_eq_str(bundle.get("suite_id"), "CRT-RSD512"):
                return False, b""
            msg = _b64d(bundle["message_b64"])
            ok = MultivariateQuadraticEngine.verify(_b64d(blwe_pub["sig_pk_b64"]), msg, _b64d(bundle["sig_qmq_b64"]))
            return bool(ok), (msg if ok else b"")
        except _PARSING_ERRORS:
            return False, b""
    if suite_id == "CGM-8192":
        try:
            _validate_material(suite_id, blwe_pub, "sig_pk_b64", "public")
            raw, _ = armor_unwrap(armored_sig, CGM_SIG_LABEL)
            bundle = strict_json_loads(raw)
            if not isinstance(bundle, dict) or not ct_eq_str(bundle.get("suite_id"), "CGM-8192"):
                return False, b""
            msg = _b64d(bundle["message_b64"])
            ok = QHS512HypertreeEngine.verify(_b64d(blwe_pub["sig_pk_b64"]), msg, _b64d(bundle["sig_qhs_b64"]))
            return bool(ok), (msg if ok else b"")
        except _PARSING_ERRORS:
            return False, b""
    if suite_id == "CULC-2048":
        if not isinstance(blwe_pub, dict) or "pub" not in blwe_pub:
            return False, b""
        return CalyxUnstructuredCitadelSuite.verify(armored_sig, blwe_pub["pub"])
    if not isinstance(blwe_pub, dict) or "pub" not in blwe_pub:
        return False, b""
    return CalyxSovereignPentad.verify(armored_sig, blwe_pub["pub"])
