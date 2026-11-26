#!/usr/bin/env python3
"""
OpenQPEP Automated 10-Suite Benchmark Harness (Official Release 1.2.9 / v1.2.9).

Measures keygen, encaps/encrypt, decaps/decrypt, sign, verify, total latency, and peak RSS RAM
across all 10 canonical post-quantum suites — supporting both single-backend benchmarking and
side-by-side Native C99/SIMD (`libopenqpep`) vs Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`)
comparative speedup telemetry.
"""
import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from calyx_qpep import (
    UNIVERSAL_VERSION,
    is_native_available,
    native_abi_version,
    native_backend_info,
    set_native_enabled,
)
from calyx_qpep.codes.goppa_suite import CalyxGoppaMonolithSuite
from calyx_qpep.codes.rank_suite import CalyxRankMetricSuite
from calyx_qpep.hashsig.qhs_512_hypertree import QHS512HypertreeEngine
from calyx_qpep.isogeny.isogeny_suite import CalyxIsogenyForgeSuite
from calyx_qpep.lattice.citadel_suite import CalyxUnstructuredCitadelSuite
from calyx_qpep.lattice.qlx_kem import QLXEngine
from calyx_qpep.lattice.qvs_dsa import QVSEngine
from calyx_qpep.multivariate.qmq_512 import MultivariateQuadraticEngine
from calyx_qpep.pentad import CalyxSovereignPentad

QLX_SUITES = [
    ("QLX-4096", "Calyx Lattice-Apex: QLX-4096 + QVS-256 (4,096-Dim Module-LWE — All Devices)", "QLX-4096", "QVS-256", "All Devices"),
    ("QLX-768", "Calyx Velocity: QLX-768 + QVS-65 (High-Speed Mobile — All Devices)", "QLX-768", "QVS-65", "All Devices"),
    ("QLX-1024", "Calyx Sovereign-Hybrid: QLX-1024 + QVS-87 (Balanced Post-Quantum — All Devices)", "QLX-1024", "QVS-87", "All Devices"),
    ("QLX-2048", "Calyx Ultra-Grid: QLX-2048 + QVS-128 (2,048-Dim Lattice — All Devices)", "QLX-2048", "QVS-128", "All Devices"),
    ("QLX-16384", "Calyx Hyper-Tesseract: QLX-16384 + QVS-1024 (16,384-Dim 4-Manifold — HIGH-TIER HARDWARE ONLY)", "QLX-16384", "QVS-1024", "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)"),
]

ALL_BENCH_SUITE_IDS = [
    "QLX-4096",
    "QLX-768",
    "QLX-1024",
    "QLX-2048",
    "QLX-16384",
    "CIF-SQI-512",
    "CRT-RSD512",
    "CGM-8192",
    "CULC-2048",
    "CSP-Omega",
]


def _peak_rss_mib() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS/Darwin reports bytes.
    if platform.system() == "Darwin":
        return round(rss / (1024.0 * 1024.0), 2)
    return round(rss / 1024.0, 2)


def _safe_ratio(pure_ms: float, native_ms: float) -> float:
    return round(pure_ms / max(native_ms, 0.001), 2)


def _make_row(
    suite_id: str,
    label: str,
    hw_tier: str,
    backend_label: str,
    kg_ms: float,
    enc_ms: float,
    dec_ms: float,
    sign_ms: float,
    ver_ms: float,
) -> Dict[str, Any]:
    total_ms = round(kg_ms + enc_ms + dec_ms + sign_ms + ver_ms, 2)
    return {
        "release": f"v{UNIVERSAL_VERSION}",
        "suite_id": suite_id,
        "suite": label,
        "hardware_tier": hw_tier,
        "backend": backend_label,
        "keygen_ms": kg_ms,
        "encaps_ms": enc_ms,
        "decaps_ms": dec_ms,
        "sign_ms": sign_ms,
        "verify_ms": ver_ms,
        "total_ms": total_ms,
        "peak_rss_mib": _peak_rss_mib(),
    }


def run_benchmarks(
    include_heavy: bool = True,
    *,
    native_enabled: Optional[bool] = None,
    suite_ids: Optional[Iterable[str]] = None,
    warmup: bool = True,
) -> List[Dict[str, Any]]:
    """
    Runs end-to-end keygen, encaps/encrypt, decaps/decrypt, sign, and verify across
    OpenQPEP's canonical suites and returns structured per-suite telemetry rows.
    """
    prev_native = is_native_available()
    selected: Optional[Set[str]] = set(suite_ids) if suite_ids is not None else None

    try:
        if native_enabled is not None:
            set_native_enabled(bool(native_enabled))

        active_native = is_native_available()
        backend_label = "native_c99" if active_native else "pure_python"

        # Warm up dynamic library / Python bytecode caches so first suite pays no cold-start penalty.
        if warmup:
            w_witness = b"\x5A" * 64
            ek_w, dk_w = QLXEngine.keygen("QLX-768", w_witness)
            ct_w, ss_w = QLXEngine.encaps(ek_w, "QLX-768")
            if QLXEngine.decaps(dk_w, ct_w, "QLX-768") != ss_w:
                raise RuntimeError("Benchmark warmup QLX-768 parity failed.")

        rows: List[Dict[str, Any]] = []
        witness = os.urandom(64)
        msg = f"OpenQPEP Official Release {UNIVERSAL_VERSION} Benchmark Message".encode("ascii")

        target_qlx = QLX_SUITES if include_heavy else QLX_SUITES[:4]
        for suite_id, label, qlx_t, qvs_t, hw_tier in target_qlx:
            if selected is not None and suite_id not in selected:
                continue

            t0 = time.perf_counter()
            ek, dk = QLXEngine.keygen(qlx_t, witness)
            pk_s, sk_s = QVSEngine.keygen(qvs_t, witness)
            kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            t0 = time.perf_counter()
            ct, ss = QLXEngine.encaps(ek, qlx_t)
            enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            t0 = time.perf_counter()
            if QLXEngine.decaps(dk, ct, qlx_t) != ss:
                raise RuntimeError(f"{suite_id} decaps mismatch during benchmark.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            t0 = time.perf_counter()
            sig = QVSEngine.sign(sk_s, pk_s, msg, tier=qvs_t)
            sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            t0 = time.perf_counter()
            if not QVSEngine.verify(pk_s, msg, sig, tier=qvs_t):
                raise RuntimeError(f"{suite_id} verify failed during benchmark.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            rows.append(_make_row(suite_id, label, hw_tier, backend_label, kg_ms, enc_ms, dec_ms, sign_ms, ver_ms))

        # 6. Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512
        if selected is None or "CIF-SQI-512" in selected:
            t0 = time.perf_counter(); iso_pub, iso_priv = CalyxIsogenyForgeSuite.keygen(); kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); iso_ct = CalyxIsogenyForgeSuite.encrypt(msg, iso_pub); enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if CalyxIsogenyForgeSuite.decrypt(iso_ct, iso_priv) != msg:
                raise RuntimeError("CIF-SQI-512 decrypt mismatch.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); iso_sig = CalyxIsogenyForgeSuite.sign(msg, iso_priv); sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); ok, _ = CalyxIsogenyForgeSuite.verify(iso_sig, iso_pub)
            if not ok:
                raise RuntimeError("CIF-SQI-512 verify failed.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rows.append(_make_row(
                "CIF-SQI-512",
                "Calyx Isogeny-Forge: CIF-SQI-512 + QHS-512 (2D Supersingular Isogeny — All Devices)",
                "All Devices",
                backend_label,
                kg_ms, enc_ms, dec_ms, sign_ms, ver_ms,
            ))

        # 7. Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512
        if selected is None or "CRT-RSD512" in selected:
            t0 = time.perf_counter(); rm_pk, rm_sk = CalyxRankMetricSuite.keygen(); mq_pk, mq_sk = MultivariateQuadraticEngine.keygen(); kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); rm_ct = CalyxRankMetricSuite.encrypt(msg, rm_pk); enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if CalyxRankMetricSuite.decrypt(rm_ct, rm_sk) != msg:
                raise RuntimeError("CRT-RSD512 decrypt mismatch.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); mq_sig = MultivariateQuadraticEngine.sign(mq_sk, msg); sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if not MultivariateQuadraticEngine.verify(mq_pk, msg, mq_sig):
                raise RuntimeError("QMQ-512 verify failed.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rows.append(_make_row(
                "CRT-RSD512",
                "Calyx Rank-Metric Tensor: CRT-RSD512 + QMQ-512 (All-Devices Signature Default — All Devices)",
                "All Devices",
                backend_label,
                kg_ms, enc_ms, dec_ms, sign_ms, ver_ms,
            ))

        # 8. Calyx Goppa-Monolith: CGM-8192 + QHS-512
        if selected is None or "CGM-8192" in selected:
            t0 = time.perf_counter(); gm_pk, gm_sk = CalyxGoppaMonolithSuite.keygen(); qhs_pk, qhs_sk = QHS512HypertreeEngine.keygen(); kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); gm_ct = CalyxGoppaMonolithSuite.encrypt(msg, gm_pk); enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if CalyxGoppaMonolithSuite.decrypt(gm_ct, gm_sk) != msg:
                raise RuntimeError("CGM-8192 decrypt mismatch.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); qhs_sig = QHS512HypertreeEngine.sign(qhs_sk, msg); sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if not QHS512HypertreeEngine.verify(qhs_pk, msg, qhs_sig):
                raise RuntimeError("QHS-512 verify failed.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rows.append(_make_row(
                "CGM-8192",
                "Calyx Goppa-Monolith: CGM-8192 + QHS-512 (Binary Goppa Code-Based — HIGH-TIER HARDWARE ONLY)",
                "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
                backend_label,
                kg_ms, enc_ms, dec_ms, sign_ms, ver_ms,
            ))

        # 9. Calyx Unstructured-Citadel: CULC-2048 + CGM-8192
        if selected is None or "CULC-2048" in selected:
            t0 = time.perf_counter(); cit_pub, cit_priv = CalyxUnstructuredCitadelSuite.keygen(allow_low_ram_override=True); kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); cit_ct = CalyxUnstructuredCitadelSuite.encrypt(msg, cit_pub); enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if CalyxUnstructuredCitadelSuite.decrypt(cit_ct, cit_priv) != msg:
                raise RuntimeError("CULC-2048 decrypt mismatch.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); cit_sig = CalyxUnstructuredCitadelSuite.sign(msg, cit_priv); sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); ok, _ = CalyxUnstructuredCitadelSuite.verify(cit_sig, cit_pub)
            if not ok:
                raise RuntimeError("CULC-2048 verify failed.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rows.append(_make_row(
                "CULC-2048",
                "Calyx Unstructured-Citadel: CULC-2048 + CGM-8192 (Zero-Ring Plain-LWE + Goppa — HIGH-TIER HARDWARE ONLY)",
                "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
                backend_label,
                kg_ms, enc_ms, dec_ms, sign_ms, ver_ms,
            ))

        # 10. Calyx Sovereign-Pentad: CSP-Omega + QHS-512
        if selected is None or "CSP-Omega" in selected:
            t0 = time.perf_counter(); p_pub, p_priv = CalyxSovereignPentad.keygen(allow_low_ram_override=True); kg_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); p_ct = CalyxSovereignPentad.encrypt(msg, p_pub); enc_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter()
            if CalyxSovereignPentad.decrypt(p_ct, p_priv) != msg:
                raise RuntimeError("CSP-Omega decrypt mismatch.")
            dec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); p_sig = CalyxSovereignPentad.sign(msg, p_pub, p_priv); sign_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            t0 = time.perf_counter(); ok, _ = CalyxSovereignPentad.verify(p_sig, p_pub)
            if not ok:
                raise RuntimeError("CSP-Omega verify failed.")
            ver_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rows.append(_make_row(
                "CSP-Omega",
                "Calyx Sovereign-Pentad: CSP-Omega + QHS-512 (High-Tier Signature Default — HIGH-TIER HARDWARE ONLY)",
                "HIGH-TIER HARDWARE ONLY (>= 12 GB RAM)",
                backend_label,
                kg_ms, enc_ms, dec_ms, sign_ms, ver_ms,
            ))

        return rows
    finally:
        set_native_enabled(prev_native)


def _run_isolated_backend_pass(
    mode: str,
    include_heavy: bool,
    suite_ids: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """Executes one backend pass in a clean child process so peak RSS is measured independently."""
    cmd = [sys.executable, str(Path(__file__).resolve()), "--emit-json-stdout", f"--mode={mode}"]
    if not include_heavy:
        cmd.append("--no-heavy")
    if suite_ids:
        cmd.append("--suites=" + ",".join(suite_ids))
    env = os.environ.copy()
    if mode == "pure":
        env["OPENQPEP_DISABLE_NATIVE"] = "1"
    else:
        env.pop("OPENQPEP_DISABLE_NATIVE", None)
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def run_comparative_benchmarks(
    include_heavy: bool = True,
    *,
    suite_ids: Optional[Iterable[str]] = None,
    isolate_processes: bool = False,
) -> List[Dict[str, Any]]:
    """
    Measures Native C99/SIMD (`libopenqpep`) vs Pure-Python (`OPENQPEP_DISABLE_NATIVE=1`)
    side-by-side and returns enriched benchmark records preserving all legacy JSON keys.
    """
    sel_list = list(suite_ids) if suite_ids is not None else None
    if isolate_processes:
        native_rows = _run_isolated_backend_pass("native", include_heavy, sel_list)
        pure_rows = _run_isolated_backend_pass("pure", include_heavy, sel_list)
    else:
        native_rows = run_benchmarks(include_heavy=include_heavy, native_enabled=True, suite_ids=sel_list)
        pure_rows = run_benchmarks(include_heavy=include_heavy, native_enabled=False, suite_ids=sel_list)

    pure_by_id = {r["suite_id"]: r for r in pure_rows}
    abi_hex = f"0x{native_abi_version():08x}" if is_native_available() else "0x00000000"
    backend_meta = native_backend_info()
    arch = platform.machine()

    merged: List[Dict[str, Any]] = []
    for nr in native_rows:
        sid = nr["suite_id"]
        pr = pure_by_id[sid]
        rec = dict(nr)
        rec["native_abi_version"] = abi_hex
        rec["native_simd_flags"] = backend_meta.get("simd", [])
        rec["cpu_arch"] = arch
        rec["pure_python"] = {
            "keygen_ms": pr["keygen_ms"],
            "encaps_ms": pr["encaps_ms"],
            "decaps_ms": pr["decaps_ms"],
            "sign_ms": pr["sign_ms"],
            "verify_ms": pr["verify_ms"],
            "total_ms": pr["total_ms"],
            "peak_rss_mib": pr["peak_rss_mib"],
        }
        rec["speedup_vs_pure_python"] = {
            "keygen_x": _safe_ratio(pr["keygen_ms"], nr["keygen_ms"]),
            "encaps_x": _safe_ratio(pr["encaps_ms"], nr["encaps_ms"]),
            "decaps_x": _safe_ratio(pr["decaps_ms"], nr["decaps_ms"]),
            "sign_x": _safe_ratio(pr["sign_ms"], nr["sign_ms"]),
            "verify_x": _safe_ratio(pr["verify_ms"], nr["verify_ms"]),
            "total_x": _safe_ratio(pr["total_ms"], nr["total_ms"]),
        }
        merged.append(rec)
    return merged


def format_markdown_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        f"| OpenQPEP Suite (`v{UNIVERSAL_VERSION}`) | Hardware Tier | Keygen (ms) | Encaps (ms) | Decaps (ms) | Sign (ms) | Verify (ms) | Peak RSS (MiB) |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| {r['suite']} | {r['hardware_tier']} | {r['keygen_ms']:.2f} | {r['encaps_ms']:.2f} | "
            f"{r['decaps_ms']:.2f} | {r['sign_ms']:.2f} | {r['verify_ms']:.2f} | {r['peak_rss_mib']:.2f} |"
        )
    return "\n".join(lines)


def format_comparative_markdown_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        f"| Suite (`v{UNIVERSAL_VERSION}`) | Keygen (C99 / Py) | Encaps (C99 / Py) | Decaps (C99 / Py) | Sign (C99 / Py) | Verify (C99 / Py) | Total Speedup | Peak RSS (MiB) |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        py = r.get("pure_python")
        sp = r.get("speedup_vs_pure_python")
        if py and sp:
            lines.append(
                f"| **{r['suite_id']}** | {r['keygen_ms']:.2f} / {py['keygen_ms']:.2f} ms | "
                f"{r['encaps_ms']:.2f} / {py['encaps_ms']:.2f} ms | "
                f"{r['decaps_ms']:.2f} / {py['decaps_ms']:.2f} ms | "
                f"{r['sign_ms']:.2f} / {py['sign_ms']:.2f} ms | "
                f"{r['verify_ms']:.2f} / {py['verify_ms']:.2f} ms | "
                f"**{sp['total_x']:.2f}x** | {r['peak_rss_mib']:.2f} |"
            )
        else:
            lines.append(
                f"| **{r['suite_id']}** | {r['keygen_ms']:.2f} ms | {r['encaps_ms']:.2f} ms | "
                f"{r['decaps_ms']:.2f} ms | {r['sign_ms']:.2f} ms | {r['verify_ms']:.2f} ms | "
                f"N/A | {r['peak_rss_mib']:.2f} |"
            )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OpenQPEP Automated 10-Suite Benchmark Harness")
    parser.add_argument("--no-heavy", action="store_true", help="Skip QLX-16384 heavy lattice tier.")
    parser.add_argument("--compare", action="store_true", help="Run Native C99 vs Pure-Python comparative benchmarks.")
    parser.add_argument("--isolate", action="store_true", help="Isolate Native & Pure-Python passes in separate processes for exact Peak RSS.")
    parser.add_argument("--mode", choices=["auto", "native", "pure"], default="auto", help="Backend mode for single-pass runs.")
    parser.add_argument("--suites", default="", help="Optional comma-separated subset of suite IDs.")
    parser.add_argument("--emit-json-stdout", action="store_true", help="Print raw JSON to stdout without writing benchmark_results.json.")
    parser.add_argument("--output", default=str(Path(__file__).resolve().parent / "benchmark_results.json"), help="Output JSON file path.")
    args = parser.parse_args(argv)

    suite_filter = [s.strip() for s in args.suites.split(",") if s.strip()] or None
    include_heavy = not args.no_heavy

    if args.compare:
        results = run_comparative_benchmarks(
            include_heavy=include_heavy,
            suite_ids=suite_filter,
            isolate_processes=args.isolate,
        )
        if args.emit_json_stdout:
            print(json.dumps(results, indent=2))
            return 0
        print(format_comparative_markdown_table(results))
    else:
        native_flag: Optional[bool] = None
        if args.mode == "native":
            native_flag = True
        elif args.mode == "pure":
            native_flag = False
        results = run_benchmarks(include_heavy=include_heavy, native_enabled=native_flag, suite_ids=suite_filter)
        if args.emit_json_stdout:
            print(json.dumps(results, indent=2))
            return 0
        print(format_markdown_table(results))

    out_json = Path(args.output)
    out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
