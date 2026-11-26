"""
OpenQPEP Hardware Auto-Tuner & Memory-Ceiling Guard for QPKD-Argon2id (Official Release 1.2.9 / kdf_version: 4).

Calibrates memory-hard RFC 9106 Argon2id parameters (m_kib, t_cost, p_lanes) for:
  - Standard devices (QLX-768 .. QLX-4096): 64 MiB, t=3, p<=4
  - Calyx Hyper-Tesseract flagship hardware (QLX-16384): 256 MiB, t=4, p<=4 (when RAM >= 4 GiB)
  - Low-RAM constrained environments (< 1.5 GiB usable RAM): 32 MiB, t=3, p<=2

v1.2.9 Hardening:
  - Container/cgroup-aware RAM detection (/sys/fs/cgroup memory.max & memory.limit_in_bytes).
  - Explicit memory-ceiling safety bounds (compute_safe_memory_ceiling_kib, enforce_kdf_memory_ceiling)
    preventing OOM kills on constrained hosts and rejecting malicious .qpkrf memory-bomb parameters.
  - Multi-sample calibrated per-device KDF benchmark reporting (benchmark_kdf & calibrate_kdf_for_device)
    with throughput telemetry (MiB/s) and iteration calibration without ever lowering security floors.
"""
import os
import statistics
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..exceptions import QPEPSuiteError
from ..primitives.zeroize import SecretBuffer

MIN_SAFE_KDF_MEMORY_KIB = 32768         # 32 MiB standard auto-tuner security floor
LOW_MEM_FLOOR_KIB = 8192                # 8 MiB absolute floor for ultra-constrained <= 128 MiB hosts
MAX_SAFE_KDF_MEMORY_KIB = 524288        # 512 MiB auto-tuner ceiling
HARD_CEILING_KDF_MEMORY_KIB = 1048576   # 1 GiB absolute .qpkrf unlock ceiling (OOM-bomb defense)
MAX_RAM_FRACTION = 0.25                 # Never auto-allocate more than 25% of detected device RAM
MAX_CALIBRATED_TIME_COST = 16


@dataclass(frozen=True)
class KDFHardwareProfile:
    profile_name: str
    m_kib: int
    t_cost: int
    p_lanes: int
    detected_ram_mib: int
    detected_cpus: int
    memory_ceiling_kib: int = MAX_SAFE_KDF_MEMORY_KIB
    clamped_by_ceiling: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "hardware_profile": self.profile_name,
            "m_kib": self.m_kib,
            "t_cost": self.t_cost,
            "p_lanes": self.p_lanes,
            "detected_ram_mib": self.detected_ram_mib,
            "detected_cpus": self.detected_cpus,
            "memory_ceiling_kib": self.memory_ceiling_kib,
            "clamped_by_ceiling": self.clamped_by_ceiling,
        }


def detect_cgroup_ram_limit_mib() -> Optional[int]:
    """
    Inspects Linux cgroup v2 (/sys/fs/cgroup/memory.max) or cgroup v1 memory limits so
    containerized/Android deployments never exceed their real RAM quota.
    """
    candidates = (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    )
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
            if not raw or raw == "max":
                continue
            limit_bytes = int(raw)
            # Ignore kernel "unlimited" sentinel values (>= 1 PiB)
            if 0 < limit_bytes < (1 << 50):
                return max(64, limit_bytes // (1024 * 1024))
        except (OSError, ValueError, TypeError):
            continue
    return None


def _detect_host_physical_ram_mib() -> int:
    try:
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if isinstance(pages, int) and isinstance(page_size, int) and pages > 0 and page_size > 0:
                return max(64, (pages * page_size) // (1024 * 1024))
    except (OSError, ValueError, AttributeError):
        pass
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return max(64, kb // 1024)
    except (OSError, ValueError, AttributeError):
        pass
    return 4096


def detect_system_ram_mib() -> int:
    """Returns effective usable system RAM in MiB, honoring container cgroup ceilings."""
    phys_mib = _detect_host_physical_ram_mib()
    cg_mib = detect_cgroup_ram_limit_mib()
    if cg_mib is not None and cg_mib < phys_mib:
        return max(64, cg_mib)
    return max(512, phys_mib)


def detect_available_ram_mib() -> int:
    """Returns currently available RAM in MiB (bounded by cgroup limit if applicable)."""
    avail_mib: Optional[int] = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    avail_mib = max(64, kb // 1024)
                    break
    except (OSError, ValueError, AttributeError):
        avail_mib = None

    total_mib = detect_system_ram_mib()
    if avail_mib is None:
        return total_mib
    return min(avail_mib, total_mib)


def compute_safe_memory_ceiling_kib(
    ram_mib: Optional[int] = None,
    *,
    ram_fraction: float = MAX_RAM_FRACTION,
    hard_ceiling_kib: int = MAX_SAFE_KDF_MEMORY_KIB,
) -> int:
    """
    Computes the maximum safe Argon2id memory budget (in KiB) for a host with `ram_mib` MiB RAM:
      - Caps at `ram_fraction` (default 25%) of detected RAM to avoid OS/Android OOM kills.
      - Caps at `hard_ceiling_kib` (default 512 MiB for auto-tuning, up to 1 GiB hard limit).
      - Rounds down to a 1024 KiB (1 MiB) boundary while preserving at least LOW_MEM_FLOOR_KIB (8 MiB).
    """
    if isinstance(ram_mib, bool):
        raise QPEPSuiteError("ram_mib must be an integer or None, not bool.")
    if ram_mib is not None and (not isinstance(ram_mib, int) or ram_mib <= 0):
        raise QPEPSuiteError("ram_mib must be a positive integer.")
    if isinstance(hard_ceiling_kib, bool) or not isinstance(hard_ceiling_kib, int) or hard_ceiling_kib < 8:
        raise QPEPSuiteError("hard_ceiling_kib must be an integer >= 8 KiB.")
    if not isinstance(ram_fraction, (int, float)) or isinstance(ram_fraction, bool) or not (0.05 <= float(ram_fraction) <= 0.75):
        raise QPEPSuiteError("ram_fraction must be between 0.05 and 0.75.")

    eff_ram = ram_mib if ram_mib is not None else detect_system_ram_mib()
    fraction_kib = int(eff_ram * 1024 * float(ram_fraction))
    if fraction_kib >= 1024:
        fraction_kib = (fraction_kib // 1024) * 1024
    floor_kib = min(LOW_MEM_FLOOR_KIB, hard_ceiling_kib)
    return max(floor_kib, min(fraction_kib, hard_ceiling_kib))


def enforce_kdf_memory_ceiling(
    m_kib: int,
    *,
    ram_mib: Optional[int] = None,
    max_memory_kib: Optional[int] = None,
    enforce_ram_fraction: bool = False,
) -> int:
    """
    Validates that a requested Argon2id memory_cost (`m_kib`) does not violate the hard
    anti-OOM ceiling (1 GiB default), caller-supplied `max_memory_kib`, or optional host RAM fraction.
    """
    if isinstance(m_kib, bool) or not isinstance(m_kib, int) or m_kib <= 0:
        raise QPEPSuiteError("Argon2id m_kib must be a positive integer.")

    ceiling = HARD_CEILING_KDF_MEMORY_KIB
    if max_memory_kib is not None:
        if isinstance(max_memory_kib, bool) or not isinstance(max_memory_kib, int) or max_memory_kib < 8:
            raise QPEPSuiteError("max_memory_kib must be an integer >= 8 KiB.")
        ceiling = min(ceiling, max_memory_kib)

    if enforce_ram_fraction:
        ram_cap = compute_safe_memory_ceiling_kib(ram_mib, hard_ceiling_kib=ceiling)
        ceiling = min(ceiling, ram_cap)

    if m_kib > ceiling:
        raise QPEPSuiteError(
            f"Requested QPKD-Argon2id memory cost ({m_kib} KiB) exceeds safety ceiling ({ceiling} KiB)."
        )
    return m_kib


def select_kdf_profile(
    qlx_tier: str = "QLX-4096",
    override_ram_mib: int = 0,
    *,
    max_memory_kib: Optional[int] = None,
    override_cpus: int = 0,
) -> KDFHardwareProfile:
    """
    Auto-tunes QPKD-Argon2id parameters per OpenQPEP Official Release specification with
    memory-ceiling safety enforcement:
      - Calyx Hyper-Tesseract (QLX-16384): m = 262,144 KiB (256 MiB), t = 4, p <= 4 (when RAM >= 4 GiB)
      - Standard devices (QLX-768 .. QLX-4096): m = 65,536 KiB (64 MiB), t = 3, p <= 4
      - Low-RAM constrained devices (< 1.5 GiB usable RAM): m = 32,768 KiB (32 MiB), t = 3, p <= 2
      - Memory-ceiling guard: clamps m_kib <= min(25% RAM, max_memory_kib, 512 MiB) and compensates
        with +1 iteration (up to 8) if memory clamping occurs.
    """
    if isinstance(override_ram_mib, bool) or not isinstance(override_ram_mib, int) or override_ram_mib < 0:
        raise QPEPSuiteError("override_ram_mib must be a non-negative integer.")
    if isinstance(override_cpus, bool) or not isinstance(override_cpus, int) or override_cpus < 0:
        raise QPEPSuiteError("override_cpus must be a non-negative integer.")
    if max_memory_kib is not None and (
        isinstance(max_memory_kib, bool) or not isinstance(max_memory_kib, int) or max_memory_kib < 8
    ):
        raise QPEPSuiteError("max_memory_kib must be an integer >= 8 KiB.")

    ram_mib = override_ram_mib if override_ram_mib > 0 else detect_system_ram_mib()
    cpus = override_cpus if override_cpus > 0 else max(1, os.cpu_count() or 2)
    is_tesseract = "16384" in str(qlx_tier) or "Tesseract" in str(qlx_tier)

    ram_ceiling_kib = compute_safe_memory_ceiling_kib(ram_mib, hard_ceiling_kib=MAX_SAFE_KDF_MEMORY_KIB)
    effective_ceiling_kib = min(ram_ceiling_kib, max_memory_kib) if max_memory_kib is not None else ram_ceiling_kib

    if is_tesseract and ram_mib >= 4096:
        profile_name = "hyper_tesseract_256m"
        desired_m_kib = 262144
        desired_t_cost = 4
        p_lanes = min(4, max(1, cpus))
    elif ram_mib < 1536:
        profile_name = "constrained_32m"
        desired_m_kib = 32768
        desired_t_cost = 3
        p_lanes = min(2, max(1, cpus))
    else:
        profile_name = "standard_64m"
        desired_m_kib = 65536
        desired_t_cost = 3
        p_lanes = min(4, max(1, cpus))

    clamped = False
    m_kib = desired_m_kib
    t_cost = desired_t_cost
    if m_kib > effective_ceiling_kib:
        # Ensure RFC 9106 m_kib >= 8 * p_lanes and aligned to 4 * p_lanes
        if effective_ceiling_kib < 8 * p_lanes:
            p_lanes = max(1, min(p_lanes, effective_ceiling_kib // 8))
        aligned = (effective_ceiling_kib // (4 * p_lanes)) * (4 * p_lanes)
        m_kib = max(8 * p_lanes, aligned)
        t_cost = min(8, desired_t_cost + 1)
        profile_name = f"{profile_name}_capped"
        clamped = True

    return KDFHardwareProfile(
        profile_name=profile_name,
        m_kib=m_kib,
        t_cost=t_cost,
        p_lanes=p_lanes,
        detected_ram_mib=ram_mib,
        detected_cpus=cpus,
        memory_ceiling_kib=effective_ceiling_kib,
        clamped_by_ceiling=clamped,
    )


def benchmark_kdf(
    qlx_tier: str = "QLX-4096",
    *,
    samples: int = 1,
    target_ms: float = 250.0,
    override_ram_mib: int = 0,
    max_memory_kib: Optional[int] = None,
) -> Dict[str, object]:
    """
    Benchmarks QPKD-Argon2id (kdf_version: 4) derivation latency on the current hardware and
    produces calibrated per-device telemetry (latency stats, MiB/s throughput, memory ceiling,
    and recommended iteration count for target_ms without lowering profile security floors).
    """
    from .argon2id_cascade import derive_qpkrf_keys_v4, get_available_kdf_backends

    if isinstance(samples, bool) or not isinstance(samples, int) or not (1 <= samples <= 10):
        raise QPEPSuiteError("benchmark_kdf samples must be an integer between 1 and 10.")
    if isinstance(target_ms, bool) or not isinstance(target_ms, (int, float)) or not (10.0 <= float(target_ms) <= 30000.0):
        raise QPEPSuiteError("benchmark_kdf target_ms must be between 10.0 and 30000.0 ms.")

    profile = select_kdf_profile(
        qlx_tier,
        override_ram_mib=override_ram_mib,
        max_memory_kib=max_memory_kib,
    )
    salt = b"\x42" * 32
    timings_ms: List[float] = []
    last_params: Dict[str, object] = {}

    kdf_spec = {
        "m_kib": profile.m_kib,
        "t_cost": profile.t_cost,
        "p_lanes": profile.p_lanes,
        "hardware_profile": profile.profile_name,
    }
    for _ in range(samples):
        t0 = time.perf_counter()
        k1, k2, kmac, params = derive_qpkrf_keys_v4(
            "Calyx!@#$_2026BenchAa99",
            salt,
            qlx_tier=qlx_tier,
            kdf_params=kdf_spec,
        )
        dt_ms = (time.perf_counter() - t0) * 1000.0
        with SecretBuffer(k1), SecretBuffer(k2), SecretBuffer(kmac):
            pass
        timings_ms.append(dt_ms)
        last_params = params

    median_ms = round(float(statistics.median(timings_ms)), 2)
    min_ms = round(float(min(timings_ms)), 2)
    max_ms = round(float(max(timings_ms)), 2)

    m_mib = float(profile.m_kib) / 1024.0
    total_mib_scanned = m_mib * float(profile.t_cost)
    mib_per_sec = round(total_mib_scanned / max(median_ms / 1000.0, 1e-6), 2)

    # Calibrate recommended_t_cost to meet target_ms while NEVER dropping below profile.t_cost
    ms_per_iter = max(median_ms / max(1, profile.t_cost), 1e-3)
    scaled_t = int(round(float(target_ms) / ms_per_iter))
    recommended_t = max(profile.t_cost, min(MAX_CALIBRATED_TIME_COST, scaled_t))

    return {
        "qlx_tier": qlx_tier,
        "kdf_version": last_params["kdf_version"],
        "profile": profile.profile_name,
        "backend": last_params["backend"],
        "available_backends": get_available_kdf_backends(),
        "m_kib": last_params["m_kib"],
        "t_cost": last_params["t_cost"],
        "p_lanes": last_params["p_lanes"],
        "elapsed_ms": median_ms,
        "samples": samples,
        "min_ms": min_ms,
        "median_ms": median_ms,
        "max_ms": max_ms,
        "mib_per_sec": mib_per_sec,
        "detected_ram_mib": profile.detected_ram_mib,
        "detected_cpus": profile.detected_cpus,
        "memory_ceiling_kib": profile.memory_ceiling_kib,
        "clamped_by_ceiling": profile.clamped_by_ceiling,
        "target_ms": float(target_ms),
        "recommended_t_cost": recommended_t,
    }


def calibrate_kdf_for_device(
    qlx_tier: str = "QLX-4096",
    *,
    target_ms: float = 250.0,
    samples: int = 1,
    override_ram_mib: int = 0,
    max_memory_kib: Optional[int] = None,
) -> Dict[str, object]:
    """
    Runs a live hardware calibration probe and returns a ready-to-use `calibrated_kdf_params`
    dictionary alongside full per-device benchmark diagnostics.
    """
    bench = benchmark_kdf(
        qlx_tier=qlx_tier,
        samples=samples,
        target_ms=target_ms,
        override_ram_mib=override_ram_mib,
        max_memory_kib=max_memory_kib,
    )
    calibrated_params = {
        "hardware_profile": f"{bench['profile']}_calibrated",
        "m_kib": int(bench["m_kib"]),
        "t_cost": int(bench["recommended_t_cost"]),
        "p_lanes": int(bench["p_lanes"]),
        "backend": str(bench["backend"]),
    }
    return {
        "benchmark": bench,
        "calibrated_kdf_params": calibrated_params,
    }
