"""OpenQPEP Adversarial Security Audit Suite: Wire Fuzzer, Attack Simulator, Timing Audit & 5-Language Interop Matrix (Official Release 1.2.6)."""
from .fuzz_wire import fuzz_wire_parsers, validate_webview_bridge_command
from .attack_sim import (
    simulate_fo_cca2_malleability,
    simulate_qvs_fault_injection,
    simulate_stream_truncation_and_reorder,
    simulate_suite_downgrade_attack,
    simulate_ed448_small_order_and_x448_low_order_attack,
    simulate_non_canonical_base64_and_armor_dos_attack,
    simulate_json_duplicate_key_and_depth_bomb_attack,
    simulate_replay_and_zip_bomb_attack,
    simulate_multi_suite_fault_injection_attack,
    run_all_attack_simulations,
)
from .timing_audit import (
    welch_t_statistic,
    audit_ct_cmov_timing,
    audit_qlx_decaps_timing,
    run_full_constant_time_audit,
)
from .interop_matrix import run_cross_language_interop_matrix

__all__ = [
    "fuzz_wire_parsers",
    "validate_webview_bridge_command",
    "simulate_fo_cca2_malleability",
    "simulate_qvs_fault_injection",
    "simulate_stream_truncation_and_reorder",
    "simulate_suite_downgrade_attack",
    "simulate_ed448_small_order_and_x448_low_order_attack",
    "simulate_non_canonical_base64_and_armor_dos_attack",
    "simulate_json_duplicate_key_and_depth_bomb_attack",
    "simulate_replay_and_zip_bomb_attack",
    "simulate_multi_suite_fault_injection_attack",
    "run_all_attack_simulations",
    "welch_t_statistic",
    "audit_ct_cmov_timing",
    "audit_qlx_decaps_timing",
    "run_full_constant_time_audit",
    "run_cross_language_interop_matrix",
]
