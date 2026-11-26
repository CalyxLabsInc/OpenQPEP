# OpenQPEP Official Release 1.2.9 (v1.2.9)
"""
Family 5 of Calyx Sovereign-Pentad (CSP-Omega): Stateless Hash-Based Signature Hypertree
(QHS-512: WOTS+ Winternitz Chains + XMSS Merkle Authentication Path over 24-round qSponge-512).
Zero algebraic structure, zero trapdoors—unforgeability reduces strictly to Keccak-f[1600] one-wayness.

v1.2.9 Native C99 / SIMD Acceleration:
  - Transparently dispatches WOTS+ chaining, 4-way SIMD Keccak-f[1600] leaf generation, O(h)-stack
    TreeHash, and signing/verification to `libopenqpep` (`qhs_c.c`) while preserving 100% bit-exact
    Pure-Python fallback under `OPENQPEP_DISABLE_NATIVE=1`.
  - Automatically parallelizes high-height hypertrees (`height >= 6`) across multiple CPU cores
    using GIL-released C99 `openqpep_qhs_treehash_subtree` + `openqpep_qhs_fold_subtrees`.
"""
import concurrent.futures
import os
import struct
from typing import List, Optional, Tuple

from ..exceptions import QPEPFaultGuardError
from ..native.loader import (
    is_native_available,
    native_qhs_fold_subtrees,
    native_qhs_keygen_from_seeds,
    native_qhs_sign_core,
    native_qhs_treehash_subtree,
    native_qhs_verify,
    native_qhs_wots_chain,
    native_qhs_wots_pk_from_sk_seed,
    native_qhs_wots_sign,
)
from ..primitives.consttime import ct_eq
from ..primitives.qsponge import qsponge_512, qsponge_var
from ..primitives.zeroize import SecretBuffer

WOTS_W = 16       # 4-bit Winternitz digits (0..15)
WOTS_N = 32       # 256-bit chain nodes (derived from qSponge-512)
WOTS_LEN1 = 64    # 256 bits / 4 bits
WOTS_LEN2 = 3     # checksum digits
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2  # 67 chains
QHS_MAX_HEIGHT = 20


def _validate_height(height: int) -> int:
    if isinstance(height, bool) or not isinstance(height, int) or height < 0 or height > QHS_MAX_HEIGHT:
        raise ValueError(f"QHS-512 tree height must be an integer in 0..{QHS_MAX_HEIGHT}, got {height!r}.")
    return height


def _chain(x: bytes, start: int, steps: int, pub_seed: bytes, leaf_idx: int, chain_idx: int) -> bytes:
    nat = native_qhs_wots_chain(x, start, steps, pub_seed, leaf_idx, chain_idx)
    if nat is not None:
        return nat
    cur = x
    for s in range(start, start + steps):
        cur = qsponge_512(
            b"CALYX-QHS-CHAIN|" + pub_seed + struct.pack(">IHB", leaf_idx, chain_idx, s) + cur
        )[:WOTS_N]
    return cur


def _msg_to_base_w(msg_digest32: bytes) -> List[int]:
    digits: List[int] = []
    for b in msg_digest32:
        digits.append((b >> 4) & 0x0F)
        digits.append(b & 0x0F)
    csum = sum((WOTS_W - 1) - d for d in digits)
    digits.append((csum >> 8) & 0x0F)
    digits.append((csum >> 4) & 0x0F)
    digits.append(csum & 0x0F)
    return digits


def _wots_pk_from_sk_seed(sk_seed: bytes, pub_seed: bytes, leaf_idx: int) -> bytes:
    nat = native_qhs_wots_pk_from_sk_seed(sk_seed, pub_seed, leaf_idx)
    if nat is not None:
        return nat
    nodes = []
    for i in range(WOTS_LEN):
        sk_i = qsponge_var(b"CALYX-QHS-WOTS-SK|" + sk_seed + struct.pack(">IH", leaf_idx, i), WOTS_N)
        nodes.append(_chain(sk_i, 0, WOTS_W - 1, pub_seed, leaf_idx, i))
    return qsponge_512(b"CALYX-QHS-WOTS-PK|" + pub_seed + struct.pack(">I", leaf_idx) + b"".join(nodes))[:WOTS_N]


def _parallel_treehash_native(
    sk_seed: bytes,
    pub_seed: bytes,
    height: int,
    *,
    target_leaf: int = 0,
    capture_auth: bool = False,
    workers: int = 0,
) -> Optional[Tuple[bytes, bytes]]:
    """
    Parallelizes Merkle tree construction across CPU cores using GIL-released C99
    `openqpep_qhs_treehash_subtree` + `openqpep_qhs_fold_subtrees`.
    """
    if not is_native_available():
        return None
    cpu_cnt = workers if workers > 0 else (os.cpu_count() or 1)
    if height < 6 or cpu_cnt <= 1 or os.environ.get("OPENQPEP_DETERMINISTIC_KAT") == "1":
        return native_qhs_treehash_subtree(
            sk_seed,
            pub_seed,
            0,
            height,
            target_leaf=target_leaf,
            capture_auth=capture_auth,
        )

    top_h = min(height - 3, 4)
    sub_h = height - top_h
    num_subtrees = 1 << top_h
    sub_size = 1 << sub_h
    target_sub = target_leaf >> sub_h
    max_workers = min(cpu_cnt, num_subtrees)

    def _run_sub(sidx: int) -> Tuple[int, bytes, bytes]:
        want_auth = capture_auth and (sidx == target_sub)
        res = native_qhs_treehash_subtree(
            sk_seed,
            pub_seed,
            sidx * sub_size,
            sub_h,
            target_leaf=target_leaf if want_auth else 0,
            capture_auth=want_auth,
        )
        if res is None:
            raise RuntimeError("Native QHS subtree evaluation unexpectedly unavailable.")
        return sidx, res[0], res[1]

    roots: List[bytes] = [b""] * num_subtrees
    sub_auth = b""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_run_sub, sidx) for sidx in range(num_subtrees)]
        for fut in futures:
            sidx, sroot, sauth = fut.result()
            roots[sidx] = sroot
            if capture_auth and sidx == target_sub:
                sub_auth = sauth

    folded = native_qhs_fold_subtrees(
        pub_seed,
        b"".join(roots),
        top_h,
        target_subtree_idx=target_sub if capture_auth else 0,
        capture_auth=capture_auth,
    )
    if folded is None:
        return None
    final_root, top_auth = folded
    return final_root, (sub_auth + top_auth if capture_auth else b"")


class QHS512HypertreeEngine:
    """
    Stateless WOTS+ + XMSS Merkle Hypertree Signature Engine over qSponge-512 (QHS-512).
    Default tree height h=4 (16 leaves) in pure-Python reference mode for instant execution;
    scales smoothly to high-height hypertrees under native C99 4-way SIMD + multi-core TreeHash.
    """

    @staticmethod
    def keygen(height: int = 4, *, workers: int = 0) -> Tuple[bytes, bytes]:
        h = _validate_height(height)
        sk_seed = os.urandom(32)
        pub_seed = os.urandom(32)

        with SecretBuffer(sk_seed) as sk_buf:
            sk_raw = sk_buf.as_bytes()
            if is_native_available():
                if h >= 6 and os.environ.get("OPENQPEP_DETERMINISTIC_KAT") != "1" and (workers > 1 or (workers == 0 and (os.cpu_count() or 1) > 1)):
                    par = _parallel_treehash_native(sk_raw, pub_seed, h, workers=workers)
                    if par is not None:
                        root = par[0]
                        pk = struct.pack(">B", h) + pub_seed + root
                        sk = struct.pack(">B", h) + sk_raw + pub_seed + root
                        return pk, sk
                nat_kp = native_qhs_keygen_from_seeds(h, sk_raw, pub_seed)
                if nat_kp is not None:
                    return nat_kp

            num_leaves = 1 << h
            leaves = [_wots_pk_from_sk_seed(sk_raw, pub_seed, idx) for idx in range(num_leaves)]

            cur = leaves
            while len(cur) > 1:
                nxt = []
                for i in range(0, len(cur), 2):
                    nxt.append(qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur[i] + cur[i + 1])[:WOTS_N])
                cur = nxt
            root = cur[0]
            pk = struct.pack(">B", h) + pub_seed + root
            sk = struct.pack(">B", h) + sk_raw + pub_seed + root
            return pk, sk

    @staticmethod
    def sign(sk: bytes, message: bytes, *, hedged: bool = True, rnd: Optional[bytes] = None, workers: int = 0) -> bytes:
        """
        Signs `message` with QHS-512 WOTS+ + XMSS Hypertree:
          - Default `hedged=True` hedges `opt_rand` over (sk_seed || os.urandom(32) || pub_seed || root || message)
            so weak/stuck RNGs cannot cause nonce reuse across distinct messages.
          - Enforces mandatory Verify-Before-Emit Fault-Guard (`QPEPFaultGuardError`).
        """
        if not isinstance(sk, (bytes, bytearray, memoryview)) or len(sk) != 97:
            raise ValueError("Invalid QHS-512 secret key length (expected 97 bytes).")
        if rnd is not None:
            if not isinstance(rnd, (bytes, bytearray, memoryview)) or len(rnd) != 32:
                raise ValueError("QHS-512 hedged signing rnd must be exactly 32 bytes.")

        with SecretBuffer(sk) as sk_buf:
            with sk_buf.view() as mv:
                height = _validate_height(int(mv[0]))
                sk_seed = bytes(mv[1:33])
                pub_seed = bytes(mv[33:65])
                root = bytes(mv[65:97])

            num_leaves = 1 << height
            sig_out: Optional[bytes] = None

            if hedged:
                with SecretBuffer(os.urandom(32) if rnd is None else bytes(rnd)) as rnd_buf:
                    rnd_raw = rnd_buf.as_bytes()
                    if is_native_available() and (
                        height < 6
                        or os.environ.get("OPENQPEP_DETERMINISTIC_KAT") == "1"
                        or (workers == 1)
                        or (workers == 0 and (os.cpu_count() or 1) <= 1)
                    ):
                        nat_sig = native_qhs_sign_core(sk_buf.as_bytes(), message, hedged=True, rnd32=rnd_raw)
                        if nat_sig is not None:
                            rc, sig_bytes = nat_sig
                            if rc == -5:
                                raise QPEPFaultGuardError(
                                    "QHS-512 Hypertree Fault-Injection Guard triggered: signature failed internal verification."
                                )
                            sig_out = sig_bytes
                    if sig_out is None:
                        opt_rand = qsponge_512(
                            b"CALYX-QHS-HEDGE-v1.1.4|" + sk_seed + rnd_raw + pub_seed + root + message
                        )[:32]
            else:
                if is_native_available() and (
                    height < 6
                    or os.environ.get("OPENQPEP_DETERMINISTIC_KAT") == "1"
                    or (workers == 1)
                    or (workers == 0 and (os.cpu_count() or 1) <= 1)
                ):
                    nat_sig = native_qhs_sign_core(sk_buf.as_bytes(), message, hedged=False)
                    if nat_sig is not None:
                        rc, sig_bytes = nat_sig
                        if rc == -5:
                            raise QPEPFaultGuardError(
                                "QHS-512 Hypertree Fault-Injection Guard triggered: signature failed internal verification."
                            )
                        sig_out = sig_bytes
                if sig_out is None:
                    opt_rand = qsponge_512(b"CALYX-QHS-DET-v1.1.4|" + sk_seed + pub_seed + root + message)[:32]

            if sig_out is None:
                # Stateless hedged leaf selection + message digest
                h_all = qsponge_512(b"CALYX-QHS-MSG|" + opt_rand + pub_seed + root + message)
                msg_digest32 = h_all[:32]
                leaf_idx = int.from_bytes(h_all[32:36], "big") % num_leaves

                # WOTS+ signature on leaf_idx (native C99 or Pure-Python fallback)
                nat_wots = native_qhs_wots_sign(sk_seed, pub_seed, leaf_idx, msg_digest32)
                if nat_wots is not None:
                    wots_sig = nat_wots
                else:
                    digits = _msg_to_base_w(msg_digest32)
                    wots_sig_parts = []
                    for i, d in enumerate(digits):
                        sk_i = qsponge_var(b"CALYX-QHS-WOTS-SK|" + sk_seed + struct.pack(">IH", leaf_idx, i), WOTS_N)
                        wots_sig_parts.append(_chain(sk_i, 0, d, pub_seed, leaf_idx, i))
                    wots_sig = b"".join(wots_sig_parts)

                # Build XMSS Merkle authentication path (parallel C99 TreeHash or Pure-Python fallback)
                par_tree = _parallel_treehash_native(
                    sk_seed,
                    pub_seed,
                    height,
                    target_leaf=leaf_idx,
                    capture_auth=True,
                    workers=workers,
                )
                if par_tree is not None:
                    auth_bytes = par_tree[1]
                else:
                    leaves = [_wots_pk_from_sk_seed(sk_seed, pub_seed, idx) for idx in range(num_leaves)]
                    auth_path = []
                    cur = leaves
                    idx = leaf_idx
                    while len(cur) > 1:
                        sib = cur[idx ^ 1]
                        auth_path.append(sib)
                        nxt = []
                        for i in range(0, len(cur), 2):
                            nxt.append(qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur[i] + cur[i + 1])[:WOTS_N])
                        cur = nxt
                        idx //= 2
                    auth_bytes = b"".join(auth_path)

                sig_out = struct.pack(">I", leaf_idx) + opt_rand + wots_sig + auth_bytes

        pk_rebuilt = struct.pack(">B", height) + pub_seed + root
        if not QHS512HypertreeEngine.verify(pk_rebuilt, message, sig_out):
            raise QPEPFaultGuardError("QHS-512 Hypertree Fault-Injection Guard triggered: signature failed internal verification.")
        return sig_out

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(pk, (bytes, bytearray, memoryview)) or len(pk) != 65:
            return False
        if not isinstance(signature, (bytes, bytearray, memoryview)):
            return False
        nat_ok = native_qhs_verify(pk, message, signature)
        if nat_ok is not None:
            return nat_ok

        height = pk[0]
        if height > QHS_MAX_HEIGHT:
            return False
        pub_seed = bytes(pk[1:33])
        expected_root = bytes(pk[33:65])
        expected_len = 4 + 32 + (WOTS_LEN * WOTS_N) + (height * WOTS_N)
        if len(signature) != expected_len:
            return False

        sig_b = bytes(signature)
        leaf_idx = struct.unpack(">I", sig_b[:4])[0]
        if leaf_idx >= (1 << height):
            return False
        opt_rand = sig_b[4:36]
        wots_sig = sig_b[36 : 36 + WOTS_LEN * WOTS_N]
        auth_bytes = sig_b[36 + WOTS_LEN * WOTS_N :]

        h_all = qsponge_512(b"CALYX-QHS-MSG|" + opt_rand + pub_seed + expected_root + message)
        msg_digest32 = h_all[:32]
        digits = _msg_to_base_w(msg_digest32)

        # Complete WOTS+ chains to recover leaf public key
        nodes = []
        for i, d in enumerate(digits):
            sig_i = wots_sig[i * WOTS_N : (i + 1) * WOTS_N]
            nodes.append(_chain(sig_i, d, (WOTS_W - 1) - d, pub_seed, leaf_idx, i))
        cur = qsponge_512(b"CALYX-QHS-WOTS-PK|" + pub_seed + struct.pack(">I", leaf_idx) + b"".join(nodes))[:WOTS_N]

        # Walk XMSS Merkle authentication path up to root
        idx = leaf_idx
        for lvl in range(height):
            sib = auth_bytes[lvl * WOTS_N : (lvl + 1) * WOTS_N]
            if idx % 2 == 0:
                cur = qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + cur + sib)[:WOTS_N]
            else:
                cur = qsponge_512(b"CALYX-QHS-NODE|" + pub_seed + sib + cur)[:WOTS_N]
            idx //= 2

        return ct_eq(cur, expected_root)
