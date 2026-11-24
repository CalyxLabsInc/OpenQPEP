"""
OS Memory Locking (mlock / MADV_DONTDUMP / PR_SET_DUMPABLE), Guard-Page Secret Arenas,
and Active Compiler-Barrier Zeroization (Official Release 1.1.4 / v1.1.4).

Security Guarantees:
  1. Compiler-Barrier Zeroization: Overwrites secret memory using C99 `openqpep_explicit_bzero`
     (volatile store + compiler memory fence) with `ctypes.memset` fallback, plus constant-time
     verification via `openqpep_is_zeroed`.
  2. Reference-Counted Page Locking (`SecretBuffer`): Locks secret `bytearray` memory pages in RAM
     via OS `mlock()` (with thread-safe per-page reference counting so overlapping buffers on a
     shared heap page never prematurely unlock another live secret) and pins the backing buffer to
     prevent silent `bytearray` heap relocation. Gracefully degrades under tight `RLIMIT_MEMLOCK`.
  3. Dedicated Guard-Page & Core-Dump-Excluded Arenas (`LockedMemoryBuffer`): Allocates private
     POSIX `mmap()` pages bracketed by `PROT_NONE` guard pages, applies both `mlock()` and Linux
     `madvise(MADV_DONTDUMP)` exclusively to the secret pages, verifies full-page zeroization on
     wipe, and immediately `munlock()` + `munmap()`s the arena.
  4. Opt-In Process Hardening (`disable_core_dumps`, `harden_process_memory`): Zeroes `RLIMIT_CORE`
     and sets Linux `prctl(PR_SET_DUMPABLE, 0)`.
"""
import contextlib
import ctypes
import ctypes.util
import mmap as _mmap_mod
import os
import sys
import threading
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

try:
    import resource as _resource_mod
except ImportError:
    _resource_mod = None  # type: ignore[assignment]


def _detect_page_size() -> int:
    try:
        if hasattr(os, "sysconf"):
            ps = int(os.sysconf("SC_PAGESIZE"))
            if ps > 0 and (ps & (ps - 1)) == 0:
                return ps
    except (ValueError, OSError, AttributeError):
        pass
    ps_mmap = getattr(_mmap_mod, "PAGESIZE", 4096)
    return int(ps_mmap) if ps_mmap > 0 else 4096


PAGE_SIZE: int = _detect_page_size()

_IS_POSIX: bool = os.name == "posix"
_IS_LINUX: bool = sys.platform.startswith("linux")

# POSIX / Linux memory-protection constants
_PROT_NONE: int = getattr(_mmap_mod, "PROT_NONE", 0x0)
_PROT_READ: int = getattr(_mmap_mod, "PROT_READ", 0x1)
_PROT_WRITE: int = getattr(_mmap_mod, "PROT_WRITE", 0x2)
_MAP_PRIVATE: int = getattr(_mmap_mod, "MAP_PRIVATE", 0x02)
_MAP_ANON: int = getattr(
    _mmap_mod,
    "MAP_ANONYMOUS",
    getattr(_mmap_mod, "MAP_ANON", 0x20 if _IS_LINUX else 0x1000),
)
_MAP_FAILED: int = ctypes.c_void_p(-1).value or ((1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1)

# Linux kernel ABI constants (<sys/mman.h> and <sys/prctl.h>)
_MADV_DONTDUMP: int = 16
_PR_GET_DUMPABLE: int = 3
_PR_SET_DUMPABLE: int = 4

_LIBC_LOCK = threading.Lock()
_LIBC_INITIALIZED: bool = False
_LIBC: Optional[ctypes.CDLL] = None
_FN_MLOCK: Any = None
_FN_MUNLOCK: Any = None
_FN_MADVISE: Any = None
_FN_PRCTL: Any = None
_FN_MMAP: Any = None
_FN_MUNMAP: Any = None
_FN_MPROTECT: Any = None


def _init_libc() -> Optional[ctypes.CDLL]:
    global _LIBC_INITIALIZED, _LIBC
    global _FN_MLOCK, _FN_MUNLOCK, _FN_MADVISE, _FN_PRCTL, _FN_MMAP, _FN_MUNMAP, _FN_MPROTECT
    if _LIBC_INITIALIZED:
        return _LIBC
    with _LIBC_LOCK:
        if _LIBC_INITIALIZED:
            return _LIBC
        _LIBC_INITIALIZED = True
        if not _IS_POSIX:
            return None

        libc: Optional[ctypes.CDLL] = None
        candidates: List[Optional[str]] = [None]
        found_c = ctypes.util.find_library("c")
        if found_c:
            candidates.append(found_c)
        for cand in candidates:
            try:
                probe = ctypes.CDLL(cand, use_errno=True)
                if hasattr(probe, "mlock") and hasattr(probe, "munlock"):
                    libc = probe
                    break
            except OSError:
                continue

        if libc is None:
            return None

        if hasattr(libc, "mlock"):
            fn = libc.mlock
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            fn.restype = ctypes.c_int
            _FN_MLOCK = fn
        if hasattr(libc, "munlock"):
            fn = libc.munlock
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            fn.restype = ctypes.c_int
            _FN_MUNLOCK = fn
        if _IS_LINUX and hasattr(libc, "madvise"):
            fn = libc.madvise
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            fn.restype = ctypes.c_int
            _FN_MADVISE = fn
        if _IS_LINUX and hasattr(libc, "prctl"):
            fn = libc.prctl
            fn.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            fn.restype = ctypes.c_int
            _FN_PRCTL = fn
        if hasattr(libc, "mmap") and hasattr(libc, "munmap"):
            fn_mmap = libc.mmap
            fn_mmap.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_long,
            ]
            fn_mmap.restype = ctypes.c_void_p
            _FN_MMAP = fn_mmap

            fn_munmap = libc.munmap
            fn_munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            fn_munmap.restype = ctypes.c_int
            _FN_MUNMAP = fn_munmap
        if hasattr(libc, "mprotect"):
            fn = libc.mprotect
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            fn.restype = ctypes.c_int
            _FN_MPROTECT = fn

        _LIBC = libc
        return _LIBC


def _os_mlock(addr: int, length: int) -> bool:
    _init_libc()
    if _FN_MLOCK is None or addr <= 0 or length <= 0:
        return False
    try:
        return int(_FN_MLOCK(ctypes.c_void_p(addr), ctypes.c_size_t(length))) == 0
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def _os_munlock(addr: int, length: int) -> bool:
    _init_libc()
    if _FN_MUNLOCK is None or addr <= 0 or length <= 0:
        return False
    try:
        return int(_FN_MUNLOCK(ctypes.c_void_p(addr), ctypes.c_size_t(length))) == 0
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def _os_madvise_dontdump(addr: int, length: int) -> bool:
    _init_libc()
    if _FN_MADVISE is None or addr <= 0 or length <= 0:
        return False
    try:
        return int(_FN_MADVISE(ctypes.c_void_p(addr), ctypes.c_size_t(length), _MADV_DONTDUMP)) == 0
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def _os_mmap_anon(length: int) -> int:
    _init_libc()
    if _FN_MMAP is None or length <= 0:
        return 0
    try:
        ptr = _FN_MMAP(
            None,
            ctypes.c_size_t(length),
            _PROT_READ | _PROT_WRITE,
            _MAP_PRIVATE | _MAP_ANON,
            -1,
            0,
        )
    except (OSError, ValueError, ctypes.ArgumentError):
        return 0
    if ptr is None or int(ptr) == 0 or int(ptr) == _MAP_FAILED:
        return 0
    return int(ptr)


def _os_munmap(addr: int, length: int) -> bool:
    _init_libc()
    if _FN_MUNMAP is None or addr <= 0 or length <= 0:
        return False
    try:
        return int(_FN_MUNMAP(ctypes.c_void_p(addr), ctypes.c_size_t(length))) == 0
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def _os_mprotect(addr: int, length: int, prot: int) -> bool:
    _init_libc()
    if _FN_MPROTECT is None or addr <= 0 or length <= 0:
        return False
    try:
        return int(_FN_MPROTECT(ctypes.c_void_p(addr), ctypes.c_size_t(length), prot)) == 0
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


class _PageLockRegistry:
    """
    Thread-safe reference counter for `mlock()`ed memory pages.
    Prevents premature `munlock()` when multiple `SecretBuffer` allocations share a heap page.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Dict[int, int] = {}

    def lock_range(self, addr: int, length: int) -> Tuple[int, int]:
        if addr <= 0 or length <= 0:
            return 0, 0
        _init_libc()
        if _FN_MLOCK is None or _FN_MUNLOCK is None:
            return 0, 0

        mask = ~(PAGE_SIZE - 1)
        page_start = addr & mask
        page_end = (addr + length + PAGE_SIZE - 1) & mask
        num_pages = (page_end - page_start) // PAGE_SIZE
        if num_pages <= 0:
            return 0, 0

        with self._lock:
            newly_locked: List[int] = []
            incremented: List[int] = []
            for idx in range(num_pages):
                page = page_start + idx * PAGE_SIZE
                cur = self._counts.get(page, 0)
                if cur > 0:
                    self._counts[page] = cur + 1
                    incremented.append(page)
                else:
                    if not _os_mlock(page, PAGE_SIZE):
                        # Roll back partial acquisition cleanly
                        for p in incremented:
                            self._counts[p] -= 1
                        for p in newly_locked:
                            self._counts.pop(p, None)
                            _os_munlock(p, PAGE_SIZE)
                        return 0, 0
                    self._counts[page] = 1
                    newly_locked.append(page)
            return page_start, num_pages

    def unlock_range(self, page_start: int, num_pages: int) -> None:
        if page_start <= 0 or num_pages <= 0:
            return
        with self._lock:
            for idx in range(num_pages):
                page = page_start + idx * PAGE_SIZE
                cur = self._counts.get(page, 0)
                if cur <= 1:
                    self._counts.pop(page, None)
                    _os_munlock(page, PAGE_SIZE)
                else:
                    self._counts[page] = cur - 1

    def active_locked_pages(self) -> int:
        with self._lock:
            return len(self._counts)


_PAGE_LOCKS = _PageLockRegistry()


def zeroize_addr(addr: int, length: int) -> None:
    """Explicitly overwrite `length` bytes starting at `addr` with 0x00 using compiler-barrier zeroization."""
    if addr <= 0 or length <= 0:
        return
    try:
        from ..native.loader import native_explicit_bzero
        if native_explicit_bzero(addr, length):
            return
    except (ImportError, OSError, AttributeError):
        pass
    ctypes.memset(ctypes.c_void_p(addr), 0, length)


def is_addr_zeroed(addr: int, length: int) -> bool:
    """Constant-time check that every byte in `[addr, addr + length)` is 0x00."""
    if length <= 0:
        return True
    if addr <= 0:
        return False
    try:
        from ..native.loader import native_is_zeroed
        res = native_is_zeroed(addr, length)
        if res is not None:
            return res
    except (ImportError, OSError, AttributeError):
        pass
    buf = (ctypes.c_ubyte * length).from_address(addr)
    acc = 0
    for b in buf:
        acc |= b
    return acc == 0


def zeroize_bytes(buf: bytearray) -> None:
    """Explicitly overwrite every byte of a mutable bytearray in RAM with 0x00 using compiler-barrier zeroization."""
    if not isinstance(buf, bytearray):
        raise TypeError("zeroize_bytes requires a mutable bytearray buffer.")
    n = len(buf)
    if n == 0:
        return
    c_buf = (ctypes.c_char * n).from_buffer(buf)
    zeroize_addr(ctypes.addressof(c_buf), n)


def disable_core_dumps() -> Dict[str, Any]:
    """
    Opt-in process hardening: sets `RLIMIT_CORE = (0, 0)` and (on Linux) `prctl(PR_SET_DUMPABLE, 0)`
    so secret key material cannot be written into core dump files or attached by unprivileged tracers.
    """
    rlimit_zeroed = False
    prctl_zeroed = False

    if _resource_mod is not None and hasattr(_resource_mod, "RLIMIT_CORE"):
        try:
            _resource_mod.setrlimit(_resource_mod.RLIMIT_CORE, (0, 0))
            soft, hard = _resource_mod.getrlimit(_resource_mod.RLIMIT_CORE)
            rlimit_zeroed = (soft == 0 and hard == 0)
        except (ValueError, OSError):
            try:
                soft, hard = _resource_mod.getrlimit(_resource_mod.RLIMIT_CORE)
                _resource_mod.setrlimit(_resource_mod.RLIMIT_CORE, (0, hard))
                soft2, _ = _resource_mod.getrlimit(_resource_mod.RLIMIT_CORE)
                rlimit_zeroed = (soft2 == 0)
            except (ValueError, OSError):
                rlimit_zeroed = False

    _init_libc()
    if _FN_PRCTL is not None:
        try:
            rc = int(_FN_PRCTL(_PR_SET_DUMPABLE, 0, 0, 0, 0))
            prctl_zeroed = (rc == 0)
        except (OSError, ValueError, ctypes.ArgumentError):
            prctl_zeroed = False

    return {
        "rlimit_core_zeroed": rlimit_zeroed,
        "pr_set_dumpable_zeroed": prctl_zeroed,
        "platform": sys.platform,
    }


def memory_security_status() -> Dict[str, Any]:
    """Returns non-mutating telemetry on active OS memory-locking and zeroization capabilities."""
    _init_libc()
    native_bzero = False
    native_zero_check = False
    try:
        from ..native.loader import is_native_available, native_is_zeroed
        if is_native_available():
            native_bzero = True
            probe = ctypes.create_string_buffer(b"\x00", 1)
            native_zero_check = native_is_zeroed(ctypes.addressof(probe), 1) is True
    except (ImportError, OSError, AttributeError):
        pass

    memlock_soft: Optional[int] = None
    memlock_hard: Optional[int] = None
    core_soft: Optional[int] = None
    core_hard: Optional[int] = None
    if _resource_mod is not None:
        if hasattr(_resource_mod, "RLIMIT_MEMLOCK"):
            try:
                memlock_soft, memlock_hard = _resource_mod.getrlimit(_resource_mod.RLIMIT_MEMLOCK)
            except (ValueError, OSError):
                pass
        if hasattr(_resource_mod, "RLIMIT_CORE"):
            try:
                core_soft, core_hard = _resource_mod.getrlimit(_resource_mod.RLIMIT_CORE)
            except (ValueError, OSError):
                pass

    pr_dumpable: Optional[int] = None
    if _FN_PRCTL is not None:
        try:
            val = int(_FN_PRCTL(_PR_GET_DUMPABLE, 0, 0, 0, 0))
            if val >= 0:
                pr_dumpable = val
        except (OSError, ValueError, ctypes.ArgumentError):
            pass

    return {
        "platform": sys.platform,
        "page_size": PAGE_SIZE,
        "native_explicit_bzero_available": native_bzero,
        "native_is_zeroed_available": native_zero_check,
        "mlock_available": _FN_MLOCK is not None and _FN_MUNLOCK is not None,
        "mmap_guard_pages_available": _FN_MMAP is not None and _FN_MUNMAP is not None and _FN_MPROTECT is not None,
        "madv_dontdump_available": _FN_MADVISE is not None,
        "prctl_dumpable_available": _FN_PRCTL is not None,
        "rlimit_memlock_soft": memlock_soft,
        "rlimit_memlock_hard": memlock_hard,
        "rlimit_core_soft": core_soft,
        "rlimit_core_hard": core_hard,
        "pr_dumpable": pr_dumpable,
        "active_locked_pages": _PAGE_LOCKS.active_locked_pages(),
    }


def harden_process_memory() -> Dict[str, Any]:
    """Applies opt-in process core-dump hardening and returns combined memory security telemetry."""
    core_res = disable_core_dumps()
    status = memory_security_status()
    status.update(core_res)
    return status


class SecretBuffer:
    """
    Context manager holding sensitive key material in a pinned mutable `bytearray` whose backing
    memory pages are reference-counted `mlock()`ed in RAM (when permitted by the OS) and
    deterministically zeroed via compiler-barrier `openqpep_explicit_bzero` before `munlock()` on exit.
    """

    def __init__(self, data: Union[bytes, bytearray, memoryview], *, lock_memory: bool = True):
        self._buf = bytearray(data)
        self._len = len(self._buf)
        self._wiped = False
        self._locked = False
        self._lock_start = 0
        self._lock_pages = 0
        self._pinned_c_buf: Any = None
        self._addr = 0

        if self._len > 0:
            self._pinned_c_buf = (ctypes.c_char * self._len).from_buffer(self._buf)
            self._addr = ctypes.addressof(self._pinned_c_buf)
            if lock_memory:
                start, pages = _PAGE_LOCKS.lock_range(self._addr, self._len)
                if pages > 0:
                    self._lock_start = start
                    self._lock_pages = pages
                    self._locked = True

    @property
    def raw(self) -> bytearray:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        return self._buf

    @property
    def is_memory_locked(self) -> bool:
        return self._locked

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    def view(self) -> memoryview:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        return memoryview(self._buf)

    def as_bytes(self) -> bytes:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        return bytes(self._buf)

    def copy_into(self, dst: bytearray, offset: int = 0) -> None:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped SecretBuffer.")
        if not isinstance(dst, bytearray):
            raise TypeError("copy_into requires a mutable bytearray destination.")
        if offset < 0 or offset + self._len > len(dst):
            raise ValueError("Destination bytearray is too small for SecretBuffer contents.")
        dst[offset : offset + self._len] = self._buf

    def wipe(self) -> None:
        if not self._wiped:
            if self._len > 0 and self._addr > 0:
                zeroize_addr(self._addr, self._len)
                if self._locked:
                    _PAGE_LOCKS.unlock_range(self._lock_start, self._lock_pages)
                    self._locked = False
                    self._lock_start = 0
                    self._lock_pages = 0
                self._pinned_c_buf = None
                self._addr = 0
            elif self._len > 0:
                zeroize_bytes(self._buf)
            self._wiped = True

    def __len__(self) -> int:
        return self._len

    def __enter__(self) -> "SecretBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except (TypeError, ValueError, BufferError, OSError, AttributeError):
            pass


class LockedMemoryBuffer:
    """
    Dedicated POSIX `mmap()` secret arena bracketed by `PROT_NONE` guard pages, locked in RAM via
    `mlock()`, and excluded from Linux core dumps via `madvise(MADV_DONTDUMP)`.
    Falls back cleanly to a memory-locked `SecretBuffer` on non-POSIX systems.
    """

    def __init__(self, data: Union[bytes, bytearray, memoryview, int], *, guard_pages: bool = True):
        if isinstance(data, bool):
            raise TypeError("LockedMemoryBuffer data must be bytes-like or a non-negative integer size.")
        if isinstance(data, int):
            if data < 0:
                raise ValueError("LockedMemoryBuffer size must be non-negative.")
            init_bytes: Optional[bytes] = None
            self._size = data
        elif isinstance(data, (bytes, bytearray, memoryview)):
            init_bytes = bytes(data)
            self._size = len(init_bytes)
        else:
            raise TypeError("LockedMemoryBuffer data must be bytes, bytearray, memoryview, or int.")

        self._wiped = False
        self._verified_zeroed = False
        self._locked = False
        self._dontdump_active = False
        self._guard_pages_active = False
        self._base_addr = 0
        self._secret_addr = 0
        self._data_region_len = 0
        self._total_len = 0
        self._fallback: Optional[SecretBuffer] = None

        if self._size == 0:
            return

        data_pages = (self._size + PAGE_SIZE - 1) // PAGE_SIZE
        data_region_len = data_pages * PAGE_SIZE
        guard_len = PAGE_SIZE if guard_pages else 0
        total_len = data_region_len + 2 * guard_len

        base = _os_mmap_anon(total_len)
        if base > 0:
            secret_addr = base + guard_len
            self._base_addr = base
            self._secret_addr = secret_addr
            self._data_region_len = data_region_len
            self._total_len = total_len

            if guard_pages:
                g1 = _os_mprotect(base, PAGE_SIZE, _PROT_NONE)
                g2 = _os_mprotect(secret_addr + data_region_len, PAGE_SIZE, _PROT_NONE)
                self._guard_pages_active = bool(g1 and g2)

            self._dontdump_active = _os_madvise_dontdump(secret_addr, data_region_len)
            self._locked = _os_mlock(secret_addr, data_region_len)

            if init_bytes:
                ctypes.memmove(ctypes.c_void_p(secret_addr), init_bytes, self._size)
        else:
            seed = init_bytes if init_bytes is not None else (b"\x00" * self._size)
            self._fallback = SecretBuffer(seed, lock_memory=True)
            self._locked = self._fallback.is_memory_locked

    @property
    def is_memory_locked(self) -> bool:
        return self._locked

    @property
    def is_dontdump_active(self) -> bool:
        return self._dontdump_active

    @property
    def has_guard_pages(self) -> bool:
        return self._guard_pages_active

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    @property
    def verified_zeroed_on_wipe(self) -> bool:
        return self._verified_zeroed

    def as_bytes(self) -> bytes:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped LockedMemoryBuffer.")
        if self._size == 0:
            return b""
        if self._fallback is not None:
            return self._fallback.as_bytes()
        return ctypes.string_at(ctypes.c_void_p(self._secret_addr), self._size)

    def copy_into(self, dst: bytearray, offset: int = 0) -> None:
        if self._wiped:
            raise RuntimeError("Attempted to access a wiped LockedMemoryBuffer.")
        if not isinstance(dst, bytearray):
            raise TypeError("copy_into requires a mutable bytearray destination.")
        if offset < 0 or offset + self._size > len(dst):
            raise ValueError("Destination bytearray is too small for LockedMemoryBuffer contents.")
        if self._size == 0:
            return
        if self._fallback is not None:
            self._fallback.copy_into(dst, offset)
            return
        dst_view = (ctypes.c_char * self._size).from_buffer(dst, offset)
        ctypes.memmove(ctypes.addressof(dst_view), ctypes.c_void_p(self._secret_addr), self._size)

    def write(self, data: Union[bytes, bytearray, memoryview], offset: int = 0) -> None:
        if self._wiped:
            raise RuntimeError("Attempted to write to a wiped LockedMemoryBuffer.")
        raw = bytes(data)
        if offset < 0 or offset + len(raw) > self._size:
            raise ValueError("Write exceeds LockedMemoryBuffer bounds.")
        if not raw:
            return
        if self._fallback is not None:
            self._fallback.raw[offset : offset + len(raw)] = raw
            return
        ctypes.memmove(ctypes.c_void_p(self._secret_addr + offset), raw, len(raw))

    @contextlib.contextmanager
    def scoped_view(self) -> Iterator[memoryview]:
        """Yields a zero-copy mutable `memoryview` bound strictly to this context scope."""
        if self._wiped:
            raise RuntimeError("Attempted to view a wiped LockedMemoryBuffer.")
        if self._fallback is not None:
            mv = self._fallback.view()
        elif self._size == 0:
            mv = memoryview(bytearray())
        else:
            c_arr = (ctypes.c_ubyte * self._size).from_address(self._secret_addr)
            mv = memoryview(c_arr)
        try:
            yield mv
        finally:
            mv.release()

    def wipe(self) -> None:
        if self._wiped:
            return
        if self._fallback is not None:
            self._fallback.wipe()
            self._verified_zeroed = True
            self._locked = False
        elif self._base_addr > 0:
            zeroize_addr(self._secret_addr, self._data_region_len)
            self._verified_zeroed = is_addr_zeroed(self._secret_addr, self._data_region_len)
            if self._locked:
                _os_munlock(self._secret_addr, self._data_region_len)
                self._locked = False
            _os_munmap(self._base_addr, self._total_len)
            self._base_addr = 0
            self._secret_addr = 0
            self._data_region_len = 0
            self._total_len = 0
            self._guard_pages_active = False
            self._dontdump_active = False
        else:
            self._verified_zeroed = True
        self._wiped = True

    def __len__(self) -> int:
        return self._size

    def __enter__(self) -> "LockedMemoryBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except (TypeError, ValueError, BufferError, OSError, AttributeError):
            pass


def zeroize_many(*items: Any) -> int:
    """Deterministically scrubs any combination of `bytearray`, `SecretBuffer`, or `LockedMemoryBuffer` objects."""
    count = 0
    for item in items:
        if item is None:
            continue
        if isinstance(item, bytearray):
            zeroize_bytes(item)
            count += 1
        elif isinstance(item, (SecretBuffer, LockedMemoryBuffer)):
            item.wipe()
            count += 1
    return count


def zeroize_secret_dict(mapping: Dict[Any, Any]) -> int:
    """
    Recursively scrubs mutable secret buffers (`bytearray`, `SecretBuffer`, `LockedMemoryBuffer`)
    and integer polynomial vectors inside a dict, then clears the mapping to drop references immediately.
    """
    if not isinstance(mapping, dict):
        return 0
    cleared = 0
    for val in list(mapping.values()):
        if isinstance(val, bytearray):
            zeroize_bytes(val)
            cleared += 1
        elif isinstance(val, (SecretBuffer, LockedMemoryBuffer)):
            val.wipe()
            cleared += 1
        elif isinstance(val, dict):
            cleared += zeroize_secret_dict(val)
        elif isinstance(val, list):
            for idx, elem in enumerate(val):
                if isinstance(elem, bytearray):
                    zeroize_bytes(elem)
                    cleared += 1
                elif isinstance(elem, (SecretBuffer, LockedMemoryBuffer)):
                    elem.wipe()
                    cleared += 1
                elif isinstance(elem, dict):
                    cleared += zeroize_secret_dict(elem)
                elif isinstance(elem, int) and not isinstance(elem, bool):
                    val[idx] = 0
                    cleared += 1
    cleared += len(mapping)
    mapping.clear()
    return cleared
