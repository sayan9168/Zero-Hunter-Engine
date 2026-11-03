#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Real Instrumentation Coverage & CmpLog Tracker
Supports SanitizerCoverage (trace-pc + trace-cmp) 64KB shared-memory edge bitmaps
with AFL-style logarithmic hit-count bucketing and blackbox behavioral fallback.

Educational & Authorized Defensive Research Only
"""

import ctypes
import hashlib
import mmap
import os
import struct
import subprocess
import tempfile
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from utils.logger import setup_logger

logger = setup_logger("coverage")

MAP_SIZE = 1 << 16          # 65,536 edge slots
CMP_HEADER_SIZE = 8         # uint32 cmp_write_idx + uint32 total_blocks
CMP_RING_SIZE = 256         # 256 CmpLog slots
CMP_ENTRY_SIZE = 32         # 32 bytes per CmpLog slot
SHM_TOTAL_SIZE = MAP_SIZE + CMP_HEADER_SIZE + (CMP_RING_SIZE * CMP_ENTRY_SIZE)


def _build_count_lookup() -> List[int]:
    table = [0] * 256
    table[1] = 1
    table[2] = 2
    table[3] = 4
    for i in range(4, 8):
        table[i] = 8
    for i in range(8, 16):
        table[i] = 16
    for i in range(16, 32):
        table[i] = 32
    for i in range(32, 128):
        table[i] = 64
    for i in range(128, 256):
        table[i] = 128
    return table


COUNT_CLASS_LOOKUP = _build_count_lookup()


def ensure_sancov_runtime() -> Optional[Path]:
    """Ensure instrumentation/sancov_rt.o is compiled and ready."""
    repo_root = Path(__file__).resolve().parent.parent
    inst_dir = repo_root / "instrumentation"
    rt_obj = inst_dir / "sancov_rt.o"
    rt_src = inst_dir / "sancov_rt.c"
    if rt_obj.exists():
        return rt_obj
    if rt_src.exists():
        try:
            subprocess.run(
                ["make", "-s", "-C", str(inst_dir), "sancov_rt.o"],
                check=True,
                timeout=15,
            )
            if rt_obj.exists():
                return rt_obj
        except Exception as exc:
            logger.debug(f"Could not auto-build sancov_rt.o: {exc}")
    return None


def _load_native_bitmap_helper():
    repo_root = Path(__file__).resolve().parent.parent
    native_dir = repo_root / "native"
    so_path = native_dir / "libmutator.so"
    if not so_path.exists() and (native_dir / "mutator_ext.cpp").exists():
        try:
            subprocess.run(["make", "-s", "-C", str(native_dir)], check=True, timeout=20)
        except Exception:
            return None
    if not so_path.exists():
        return None
    try:
        lib = ctypes.CDLL(str(so_path))
        lib.zh_update_coverage_bitmap.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.zh_update_coverage_bitmap.restype = ctypes.c_uint32
        return lib
    except Exception:
        return None


@dataclass
class CoverageObservation:
    has_new_edges: bool = False
    has_new_hits: bool = False
    run_edges: int = 0
    new_edges_count: int = 0
    instrumented: bool = False
    edge_indices: List[int] = field(default_factory=list)
    cmp_pairs: List[Tuple[bytes, bytes]] = field(default_factory=list)

    @property
    def is_interesting(self) -> bool:
        return self.has_new_edges or self.has_new_hits


class CoverageTracker:
    """
    Production-grade coverage & crash deduplication engine:
    - 64KB SanitizerCoverage shared-memory edge bitmap + hit-count bucketing
    - CmpLog operand ring buffer extraction for RedQueen / I2S magic-byte solving
    - Blackbox stdout/stderr/returncode behavioral fallback for uninstrumented targets
    - Stack-hash + signal crash deduplication
    """

    def __init__(self, shm_dir: Optional[str] = None):
        ensure_sancov_runtime()
        self._lock = threading.Lock()
        self.seen_crashes: Set[str] = set()
        self.interesting_inputs: Set[str] = set()
        self.blackbox_states: Set[str] = set()
        self.cmp_tokens: Counter = Counter()
        self.recent_cmp_pairs: List[Tuple[bytes, bytes]] = []

        self.virgin_bits = (ctypes.c_uint8 * MAP_SIZE)(*([0xFF] * MAP_SIZE))
        self.global_hit_counts = [0] * 64   # 64 heatmap summary blocks (1024 edges each)
        self.total_edges = 0
        self.total_hit_updates = 0
        self.instrumented_runs = 0
        self.history: List[Dict[str, float]] = []

        self._native = _load_native_bitmap_helper()
        self.cov_file_path = self._init_shm_file(shm_dir)

    def _init_shm_file(self, shm_dir: Optional[str] = None) -> str:
        base_dir = shm_dir
        if not base_dir:
            base_dir = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else tempfile.gettempdir()

        fd, path = tempfile.mkstemp(prefix="zh_cov_", suffix=".shm", dir=base_dir)
        with os.fdopen(fd, "wb") as fp:
            fp.write(b"\x00" * SHM_TOTAL_SIZE)

        self._shm_fd = os.open(path, os.O_RDWR)
        self._mm = mmap.mmap(self._shm_fd, SHM_TOTAL_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self._zero_block = b"\x00" * (MAP_SIZE + CMP_HEADER_SIZE)
        return path

    def create_worker_shm(self) -> Tuple[str, int, mmap.mmap]:
        """Allocate an isolated shared-memory coverage region for a parallel worker."""
        base_dir = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else tempfile.gettempdir()
        fd, path = tempfile.mkstemp(prefix="zh_wcov_", suffix=".shm", dir=base_dir)
        with os.fdopen(fd, "wb") as fp:
            fp.write(b"\x00" * SHM_TOTAL_SIZE)
        raw_fd = os.open(path, os.O_RDWR)
        mm = mmap.mmap(raw_fd, SHM_TOTAL_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        return path, raw_fd, mm

    def close(self):
        try:
            if hasattr(self, "_mm") and self._mm:
                self._mm.close()
                self._mm = None
            if hasattr(self, "_shm_fd") and self._shm_fd is not None:
                os.close(self._shm_fd)
                self._shm_fd = None
            if hasattr(self, "cov_file_path") and self.cov_file_path and os.path.exists(self.cov_file_path):
                os.unlink(self.cov_file_path)
        except Exception:
            pass

    def __del__(self):
        self.close()

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    def reset_trace(self, mm: Optional[mmap.mmap] = None):
        """Zero edge bitmap & CmpLog counter prior to spawning instrumented target."""
        target_mm = mm or self._mm
        if target_mm is not None:
            target_mm.seek(0)
            target_mm.write(self._zero_block)

    def _extract_cmplog(self, mm: mmap.mmap) -> List[Tuple[bytes, bytes]]:
        mm.seek(MAP_SIZE)
        hdr = mm.read(CMP_HEADER_SIZE)
        if len(hdr) < 4:
            return []
        write_idx = struct.unpack_from("<I", hdr, 0)[0]
        if write_idx == 0:
            return []

        count = min(write_idx, CMP_RING_SIZE)
        raw_ring = mm.read(count * CMP_ENTRY_SIZE)
        pairs: List[Tuple[bytes, bytes]] = []
        seen_local: Set[Tuple[bytes, bytes]] = set()

        for i in range(count):
            off = i * CMP_ENTRY_SIZE
            if off + CMP_ENTRY_SIZE > len(raw_ring):
                break
            ctype, sz, _pc = struct.unpack_from("<BBH", raw_ring, off)
            if sz < 1 or sz > 14:
                continue
            op1 = raw_ring[off + 4 : off + 4 + sz]
            op2 = raw_ring[off + 18 : off + 18 + sz]
            if op1 == op2:
                continue
            key = (op1, op2)
            if key not in seen_local:
                seen_local.add(key)
                pairs.append(key)
                # Count operand frequency across runs: true program constants repeat (>=2),
                # whereas random mutated input bytes appear only once!
                for cand in (op1, op2):
                    if len(cand) >= 2 and cand.strip(b"\x00\xff"):
                        self.cmp_tokens[cand] += 1
        return pairs

    def _collect_sampled_edges(self, trace_bytes: bytes, limit: int = 256) -> List[int]:
        """Collect non-zero edge indices from trace_bytes cleanly using memoryview."""
        mv = memoryview(trace_bytes).cast("Q")
        indices: List[int] = []
        for w_idx, word in enumerate(mv):
            if word == 0:
                continue
            base = w_idx * 8
            for b in range(8):
                val = trace_bytes[base + b]
                if val:
                    indices.append(base + b)
                    if len(indices) >= limit:
                        return indices
        return indices

    def evaluate_run(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: Optional[int] = 0,
        mm: Optional[mmap.mmap] = None,
    ) -> CoverageObservation:
        """
        Inspect shared-memory bitmap after target execution and update global virgin map.
        Falls back to behavioral state hashing when target has 0 instrumented edges.
        """
        target_mm = mm or self._mm
        obs = CoverageObservation()
        if target_mm is None:
            return obs

        target_mm.seek(0)
        trace_bytes = target_mm.read(MAP_SIZE)
        cmp_pairs = self._extract_cmplog(target_mm)
        obs.cmp_pairs = cmp_pairs

        with self._lock:
            if cmp_pairs:
                self.recent_cmp_pairs = (cmp_pairs + self.recent_cmp_pairs)[:128]

            if self._native is not None:
                c_trace = (ctypes.c_uint8 * MAP_SIZE).from_buffer_copy(trace_bytes)
                run_edges = ctypes.c_uint32(0)
                new_edges = ctypes.c_uint32(0)
                status = self._native.zh_update_coverage_bitmap(
                    ctypes.addressof(c_trace),
                    ctypes.addressof(self.virgin_bits),
                    MAP_SIZE,
                    ctypes.byref(run_edges),
                    ctypes.byref(new_edges),
                )
                obs.run_edges = int(run_edges.value)
                obs.new_edges_count = int(new_edges.value)
                obs.has_new_edges = (status == 2)
                obs.has_new_hits = (status == 1)
            else:
                # Pure-Python 64-bit word-skipping fallback
                mv = memoryview(trace_bytes).cast("Q")
                run_edges_cnt = 0
                new_edges_cnt = 0
                status = 0
                for w_idx, word in enumerate(mv):
                    if word == 0:
                        continue
                    base = w_idx * 8
                    for b in range(8):
                        raw = trace_bytes[base + b]
                        if not raw:
                            continue
                        run_edges_cnt += 1
                        classified = COUNT_CLASS_LOOKUP[raw]
                        virgin = self.virgin_bits[base + b]
                        if classified & virgin:
                            if virgin == 0xFF:
                                status = 2
                                new_edges_cnt += 1
                            elif status < 1:
                                status = 1
                            self.virgin_bits[base + b] = virgin & (~classified & 0xFF)
                obs.run_edges = run_edges_cnt
                obs.new_edges_count = new_edges_cnt
                obs.has_new_edges = (status == 2)
                obs.has_new_hits = (status == 1)

            if obs.run_edges > 0:
                obs.instrumented = True
                self.instrumented_runs += 1
                obs.edge_indices = self._collect_sampled_edges(trace_bytes)
                for edge_idx in obs.edge_indices:
                    self.global_hit_counts[edge_idx >> 10] += 1
                if obs.new_edges_count > 0:
                    self.total_edges += obs.new_edges_count
                if obs.has_new_hits or obs.has_new_edges:
                    self.total_hit_updates += 1
            else:
                # Uninstrumented blackbox target fallback: behavioral output/exit-code state hash
                out_sig = hashlib.sha256(stdout[:256]).hexdigest()[:8] if stdout else "0"
                # Strip PID numbers from stderr so ASAN PIDs don't look like distinct states
                clean_err = stderr[:256] if stderr else b""
                err_sig = hashlib.sha256(clean_err).hexdigest()[:8] if clean_err else "0"
                state_sig = f"rc={returncode}:olen={len(stdout)//16}:o={out_sig}:e={err_sig}"
                if state_sig not in self.blackbox_states:
                    self.blackbox_states.add(state_sig)
                    obs.has_new_hits = True

        return obs

    def is_new_crash(
        self,
        payload: bytes,
        signal: Optional[int] = None,
        stack_hash: Optional[str] = None,
        bug_class: Optional[str] = None,
    ) -> bool:
        """
        Return True if this crash represents a unique defect.
        Uses stack_hash + bug_class + signal when available (preventing duplicate crash floods),
        otherwise falls back to payload + signal signature.
        """
        with self._lock:
            if stack_hash and stack_hash != "none":
                sig = f"stack:{bug_class or 'crash'}:{signal}:{stack_hash}"
            else:
                sig = f"{self._hash(payload)}:{signal}"
            if sig in self.seen_crashes:
                return False
            self.seen_crashes.add(sig)
            return True

    def mark_interesting(self, payload: bytes):
        """Mark an input as interesting (caused new coverage or new unique crash)."""
        h = self._hash(payload)
        with self._lock:
            if h not in self.interesting_inputs:
                self.interesting_inputs.add(h)
                logger.info(f"[COVERAGE] New interesting input: {h} (edges={self.total_edges})")

    def get_heatmap_blocks(self) -> List[int]:
        """Return 64 block counts representing edge density across the 64KB map."""
        with self._lock:
            blocks = [0] * 64
            for idx in range(MAP_SIZE):
                if self.virgin_bits[idx] != 0xFF:
                    blocks[idx >> 10] += 1
            return blocks

    def get_cmp_tokens(self, max_tokens: int = 48) -> List[bytes]:
        with self._lock:
            # Return highest-frequency repeating program constants (filtering out 1-hit input noise)
            return [tok for tok, cnt in self.cmp_tokens.most_common(max_tokens) if cnt >= 2]

    def get_recent_cmp_pairs(self, limit: int = 32) -> List[Tuple[bytes, bytes]]:
        with self._lock:
            return list(self.recent_cmp_pairs[:limit])

    def get_stats(self) -> Dict:
        with self._lock:
            density = (self.total_edges / MAP_SIZE) * 100.0
            true_tokens = sum(1 for _, cnt in self.cmp_tokens.items() if cnt >= 2)
            return {
                "unique_crashes": len(self.seen_crashes),
                "interesting_inputs": len(self.interesting_inputs),
                "total_edges": self.total_edges,
                "edge_density_pct": round(density, 4),
                "hit_bucket_updates": self.total_hit_updates,
                "cmp_tokens_discovered": true_tokens,
                "blackbox_states": len(self.blackbox_states),
                "instrumented": self.instrumented_runs > 0,
            }

    def should_prefer(self, payload: bytes) -> bool:
        """Heuristic: prefer inputs that previously unlocked new coverage or crashes."""
        return self._hash(payload) in self.interesting_inputs
