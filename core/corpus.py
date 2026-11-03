#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Dynamic Corpus Queue & AFLFast Energy Scheduler
Manages discovered interesting inputs, performs edge-cover culling (favored seeds),
assigns exponential mutation energy, and supports corpus minimization (cmin).

Educational & Authorized Defensive Research Only
"""

import hashlib
import math
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from utils.logger import setup_logger

logger = setup_logger("corpus")


@dataclass
class SeedEntry:
    seed_id: str
    data: bytes
    exec_time_ms: float = 1.0
    edges_count: int = 0
    edge_indices: List[int] = field(default_factory=list)
    depth: int = 0
    fuzz_count: int = 0
    favored: bool = True
    discovered_at: float = field(default_factory=time.time)
    parent_id: Optional[str] = None
    reason: str = "initial"

    @property
    def perf_score(self) -> float:
        """Lower is better for set-cover culling (fast & compact)."""
        return max(0.1, self.exec_time_ms) * max(1, len(self.data))


class CorpusManager:
    """
    AFL/AFLFast-inspired corpus queue with:
    - SHA-256 deduplication
    - Greedy minimum edge-cover culling (`cull_favored`)
    - Exponential power scheduling (`assign_energy`)
    - Corpus distillation (`minimize_corpus` / `cmin`)
    """

    def __init__(self, queue_dir: Optional[str] = None, max_corpus_size: int = 2048):
        self._lock = threading.Lock()
        self.entries: List[SeedEntry] = []
        self._seen_hashes: Set[str] = set()
        self._top_rated: Dict[int, SeedEntry] = {}
        self.max_corpus_size = max_corpus_size
        self.queue_dir = Path(queue_dir) if queue_dir else None
        self.avg_exec_ms = 2.0
        self.avg_edges = 1.0
        if self.queue_dir:
            self.queue_dir.mkdir(parents=True, exist_ok=True)

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    def add_seed(
        self,
        data: bytes,
        exec_time_ms: float = 1.0,
        edges_count: int = 0,
        edge_indices: Optional[List[int]] = None,
        depth: int = 0,
        parent_id: Optional[str] = None,
        reason: str = "initial",
        persist: bool = True,
    ) -> Optional[SeedEntry]:
        h = self._hash(data)
        with self._lock:
            if h in self._seen_hashes:
                return None
            if len(self.entries) >= self.max_corpus_size:
                # Evict oldest non-favored heavily-fuzzed seed if full
                candidates = [e for e in self.entries if not e.favored and e.fuzz_count > 4]
                if candidates:
                    victim = min(candidates, key=lambda x: x.edges_count)
                    self.entries.remove(victim)
                else:
                    return None

            self._seen_hashes.add(h)
            idx = len(self.entries)
            seed_id = f"id_{idx:05d}_{reason}_{h[:8]}"
            edges = list(edge_indices) if edge_indices else []

            entry = SeedEntry(
                seed_id=seed_id,
                data=data,
                exec_time_ms=max(0.05, exec_time_ms),
                edges_count=edges_count,
                edge_indices=edges,
                depth=depth,
                parent_id=parent_id,
                reason=reason,
            )
            self.entries.append(entry)

            # Update running averages
            n = len(self.entries)
            self.avg_exec_ms = ((self.avg_exec_ms * (n - 1)) + entry.exec_time_ms) / n
            if edges_count > 0:
                self.avg_edges = ((self.avg_edges * (n - 1)) + edges_count) / n

            # Update top_rated per covered edge
            for edge in edges:
                prev = self._top_rated.get(edge)
                if prev is None or entry.perf_score < prev.perf_score:
                    self._top_rated[edge] = entry

            if persist and self.queue_dir and reason != "initial":
                out_file = self.queue_dir / f"{seed_id}.bin"
                try:
                    out_file.write_bytes(data)
                except Exception:
                    pass

            return entry

    def cull_favored(self):
        """Mark minimal fast/small set of seeds covering all known edges as favored."""
        with self._lock:
            if not self.entries:
                return
            if not self._top_rated:
                for e in self.entries:
                    e.favored = True
                return

            for e in self.entries:
                e.favored = False

            covered_edges: Set[int] = set()
            for edge, winner in self._top_rated.items():
                if edge in covered_edges:
                    continue
                winner.favored = True
                covered_edges.update(winner.edge_indices)

            # Always keep newest unfuzzed entries favored for at least 1 cycle
            for e in self.entries:
                if e.fuzz_count == 0:
                    e.favored = True

    def select_next(self) -> SeedEntry:
        """Select next corpus seed using favored + inverse-fuzz-frequency weighting."""
        with self._lock:
            if not self.entries:
                return SeedEntry(seed_id="fallback", data=b"A" * 32)

            weights: List[float] = []
            for e in self.entries:
                w = 1.0 / (1.0 + e.fuzz_count * 0.75)
                if e.favored:
                    w *= 5.0
                if e.fuzz_count == 0:
                    w *= 3.0
                if e.depth > 0:
                    w *= min(2.5, 1.0 + 0.2 * e.depth)
                weights.append(w)

            chosen = random.choices(self.entries, weights=weights, k=1)[0]
            chosen.fuzz_count += 1
            return chosen

    def select_random_other(self, exclude_id: str) -> Optional[SeedEntry]:
        with self._lock:
            if len(self.entries) < 2:
                return None
            others = [e for e in self.entries if e.seed_id != exclude_id]
            return random.choice(others) if others else None

    def assign_energy(self, entry: SeedEntry, base_energy: int = 6) -> int:
        """
        AFLFast-inspired exponential power schedule:
        Allocates mutation budget based on execution speed, bitmap coverage, depth, and fuzz count.
        """
        score = float(base_energy)

        # Speed factor
        if entry.exec_time_ms < self.avg_exec_ms * 0.5:
            score *= 1.75
        elif entry.exec_time_ms < self.avg_exec_ms:
            score *= 1.25
        elif entry.exec_time_ms > self.avg_exec_ms * 2.5:
            score *= 0.5

        # Coverage factor
        if entry.edges_count > self.avg_edges * 1.3:
            score *= 1.5
        elif entry.edges_count > self.avg_edges:
            score *= 1.2

        # Depth factor (deeper paths often guard rarer bugs)
        if entry.depth >= 3:
            score *= 1.5
        elif entry.depth >= 1:
            score *= 1.2

        # Favored bonus & exponential cooldown for heavily fuzzed seeds
        if entry.favored:
            score *= 1.4
        cooldown = math.pow(0.82, min(entry.fuzz_count, 10))
        score *= max(0.35, cooldown)

        return max(1, min(32, int(round(score))))

    def get_stats(self) -> Dict:
        with self._lock:
            favored_cnt = sum(1 for e in self.entries if e.favored)
            max_depth = max((e.depth for e in self.entries), default=0)
            return {
                "corpus_size": len(self.entries),
                "favored_seeds": favored_cnt,
                "max_depth": max_depth,
                "avg_exec_ms": round(self.avg_exec_ms, 2),
                "covered_top_edges": len(self._top_rated),
            }

    def list_entries(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            sorted_entries = sorted(
                self.entries,
                key=lambda e: (e.favored, e.edges_count, -len(e.data)),
                reverse=True,
            )[:limit]
            return [
                {
                    "seed_id": e.seed_id,
                    "size": len(e.data),
                    "edges": e.edges_count,
                    "depth": e.depth,
                    "fuzz_count": e.fuzz_count,
                    "favored": e.favored,
                    "exec_time_ms": round(e.exec_time_ms, 2),
                    "reason": e.reason,
                    "preview_hex": e.data[:24].hex(),
                }
                for e in sorted_entries
            ]

    @staticmethod
    def minimize_corpus(
        seeds: List[bytes],
        trace_fn: Callable[[bytes], Set[int]],
    ) -> List[bytes]:
        """
        Corpus Distillation (`cmin`):
        Greedy weighted set-cover returning the smallest set of shortest inputs
        that preserve 100% of total observed coverage edges.
        """
        evaluated = []
        universe: Set[int] = set()
        for data in seeds:
            edges = trace_fn(data)
            if edges:
                evaluated.append((data, edges))
                universe.update(edges)

        if not universe:
            # Deduplicate by content if uninstrumented
            seen = set()
            unique = []
            for s in sorted(seeds, key=len):
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            return unique

        uncovered = set(universe)
        selected: List[bytes] = []

        while uncovered and evaluated:
            # Pick candidate covering most uncovered edges, tie-break by shortest length
            best_idx = -1
            best_gain = 0
            best_len = 1 << 30
            for idx, (data, edges) in enumerate(evaluated):
                gain = len(edges & uncovered)
                if gain > best_gain or (gain == best_gain and gain > 0 and len(data) < best_len):
                    best_gain = gain
                    best_len = len(data)
                    best_idx = idx

            if best_idx < 0 or best_gain == 0:
                break

            chosen_data, chosen_edges = evaluated.pop(best_idx)
            selected.append(chosen_data)
            uncovered -= chosen_edges

        return selected
