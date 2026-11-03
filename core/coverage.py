#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Coverage Guidance (Skeleton)
Placeholder for future coverage-guided fuzzing (AFL-style / SanitizerCoverage)
Educational & Authorized Research Only
"""

from typing import Set, Dict, Optional
from pathlib import Path
import hashlib

from utils.logger import setup_logger

logger = setup_logger("coverage")


class CoverageTracker:
    """
    Basic coverage tracker skeleton.

    Current version:
    - Tracks unique crash signatures
    - Tracks unique payload hashes that caused new behavior
    - Ready to be extended with real instrumentation (SanitizerCoverage, LLVM coverage, etc.)
    """

    def __init__(self):
        self.seen_crashes: Set[str] = set()
        self.interesting_inputs: Set[str] = set()
        self.total_edges = 0          # Placeholder for future edge coverage

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    def is_new_crash(self, payload: bytes, signal: Optional[int] = None) -> bool:
        """Return True if this crash signature has not been seen before."""
        sig = f"{self._hash(payload)}:{signal}"
        if sig in self.seen_crashes:
            return False
        self.seen_crashes.add(sig)
        return True

    def mark_interesting(self, payload: bytes):
        """Mark an input as interesting (caused new coverage or new crash)."""
        h = self._hash(payload)
        if h not in self.interesting_inputs:
            self.interesting_inputs.add(h)
            logger.info(f"[COVERAGE] New interesting input: {h}")

    def get_stats(self) -> Dict:
        return {
            "unique_crashes": len(self.seen_crashes),
            "interesting_inputs": len(self.interesting_inputs),
            "total_edges": self.total_edges,  # Will be real in future versions
        }

    def should_prefer(self, payload: bytes) -> bool:
        """Simple heuristic: prefer inputs that previously found new crashes."""
        return self._hash(payload) in self.interesting_inputs
