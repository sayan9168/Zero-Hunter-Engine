#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Delta-Debugging Crash Minimizer (`tmin`)
Reduces crashing inputs to the minimal reproducible byte sequence that triggers
the exact same vulnerability signature (bug_class + stack_hash + signal),
followed by optional non-essential byte normalization.

Educational & Authorized Defensive Research Only
"""

import zlib
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from core.triage import CrashTriage, TriageResult
from utils.logger import setup_logger

logger = setup_logger("minimizer")


@dataclass
class MinimizationResult:
    original_size: int
    minimized_size: int
    minimized_payload: bytes
    steps_executed: int
    reproducible: bool
    reduction_pct: float
    signature: str


class CrashMinimizer:
    """
    AFL-tmin / ddmin style test-case reducer:
    1. Verifies crash reproducibility and records target signature `(bug_class, stack_hash, signal)`
    2. Performs logarithmic block deletion (`chunk = N/2, N/4, ..., 1`)
    3. Simplifies unconstrained bytes toward readable `'A'` (`0x41`)
    """

    def __init__(
        self,
        execute_fn: Callable[[bytes], Dict[str, Any]],
        triage: Optional[CrashTriage] = None,
        max_steps: int = 300,
        normalize_bytes: bool = True,
        checksum_mode: str = "none",
    ):
        self.execute_fn = execute_fn
        self.triage = triage or CrashTriage()
        self.max_steps = max_steps
        self.normalize_bytes = normalize_bytes
        self.checksum_mode = checksum_mode

    def _fixup_candidate(self, cand: bytes) -> bytes:
        if self.checksum_mode == "crc32" and len(cand) >= 12 and cand[:4] == b"ZHV3":
            buf = bytearray(cand)
            crc = zlib.crc32(bytes(buf[10:])) & 0xFFFFFFFF
            struct.pack_into("<I", buf, 6, crc)
            return bytes(buf)
        return cand

    def _signature_of(self, exec_res: Dict[str, Any]) -> Optional[str]:
        if not exec_res.get("crashed"):
            return None
        tr: TriageResult = self.triage.analyze(exec_res)
        if tr.stack_hash and tr.stack_hash != "none":
            return f"{tr.bug_class}:{tr.stack_hash}"
        return f"{tr.bug_class}:sig={exec_res.get('signal')}"

    def minimize(
        self,
        payload: bytes,
        expected_signature: Optional[str] = None,
    ) -> MinimizationResult:
        orig_len = len(payload)
        steps = 0

        if orig_len <= 1:
            return MinimizationResult(
                original_size=orig_len,
                minimized_size=orig_len,
                minimized_payload=payload,
                steps_executed=0,
                reproducible=True,
                reduction_pct=0.0,
                signature=expected_signature or "trivial",
            )

        # Verify baseline crash if signature not supplied
        if not expected_signature:
            steps += 1
            base_res = self.execute_fn(payload)
            expected_signature = self._signature_of(base_res)
            if not expected_signature:
                return MinimizationResult(
                    original_size=orig_len,
                    minimized_size=orig_len,
                    minimized_payload=payload,
                    steps_executed=steps,
                    reproducible=False,
                    reduction_pct=0.0,
                    signature="unreproducible",
                )

        cur = bytearray(payload)

        # Phase 1: Binary tail truncation fast-path
        while len(cur) > 2 and steps < self.max_steps:
            half = len(cur) // 2
            candidate = self._fixup_candidate(bytes(cur[:half]))
            steps += 1
            if self._signature_of(self.execute_fn(candidate)) == expected_signature:
                cur = bytearray(candidate)
            else:
                break

        # Phase 2: Delta-debugging chunk removal
        chunk = max(1, len(cur) // 2)
        while chunk >= 1 and steps < self.max_steps and len(cur) > 1:
            pos = 0
            improved_in_pass = False
            while pos < len(cur) and steps < self.max_steps and len(cur) > 1:
                end = min(len(cur), pos + chunk)
                if pos == 0 and end == len(cur):
                    break
                candidate = self._fixup_candidate(bytes(cur[:pos] + cur[end:]))
                steps += 1
                if self._signature_of(self.execute_fn(candidate)) == expected_signature:
                    cur = bytearray(candidate)
                    improved_in_pass = True
                else:
                    pos += chunk

            if chunk == 1:
                if not improved_in_pass:
                    break
            else:
                chunk //= 2

        # Phase 3: Byte simplification toward ASCII 'A' (0x41)
        if self.normalize_bytes and steps < self.max_steps:
            span = 8 if len(cur) > 16 else 1
            while span >= 1 and steps < self.max_steps:
                i = 0
                while i < len(cur) and steps < self.max_steps:
                    seg_end = min(len(cur), i + span)
                    if all(b == 0x41 for b in cur[i:seg_end]):
                        i += span
                        continue
                    trial = bytearray(cur)
                    trial[i:seg_end] = b"\x41" * (seg_end - i)
                    fixed_trial = self._fixup_candidate(bytes(trial))
                    steps += 1
                    if self._signature_of(self.execute_fn(fixed_trial)) == expected_signature:
                        cur = bytearray(fixed_trial)
                    i += span
                if span == 8 and len(cur) <= 64:
                    span = 1
                else:
                    break

        final_bytes = bytes(cur)
        reduction = ((orig_len - len(final_bytes)) / orig_len * 100.0) if orig_len > 0 else 0.0
        logger.info(
            f"[MINIMIZER] Reduced {orig_len}B → {len(final_bytes)}B "
            f"({reduction:.1f}% smaller in {steps} execs, sig={expected_signature})"
        )
        return MinimizationResult(
            original_size=orig_len,
            minimized_size=len(final_bytes),
            minimized_payload=final_bytes,
            steps_executed=steps,
            reproducible=True,
            reduction_pct=round(reduction, 2),
            signature=expected_signature,
        )
