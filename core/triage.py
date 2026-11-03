#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Crash Triage System
Classifies crashes into Exploitable (High Risk) vs Non-Exploitable (Low Risk)
Educational & Authorized Research Only
"""

import re
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from utils.logger import setup_logger

logger = setup_logger("triage")


class RiskLevel(Enum):
    HIGH = "Exploitable (High Risk)"
    MEDIUM = "Potentially Exploitable"
    LOW = "Non-Exploitable (Low Risk)"
    UNKNOWN = "Unknown / Needs Manual Review"


@dataclass
class TriageResult:
    risk: RiskLevel
    confidence: float          # 0.0 - 1.0
    reason: str
    signal: Optional[int] = None
    notes: str = ""


class CrashTriage:
    """
    Simple but effective triage based on:
    - Signal type (SIGSEGV, SIGABRT, etc.)
    - Common crash patterns from logs
    - Return code / ASAN output heuristics
    """

    # High risk indicators
    HIGH_RISK_SIGNALS = {11, 4, 8}          # SIGSEGV, SIGILL, SIGFPE
    HIGH_RISK_KEYWORDS = [
        r"heap[- ]overflow",
        r"use[- ]after[- ]free|UAF",
        r"double[- ]free",
        r"stack[- ]overflow",
        r"write access",
        r"SEGV_MAPERR",
        r"SEGV_ACCERR",
        r"KASAN",
        r"AddressSanitizer",
        r"heap-buffer-overflow",
        r"stack-buffer-overflow",
    ]

    # Low risk / less interesting
    LOW_RISK_KEYWORDS = [
        r"stack[- ]smashing detected",
        r"abort",
        r"assertion",
        r"TIMEOUT",
        r"SIGABRT",
    ]

    def __init__(self):
        self.high_patterns = [re.compile(p, re.I) for p in self.HIGH_RISK_KEYWORDS]
        self.low_patterns = [re.compile(p, re.I) for p in self.LOW_RISK_KEYWORDS]

    def analyze(self, crash_meta: Dict[str, Any], log_lines: Optional[list] = None) -> TriageResult:
        """
        Analyze a crash dictionary and optional log lines.
        Returns a TriageResult with risk classification.
        """
        signal = crash_meta.get("signal")
        returncode = crash_meta.get("returncode")
        stderr = crash_meta.get("stderr", b"").decode(errors="ignore") if isinstance(crash_meta.get("stderr"), bytes) else str(crash_meta.get("stderr", ""))
        raw_log = " ".join(log_lines) if log_lines else ""

        combined_text = f"{stderr} {raw_log}".lower()

        # --- High Risk checks ---
        if signal in self.HIGH_RISK_SIGNALS:
            for pat in self.high_patterns:
                if pat.search(combined_text):
                    return TriageResult(
                        risk=RiskLevel.HIGH,
                        confidence=0.85,
                        reason=f"Signal {signal} + high-risk pattern matched",
                        signal=signal,
                        notes="Memory corruption indicators present. Prioritize for further analysis."
                    )
            # SIGSEGV without clear pattern still interesting
            if signal == 11:
                return TriageResult(
                    risk=RiskLevel.MEDIUM,
                    confidence=0.65,
                    reason="SIGSEGV detected (needs deeper analysis)",
                    signal=signal,
                    notes="Possible memory corruption. Check registers & stack manually."
                )

        # ASAN / KASAN strong indicators
        if "addresssanitizer" in combined_text or "kasan" in combined_text:
            return TriageResult(
                risk=RiskLevel.HIGH,
                confidence=0.90,
                reason="AddressSanitizer / KASAN report detected",
                signal=signal,
                notes="High confidence memory error. Very valuable for research."
            )

        # --- Low Risk checks ---
        for pat in self.low_patterns:
            if pat.search(combined_text):
                return TriageResult(
                    risk=RiskLevel.LOW,
                    confidence=0.75,
                    reason="Low-risk pattern matched (abort / stack protector / timeout)",
                    signal=signal,
                    notes="Usually not directly exploitable. Still log for completeness."
                )

        # Timeout
        if signal == "TIMEOUT" or returncode == -9:
            return TriageResult(
                risk=RiskLevel.LOW,
                confidence=0.80,
                reason="Timeout / killed by fuzzer",
                signal=signal,
                notes="Performance or infinite loop. Low security impact."
            )

        # Default
        return TriageResult(
            risk=RiskLevel.UNKNOWN,
            confidence=0.40,
            reason="Insufficient information for automatic classification",
            signal=signal,
            notes="Manual review recommended (registers, stack trace, disassembly)."
        )

    def print_report(self, result: TriageResult, crash_id: str = ""):
        color_map = {
            RiskLevel.HIGH: "\033[91m",      # Red
            RiskLevel.MEDIUM: "\033[93m",    # Yellow
            RiskLevel.LOW: "\033[92m",       # Green
            RiskLevel.UNKNOWN: "\033[94m",  # Blue
        }
        reset = "\033[0m"
        color = color_map.get(result.risk, "")

        logger.info(f"{color}[TRIAGE] {crash_id} → {result.risk.value} (confidence: {result.confidence:.0%}){reset}")
        logger.info(f"         Reason : {result.reason}")
        if result.notes:
            logger.info(f"         Notes  : {result.notes}")
