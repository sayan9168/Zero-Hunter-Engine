#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Deep Crash Triage & Stack-Hash Deduplication System
Parses AddressSanitizer / UBSan / KASAN / Linux signal diagnostics to extract:
- Exact vulnerability class & CWE mapping
- Memory access direction (READ/WRITE/FREE) & size
- Faulting address classification (NULL page vs wild/corrupted pointer)
- ASLR-independent symbolized call-stack hashes for accurate deduplication
- ASAN Scariness score & exploitability assessment

Educational & Authorized Defensive Research Only
"""

import hashlib
import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

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
    confidence: float                   # 0.0 - 1.0
    reason: str
    signal: Optional[Any] = None
    notes: str = ""
    bug_class: str = "unknown-crash"
    cwe: str = "CWE-119"
    access_type: str = "UNKNOWN"
    access_size: Optional[int] = None
    fault_address: Optional[str] = None
    scariness: Optional[int] = None
    scariness_desc: str = ""
    stack_frames: List[str] = field(default_factory=list)
    stack_hash: str = "none"
    cvss_estimate: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["risk_key"] = self.risk.name
        return d


ASAN_ERROR_RE = re.compile(
    r"ERROR:\s*(?:AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer):\s*([A-Za-z0-9_-]+)"
    r"(?:\s+on\s+(?:unknown\s+)?address\s+(0x[0-9a-fA-F]+)|(?:\s+on\s+(0x[0-9a-fA-F]+)))?",
    re.I,
)
UBSAN_ERROR_RE = re.compile(r"runtime error:\s*([^\n]+)", re.I)
ACCESS_RE = re.compile(r"\b(READ|WRITE)\s+of\s+size\s+(\d+)\s+at\s+(0x[0-9a-fA-F]+)", re.I)
SCARINESS_RE = re.compile(r"SCARINESS:\s*(\d+)\s*\(([^)]+)\)", re.I)
FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+([^\s]+)\s+)?(.+)$")

RUNTIME_SKIP_FUNCS = (
    "__interceptor_",
    "__asan_",
    "__ubsan_",
    "__sanitizer_",
    "__libc_start",
    "_start",
    "abort",
    "raise",
    "gsignal",
)


class CrashTriage:
    """
    Deep exploitability triage engine combining sanitizer report parsing,
    CWE mapping, NULL-page vs wild-pointer heuristics, and stack-hash deduplication.
    """

    HIGH_RISK_SIGNALS = {11, 4, 7, 8}  # SIGSEGV, SIGILL, SIGBUS, SIGFPE

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
        r"global-buffer-overflow",
    ]

    LOW_RISK_KEYWORDS = [
        r"stack[- ]smashing detected",
        r"assertion",
        r"TIMEOUT",
    ]

    def __init__(self):
        self.high_patterns = [re.compile(p, re.I) for p in self.HIGH_RISK_KEYWORDS]
        self.low_patterns = [re.compile(p, re.I) for p in self.LOW_RISK_KEYWORDS]

    def _extract_frames(self, text: str) -> List[str]:
        """Extract first call-stack trace and normalize ASLR addresses away."""
        frames: List[str] = []
        started = False
        for line in text.splitlines():
            m = FRAME_RE.match(line)
            if m:
                started = True
                func = (m.group(2) or "").strip()
                loc = m.group(3).strip()
                # Shorten full filesystem path to basename:line for portability
                if "/" in loc and not loc.startswith("("):
                    loc_parts = loc.split()
                    loc = os.path.basename(loc_parts[0])
                elif loc.startswith("(") and "+" in loc:
                    # Strip ASLR base module path, keep binary+offset ONLY if no symbols
                    inner = loc.strip("()")
                    mod, off = inner.rsplit("+", 1)
                    loc = f"{os.path.basename(mod)}+{off}"

                if func and any(func.startswith(p) for p in RUNTIME_SKIP_FUNCS):
                    continue
                if "libc.so" in loc or "libsanitizer" in loc or "libasan" in loc:
                    continue

                entry = f"{func} ({loc})" if func else loc
                frames.append(entry)
                if len(frames) >= 6:
                    break
            elif started and not line.strip():
                if frames:
                    break
        return frames

    @staticmethod
    def _compute_stack_hash(bug_class: str, frames: List[str]) -> str:
        if not frames:
            return "none"
        top = "|".join(frames[:3])
        digest = hashlib.sha256(f"{bug_class}:{top}".encode("utf-8")).hexdigest()
        return digest[:12]

    @staticmethod
    def _is_null_page(addr_str: Optional[str]) -> bool:
        if not addr_str:
            return False
        try:
            val = int(addr_str, 16)
            return val < 0x10000
        except ValueError:
            return False

    @staticmethod
    def _classify_cwe(bug_class: str, access_type: str, is_null: bool) -> str:
        bc = bug_class.lower()
        if is_null or "null" in bc:
            return "CWE-476 (NULL Pointer Dereference)"
        if "use-after-free" in bc or "uaf" in bc:
            return "CWE-416 (Use After Free)"
        if "double-free" in bc or "invalid-free" in bc:
            return "CWE-415 (Double Free)"
        if "buffer-overflow" in bc or "overflow" in bc:
            if access_type == "READ":
                return "CWE-125 (Out-of-bounds Read)"
            return "CWE-787 (Out-of-bounds Write)"
        if "integer-overflow" in bc or "shift" in bc:
            return "CWE-190 (Integer Overflow or Wraparound)"
        if "div" in bc or "fpe" in bc:
            return "CWE-369 (Divide By Zero)"
        if "segv" in bc:
            if access_type == "WRITE":
                return "CWE-787 (Out-of-bounds Write)"
            return "CWE-119 (Improper Restriction of Operations within Memory Buffer)"
        return "CWE-119 (Memory Safety Violation)"

    def analyze(self, crash_meta: Dict[str, Any], log_lines: Optional[list] = None) -> TriageResult:
        """
        Analyze a crash dictionary and optional kernel/system log lines.
        Returns a rich TriageResult with risk, CWE, stack hash, and exploitability notes.
        """
        signal_val = crash_meta.get("signal")
        returncode = crash_meta.get("returncode")
        raw_stderr = crash_meta.get("stderr", b"")
        stderr = (
            raw_stderr.decode("utf-8", errors="ignore")
            if isinstance(raw_stderr, (bytes, bytearray))
            else str(raw_stderr or "")
        )
        raw_log = "\n".join(log_lines) if log_lines else ""
        full_text = f"{stderr}\n{raw_log}"
        combined_lower = full_text.lower()

        # Timeout check first
        if signal_val == "TIMEOUT" or crash_meta.get("timed_out") or returncode == -9:
            return TriageResult(
                risk=RiskLevel.LOW,
                confidence=0.85,
                reason="Execution timeout / hang detected",
                signal=signal_val,
                notes="Potential infinite loop or algorithmic complexity DoS (CWE-400).",
                bug_class="timeout-hang",
                cwe="CWE-400 (Uncontrolled Resource Consumption)",
                access_type="NONE",
                stack_hash="timeout",
                cvss_estimate=3.7,
            )

        # Parse ASAN / Sanitizer structured diagnostics
        asan_match = ASAN_ERROR_RE.search(full_text)
        ubsan_match = UBSAN_ERROR_RE.search(full_text)
        access_match = ACCESS_RE.search(full_text)
        scary_match = SCARINESS_RE.search(full_text)
        frames = self._extract_frames(full_text)

        access_type = access_match.group(1).upper() if access_match else "UNKNOWN"
        access_size = int(access_match.group(2)) if access_match else None
        fault_addr = None
        if asan_match:
            fault_addr = asan_match.group(2) or asan_match.group(3)
        if not fault_addr and access_match:
            fault_addr = access_match.group(3)

        scariness = int(scary_match.group(1)) if scary_match else None
        scariness_desc = scary_match.group(2) if scary_match else ""

        if asan_match:
            raw_bug = asan_match.group(1).lower()
            if raw_bug == "attempting":
                if "double-free" in combined_lower:
                    raw_bug = "double-free"
                else:
                    raw_bug = "invalid-free"

            is_null = self._is_null_page(fault_addr)
            if raw_bug == "segv" and is_null:
                raw_bug = "null-dereference"
            if "free" in raw_bug and access_type == "UNKNOWN":
                access_type = "FREE"

            cwe = self._classify_cwe(raw_bug, access_type, is_null)
            stack_hash = self._compute_stack_hash(raw_bug, frames)

            # Determine RiskLevel based on bug class + READ/WRITE + NULL page
            if is_null:
                risk = RiskLevel.LOW if access_type == "READ" else RiskLevel.MEDIUM
                conf = 0.88
                cvss = 5.5 if access_type != "READ" else 4.3
                reason = f"AddressSanitizer: {raw_bug} ({access_type} near NULL {fault_addr})"
                notes = "NULL-page fault; typically causes DoS unless kernel/mmap_min_addr=0."
            elif any(k in raw_bug for k in ("use-after-free", "double-free", "buffer-overflow")) and access_type in ("WRITE", "FREE"):
                risk = RiskLevel.HIGH
                conf = 0.95
                cvss = 8.8
                sz_note = f" of {access_size} bytes" if access_size else ""
                reason = f"AddressSanitizer: {raw_bug} ({access_type}{sz_note})"
                notes = f"High-impact memory corruption ({cwe}). Top frame: {frames[0] if frames else 'n/a'}."
            elif any(k in raw_bug for k in ("buffer-overflow", "use-after-free")) and access_type == "READ":
                risk = RiskLevel.MEDIUM
                conf = 0.88
                cvss = 6.8
                reason = f"AddressSanitizer: {raw_bug} (Out-of-bounds READ)"
                notes = f"Information disclosure / memory leak primitive ({cwe})."
            else:
                risk = RiskLevel.HIGH
                conf = 0.90
                cvss = 8.1
                reason = f"AddressSanitizer / KASAN report detected ({raw_bug})"
                notes = f"Confirmed sanitizer violation ({cwe})."

            return TriageResult(
                risk=risk,
                confidence=conf,
                reason=reason,
                signal=signal_val,
                notes=notes,
                bug_class=raw_bug,
                cwe=cwe,
                access_type=access_type,
                access_size=access_size,
                fault_address=fault_addr,
                scariness=scariness,
                scariness_desc=scariness_desc,
                stack_frames=frames,
                stack_hash=stack_hash,
                cvss_estimate=cvss,
            )

        if ubsan_match:
            ub_desc = ubsan_match.group(1).strip()
            stack_hash = self._compute_stack_hash("ubsan", frames)
            return TriageResult(
                risk=RiskLevel.MEDIUM,
                confidence=0.80,
                reason=f"UBSan undefined behavior: {ub_desc[:80]}",
                signal=signal_val,
                notes="Undefined behavior may lead to integer wraparound or downstream memory corruption.",
                bug_class="undefined-behavior",
                cwe="CWE-190 (Integer Overflow or Undefined Behavior)",
                stack_frames=frames,
                stack_hash=stack_hash,
                cvss_estimate=6.1,
            )

        # KASAN in dmesg/journalctl
        if "kasan" in combined_lower:
            return TriageResult(
                risk=RiskLevel.HIGH,
                confidence=0.92,
                reason="Kernel AddressSanitizer (KASAN) fault detected",
                signal=signal_val,
                notes="Kernel memory corruption detected in system logs.",
                bug_class="kasan-memory-corruption",
                cwe="CWE-787 (Kernel Memory Corruption)",
                stack_frames=frames,
                stack_hash=self._compute_stack_hash("kasan", frames),
                cvss_estimate=8.8,
            )

        # Native signal analysis (uninstrumented target)
        if signal_val in self.HIGH_RISK_SIGNALS:
            for pat in self.high_patterns:
                if pat.search(combined_lower):
                    return TriageResult(
                        risk=RiskLevel.HIGH,
                        confidence=0.85,
                        reason=f"Signal {signal_val} + high-risk corruption indicator matched",
                        signal=signal_val,
                        notes="Memory corruption indicators present. Rebuild with zh-cc for exact frame triage.",
                        bug_class=f"signal-{signal_val}-corruption",
                        cwe="CWE-787 (Out-of-bounds Write)",
                        stack_frames=frames,
                        stack_hash=self._compute_stack_hash(f"sig{signal_val}", frames),
                        cvss_estimate=8.2,
                    )
            if signal_val == 11:
                return TriageResult(
                    risk=RiskLevel.MEDIUM,
                    confidence=0.68,
                    reason="SIGSEGV segmentation fault detected",
                    signal=signal_val,
                    notes="Possible memory corruption or invalid pointer dereference.",
                    bug_class="sigsegv",
                    cwe="CWE-119 (Memory Buffer Violation)",
                    stack_frames=frames,
                    stack_hash=self._compute_stack_hash("sigsegv", frames),
                    cvss_estimate=6.8,
                )
            if signal_val == 8:
                return TriageResult(
                    risk=RiskLevel.LOW,
                    confidence=0.80,
                    reason="SIGFPE arithmetic exception (divide-by-zero)",
                    signal=signal_val,
                    notes="Arithmetic fault causing denial of service.",
                    bug_class="sigfpe",
                    cwe="CWE-369 (Divide By Zero)",
                    cvss_estimate=4.8,
                )

        # Stack protector / abort / assertion
        if "stack smashing detected" in combined_lower:
            return TriageResult(
                risk=RiskLevel.MEDIUM,
                confidence=0.85,
                reason="Stack canary corruption detected (__stack_chk_fail)",
                signal=signal_val,
                notes="Confirmed stack buffer overflow mitigated by stack canary.",
                bug_class="stack-canary-trip",
                cwe="CWE-787 (Stack Buffer Overflow)",
                cvss_estimate=7.0,
            )

        for pat in self.low_patterns:
            if pat.search(combined_lower):
                return TriageResult(
                    risk=RiskLevel.LOW,
                    confidence=0.75,
                    reason="Low-risk abort / assertion matched",
                    signal=signal_val,
                    notes="Program terminated via assertion or abort.",
                    bug_class="abort-assertion",
                    cwe="CWE-617 (Reachable Assertion)",
                    cvss_estimate=3.5,
                )

        if signal_val == 6:
            return TriageResult(
                risk=RiskLevel.MEDIUM,
                confidence=0.60,
                reason="SIGABRT received (possible heap allocator corruption or abort)",
                signal=signal_val,
                notes="Check allocator diagnostics (double-free / corrupted chunk) or assertions.",
                bug_class="sigabrt",
                cwe="CWE-119 (Allocator Abort / Assertion)",
                cvss_estimate=5.8,
            )

        return TriageResult(
            risk=RiskLevel.UNKNOWN,
            confidence=0.40,
            reason="Insufficient telemetry for automatic classification",
            signal=signal_val,
            notes="Compile target with ./instrumentation/zh-cc for ASAN + CmpLog diagnostics.",
            bug_class="unknown-crash",
            cvss_estimate=5.0,
        )

    def print_report(self, result: TriageResult, crash_id: str = ""):
        color_map = {
            RiskLevel.HIGH: "\033[91m",
            RiskLevel.MEDIUM: "\033[93m",
            RiskLevel.LOW: "\033[92m",
            RiskLevel.UNKNOWN: "\033[94m",
        }
        reset = "\033[0m"
        color = color_map.get(result.risk, "")

        logger.info(
            f"{color}[TRIAGE] {crash_id} → {result.risk.value} "
            f"[{result.cwe}] (confidence: {result.confidence:.0%}, CVSS ~{result.cvss_estimate:.1f}){reset}"
        )
        logger.info(f"         Reason : {result.reason}")
        if result.stack_frames:
            logger.info(f"         Stack  : {' -> '.join(result.stack_frames[:3])} (hash={result.stack_hash})")
        if result.notes:
            logger.info(f"         Notes  : {result.notes}")
