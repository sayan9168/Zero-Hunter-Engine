#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Hybrid SAST Source-Code Vulnerability & Hotspot Analyzer
Scans C/C++ source code for memory-safety, integer, format-string, and logic sinks,
maps findings to CWEs with defensive remediation advice, and synthesizes fuzzer
dictionary tokens & checksum hints for Directed Greybox Fuzzing.

Educational & Authorized Defensive Research Only
"""

import os
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from utils.logger import setup_logger

logger = setup_logger("static_analyzer")


@dataclass
class StaticFinding:
    rule_id: str
    severity: str               # "HIGH" | "MEDIUM" | "LOW"
    cwe: str
    title: str
    file_path: str
    line: int
    column: int
    code_snippet: str
    remediation: str
    confidence: float = 0.85

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StaticAuditReport:
    scanned_paths: List[str]
    files_scanned: int
    findings: List[StaticFinding] = field(default_factory=list)
    extracted_tokens: List[bytes] = field(default_factory=list)
    detected_checksum: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_paths": self.scanned_paths,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "high_count": sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium_count": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low_count": sum(1 for f in self.findings if f.severity == "LOW"),
            "detected_checksum": self.detected_checksum,
            "extracted_tokens_hex": [t.hex() for t in self.extracted_tokens[:32]],
            "findings": [f.to_dict() for f in self.findings],
        }


# Declarative C/C++ dangerous sink patterns
SINK_RULES = [
    (
        "ZH-SAST-001",
        "HIGH",
        "CWE-787",
        "Unbounded string copy/concatenation (strcpy / strcat / gets)",
        re.compile(r"\b(strcpy|strcat|gets)\s*\("),
        "Replace with bounds-checked `snprintf(dst, sizeof(dst), \"%s\", src)` or `strlcpy`.",
    ),
    (
        "ZH-SAST-002",
        "HIGH",
        "CWE-787",
        "Unbounded formatted buffer write (sprintf / vsprintf)",
        re.compile(r"\b(sprintf|vsprintf)\s*\("),
        "Use `snprintf` / `vsnprintf` with explicit destination buffer capacity.",
    ),
    (
        "ZH-SAST-003",
        "HIGH",
        "CWE-134",
        "Uncontrolled format string variable passed to printf-family sink",
        re.compile(r"\b(?:printf|SYSLOG|syslog)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"),
        "Always supply a constant format literal: `printf(\"%s\", user_str)`.",
    ),
    (
        "ZH-SAST-004",
        "MEDIUM",
        "CWE-787",
        "Raw memory copy/fill (`memcpy` / `memmove` / `memset`) — verify length clamping",
        re.compile(r"\b(memcpy|memmove)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_+\-*/ ()]*)\s*\)"),
        "Validate `copy_len <= dst_capacity` (and check unsigned underflow on `n - hdr_len`) prior to `memcpy`.",
    ),
    (
        "ZH-SAST-005",
        "MEDIUM",
        "CWE-190",
        "Potential integer wraparound in dynamic allocation or multiplication",
        re.compile(r"\bmalloc\s*\([^)]*[*+][^)]*\)|\b[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[0-9]{4,}"),
        "Use `calloc(nmemb, size)` or `__builtin_mul_overflow` / `__builtin_add_overflow` before allocation or arithmetic.",
    ),
    (
        "ZH-SAST-006",
        "MEDIUM",
        "CWE-681",
        "Narrowing integer truncation cast (`uint16_t` / `int16_t` / `int8_t`) on numeric value",
        re.compile(r"\(\s*u?int(?:8|16)_t\s*\)\s*\(?[A-Za-z_][A-Za-z0-9_]*"),
        "Compare full-width integers before narrowing casts to prevent high-word truncation bypasses.",
    ),
    (
        "ZH-SAST-007",
        "HIGH",
        "CWE-78",
        "OS command execution sink (`system` / `popen`)",
        re.compile(r"\b(system|popen)\s*\("),
        "Avoid shell invocation on untrusted data; use `execve` with an explicit argument array and allowlisted inputs.",
    ),
]

MEMCMP_LIT_RE = re.compile(r'\b(?:memcmp|strncmp|strcmp)\s*\([^,]+,\s*"([^"]{2,16})"', re.M)
HEX_CONST_RE = re.compile(r"\b0x([0-9a-fA-F]{4,16})[uUlL]*\b")
FREE_CALL_RE = re.compile(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;")
NULL_ASSIGN_FMT = r"\b{var}\s*=\s*(?:NULL|0|nullptr)\b"


class StaticSourceAnalyzer:
    """
    Lightweight, zero-dependency C/C++ static vulnerability & constant extractor.
    """

    SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

    def scan_path(self, target_path: str) -> StaticAuditReport:
        p = Path(target_path)
        files: List[Path] = []
        if p.is_file() and p.suffix.lower() in self.SOURCE_EXTS:
            files.append(p)
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in self.SOURCE_EXTS:
                    # Skip fuzzer runtime internals unless specifically pointed at instrumentation/
                    if "instrumentation" in child.parts and p.name != "instrumentation":
                        continue
                    files.append(child)

        findings: List[StaticFinding] = []
        tokens: List[bytes] = []
        seen_tok: Set[bytes] = set()
        detected_checksum: Optional[str] = None

        for src_file in files:
            f_findings, f_tokens, csum = self._analyze_file(src_file)
            findings.extend(f_findings)
            if csum and not detected_checksum:
                detected_checksum = csum
            for t in f_tokens:
                if t not in seen_tok:
                    seen_tok.add(t)
                    tokens.append(t)

        # Sort findings HIGH -> MEDIUM -> LOW
        sev_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        findings.sort(key=lambda x: (sev_rank.get(x.severity, 3), x.file_path, x.line))

        return StaticAuditReport(
            scanned_paths=[str(p)],
            files_scanned=len(files),
            findings=findings,
            extracted_tokens=tokens,
            detected_checksum=detected_checksum,
        )

    def infer_source_for_binary(self, binary_path: str) -> Optional[StaticAuditReport]:
        """Locate sibling C/C++ source files next to a target binary for hybrid SAST+DAST."""
        bp = Path(binary_path)
        parent = bp.parent
        if not parent.is_dir():
            return None
        c_files = [f for f in parent.glob("*") if f.suffix.lower() in self.SOURCE_EXTS]
        if not c_files:
            return None
        # Prefer exact stem match if present (e.g., vuln_maze -> vuln_maze.c), else directory
        exact = parent / f"{bp.name}.c"
        if exact.is_file():
            return self.scan_path(str(exact))
        return self.scan_path(str(parent))

    def _analyze_file(self, src_file: Path):
        text = src_file.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        findings: List[StaticFinding] = []
        tokens: List[bytes] = []
        detected_checksum: Optional[str] = None

        # Detect CRC32 / Adler32 constants in source
        if "0xEDB88320" in text or "0xedb88320" in text or "crc32" in text.lower():
            detected_checksum = "crc32"
        elif "65521" in text or "adler32" in text.lower():
            detected_checksum = "adler32"

        # Extract string literals from memcmp / strcmp
        for m in MEMCMP_LIT_RE.finditer(text):
            raw_s = m.group(1).encode("utf-8", errors="ignore")
            if raw_s:
                tokens.append(raw_s)

        # Extract non-trivial 16/32-bit hex magic constants
        for m in HEX_CONST_RE.finditer(text):
            hex_digits = m.group(1)
            try:
                val = int(hex_digits, 16)
                if val in (0, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xEDB88320):
                    continue
                if val <= 0xFFFF:
                    tokens.append(struct.pack("<H", val))
                elif val <= 0xFFFFFFFF:
                    tokens.append(struct.pack("<I", val))
            except ValueError:
                pass

        # Line-by-line rule scan + stateful intra-procedural UAF / Double-Free detector
        in_block_comment = False
        freed_vars: Dict[str, int] = {}
        brace_depth = 0

        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith("/*"):
                if "*/" not in stripped:
                    in_block_comment = True
                continue
            code_only = raw_line.split("//", 1)[0]
            if not code_only.strip():
                continue

            # Reset intra-function freed tracker at function scope boundaries
            brace_depth += code_only.count("{") - code_only.count("}")
            if brace_depth <= 0:
                brace_depth = 0
                freed_vars.clear()

            # Check UAF / Double-Free on previously freed pointer in same function
            for fvar, free_line in list(freed_vars.items()):
                if re.search(NULL_ASSIGN_FMT.format(var=re.escape(fvar)), code_only):
                    del freed_vars[fvar]
                    continue
                if re.search(rf"\bfree\s*\(\s*{re.escape(fvar)}\s*\)", code_only):
                    findings.append(StaticFinding(
                        rule_id="ZH-SAST-008",
                        severity="HIGH",
                        cwe="CWE-415",
                        title=f"Potential Double Free of pointer `{fvar}` (previously freed at line {free_line})",
                        file_path=str(src_file),
                        line=idx,
                        column=max(1, raw_line.find("free") + 1),
                        code_snippet=raw_line.strip(),
                        remediation=f"Set `{fvar} = NULL;` immediately after `free({fvar})` and guard error paths.",
                        confidence=0.90,
                    ))
                elif re.search(rf"\b{re.escape(fvar)}\s*(?:->|\[)", code_only):
                    findings.append(StaticFinding(
                        rule_id="ZH-SAST-009",
                        severity="HIGH",
                        cwe="CWE-416",
                        title=f"Potential Heap Use-After-Free of `{fvar}` (freed at line {free_line})",
                        file_path=str(src_file),
                        line=idx,
                        column=max(1, raw_line.find(fvar) + 1),
                        code_snippet=raw_line.strip(),
                        remediation=f"Do not dereference `{fvar}` after `free({fvar})`; nullify pointer or return early on error paths.",
                        confidence=0.91,
                    ))

            free_m = FREE_CALL_RE.search(code_only)
            if free_m:
                freed_vars[free_m.group(1)] = idx

            # Declarative sink rules
            for rule_id, sev, cwe, title, regex, fix in SINK_RULES:
                m = regex.search(code_only)
                if not m:
                    continue
                # Skip safe literal sizeof memcpy like `memcpy(&val, buf, 4)` or `sizeof(...)`
                if rule_id == "ZH-SAST-004":
                    len_expr = m.group(3).strip()
                    if len_expr.isdigit() or len_expr.startswith("sizeof"):
                        continue
                findings.append(StaticFinding(
                    rule_id=rule_id,
                    severity=sev,
                    cwe=cwe,
                    title=title,
                    file_path=str(src_file),
                    line=idx,
                    column=max(1, m.start() + 1),
                    code_snippet=raw_line.strip(),
                    remediation=fix,
                ))

        return findings, tokens, detected_checksum
