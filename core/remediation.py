#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Root-Cause Source Localization & Defensive Remediation Advisor
Maps dynamic crash stack frames to exact C/C++ source lines, extracts surrounding
source context, and provides CWE-aligned secure coding remediation guidance.

Educational & Authorized Defensive Research Only
"""

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


FRAME_FILE_LINE_RE = re.compile(r"\(([^():]+):(\d+)\)")


CWE_REMEDIATION_DB: Dict[str, Tuple[str, str]] = {
    "CWE-787": (
        "Validate input length against destination buffer capacity before copying, and replace unbounded C string routines with bounded equivalents.",
        "if (input_len >= sizeof(buf)) { return -1; }\nmemcpy(buf, input, input_len);\nbuf[input_len] = '\\0';",
    ),
    "CWE-125": (
        "Never trust packet-declared length headers blindly; clamp declared read lengths against actual received buffer byte count (`n`).",
        "if (declared_len > actual_received_len) { return -1; }\nfor (size_t i = 0; i < declared_len; i++) { ... }",
    ),
    "CWE-416": (
        "Eliminate premature `free()` on shared/active heap objects; set pointers to `NULL` immediately after `free()` and return early on error paths.",
        "free(sess);\nsess = NULL;\nreturn ERR_INVALID_STATE; /* Do not touch sess after free */",
    ),
    "CWE-415": (
        "Ensure single-ownership heap lifecycle: nullify pointers right after `free(ptr)` so cleanup paths cannot free the same chunk twice.",
        "if (buf != NULL) {\n    free(buf);\n    buf = NULL;\n}",
    ),
    "CWE-476": (
        "Guard pointer dereferences with explicit `NULL` checks across all control-flow paths before reading or writing through the pointer.",
        "if (ptr == NULL) {\n    return -1;\n}\n*ptr = value;",
    ),
    "CWE-190": (
        "Check arithmetic operations for signed/unsigned integer wraparound using compiler overflow builtins prior to memory allocation or indexing.",
        "int32_t total = 0;\nif (__builtin_mul_overflow(units, stride, &total)) {\n    return -1; /* Reject overflow */\n}",
    ),
    "CWE-134": (
        "Never pass user-controlled buffers as the format string argument to `printf`/`snprintf`/`syslog`.",
        "printf(\"%s\\n\", untrusted_buf);",
    ),
    "CWE-681": (
        "Perform authorization and bounds checks on full-width integer types before any narrowing cast (`uint16_t` / `int16_t`).",
        "if (credits == 0 || credits > MAX_CREDITS) { return DENY; }",
    ),
}


@dataclass
class RootCauseAdvice:
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    function_name: str = ""
    crashing_statement: str = ""
    context_lines: List[Dict[str, Any]] = field(default_factory=list)
    remediation_summary: str = ""
    secure_code_example: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RootCauseLocalizer:
    """Resolves stack frames to workspace source files and builds remediation guidance."""

    _SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "proc", "sys", "dev"}

    def __init__(self, search_roots: Optional[Any] = None):
        repo_root = Path(__file__).resolve().parent.parent
        if search_roots is None:
            roots = [repo_root]
        elif isinstance(search_roots, (str, Path)):
            roots = [Path(search_roots)]
        else:
            roots = [Path(r) for r in search_roots]
        self.search_roots = roots
        self._file_index: Dict[str, Path] = {}
        self._build_index()

    def _build_index(self):
        import os

        for root in self.search_roots:
            try:
                if not root.exists():
                    continue
                if root.is_file():
                    self._file_index[root.name] = root
                    continue
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [d for d in dirnames if d not in self._SKIP_DIRS]
                    for fn in filenames:
                        if Path(fn).suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp"}:
                            self._file_index.setdefault(fn, Path(dirpath) / fn)
            except OSError:
                continue

    def localize(self, cwe: str, stack_frames: List[str]) -> RootCauseAdvice:
        cwe_id = cwe.split()[0].strip() if cwe else "CWE-119"
        summary, example = CWE_REMEDIATION_DB.get(
            cwe_id,
            (
                "Add strict bounds, state, and type validation at parser entry points and compile with ASan + UBSan during CI.",
                "if (len > MAX_SAFE_LEN) { return -1; }",
            ),
        )

        advice = RootCauseAdvice(
            remediation_summary=summary,
            secure_code_example=example,
        )

        for frame in stack_frames:
            m = FRAME_FILE_LINE_RE.search(frame)
            if not m:
                continue
            fname, line_s = m.group(1), m.group(2)
            line_no = int(line_s)
            func_name = frame.split("(")[0].strip()
            resolved = self._file_index.get(Path(fname).name)
            if resolved and resolved.is_file():
                try:
                    src_lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if 1 <= line_no <= len(src_lines):
                        advice.source_file = str(resolved)
                        advice.line_number = line_no
                        advice.function_name = func_name
                        advice.crashing_statement = src_lines[line_no - 1].strip()
                        start = max(1, line_no - 4)
                        end = min(len(src_lines), line_no + 4)
                        advice.context_lines = [
                            {
                                "line": ln,
                                "code": src_lines[ln - 1],
                                "focus": ln == line_no,
                            }
                            for ln in range(start, end + 1)
                        ]
                        break
                except Exception:
                    pass

        return advice
