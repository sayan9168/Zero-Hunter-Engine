#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Differential Fuzzing Engine
Discovers non-crashing logic vulnerabilities, authorization/quota bypasses, integer
truncation discrepancies, and parser differentials by executing candidate inputs
against both a Reference target and a Candidate target using dual Forkservers.

Educational & Authorized Defensive Research Only
"""

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.corpus import CorpusManager
from core.coverage import CoverageTracker
from core.forkserver import ForkserverExecutor
from core.grammar import GrammarEngine
from core.mutator import MutatorEngine
from core.reporter import format_hexdump
from core.static_analyzer import StaticSourceAnalyzer
from utils.logger import setup_logger
from utils.process_manager import ProcessManager

logger = setup_logger("differential")


@dataclass
class DivergenceFinding:
    diff_id: str
    category: str               # "crash-asymmetry" | "decision-bypass" | "output-divergence"
    cwe: str
    reference_target: str
    candidate_target: str
    ref_rc: Optional[int]
    cand_rc: Optional[int]
    ref_stdout: str
    cand_stdout: str
    payload_size: int
    minimized_size: int
    payload_hex: str
    hexdump: str
    file_path: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DifferentialFuzzer:
    """
    Coverage-guided + CmpLog differential fuzzer over (reference_target, candidate_target).
    """

    def __init__(
        self,
        reference_target: str,
        candidate_target: str,
        input_mode: str = "stdin",
        output_dir: str = "crashes",
        max_iterations: int = 800,
        sandbox: bool = True,
    ):
        self.reference_target = reference_target
        self.candidate_target = candidate_target
        self.input_mode = input_mode
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_iterations = max_iterations
        self.sandbox = sandbox

        self.coverage = CoverageTracker()
        self.corpus = CorpusManager()
        self.mutator = MutatorEngine()
        self.grammar = GrammarEngine()
        self.pm = ProcessManager()
        self.seen_signatures: Set[str] = set()
        self.findings: List[DivergenceFinding] = []

        # Extract static tokens from sibling source files if available
        sast = StaticSourceAnalyzer()
        for t in (reference_target, candidate_target):
            rep = sast.infer_source_for_binary(t)
            if rep and rep.extracted_tokens:
                self.mutator.add_dynamic_tokens(rep.extracted_tokens)

        self._fs_ref = ForkserverExecutor(
            reference_target,
            input_mode=input_mode,
            cov_file=self.coverage.cov_file_path,
            sandbox=sandbox,
            capture_stdout=True,
            worker_tag="diff_ref",
        )
        self._fs_cand = ForkserverExecutor(
            candidate_target,
            input_mode=input_mode,
            cov_file=self.coverage.cov_file_path,
            sandbox=sandbox,
            capture_stdout=True,
            worker_tag="diff_cand",
        )

    def _exec_one(self, fs: ForkserverExecutor, target: str, data: bytes) -> Dict[str, Any]:
        if fs.is_supported:
            return fs.execute(data)
        if self.input_mode == "stdin":
            return self.pm.spawn([target], stdin_data=data, sandbox=self.sandbox, cov_file=self.coverage.cov_file_path)
        tmp = self.output_dir / "_diff_tmp.bin"
        tmp.write_bytes(data)
        return self.pm.spawn([target, str(tmp)], sandbox=self.sandbox, cov_file=self.coverage.cov_file_path)

    def _run_pair(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        r_ref = self._exec_one(self._fs_ref, self.reference_target, data)
        r_cand = self._exec_one(self._fs_cand, self.candidate_target, data)
        return r_ref, r_cand

    @staticmethod
    def _classify_divergence(r_ref: Dict[str, Any], r_cand: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
        if bool(r_ref.get("crashed")) != bool(r_cand.get("crashed")):
            sig = f"crash:{r_ref.get('crashed')}:{r_cand.get('crashed')}:{r_cand.get('signal')}"
            return ("crash-asymmetry", "CWE-119", sig)

        rc_a = r_ref.get("returncode")
        rc_b = r_cand.get("returncode")
        out_a = (r_ref.get("stdout") or b"").strip()
        out_b = (r_cand.get("stdout") or b"").strip()

        if rc_a != rc_b:
            sig = f"rc:{rc_a}_vs_{rc_b}"
            return ("decision-bypass", "CWE-681", sig)

        if out_a != out_b:
            prefix_a = out_a.split(b":", 1)[0][:16]
            prefix_b = out_b.split(b":", 1)[0][:16]
            sig = f"out:{prefix_a!r}_vs_{prefix_b!r}"
            return ("output-divergence", "CWE-436", sig)

        return None

    def _minimize_divergence(self, payload: bytes, target_sig: str) -> bytes:
        cur = bytearray(payload)
        steps = 0
        chunk = max(1, len(cur) // 2)
        while chunk >= 1 and len(cur) > 1 and steps < 80:
            pos = 0
            while pos < len(cur) and len(cur) > 1 and steps < 80:
                end = min(len(cur), pos + chunk)
                if pos == 0 and end == len(cur):
                    break
                cand = bytes(cur[:pos] + cur[end:])
                steps += 1
                ra, rb = self._run_pair(cand)
                div = self._classify_divergence(ra, rb)
                if div and div[2] == target_sig:
                    cur = bytearray(cand)
                else:
                    pos += chunk
            if chunk == 1:
                break
            chunk //= 2
        return bytes(cur)

    def run(self, initial_seeds: Optional[List[bytes]] = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        seeds = initial_seeds or [b"AAAA", b"TOK:\x0a\x00\x00\x00U", b"PING\n"]
        for s in seeds:
            self.corpus.add_seed(s, persist=False)

        logger.info(
            f"[*] Differential Fuzzing started: ref={self.reference_target} vs cand={self.candidate_target}"
        )

        try:
            for it in range(1, self.max_iterations + 1):
                entry = self.corpus.select_next()
                cmp_pairs = self.coverage.get_recent_cmp_pairs(24)

                if it % 7 == 0:
                    payload = self.grammar.generate(seed_hint=entry.data)
                else:
                    payload = self.mutator.mutate(entry.data, cmp_pairs=cmp_pairs)

                self.coverage.reset_trace()
                r_ref, r_cand = self._run_pair(payload)
                obs = self.coverage.evaluate_run(r_cand["stdout"], r_cand["stderr"], r_cand["returncode"])

                if obs.cmp_pairs:
                    self.mutator.add_dynamic_tokens(self.coverage.get_cmp_tokens(24))

                if obs.is_interesting:
                    self.corpus.add_seed(
                        payload,
                        edges_count=obs.run_edges,
                        edge_indices=obs.edge_indices,
                        depth=entry.depth + 1,
                        reason="diff_edge",
                        persist=False,
                    )

                div = self._classify_divergence(r_ref, r_cand)
                if div is not None:
                    category, cwe, sig = div
                    if sig not in self.seen_signatures:
                        self.seen_signatures.add(sig)
                        min_payload = self._minimize_divergence(payload, sig)
                        r_ref_m, r_cand_m = self._run_pair(min_payload)
                        idx = len(self.findings)
                        diff_id = f"diff_{idx:04d}_{int(time.time())}"
                        bin_path = self.output_dir / f"{diff_id}.bin"
                        json_path = self.output_dir / f"{diff_id}.json"
                        bin_path.write_bytes(min_payload)

                        finding = DivergenceFinding(
                            diff_id=diff_id,
                            category=category,
                            cwe=cwe,
                            reference_target=self.reference_target,
                            candidate_target=self.candidate_target,
                            ref_rc=r_ref_m.get("returncode"),
                            cand_rc=r_cand_m.get("returncode"),
                            ref_stdout=(r_ref_m.get("stdout") or b"").decode("utf-8", errors="ignore").strip(),
                            cand_stdout=(r_cand_m.get("stdout") or b"").decode("utf-8", errors="ignore").strip(),
                            payload_size=len(payload),
                            minimized_size=len(min_payload),
                            payload_hex=min_payload.hex(),
                            hexdump=format_hexdump(min_payload),
                            file_path=str(bin_path),
                        )
                        json_path.write_text(json.dumps(finding.to_dict(), indent=2), encoding="utf-8")
                        self.findings.append(finding)
                        logger.warning(
                            f"[DIFF BUG] {diff_id} ({category} / {cwe}): "
                            f"ref='{finding.ref_stdout}' (rc={finding.ref_rc}) vs "
                            f"cand='{finding.cand_stdout}' (rc={finding.cand_rc}) | min={len(min_payload)}B"
                        )
        finally:
            self._fs_ref.stop()
            self._fs_cand.stop()
            elapsed = max(0.001, time.perf_counter() - t0)
            edges = self.coverage.get_stats()["total_edges"]
            self.coverage.close()

        return {
            "iterations": self.max_iterations,
            "elapsed_sec": round(elapsed, 2),
            "execs_per_sec": round((self.max_iterations * 2) / elapsed, 1),
            "total_edges": edges,
            "divergences_found": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
