#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - OASIS SARIF v2.1.0 Security Report Exporter
Exports unified Static Analysis (SAST) + Dynamic Fuzzing (DAST) + Differential
Testing findings in OASIS SARIF v2.1.0 format for GitHub Code Scanning & IDEs.

Educational & Authorized Defensive Research Only
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


class SARIFExporter:
    """Builds OASIS SARIF v2.1.0 compliant JSON documents."""

    def __init__(self, repo_root: Optional[str] = None):
        self.repo_root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent

    def _rel_uri(self, file_path: Optional[str]) -> str:
        if not file_path:
            return "unknown_target"
        try:
            p = Path(file_path).resolve()
            return str(p.relative_to(self.repo_root.resolve())).replace("\\", "/")
        except Exception:
            return os.path.basename(file_path)

    def build_sarif(
        self,
        crashes: List[Dict[str, Any]],
        static_findings: Optional[List[Dict[str, Any]]] = None,
        differential_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        # 1. Dynamic crash results
        for c in crashes:
            tr = c.get("triage", {})
            rc_adv = c.get("root_cause", {}) or {}
            cwe_full = tr.get("cwe", "CWE-119 (Memory Safety Violation)")
            rule_id = cwe_full.split()[0] if cwe_full else "CWE-119"

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": tr.get("bug_class", "memory-safety-violation"),
                    "shortDescription": {"text": cwe_full},
                    "help": {
                        "text": rc_adv.get(
                            "remediation_summary",
                            "Validate buffer bounds, pointer lifetimes, and integer arithmetic.",
                        )
                    },
                }

            rkey = tr.get("risk_key", "MEDIUM")
            level = "error" if rkey == "HIGH" else ("warning" if rkey == "MEDIUM" else "note")

            src_uri = self._rel_uri(rc_adv.get("source_file") or c.get("target"))
            line_no = int(rc_adv.get("line_number") or 1)

            msg = (
                f"[Dynamic Fuzz Crash {c.get('crash_id')}] {tr.get('reason', 'Crash')} | "
                f"Reproducer: {c.get('min_file') or c.get('crash_file', 'n/a')} "
                f"({c.get('min_size') or c.get('raw_size', 0)} bytes)"
            )

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": src_uri},
                            "region": {"startLine": max(1, line_no)},
                        }
                    }
                ],
                "fingerprints": {
                    "zeroHunterStackHash": tr.get("stack_hash", c.get("crash_id", "unknown"))
                },
            })

        # 2. Differential logic divergence results
        for df in differential_findings or []:
            rule_id = df.get("cwe", "CWE-681")
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": "differential-semantic-divergence",
                    "shortDescription": {"text": f"{rule_id}: Behavioral / Authorization Logic Divergence"},
                }
            results.append({
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": (
                        f"[Differential Divergence {df.get('diff_id')}] {df.get('category')}: "
                        f"ref_rc={df.get('ref_rc')} vs cand_rc={df.get('cand_rc')} "
                        f"({df.get('payload_size')} bytes)"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": self._rel_uri(df.get("candidate_target"))},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            })

        # 3. Static SAST hotspot results
        for sf in static_findings or []:
            rule_id = sf.get("rule_id", "ZH-SAST")
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": sf.get("cwe", "CWE-119"),
                    "shortDescription": {"text": sf.get("title", "Static Vulnerability Hotspot")},
                    "help": {"text": sf.get("remediation", "")},
                }
            sev = sf.get("severity", "MEDIUM")
            level = "error" if sev == "HIGH" else ("warning" if sev == "MEDIUM" else "note")
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[SAST {sf.get('cwe')}] {sf.get('title')} — Fix: {sf.get('remediation')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": self._rel_uri(sf.get("file_path"))},
                            "region": {
                                "startLine": max(1, int(sf.get("line", 1))),
                                "startColumn": max(1, int(sf.get("column", 1))),
                            },
                        }
                    }
                ],
            })

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Zero-Hunter-Engine",
                            "version": "3.0.0",
                            "informationUri": "https://github.com/sayan9168/Zero-Hunter-Engine",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def export_to_file(
        self,
        out_path: str,
        crashes: List[Dict[str, Any]],
        static_findings: Optional[List[Dict[str, Any]]] = None,
        differential_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        doc = self.build_sarif(crashes, static_findings, differential_findings)
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return str(p)
