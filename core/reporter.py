#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Security Assessment & SARIF Report Generator
Produces structured JSON, Markdown, OASIS SARIF v2.1.0, and self-contained
interactive HTML reports including root-cause source context, defensive patch
guidance, SAST findings, and differential logic divergences.

Educational & Authorized Defensive Research Only
"""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.remediation import RootCauseLocalizer
from core.sarif_exporter import SARIFExporter
from utils.logger import setup_logger

logger = setup_logger("reporter")


def format_hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Format binary payload as classic 16-byte Hex + ASCII dump."""
    view = data[:max_bytes]
    lines: List[str] = []
    for offset in range(0, len(view), 16):
        chunk = view[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<47}  |{ascii_part}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} additional bytes truncated)")
    return "\n".join(lines) if lines else "(empty payload)"


def load_divergences_from_dir(crash_dir: str) -> List[Dict[str, Any]]:
    cdir = Path(crash_dir)
    if not cdir.exists():
        return []
    out: List[Dict[str, Any]] = []
    for df in sorted(cdir.glob("diff_*.json")):
        try:
            out.append(json.loads(df.read_text(encoding="utf-8")))
        except Exception:
            pass
    return out


def load_crashes_from_dir(crash_dir: str) -> List[Dict[str, Any]]:
    """Load structured `.json` (and legacy `.meta`) crash artifacts from disk."""
    cdir = Path(crash_dir)
    if not cdir.exists():
        return []

    localizer = RootCauseLocalizer()
    records: List[Dict[str, Any]] = []
    seen_ids = set()

    for jf in sorted(cdir.glob("crash_*.json")):
        try:
            rec = json.loads(jf.read_text(encoding="utf-8"))
            cid = rec.get("crash_id", jf.stem)
            seen_ids.add(cid)
            bin_path = cdir / f"{cid}.bin"
            min_path = cdir / f"{cid}.min.bin"
            raw_bytes = bin_path.read_bytes() if bin_path.exists() else b""
            min_bytes = min_path.read_bytes() if min_path.exists() else None
            rec["raw_size"] = len(raw_bytes)
            rec["hexdump"] = format_hexdump(raw_bytes)
            if min_bytes is not None:
                rec["min_size"] = len(min_bytes)
                rec["min_hexdump"] = format_hexdump(min_bytes)
            if not rec.get("root_cause"):
                tr = rec.get("triage", {})
                rec["root_cause"] = localizer.localize(
                    tr.get("cwe", "CWE-119"),
                    tr.get("stack_frames", []),
                ).to_dict()
            records.append(rec)
        except Exception as exc:
            logger.debug(f"Failed reading {jf}: {exc}")

    for mf in sorted(cdir.glob("crash_*.meta")):
        cid = mf.stem
        if cid in seen_ids:
            continue
        bin_path = cdir / f"{cid}.bin"
        raw_bytes = bin_path.read_bytes() if bin_path.exists() else b""
        meta_txt = mf.read_text(errors="ignore")
        records.append({
            "crash_id": cid,
            "timestamp": mf.stat().st_mtime,
            "raw_size": len(raw_bytes),
            "hexdump": format_hexdump(raw_bytes),
            "triage": {
                "risk": "Exploitable (High Risk)" if "Exploitable (High Risk)" in meta_txt else "Unknown",
                "risk_key": "HIGH" if "Exploitable (High Risk)" in meta_txt else "UNKNOWN",
                "cwe": "CWE-119",
                "bug_class": "legacy-crash",
                "confidence": 0.8,
                "cvss_estimate": 7.5,
                "reason": "Imported from legacy .meta record",
                "stack_frames": [],
                "stack_hash": "legacy",
            },
            "root_cause": localizer.localize("CWE-119", []).to_dict(),
            "stderr_excerpt": meta_txt[:1000],
        })

    return records


class ReportGenerator:
    """Generates JSON, Markdown, OASIS SARIF v2.1.0, and HTML vulnerability reports."""

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(
        self,
        session_summary: Dict[str, Any],
        crash_dir: str = "crashes",
        base_name: str = "latest_report",
        static_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, str]:
        crashes = load_crashes_from_dir(crash_dir)
        divergences = load_divergences_from_dir(crash_dir)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        sast_list = static_findings if static_findings is not None else session_summary.get("sast_findings", [])

        payload = {
            "generated_at": now_iso,
            "engine": "Zero-Hunter-Engine v3.0",
            "summary": session_summary,
            "total_unique_crashes": len(crashes),
            "total_divergences": len(divergences),
            "total_sast_findings": len(sast_list),
            "crashes": crashes,
            "divergences": divergences,
            "sast_findings": sast_list,
        }

        json_path = self.reports_dir / f"{base_name}.json"
        md_path = self.reports_dir / f"{base_name}.md"
        html_path = self.reports_dir / f"{base_name}.html"
        sarif_path = self.reports_dir / f"{base_name}.sarif"

        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        md_path.write_text(self._render_markdown(payload), encoding="utf-8")
        html_path.write_text(self._render_html(payload), encoding="utf-8")
        SARIFExporter().export_to_file(
            str(sarif_path),
            crashes=crashes,
            static_findings=sast_list,
            differential_findings=divergences,
        )

        logger.info(f"[REPORT] Generated v3.0 reports → {html_path}, {sarif_path}, {md_path}, {json_path}")
        return {
            "json": str(json_path),
            "markdown": str(md_path),
            "html": str(html_path),
            "sarif": str(sarif_path),
        }

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        s = data.get("summary", {})
        crashes = data.get("crashes", [])
        divs = data.get("divergences", [])
        lines = [
            "# Zero-Hunter-Engine v3.0 — Vulnerability Research Report",
            "",
            f"- **Generated:** {data['generated_at']}",
            f"- **Target:** `{s.get('target', 'unknown')}` (`{s.get('input_mode', 'file')}` mode, Forkserver=`{s.get('forkserver_active', False)}`)",
            f"- **Iterations:** `{s.get('iterations', 0)}` ({s.get('execs_per_sec', 0):.1f} exec/s)",
            f"- **Coverage Edges:** `{s.get('total_edges', 0)}` | **Corpus Size:** `{s.get('corpus_size', 0)}`",
            f"- **Unique Crashes:** `{len(crashes)}` | **Differential Divergences:** `{len(divs)}`",
            "",
            "## Crash Findings Summary",
            "",
        ]

        if not crashes:
            lines.append("_No unique crashes recorded in this campaign._")
        else:
            lines.append("| Crash ID | Risk | Bug Class | CWE | CVSS | Size (Raw → Min) | Stack Hash |")
            lines.append("|---|---|---|---|---|---|---|")
            for c in crashes:
                tr = c.get("triage", {})
                sz = f"{c.get('raw_size', 0)}B"
                if c.get("min_size") is not None:
                    sz += f" → **{c['min_size']}B**"
                lines.append(
                    f"| `{c['crash_id']}` | {tr.get('risk', 'Unknown')} | `{tr.get('bug_class', 'n/a')}` "
                    f"| {tr.get('cwe', 'n/a')} | {tr.get('cvss_estimate', 0):.1f} | {sz} | `{tr.get('stack_hash', 'none')}` |"
                )

            lines.append("")
            lines.append("## Root-Cause Forensics & Remediation")
            for c in crashes:
                tr = c.get("triage", {})
                rc = c.get("root_cause", {}) or {}
                lines.extend([
                    "",
                    f"### {c['crash_id']} — `{tr.get('bug_class', 'crash')}` ({tr.get('cwe', 'n/a')})",
                    f"- **Classification:** {tr.get('risk', '')} (Confidence: {tr.get('confidence', 0)*100:.0f}%)",
                    f"- **Reason:** {tr.get('reason', '')}",
                    f"- **Remediation:** {rc.get('remediation_summary', '')}",
                ])
                if rc.get("source_file"):
                    lines.append(f"- **Source Location:** `{rc['source_file']}:{rc.get('line_number')}`")
                if c.get("min_hexdump"):
                    lines.extend(["", "**Minimized Reproducer Hexdump:**", "```text", c["min_hexdump"], "```"])
                else:
                    lines.extend(["", "**Payload Hexdump:**", "```text", c.get("hexdump", ""), "```"])

        if divs:
            lines.extend(["", "## Differential Logic Divergences", ""])
            for d in divs:
                lines.append(
                    f"- **`{d['diff_id']}`** (`{d['category']}` / `{d['cwe']}`): "
                    f"ref=`{d['ref_stdout']}` (rc={d['ref_rc']}) vs cand=`{d['cand_stdout']}` (rc={d['cand_rc']})"
                )

        lines.extend(["", "---", "_Educational & Authorized Defensive Security Research Only._", ""])
        return "\n".join(lines)

    def _render_html(self, data: Dict[str, Any]) -> str:
        s = data.get("summary", {})
        crashes = data.get("crashes", [])
        divs = data.get("divergences", [])
        high_cnt = sum(1 for c in crashes if c.get("triage", {}).get("risk_key") == "HIGH")
        heatmap = s.get("heatmap", [0] * 64)
        max_hm = max(heatmap) if heatmap and max(heatmap) > 0 else 1

        hm_cells = "".join(
            f'<div class="hm-cell" style="opacity:{0.15 + 0.85 * (v / max_hm):.2f}" title="Sector {i}: {v} edges"></div>'
            for i, v in enumerate(heatmap[:64])
        )

        crash_cards = []
        for c in crashes:
            tr = c.get("triage", {})
            rc = c.get("root_cause", {}) or {}
            rkey = tr.get("risk_key", "UNKNOWN")
            badge_cls = {"HIGH": "b-high", "MEDIUM": "b-med", "LOW": "b-low"}.get(rkey, "b-unk")
            frames_html = "".join(f"<li><code>{html.escape(fr)}</code></li>" for fr in tr.get("stack_frames", []))
            if not frames_html:
                frames_html = "<li><code>(No symbolized frames)</code></li>"

            src_block = ""
            if rc.get("context_lines"):
                code_rows = "\n".join(
                    f"{'>>>' if row['focus'] else '   '} {row['line']:4d} | {row['code']}"
                    for row in rc["context_lines"]
                )
                src_block = f"""
                <div style="margin:10px 0;">
                  <h4>Root-Cause Source ({html.escape(str(rc.get('source_file')))}:{rc.get('line_number')})</h4>
                  <pre>{html.escape(code_rows)}</pre>
                </div>
                """

            rem_block = f"""
            <div style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.35);border-radius:8px;padding:10px 12px;margin:10px 0;font-size:13px;">
              <strong style="color:#6ee7b7;">Defensive Patch Guidance:</strong> {html.escape(rc.get('remediation_summary', ''))}
              <pre style="margin-top:6px;">{html.escape(rc.get('secure_code_example', ''))}</pre>
            </div>
            """

            min_section = ""
            if c.get("min_hexdump"):
                min_section = f"""
                <div class="hex-col">
                  <h4>Minimized Reproducer ({c.get('min_size')} bytes)</h4>
                  <pre>{html.escape(c['min_hexdump'])}</pre>
                </div>
                """

            crash_cards.append(f"""
            <div class="card crash-card">
              <div class="crash-hdr">
                <div>
                  <span class="badge {badge_cls}">{html.escape(tr.get('risk', 'Unknown'))}</span>
                  <strong class="cid">{html.escape(c.get('crash_id', ''))}</strong>
                  <span class="cwe">{html.escape(tr.get('cwe', ''))}</span>
                </div>
                <div class="cvss">CVSS ~{tr.get('cvss_estimate', 0):.1f} | Hash: <code>{html.escape(tr.get('stack_hash', 'none'))}</code></div>
              </div>
              <p class="reason">{html.escape(tr.get('reason', ''))}</p>
              <p class="meta-line">Strategy: <code>{html.escape(str(c.get('strategy', 'havoc')))}</code> | Access: <code>{html.escape(str(tr.get('access_type', 'N/A')))}</code> | Fault Addr: <code>{html.escape(str(tr.get('fault_address') or 'N/A'))}</code></p>
              <div class="frames"><strong>Normalized Call Stack:</strong><ul>{frames_html}</ul></div>
              {src_block}
              {rem_block}
              <div class="hex-grid">
                <div class="hex-col">
                  <h4>Original Crash Input ({c.get('raw_size', 0)} bytes)</h4>
                  <pre>{html.escape(c.get('hexdump', ''))}</pre>
                </div>
                {min_section}
              </div>
            </div>
            """)

        cards_joined = "\n".join(crash_cards) if crash_cards else '<div class="card">No unique crashes recorded.</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Zero-Hunter-Engine v3.0 Security Report</title>
<style>
  :root {{ --bg:#0b0f19; --panel:#131a2a; --border:#23304d; --txt:#e2e8f0; --muted:#94a3b8; --acc:#22d3ee; --red:#ef4444; --yel:#f59e0b; --grn:#10b981; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background:var(--bg); color:var(--txt); margin:0; padding:32px; line-height:1.5; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  h1 {{ margin:0 0 6px; font-size:26px; color:#fff; }}
  .sub {{ color:var(--muted); font-size:14px; margin-bottom:24px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(165px,1fr)); gap:14px; margin-bottom:24px; }}
  .kpi {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }}
  .kpi .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  .kpi .val {{ font-size:24px; font-weight:700; margin-top:4px; color:var(--acc); }}
  .kpi .val.danger {{ color:var(--red); }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:18px; }}
  .hm-grid {{ display:grid; grid-template-columns:repeat(32, 1fr); gap:4px; margin-top:10px; }}
  .hm-cell {{ height:16px; background:var(--acc); border-radius:3px; }}
  .crash-hdr {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:8px; }}
  .badge {{ padding:3px 10px; border-radius:999px; font-size:12px; font-weight:700; margin-right:8px; }}
  .b-high {{ background:rgba(239,68,68,.2); color:#fca5a5; border:1px solid var(--red); }}
  .b-med {{ background:rgba(245,158,11,.2); color:#fcd34d; border:1px solid var(--yel); }}
  .b-low {{ background:rgba(16,185,129,.2); color:#6ee7b7; border:1px solid var(--grn); }}
  .b-unk {{ background:rgba(148,163,184,.2); color:#cbd5e1; }}
  .cid {{ font-size:16px; margin-right:10px; }}
  .cwe {{ color:var(--acc); font-size:13px; }}
  .cvss {{ color:var(--muted); font-size:13px; }}
  .reason {{ margin:6px 0; font-weight:500; }}
  .meta-line {{ color:var(--muted); font-size:13px; margin:4px 0 10px; }}
  .frames ul {{ margin:6px 0 12px; padding-left:20px; font-size:13px; }}
  .hex-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(420px,1fr)); gap:14px; }}
  pre {{ background:#070a12; border:1px solid #1e293b; border-radius:8px; padding:12px; overflow-x:auto; font-size:12px; color:#cbd5e1; margin:6px 0 0; }}
  h4 {{ margin:0; font-size:13px; color:var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Zero-Hunter-Engine v3.0 — Vulnerability Research Report</h1>
  <div class="sub">Generated {html.escape(data['generated_at'])} • Target: <code>{html.escape(str(s.get('target', 'unknown')))}</code> ({html.escape(str(s.get('input_mode', 'file')))} mode)</div>

  <div class="kpis">
    <div class="kpi"><div class="lbl">Iterations</div><div class="val">{s.get('iterations', 0):,}</div></div>
    <div class="kpi"><div class="lbl">Throughput</div><div class="val">{s.get('execs_per_sec', 0):.1f}/s</div></div>
    <div class="kpi"><div class="lbl">Coverage Edges</div><div class="val">{s.get('total_edges', 0):,}</div></div>
    <div class="kpi"><div class="lbl">Corpus Seeds</div><div class="val">{s.get('corpus_size', 0):,}</div></div>
    <div class="kpi"><div class="lbl">Unique Crashes</div><div class="val danger">{len(crashes)}</div></div>
    <div class="kpi"><div class="lbl">High-Risk / Diff Bugs</div><div class="val danger">{high_cnt + len(divs)}</div></div>
  </div>

  <div class="card">
    <strong>64KB Edge Coverage Bitmap Density (64 Sectors)</strong>
    <div class="hm-grid">{hm_cells}</div>
  </div>

  <h2>Triaged Findings & Root-Cause Advisories ({len(crashes)})</h2>
  {cards_joined}
</div>
</body>
</html>
"""
