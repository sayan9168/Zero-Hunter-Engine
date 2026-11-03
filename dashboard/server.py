#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Real-Time Web Mission Control Server
Zero-dependency HTTP/JSON server (`ThreadingHTTPServer`) bound to 0.0.0.0 for:
- Forkserver Turbo Fuzzing & 64KB Coverage Bitmap Visualization
- Checksum-Guarded (CRC32) & Multi-Sanitizer (ASan + UBSan) Campaign Control
- Differential Logic-Bug Fuzzing (`parser_ref` vs `parser_buggy`)
- Hybrid SAST Source-Code Vulnerability & Hotspot Auditing
- Root-Cause Source Localization, Defensive Patch Advisor & OASIS SARIF v2.1.0 Export

Educational & Authorized Defensive Research Only
"""

import json
import subprocess
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from core.differential import DifferentialFuzzer
from core.fuzzer_engine import FuzzConfig, FuzzerEngine
from core.reporter import (
    ReportGenerator,
    load_crashes_from_dir,
    load_divergences_from_dir,
)
from core.sarif_exporter import SARIFExporter
from core.static_analyzer import StaticSourceAnalyzer
from utils.logger import setup_logger
from utils.sandbox import inspect_target_binary, probe_sandbox_capabilities

logger = setup_logger("dashboard")

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

TARGET_PRESETS: Dict[str, Dict[str, Any]] = {
    "vuln_vault": {
        "label": "vuln_vault — CRC32-Guarded Container (UBSan IntOverflow + OOB Read + RLE Overflow)",
        "target": str(REPO_ROOT / "targets/vulnerable_vault/vuln_vault"),
        "make_dir": str(REPO_ROOT / "targets/vulnerable_vault"),
        "input_mode": "stdin",
        "checksum_mode": "crc32",
        "dict_path": str(REPO_ROOT / "configs/dictionaries/common.dict"),
    },
    "vuln_maze": {
        "label": "vuln_maze — Multi-Bug CmpLog & SanCov Benchmark (UAF + DoubleFree + Overflow + Null)",
        "target": str(REPO_ROOT / "targets/vulnerable_test/vuln_maze"),
        "make_dir": str(REPO_ROOT / "targets/vulnerable_test"),
        "input_mode": "stdin",
        "checksum_mode": "auto",
        "dict_path": str(REPO_ROOT / "configs/dictionaries/common.dict"),
    },
    "diff_quota": {
        "label": "diff_test — Differential Logic Bypass (parser_ref vs parser_buggy 16-bit Truncation)",
        "target": str(REPO_ROOT / "targets/differential_test/parser_buggy"),
        "ref_target": str(REPO_ROOT / "targets/differential_test/parser_ref"),
        "make_dir": str(REPO_ROOT / "targets/differential_test"),
        "input_mode": "differential",
        "checksum_mode": "none",
        "dict_path": None,
    },
    "vuln_net": {
        "label": "vuln_net — Loopback TCP Protocol Server (Managed Network Fuzzing)",
        "target": str(REPO_ROOT / "targets/vulnerable_net/vuln_net"),
        "make_dir": str(REPO_ROOT / "targets/vulnerable_net"),
        "input_mode": "network",
        "checksum_mode": "none",
        "dict_path": str(REPO_ROOT / "configs/dictionaries/common.dict"),
    },
    "vuln_asan": {
        "label": "vuln_asan — Stack Buffer Overflow Target (ASan + UBSan + Forkserver)",
        "target": str(REPO_ROOT / "targets/vulnerable_test/vuln_asan"),
        "make_dir": str(REPO_ROOT / "targets/vulnerable_test"),
        "input_mode": "file",
        "checksum_mode": "none",
        "dict_path": str(REPO_ROOT / "configs/dictionaries/common.dict"),
    },
}


class CampaignController:
    """Thread-safe controller managing Fuzzing, Differential Testing, and SAST Auditing."""

    def __init__(self, output_dir: str = "crashes", seed_dir: str = "seeds", reports_dir: str = "reports"):
        self._lock = threading.Lock()
        self.engine: Optional[FuzzerEngine] = None
        self.thread: Optional[threading.Thread] = None
        self.last_summary: Optional[Dict[str, Any]] = None
        self.sast_cache: Optional[Dict[str, Any]] = None
        self.output_dir = str((REPO_ROOT / output_dir).resolve())
        self.seed_dir = str((REPO_ROOT / seed_dir).resolve())
        self.reports_dir = str((REPO_ROOT / reports_dir).resolve())
        self.sandbox_caps = probe_sandbox_capabilities()

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.seed_dir).mkdir(parents=True, exist_ok=True)
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

    def ensure_targets_built(self):
        built_dirs = set()
        for preset in TARGET_PRESETS.values():
            mdir = preset["make_dir"]
            if mdir in built_dirs:
                continue
            tpath = Path(preset["target"])
            if not tpath.exists():
                try:
                    subprocess.run(["make", "-s", "-C", mdir], check=True, timeout=25)
                except Exception as exc:
                    logger.warning(f"Target build warning ({mdir}): {exc}")
            built_dirs.add(mdir)

    def run_sast_audit(self, scan_dir: str = "targets") -> Dict[str, Any]:
        resolved = (REPO_ROOT / scan_dir).resolve()
        # Restrict scan path within repository root for safety
        if REPO_ROOT.resolve() not in resolved.parents and resolved != REPO_ROOT.resolve():
            resolved = (REPO_ROOT / "targets").resolve()
        rep = StaticSourceAnalyzer().scan_path(str(resolved))
        data = rep.to_dict()
        with self._lock:
            self.sast_cache = data
        return data

    def start_campaign(self, params: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self.engine is not None and self.engine.running:
                return {"ok": False, "error": "A fuzzing campaign is already running."}

            self.ensure_targets_built()

            preset_key = str(params.get("preset", "vuln_vault"))
            preset = TARGET_PRESETS.get(preset_key, TARGET_PRESETS["vuln_vault"])
            max_iters = max(50, min(50000, int(params.get("max_iterations", 1400))))

            # Differential Fuzzing Mode
            if preset["input_mode"] == "differential":
                ref_bin = preset["ref_target"]
                cand_bin = preset["target"]

                def _diff_runner():
                    df = DifferentialFuzzer(
                        reference_target=ref_bin,
                        candidate_target=cand_bin,
                        input_mode="stdin",
                        output_dir=self.output_dir,
                        max_iterations=min(max_iters, 2000),
                        sandbox=bool(params.get("sandbox", True)),
                    )
                    res = df.run()
                    with self._lock:
                        self.last_summary = {
                            "running": False,
                            "engine_version": "3.0.0",
                            "target": f"{Path(ref_bin).name} vs {Path(cand_bin).name}",
                            "input_mode": "differential",
                            "workers": 1,
                            "forkserver_active": True,
                            "checksum_mode": "none",
                            "iterations": res["iterations"],
                            "max_iterations": res["iterations"],
                            "elapsed_sec": res["elapsed_sec"],
                            "execs_per_sec": res["execs_per_sec"],
                            "unique_crashes": res["divergences_found"],
                            "raw_crashes": res["divergences_found"],
                            "timeouts": 0,
                            "total_edges": res["total_edges"],
                            "edge_density_pct": 0.07,
                            "cmp_tokens_discovered": 4,
                            "corpus_size": len(df.corpus.entries),
                            "favored_seeds": len(df.corpus.entries),
                            "max_depth": 2,
                            "native_mutator": True,
                            "binary_info": inspect_target_binary(cand_bin),
                            "sandbox_caps": self.sandbox_caps,
                            "strategy_stats": dict(df.mutator.strategy_stats),
                            "pso_weights": df.mutator.pso.get_weights(),
                            "heatmap": [0] * 64,
                            "timeline": [],
                        }
                        ReportGenerator(self.reports_dir).generate_all(
                            session_summary=self.last_summary,
                            crash_dir=self.output_dir,
                        )

                self.thread = threading.Thread(target=_diff_runner, daemon=True)
                self.thread.start()
                return {"ok": True, "mode": "differential", "target": cand_bin}

            target_path = str(params.get("target") or preset["target"])
            input_mode = str(params.get("input_mode") or preset["input_mode"])
            workers = max(1, min(4, int(params.get("workers", 2 if input_mode != "network" else 1))))
            sandbox = bool(params.get("sandbox", True))
            auto_minimize = bool(params.get("auto_minimize", True))
            use_dict = bool(params.get("use_dict", True))
            use_forkserver = bool(params.get("use_forkserver", True))

            sdir = Path(self.seed_dir)
            if not list(sdir.glob("*")):
                (sdir / "seed_alpha.bin").write_bytes(b"AAAA1234567890")
                (sdir / "seed_ping.bin").write_bytes(b"PING\n")

            cfg = FuzzConfig(
                target=target_path,
                input_mode=input_mode,
                seed_dir=self.seed_dir,
                output_dir=self.output_dir,
                reports_dir=self.reports_dir,
                dict_path=preset["dict_path"] if use_dict else None,
                checksum_mode=preset.get("checksum_mode", "auto"),
                max_iterations=max_iters,
                workers=workers,
                use_forkserver=use_forkserver,
                enable_sast_hints=True,
                sandbox=sandbox,
                monitor_logs=False,
                enable_triage=True,
                enable_coverage=True,
                auto_minimize=auto_minimize,
                generate_report=True,
            )

            engine = FuzzerEngine(cfg)
            self.engine = engine

            def _runner():
                summary = engine.run()
                with self._lock:
                    self.last_summary = summary

            self.thread = threading.Thread(target=_runner, daemon=True)
            self.thread.start()

            return {"ok": True, "target": target_path, "input_mode": input_mode, "max_iterations": max_iters}

    def stop_campaign(self) -> Dict[str, Any]:
        with self._lock:
            if self.engine and self.engine.running:
                self.engine.stop()
                return {"ok": True, "status": "stopping"}
            return {"ok": True, "status": "idle"}

    def clear_crashes(self) -> Dict[str, Any]:
        with self._lock:
            if self.engine and self.engine.running:
                return {"ok": False, "error": "Stop active campaign before clearing crashes."}
            cdir = Path(self.output_dir)
            removed = 0
            for pattern in ("crash_*", "diff_*"):
                for f in cdir.glob(pattern):
                    if f.is_file():
                        f.unlink()
                        removed += 1
            qdir = cdir / "queue"
            if qdir.exists():
                for f in qdir.glob("*.bin"):
                    f.unlink()
            self.last_summary = None
            self.engine = None
            return {"ok": True, "removed_files": removed}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            eng = self.engine
            last = self.last_summary
            sast = self.sast_cache

        if sast is None:
            sast = self.run_sast_audit("targets")

        crashes_on_disk = load_crashes_from_dir(self.output_dir)
        divs_on_disk = load_divergences_from_dir(self.output_dir)

        if eng is not None:
            summary = eng.get_summary() if eng.running else (last or eng.get_summary())
            corpus_list = eng.corpus.list_entries(limit=30)
        elif last is not None:
            summary = dict(last)
            corpus_list = []
        else:
            default_bin = TARGET_PRESETS["vuln_vault"]["target"]
            summary = {
                "running": False,
                "engine_version": "3.0.0",
                "target": default_bin,
                "input_mode": "stdin",
                "workers": 2,
                "forkserver_active": True,
                "checksum_mode": "crc32",
                "iterations": 0,
                "max_iterations": 1400,
                "elapsed_sec": 0.0,
                "execs_per_sec": 0.0,
                "unique_crashes": len(crashes_on_disk),
                "raw_crashes": len(crashes_on_disk),
                "timeouts": 0,
                "total_edges": 0,
                "edge_density_pct": 0.0,
                "cmp_tokens_discovered": 0,
                "corpus_size": 0,
                "favored_seeds": 0,
                "max_depth": 0,
                "native_mutator": (REPO_ROOT / "native/libmutator.so").exists(),
                "binary_info": inspect_target_binary(default_bin),
                "sandbox_caps": self.sandbox_caps,
                "strategy_stats": {},
                "pso_weights": {},
                "heatmap": [0] * 64,
                "timeline": [],
            }
            corpus_list = []

        summary["saved_crashes_count"] = len(crashes_on_disk)
        summary["saved_divergences_count"] = len(divs_on_disk)
        return {
            "summary": summary,
            "presets": {
                k: {"label": v["label"], "input_mode": v["input_mode"], "target": v["target"]}
                for k, v in TARGET_PRESETS.items()
            },
            "corpus": corpus_list,
            "crashes": crashes_on_disk[:50],
            "divergences": divs_on_disk[:30],
            "sast": sast,
        }

    def get_report_html(self) -> str:
        report_file = Path(self.reports_dir) / "latest_report.html"
        status = self.get_status()
        ReportGenerator(self.reports_dir).generate_all(
            session_summary=status["summary"],
            crash_dir=self.output_dir,
            static_findings=status["sast"].get("findings", []),
        )
        if report_file.exists():
            return report_file.read_text(encoding="utf-8")
        return "<h1>No report generated yet.</h1>"

    def get_report_sarif(self) -> Dict[str, Any]:
        status = self.get_status()
        return SARIFExporter().build_sarif(
            crashes=status["crashes"],
            static_findings=status["sast"].get("findings", []),
            differential_findings=status["divergences"],
        )


def create_handler(controller: CampaignController):
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send_json(self, data: Any, status: int = HTTPStatus.OK, download_name: Optional[str] = None):
            raw = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if download_name:
                self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, html_text: str, status: int = HTTPStatus.OK):
            raw = html_text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self):
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self):
            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"

            if route in ("/", "/index.html"):
                idx_file = STATIC_DIR / "index.html"
                if idx_file.exists():
                    self._send_html(idx_file.read_text(encoding="utf-8"))
                else:
                    self._send_html("<h1>Dashboard static index.html missing</h1>", HTTPStatus.NOT_FOUND)
                return

            if route == "/api/status":
                self._send_json(controller.get_status())
                return

            if route == "/api/sast":
                self._send_json(controller.run_sast_audit("targets"))
                return

            if route == "/api/crashes":
                self._send_json({
                    "crashes": load_crashes_from_dir(controller.output_dir),
                    "divergences": load_divergences_from_dir(controller.output_dir),
                })
                return

            if route == "/api/report/html":
                self._send_html(controller.get_report_html())
                return

            if route == "/api/report/sarif":
                self._send_json(controller.get_report_sarif(), download_name="zero-hunter-results.sarif")
                return

            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self):
            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/")
            length = int(self.headers.get("Content-Length", "0") or "0")
            body_bytes = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                payload = {}

            if route == "/api/start":
                res = controller.start_campaign(payload)
                code = HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT
                self._send_json(res, code)
                return

            if route == "/api/stop":
                self._send_json(controller.stop_campaign())
                return

            if route == "/api/clear":
                res = controller.clear_crashes()
                code = HTTPStatus.OK if res.get("ok") else HTTPStatus.CONFLICT
                self._send_json(res, code)
                return

            if route == "/api/sast":
                scan_dir = str(payload.get("path", "targets"))
                self._send_json(controller.run_sast_audit(scan_dir))
                return

            self._send_json({"error": "Unknown endpoint"}, HTTPStatus.NOT_FOUND)

    return DashboardHandler


def run_dashboard_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    output_dir: str = "crashes",
    seed_dir: str = "seeds",
    reports_dir: str = "reports",
    auto_demo: bool = False,
):
    controller = CampaignController(output_dir=output_dir, seed_dir=seed_dir, reports_dir=reports_dir)
    controller.ensure_targets_built()
    controller.run_sast_audit("targets")

    if auto_demo and not load_crashes_from_dir(controller.output_dir):
        logger.info("[*] Starting initial v3.0 Forkserver + CRC32 Vault campaign for live telemetry...")
        controller.start_campaign({"preset": "vuln_vault", "max_iterations": 1200, "workers": 2})

    handler_cls = create_handler(controller)
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((host, port), handler_cls)
    logger.info(f"[*] Zero-Hunter v3.0 Mission Control listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[*] Shutting down Mission Control server")
    finally:
        controller.stop_campaign()
        server.server_close()


if __name__ == "__main__":
    run_dashboard_server()
