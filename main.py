#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 (Apex Edition) - Unified CLI Entry Point
Supports:
  python3 main.py                                           # Default turbo fuzzing run
  python3 main.py fuzz --config configs/vault_crc32.yaml    # Forkserver + CRC32 + SAST + PSO campaign
  python3 main.py audit targets/                            # Hybrid C/C++ SAST vulnerability & hotspot scan
  python3 main.py diff --ref A --target B                   # Differential logic-bug fuzzing
  python3 main.py minimize <crash.bin> --target ...         # Checksum-aware delta-debugging (tmin)
  python3 main.py cmin --seed-dir ... --out-dir ...         # Greedy edge-cover corpus minimizer (cmin)
  python3 main.py triage --crash-dir crashes                # Inspect triaged findings & root-cause lines
  python3 main.py report --crash-dir crashes                # Generate HTML / SARIF / Markdown / JSON reports
  python3 main.py sarif --out reports/results.sarif         # Export OASIS SARIF v2.1.0 report
  python3 main.py dashboard --port 8080 --demo              # Launch live Web Mission Control v3.0

Educational & Authorized Defensive Research Only
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Set

from core.corpus import CorpusManager
from core.coverage import CoverageTracker
from core.differential import DifferentialFuzzer
from core.fuzzer_engine import FuzzConfig, FuzzerEngine
from core.minimizer import CrashMinimizer
from core.reporter import (
    ReportGenerator,
    load_crashes_from_dir,
    load_divergences_from_dir,
)
from core.sarif_exporter import SARIFExporter
from core.static_analyzer import StaticSourceAnalyzer
from utils.logger import setup_logger
from utils.process_manager import ProcessManager

logger = setup_logger("cli")


def _ensure_default_target_and_seeds() -> str:
    target_dir = Path("targets/vulnerable_test")
    asan_bin = target_dir / "vuln_asan"
    plain_bin = target_dir / "vuln"

    if not asan_bin.exists() and (target_dir / "Makefile").exists():
        try:
            subprocess.run(["make", "-s", "-C", str(target_dir)], check=True, timeout=25)
        except Exception:
            pass

    target = str(asan_bin) if asan_bin.exists() else str(plain_bin)

    seed_dir = Path("seeds")
    seed_dir.mkdir(exist_ok=True)
    if not list(seed_dir.glob("*")):
        (seed_dir / "seed1.bin").write_bytes(b"A" * 24)
        (seed_dir / "seed2.bin").write_bytes(b"B" * 48)
        (seed_dir / "seed3.bin").write_bytes(b"AAAA12345678")
        (seed_dir / "seed4.bin").write_bytes(b"PING\n")

    return f"./{target}" if not target.startswith(("./", "/")) else target


def cmd_fuzz(args: argparse.Namespace) -> int:
    if args.config:
        cfg = FuzzConfig.from_yaml(args.config)
    else:
        default_target = args.target or _ensure_default_target_and_seeds()
        default_dict = "configs/dictionaries/common.dict"
        cfg = FuzzConfig(
            target=default_target,
            dict_path=default_dict if Path(default_dict).exists() else None,
            max_iterations=1500,
            workers=2,
        )

    if args.target:
        cfg.target = args.target
    if args.mode:
        cfg.input_mode = args.mode
    if args.iterations is not None:
        cfg.max_iterations = args.iterations
    if args.workers is not None:
        cfg.workers = args.workers
    if args.seed_dir:
        cfg.seed_dir = args.seed_dir
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.dict_path:
        cfg.dict_path = args.dict_path
    if getattr(args, "grammar", None):
        cfg.grammar_spec = args.grammar
    if getattr(args, "checksum", None):
        cfg.checksum_mode = args.checksum
    if getattr(args, "checkpoint", None):
        cfg.checkpoint_path = args.checkpoint
    if args.port is not None:
        cfg.network_port = args.port
    if args.host:
        cfg.network_host = args.host
    if args.protocol:
        cfg.network_protocol = args.protocol
    if getattr(args, "no_forkserver", False):
        cfg.use_forkserver = False
    if args.no_sandbox:
        cfg.sandbox = False
    if args.no_minimize:
        cfg.auto_minimize = False

    engine = FuzzerEngine(cfg)
    engine.run()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    analyzer = StaticSourceAnalyzer()
    rep = analyzer.scan_path(args.path)
    logger.info(
        f"[*] SAST Audit scanned {rep.files_scanned} C/C++ file(s) → "
        f"{len(rep.findings)} hotspot(s) | Checksum hint: {rep.detected_checksum or 'none'}"
    )
    for f in rep.findings:
        logger.info(
            f"  [{f.severity}] {f.cwe} ({f.rule_id}) {f.file_path}:{f.line} — {f.title}\n"
            f"         Code : {f.code_snippet}\n"
            f"         Fix  : {f.remediation}"
        )
    if args.out_dict and rep.extracted_tokens:
        out_p = Path(args.out_dict)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        lines = [f'tok_{i}="' + "".join(f"\\x{b:02x}" for b in tok) + '"' for i, tok in enumerate(rep.extracted_tokens)]
        out_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info(f"[*] Exported {len(lines)} extracted source constants → {out_p}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    df = DifferentialFuzzer(
        reference_target=args.ref,
        candidate_target=args.target,
        input_mode=args.mode,
        output_dir=args.output_dir,
        max_iterations=args.iterations,
        sandbox=not args.no_sandbox,
    )
    res = df.run()
    logger.info(
        f"[*] Differential Fuzzing complete ({res['execs_per_sec']} exec/s) → "
        f"{res['divergences_found']} logic/behavioral divergence(s) saved in {args.output_dir}"
    )
    return 0


def cmd_minimize(args: argparse.Namespace) -> int:
    crash_path = Path(args.crash_file)
    if not crash_path.is_file():
        logger.error(f"Crash file not found: {crash_path}")
        return 1

    payload = crash_path.read_bytes()
    pm = ProcessManager()
    tmp_path = Path(tempfile.gettempdir()) / f"zh_cli_min_{os.getpid()}.bin"

    def _exec(cand: bytes):
        if args.mode == "stdin":
            return pm.spawn([args.target], stdin_data=cand, timeout=args.timeout, sandbox=not args.no_sandbox)
        tmp_path.write_bytes(cand)
        return pm.spawn([args.target, str(tmp_path)], timeout=args.timeout, sandbox=not args.no_sandbox)

    try:
        minimizer = CrashMinimizer(_exec, max_steps=args.max_steps, checksum_mode=args.checksum)
        res = minimizer.minimize(payload)
        if not res.reproducible:
            logger.error("Target did not crash on the supplied input; cannot minimize.")
            return 2

        out_path = Path(args.out) if args.out else crash_path.with_suffix(".min.bin")
        out_path.write_bytes(res.minimized_payload)
        logger.info(
            f"[*] Saved minimized crash ({res.original_size}B → {res.minimized_size}B, "
            f"-{res.reduction_pct:.1f}%) to {out_path}"
        )
        return 0
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def cmd_cmin(args: argparse.Namespace) -> int:
    in_dir = Path(args.seed_dir)
    out_dir = Path(args.out_dir)
    if not in_dir.is_dir():
        logger.error(f"Seed directory not found: {in_dir}")
        return 1

    seeds: List[bytes] = [f.read_bytes() for f in sorted(in_dir.glob("*")) if f.is_file()]
    if not seeds:
        logger.warning("No seed files found to minimize.")
        return 0

    cov = CoverageTracker()
    pm = ProcessManager()
    tmp_path = Path(tempfile.gettempdir()) / f"zh_cli_cmin_{os.getpid()}.bin"

    def _trace(data: bytes) -> Set[int]:
        cov.reset_trace()
        if args.mode == "stdin":
            r = pm.spawn([args.target], stdin_data=data, cov_file=cov.cov_file_path)
        else:
            tmp_path.write_bytes(data)
            r = pm.spawn([args.target, str(tmp_path)], cov_file=cov.cov_file_path)
        obs = cov.evaluate_run(r["stdout"], r["stderr"], r["returncode"])
        return set(obs.edge_indices)

    try:
        distilled = CorpusManager.minimize_corpus(seeds, _trace)
        out_dir.mkdir(parents=True, exist_ok=True)
        for idx, blob in enumerate(distilled):
            (out_dir / f"min_seed_{idx:04d}.bin").write_bytes(blob)
        logger.info(
            f"[*] Corpus minimization complete: {len(seeds)} seeds → {len(distilled)} seeds in {out_dir}"
        )
        return 0
    finally:
        cov.close()
        if tmp_path.exists():
            tmp_path.unlink()


def cmd_triage(args: argparse.Namespace) -> int:
    records = load_crashes_from_dir(args.crash_dir)
    divs = load_divergences_from_dir(args.crash_dir)
    if not records and not divs:
        logger.info(f"No crash or divergence artifacts found in {args.crash_dir}")
        return 0

    if records:
        logger.info(f"[*] Loaded {len(records)} unique crash record(s) from {args.crash_dir}:")
        for rec in records:
            tr = rec.get("triage", {})
            rc = rec.get("root_cause", {}) or {}
            loc = f"{Path(rc['source_file']).name}:{rc['line_number']}" if rc.get("source_file") else "n/a"
            logger.info(
                f"  • {rec['crash_id']} | {tr.get('risk', 'Unknown')} | "
                f"{tr.get('bug_class', 'n/a')} | {tr.get('cwe', 'n/a')} | "
                f"Source={loc} | Raw={rec.get('raw_size', 0)}B Min={rec.get('min_size', 'n/a')}"
            )
    if divs:
        logger.info(f"[*] Loaded {len(divs)} differential logic divergence(s):")
        for d in divs:
            logger.info(
                f"  • {d['diff_id']} | {d['category']} ({d['cwe']}) | "
                f"ref='{d['ref_stdout']}' vs cand='{d['cand_stdout']}' | {d['minimized_size']}B"
            )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    records = load_crashes_from_dir(args.crash_dir)
    sast_rep = StaticSourceAnalyzer().scan_path(args.sast_dir) if Path(args.sast_dir).exists() else None
    summary = {
        "target": args.target or "offline-crash-directory",
        "input_mode": "offline",
        "iterations": 0,
        "execs_per_sec": 0.0,
        "total_edges": 0,
        "corpus_size": 0,
        "unique_crashes": len(records),
        "heatmap": [0] * 64,
    }
    paths = ReportGenerator(args.reports_dir).generate_all(
        session_summary=summary,
        crash_dir=args.crash_dir,
        base_name=args.name,
        static_findings=[f.to_dict() for f in sast_rep.findings] if sast_rep else [],
    )
    logger.info(f"[*] HTML Report  : {paths['html']}")
    logger.info(f"[*] SARIF v2.1.0 : {paths['sarif']}")
    logger.info(f"[*] MD Report    : {paths['markdown']}")
    logger.info(f"[*] JSON Report  : {paths['json']}")
    return 0


def cmd_sarif(args: argparse.Namespace) -> int:
    crashes = load_crashes_from_dir(args.crash_dir)
    divs = load_divergences_from_dir(args.crash_dir)
    sast_findings = []
    if args.sast_path and Path(args.sast_path).exists():
        sast_findings = [f.to_dict() for f in StaticSourceAnalyzer().scan_path(args.sast_path).findings]
    out = SARIFExporter().export_to_file(
        args.out,
        crashes=crashes,
        static_findings=sast_findings,
        differential_findings=divs,
    )
    logger.info(f"[*] Exported OASIS SARIF v2.1.0 report ({len(crashes)} crashes, {len(divs)} diffs, {len(sast_findings)} SAST) → {out}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from dashboard.server import run_dashboard_server

    run_dashboard_server(
        host=args.host,
        port=args.port,
        output_dir=args.crash_dir,
        seed_dir=args.seed_dir,
        reports_dir=args.reports_dir,
        auto_demo=args.demo,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zero-hunter",
        description="Zero-Hunter-Engine v3.0 — Apex Coverage-Guided, Forkserver, SAST & Differential Fuzzing Framework",
    )
    parser.add_argument("--config", help="YAML config path (shorthand for `fuzz --config`)")
    parser.add_argument("--dashboard", action="store_true", help="Launch live Web Mission Control server")

    sub = parser.add_subparsers(dest="command")

    # fuzz
    p_fuzz = sub.add_parser("fuzz", help="Run Forkserver + SanCov + PSO + Checksum fuzzing campaign")
    p_fuzz.add_argument("-c", "--config", help="Path to YAML configuration file")
    p_fuzz.add_argument("-t", "--target", help="Target binary path")
    p_fuzz.add_argument("-m", "--mode", choices=["file", "stdin", "network"], help="Input delivery mode")
    p_fuzz.add_argument("-n", "--iterations", type=int, help="Maximum fuzzing iterations")
    p_fuzz.add_argument("-w", "--workers", type=int, help="Number of parallel workers")
    p_fuzz.add_argument("-s", "--seed-dir", help="Initial seed corpus directory")
    p_fuzz.add_argument("-o", "--output-dir", help="Crash output directory")
    p_fuzz.add_argument("-x", "--dict", dest="dict_path", help="AFL-compatible token dictionary")
    p_fuzz.add_argument("-g", "--grammar", help="Grammar spec (`json`, `http`, or `.json` file)")
    p_fuzz.add_argument("--checksum", choices=["auto", "crc32", "adler32", "none"], help="Container checksum repair mode")
    p_fuzz.add_argument("--checkpoint", help="Save/resume campaign state JSON path")
    p_fuzz.add_argument("--host", help="Target host for network mode (default 127.0.0.1)")
    p_fuzz.add_argument("--port", type=int, help="Target port for network mode (0 = ephemeral)")
    p_fuzz.add_argument("--protocol", choices=["tcp", "udp"], help="Network protocol")
    p_fuzz.add_argument("--no-forkserver", action="store_true", help="Disable persistent UNIX forkserver")
    p_fuzz.add_argument("--no-sandbox", action="store_true", help="Disable Linux sandbox")
    p_fuzz.add_argument("--no-minimize", action="store_true", help="Skip automatic crash minimization")

    # audit (SAST)
    p_aud = sub.add_parser("audit", help="Static C/C++ vulnerability hotspot scan & dictionary synthesis")
    p_aud.add_argument("path", nargs="?", default="targets", help="Source file or directory to scan")
    p_aud.add_argument("--out-dict", help="Optional path to export extracted magic constants as AFL .dict")

    # diff (Differential Fuzzing)
    p_diff = sub.add_parser("diff", help="Differential fuzzing between reference and candidate binaries")
    p_diff.add_argument("--ref", required=True, help="Reference implementation binary")
    p_diff.add_argument("-t", "--target", required=True, help="Candidate implementation binary")
    p_diff.add_argument("-m", "--mode", choices=["file", "stdin"], default="stdin")
    p_diff.add_argument("-n", "--iterations", type=int, default=800)
    p_diff.add_argument("-o", "--output-dir", default="crashes")
    p_diff.add_argument("--no-sandbox", action="store_true")

    # minimize (tmin)
    p_min = sub.add_parser("minimize", help="Delta-debug & shrink a crashing input (tmin)")
    p_min.add_argument("crash_file", help="Path to crashing .bin payload")
    p_min.add_argument("-t", "--target", required=True, help="Target binary path")
    p_min.add_argument("-m", "--mode", choices=["file", "stdin"], default="file")
    p_min.add_argument("--checksum", choices=["none", "crc32"], default="none")
    p_min.add_argument("-o", "--out", help="Output path for minimized payload")
    p_min.add_argument("--timeout", type=float, default=2.0)
    p_min.add_argument("--max-steps", type=int, default=250)
    p_min.add_argument("--no-sandbox", action="store_true")

    # cmin
    p_cmin = sub.add_parser("cmin", help="Distill seed directory to minimal edge-covering set (cmin)")
    p_cmin.add_argument("-s", "--seed-dir", required=True, help="Input seed directory")
    p_cmin.add_argument("-o", "--out-dir", required=True, help="Output minimized corpus directory")
    p_cmin.add_argument("-t", "--target", required=True, help="Instrumented target binary")
    p_cmin.add_argument("-m", "--mode", choices=["file", "stdin"], default="file")

    # triage
    p_tri = sub.add_parser("triage", help="Display structured triage & source root-cause summary")
    p_tri.add_argument("-d", "--crash-dir", default="crashes")

    # report
    p_rep = sub.add_parser("report", help="Generate HTML, SARIF v2.1.0, Markdown, and JSON reports")
    p_rep.add_argument("-d", "--crash-dir", default="crashes")
    p_rep.add_argument("-r", "--reports-dir", default="reports")
    p_rep.add_argument("--sast-dir", default="targets")
    p_rep.add_argument("-t", "--target", default="")
    p_rep.add_argument("--name", default="latest_report")

    # sarif
    p_sar = sub.add_parser("sarif", help="Export OASIS SARIF v2.1.0 results for GitHub / IDE Code Scanning")
    p_sar.add_argument("-d", "--crash-dir", default="crashes")
    p_sar.add_argument("--sast-path", default="targets")
    p_sar.add_argument("-o", "--out", default="reports/latest_report.sarif")

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Start real-time Web Mission Control v3.0 UI")
    p_dash.add_argument("--host", default="0.0.0.0")
    p_dash.add_argument("-p", "--port", type=int, default=8080)
    p_dash.add_argument("--crash-dir", default="crashes")
    p_dash.add_argument("--seed-dir", default="seeds")
    p_dash.add_argument("--reports-dir", default="reports")
    p_dash.add_argument("--demo", action="store_true", help="Auto-run initial CRC32 Vault campaign")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dashboard:
        ns = argparse.Namespace(
            host="0.0.0.0",
            port=8080,
            crash_dir="crashes",
            seed_dir="seeds",
            reports_dir="reports",
            demo=True,
        )
        return cmd_dashboard(ns)

    if args.command is None:
        fuzz_ns = argparse.Namespace(
            config=args.config,
            target=None,
            mode=None,
            iterations=1000 if not args.config else None,
            workers=None,
            seed_dir=None,
            output_dir=None,
            dict_path=None,
            grammar=None,
            checksum=None,
            checkpoint=None,
            host=None,
            port=None,
            protocol=None,
            no_forkserver=False,
            no_sandbox=False,
            no_minimize=False,
        )
        return cmd_fuzz(fuzz_ns)

    dispatch = {
        "fuzz": cmd_fuzz,
        "audit": cmd_audit,
        "diff": cmd_diff,
        "minimize": cmd_minimize,
        "cmin": cmd_cmin,
        "triage": cmd_triage,
        "report": cmd_report,
        "sarif": cmd_sarif,
        "dashboard": cmd_dashboard,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
