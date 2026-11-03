#!/usr/bin/env python3
"""
Comprehensive Test Suite for Zero-Hunter-Engine v3.0 (Apex Edition)
Tests:
  - SanitizerCoverage + ASLR-invariant edge bitmap + CmpLog I2S
  - Persistent UNIX Pipe Forkserver (`ZH30` handshake & crash isolation)
  - Hybrid SAST Source-Code Scanner & Magic/Checksum Hint Extraction
  - MOpt Particle Swarm Optimization (PSO) Mutation Operator Scheduler
  - Native C++17 Mutator + Grammar & CRC32 Checksum-Aware Fuzzing (`vuln_vault`)
  - Differential Fuzzing Engine (`parser_ref` vs `parser_buggy` logic bypass)
  - Root-Cause Source Localization (`file:line`), Defensive Patch Advisor & SARIF v2.1.0
  - Campaign Checkpointing & Mission Control v3.0 API
"""

import json
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from core.checkpoint import CampaignCheckpointer
from core.corpus import CorpusManager
from core.coverage import CoverageTracker
from core.differential import DifferentialFuzzer
from core.forkserver import ForkserverExecutor
from core.fuzzer_engine import FuzzConfig, FuzzerEngine
from core.grammar import ChecksumPatcher, GrammarEngine
from core.minimizer import CrashMinimizer
from core.mutator import MutatorEngine, _parse_afl_dict_line
from core.network_fuzzer import NetworkFuzzer
from core.pso_scheduler import MOptPSOScheduler
from core.remediation import RootCauseLocalizer
from core.static_analyzer import StaticSourceAnalyzer
from core.triage import CrashTriage, RiskLevel
from dashboard.server import CampaignController
from utils.process_manager import ProcessManager
from utils.sandbox import inspect_target_binary, probe_sandbox_capabilities


@pytest.fixture(scope="session", autouse=True)
def build_all_artifacts():
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "instrumentation")], check=True)
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "native")], check=True)
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "targets/vulnerable_test")], check=True)
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "targets/vulnerable_net")], check=True)
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "targets/vulnerable_vault")], check=True)
    subprocess.run(["make", "-s", "-C", str(REPO_ROOT / "targets/differential_test")], check=True)


def test_aslr_invariant_coverage_and_cmplog():
    maze_bin = str(REPO_ROOT / "targets/vulnerable_test/vuln_maze")
    cov = CoverageTracker()
    pm = ProcessManager()
    try:
        cov.reset_trace()
        r1 = pm.spawn([maze_bin, "-"], stdin_data=b"AAAA12345678", cov_file=cov.cov_file_path)
        obs1 = cov.evaluate_run(r1["stdout"], r1["stderr"], r1["returncode"])
        assert obs1.instrumented is True
        assert obs1.has_new_edges is True
        edges_after_1 = cov.get_stats()["total_edges"]
        assert edges_after_1 > 5

        cov.reset_trace()
        r2 = pm.spawn([maze_bin, "-"], stdin_data=b"AAAA12345678", cov_file=cov.cov_file_path)
        obs2 = cov.evaluate_run(r2["stdout"], r2["stderr"], r2["returncode"])
        assert obs2.has_new_edges is False
        assert cov.get_stats()["total_edges"] == edges_after_1

        cov.reset_trace()
        r3 = pm.spawn([maze_bin, "-"], stdin_data=b"ZH26UFAABBCCDD", cov_file=cov.cov_file_path)
        obs3 = cov.evaluate_run(r3["stdout"], r3["stderr"], r3["returncode"])
        assert obs3.has_new_edges is True
        assert cov.get_stats()["total_edges"] > edges_after_1

        tokens = cov.get_cmp_tokens()
        assert b"ZH26" in tokens
    finally:
        cov.close()


def test_forkserver_executor_throughput_and_crash_isolation():
    maze_bin = str(REPO_ROOT / "targets/vulnerable_test/vuln_maze")
    cov = CoverageTracker()
    fs = ForkserverExecutor(
        target=maze_bin,
        input_mode="stdin",
        cov_file=cov.cov_file_path,
        timeout=1.5,
        sandbox=True,
    )
    try:
        assert fs.is_supported is True
        assert fs.start() is True

        # Safe run records SanCov edges
        cov.reset_trace()
        r_ok = fs.execute(b"SAFE_PAYLOAD")
        obs = cov.evaluate_run(r_ok["stdout"], r_ok["stderr"], r_ok["returncode"])
        assert r_ok["crashed"] is False
        assert r_ok["forkserver"] is True
        assert obs.run_edges > 5

        # Crash inside child does NOT kill persistent forkserver parent
        r_crash = fs.execute(b"ZH26UF\x11\x22FREE_BOOM")
        assert r_crash["crashed"] is True

        # Rapid 60-exec burst through forkserver after crash
        t0 = time.monotonic()
        for _ in range(60):
            res = fs.execute(b"FAST_FORK_TEST")
            assert res["crashed"] is False
        elapsed = max(time.monotonic() - t0, 1e-4)
        assert (60.0 / elapsed) > 120.0
    finally:
        fs.stop()
        cov.close()


def test_static_source_analyzer_sast_and_token_extraction():
    sast = StaticSourceAnalyzer()
    vault_rep = sast.scan_path(str(REPO_ROOT / "targets/vulnerable_vault"))
    assert vault_rep.files_scanned >= 1
    assert vault_rep.detected_checksum == "crc32"
    assert b"ZHV3" in vault_rep.extracted_tokens
    cwes = {f.cwe for f in vault_rep.findings}
    assert "CWE-190" in cwes or "CWE-787" in cwes

    full_rep = sast.scan_path(str(REPO_ROOT / "targets"))
    assert len(full_rep.findings) >= 8


def test_mopt_pso_adaptive_scheduler():
    ops = ["havoc", "cmplog", "checksum", "grammar"]
    pso = MOptPSOScheduler(operators=ops, swarm_size=3, epoch_budget=30)
    for _ in range(300):
        chosen = pso.sample_operator()
        if chosen == "checksum":
            pso.record_reward("checksum", weight=5)
    weights = pso.get_weights()
    eff = pso.get_efficiency_summary()
    assert eff["checksum"]["finds"] > 0
    assert weights["checksum"] > weights["grammar"]


def test_native_mutator_grammar_and_checksum_patcher():
    mut = MutatorEngine(dict_path=str(REPO_ROOT / "configs/dictionaries/common.dict"))
    assert mut.native_enabled is True
    assert _parse_afl_dict_line('magic="\\xef\\xbe\\xad\\xde"') == b"\xef\xbe\xad\xde"

    i2s = mut.mutate_cmplog(b"AAAA_payload", [(b"AAAA", b"ZH26")])
    assert i2s is not None and i2s.startswith(b"ZH26")

    # Grammar synthesis
    ge = GrammarEngine("json")
    g_sample = ge.generate()
    assert isinstance(json.loads(g_sample.decode("utf-8")), dict)

    # ChecksumPatcher repairs ZHV3 CRC32 header (`[6..9]` == crc32(`frame[10:]`))
    raw = b"ZHV3\x04\x00\x00\x00\x00\x00\x01\x00ABCD"
    frame = ChecksumPatcher.repair_payload(raw, mode="crc32")
    assert frame[:4] == b"ZHV3"
    crc_hdr = struct.unpack_from("<I", frame, 6)[0]
    assert crc_hdr == (zlib.crc32(frame[10:]) & 0xFFFFFFFF)


def test_corpus_energy_and_cmin_distillation():
    cm = CorpusManager()
    e1 = cm.add_seed(b"short_fast", exec_time_ms=0.5, edges_count=20, edge_indices=[1, 2, 3, 4], persist=False)
    e2 = cm.add_seed(b"long_slow" * 50, exec_time_ms=10.0, edges_count=4, edge_indices=[1, 2], persist=False)
    assert e1 is not None and e2 is not None
    e1.fuzz_count = 1
    e2.fuzz_count = 1
    cm.cull_favored()
    assert e1.favored is True
    assert e2.favored is False
    assert cm.assign_energy(e1) >= cm.assign_energy(e2)

    fake_map = {
        b"s_long_12": {10, 20},
        b"s1": {10, 20},
        b"s2": {20, 30},
        b"s_redundant": {10},
    }
    distilled = CorpusManager.minimize_corpus(list(fake_map.keys()), lambda b: fake_map[b])
    assert set(distilled) == {b"s1", b"s2"}


def test_sandbox_seccomp_and_asan_compatibility():
    caps = probe_sandbox_capabilities()
    assert caps["linux"] is True
    assert caps["seccomp_bpf"] is True

    vault_bin = str(REPO_ROOT / "targets/vulnerable_vault/vuln_vault")
    binfo = inspect_target_binary(vault_bin)
    assert binfo["uses_asan"] is True
    assert binfo["uses_ubsan"] is True
    assert binfo["uses_sancov"] is True

    pm = ProcessManager()
    ok = pm.spawn([vault_bin, "-"], stdin_data=b"INVALID_HDR", sandbox=True)
    assert ok["crashed"] is False

    blocked = pm.spawn(["python3", "-c", "import socket; socket.socket()"], sandbox=True)
    assert blocked["returncode"] != 0


def test_deep_triage_root_cause_and_crash_minimizer():
    maze_bin = str(REPO_ROOT / "targets/vulnerable_test/vuln_maze")
    pm = ProcessManager()
    triage = CrashTriage()
    localizer = RootCauseLocalizer(REPO_ROOT)
    exec_fn = lambda data: pm.spawn([maze_bin, "-"], stdin_data=data)

    uaf_bloated = b"ZH26UF\x11\x22FREE" + bytes(range(96))
    r_uaf = exec_fn(uaf_bloated)
    assert r_uaf["crashed"] is True
    tr_uaf = triage.analyze(r_uaf)
    assert tr_uaf.risk == RiskLevel.HIGH
    assert "CWE-416" in tr_uaf.cwe

    # RootCauseLocalizer pinpoints vuln_maze.c line & patch advice
    rc = localizer.localize(tr_uaf.cwe, tr_uaf.stack_frames)
    assert rc.source_file is not None and "vuln_maze.c" in rc.source_file
    assert rc.line_number is not None and rc.line_number > 0
    assert len(rc.secure_code_example) > 15

    minimizer = CrashMinimizer(exec_fn, triage=triage, max_steps=180)
    mres = minimizer.minimize(uaf_bloated)
    assert mres.reproducible is True
    assert mres.minimized_size <= 20


def test_differential_fuzzer_logic_bug_discovery(tmp_path: Path):
    diff_out = tmp_path / "diff_crashes"
    df = DifferentialFuzzer(
        reference_target=str(REPO_ROOT / "targets/differential_test/parser_ref"),
        candidate_target=str(REPO_ROOT / "targets/differential_test/parser_buggy"),
        input_mode="stdin",
        output_dir=str(diff_out),
        max_iterations=450,
    )
    res = df.run()
    assert res["divergences_found"] >= 1
    div = res["findings"][0]
    assert div["cwe"] == "CWE-681"
    assert "DENY" in div["ref_stdout"]
    assert "ALLOW:" in div["cand_stdout"]


def test_network_fuzzer_managed_tcp():
    net_bin = str(REPO_ROOT / "targets/vulnerable_net/vuln_net")
    cov = CoverageTracker()
    nf = NetworkFuzzer(net_bin, cov_file=cov.cov_file_path)
    triage = CrashTriage()
    try:
        cov.reset_trace()
        r_ping = nf.send_payload(b"PING\n")
        obs = cov.evaluate_run(r_ping["stdout"], r_ping["stderr"], r_ping["returncode"])
        assert r_ping["crashed"] is False
        assert r_ping["response"] == b"PONG\n"
        assert obs.run_edges > 5

        r_crash = nf.send_payload(b"AUTH " + b"A" * 72)
        assert r_crash["crashed"] is True
        tr = triage.analyze(r_crash)
        assert tr.risk == RiskLevel.HIGH
        assert "CWE-787" in tr.cwe
    finally:
        nf.stop()
        cov.close()


def test_v3_crc32_vault_campaign_sarif_checkpoint_and_dashboard(tmp_path: Path):
    seed_dir = tmp_path / "seeds"
    crash_dir = tmp_path / "crashes"
    rep_dir = tmp_path / "reports"
    ckpt_file = tmp_path / "vault_ckpt.json"
    seed_dir.mkdir()
    (seed_dir / "s0.bin").write_bytes(b"AAAA")

    cfg = FuzzConfig(
        target=str(REPO_ROOT / "targets/vulnerable_vault/vuln_vault"),
        input_mode="file",
        seed_dir=str(seed_dir),
        output_dir=str(crash_dir),
        reports_dir=str(rep_dir),
        checksum_mode="auto",
        use_forkserver=True,
        checkpoint_path=str(ckpt_file),
        max_iterations=700,
        workers=2,
        monitor_logs=False,
        auto_minimize=True,
        generate_report=True,
    )
    summary = FuzzerEngine(cfg).run()
    assert summary["forkserver_active"] is True
    assert summary["checksum_mode"] == "crc32"
    assert summary["sast_findings_count"] >= 2
    assert summary["unique_crashes"] >= 1
    assert ckpt_file.exists()

    # Check SARIF v2.1.0 report schema
    sarif_path = rep_dir / "latest_report.sarif"
    assert sarif_path.exists()
    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) >= 2

    # Check Checkpoint reload into a fresh FuzzerEngine
    resumed_engine = FuzzerEngine(cfg)
    try:
        assert CampaignCheckpointer.load(resumed_engine, str(ckpt_file)) is True
        assert len(resumed_engine.corpus.entries) >= 1
        assert resumed_engine.coverage.total_edges >= 20
    finally:
        if resumed_engine.coverage:
            resumed_engine.coverage.close()

    # Check Mission Control v3.0 Controller
    ctrl = CampaignController(
        output_dir=str(crash_dir),
        seed_dir=str(seed_dir),
        reports_dir=str(rep_dir),
    )
    st = ctrl.get_status()
    assert st["summary"]["saved_crashes_count"] >= 1
    assert len(ctrl.run_sast_audit("targets")["findings"]) >= 5
    assert ctrl.get_report_sarif()["version"] == "2.1.0"
