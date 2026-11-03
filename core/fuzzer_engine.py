#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Apex Coverage-Guided, Forkserver & Hybrid SAST/DAST Engine
Integrates:
- Persistent UNIX Pipe Forkserver (`ForkserverExecutor`) for 5x-10x turbo throughput
- SanitizerCoverage (trace-pc + trace-cmp) 64KB ASLR-invariant bitmap & CmpLog I2S
- Hybrid SAST Source-Code Pre-Scanner (`StaticSourceAnalyzer`) for magic token & CRC hints
- Dynamic Corpus Manager with AFLFast exponential energy scheduling
- MOpt Particle Swarm Optimization (PSO) + C++17 Native + Grammar + Checksum Mutators
- Multi-layer Linux Sandbox (namespaces + seccomp-bpf + ASan/UBSan awareness)
- File, Stdin, and TCP/UDP Network Protocol fuzzing modes
- Deep ASan/UBSan/Signal Triage, Root-Cause Source Localization, `tmin` & SARIF v2.1.0

Educational & Authorized Defensive Research Only
"""

import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.checkpoint import CampaignCheckpointer
from core.corpus import CorpusManager, SeedEntry
from core.coverage import CoverageObservation, CoverageTracker
from core.forkserver import ForkserverExecutor
from core.minimizer import CrashMinimizer
from core.mutator import MutatorEngine
from core.network_fuzzer import NetworkConfig, NetworkFuzzer
from core.pso_scheduler import MOptPSOScheduler
from core.remediation import RootCauseLocalizer
from core.reporter import ReportGenerator
from core.static_analyzer import StaticSourceAnalyzer
from core.triage import CrashTriage, TriageResult
from utils.crash_monitor import CrashMonitor
from utils.logger import setup_logger
from utils.process_manager import ProcessLimits, ProcessManager
from utils.sandbox import inspect_target_binary, probe_sandbox_capabilities

logger = setup_logger("fuzzer_engine")


def _load_yaml_dict(path: str) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else {}
    except ImportError:
        out: Dict[str, Any] = {}
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if v.lower() in ("true", "yes"):
                out[k] = True
            elif v.lower() in ("false", "no"):
                out[k] = False
            else:
                try:
                    out[k] = int(v) if "." not in v else float(v)
                except ValueError:
                    out[k] = v
        return out


@dataclass
class FuzzConfig:
    target: str
    input_mode: str = "file"            # "file" | "stdin" | "network"
    seed_dir: str = "seeds"
    output_dir: str = "crashes"
    reports_dir: str = "reports"
    dict_path: Optional[str] = None
    grammar_spec: Optional[str] = None
    checksum_mode: str = "auto"         # "auto" | "crc32" | "adler32" | "none"
    checkpoint_path: Optional[str] = None
    timeout: float = 1.5
    max_iterations: int = 3000
    mutation_rate: float = 0.18
    max_input_size: int = 4096
    workers: int = 1
    use_forkserver: bool = True
    enable_sast_hints: bool = True
    sandbox: bool = True
    enable_namespaces: bool = True
    enable_seccomp: bool = True
    memory_mb: int = 256
    monitor_logs: bool = True
    enable_triage: bool = True
    enable_coverage: bool = True
    auto_minimize: bool = True
    generate_report: bool = True
    # Network protocol mode parameters
    network_host: str = "127.0.0.1"
    network_port: int = 0
    network_protocol: str = "tcp"
    network_framing: str = "raw"
    managed_server: bool = True
    server_args: str = "--port {port}"

    @classmethod
    def from_yaml(cls, path: str) -> "FuzzConfig":
        raw = _load_yaml_dict(path)
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
        filtered = {k: v for k, v in raw.items() if k in valid_fields and v is not None}
        if "target" not in filtered:
            filtered["target"] = "./targets/vulnerable_test/vuln_asan"
        return cls(**filtered)


class FuzzerEngine:
    def __init__(self, config: FuzzConfig):
        self.config = config
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        isolate_net = config.input_mode != "network"
        self.process_mgr = ProcessManager(
            ProcessLimits(
                cpu_seconds=max(2, int(config.timeout) + 1),
                memory_mb=config.memory_mb,
                enable_namespaces=config.enable_namespaces,
                enable_seccomp=config.enable_seccomp,
                isolate_network=isolate_net,
            )
        )
        self.monitor = CrashMonitor() if config.monitor_logs else None
        self.triage = CrashTriage() if config.enable_triage else None
        self.localizer = RootCauseLocalizer()
        self.coverage = CoverageTracker() if config.enable_coverage else None
        self.corpus = CorpusManager(queue_dir=str(Path(config.output_dir) / "queue"))
        self.shared_pso = MOptPSOScheduler()

        # Optional Hybrid SAST pre-analysis on sibling C/C++ source
        self.sast_findings: List[Dict[str, Any]] = []
        sast_tokens: List[bytes] = []
        effective_checksum = config.checksum_mode
        if config.enable_sast_hints:
            sast_rep = StaticSourceAnalyzer().infer_source_for_binary(config.target)
            if sast_rep is not None:
                self.sast_findings = [f.to_dict() for f in sast_rep.findings]
                sast_tokens = sast_rep.extracted_tokens
                if effective_checksum == "auto" and sast_rep.detected_checksum:
                    effective_checksum = sast_rep.detected_checksum

        self.effective_checksum = effective_checksum
        self.mutator = MutatorEngine(
            mutation_rate=config.mutation_rate,
            max_input_size=config.max_input_size,
            dict_path=config.dict_path,
            grammar_spec=config.grammar_spec,
            checksum_mode=effective_checksum,
            pso=self.shared_pso,
        )
        if sast_tokens:
            self.mutator.add_dynamic_tokens(sast_tokens)

        self.crash_count = 0
        self.total_crashes_raw = 0
        self.timeouts_count = 0
        self.iteration = 0
        self.start_time = 0.0
        self.running = False
        self.forkserver_active = False
        self.coverage_timeline: List[Dict[str, Any]] = []
        self.crash_records: List[Dict[str, Any]] = []

        self.binary_info = inspect_target_binary(config.target)
        self.sandbox_caps = probe_sandbox_capabilities() if config.sandbox else {}

        self._shm_dir = (
            "/dev/shm"
            if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK)
            else tempfile.gettempdir()
        )
        self._main_input_path = Path(self._shm_dir) / f"zh_in_{os.getpid()}_main.bin"
        self._net_fuzzer: Optional[NetworkFuzzer] = None
        self._main_forkserver: Optional[ForkserverExecutor] = None

        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        Path(config.seed_dir).mkdir(parents=True, exist_ok=True)

    def load_seeds(self) -> List[bytes]:
        seeds: List[bytes] = []
        seed_path = Path(self.config.seed_dir)
        if seed_path.exists():
            for f in sorted(seed_path.glob("*")):
                if f.is_file():
                    seeds.append(f.read_bytes())
        if not seeds:
            if self.config.input_mode == "network":
                seeds = [b"PING\n", b"AUTH guest\n", b"ZHTP\x00\x04TEST"]
            else:
                seeds = [
                    b"A" * 16,
                    b"B" * 32,
                    b"ZERO1234",
                    b"AAAA12345678",
                ]
        # Add grammar bootstrap packet when CRC32/ZHV3 detected
        if self.effective_checksum == "crc32":
            seeds.append(self.mutator.grammar.generate(seed_hint=b"ZHV3"))
        return seeds

    def mutate(self, data: bytes) -> bytes:
        cmp_pairs = self.coverage.get_recent_cmp_pairs(24) if self.coverage else None
        return self.mutator.mutate(data, cmp_pairs=cmp_pairs)

    def _create_forkserver(self, cov_file: Optional[str], tag: str) -> Optional[ForkserverExecutor]:
        if not self.config.use_forkserver or self.config.input_mode not in ("file", "stdin"):
            return None
        fs = ForkserverExecutor(
            target=self.config.target,
            input_mode=self.config.input_mode,
            cov_file=cov_file,
            sandbox=self.config.sandbox,
            enable_namespaces=self.config.enable_namespaces,
            enable_seccomp=self.config.enable_seccomp,
            memory_mb=self.config.memory_mb,
            timeout=self.config.timeout,
            worker_tag=tag,
        )
        if fs.is_supported and fs.start():
            self.forkserver_active = True
            return fs
        fs.stop()
        return None

    def execute_target(
        self,
        payload: bytes,
        cov_file: Optional[str] = None,
        input_file_path: Optional[Path] = None,
        net_runner: Optional[NetworkFuzzer] = None,
        forkserver: Optional[ForkserverExecutor] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "crashed": False,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "signal": None,
            "timed_out": False,
            "exec_time_ms": 0.0,
            "payload": payload,
        }

        active_cov = cov_file
        if active_cov is None and self.coverage is not None:
            active_cov = self.coverage.cov_file_path

        try:
            if forkserver is not None:
                exec_result = forkserver.execute(payload)
            elif self.config.input_mode == "network":
                runner = net_runner or self._get_or_create_net_fuzzer(active_cov)
                exec_result = runner.send_payload(payload)
            elif self.config.input_mode == "file":
                tmp = input_file_path or self._main_input_path
                tmp.write_bytes(payload)
                cmd = [self.config.target, str(tmp)]
                exec_result = self.process_mgr.spawn(
                    cmd=cmd,
                    timeout=self.config.timeout,
                    sandbox=self.config.sandbox,
                    cov_file=active_cov,
                )
            else:
                exec_result = self.process_mgr.spawn(
                    cmd=[self.config.target],
                    stdin_data=payload,
                    timeout=self.config.timeout,
                    sandbox=self.config.sandbox,
                    cov_file=active_cov,
                )

            result.update(exec_result)
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            result["crashed"] = True
            result["stderr"] = str(e).encode()

        return result

    def _get_or_create_net_fuzzer(self, cov_file: Optional[str]) -> NetworkFuzzer:
        if self._net_fuzzer is None:
            self._net_fuzzer = NetworkFuzzer(
                target_binary=self.config.target,
                net_config=NetworkConfig(
                    host=self.config.network_host,
                    port=self.config.network_port,
                    protocol=self.config.network_protocol,
                    framing=self.config.network_framing,
                    managed_server=self.config.managed_server,
                    server_args=self.config.server_args,
                ),
                sandbox=self.config.sandbox,
                cov_file=cov_file,
                memory_mb=self.config.memory_mb,
            )
        return self._net_fuzzer

    def _minimize_crash_payload(self, payload: bytes, triage_result: Optional[TriageResult]) -> Optional[bytes]:
        if not self.config.auto_minimize or len(payload) <= 4:
            return None
        if triage_result and triage_result.bug_class == "timeout-hang":
            return None

        min_tmp = Path(self._shm_dir) / f"zh_min_{os.getpid()}_{threading.get_ident()}.bin"
        min_net: Optional[NetworkFuzzer] = None
        min_fs: Optional[ForkserverExecutor] = None

        if self.config.input_mode == "network" and self.config.managed_server:
            min_net = NetworkFuzzer(
                target_binary=self.config.target,
                net_config=NetworkConfig(
                    host=self.config.network_host,
                    port=0,
                    protocol=self.config.network_protocol,
                    framing=self.config.network_framing,
                    managed_server=True,
                    server_args=self.config.server_args,
                ),
                sandbox=self.config.sandbox,
                cov_file=None,
                memory_mb=self.config.memory_mb,
            )
        elif self.config.use_forkserver and self.config.input_mode in ("file", "stdin"):
            min_fs = self._create_forkserver(None, f"min_{threading.get_ident()}")

        def _verify(cand: bytes) -> Dict[str, Any]:
            return self.execute_target(
                cand,
                cov_file=None,
                input_file_path=min_tmp,
                net_runner=min_net,
                forkserver=min_fs,
            )

        try:
            sig = None
            if triage_result:
                if triage_result.stack_hash and triage_result.stack_hash != "none":
                    sig = f"{triage_result.bug_class}:{triage_result.stack_hash}"
                else:
                    sig = f"{triage_result.bug_class}:sig={triage_result.signal}"

            minimizer = CrashMinimizer(
                _verify,
                triage=self.triage,
                max_steps=160,
                checksum_mode=self.effective_checksum,
            )
            mres = minimizer.minimize(payload, expected_signature=sig)
            if mres.reproducible and mres.minimized_size < len(payload):
                return mres.minimized_payload
            return None
        finally:
            if min_fs is not None:
                min_fs.stop()
            if min_net is not None:
                min_net.stop()
            try:
                if min_tmp.exists():
                    min_tmp.unlink()
            except Exception:
                pass

    def save_crash(
        self,
        payload: bytes,
        meta: Dict[str, Any],
        triage_result: Optional[TriageResult] = None,
        minimized_payload: Optional[bytes] = None,
        strategy: str = "havoc",
    ) -> Dict[str, Any]:
        with self._lock:
            idx = self.crash_count
            self.crash_count += 1

        ts = int(time.time())
        crash_id = f"crash_{idx:05d}_{ts}"
        out_dir = Path(self.config.output_dir)
        crash_file = out_dir / f"{crash_id}.bin"
        meta_file = out_dir / f"{crash_id}.meta"
        json_file = out_dir / f"{crash_id}.json"

        crash_file.write_bytes(payload)

        min_file_str = None
        if minimized_payload is not None:
            min_file = out_dir / f"{crash_id}.min.bin"
            min_file.write_bytes(minimized_payload)
            min_file_str = str(min_file)

        stderr_txt = (
            meta.get("stderr", b"").decode("utf-8", errors="ignore")
            if isinstance(meta.get("stderr"), (bytes, bytearray))
            else str(meta.get("stderr", ""))
        )

        root_cause_dict: Dict[str, Any] = {}
        if triage_result:
            root_cause_dict = self.localizer.localize(
                triage_result.cwe,
                triage_result.stack_frames,
            ).to_dict()

        meta_content = (
            f"Crash ID: {crash_id}\n"
            f"Target: {self.config.target}\n"
            f"Mode: {self.config.input_mode}\n"
            f"Strategy: {strategy}\n"
            f"Return Code: {meta.get('returncode')}\n"
            f"Signal: {meta.get('signal')}\n"
            f"Payload Size: {len(payload)} bytes\n"
        )
        if minimized_payload is not None:
            meta_content += f"Minimized Size: {len(minimized_payload)} bytes ({min_file_str})\n"

        if triage_result:
            meta_content += (
                f"\n[TRIAGE]\n"
                f"Risk: {triage_result.risk.value}\n"
                f"CWE: {triage_result.cwe}\n"
                f"Bug Class: {triage_result.bug_class}\n"
                f"Confidence: {triage_result.confidence:.0%}\n"
                f"CVSS Estimate: {triage_result.cvss_estimate:.1f}\n"
                f"Stack Hash: {triage_result.stack_hash}\n"
                f"Reason: {triage_result.reason}\n"
                f"Notes: {triage_result.notes}\n"
            )
            if root_cause_dict.get("source_file"):
                meta_content += (
                    f"Root Cause: {root_cause_dict['source_file']}:{root_cause_dict.get('line_number')}\n"
                    f"Patch Guidance: {root_cause_dict.get('remediation_summary')}\n"
                )

        if stderr_txt:
            meta_content += f"\n[STDERR]\n{stderr_txt[:2500]}\n"

        meta_file.write_text(meta_content, encoding="utf-8")

        record: Dict[str, Any] = {
            "crash_id": crash_id,
            "timestamp": ts,
            "iteration": self.iteration,
            "target": self.config.target,
            "input_mode": self.config.input_mode,
            "strategy": strategy,
            "signal": meta.get("signal"),
            "returncode": meta.get("returncode"),
            "raw_size": len(payload),
            "min_size": len(minimized_payload) if minimized_payload is not None else None,
            "crash_file": str(crash_file),
            "min_file": min_file_str,
            "triage": triage_result.to_dict() if triage_result else {},
            "root_cause": root_cause_dict,
            "stderr_excerpt": stderr_txt[:1500],
        }
        json_file.write_text(json.dumps(record, indent=2), encoding="utf-8")

        with self._lock:
            self.crash_records.append(record)

        logger.warning(f"[CRASH] Saved → {crash_file}" + (f" (min → {min_file_str})" if min_file_str else ""))
        if self.triage and triage_result:
            self.triage.print_report(triage_result, crash_id)

        return record

    def _calibrate_initial_seeds(self, raw_seeds: List[bytes]):
        if self.coverage is not None and self._main_forkserver is None:
            self._main_forkserver = self._create_forkserver(self.coverage.cov_file_path, "w0")

        for s in raw_seeds:
            if self._stop_event.is_set():
                break
            if self.coverage:
                self.coverage.reset_trace()
            res = self.execute_target(s, forkserver=self._main_forkserver)
            obs = (
                self.coverage.evaluate_run(res["stdout"], res["stderr"], res["returncode"])
                if self.coverage
                else CoverageObservation()
            )
            if obs.cmp_pairs and self.coverage:
                self.mutator.add_dynamic_tokens(self.coverage.get_cmp_tokens(32))

            self.corpus.add_seed(
                data=s,
                exec_time_ms=res.get("exec_time_ms", 1.0),
                edges_count=obs.run_edges,
                edge_indices=obs.edge_indices,
                depth=0,
                reason="initial",
                persist=False,
            )

            if res.get("crashed"):
                self._handle_crash(s, res, strategy="initial_seed")

        self.corpus.cull_favored()

    def _handle_crash(self, payload: bytes, result: Dict[str, Any], strategy: str) -> bool:
        with self._lock:
            self.total_crashes_raw += 1
            if result.get("timed_out"):
                self.timeouts_count += 1

        triage_result: Optional[TriageResult] = None
        if self.triage:
            log_crashes = self.monitor.check_for_new_crashes() if self.monitor else []
            log_lines = [c["raw"] for c in log_crashes]
            triage_result = self.triage.analyze(result, log_lines)

        is_new = True
        if self.coverage:
            stack_hash = triage_result.stack_hash if triage_result else None
            bug_class = triage_result.bug_class if triage_result else None
            is_new = self.coverage.is_new_crash(
                payload,
                signal=result.get("signal"),
                stack_hash=stack_hash,
                bug_class=bug_class,
            )
            if is_new:
                self.coverage.mark_interesting(payload)

        if is_new:
            self.mutator.reward_strategy(strategy, weight=4)
            min_payload = self._minimize_crash_payload(payload, triage_result)
            self.save_crash(
                payload,
                result,
                triage_result=triage_result,
                minimized_payload=min_payload,
                strategy=strategy,
            )
        return is_new

    def _worker_loop(self, worker_id: int):
        w_cov_path: Optional[str] = None
        w_cov_fd: Optional[int] = None
        w_cov_mm = None

        if self.coverage is not None:
            if worker_id == 0:
                w_cov_path = self.coverage.cov_file_path
                w_cov_mm = self.coverage._mm
            else:
                w_cov_path, w_cov_fd, w_cov_mm = self.coverage.create_worker_shm()

        w_input_path = Path(self._shm_dir) / f"zh_in_{os.getpid()}_w{worker_id}.bin"
        w_mutator = (
            self.mutator
            if worker_id == 0
            else MutatorEngine(
                mutation_rate=self.config.mutation_rate,
                max_input_size=self.config.max_input_size,
                dict_path=self.config.dict_path,
                grammar_spec=self.config.grammar_spec,
                checksum_mode=self.effective_checksum,
                pso=self.shared_pso,
            )
        )
        if worker_id != 0 and self.mutator.tokens:
            w_mutator.add_dynamic_tokens(self.mutator.tokens)

        w_fs: Optional[ForkserverExecutor] = None
        if worker_id == 0 and self._main_forkserver is not None:
            w_fs = self._main_forkserver
        else:
            w_fs = self._create_forkserver(w_cov_path, f"w{worker_id}")

        w_net: Optional[NetworkFuzzer] = None
        if self.config.input_mode == "network":
            if worker_id == 0:
                w_net = self._get_or_create_net_fuzzer(w_cov_path)
            else:
                w_net = NetworkFuzzer(
                    target_binary=self.config.target,
                    net_config=NetworkConfig(
                        host=self.config.network_host,
                        port=0 if self.config.managed_server else self.config.network_port,
                        protocol=self.config.network_protocol,
                        framing=self.config.network_framing,
                        managed_server=self.config.managed_server,
                        server_args=self.config.server_args,
                    ),
                    sandbox=self.config.sandbox,
                    cov_file=w_cov_path,
                    memory_mb=self.config.memory_mb,
                )

        try:
            while not self._stop_event.is_set():
                parent_entry: SeedEntry = self.corpus.select_next()
                energy = self.corpus.assign_energy(parent_entry, base_energy=6)

                for _ in range(energy):
                    if self._stop_event.is_set():
                        break

                    with self._lock:
                        if self.iteration >= self.config.max_iterations:
                            self._stop_event.set()
                            break
                        self.iteration += 1
                        cur_iter = self.iteration

                    mate_entry = self.corpus.select_random_other(parent_entry.seed_id)
                    cmp_pairs = self.coverage.get_recent_cmp_pairs(24) if self.coverage else None

                    payload = w_mutator.mutate(
                        parent_entry.data,
                        mate=mate_entry.data if mate_entry else None,
                        cmp_pairs=cmp_pairs,
                    )
                    strategy = w_mutator.last_strategy

                    if self.coverage and w_cov_mm is not None:
                        self.coverage.reset_trace(mm=w_cov_mm)

                    result = self.execute_target(
                        payload,
                        cov_file=w_cov_path,
                        input_file_path=w_input_path,
                        net_runner=w_net,
                        forkserver=w_fs,
                    )

                    obs = CoverageObservation()
                    if self.coverage and w_cov_mm is not None:
                        obs = self.coverage.evaluate_run(
                            stdout=result["stdout"],
                            stderr=result["stderr"],
                            returncode=result["returncode"],
                            mm=w_cov_mm,
                        )
                        if obs.cmp_pairs:
                            w_mutator.add_dynamic_tokens(self.coverage.get_cmp_tokens(32))

                    if result["crashed"]:
                        self._handle_crash(payload, result, strategy=strategy)
                    elif obs.is_interesting and self.coverage:
                        w_mutator.reward_strategy(strategy, weight=2 if obs.has_new_edges else 1)
                        reason = "new_edge" if obs.has_new_edges else "new_bucket"
                        self.coverage.mark_interesting(payload)
                        self.corpus.add_seed(
                            data=payload,
                            exec_time_ms=result.get("exec_time_ms", 1.0),
                            edges_count=obs.run_edges,
                            edge_indices=obs.edge_indices,
                            depth=parent_entry.depth + 1,
                            parent_id=parent_entry.seed_id,
                            reason=reason,
                        )

                    if cur_iter % 50 == 0:
                        self.corpus.cull_favored()
                        self._record_timeline_point(cur_iter)

                    if cur_iter % 250 == 0:
                        self._log_progress(cur_iter)
        finally:
            if worker_id != 0 and w_fs is not None:
                w_fs.stop()
            if worker_id != 0 and w_net is not None:
                w_net.stop()
            if worker_id != 0 and w_cov_mm is not None:
                try:
                    w_cov_mm.close()
                except Exception:
                    pass
            if worker_id != 0 and w_cov_fd is not None:
                try:
                    os.close(w_cov_fd)
                except Exception:
                    pass
            if worker_id != 0 and w_cov_path and os.path.exists(w_cov_path):
                try:
                    os.unlink(w_cov_path)
                except Exception:
                    pass
            try:
                if w_input_path.exists():
                    w_input_path.unlink()
            except Exception:
                pass

    def _record_timeline_point(self, cur_iter: int):
        elapsed = max(0.001, time.perf_counter() - self.start_time)
        cov_stats = self.coverage.get_stats() if self.coverage else {}
        with self._lock:
            self.coverage_timeline.append({
                "iteration": cur_iter,
                "elapsed_sec": round(elapsed, 2),
                "edges": cov_stats.get("total_edges", 0),
                "corpus": len(self.corpus.entries),
                "unique_crashes": self.crash_count,
                "execs_per_sec": round(cur_iter / elapsed, 1),
            })
            if len(self.coverage_timeline) > 120:
                self.coverage_timeline = self.coverage_timeline[-120:]

    def _log_progress(self, cur_iter: int):
        elapsed = max(0.001, time.perf_counter() - self.start_time)
        rate = cur_iter / elapsed
        stats = (
            f"Iter: {cur_iter}/{self.config.max_iterations} ({rate:.1f}/s) | "
            f"Unique Crashes: {self.crash_count} (raw: {self.total_crashes_raw}) | "
            f"Corpus: {len(self.corpus.entries)}"
        )
        if self.coverage:
            cov = self.coverage.get_stats()
            stats += f" | Edges: {cov['total_edges']} | CmpTokens: {cov['cmp_tokens_discovered']}"
        logger.info(f"[*] {stats}")

    def stop(self):
        self._stop_event.set()

    def get_summary(self) -> Dict[str, Any]:
        elapsed = max(0.001, (time.perf_counter() - self.start_time) if self.start_time else 0.001)
        cov_stats = self.coverage.get_stats() if self.coverage else {}
        corpus_stats = self.corpus.get_stats()
        return {
            "running": self.running,
            "engine_version": "3.0.0",
            "target": self.config.target,
            "input_mode": self.config.input_mode,
            "workers": self.config.workers,
            "forkserver_active": self.forkserver_active,
            "checksum_mode": self.effective_checksum,
            "iterations": self.iteration,
            "max_iterations": self.config.max_iterations,
            "elapsed_sec": round(elapsed, 2),
            "execs_per_sec": round(self.iteration / elapsed, 1) if self.iteration > 0 else 0.0,
            "unique_crashes": self.crash_count,
            "raw_crashes": self.total_crashes_raw,
            "timeouts": self.timeouts_count,
            "total_edges": cov_stats.get("total_edges", 0),
            "edge_density_pct": cov_stats.get("edge_density_pct", 0.0),
            "cmp_tokens_discovered": cov_stats.get("cmp_tokens_discovered", 0),
            "corpus_size": corpus_stats.get("corpus_size", 0),
            "favored_seeds": corpus_stats.get("favored_seeds", 0),
            "max_depth": corpus_stats.get("max_depth", 0),
            "native_mutator": self.mutator.native_enabled,
            "binary_info": self.binary_info,
            "sandbox_caps": self.sandbox_caps,
            "strategy_stats": dict(self.mutator.strategy_stats),
            "pso_weights": self.shared_pso.get_weights(),
            "pso_efficiency": self.shared_pso.get_efficiency_summary(),
            "sast_findings_count": len(self.sast_findings),
            "sast_findings": self.sast_findings[:30],
            "heatmap": self.coverage.get_heatmap_blocks() if self.coverage else [0] * 64,
            "timeline": list(self.coverage_timeline),
        }

    def run(self) -> Dict[str, Any]:
        self._stop_event.clear()
        self.running = True
        self.start_time = time.perf_counter()

        if self.config.checkpoint_path and Path(self.config.checkpoint_path).is_file():
            CampaignCheckpointer.load(self, self.config.checkpoint_path)

        logger.info(f"[*] Zero-Hunter-Engine v3.0 started on: {self.config.target} (mode={self.config.input_mode})")
        logger.info(
            f"[*] Sandbox: {self.config.sandbox} | Forkserver: {self.config.use_forkserver and self.binary_info.get('uses_forkserver')} | "
            f"UBSan: {self.binary_info.get('uses_ubsan')} | SAST Hotspots: {len(self.sast_findings)} | "
            f"Checksum: {self.effective_checksum} | Workers: {self.config.workers}"
        )

        raw_seeds = self.load_seeds()
        if self.monitor:
            self.monitor.start()

        try:
            self._calibrate_initial_seeds(raw_seeds)
            self._record_timeline_point(0)

            num_workers = max(1, int(self.config.workers))
            if num_workers == 1:
                self._worker_loop(0)
            else:
                threads = [
                    threading.Thread(target=self._worker_loop, args=(wid,), daemon=True)
                    for wid in range(num_workers)
                ]
                for t in threads:
                    t.start()
                while any(t.is_alive() for t in threads):
                    for t in threads:
                        t.join(timeout=0.2)
                    if self._stop_event.is_set():
                        break

        except KeyboardInterrupt:
            logger.info("[*] Stopped by user")
            self._stop_event.set()
        finally:
            self.running = False
            if self._main_forkserver is not None:
                self._main_forkserver.stop()
                self._main_forkserver = None
            if self._net_fuzzer is not None:
                self._net_fuzzer.stop()
                self._net_fuzzer = None
            try:
                if self._main_input_path.exists():
                    self._main_input_path.unlink()
            except Exception:
                pass
            if self.monitor:
                self.monitor.stop()

            if self.config.checkpoint_path:
                try:
                    CampaignCheckpointer.save(self, self.config.checkpoint_path)
                except Exception as exc:
                    logger.error(f"Checkpoint save failed: {exc}")

            self._record_timeline_point(self.iteration)
            summary = self.get_summary()
            logger.info(
                f"[*] Campaign complete in {summary['elapsed_sec']}s ({summary['execs_per_sec']} exec/s) — "
                f"Unique crashes: {self.crash_count}, Edges: {summary['total_edges']}, Corpus: {summary['corpus_size']}"
            )

            if self.config.generate_report:
                try:
                    ReportGenerator(self.config.reports_dir).generate_all(
                        session_summary=summary,
                        crash_dir=self.config.output_dir,
                        static_findings=self.sast_findings,
                    )
                except Exception as exc:
                    logger.error(f"Report generation failed: {exc}")

            if self.coverage:
                self.coverage.close()

        return summary
