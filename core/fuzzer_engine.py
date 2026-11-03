#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Core Fuzzer Engine
Educational & Authorized Research Only
"""

import os
import sys
import time
import random
import signal
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.crash_monitor import CrashMonitor
from utils.process_manager import ProcessManager, ProcessLimits
from utils.logger import setup_logger
from core.triage import CrashTriage, RiskLevel
from core.coverage import CoverageTracker

logger = setup_logger("fuzzer_engine")

@dataclass
class FuzzConfig:
    target: str
    input_mode: str = "file"          # "file" | "stdin" | "network"
    seed_dir: str = "seeds"
    output_dir: str = "crashes"
    timeout: float = 2.0
    max_iterations: int = 10000
    mutation_rate: float = 0.18
    sandbox: bool = True
    monitor_logs: bool = True
    enable_triage: bool = True
    enable_coverage: bool = True


class FuzzerEngine:
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.monitor = CrashMonitor() if config.monitor_logs else None
        self.process_mgr = ProcessManager(ProcessLimits(cpu_seconds=3, memory_mb=128))
        self.triage = CrashTriage() if config.enable_triage else None
        self.coverage = CoverageTracker() if config.enable_coverage else None
        self.crash_count = 0
        self.iteration = 0
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        Path(config.seed_dir).mkdir(parents=True, exist_ok=True)

    def load_seeds(self) -> List[bytes]:
        seeds = []
        for f in Path(self.config.seed_dir).glob("*"):
            if f.is_file():
                seeds.append(f.read_bytes())
        if not seeds:
            seeds = [
                b"A" * 64,
                b"B" * 256,
                b"%n%n%n%n",
                b"\x00" * 64,
                b"\xff" * 128,
            ]
        return seeds

    def mutate(self, data: bytes) -> bytes:
        """Bit-flip, byte-flip, insert, delete, arithmetic, interesting values"""
        if not data:
            data = b"A" * 32
        data = bytearray(data)
        mutations = max(1, int(len(data) * self.config.mutation_rate))

        for _ in range(mutations):
            strategy = random.choice(
                ["bitflip", "byteflip", "insert", "delete", "arith", "interesting"]
            )
            if strategy == "bitflip" and data:
                idx = random.randrange(len(data))
                data[idx] ^= (1 << random.randint(0, 7))
            elif strategy == "byteflip" and data:
                idx = random.randrange(len(data))
                data[idx] = random.randint(0, 255)
            elif strategy == "insert":
                idx = random.randint(0, len(data))
                data[idx:idx] = bytes([random.randint(0, 255)])
            elif strategy == "delete" and len(data) > 8:
                idx = random.randrange(len(data))
                del data[idx]
            elif strategy == "arith" and data:
                idx = random.randrange(len(data))
                data[idx] = (data[idx] + random.randint(-40, 40)) % 256
            elif strategy == "interesting" and data:
                interesting = [0x00, 0x01, 0x7f, 0x80, 0xff, 0x41, 0x00]
                idx = random.randrange(len(data))
                data[idx] = random.choice(interesting)
        return bytes(data)

    def execute_target(self, payload: bytes) -> Dict[str, Any]:
        result = {
            "crashed": False,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "signal": None,
            "payload": payload,
        }

        try:
            if self.config.input_mode == "file":
                tmp = Path(self.config.output_dir) / f"input_{self.iteration}.bin"
                tmp.write_bytes(payload)
                cmd = [self.config.target, str(tmp)]
                exec_result = self.process_mgr.spawn(
                    cmd=cmd,
                    timeout=self.config.timeout,
                    sandbox=self.config.sandbox,
                )
            else:  # stdin
                exec_result = self.process_mgr.spawn(
                    cmd=[self.config.target],
                    stdin_data=payload,
                    timeout=self.config.timeout,
                    sandbox=self.config.sandbox,
                )

            result.update(exec_result)

        except Exception as e:
            logger.error(f"Execution failed: {e}")
            result["crashed"] = True

        return result

    def save_crash(self, payload: bytes, meta: Dict[str, Any], triage_result=None):
        crash_id = f"crash_{self.crash_count:05d}_{int(time.time())}"
        crash_file = Path(self.config.output_dir) / f"{crash_id}.bin"
        meta_file = Path(self.config.output_dir) / f"{crash_id}.meta"

        crash_file.write_bytes(payload)

        meta_content = str(meta)
        if triage_result:
            meta_content += f"\n\n[TRIAGE]\nRisk: {triage_result.risk.value}\n"
            meta_content += f"Confidence: {triage_result.confidence:.0%}\n"
            meta_content += f"Reason: {triage_result.reason}\n"
            meta_content += f"Notes: {triage_result.notes}\n"

        meta_file.write_text(meta_content)
        logger.warning(f"[CRASH] Saved → {crash_file}")
        self.crash_count += 1

        if self.triage and triage_result:
            self.triage.print_report(triage_result, crash_id)

    def run(self):
        logger.info(f"[*] Zero-Hunter-Engine started on: {self.config.target}")
        logger.info(f"[*] Sandbox: {self.config.sandbox} | Triage: {self.config.enable_triage} | Coverage: {self.config.enable_coverage}")
        seeds = self.load_seeds()

        if self.monitor:
            self.monitor.start()

        try:
            while self.iteration < self.config.max_iterations:
                # Prefer interesting seeds if coverage tracking is enabled
                if self.coverage and self.coverage.interesting_inputs and random.random() < 0.4:
                    # Simple preference (future: real energy scheduling)
                    seed = random.choice(seeds)
                else:
                    seed = random.choice(seeds)

                payload = self.mutate(seed)
                result = self.execute_target(payload)

                if result["crashed"]:
                    # Coverage check
                    is_new = True
                    if self.coverage:
                        is_new = self.coverage.is_new_crash(payload, result.get("signal"))
                        if is_new:
                            self.coverage.mark_interesting(payload)

                    if is_new:
                        triage_result = None
                        if self.triage:
                            log_crashes = self.monitor.check_for_new_crashes() if self.monitor else []
                            log_lines = [c["raw"] for c in log_crashes]
                            triage_result = self.triage.analyze(result, log_lines)

                        self.save_crash(payload, result, triage_result)

                self.iteration += 1
                if self.iteration % 200 == 0:
                    stats = f"Iter: {self.iteration} | Crashes: {self.crash_count}"
                    if self.coverage:
                        cov = self.coverage.get_stats()
                        stats += f" | Unique: {cov['unique_crashes']} | Interesting: {cov['interesting_inputs']}"
                    logger.info(f"[*] {stats}")

        except KeyboardInterrupt:
            logger.info("[*] Stopped by user")
        finally:
            if self.monitor:
                self.monitor.stop()
            logger.info(f"[*] Done. Total crashes saved: {self.crash_count}")
            if self.coverage:
                logger.info(f"[*] Coverage stats: {self.coverage.get_stats()}")


if __name__ == "__main__":
    config = FuzzConfig(
        target="./targets/vulnerable_test/vuln",
        input_mode="file",
        max_iterations=5000,
        sandbox=True,
    )
    engine = FuzzerEngine(config)
    engine.run()
