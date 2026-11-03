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
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.crash_monitor import CrashMonitor
from utils.logger import setup_logger

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


class FuzzerEngine:
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.monitor = CrashMonitor() if config.monitor_logs else None
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
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if self.config.sandbox else None,
                )
            else:  # stdin
                proc = subprocess.Popen(
                    [self.config.target],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if self.config.sandbox else None,
                )
                proc.stdin.write(payload)
                proc.stdin.close()

            try:
                stdout, stderr = proc.communicate(timeout=self.config.timeout)
                result["returncode"] = proc.returncode
                result["stdout"] = stdout
                result["stderr"] = stderr
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                result["returncode"] = -9
                result["signal"] = "TIMEOUT"

            if result["returncode"] is not None and result["returncode"] < 0:
                result["crashed"] = True
                result["signal"] = -result["returncode"]

        except Exception as e:
            logger.error(f"Execution failed: {e}")
            result["crashed"] = True

        return result

    def save_crash(self, payload: bytes, meta: Dict[str, Any]):
        crash_id = f"crash_{self.crash_count:05d}_{int(time.time())}"
        crash_file = Path(self.config.output_dir) / f"{crash_id}.bin"
        meta_file = Path(self.config.output_dir) / f"{crash_id}.meta"
        crash_file.write_bytes(payload)
        meta_file.write_text(str(meta))
        logger.warning(f"[CRASH] Saved → {crash_file}")
        self.crash_count += 1

    def run(self):
        logger.info(f"[*] Zero-Hunter-Engine started on: {self.config.target}")
        logger.info(f"[*] Sandbox: {self.config.sandbox} | Log Monitor: {self.config.monitor_logs}")
        seeds = self.load_seeds()

        if self.monitor:
            self.monitor.start()

        try:
            while self.iteration < self.config.max_iterations:
                seed = random.choice(seeds)
                payload = self.mutate(seed)
                result = self.execute_target(payload)

                if result["crashed"]:
                    self.save_crash(payload, result)
                    if self.monitor:
                        self.monitor.check_for_new_crashes()

                self.iteration += 1
                if self.iteration % 200 == 0:
                    logger.info(f"[*] Iter: {self.iteration} | Crashes: {self.crash_count}")

        except KeyboardInterrupt:
            logger.info("[*] Stopped by user")
        finally:
            if self.monitor:
                self.monitor.stop()
            logger.info(f"[*] Done. Total unique crashes: {self.crash_count}")


if __name__ == "__main__":
    config = FuzzConfig(
        target="./targets/vulnerable_test/vuln",
        input_mode="file",
        max_iterations=5000,
        sandbox=True,
    )
    engine = FuzzerEngine(config)
    engine.run()
