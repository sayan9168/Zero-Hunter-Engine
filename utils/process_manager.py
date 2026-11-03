#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Process Manager + Multi-Layer Sandbox Integration
Provides fast, isolated target process spawning with ASAN shadow-memory awareness,
Linux namespaces, seccomp-bpf filtering, and execution latency measurement.

Educational & Authorized Defensive Research Only
"""

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from utils.logger import setup_logger
from utils.sandbox import (
    SandboxConfig,
    apply_child_sandbox,
    build_target_env,
    inspect_target_binary,
)

logger = setup_logger("process_manager")


@dataclass
class ProcessLimits:
    cpu_seconds: int = 5
    memory_mb: int = 256
    max_files: int = 64
    enable_namespaces: bool = True
    enable_seccomp: bool = True
    isolate_network: bool = True


class ProcessManager:
    """
    Manages target process lifecycle with POSIX resource limits,
    Linux namespaces, seccomp-bpf syscall filtering, and process-group cleanup.
    """

    def __init__(self, limits: Optional[ProcessLimits] = None):
        self.limits = limits or ProcessLimits()

    def spawn(
        self,
        cmd: List[str],
        stdin_data: Optional[bytes] = None,
        timeout: float = 2.0,
        sandbox: bool = True,
        cwd: Optional[str] = None,
        cov_file: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
        isolate_network: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Spawn a target process inside the multi-layer sandbox and return execution telemetry.
        """
        result: Dict[str, Any] = {
            "crashed": False,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "signal": None,
            "timed_out": False,
            "exec_time_ms": 0.0,
        }

        if not cmd:
            return result

        binary_info = inspect_target_binary(cmd[0])
        uses_shadow = bool(
            binary_info.get("uses_asan")
            or binary_info.get("uses_msan")
            or binary_info.get("uses_tsan")
        )

        net_iso = self.limits.isolate_network if isolate_network is None else isolate_network
        sb_cfg = SandboxConfig(
            enabled=sandbox,
            enable_namespaces=self.limits.enable_namespaces,
            enable_seccomp=self.limits.enable_seccomp,
            isolate_network=net_iso,
            cpu_seconds=self.limits.cpu_seconds,
            memory_mb=self.limits.memory_mb,
            max_files=self.limits.max_files,
        )

        env = build_target_env(
            cov_file=cov_file,
            binary_info=binary_info,
            memory_mb=self.limits.memory_mb,
            extra_env=extra_env,
        )

        preexec = None
        if sandbox:
            def preexec_fn():
                apply_child_sandbox(sb_cfg, uses_sanitizer_shadow=uses_shadow)
            preexec = preexec_fn

        t0 = time.perf_counter()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                cwd=cwd,
                env=env,
            )

            try:
                stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
                result["returncode"] = proc.returncode
                result["stdout"] = stdout
                result["stderr"] = stderr
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                result["signal"] = "TIMEOUT"
                self.kill_process_group(proc.pid)
                try:
                    proc.kill()
                    _, stderr = proc.communicate(timeout=0.2)
                    result["stderr"] = stderr
                except Exception:
                    pass
                result["returncode"] = -9

            result["exec_time_ms"] = (time.perf_counter() - t0) * 1000.0

            rc = result["returncode"]
            if rc is not None and rc < 0 and not result["timed_out"]:
                result["crashed"] = True
                result["signal"] = -rc
            elif b"ERROR: AddressSanitizer:" in result["stderr"] or b" runtime error:" in result["stderr"]:
                # Catch ASAN/UBSAN exits even if configured with custom exitcode > 0
                result["crashed"] = True
                if result["signal"] is None:
                    result["signal"] = 6

        except Exception as e:
            result["exec_time_ms"] = (time.perf_counter() - t0) * 1000.0
            logger.error(f"Process spawn failed: {e}")
            result["crashed"] = True
            result["stderr"] = str(e).encode()

        return result

    def kill_process_group(self, pid: int):
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass
