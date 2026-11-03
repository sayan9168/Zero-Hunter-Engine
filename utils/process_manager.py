#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Process Manager + Sandbox Helpers
Provides safer process spawning and basic isolation
Educational & Authorized Research Only
"""

import os
import signal
import subprocess
import resource
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from utils.logger import setup_logger

logger = setup_logger("process_manager")


@dataclass
class ProcessLimits:
    cpu_seconds: int = 5
    memory_mb: int = 256
    max_files: int = 64


class ProcessManager:
    """
    Manages target process lifecycle with basic resource limits
    and process-group isolation (sandbox mode).
    """

    def __init__(self, limits: Optional[ProcessLimits] = None):
        self.limits = limits or ProcessLimits()

    def _set_limits(self):
        """Called in child process before exec"""
        try:
            # CPU time limit
            resource.setrlimit(resource.RLIMIT_CPU, (self.limits.cpu_seconds, self.limits.cpu_seconds))
            # Memory limit (address space)
            mem_bytes = self.limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            # Open files
            resource.setrlimit(resource.RLIMIT_NOFILE, (self.limits.max_files, self.limits.max_files))
        except Exception as e:
            # Limits may fail on some systems; continue anyway
            pass

    def spawn(
        self,
        cmd: List[str],
        stdin_data: Optional[bytes] = None,
        timeout: float = 2.0,
        sandbox: bool = True,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Spawn a process with optional resource limits and process group isolation.
        Returns a result dictionary similar to fuzzer_engine.
        """
        result = {
            "crashed": False,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "signal": None,
            "timed_out": False,
        }

        preexec = None
        if sandbox:
            def preexec_fn():
                os.setsid()          # New process group
                self._set_limits()
            preexec = preexec_fn

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                cwd=cwd,
            )

            try:
                stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
                result["returncode"] = proc.returncode
                result["stdout"] = stdout
                result["stderr"] = stderr
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                result["signal"] = "TIMEOUT"
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
                result["returncode"] = -9

            if result["returncode"] is not None and result["returncode"] < 0:
                result["crashed"] = True
                result["signal"] = -result["returncode"]

        except Exception as e:
            logger.error(f"Process spawn failed: {e}")
            result["crashed"] = True
            result["stderr"] = str(e).encode()

        return result

    def kill_process_group(self, pid: int):
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass
