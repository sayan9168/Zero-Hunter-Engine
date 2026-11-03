#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Network Protocol Fuzzing Engine (TCP / UDP)
Supports:
1. Managed Sandbox Server Mode: launches an instrumented target server on 127.0.0.1,
   streams fuzz frames at high speed while collecting live SanitizerCoverage + CmpLog
   via shared memory, and captures full ASAN diagnostics on crash with auto-respawn.
2. External Endpoint Mode: fuzzes an authorized listening TCP/UDP service with
   configurable protocol framing and liveness probing.

Educational & Authorized Defensive Research Only
"""

import os
import shlex
import signal
import socket
import struct
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

logger = setup_logger("network_fuzzer")


@dataclass
class NetworkConfig:
    host: str = "127.0.0.1"
    port: int = 0                       # 0 = auto-pick free ephemeral port
    protocol: str = "tcp"               # "tcp" | "udp"
    framing: str = "raw"                # "raw" | "crlf" | "len16be" | "len16le" | "len32be"
    managed_server: bool = True         # Spawn & supervise target binary automatically
    server_args: str = "--port {port}"  # Args template when spawning managed server
    connect_timeout: float = 0.5
    recv_timeout: float = 0.05
    startup_timeout: float = 2.0


def find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def apply_framing(payload: bytes, framing: str) -> bytes:
    if framing == "crlf":
        return payload if payload.endswith(b"\r\n") else (payload + b"\r\n")
    if framing == "len16be":
        return struct.pack(">H", len(payload) & 0xFFFF) + payload
    if framing == "len16le":
        return struct.pack("<H", len(payload) & 0xFFFF) + payload
    if framing == "len32be":
        return struct.pack(">I", len(payload) & 0xFFFFFFFF) + payload
    return payload


class NetworkFuzzer:
    """
    High-speed persistent & supervised network protocol target runner.
    """

    def __init__(
        self,
        target_binary: Optional[str],
        net_config: Optional[NetworkConfig] = None,
        sandbox: bool = True,
        cov_file: Optional[str] = None,
        memory_mb: int = 256,
    ):
        self.target_binary = target_binary
        self.cfg = net_config or NetworkConfig()
        self.sandbox = sandbox
        self.cov_file = cov_file
        self.memory_mb = memory_mb

        if self.cfg.port <= 0:
            self.cfg.port = find_free_port(self.cfg.host)

        self._proc: Optional[subprocess.Popen] = None
        self._binary_info = inspect_target_binary(target_binary) if target_binary else {}

    def _start_server(self) -> bool:
        if not self.cfg.managed_server or not self.target_binary:
            return True

        self.stop()

        arg_str = self.cfg.server_args.format(port=self.cfg.port, host=self.cfg.host)
        cmd = [self.target_binary] + shlex.split(arg_str)

        uses_shadow = bool(
            self._binary_info.get("uses_asan")
            or self._binary_info.get("uses_msan")
            or self._binary_info.get("uses_tsan")
        )
        sb_cfg = SandboxConfig(
            enabled=self.sandbox,
            enable_namespaces=True,
            enable_seccomp=True,
            isolate_network=False,  # Allow loopback socket inside server
            cpu_seconds=30,
            memory_mb=self.memory_mb,
        )
        env = build_target_env(
            cov_file=self.cov_file,
            binary_info=self._binary_info,
            memory_mb=self.memory_mb,
        )

        preexec = None
        if self.sandbox:
            def preexec_fn():
                apply_child_sandbox(sb_cfg, uses_sanitizer_shadow=uses_shadow)
            preexec = preexec_fn

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                env=env,
            )
        except Exception as exc:
            logger.error(f"Failed to start managed network target {cmd}: {exc}")
            self._proc = None
            return False

        # Wait until TCP port accepts connections (or UDP process stays alive)
        deadline = time.perf_counter() + self.cfg.startup_timeout
        while time.perf_counter() < deadline:
            if self._proc.poll() is not None:
                return False
            if self.cfg.protocol.lower() == "udp":
                time.sleep(0.03)
                return self._proc.poll() is None
            try:
                with socket.create_connection((self.cfg.host, self.cfg.port), timeout=0.05):
                    return True
            except OSError:
                time.sleep(0.015)

        return self._proc.poll() is None

    def ensure_running(self) -> bool:
        if not self.cfg.managed_server:
            return True
        if self._proc is not None and self._proc.poll() is None:
            return True
        return self._start_server()

    def _collect_server_crash(self, result: Dict[str, Any]):
        if self._proc is None:
            return
        try:
            stdout, stderr = self._proc.communicate(timeout=0.35)
        except Exception:
            try:
                self._proc.kill()
                stdout, stderr = self._proc.communicate(timeout=0.2)
            except Exception:
                stdout, stderr = b"", b""

        rc = self._proc.returncode
        self._proc = None

        result["returncode"] = rc
        result["stdout"] = stdout
        result["stderr"] = stderr
        if rc is not None and rc < 0:
            result["crashed"] = True
            result["signal"] = -rc
        elif b"ERROR: AddressSanitizer:" in stderr or b"runtime error:" in stderr:
            result["crashed"] = True
            result["signal"] = 6
        elif rc not in (0, None):
            result["crashed"] = True
            result["signal"] = rc

    def send_payload(self, payload: bytes) -> Dict[str, Any]:
        """Deliver one mutated network frame and check for daemon crash or hang."""
        result: Dict[str, Any] = {
            "crashed": False,
            "returncode": 0,
            "stdout": b"",
            "stderr": b"",
            "signal": None,
            "timed_out": False,
            "exec_time_ms": 0.0,
            "payload": payload,
            "response": b"",
        }

        t0 = time.perf_counter()
        if not self.ensure_running():
            # Server failed immediately on startup
            if self._proc is not None:
                self._collect_server_crash(result)
            else:
                result["stderr"] = b"Managed network server failed to bind/start"
            result["exec_time_ms"] = (time.perf_counter() - t0) * 1000.0
            return result

        framed = apply_framing(payload, self.cfg.framing)
        proto = self.cfg.protocol.lower()
        conn_dropped = False

        try:
            if proto == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.cfg.recv_timeout)
                    sock.sendto(framed, (self.cfg.host, self.cfg.port))
                    try:
                        resp, _ = sock.recvfrom(4096)
                        result["response"] = resp
                        result["stdout"] = resp
                    except socket.timeout:
                        pass
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.settimeout(self.cfg.connect_timeout)
                    sock.connect((self.cfg.host, self.cfg.port))
                    sock.sendall(framed)
                    sock.settimeout(self.cfg.recv_timeout)
                    try:
                        resp = sock.recv(4096)
                        result["response"] = resp
                        result["stdout"] = resp
                        if resp == b"":
                            conn_dropped = True
                    except socket.timeout:
                        pass
                    except ConnectionResetError:
                        conn_dropped = True
        except ConnectionRefusedError:
            conn_dropped = True
        except socket.timeout:
            result["timed_out"] = True
        except OSError:
            conn_dropped = True

        # Check if managed server crashed (allow ~35ms for ASAN symbolization on EOF/reset)
        if self.cfg.managed_server and self._proc is not None:
            if self._proc.poll() is not None:
                self._collect_server_crash(result)
            elif conn_dropped:
                try:
                    self._proc.wait(timeout=0.05)
                    self._collect_server_crash(result)
                except subprocess.TimeoutExpired:
                    pass
        elif not self.cfg.managed_server and conn_dropped and proto == "tcp":
            # External service liveness check
            try:
                with socket.create_connection((self.cfg.host, self.cfg.port), timeout=0.25):
                    pass
            except OSError:
                result["crashed"] = True
                result["signal"] = "SERVICE_DOWN"
                result["stderr"] = f"Target {self.cfg.host}:{self.cfg.port} stopped responding".encode()

        result["exec_time_ms"] = (time.perf_counter() - t0) * 1000.0
        return result

    def stop(self):
        if self._proc is not None:
            try:
                if self._proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                    except Exception:
                        self._proc.kill()
                self._proc.communicate(timeout=0.2)
            except Exception:
                pass
            self._proc = None

    def __del__(self):
        self.stop()
