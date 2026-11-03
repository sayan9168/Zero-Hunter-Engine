#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Real-time Crash Monitor
Parses dmesg / journalctl for memory corruption signals
"""

import re
import time
import threading
import subprocess
from collections import deque
from typing import List, Dict, Optional
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger("crash_monitor")

CRASH_PATTERNS = [
    re.compile(r"segfault|segmentation fault", re.I),
    re.compile(r"general protection fault", re.I),
    re.compile(r"heap[- ]overflow|heap[- ]buffer", re.I),
    re.compile(r"use[- ]after[- ]free|UAF", re.I),
    re.compile(r"double[- ]free", re.I),
    re.compile(r"stack[- ]overflow|stack[- ]smashing detected", re.I),
    re.compile(r"invalid free|corrupted double-linked list", re.I),
    re.compile(r"BUG: KASAN|KASAN:", re.I),
    re.compile(r"traps: .* general protection", re.I),
    re.compile(r"killed process .* (segfault|SIGSEGV)", re.I),
]


class CrashMonitor:
    def __init__(self, max_history: int = 500):
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.seen_lines = deque(maxlen=max_history)
        self.new_crashes: List[Dict] = []
        self.lock = threading.Lock()

    def _get_log_source(self) -> List[str]:
        """Prefer journalctl, fallback to dmesg"""
        try:
            out = subprocess.check_output(
                ["journalctl", "-k", "-n", "200", "--no-pager"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )
            return out.splitlines()
        except Exception:
            try:
                out = subprocess.check_output(
                    ["dmesg", "--ctime"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                )
                return out.splitlines()
            except Exception:
                return []

    def _scan_logs(self):
        lines = self._get_log_source()
        for line in lines:
            if line in self.seen_lines:
                continue
            self.seen_lines.append(line)

            for pattern in CRASH_PATTERNS:
                if pattern.search(line):
                    crash_info = {
                        "timestamp": time.time(),
                        "raw": line.strip(),
                        "pattern": pattern.pattern,
                    }
                    with self.lock:
                        self.new_crashes.append(crash_info)
                    logger.critical(f"[KERNEL/LOG CRASH] {line.strip()}")
                    break

    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_logs()
            except Exception as e:
                logger.error(f"Monitor error: {e}")
            time.sleep(0.8)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("[*] CrashMonitor started (dmesg/journalctl)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("[*] CrashMonitor stopped")

    def check_for_new_crashes(self) -> List[Dict]:
        with self.lock:
            crashes = self.new_crashes[:]
            self.new_crashes.clear()
        return crashes
