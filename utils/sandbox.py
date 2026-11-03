#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Multi-Layer Linux Sandbox (Namespaces + seccomp-bpf + RLIMITs)
Provides low-overhead in-process child sandboxing via libc unshare(), seccomp-bpf
syscall filtering, and ASAN-aware POSIX resource limits.

Educational & Authorized Defensive Research Only
"""

import ctypes
import os
import platform
import resource
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import setup_logger

logger = setup_logger("sandbox")

# Linux clone/unshare namespace constants
CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

# Linux prctl & seccomp constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# Classic BPF opcodes
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO_EPERM = 0x00050001  # SECCOMP_RET_ERRNO | EPERM(1)

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# High-risk syscalls blocked inside sandboxed fuzz targets (x86_64)
X86_64_DENY_ADMIN = [
    101,  # ptrace
    154,  # modify_ldt
    155,  # pivot_root
    161,  # chroot
    163,  # acct
    165,  # mount
    166,  # umount2
    167,  # swapon
    168,  # swapoff
    169,  # reboot
    175,  # init_module
    176,  # delete_module
    246,  # kexec_load
    313,  # finit_module
    320,  # kexec_file_load
    321,  # bpf
]
X86_64_DENY_NET = [
    41,   # socket
    42,   # connect
    49,   # bind
    50,   # listen
]

# High-risk syscalls for aarch64
AARCH64_DENY_ADMIN = [
    117,  # ptrace
    39,   # umount2
    40,   # mount
    41,   # pivot_root
    51,   # chroot
    89,   # acct
    104,  # kexec_load
    105,  # init_module
    106,  # delete_module
    142,  # reboot
    224,  # swapon
    225,  # swapoff
    273,  # finit_module
    280,  # bpf
]
AARCH64_DENY_NET = [
    198,  # socket
    200,  # bind
    201,  # listen
    203,  # connect
]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _get_libc():
    if platform.system() != "Linux":
        return None
    try:
        return ctypes.CDLL("libc.so.6", use_errno=True)
    except Exception:
        return None


_LIBC = _get_libc()


@dataclass
class SandboxConfig:
    enabled: bool = True
    enable_namespaces: bool = True
    enable_seccomp: bool = True
    isolate_network: bool = True
    cpu_seconds: int = 3
    memory_mb: int = 256
    max_files: int = 64
    max_file_size_mb: int = 8


@lru_cache(maxsize=64)
def inspect_target_binary(binary_path: str) -> Dict[str, bool]:
    """
    Inspect target binary bytes once to detect ASAN/UBSAN/MSAN and SanitizerCoverage hooks.
    """
    info = {
        "exists": False,
        "uses_asan": False,
        "uses_msan": False,
        "uses_tsan": False,
        "uses_ubsan": False,
        "uses_sancov": False,
        "uses_cmplog": False,
        "uses_forkserver": False,
    }
    p = Path(binary_path)
    if not p.is_file():
        return info
    try:
        blob = p.read_bytes()
        info["exists"] = True
        info["uses_asan"] = (b"__asan_init" in blob) or (b"AddressSanitizer" in blob)
        info["uses_msan"] = b"__msan_init" in blob
        info["uses_tsan"] = b"__tsan_init" in blob
        info["uses_ubsan"] = b"__ubsan_handle" in blob
        info["uses_sancov"] = (
            b"__sanitizer_cov_trace_pc" in blob or b"ZERO_HUNTER_COV_FILE" in blob
        )
        info["uses_cmplog"] = (
            b"__sanitizer_cov_trace_cmp" in blob or b"__sanitizer_weak_hook_memcmp" in blob
        )
        info["uses_forkserver"] = b"ZERO_HUNTER_FORKSRV_CTL_FD" in blob
    except Exception:
        pass
    return info


def build_seccomp_filter(isolate_network: bool = True) -> Optional[List[_SockFilter]]:
    """Construct a classic BPF filter denying dangerous syscalls with EPERM."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch_val = AUDIT_ARCH_X86_64
        deny_list = list(X86_64_DENY_ADMIN)
        if isolate_network:
            deny_list.extend(X86_64_DENY_NET)
    elif machine in ("aarch64", "arm64"):
        arch_val = AUDIT_ARCH_AARCH64
        deny_list = list(AARCH64_DENY_ADMIN)
        if isolate_network:
            deny_list.extend(AARCH64_DENY_NET)
    else:
        return None

    insns: List[_SockFilter] = [
        # [0] Load seccomp_data.arch (offset 4)
        _SockFilter(BPF_LD_W_ABS, 0, 0, 4),
        # [1] If arch == expected arch, jump +1 (to [3]), else fallthrough to [2] (ALLOW foreign compat or EPERM)
        _SockFilter(BPF_JMP_JEQ_K, 1, 0, arch_val),
        # [2] Mismatched arch -> EPERM
        _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM),
        # [3] Load seccomp_data.nr (offset 0)
        _SockFilter(BPF_LD_W_ABS, 0, 0, 0),
    ]

    # For each denied syscall, if nr == sysno jump to final DENY instruction
    total_deny = len(deny_list)
    for idx, sysno in enumerate(deny_list):
        jump_to_deny = total_deny - idx  # Distance over remaining JEQs + 1 ALLOW instruction
        insns.append(_SockFilter(BPF_JMP_JEQ_K, jump_to_deny, 0, sysno))

    # Default action: ALLOW
    insns.append(_SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    # Deny target: return EPERM
    insns.append(_SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM))
    return insns


def apply_child_sandbox(config: SandboxConfig, uses_sanitizer_shadow: bool = False):
    """
    Executed inside forked child (`preexec_fn`) right before `execve`:
    1. Creates isolated process group (`setsid`)
    2. Enters unprivileged Linux namespaces (`CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS [| CLONE_NEWNET]`)
    3. Applies POSIX resource limits (`RLIMIT_CPU`, `RLIMIT_CORE=0`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, and `RLIMIT_AS` when safe)
    4. Installs `PR_SET_NO_NEW_PRIVS` + `seccomp-bpf` syscall filter
    """
    try:
        os.setsid()
    except Exception:
        pass

    if not config.enabled:
        return

    # 1. Linux Namespaces via libc.unshare() (zero extra execve overhead)
    if config.enable_namespaces and _LIBC is not None:
        ns_flags = CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS
        if config.isolate_network:
            ns_flags |= CLONE_NEWNET
        try:
            rc = _LIBC.unshare(ns_flags)
            if rc != 0 and config.isolate_network:
                # Fallback without CLONE_NEWNET if kernel restricts netns
                _LIBC.unshare(CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS)
        except Exception:
            pass

    # 2. POSIX Resource Limits
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    try:
        cpu = max(1, int(config.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    except Exception:
        pass

    try:
        fsize = max(1, int(config.max_file_size_mb)) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    except Exception:
        pass

    try:
        nofile = max(16, int(config.max_files))
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    except Exception:
        pass

    # IMPORTANT: AddressSanitizer / MSan / TSan reserve ~16TB virtual shadow memory.
    # Setting RLIMIT_AS on ASAN binaries causes ReserveShadowMemoryRange failure (SIGABRT).
    # For sanitizer binaries we enforce RSS limits via ASAN_OPTIONS=hard_rss_limit_mb instead!
    if not uses_sanitizer_shadow and config.memory_mb > 0:
        try:
            mem_bytes = int(config.memory_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except Exception:
            pass

    # 3. seccomp-bpf syscall filter
    if config.enable_seccomp and _LIBC is not None:
        try:
            if _LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0:
                insns = build_seccomp_filter(isolate_network=config.isolate_network)
                if insns:
                    arr_type = _SockFilter * len(insns)
                    arr = arr_type(*insns)
                    prog = _SockFprog(len(insns), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
                    _LIBC.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
        except Exception:
            pass


def build_target_env(
    cov_file: Optional[str] = None,
    binary_info: Optional[Dict[str, bool]] = None,
    memory_mb: int = 256,
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Construct clean, deterministic environment for target execution."""
    env: Dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "MALLOC_CHECK_": "2",
    }

    if cov_file:
        env["ZERO_HUNTER_COV_FILE"] = cov_file

    if binary_info and binary_info.get("uses_asan"):
        rss_cap = max(64, int(memory_mb))
        asan_opts = (
            f"detect_leaks=0:abort_on_error=1:allocator_may_return_null=1:"
            f"symbolize=1:print_scariness=1:hard_rss_limit_mb={rss_cap}"
        )
        env["ASAN_OPTIONS"] = asan_opts

    if binary_info and binary_info.get("uses_ubsan"):
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"

    if extra_env:
        env.update(extra_env)

    return env


def probe_sandbox_capabilities() -> Dict[str, bool]:
    """Probe active Linux kernel sandbox features in a child process."""
    caps = {
        "linux": platform.system() == "Linux",
        "rlimits": True,
        "user_namespaces": False,
        "net_namespaces": False,
        "seccomp_bpf": False,
    }
    if _LIBC is None:
        return caps

    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            if _LIBC.unshare(CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS) == 0:
                code |= 1
            if _LIBC.unshare(CLONE_NEWNET) == 0:
                code |= 2
            if _LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0:
                insns = build_seccomp_filter(isolate_network=True)
                if insns:
                    arr = (_SockFilter * len(insns))(*insns)
                    prog = _SockFprog(len(insns), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
                    if _LIBC.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) == 0:
                        code |= 4
        except Exception:
            pass
        os._exit(code)
    else:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            mask = os.WEXITSTATUS(status)
            caps["user_namespaces"] = bool(mask & 1)
            caps["net_namespaces"] = bool(mask & 2)
            caps["seccomp_bpf"] = bool(mask & 4)
    return caps
