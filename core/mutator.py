#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Hybrid C++17 / PSO / Grammar / Checksum-Aware Mutation Engine
Combines:
- Native C++17 high-throughput havoc & crossover splice (`native/libmutator.so`)
- MOpt Particle Swarm Optimization (PSO) adaptive operator probability scheduler
- CmpLog / RedQueen Input-to-State (I2S) magic-value & checksum solver
- Specification Grammar synthesizer & CRC32/Adler32 Checksum Patcher
- AFL-compatible dictionary token injector & Structure-aware JSON/Packet mutators

Educational & Authorized Defensive Research Only
"""

import ctypes
import json
import random
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from core.grammar import ChecksumPatcher, GrammarEngine
from core.pso_scheduler import MOptPSOScheduler
from utils.logger import setup_logger

logger = setup_logger("mutator")

INTERESTING_8 = [0x00, 0x01, 0x10, 0x20, 0x40, 0x7F, 0x80, 0xFE, 0xFF]
INTERESTING_16 = [0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_32 = [
    0x00000000,
    0x00000001,
    0x0000FFFF,
    0x00010000,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
]

DEFAULT_TOKENS: List[bytes] = [
    b"%s%s%s%s",
    b"%n%n%n%n",
    b"%x.%x.%x.%x",
    b"\x00\x00\x00\x00",
    b"\xff\xff\xff\xff",
    b"\x7f\xff\xff\xff",
    b"\x00\x00\x00\x80",
    b"../../",
    b"PING\r\n",
    b"AUTH ",
    b"ZHTP",
    b"ZHV3",
]


def _parse_afl_dict_line(line: str) -> Optional[bytes]:
    """Parse an AFL-format dictionary line like `kw="\\xde\\xad\\xbe\\xef"` or `"ADMIN"`."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "=" in line:
        _, rhs = line.split("=", 1)
        line = rhs.strip()
    if len(line) >= 2 and line[0] == '"' and line[-1] == '"':
        line = line[1:-1]

    out = bytearray()
    i = 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == "x" and i + 3 < len(line):
                try:
                    out.append(int(line[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            escapes = {"n": 0x0A, "r": 0x0D, "t": 0x09, "0": 0x00, "\\": 0x5C, '"': 0x22}
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
        out.append(ord(line[i]) & 0xFF)
        i += 1
    return bytes(out) if out else None


class MutatorEngine:
    """
    MOpt PSO-scheduled mutation engine backed by C++17 `libmutator.so` + Grammar + ChecksumPatcher.
    """

    def __init__(
        self,
        mutation_rate: float = 0.18,
        max_input_size: int = 4096,
        dict_path: Optional[str] = None,
        use_native: bool = True,
        grammar_spec: Optional[str] = None,
        checksum_mode: str = "auto",
        pso: Optional[MOptPSOScheduler] = None,
    ):
        self.mutation_rate = mutation_rate
        self.max_input_size = max(64, max_input_size)
        self.checksum_mode = checksum_mode
        self.tokens: List[bytes] = list(DEFAULT_TOKENS)
        self.grammar = GrammarEngine(grammar_spec=grammar_spec, checksum_mode=checksum_mode)
        self.pso = pso or MOptPSOScheduler()

        self.strategy_stats: Dict[str, int] = {
            "native_havoc": 0,
            "python_havoc": 0,
            "cmplog_i2s": 0,
            "dictionary": 0,
            "grammar": 0,
            "checksum_patch": 0,
            "splice": 0,
            "structure": 0,
        }
        self.last_strategy: str = "native_havoc"
        self._native = self._init_native() if use_native else None
        self._out_buf = ctypes.create_string_buffer(self.max_input_size) if self._native else None

        if dict_path:
            self.load_dictionary(dict_path)

    def _init_native(self):
        repo_root = Path(__file__).resolve().parent.parent
        native_dir = repo_root / "native"
        so_path = native_dir / "libmutator.so"
        if not so_path.exists() and (native_dir / "mutator_ext.cpp").exists():
            try:
                subprocess.run(["make", "-s", "-C", str(native_dir)], check=True, timeout=20)
            except Exception as exc:
                logger.debug(f"Native C++ mutator build skipped: {exc}")
                return None

        if not so_path.exists():
            return None

        try:
            lib = ctypes.CDLL(str(so_path))
            lib.zh_native_version.restype = ctypes.c_char_p
            lib.zh_mutate_havoc.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_uint64,
            ]
            lib.zh_mutate_havoc.restype = ctypes.c_size_t

            lib.zh_mutate_splice.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_uint64,
            ]
            lib.zh_mutate_splice.restype = ctypes.c_size_t
            return lib
        except Exception as exc:
            logger.debug(f"Could not load libmutator.so: {exc}")
            return None

    @property
    def native_enabled(self) -> bool:
        return self._native is not None

    def load_dictionary(self, dict_path: str) -> int:
        p = Path(dict_path)
        if not p.exists():
            return 0
        added = 0
        for raw_line in p.read_text(errors="ignore").splitlines():
            tok = _parse_afl_dict_line(raw_line)
            if tok and tok not in self.tokens:
                self.tokens.append(tok)
                added += 1
        logger.info(f"[*] Loaded {added} dictionary tokens from {dict_path}")
        return added

    def add_dynamic_tokens(self, new_tokens: Sequence[bytes]):
        for tok in new_tokens:
            if tok and len(tok) <= 32 and tok not in self.tokens:
                self.tokens.append(tok)
                if len(self.tokens) > 280:
                    self.tokens.pop(len(DEFAULT_TOKENS))

    def reward_strategy(self, strategy: Optional[str] = None, weight: int = 1):
        op = strategy or self.last_strategy
        if op == "python_havoc":
            op = "native_havoc"
        self.pso.record_reward(op, weight=weight)

    def mutate_cmplog(
        self,
        data: bytes,
        cmp_pairs: Sequence[Tuple[bytes, bytes]],
    ) -> Optional[bytes]:
        if not cmp_pairs:
            return None

        buf = bytearray(data if data else b"A" * 16)
        pairs = list(cmp_pairs)
        random.shuffle(pairs)

        for op1, op2 in pairs[:16]:
            for needle, replacement in (
                (op1, op2),
                (op2, op1),
                (op1[::-1], op2[::-1]),
                (op2[::-1], op1[::-1]),
            ):
                if len(needle) < 1:
                    continue
                pos = buf.find(needle)
                if pos != -1:
                    buf[pos : pos + len(needle)] = replacement
                    if random.random() < 0.35 and len(buf) < 64:
                        buf.extend(random.randbytes(random.randint(4, 32)))
                    return bytes(buf[: self.max_input_size])

        op1, op2 = random.choice(pairs)
        chosen = op2 if random.random() < 0.6 else op1
        if random.random() < 0.25 and len(chosen) in (2, 4, 8):
            chosen = chosen[::-1]

        candidate_offsets = [0, 4, 6, 8, 10, 12]
        if len(buf) > len(chosen):
            candidate_offsets.append(random.randint(0, len(buf) - len(chosen)))
        off = random.choice(candidate_offsets)
        if off + len(chosen) > len(buf):
            buf.extend(b"\x41" * (off + len(chosen) - len(buf)))
        buf[off : off + len(chosen)] = chosen
        if len(buf) < 24 and random.random() < 0.4:
            buf.extend(b"A" * random.randint(8, 48))
        return bytes(buf[: self.max_input_size])

    def mutate_dictionary(self, data: bytes) -> bytes:
        buf = bytearray(data if data else b"A" * 16)
        if not self.tokens:
            return self.mutate_python_havoc(bytes(buf))
        tok = random.choice(self.tokens)
        mode = random.choice(["overwrite", "insert", "prefix"])
        if mode == "prefix":
            buf[0:0] = tok
        elif mode == "insert":
            pos = random.randint(0, len(buf))
            buf[pos:pos] = tok
        else:
            pos = random.randint(0, max(0, len(buf) - 1))
            buf[pos : pos + len(tok)] = tok
        return bytes(buf[: self.max_input_size])

    def mutate_structure(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None

        stripped = data.strip()
        if stripped.startswith((b"{", b"[")) and stripped.endswith((b"}", b"]")):
            try:
                obj = json.loads(stripped.decode("utf-8"))
                obj = self._mutate_json_node(obj)
                return json.dumps(obj).encode("utf-8")[: self.max_input_size]
            except Exception:
                pass

        if b" " in data[:16] and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:8]):
            verb, rest = data.split(b" ", 1)
            mutated_rest = self.mutate_havoc(rest, intensity=4)
            suffix = b"\r\n" if data.endswith(b"\r\n") else (b"\n" if data.endswith(b"\n") else b"")
            out = verb + b" " + mutated_rest
            if suffix and not out.endswith(suffix):
                out += suffix
            return out[: self.max_input_size]

        if len(data) >= 6:
            buf = bytearray(data)
            body_mut = self.mutate_havoc(bytes(buf[6:]), intensity=4)
            buf[6:] = body_mut
            if random.random() < 0.6:
                plen = len(body_mut) & 0xFFFF
            else:
                plen = random.choice([0, 0xFFFF, 0x7FFF, min(0xFFFF, len(body_mut) + 64)])
            endian = "<H" if random.random() < 0.7 else ">H"
            struct.pack_into(endian, buf, 4, plen)
            return bytes(buf[: self.max_input_size])

        return None

    def _mutate_json_node(self, node):
        if isinstance(node, dict) and node:
            out = dict(node)
            k = random.choice(list(out.keys()))
            out[k] = self._mutate_json_node(out[k])
            if random.random() < 0.2:
                out["__fuzz__" * random.randint(1, 8)] = "A" * random.choice([64, 256, 1024])
            return out
        if isinstance(node, list):
            out = list(node)
            if out:
                idx = random.randrange(len(out))
                out[idx] = self._mutate_json_node(out[idx])
            else:
                out.append("A" * 128)
            return out
        if isinstance(node, str):
            return random.choice([
                node + ("A" * random.choice([32, 128, 512])),
                "%s%n%s%n",
                "\x00" * 32,
                node[::-1],
            ])
        if isinstance(node, (int, float)):
            return random.choice([0, -1, 2147483647, -2147483648, 65536, node + random.randint(-50, 50)])
        return "A" * 64

    def mutate_havoc(self, data: bytes, intensity: int = 0) -> bytes:
        if self._native is not None and self._out_buf is not None:
            seed = random.getrandbits(64) | 1
            out_len = self._native.zh_mutate_havoc(
                data,
                len(data),
                self._out_buf,
                self.max_input_size,
                intensity,
                seed,
            )
            return self._out_buf.raw[:out_len]
        return self.mutate_python_havoc(data, intensity=intensity)

    def mutate_python_havoc(self, data: bytes, intensity: int = 0) -> bytes:
        if not data:
            data = b"A" * 32
        buf = bytearray(data)
        steps = intensity if intensity > 0 else max(1, int(len(buf) * self.mutation_rate))
        steps = min(steps, 32)

        for _ in range(steps):
            strategy = random.choice(
                ["bitflip", "byteflip", "insert", "delete", "arith", "interesting", "block_clone"]
            )
            if strategy == "bitflip" and buf:
                idx = random.randrange(len(buf))
                buf[idx] ^= 1 << random.randint(0, 7)
            elif strategy == "byteflip" and buf:
                idx = random.randrange(len(buf))
                buf[idx] = random.randint(0, 255)
            elif strategy == "insert" and len(buf) < self.max_input_size:
                idx = random.randint(0, len(buf))
                buf[idx:idx] = random.randbytes(random.randint(1, 16))
            elif strategy == "delete" and len(buf) > 4:
                del_len = random.randint(1, min(16, len(buf) - 2))
                idx = random.randint(0, len(buf) - del_len)
                del buf[idx : idx + del_len]
            elif strategy == "arith" and buf:
                idx = random.randrange(len(buf))
                buf[idx] = (buf[idx] + random.randint(-35, 35)) & 0xFF
            elif strategy == "interesting" and buf:
                if len(buf) >= 4 and random.random() < 0.35:
                    idx = random.randint(0, len(buf) - 4)
                    val = random.choice(INTERESTING_32)
                    fmt = "<I" if random.random() < 0.5 else ">I"
                    struct.pack_into(fmt, buf, idx, val)
                elif len(buf) >= 2 and random.random() < 0.5:
                    idx = random.randint(0, len(buf) - 2)
                    val = random.choice(INTERESTING_16)
                    fmt = "<H" if random.random() < 0.5 else ">H"
                    struct.pack_into(fmt, buf, idx, val)
                else:
                    idx = random.randrange(len(buf))
                    buf[idx] = random.choice(INTERESTING_8)
            elif strategy == "block_clone" and len(buf) >= 4 and len(buf) < self.max_input_size:
                clen = random.randint(2, min(32, len(buf)))
                src = random.randint(0, len(buf) - clen)
                dst = random.randint(0, len(buf))
                buf[dst:dst] = buf[src : src + clen]

        return bytes(buf[: self.max_input_size])

    def mutate_splice(self, seed_a: bytes, seed_b: bytes) -> bytes:
        if self._native is not None and self._out_buf is not None:
            seed = random.getrandbits(64) | 1
            out_len = self._native.zh_mutate_splice(
                seed_a,
                len(seed_a),
                seed_b,
                len(seed_b),
                self._out_buf,
                self.max_input_size,
                seed,
            )
            return self._out_buf.raw[:out_len]

        if not seed_a:
            return self.mutate_python_havoc(seed_b)
        if not seed_b:
            return self.mutate_python_havoc(seed_a)
        split = random.randint(1, max(1, min(len(seed_a), len(seed_b)) - 1))
        merged = (seed_a[:split] + seed_b[split:])[: self.max_input_size]
        return self.mutate_python_havoc(merged, intensity=3)

    def _maybe_post_repair_checksum(
        self,
        out: bytes,
        cmp_pairs: Optional[Sequence[Tuple[bytes, bytes]]],
    ) -> bytes:
        if self.checksum_mode in ("crc32", "adler32") and random.random() < 0.80:
            return ChecksumPatcher.repair_payload(out, mode=self.checksum_mode, cmp_pairs=cmp_pairs)
        if self.checksum_mode == "auto" and len(out) >= 12 and out[:4] == b"ZHV3" and random.random() < 0.80:
            return ChecksumPatcher.repair_payload(out, mode="crc32", cmp_pairs=cmp_pairs)
        return out

    def mutate(
        self,
        data: bytes,
        mate: Optional[bytes] = None,
        cmp_pairs: Optional[Sequence[Tuple[bytes, bytes]]] = None,
    ) -> bytes:
        """
        MOpt PSO-driven adaptive mutator dispatcher.
        """
        op = self.pso.sample_operator()

        if op == "cmplog_i2s" and cmp_pairs:
            res = self.mutate_cmplog(data, cmp_pairs)
            if res is not None:
                self.last_strategy = "cmplog_i2s"
                self.strategy_stats["cmplog_i2s"] += 1
                return self._maybe_post_repair_checksum(res, cmp_pairs)

        if op == "grammar":
            self.last_strategy = "grammar"
            self.strategy_stats["grammar"] += 1
            gen = self.grammar.generate(seed_hint=data)
            return gen[: self.max_input_size]

        if op == "checksum_patch":
            self.last_strategy = "checksum_patch"
            self.strategy_stats["checksum_patch"] += 1
            mutated = self.mutate_havoc(data, intensity=3)
            return ChecksumPatcher.repair_payload(mutated, mode=self.checksum_mode, cmp_pairs=cmp_pairs)[
                : self.max_input_size
            ]

        if op == "splice" and mate:
            self.last_strategy = "splice"
            self.strategy_stats["splice"] += 1
            spliced = self.mutate_splice(data, mate)
            return self._maybe_post_repair_checksum(spliced, cmp_pairs)

        if op == "dictionary" and self.tokens:
            self.last_strategy = "dictionary"
            self.strategy_stats["dictionary"] += 1
            d_out = self.mutate_dictionary(data)
            return self._maybe_post_repair_checksum(d_out, cmp_pairs)

        if op == "structure":
            s_res = self.mutate_structure(data)
            if s_res is not None:
                self.last_strategy = "structure"
                self.strategy_stats["structure"] += 1
                return self._maybe_post_repair_checksum(s_res, cmp_pairs)

        if self._native is not None:
            self.last_strategy = "native_havoc"
            self.strategy_stats["native_havoc"] += 1
        else:
            self.last_strategy = "python_havoc"
            self.strategy_stats["python_havoc"] += 1
        out = self.mutate_havoc(data)
        return self._maybe_post_repair_checksum(out, cmp_pairs)
