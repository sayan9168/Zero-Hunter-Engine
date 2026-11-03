#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Specification Grammar Generator & Checksum-Aware Patcher
Provides:
1. Context-free & binary packet grammar generation/mutation (JSON, HTTP, ZHTP, ZHV3 Vault, Token)
2. Automatic Checksum & Length-Header Repairer (IEEE CRC32, Adler32, Sum16, XOR8)
   enabling immediate penetration past integrity-checked container headers.

Educational & Authorized Defensive Research Only
"""

import json
import random
import struct
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


BUILTIN_GRAMMARS: Dict[str, Dict[str, List[str]]] = {
    "json": {
        "<start>": ['{"cmd": <cmd>, "len": <num>, "data": <str>, "nested": <obj>}'],
        "<obj>": ['{"role": <str>, "id": <num>}', "[<num>, <str>, <num>]"],
        "<cmd>": ['"AUTH"', '"READ"', '"WRITE"', '"UNPACK"', '"ADMIN"'],
        "<num>": ["0", "-1", "65536", "2147483647", "-2147483648", "4294967295"],
        "<str>": ['"AAAA"', '"%s%s%s%n"', '"' + ("A" * 96) + '"', '"ZH26"'],
    },
    "http": {
        "<start>": [
            "<method> <path> HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: <len>\r\n\r\n<body>"
        ],
        "<method>": ["GET", "POST", "PUT", "DELETE"],
        "<path>": ["/", "/api/v1/parse", "/auth?user=admin", "/" + ("A" * 80)],
        "<len>": ["0", "4", "64", "65535", "-1"],
        "<body>": ["", "PING\r\n", "A" * 80],
    },
}


class ChecksumPatcher:
    """
    Repairs binary container length & checksum headers after payload mutation
    so integrity gates (CRC32, Adler32, CmpLog-observed checksums) pass cleanly.
    """

    @staticmethod
    def crc32_le(data: bytes) -> bytes:
        return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)

    @staticmethod
    def crc32_be(data: bytes) -> bytes:
        return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)

    @staticmethod
    def adler32_le(data: bytes) -> bytes:
        return struct.pack("<I", zlib.adler32(data) & 0xFFFFFFFF)

    @classmethod
    def repair_payload(
        cls,
        data: bytes,
        mode: str = "auto",
        cmp_pairs: Optional[Sequence[Tuple[bytes, bytes]]] = None,
    ) -> bytes:
        """
        Repair checksum & length fields in `data`:
        - `crc32_vault` / `auto` on `ZHV3` frames: updates `[4..5]` length (or boundary) and `[6..9]` CRC32(data[10:])
        - Generic 4-byte tail or header CRC32 trial
        - CmpLog 4-byte checksum reflection (`op1` <-> `op2` when computed hash appeared in trace_cmp4)
        """
        if not data:
            return data

        buf = bytearray(data)

        # 1. CmpLog-guided exact 4-byte checksum fix (works on ANY unknown hash/CRC function!)
        if cmp_pairs and len(buf) >= 8:
            for op1, op2 in cmp_pairs[:16]:
                if len(op1) == 4 and len(op2) == 4:
                    pos1 = buf.find(op1)
                    if pos1 != -1:
                        buf[pos1 : pos1 + 4] = op2
                        return bytes(buf)
                    pos2 = buf.find(op2)
                    if pos2 != -1:
                        buf[pos2 : pos2 + 4] = op1
                        return bytes(buf)

        # 2. ZHV3 container layout: [0..3]="ZHV3", [4..5]=uint16 len, [6..9]=crc32(buf[10:])
        if (mode in ("auto", "crc32")) and (buf[:4] == b"ZHV3" or (mode == "crc32" and len(buf) >= 12)):
            if len(buf) < 12:
                buf.extend(b"\x10\x00" + random.randbytes(8))
            if mode == "crc32" and buf[:4] != b"ZHV3" and random.random() < 0.7:
                buf[0:4] = b"ZHV3"
            body_len = max(0, len(buf) - 12)
            # 65% accurate length, 35% inflated/boundary length to trigger OOB read/write bugs!
            declared = body_len if random.random() < 0.65 else random.choice([body_len + 32, 64, 255, 1024])
            struct.pack_into("<H", buf, 4, declared & 0xFFFF)
            buf[6:10] = cls.crc32_le(bytes(buf[10:]))
            return bytes(buf)

        # 3. Adler32 mode
        if mode == "adler32" and len(buf) >= 8:
            buf[4:8] = cls.adler32_le(bytes(buf[8:]))
            return bytes(buf)

        # 4. Generic trailing or offset-4 CRC32 injection
        if len(buf) >= 8:
            if random.random() < 0.5:
                buf[-4:] = cls.crc32_le(bytes(buf[:-4]))
            else:
                buf[4:8] = cls.crc32_le(bytes(buf[8:]))
        return bytes(buf)


class GrammarEngine:
    """
    Context-free & binary-frame specification generator for structured inputs.
    """

    def __init__(self, grammar_spec: Optional[str] = None, checksum_mode: str = "auto"):
        self.checksum_mode = checksum_mode
        self.rules: Dict[str, List[str]] = {}
        if grammar_spec:
            self.load_grammar(grammar_spec)

    def load_grammar(self, spec: str):
        if spec in BUILTIN_GRAMMARS:
            self.rules = dict(BUILTIN_GRAMMARS[spec])
            return
        p = Path(spec)
        if p.is_file():
            loaded = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.rules = {str(k): [str(x) for x in v] for k, v in loaded.items() if isinstance(v, list)}

    def expand_symbol(self, sym: str = "<start>", max_depth: int = 6) -> str:
        if max_depth <= 0 or sym not in self.rules:
            return sym
        template = random.choice(self.rules[sym])
        out = template
        for nonterm in list(self.rules.keys()):
            while nonterm in out:
                replacement = self.expand_symbol(nonterm, max_depth - 1)
                out = out.replace(nonterm, replacement, 1)
        return out

    def generate(self, seed_hint: Optional[bytes] = None) -> bytes:
        """Synthesize a grammar-valid text or binary protocol packet."""
        if self.rules:
            return self.expand_symbol("<start>").encode("utf-8", errors="ignore")

        # Smart binary/protocol synthesizer based on seed prefix or diverse templates
        if seed_hint and len(seed_hint) >= 4:
            prefix = seed_hint[:4]
            if prefix == b"ZHV3":
                rec = random.choice([0x10, 0x20, 0x30, random.randint(0, 255)])
                body = random.choice([
                    struct.pack("<i", random.choice([50000, 100000, -1, 0x7FFFFFFF])),
                    bytes([40, 0x41, 40, 0x42]),
                    random.randbytes(random.randint(4, 48)),
                ])
                pkt = bytearray(b"ZHV3\x00\x00\x00\x00\x00\x00" + bytes([rec, 0]) + body)
                return ChecksumPatcher.repair_payload(bytes(pkt), mode="crc32")

            if prefix == b"ZH26":
                op = random.choice([b"H", b"U", b"D", b"S", b"N"])
                sub = b"F" if op == b"U" else bytes([random.randint(0, 255)])
                plen = struct.pack("<H", random.choice([8, 48, 96]))
                body = random.choice([
                    struct.pack("<I", 0x1337C0DE) + b"A" * 36,
                    b"FREE" + b"B" * 12,
                    b"!" + b"C" * 16,
                    b"S" * 52,
                    struct.pack("<I", 0xBAD00000),
                ])
                return b"ZH26" + op + sub + plen + body

            if prefix == b"TOK:":
                credits = random.choice([1, 500, 1000, 1001, 65537, 131073, 0xFFFFFFFF])
                role = random.choice([ord("U"), ord("A"), 0])
                return b"TOK:" + struct.pack("<I", credits) + bytes([role])

        # General diverse protocol frames (TLV / ZHV3 / ZHTP / JSON / TOK)
        pick = random.randint(0, 4)
        if pick == 0:
            body = random.randbytes(random.randint(4, 24))
            pkt = b"ZHV3\x10\x00\x00\x00\x00\x00" + bytes([random.choice([0x10, 0x20, 0x30]), 0]) + body
            return ChecksumPatcher.repair_payload(pkt, mode="crc32")
        if pick == 1:
            return BUILTIN_GRAMMARS["json"]["<start>"][0].encode()
        if pick == 2:
            plen = random.choice([4, 64, 128])
            return b"ZHTP" + struct.pack("<H", plen) + (b"A" * random.choice([8, 64]))
        if pick == 3:
            return b"TOK:" + struct.pack("<I", random.choice([10, 65537, 65540])) + b"U"
        return b"AUTH " + (b"A" * random.choice([8, 48, 80])) + b"\n"
