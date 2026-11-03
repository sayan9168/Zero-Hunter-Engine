#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - Campaign Checkpointing & Resume Persistence
Saves and restores 64KB coverage virgin bitmap, dynamic corpus seeds, MOpt PSO
operator weights, and deduplicated crash signatures so research campaigns can
pause and resume seamlessly.

Educational & Authorized Defensive Research Only
"""

import base64
import ctypes
import json
import time
import zlib
from pathlib import Path
from typing import Any, Dict

from core.coverage import MAP_SIZE
from utils.logger import setup_logger

logger = setup_logger("checkpoint")


class CampaignCheckpointer:
    """Serializes and restores fuzzer state to/from a compressed JSON checkpoint."""

    @staticmethod
    def save(engine: Any, path: str) -> str:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cov_b64 = ""
        total_edges = 0
        seen_crashes = []
        if engine.coverage is not None:
            raw_virgin = bytes(engine.coverage.virgin_bits)
            cov_b64 = base64.b64encode(zlib.compress(raw_virgin, level=6)).decode("ascii")
            total_edges = engine.coverage.total_edges
            seen_crashes = list(engine.coverage.seen_crashes)

        corpus_items = [
            {
                "data_b64": base64.b64encode(e.data).decode("ascii"),
                "exec_time_ms": e.exec_time_ms,
                "edges_count": e.edges_count,
                "depth": e.depth,
                "fuzz_count": e.fuzz_count,
                "favored": e.favored,
                "reason": e.reason,
            }
            for e in engine.corpus.entries[:512]
        ]

        pso_weights = engine.mutator.pso.get_weights() if getattr(engine.mutator, "pso", None) else {}

        doc: Dict[str, Any] = {
            "version": "3.0.0",
            "saved_at": time.time(),
            "target": engine.config.target,
            "iteration": engine.iteration,
            "crash_count": engine.crash_count,
            "total_edges": total_edges,
            "virgin_bits_zlib_b64": cov_b64,
            "seen_crashes": seen_crashes,
            "corpus": corpus_items,
            "pso_weights": pso_weights,
        }
        out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        logger.info(f"[CHECKPOINT] Saved campaign state ({len(corpus_items)} seeds, {total_edges} edges) → {out_path}")
        return str(out_path)

    @staticmethod
    def load(engine: Any, path: str) -> bool:
        in_path = Path(path)
        if not in_path.is_file():
            return False
        try:
            doc = json.loads(in_path.read_text(encoding="utf-8"))
            if engine.coverage is not None and doc.get("virgin_bits_zlib_b64"):
                raw = zlib.decompress(base64.b64decode(doc["virgin_bits_zlib_b64"]))
                if len(raw) == MAP_SIZE:
                    engine.coverage.virgin_bits = (ctypes.c_uint8 * MAP_SIZE).from_buffer_copy(raw)
                    engine.coverage.total_edges = int(doc.get("total_edges", 0))
                    engine.coverage.seen_crashes.update(doc.get("seen_crashes", []))

            for item in doc.get("corpus", []):
                blob = base64.b64decode(item["data_b64"])
                entry = engine.corpus.add_seed(
                    data=blob,
                    exec_time_ms=float(item.get("exec_time_ms", 1.0)),
                    edges_count=int(item.get("edges_count", 0)),
                    depth=int(item.get("depth", 0)),
                    reason=str(item.get("reason", "resumed")),
                    persist=False,
                )
                if entry is not None:
                    entry.fuzz_count = int(item.get("fuzz_count", 0))
                    entry.favored = bool(item.get("favored", True))

            logger.info(
                f"[CHECKPOINT] Restored {len(engine.corpus.entries)} seeds & "
                f"{doc.get('total_edges', 0)} edges from {in_path}"
            )
            return True
        except Exception as exc:
            logger.error(f"Failed loading checkpoint {path}: {exc}")
            return False
