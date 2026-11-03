#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Entry Point
Educational & Authorized Research Only
"""

from pathlib import Path
from core.fuzzer_engine import FuzzerEngine, FuzzConfig

def main():
    # Prefer ASAN build if available
    target = "./targets/vulnerable_test/vuln_asan"
    if not Path(target).exists():
        target = "./targets/vulnerable_test/vuln"

    config = FuzzConfig(
        target=target,
        input_mode="file",
        max_iterations=3000,
        sandbox=True,
        monitor_logs=True,
        enable_triage=True,
        enable_coverage=True,
        seed_dir="seeds",
        output_dir="crashes",
    )

    # Create some basic seeds if none exist
    Path("seeds").mkdir(exist_ok=True)
    if not list(Path("seeds").glob("*")):
        (Path("seeds") / "seed1.bin").write_bytes(b"A" * 32)
        (Path("seeds") / "seed2.bin").write_bytes(b"B" * 80)
        (Path("seeds") / "seed3.bin").write_bytes(b"%n" * 16)
        (Path("seeds") / "seed4.bin").write_bytes(b"\x00" * 100)

    engine = FuzzerEngine(config)
    engine.run()

if __name__ == "__main__":
    main()
