#!/usr/bin/env python3
"""
Zero-Hunter-Engine - Entry Point
Educational & Authorized Research Only
"""

from core.fuzzer_engine import FuzzerEngine, FuzzConfig

def main():
    config = FuzzConfig(
        target="./targets/vulnerable_test/vuln_asan",
        input_mode="file",
        max_iterations=3000,
        sandbox=True,
        monitor_logs=True,
        seed_dir="seeds",
        output_dir="crashes",
    )

    # Create some basic seeds if none exist
    from pathlib import Path
    Path("seeds").mkdir(exist_ok=True)
    if not list(Path("seeds").glob("*")):
        (Path("seeds") / "seed1.bin").write_bytes(b"A" * 32)
        (Path("seeds") / "seed2.bin").write_bytes(b"B" * 80)
        (Path("seeds") / "seed3.bin").write_bytes(b"%n" * 16)

    engine = FuzzerEngine(config)
    engine.run()

if __name__ == "__main__":
    main()
