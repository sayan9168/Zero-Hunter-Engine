# Zero-Hunter-Engine

**High-performance modular fuzzing framework** for discovering memory corruption, logic flaws, and race conditions.

> **Educational & Defensive Research Only**  
> This tool is strictly for **AUTHORIZED testing on systems you own or have explicit permission to test**.  
> Focus is on discovery and responsible reporting. Do **not** use for unauthorized or malicious purposes.

## Current Features

- Smart mutation-based fuzzer engine
- Real-time crash monitoring (`dmesg` / `journalctl`)
- **Crash Triage System** → Automatically classifies crashes as:
  - `Exploitable (High Risk)`
  - `Potentially Exploitable`
  - `Non-Exploitable (Low Risk)`
- Basic coverage tracking (unique crash signatures + interesting inputs)
- Process Manager with resource limits (CPU / Memory) + process-group sandbox
- Intentionally vulnerable test target included

## Project Structure

```text
Zero-Hunter-Engine/
├── core/
│   ├── fuzzer_engine.py      # Main fuzzing engine
│   ├── triage.py             # Crash classification (NEW)
│   ├── coverage.py           # Coverage guidance skeleton (NEW)
│   └── __init__.py
├── utils/
│   ├── crash_monitor.py      # Log-based crash detector
│   ├── process_manager.py    # Sandbox + resource limits (NEW)
│   ├── logger.py
│   └── __init__.py
├── targets/
│   └── vulnerable_test/      # Safe buffer-overflow target
├── configs/
├── reports/
├── main.py
└── requirements.txt
```

## Quick Start (Safe Testing)

```bash
git clone https://github.com/sayan9168/Zero-Hunter-Engine.git
cd Zero-Hunter-Engine

pip install -r requirements.txt

# Build the vulnerable test target
cd targets/vulnerable_test
make
cd ../..

# Run fuzzer (ASAN version recommended)
python3 main.py
```

### Expected Output Example
```text
[*] Zero-Hunter-Engine started on: ./targets/vulnerable_test/vuln_asan
[*] Sandbox: True | Triage: True | Coverage: True
[CRASH] Saved → crashes/crash_00000_....bin
[TRIAGE] crash_00000_... → Exploitable (High Risk) (confidence: 90%)
         Reason : AddressSanitizer / KASAN report detected
```

## Ethical Guidelines

1. Only test systems you own or have written authorization for.
2. Always run inside a VM / container with limited privileges.
3. Never disable sandboxing on production or shared systems.
4. Report findings responsibly. This tool does **not** generate weaponized exploits.

## Roadmap

- [x] Crash Triage System
- [x] Process Manager + Resource Limits
- [x] Coverage tracking skeleton
- [ ] Real instrumentation-based coverage (SanitizerCoverage / AFL-style)
- [ ] Network protocol support
- [ ] Stronger sandbox (Linux namespaces + seccomp-bpf)
- [ ] C++ high-performance mutator extension

## License

For educational and authorized security research only.
