# Zero-Hunter-Engine v3.0 (Apex Edition)

**Next-generation hybrid coverage-guided fuzzing, persistent forkserver execution, SAST source auditing, differential logic-bug discovery, root-cause localization, and OASIS SARIF v2.1.0 security reporting framework.**

> **Educational & Authorized Defensive Research Only**  
> This framework is strictly designed for **authorized defensive software testing, QA auditing, crash minimization, root-cause analysis, and secure remediation** on codebases you own or have explicit permission to test. Do **not** use for unauthorized or malicious purposes.

---

## What's New in v3.0 (Apex Zero-Day Discovery Engine)

1. **AFL-Style Persistent UNIX Pipe Forkserver + Dual `ASan + UBSan` (`instrumentation/sancov_rt.c`, `core/forkserver.py`)**
   - `constructor(65535)` persistent forkserver inside `sancov_rt.o` completes dynamic linking and 16TB ASan shadow-memory setup **once**, then clones isolated test children via `fork()` over `ZERO_HUNTER_FORKSRV_CTL_FD` / `ZERO_HUNTER_FORKSRV_ST_FD` (`"ZH30"` handshake).
   - Delivers **400–930+ exec/sec** under full `ASan + UBSan + SanCov + CmpLog + Sandbox` (up from ~150 exec/sec in v2.0).
   - `zh-cc` now enables `-fsanitize=address,undefined -fno-sanitize-recover=undefined` to catch silent signed integer overflows (`CWE-190`), shifts, and alignment bugs before they even corrupt memory.

2. **Hybrid SAST Source-Code Vulnerability & Hotspot Scanner (`core/static_analyzer.py`)**
   - Scans C/C++ source trees (`ZH-SAST-001` .. `ZH-SAST-009`) for unbounded string copies (`CWE-787`), format strings (`CWE-134`), `memcpy` bounds risks, integer wraparound (`CWE-190`), narrowing casts (`CWE-681`), command execution (`CWE-78`), and intra-procedural Use-After-Free (`CWE-416`).
   - **Static-to-Dynamic Seed Synthesis**: automatically extracts magic headers (`"ZHV3"`, `"TOK:"`, `"ZH26"`), `switch`/`case` opcodes, and checksum hints (`crc32` / `adler32`) directly from source code to seed the fuzzer's dictionary at startup.

3. **MOpt Particle Swarm Optimization (PSO) Adaptive Scheduler (`core/pso_scheduler.py`)**
   - Dynamically learns per-target operator efficiency across 7 mutation engines (`cmplog_i2s`, `dictionary`, `grammar`, `checksum_patch`, `splice`, `structure`, `native_havoc`), shifting probability mass in real time toward operators discovering new edges and crashes.

4. **Grammar Synthesis & Checksum-Aware Fuzzing + `tmin` (`core/grammar.py`, `core/minimizer.py`)**
   - Context-free grammar generator (`json`, `http`, `ZHV3` binary frames, or custom `.json` specs) paired with **`ChecksumPatcher`** (`IEEE CRC32`, `Adler32`, length-field boundary fuzzing, and CmpLog 4-byte hash reflection).
   - Checksum-aware delta-debugging minimizer (`CrashMinimizer`) recomputes container CRC32 headers during shrinking — reducing 54-byte CRC32-signed `vuln_vault` crashes down to minimal **12–14 byte** valid frames!

5. **Differential Fuzzing Engine for Non-Crashing Logic Bugs (`core/differential.py`)**
   - Runs paired forkservers (`parser_ref` vs `parser_buggy`) on identical SanCov-guided inputs to uncover **silent semantic & authorization divergences** (`decision-bypass`, `CWE-681` integer truncation, return-code mismatches, and one-sided crashes) that never trigger memory sanitizers, and automatically delta-minimizes the diverging PoC.

6. **Root-Cause Source Localization, Patch Advisor & OASIS SARIF v2.1.0 (`core/remediation.py`, `core/sarif_exporter.py`)**
   - Maps sanitizer stack frames directly to workspace `file.c:line`, extracts surrounding C/C++ source context, attaches CWE-specific defensive code fixes, and exports unified **OASIS SARIF v2.1.0** reports (`reports/latest_report.sarif`) combining dynamic crashes, differential logic bugs, and SAST findings for GitHub Code Scanning & VS Code SARIF Viewer.

7. **Campaign Checkpointing & Mission Control v3.0 Web UI (`core/checkpoint.py`, `dashboard/`)**
   - Save and resume compressed 64KB virgin bitmaps, dynamic corpus queues, and MOpt PSO weights (`--checkpoint`).
   - Upgraded **Mission Control v3.0** (`0.0.0.0:8080`) featuring CRC32 Vault & Differential Quota presets, live MOpt PSO weight bars, Differential Logic Bug inspector, Root-Cause C/C++ source & defensive patch viewer, SAST Hotspot Audit table, and one-click SARIF v2.1.0 export.

---

## Verified v3.0 Benchmarks

| Benchmark Target | Protections / Gates | Throughput | Bugs Discovered Automatically |
| :--- | :--- | :--- | :--- |
| **`vuln_vault`** (`targets/vulnerable_vault/`) | `"ZHV3"` magic + **IEEE CRC32** checksum gate + multi-opcode TLV | **~430 exec/s** (2 workers, Forkserver + ASan + UBSan) | **3/3 bugs in <1.5s**: `CWE-787` RLE stack overflow (`vuln_vault.c:72`, min `14B`), `CWE-190` UBSan signed int overflow (`vuln_vault.c:41`, `16B`), `CWE-125` OOB heap read (`vuln_vault.c:56`, min `12B`) |
| **`parser_ref` vs `parser_buggy`** (`targets/differential_test/`) | `"TOK:"` header + 32-bit vs `uint16_t` quota check | **~860–930 exec/s** (paired Forkservers) | **`CWE-681` Logic Bypass** (`ref="DENY"` vs `cand="ALLOW:65537"`, minimized to `9B` in `0.8s`) |
| **`vuln_maze`** (`targets/vulnerable_test/`) | `"ZH26"` + nested magic constants | **~450+ exec/s** (Forkserver) | `CWE-416` Heap UAF, `CWE-415` Double Free, `CWE-787` Heap/Stack OOB Write, `CWE-476` NULL Deref |
| **`vuln_net`** (`targets/vulnerable_net/`) | Stateful TCP socket protocol (`PING`/`ECHO`/`AUTH`) | Managed auto-respawn TCP loop | `CWE-787` Stack Buffer Overflow over TCP (`AUTH ` + 64B) |

---

## Project Structure

```text
Zero-Hunter-Engine/
├── core/
│   ├── fuzzer_engine.py      # v3.0 Forkserver + SAST + PSO + SanCov orchestrator
│   ├── forkserver.py         # Persistent UNIX pipe forkserver controller (ZH30)
│   ├── static_analyzer.py    # Hybrid C/C++ SAST scanner & magic/CRC hint extractor
│   ├── pso_scheduler.py      # MOpt Particle Swarm Optimization operator scheduler
│   ├── grammar.py            # Context-free grammar synth & CRC32/Adler32 patcher
│   ├── differential.py       # Paired-target differential logic-bug fuzzer
│   ├── remediation.py        # Root-cause file:line localizer & defensive patch advisor
│   ├── sarif_exporter.py     # OASIS SARIF v2.1.0 security report exporter
│   ├── checkpoint.py         # Compressed bitmap + corpus + PSO state persistence
│   ├── coverage.py           # 64KB SanCov shm bitmap + CmpLog + blackbox fallback
│   ├── corpus.py             # Favored edge-cover queue, AFLFast energy, & cmin
│   ├── mutator.py            # C++17 bridge, PSO, CmpLog I2S, grammar & checksums
│   ├── network_fuzzer.py     # Managed & external TCP/UDP protocol fuzzer
│   ├── triage.py             # ASan/UBSan/KASAN parser, CWE mapper & stack hashing
│   ├── minimizer.py          # Checksum-aware delta-debugging crash reducer (tmin)
│   └── reporter.py           # Interactive HTML, SARIF, Markdown & JSON reports
├── instrumentation/
│   ├── sancov_rt.c           # Forkserver + ASLR-invariant SanCov + CmpLog runtime
│   ├── zh-cc                 # Compiler wrapper (ASan + UBSan + trace-pc + trace-cmp)
│   └── Makefile
├── native/
│   ├── mutator_ext.cpp       # C++17 high-throughput havoc, splice & bitmap engine
│   └── Makefile
├── dashboard/
│   ├── server.py             # Live HTTP/JSON Mission Control v3.0 backend
│   └── static/index.html     # Real-time telemetry, PSO, Diff, SAST & Root-Cause UI
├── targets/
│   ├── vulnerable_vault/     # CRC32-guarded binary container target (3 CWEs)
│   ├── differential_test/    # Reference vs Buggy quota parser (CWE-681 logic bug)
│   ├── vulnerable_test/      # Multi-branch CmpLog maze & classic overflow targets
│   └── vulnerable_net/       # Stateful vulnerable TCP network daemon
├── configs/
│   ├── vault_crc32.yaml      # v3.0 CRC32 Vault + Forkserver + SAST + PSO config
│   ├── default.yaml          # Multi-worker SanCov + CmpLog campaign config
│   └── network.yaml          # Managed TCP network fuzzing config
├── tests/
│   └── test_zero_hunter.py   # 11-test end-to-end verification suite
└── main.py                   # Unified v3.0 CLI entry point
```

---

## Quick Start & CLI Usage

### 1. Build All Native Extensions & Instrumented Targets
```bash
make -C instrumentation
make -C native
make -C targets/vulnerable_vault
make -C targets/differential_test
make -C targets/vulnerable_test
make -C targets/vulnerable_net
```

### 2. Hybrid SAST Audit & Automatic Dictionary Extraction
```bash
python3 main.py audit targets/ --out-dict configs/dictionaries/auto_sast.dict
```

### 3. Crack CRC32-Protected Binary Targets (`vuln_vault`)
```bash
python3 main.py fuzz --config configs/vault_crc32.yaml
```

### 4. Differential Fuzzing for Non-Crashing Logic Bugs
```bash
python3 main.py diff \
  --ref ./targets/differential_test/parser_ref \
  --target ./targets/differential_test/parser_buggy \
  -n 600
```

### 5. Triage, Checksum-Aware Minimization (`tmin`), and SARIF v2.1.0 Export
```bash
python3 main.py triage --crash-dir crashes
python3 main.py minimize crashes/<crash>.bin -t ./targets/vulnerable_vault/vuln_vault --checksum crc32
python3 main.py sarif --crash-dir crashes --sast-path targets -o reports/latest_report.sarif
```

### 6. Launch Live Web Mission Control v3.0
```bash
python3 main.py dashboard --host 0.0.0.0 --port 8080 --demo
```

### 7. Run Automated Test Suite
```bash
pytest -v
```
