<!-- SPDX-License-Identifier: AGPL-3.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Dirty-Room Setup & Scaffolding Guide (BYOD Cleanroom Pipeline)

This document provides a complete guide for scaffolding and operating an isolated, high-performance **Dirty Room** reverse-engineering pipeline for **Project Immortal**.

Project Immortal adheres strictly to the **Cleanroom Reverse Engineering Standard (PSL-INV-007 / ADR-028)**. No copyrighted game executables, binaries, disassemblies, or proprietary assets may ever be committed to the git repository. Instead, developers bring their own legally owned installation of *Paladins: Champions of the Realm* (**BYOD — Bring Your Own Dump/Binaries**) and scaffold a reproducible, local dirty-room analysis environment in minutes.

---

## 1. Architectural Philosophy & Cleanroom Boundaries

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DIRTY ROOM (Quarantine)                         │
│  - Storage: Fast Local NVMe (/mnt/fast_data/re_dirtyroom/ or .dirtyroom)│
│  - Raw Binaries: ShippingPC-ChaosGame.exe, MctsInterface.dll, etc.     │
│  - Ghidra Pre-Analysis Project: PaladinsProject.gpr (Indexed ~357k funcs)│
│  - SQLite Analysis DB: paladins_symbols.sqlite (817k strings, 848 RTTI)│
│  - Raw PCAPs: Wireshark captures (login, shooting range, mcts stream) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    │ Cleanroom Extraction
                                    │ (Protocols, Offsets, Spec Claims)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               FIREBREAK: CLEANROOM OBLIGATION LEDGER                  │
│  - docs/specs/CLEANROOM_LEDGER.md                                      │
│  - Typed claims, cryptographic hashes, abstract packet schemas         │
│  - Formal verification requirements & residual unknowns                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    │ Cleanroom Implementation
                                    │ (Zero proprietary bytes)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CLEAN ROOM (Repository)                         │
│  - Pure Rust implementation: crates/immortal-core, immortal-net, etc.  │
│  - Independent automated test suite: cargo test (100% hermetic)        │
│  - Community runtime & dedicated server: immortal-server               │
└────────────────────────────────────────────────────────────────────────┘
```

### The Invariants
1. **Zero Asset Pollution**: The `.dirtyroom/` folder is gitignored. Disassembly listings, decompiled C stubs, binary dumps, and Ghidra `.rep` directories must never cross the git boundary.
2. **Obligation Ledger Gate**: Every behavioral claim or network packet format derived from the dirty room must be logged in [`docs/specs/CLEANROOM_LEDGER.md`](file:///home/kuasha/Dev/immortal/docs/specs/CLEANROOM_LEDGER.md).
3. **Reproducibility**: Any developer with a licensed copy of Paladins and standard open-source tools (Ghidra, OpenJDK, Python 3, SQLite 3) can generate the exact same dirty-room database and tooling.

---

## 2. Directory Layout

The dirty room lives outside git tracking. By convention, a `.dirtyroom` symlink in the project root points to a high-speed NVMe storage directory:

```text
immortal/
├── .dirtyroom/                     # Symlink -> /mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0/
│   ├── ghidra/
│   │   ├── PaladinsProject.gpr     # Headless Ghidra permanent project
│   │   └── PaladinsProject.rep/    # Indexed binary database & program metadata
│   ├── symbols/
│   │   ├── paladins_symbols.sqlite # SQLite database (Functions, Strings, RTTI, Hashes)
│   │   ├── functions_*.jsonl       # Bulk exported Ghidra function records
│   │   └── symbols_*.jsonl         # Bulk exported Ghidra symbol records
│   ├── logs/
│   │   └── ghidra_analysis.log     # Headless analysis build log
│   └── pcaps/
│       ├── paladins_live_session.pcap
│       └── mcts_only.pcap
└── scripts/dirtyroom/
    ├── setup_dirtyroom.sh          # One-click end-to-end scaffolding script
    ├── launch_ghidra_preanalysis.sh# Headless multi-threaded Ghidra pre-analyzer
    ├── ExportGhidraData.java       # High-performance Ghidra Java bulk exporter
    ├── DecompileFunc.java          # Headless Java on-demand decompiler script
    ├── import_to_sqlite.py         # JSONL to SQLite ingestion script
    ├── index_strings_rtti.py       # High-throughput PE string & RTTI indexer
    ├── schema.sql                  # Database schema definition
    └── dirty                       # Unified CLI query tool
```

---

## 3. Prerequisites

Before running the dirty-room pipeline, ensure the following are installed:

| Tool | Minimum Version | Recommended | Purpose |
| :--- | :--- | :--- | :--- |
| **Linux OS** | Kernel 5.15+ | Arch Linux / Fedora / Ubuntu 24.04 | Host OS |
| **OpenJDK** | Java 17 | OpenJDK 21 (`/usr/lib/jvm/java-21-openjdk`) | Ghidra Runtime |
| **Ghidra** | 11.0+ | 11.2 or 12.0 (`/opt/ghidra`) | Headless Decompilation Engine |
| **Python** | 3.10+ | 3.12+ (Standard library only; zero pip dependencies) | Fast PE parsing & ingestion |
| **SQLite** | 3.35+ | 3.45+ | High-speed indexing & query engine |
| **Hardware** | 8 cores, 16GB RAM | 12+ cores (Ryzen 9 / i9), 32GB+ RAM, NVMe SSD | Fast initial pre-analysis |

---

## 4. One-Click Scaffolding (5-Minute Quickstart)

### Step 1: Set Environment Variables (Optional)
If your Paladins Steam installation or Ghidra installation is in a custom location, export them in your shell:

```bash
# Paladins 64-bit Binaries directory
export PALADINS_BIN_DIR="/path/to/SteamLibrary/steamapps/common/Paladins/Binaries/Win64"

# Path to Ghidra installation (must contain support/analyzeHeadless)
export GHIDRA_HOME="/opt/ghidra"

# Where you want the dirty-room data stored (preferably on fast NVMe)
export IMMORTAL_DIRTYROOM="/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0"

# Hardware allocation tuning
export MAX_CPU="24"                   # Number of worker threads
export GHIDRA_HEADLESS_MAXMEM="32G"   # JVM max heap size
```

### Step 2: Execute Scaffolding
Run the unified setup script from the project root:

```bash
./scripts/dirtyroom/setup_dirtyroom.sh
```

The script will automatically:
1. Verify OpenJDK, Ghidra, Python, and SQLite availability.
2. Create storage directories (`ghidra/`, `symbols/`, `logs/`, `pcaps/`) and create the `.dirtyroom` symlink.
3. Import `ShippingPC-ChaosGame.exe`, `MctsInterface.dll`, and `vivoxsdk_x64.dll` into the permanent Ghidra project and run multi-threaded headless pre-analysis.
4. Export and ingest all functions into `paladins_symbols.sqlite`.
5. Run the high-performance PE parser to index all ASCII/UTF-16 strings and RTTI classes in <10 seconds.
6. Print the dirty-room verification status.

---

## 5. Daily Reverse-Engineering with the `dirty` CLI

Once scaffolded, the `./scripts/dirtyroom/dirty` CLI provides instantaneous, sub-millisecond query capabilities directly from the terminal without launching heavy GUI tools.

### Check Status & Metrics
```bash
./scripts/dirtyroom/dirty status
```
*Output:*
```text
=== Immortal Dirty-Room Status ===
Dirty Room Root: /home/kuasha/Dev/immortal/.dirtyroom
Ghidra Project:  /home/kuasha/Dev/immortal/.dirtyroom/ghidra/PaladinsProject.gpr
  Project Exists: YES

Registered Binaries:
  - ShippingPC-ChaosGame.exe: 63.8 MB (SHA-256: 0c51d381dfe9...)
  - MctsInterface.dll: 4.5 MB (SHA-256: 90ce02b7b820...)
  - vivoxsdk_x64.dll: 5.0 MB (SHA-256: 1c4ad378fb8c...)

Indexed Database Metrics:
  Functions:    356,819
  Strings:      817,179
  RTTI Classes: 848
```

### Search Indexed Strings (<5ms)
Instantly locate string references, log messages, Unreal script names, and error strings:
```bash
# Locate network errors
./scripts/dirtyroom/dirty string "failed to get hello"

# Locate champion pawn executive functions
./scripts/dirtyroom/dirty string "TgPawn_Fernando"

# Locate map and world packages
./scripts/dirtyroom/dirty string "Shootingrange_P"
```

### Search RTTI C++ Classes (<5ms)
Inspect C++ class hierarchies, runtime type info, and vtables:
```bash
# Inspect crypto and serialization classes
./scripts/dirtyroom/dirty rtti "CryptoPP"

# Inspect network and socket classes
./scripts/dirtyroom/dirty rtti "CPack"
```

### Search Functions & Symbols (<5ms)
Look up addresses and signatures across 356k indexed functions:
```bash
./scripts/dirtyroom/dirty find "ProcessHandshake"
./scripts/dirtyroom/dirty find "CPackSocket"
./scripts/dirtyroom/dirty find "TgPlayerController"
```

### On-Demand Headless Decompilation (<6s)
Decompile any function directly to human-readable C using Ghidra's decompiler engine against the pre-analyzed `.gpr` cache:

```bash
# Decompile by virtual address in ShippingPC-ChaosGame.exe
./scripts/dirtyroom/dirty decompile 0x14002eec0

# Decompile by address in MctsInterface.dll
./scripts/dirtyroom/dirty decompile 0x18004dd50 --binary MctsInterface.dll

# Decompile by symbol name
./scripts/dirtyroom/dirty decompile "CPackSocket" --binary MctsInterface.dll
```

### MCTS Hash & Token Resolution
Look up 32-bit FNV-1a / CRC hashes and token dispatch routines:
```bash
./scripts/dirtyroom/dirty mcts 739393586
./scripts/dirtyroom/dirty mcts 0x2c123032
```

### Native Disassembly (`disasm`)
Disassemble exact instructions at any virtual address or symbol using native `objdump`:
```bash
# Disassemble 128 bytes at entry point or function address
./scripts/dirtyroom/dirty disasm 0x140b36586 --bytes 64 --limit 20

# Disassemble with specific binary
./scripts/dirtyroom/dirty disasm 0x18004e4e0 --binary MctsInterface.dll
```

### PE Section Cross-Reference Probing (`xrefs`)
Scan binary sections (.text, .rdata, .data) for references to an address or pointer:
```bash
./scripts/dirtyroom/dirty xrefs 0x18004e4e0 --binary MctsInterface.dll
```

### Network Packet Capture Inspection (`pcap`)
Quickly query dirty-room PCAP traces with Wireshark/TShark filters:
```bash
# Inspect MCTS TCP 9000 packets
./scripts/dirtyroom/dirty pcap mcts_only.pcap --filter "tcp.port==9000" --limit 15

# Inspect UDP game packets in live session
./scripts/dirtyroom/dirty pcap paladins_live_session.pcap --filter "udp.port==7777" --fields "frame.number,ip.src,ip.dst,udp.length"
```

### Window & Screen Capture (`screenshot`)
Capture the running game window or workstation screen to the artifact directory:
```bash
./scripts/dirtyroom/dirty screenshot
```

### Game & Server Process Control (`game` & `client`)
Launch and manage the local test matrix:
```bash
# Start server daemon and launch client into online flow
./scripts/dirtyroom/dirty game start

# Check active process status
./scripts/dirtyroom/dirty game status

# Tail client or server runtime logs
./scripts/dirtyroom/dirty game logs client
./scripts/dirtyroom/dirty game logs server

# Terminate all running game and server instances
./scripts/dirtyroom/dirty game kill

# Launch client with custom direct connect / travel URL
./scripts/dirtyroom/dirty client --connect "127.0.0.1:7777?Name=Fernando?Team=1"
```

---

## 6. Cleanroom Handoff Protocol

When you discover new protocol structures, packet schemas, or function behaviors in the dirty room, follow this 3-step handoff:

1. **Record the Evidence**:
   - In [`docs/specs/CLEANROOM_LEDGER.md`](file:///home/kuasha/Dev/immortal/docs/specs/CLEANROOM_LEDGER.md), add a new claim with:
     - Binary name & SHA-256.
     - Virtual Address (`0x...`).
     - Observed behavior (described in high-level prose, *not* verbatim disassembled/decompiled code).
2. **Author the Cleanroom Specification**:
   - Translate the observed packet schema into abstract byte definitions in [`docs/specs/G2_SERVER_PROTOCOL.md`](file:///home/kuasha/Dev/immortal/docs/specs/G2_SERVER_PROTOCOL.md).
3. **Implement in Pure Rust**:
   - Write the implementation in `crates/immortal-net` or `crates/immortal-core`.
   - Add hermetic unit tests with synthetic packet fixtures.
   - Run `cargo test` to verify exit code 0.

---

## 7. Troubleshooting & FAQ

#### Q: Headless analysis timed out or failed with out-of-memory error.
* **A**: A 64MB PE binary contains ~320,000 functions. Ensure `GHIDRA_HEADLESS_MAXMEM` is set to at least `16G` (recommended `32G` or `48G` on systems with sufficient RAM). Do not run headless analysis inside ephemeral `/tmp` sandboxes; use fast NVMe storage.

#### Q: Ghidra reports "PyGhidra is not available".
* **A**: Modern Ghidra versions (11.2+) require separate native wheel configuration for Python scripts. Project Immortal uses pure Java scripts (`ExportGhidraData.java`, `DecompileFunc.java`) which run directly on OpenJDK 21 without any external Python bindings.

#### Q: Why not commit `paladins_symbols.sqlite` to git?
* **A**: The SQLite database contains strings and function signatures extracted from proprietary binaries. In accordance with PSL-INV-007, git must remain 100% clean of all proprietary artifacts. Because our indexer runs in under 10 seconds, regenerating the SQLite database on any workstation is trivial.
