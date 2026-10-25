<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Project Immortal: Cleanroom Reverse Engineering & Legal Architecture Standard

## 1. Legal Grounding & Precedent

Project Immortal adheres strictly to established legal precedents governing cleanroom reverse engineering, interoperability, and game preservation:
- **Sony Computer Entertainment, Inc. v. Connectix Corp.** (203 F.3d 596, 9th Cir. 2000): Reverse engineering software to produce a non-infringing, compatible product constitutes protected fair use.
- **Sega Enterprises Ltd. v. Accolade, Inc.** (977 F.2d 1510, 9th Cir. 1992): Disassembly of copyrighted object code is fair use where it is the only way to gain access to the ideas and functional elements embodied in the code.
- **Computer Associates Int'l, Inc. v. Altai, Inc.** (982 F.2d 693, 2d Cir. 1992): The Abstraction-Filtration-Comparison test excludes functional and efficiency elements from copyright protection.

---

## 2. Inviolable Cleanroom Invariants (ADR-028)

### Invariant 1: BYOD ("Bring Your Own Data") Standard
1. **Zero Copyrighted Asset Distribution**:
   - The Project Immortal source repository MUST NEVER host, store, package, or distribute proprietary models, meshes, textures, audio banks, map geometry, or game scripts.
2. **Local Dynamic Extraction**:
   - All assets remain local and private on the user's workstation.
   - The extraction tool (`immortal-extract`) accesses the user's legally acquired Paladins installation (e.g. via Steam) and extracts assets directly into the user's private local cache (`assets/extracted/` or `~/.local/share/immortal/assets/`).

### Invariant 2: Dirty Room vs. Clean Room Isolation
1. **Dirty Room (Observation & Disassembly)**:
   - Dedicated solely to binary inspection, disassembler execution (Ghidra, REA), decompiler analysis, network packet sniffing (Wireshark, eBPF), and log inspection.
   - All dirty-room artifacts live strictly in gitignored directories (`.rea/`, `dirty_room/`, `disassembly/`, `captures/`).
   - The Dirty Room outputs only formal, typed markdown specifications and protocol schemas (`docs/specs/**`).
2. **Clean Room (Specification & Implementation)**:
   - Authored strictly by engineers (or subagents) working from markdown specifications and protocol RFCs.
   - Cleanroom source code must never contain decompiled code, vendor symbol tables, or raw proprietary binary dumps.

### Invariant 3: Typed Obligation Ledgers (`.agents/ledger/**`)
- All cleanroom reconstructions derive from formal specifications backed by typed obligation ledgers linking claims to concrete verification criteria.
- Retain immutable evidence records (`evidence_id`, subject, provider, digest) in `.agents/ledger/evidence_bundle.json`.
- Formal manifest clearance (`.agents/ledger/manifest.json`) requires valid JSON schema with `"status": "verified"` and all obligations marked `"satisfied"`.
