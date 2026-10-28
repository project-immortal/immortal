<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Agentic Cleanroom Contribution Guide 🛡️🤖

This guide establishes the mandatory cleanroom engineering standards, legal precedents, airlock boundaries, and autonomous subagent orchestration protocols for contributing to **Project Immortal**.

Whether you are a human systems engineer or an autonomous coding agent operating within the Agyis subagent ladder, strict adherence to these rules is legally and technically mandatory.

---

## 1. Cleanroom Legal Architecture & Judicial Precedents

Project Immortal is an independent, interoperable game preservation effort engineered to preserve *Paladins: Champions of the Realm* perpetually. The cleanroom methodology deployed in this repository is designed to conform to established landmark precedents in intellectual property law:

### 1. Fair Use for Interoperability
- **Sony Computer Entertainment, Inc. v. Connectix Corp.**, 203 F.3d 596 (9th Cir. 2000):
  The Ninth Circuit affirmed that reverse engineering copyrighted software (including intermediate copying of disassembly and BIOS routines) for the purpose of producing a non-infringing, functionally compatible competitive product constitutes protected fair use under 17 U.S.C. § 107.
- **Sega Enterprises Ltd. v. Accolade, Inc.**, 977 F.2d 1510 (9th Cir. 1992):
  Disassembly of copyrighted object code is protected fair use as a matter of law when it provides the only means of access to functional specifications, interface parameters, and protocol constraints necessary to build interoperable software.

### 2. The Abstraction-Filtration-Comparison (AFC) Test
- **Computer Associates International, Inc. v. Altai, Inc.**, 982 F.2d 693 (2d Cir. 1992):
  The Second Circuit's landmark three-step test governs software copyright analysis:
  1. **Abstraction**: Decompose the program into hierarchical functional layers (object code, algorithms, data structures, interface signatures, modular architecture).
  2. **Filtration**: Filter out non-protectable elements, including ideas, logic dictated purely by efficiency (*merger doctrine*), external compatibility constraints (*scenes à faire*), public standards, and game mechanics.
  3. **Comparison**: Compare the cleanroom implementation strictly against the remaining protectable expressive elements. Because cleanroom crates in Project Immortal are authored purely from filtered functional specifications without copying expression, no copyright infringement occurs.

---

## 2. Dirty Room vs. Clean Room Isolation (Airlock Architecture)

To guarantee legal invulnerability and maintain the integrity of the AFC defense, Project Immortal strictly enforces an **Airlock Architecture**:

```text
+---------------------------------------------------------------------------------+
|                                 DIRTY ROOM                                      |
|  - Tools: REA CLI (6.8.0), Ghidra, Wireshark, eBPF Tracers                     |
|  - Targets: Binaries (Paladins.exe), UPK Packages, Network Traces              |
|  - Location: Isolated, strictly gitignored paths (.rea/, dirty_room/, captures/) |
|  - Agents: @agyis_investigator                                                  |
+---------------------------------------------------------------------------------+
                                       |
                                       | [AIRLOCK FILTER: Formal RFCs / Specs]
                                       v
+---------------------------------------------------------------------------------+
|                       CLEANROOM SPECIFICATION LAYER                             |
|  - Location: docs/specs/**                                                      |
|  - Artifacts: Markdown protocol specs, byte layouts, data types, packet opcodes |
|  - Agents: @agyis_planner                                                       |
+---------------------------------------------------------------------------------+
                                       |
                                       | [TYPED OBLIGATION LEDGER: .agents/ledger/]
                                       v
+---------------------------------------------------------------------------------+
|                                 CLEAN ROOM                                      |
|  - Location: crates/** (immortal-core, immortal-extract, immortal-net, etc.)   |
|  - Implementation: Pure Rust, zero decompiled snippets, zero proprietary dumps  |
|  - Verification: Hermetic sub-second unit tests, agyis verify                   |
|  - Agents: @agyis_builder, @agyis_reviewer, @agyis_custodian, @agyis_auditor     |
+---------------------------------------------------------------------------------+
```

### Airlock Rules
1. **Dirty Room Artifacts Never Enter Version Control**:
   Binary dumps, disassemblies, raw decompiled C++ code, Ghidra projects, and PCAP recordings must remain strictly inside gitignored folders (`.rea/`, `dirty_room/`, `disassembly/`, `captures/`).
2. **Cleanroom Engineers Never View Dirty Code**:
   Cleanroom implementation engineers and builders working in `crates/**` author code solely by reading cleanroom specifications in `docs/specs/` and public standards. They never directly inspect decompiled proprietary source or reverse engineering workspaces.
3. **No Direct Copy-Pasting**:
   Direct copying of decompiled C++, UnrealScript snippets, or raw binary payloads into cleanroom source code, documentation, pull requests, or issues is grounds for immediate rejection and purging.

---

## 3. The Tool-Native Reverse Engineering Invariant (PSL-INV-004 §3)

When conducting dirty-room observation or analyzing binary structures, contributors and agents must comply with the **Tool-Native Primacy Invariant**:

### Native Tooling Primacy
- **Mandatory Native REA Usage**: All binary analysis, export table discovery, xref exploration, and structural decompilation must be conducted using native `rea` CLI and MCP interfaces:
  - `rea analyze <binary>`
  - `rea decompile <address_or_function>`
  - `rea xrefs <symbol_or_address>`
  - `rea search <pattern>`
- **Strict Prohibition on Ad-Hoc Python Scrapers**:
  Contributors are strictly forbidden from writing disposable, ad-hoc Python scripts or custom one-off binary parsers to scrape UPK offsets or extract binary assets.
- **Rationale**:
  1. *Reproducibility Drift*: Ad-hoc Python scripts lack formal type safety, drift across runtime environments, and fail under edge-case endianness or bit alignment differences.
  2. *Accidental Copyright Leaks*: Unregulated scripts frequently dump unparsed proprietary blobs directly into workspace trees without attribution or hashing.
  3. *Auditability*: Native `rea` CLI operations emit structured, cryptographically hashed evidence records that integrate directly into the typed obligation ledger.

---

## 4. Obligation Ledger Governance (`.agents/ledger/**`)

Every protocol reconstruction, packet parser, and asset extractor in Project Immortal must be substantiated by an entry in the typed obligation ledger:

### 1. Schema: `.agents/ledger/obligations.json`
Each obligation record defines:
- `id`: Unique obligation identifier (e.g. `OBL-G1-001`, `OBL-G2-002`).
- `subject`: The functional module or structure under investigation (e.g. `upk_package_header`, `mcts_tcp_framing`).
- `claim`: Clear, concise functional claim (e.g. `"CookedPCConsole packages start with magic 0x9E2A83C1 and specify file version 860+"`).
- `evidence_criteria`: The empirical verification criteria and source citation (e.g. `"Inspection of ChaosGame/CookedPCConsole package binary headers"`).
- `status`: Lifecycle state (`"open"`, `"investigating"`, `"satisfied"`, `"verified"`).

### 2. Immutable Evidence Bundles: `.agents/ledger/evidence_bundle.json`
Empirical observations are recorded in an immutable evidence bundle featuring cryptographic SHA-256 digests. This guarantees that technical claims are tethered to reproducible empirical facts without checking proprietary game binaries into git.

### 3. Manifest Clearance: `.agents/ledger/manifest.json`
The project manifest aggregates all completed milestones and asserts zero residual unproven claims before release tagging.

---

## 5. Agentic Subagent Ladder Orchestration

Project Immortal employs an autonomous multi-agent ladder to maintain high-velocity execution while preserving strict cleanroom airlock boundaries:

| Subagent Role | Primary Focus | Boundary / Airlock Plane | Key Responsibilities |
| :--- | :--- | :--- | :--- |
| **`@agyis_investigator`** | Observation & Reverse Engineering | Dirty Room (`.rea/`, `dirty_room/`) | Disassembles binaries via `rea`, records empirical findings, calculates cryptographic hashes. |
| **`@agyis_planner`** | Cleanroom Specification Authoring | Airlock Boundary (`docs/specs/`) | Converts observations into typed RFC specifications; registers claims in `obligations.json`. |
| **`@agyis_builder`** | Cleanroom Implementation | Clean Room (`crates/**`) | Authors idiomatic Rust code in crates; writes sub-second hermetic tests; ensures exit code 0. |
| **`@agyis_reviewer`** | Code Quality & Airlock Audit | Clean Room Gatekeeper | Audits code for memory safety, cleanroom airlock leaks, and architectural compliance. |
| **`@agyis_custodian`** | Git Commit Gate & DCO Hygiene | Git History Gatekeeper | Verifies DCO 1.1 sign-offs, sanitizes unstaged diffs, guarantees atomic commits. |
| **`@agyis_auditor`** | Release & Ledger Certification | Verification Authority | Executes `agyis verify`, checks sha256 evidence digests, certifies manifest clearance. |

### Subagent Execution Invariants
- **Healthy Context Zone**: Maintain context length under 50,000 tokens to prevent reasoning degradation.
- **Reactive Wait Invariant**: Never poll task statuses in tight loops; await event-driven signals.
- **Zero Verification Homework**: Never declare a task complete without executing `cargo test --workspace` and asserting exit code 0.

---

## 6. Developer Certificate of Origin (DCO)

All contributions to Project Immortal—whether submitted by human developers or autonomous agents—must include a Developer Certificate of Origin sign-off in every commit message (`git commit -s`).

### DCO 1.1 Text
```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it; and

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Commit Sign-off Format
```bash
git commit -s -m "feat(core): implement champion enum for Viktor and Cassie"
```
Which appends the trailer:
```text
Signed-off-by: Developer Name <developer@example.com>
```
Contributions without a valid DCO sign-off will be rejected by the automated CI gate.
