<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Project Immortal 🔥🛡️
> *"I will not die, not yet, amigo!"* — Fernando, *Paladins: Champions of the Realm*

**Project Immortal** is a cleanroom game preservation, protocol emulation, and community runtime initiative for *Paladins: Champions of the Realm* (target engine: Unreal Engine 3 64-bit, version `8.1.5839.0`).

---

## 🏛️ Legal & Architectural Precedent (The Cleanroom Shield)

Project Immortal operates under strict cleanroom engineering principles (*Sony Computer Entertainment, Inc. v. Connectix Corp.*, 203 F.3d 596):

1. **Zero Copyrighted Assets (BYOD - "Bring Your Own Data")**:
   - This repository contains **zero** proprietary models, textures, audio files, or game packages.
   - All assets are preserved locally on the user's disk, extracted dynamically from their legally acquired Steam game files via the cleanroom `immortal-extract` utility.
2. **Strict Dirty Room / Clean Room Airlock (ADR-028)**:
   - Disassembly, binary tracing (REA, Ghidra), and network sniffing occur strictly in isolated, untracked dirty-room environments (`.rea/`, `dirty_room/`).
   - Cleanroom source code and server emulators are authored strictly from formal markdown specifications (`docs/specs/`) and validated against typed obligation ledgers (`.agents/ledger/`).

---

## 🎯 Macro Roadmap (G1–G6)

- **[G1] Complete Asset Preservation Automation**:
  - High-throughput cleanroom extractor for CookedPCConsole Unreal Packages (`.upk`), Texture File Caches (`.tfc`), and FMOD audio banks.
  - Converts proprietary cooked structures to open standards (`.gltf`, `.dds`/`.png`, `.wav`).
- **[G2] MVP Server Protocol & Offline Range (Immediate Focus)**:
  - Auth gateway and UDP server implementation speaking the Unreal Engine 3 bit-packed bunch protocol.
  - Offline local simulation: boots client into `ShootingRange` sandbox with Fernando.
- **[G3] Baseline E2E Multiplayer Game**:
  - Full actor replication, health/shield tracking, ability cooldowns, and round state machines for Siege mode.
- **[G4] Community Store & Ecosystem Runtime**:
  - Decentralized local/community inventory server replacing proprietary microtransactions with unlocked champions, cosmetics, and card loadouts.
- **[G5] Modern Client Enhancements**:
  - Custom launcher, FOV unlockers, ultrawide fixes, and modern Vulkan translation shims.
- **[G6] Open-Source Client Replacement**:
  - Community-owned native client (Bevy/Rust or Godot 4) consuming G1 extracted assets and speaking G2/G3 networking.

---

## 🏗️ Workspace Crates

- [`crates/immortal-core`](crates/immortal-core): Shared game types, champion IDs, math primitives, and constants.
- [`crates/immortal-extract`](crates/immortal-extract): Cleanroom UPK package parser and LZO/Zlib chunk decompressor.
- [`crates/immortal-net`](crates/immortal-net): UE3 bitstream parser, bunch serializer, and auth protocol state machines.
- [`crates/immortal-server`](crates/immortal-server): High-performance async game server daemon (Tokio).

---

## ⚡ Verification & Harness Contracts

```bash
cargo test                     # Run complete Rust workspace test suite
agyis test                     # Hermetic project verification
agyis verify --spec            # Verify cleanroom specifications in docs/specs/
agyis verify                   # Formally verify typed cleanroom obligations against evidence
```
