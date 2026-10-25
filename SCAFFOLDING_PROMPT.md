# Project Immortal: Master Scaffolding Prompt & Architectural Kickoff

> **Project Name**: Project Immortal (Paladins Cleanroom Game Preservation & Server Emulation)  
> **Codenames**: *Fernando* | *Immortal* ("I will not die, not yet, amigo!")  
> **Primary Workspace**: `/home/kuasha/Dev/immortal`  
> **Target Game**: *Paladins: Champions of the Realm* (Version `8.1.5839.0`, UE3 64-bit `ChaosGame`)  
> **Local Game Installation**: `/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins`  
> **Toolchain**: Rust 1.99.1 (`cargo test`), Agyis Harness (`agyis`), REA 6.5.0 (`rea`)  
> **Governing Framework**: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) | Purrfect Software Limited (PSL)

---

## 1. Executive Mission & Legal Shield

Your mission is to establish and advance **Project Immortal**, a cleanroom server emulation and game preservation suite that allows *Paladins: Champions of the Realm* to remain playable forever, free from server shutdown risks, unmaintained dependencies, and proprietary lock-in.

### Inviolable Legal & Cleanroom Invariants (ADR-028)
1. **The BYOD ("Bring Your Own Data") Principle**:
   - Zero proprietary assets (meshes, textures, audio banks, maps) may be committed to this repository.
   - All assets remain local and private, extracted directly from the user's legally acquired Steam installation using `crates/immortal-extract`.
2. **Dirty Room vs. Clean Room Isolation**:
   - Binary disassembly, decompiler inspection (Ghidra, REA), and raw packet traces exist strictly in gitignored dirty-room directories (`.rea/`, `dirty_room/`, `disassembly/`, `captures/`).
   - Cleanroom source code is authored strictly from formal markdown specifications in `docs/specs/`.
3. **Typed Obligation Ledgers**:
   - All claims and protocol structures must be tracked in `.agents/ledger/obligations.json` and backed by immutable evidence in `.agents/ledger/evidence_bundle.json`. Verified via `agyis verify`.

---

## 2. Macro Goals (G1–G6)

```
[G1: Asset Extraction] ──▶ [G2: MVP Auth & Range] ──▶ [G3: E2E Multiplayer]
          │                                                    │
          ▼                                                    ▼
[G6: Open-Source Client] ◀── [G5: Client Enhancements] ◀── [G4: Community Store]
```

- **G1 (Asset Preservation Automation)**: High-speed, headless Rust extractor reading `ChaosGame/CookedPCConsole/*.upk` packages, decompressing LZO/Zlib blocks, resolving `.tfc` external texture mips, and exporting `.gltf`, `.dds`/`.png`, and `.wav` audio.
- **G2 (MVP Server Protocol & Offline Range)**: Tokio-based auth gateway and UDP game server implementing the Unreal Engine 3 bit-packed bunch protocol. Successfully accepts client login on `127.0.0.1:9000` and boots Fernando into `ShootingRange` at `127.0.0.1:7777`.
- **G3 (Full E2E Multiplayer Game)**: Complete Siege mode game loop, actor position/rotation replication, ability cooldowns, and card loadouts.
- **G4 (Community Store & Ecosystem Runtime)**: Replaces proprietary microtransactions with open-source local/community progression.
- **G5 (Client Enhancements)**: Custom Proton launcher, ultrawide HUD fixes, FOV unlocker, and Vulkan translation improvements.
- **G6 (Full Open-Source Client Replacement)**: Native community client (Bevy/Rust or Godot 4) consuming G1 assets directly.

---

## 3. Environment & Operating Context

- **Host OS**: Linux (Arch Linux x86_64, Kernel 6.13+).
- **Proton / Wine Runtime**: The game runs under Proton 9 / Experimental.
  - *Introspection Superpower*: Proton's Wine layer is open source. Use `WINEDEBUG=+winsock,+relay` to observe socket calls and file access.
  - *Network Redirection*: Route client traffic transparently using Linux network namespaces (`ip netns`), `iptables`, or eBPF without triggering client anti-cheat.
  - *Easy Anti-Cheat (EAC)*: Under Proton, EAC runs in userland. Offline shooting range can bypass EAC by launching `Binaries/Win64/Paladins.exe` directly with target arguments.
- **Fallback Workstation**: Bare-metal Windows VFIO gaming VM available if kernel-level Windows tooling is ever required (`purradox-vfio-gaming-workstation`).

---

## 4. Immediate Research Kickoffs & Actionable Spikes

### Spike 1: UPK Header & LZO Chunk Decompression (`crates/immortal-extract`)
- Inspect sample `.upk` files from `/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/` (e.g. `Fernando.upk` or `ChaosGame.upk`).
- Implement the package summary reader and chunked LZO decompression table parser in `crates/immortal-extract`.
- Assert `cargo test` passes in $<0.20$s.

### Spike 2: Auth Handshake & Endpoint Discovery (`crates/immortal-net`)
- Examine client logs in `/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Logs/` (e.g. `MCTS-*.log`).
- Identify the authentication URL endpoints and JSON/XML payload schemas the client sends at boot.
- Implement the mock HTTP/TCP auth gateway response in `crates/immortal-net` returning a valid session ticket.

### Spike 3: Offline Shooting Range Direct Connect (`crates/immortal-server`)
- Probe command-line arguments for `Paladins.exe` (e.g. `Paladins.exe 127.0.0.1:7777 -nosteam -nomovie -open ShootingRange`).
- Implement the Channel 0 control handshake in `crates/immortal-server`: send `NMT_Hello`, receive `NMT_NetSpeed`, send `NMT_Welcome` with map `ShootingRange`.

---

## 5. Standard Project Commands

```bash
cargo test                     # Run complete Rust workspace test suite
agyis test                     # Hermetic project verification
agyis verify --spec            # Verify cleanroom specifications in docs/specs/
agyis verify                   # Formally verify typed cleanroom obligations against evidence
agyis status                   # Check harness health & attention horizon
```
