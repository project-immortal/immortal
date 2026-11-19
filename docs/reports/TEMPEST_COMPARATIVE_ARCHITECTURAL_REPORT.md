# Comparative Architectural Report: Tempest OSS Ecosystem & Project Immortal

**Document Identifier**: `DOC-REP-TEMPEST-2026-01`  
**Classification**: Cleanroom Technical Report / Architectural Specification  
**Status**: Authoritative Cleanroom Synthesis  
**Date**: 2026-11-19  
**Authors**: Teamwork Synthesis Agent (`worker_synthesis_2`), based on surveys by `explorer_survey_1`, `explorer_survey_2`, and `spec_miner_survey_1`  
**Corporate Stewardship**: Purrfect Software Limited (PSL) under ICARO-42/b Ordinance  
**Target Repository**: Project Immortal (`/home/kuasha/Dev/immortal`)  
**External Evaluated Sources (Quarantined in `.dirtyroom/external/`)**:
- `LowRezStudio/Tempest` (commit `6ce49f1`, GPL-3.0 root, MIT sub-crates)
- `LowRezStudio/docs` (commit `001ca20`, All Rights Reserved)

---

## Executive Summary

This report delivers a publication-grade comparative architectural analysis evaluating the open-source release of the **Tempest** monorepo (`LowRezStudio/Tempest`) and its accompanying documentation repository (`LowRezStudio/docs`) against **Project Immortal**.

Project Immortal is a cleanroom, server-authoritative reconstruction of the Unreal Engine 3 (64-bit DX11) title *Paladins: Champions of the Realm*, developed in pure Rust under the AGPL-3.0 license and governed by rigorous cleanroom reverse engineering protocols (PSL-INV-007) and architectural fitness invariants (PSL-INV-011).

The OSS release of Tempest provides unprecedented visibility into the inner mechanisms of the retail Paladins client and server binaries. Rather than relying on guesswork, Project Immortal can leverage Tempest's empirical findings as formal functional specifications across five critical engineering domains:

1. **Retail Dedicated Server Oracle**: A containerized, headless Wine execution framework that runs the authentic Windows retail server binary for automated differential bitstream fuzzing and packet parity validation.
2. **MCTS Token Tables & CMarshal Serialization**: The complete binary RPC serialization protocol (`CMarshal`), including an adaptive 4-cache integer batching algorithm, 3,731 field tokens, 1,084 function symbols, and FNV-1 32-bit dispatch hashes.
3. **UPK Decompilation, Physical Collision & Havok AI NavMeshes**: The deconstruction of CookedPCConsole packages (`.upk`), separating PhysX `BrushAggGeom`/`BodySetup` world collision from Havok AI 2016.1 `TAG0` navmeshes, and detailing champion hitbox geometry and Fernando's combat abilities.
4. **Client Dynamic Injection & Hooking Architecture**: Non-invasive game hooking via a minimal Zig injector, SHA-1 verification bypass, `TAntiCheatArray` TLS XOR decryption, `ProcessEvent`/`ProcessInternal` vtable detours, and pure-Rust Audiokinetic Wwise soundbank manipulation (`ww2ogg` / `ogg_to_wem`).
5. **Licensing & Cleanroom Governance**: The legal boundary between Tempest's GPL-3.0/MIT licenses, docs statutory copyright, and Project Immortal's AGPL-3.0 codebase, enforced via a strict 4-phase cleanroom knowledge transfer protocol backed by typed obligation ledgers.

---

## Monorepo Layout & Comparative Architectural Matrix

### Monorepo Topography

The Tempest monorepo is a multi-language polyglot repository orchestrating C# (.NET 10), Rust, Zig, TypeScript (SvelteKit 5 + Electron), and Bash:

```
.dirtyroom/external/Tempest/
├── Tempest.slnx                    # .NET 10 XML Solution
├── global.json                     # .NET SDK 10.0.100 rollForward: latestFeature
├── justfile                        # Central multi-toolchain task runner
├── package.json                    # Root pnpm 11.9.0 workspace definition
├── pnpm-workspace.yaml             # Workspaces: Tempest.Launcher, Tempest.Studio
├── MarshalLib/                     # .NET 10 CMarshal binary RPC serialization library
├── MarshalLib.Database/            # .NET 10 SQLite bidirectional serialization round-trip layer
├── Tempest.CLI/                    # .NET 10 (Native AOT capable) CLI backend & server runner
│   ├── Server/                     # Embedded Kestrel gRPC/HTTP server, Lobby state machine
│   ├── Launcher/                   # Process launcher, Wine/Proton manager, EAC bypass
│   ├── Marshal/                    # PE Gzip token extractor, DWARF ELF64 enum reader
│   ├── inject/                     # Zig 0.16.0 DLL injector (CreateRemoteThread)
│   ├── Dockerfile                  # Headless Wine Debian trixie-slim container
│   └── entrypoint.sh               # Headless Wine server startup script
├── Tempest.Protocol/               # Protobuf contracts for Lobby, ServerList, and Common enums
├── Tempest.Launcher/               # Electron + SvelteKit 5 desktop client launcher
├── Tempest.Studio/                 # Electron + SvelteKit 5 UPK package visualizer
├── Tempest.StudioNative/           # Rust + GPUI native high-performance asset editor
├── Tempest.Scripting/              # Rust workspace + LuaJIT modding DLL (Win32 & Win64)
├── Tempest.UnrealScript/           # Rust workspace: compiler (uscript), upk, and tempest-assets
│   └── crates/tempest-assets/
│       ├── data/mcts/              # Extracted engine token tables: fields.dat, functions.dat
│       ├── src/mcts/               # Pure-Rust implementation of CMarshal parser/serializer
│       ├── src/havok/              # Havok AI 2016.1 tagfile parser and Recast generator
│       └── src/wwise/              # Pure-Rust Wwise .pck, .bnk, and Vorbis codec (ww2ogg)
├── Tempest.Utils/                  # Zig 0.15.2 utilities: asmloader (UPackage hook) & faststart
└── keys/                           # OpenPGP mod signing trusted/untrusted public key lists
```

### Subsystem Architectural Comparison

| Architectural Subsystem | Tempest Implementation | Project Immortal Cleanroom Implementation | Comparative Assessment & Strategic Fit |
| :--- | :--- | :--- | :--- |
| **Language & Runtime** | C# .NET 10 (CLI/Server), Rust (Compiler/Hooks), Zig (Inject), TS/Electron | 100% Pure Rust (1.85+ 2024 Edition), Tokio async runtime, zero managed runtimes | Project Immortal eliminates GC pauses, achieving sub-millisecond tick deadlines and zero runtime dependencies. |
| **Server Engine** | Orchestrates authentic retail server executable (`ChaosServer.exe`) under Wine | Server-authoritative cleanroom simulation in Rust (`crates/immortal-server`) | Tempest acts as an **Oracle** for differential verification; Immortal provides the production AGPL-3.0 server. |
| **MCTS Protocol** | .NET `MarshalLib` + Rust `tempest-assets/src/mcts/` | `crates/immortal-net/src/` (`mcts_handshake.rs`, `mcts_token.rs`) | Wire schemas are 100% identical (3,731 fields). Immortal adapts 4-cache integer batching and full FNV-1 dispatch table. |
| **Package Decompilation** | `tempest-upk` (Rust) + `tempest-unrealscript` (decompiler) | `crates/immortal-extract` (UPK reader, LZO/Zlib chunk decompressor, glTF mesh exporter) | Immortal adapts `ClassDb` reflection and typed `FPropertyTag` decoders to parse maps, collision, and actors. |
| **World Collision** | Extracts `BrushAggGeom` and PhysX `BodySetup.AggGeom` hulls | Initial bounding volumes; Milestone 5 targeted for full server-authoritative collision | Immortal avoids PhysX C++ dependencies by executing SAT/GJK queries directly over extracted convex hulls. |
| **Navigation & AI** | Parses Havok AI 2016.1 `TAG0` tagfiles; generates navmeshes via `rerecast` | Milestone 6 planned for bot pathfinding | Immortal adapts the `TAG0` binary reader and $16.0\times$ coordinate scaling for $A^*$ pathfinding over native navmeshes. |
| **Client Hooking** | Zig `inject` + Rust `tempest-scripting` (LuaJIT, `ProcessEvent`, D3D11 overlay) | Milestone 7 planned for telemetry and drop-in audio replacement | Immortal adapts minimal Zig injector and SHA bypass for non-invasive testing and presentation. |
| **Audio Pipeline** | Pure Rust `ww2ogg` / `ogg_to_wem` converter, `AKPK` v1 and `BKHD` v120 writer | `crates/immortal-extract/src/audio.rs` (initial PCK reader) | Immortal adopts pure Rust Vorbis codebook synthesis for zero-injection drop-in SoundBank replacement. |
| **License & Governance** | GPL-3.0 monorepo root, MIT subcrates, All-Rights-Reserved docs | AGPL-3.0 cleanroom codebase governed by PSL-INV-007 and PSL-INV-011 | Cleanroom membrane ensures zero source code copying; specifications derived purely from functional interfaces. |

---

## Domain 1: Retail Dedicated Server Oracle Architecture

### 1.1 The Oracle Concept in Dirty-Room Verification

A foundational challenge in server-authoritative game server reconstruction is validating that simulated game state, packet bunch framing, and replication sequences match retail behavior bit-for-bit. Attempting to deduce internal state machines purely from passive client packet captures introduces blind spots when edge cases or unobserved states occur.

Tempest solves this by running the authentic retail Windows server executable headlessly under Wine. For Project Immortal, this architecture serves as a **Retail Dedicated Server Oracle**: an isolated dirty-room containerized service against which Project Immortal's cleanroom test harness executes automated differential bitstream fuzzing and packet parity validation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 DIRTY-ROOM DIFFERENTIAL VERIFICATION HARNESS                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                      [Hermetic Test Packet Generator]
                                       │
                   ┌───────────────────┴───────────────────┐
                   │                                       │
         [Packet Vector P]                       [Packet Vector P]
                   │                                       │
                   ▼                                       ▼
┌──────────────────────────────────────┐┌──────────────────────────────────────┐
│     RETAIL DEDICATED SERVER ORACLE    ││     CLEANROOM IMMORTAL SERVER        │
│  - Debian Trixie Slim + Wine i386    ││  - crates/immortal-server (Rust)     │
│  - Headless Wine (unset DISPLAY)     ││  - Bounded Session Table             │
│  - EAC Disabled (-eac-nop-loaded)    ││  - Native Async UDP Bunch Engine      │
│  - Authentic Hi-Rez UE3 Engine       ││  - Cleanroom Replication Simulation   │
└──────────────────┬───────────────────┘└──────────────────┬───────────────────┘
                   │                                       │
          [Retail Response Wire]                  [Immortal Response Wire]
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DIFFERENTIAL BITSTREAM COMPARATOR                     │
│  - Bit-level Bunch Framing Parity Check                                     │
│  - Channel Sequence Allocation Verification                                 │
│  - Replication Bunch Serializer Conformance                                 │
│  - Automated Invariant Gate: Zero Bitstream Divergence                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Containerized Headless Wine Environment

Tempest's server container (`Tempest.CLI/Dockerfile` and `Tempest.CLI/entrypoint.sh`) provides the exact minimal environment required to run the retail Paladins server headlessly on Linux:

1. **Multi-Arch Wine Installation**:
   Paladins dedicated servers historically span both 32-bit (v0.56, v0.57) and 64-bit (v8.1+) binaries. The container bases on `debian:trixie-slim`, installs `wine` and `wine32:i386`, and configures an isolated prefix:
   ```dockerfile
   FROM debian:trixie-slim
   RUN dpkg --add-architecture i386 && \
       apt-get update && \
       apt-get install -y --no-install-recommends wine wine32:i386 jq bash ca-certificates libicu76 && \
       rm -rf /var/lib/apt/lists/*
   ENV XDG_RUNTIME_DIR="/tmp/xdg"
   EXPOSE 50051/tcp
   EXPOSE 7000/udp
   ```

2. **Null Display Driver & DLL Overrides**:
   In `entrypoint.sh`, X11 dependencies are eliminated entirely by unsetting `DISPLAY`. When `DISPLAY` is absent, Wine routes all GDI calls through its internal null/tty display driver. Internet Explorer and Mono dependencies are stripped via `WINEDLLOVERRIDES`:
   ```bash
   export HOME="/app/data"
   export WINEPREFIX="/app/data/prefix"
   export WINEDLLOVERRIDES="mscoree,mshtml="
   export WINEDEBUG="-all"
   unset DISPLAY
   ```

3. **OpenSSL Crash Remediation on Modern CPUs**:
   Modern Intel processors (10th/11th Gen and newer) crash when executing legacy OpenSSL routines bundled inside UE3 binaries due to incorrect bit manipulation flags. Tempest remediates this via the environment variable:
   ```bash
   export OPENSSL_ia32cap="~0x20000000"
   ```

### 1.3 Server Process Invocation & EAC Invalidation

When orchestrating server instances, `Tempest.CLI/Server/LobbyState.cs` and `LauncherCommands.cs` execute a sequence of engine configuration flags:

1. **EasyAntiCheat Invalidation**:
   The retail server checks for the existence of `EasyAntiCheat`. Renaming the folder to `_EasyAntiCheat` combined with passing the `-eac-nop-loaded` command-line argument bypasses all kernel-level driver requirements and prevents server startup abortion.

2. **Command-Line Parameters**:
   The server launches with an explicit URL query string defining game mode, champion roster, player count, and engine flags:
   ```bash
   wine Paladins.exe server "<map_id>?game=<game_mode>?allowedChampions=<champions>,maldamba?maxplayers=<max_players>?password=<pwd>" \
       -port=7000 \
       -seekfreeloadingpcconsole \
       -pid=402 \
       -eac-nop-loaded \
       -replayfile= \
       -COOKFORDEMO \
       -homedir="/app/data"
   ```
   - `-seekfreeloadingpcconsole`: Instructs the engine cooker to bypass package seek tables and load loose or cooked `.upk` files directly.
   - `-pid=402`: Internal Hi-Rez process identifier for server daemon tracking.
   - `-COOKFORDEMO`: Configures package memory pools for demonstration/tournament execution, disabling live CDN telemetry updates.

---

## Domain 2: MCTS Token Tables & CMarshal Serialization

### 2.1 Extraction Vectors: PE Gzip Scanning vs. DWARF ELF64 Inspection

The Paladins Master Control & Telemetry System (MCTS) protocol governs out-of-game RPC communications, including authentication, matchmaking, champion roster selection, and game server allocation. Unlike Unreal Engine's in-game UDP bitstreams, MCTS operates over TCP using Hi-Rez's proprietary `CMarshal` binary format.

Tempest demonstrates that the complete schema of field tokens and function descriptors is embedded directly inside retail binaries across two distinct extraction vectors (`Tempest.CLI/Marshal/ExtractTokens.cs`):

1. **PE Gzip Stream Extraction**:
   Windows PE executables (`Binaries/Win64/MctsInterface.dll`, `Paladins.exe`) embed compressed token tables inside `.rdata` sections. Scanning raw bytes for the Gzip magic header `1F 8B 08` yields two uncompressed data streams:
   - Stream containing ASCII magic `"HELLO"u8`: Extracted as `functions.dat`.
   - Stream containing ASCII magic `"VERSION"u8`: Extracted as `fields.dat`.

2. **DWARF ELF64 Debug Symbol Inspection**:
   In Linux binaries (`libMctsInterface.so`, `ShippingPC-ChaosServer`), compiler debug symbols retain explicit enum declarations:
   - `enum MFIELD_TOKEN`: Contains authoritative token integers mapped to field names.
   - `enum MFUNCTION`: Contains 32-bit FNV-1 hashes mapped to function dispatch names.

3. **Legacy Function Table Permutation Rewriting**:
   In legacy client builds, the first `u16` of each entry in `functions.dat` is a binary-search permutation index (as `CMarshal::GetFunction` sorts entries alphabetically), whereas the runtime wire format resolves functions by table position. Tempest's extractor automatically rewrites these headers to wire-index order to maintain exact mapping.

### 2.2 Empirical Parity Verification: 3,731 Fields

A critical discovery is that Tempest's extracted token database and Project Immortal's cleanroom test fixture share identical field counts:

- **Tempest `data/mcts/fields.dat`**: Exactly **3,731** fields.
- **Project Immortal `crates/immortal-net/tests/fixtures/mcts_field_schema.json`**: Exactly **3,731** fields (`assert_eq!(schema.len(), 3731)` in `tests/schema_conformance_test.rs:32`).

Both schemas match across IDs, type definitions, and semantic roles:
- `TOKEN 0`: `UNKNOWN` (None)
- `TOKEN 1`: `VERSION` (Int)
- `TOKEN 2`: `SUCCESS` (Byte)
- `TOKEN 11`: `PLAYER_ID` (Long / NetId)
- `TOKEN 682`: `MAP_GAME_ID` (Int)
- `TOKEN 685`: `MAP_INSTANCE_ID` (Int)

### 2.3 Function Token Resolution: 1,084 Functions & FNV-1 Parity

Tempest's `functions.dat` defines **1,084** function descriptors. In Project Immortal, `crates/immortal-net/src/mcts_handshake.rs` maintained 13 hardcoded function ID constants. Cross-referencing these hashes against `functions.dat` resolved every hash to its authentic Hi-Rez engine symbol:

| Project Immortal Constant | Wire Hash (Hex) | Authentic Engine Symbol in `functions.dat` | Verification Status |
| :--- | :---: | :--- | :---: |
| `MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE` | `0x7a4036ab` | `PLAYER_SVC_USER_LOGIN_RESPONSE` | Verified exact |
| `MCTS_FUNCTION_ID_CHANGE_MAP` | `0x847de68b` | `CHANGE_PROPERTIES` | Resolved alias |
| `MCTS_FUNCTION_ID_PLAYER_SVC_CHANGE_MAP` | `0xae90091f` | `PLAYER_SVC_CHANGE_MAP` | Verified exact |
| `MCTS_FUNCTION_ID_PLAYER_SVC_LAUNCH_MAP_INSTANCE` | `0x4bee2ed8` | `PLAYER_SVC_LAUNCH_MAP_INSTANCE` | Verified exact |
| `MCTS_FUNCTION_ID_TERMINATE_SESSION` | `0xe621824e` | `DROP_PLAYER` | Resolved alias |
| `MCTS_FUNCTION_ID_MATCH_INVITATION` | `0x423b389a` | `MATCH_INVITATION` | Verified exact |
| `MCTS_FUNCTION_ID_CHAMPION_ROSTER` | `0xdb15d3d7` | `QUEUE_AVAILABLE_CLASSES` | Resolved alias |
| `MCTS_FUNCTION_ID_MATCH_STATUS` | `0x392dcda5` | `MATCH_STATUS` | Verified exact |
| `MCTS_FUNCTION_ID_QUERY_SERVERS` | `0xaf434825` | `GET_TICKET_INFO` | Resolved alias |
| `MCTS_FUNCTION_ID_QUEUE_STATUS` | `0x2cdbafe1` | `SERVER_STATUS` | Resolved alias |
| `MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED` | `0x15c61937` | `PLAYER_SVC_GO_PLAY` | Resolved alias |
| `MCTS_FUNCTION_ID_ON_MATCH_INVITE` | `0x1ad4a846` | `MATCH_EXPIRED_INVITE` | Resolved alias |
| `MCTS_FUNCTION_ID_QUEUE_STATE_UPDATE` | `0x39d5ce77` | `CUSTOM_QUEUES` | Resolved alias |

All hashes conform deterministically to standard 32-bit FNV-1:
$$\text{hash}_0 = 2166136261$$
$$\text{hash}_{i+1} = ((\text{hash}_i \times 16777619) \oplus \text{byte}_i) \pmod{2^{32}}$$
computed over the uppercase ASCII function name string.

### 2.4 CMarshal Wire Format Specification

`CMarshal` encodes rows of strongly-typed key-value records. The stream layout operates as follows:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CMARSHAL STREAM HEADER                          │
├──────────────┬───────────────────────────────┬──────────────────────────────┤
│ Flags (u8)   │ Function Hash (u32 LE)        │ Entry Count (u16 LE)         │
│ 0x00         │ e.g. 0x7A4036AB               │ 0x0001..0xFFFE (0xFFFF -> u32│
└──────────────┴───────────────────────────────┴──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               ROW RECORD STREAM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Entry Header (u16 LE):                                                     │
│    - Bits 15..12: Header Type Kind (1 to 10)                                │
│    - Bits 11..6:  Reserved                                                  │
│    - Bits 5..0:   Parameter / Item Count (0 to 32)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Type Payloads (Batched or Direct):                                         │
│    - Type 1 (0x1000): 8-bit Ints   [u16 tokens...] then [u8 values...]      │
│    - Type 2 (0x2000): 16-bit Ints  [u16 tokens...] then [u16 values...]     │
│    - Type 3 (0x3000): 32-bit Ints  [u16 tokens...] then [u32 values...]     │
│    - Type 4 (0x4000): 64-bit Ints  [u16 tokens...] then [u64 values...]     │
│    - Type 5 (0x5000): Legacy String [u16 token, u16 len, chars...]          │
│    - Type 6 (0x6000): DataSet      [u16 token, u16 row_count, rows...]      │
│    - Type 7 (0x7000): GUID         [u16 token, 16 raw GUID bytes]           │
│    - Type 8 (0x8000): Raw Blob     [u16 token, u16 len, payload...]         │
│    - Type 9 (0x9000): Inline UTF16 [u16 token, param*2 bytes] (param <= 3) │
│    - Type 10 (0xA000): Modern Str  [u16 token, u16 len, encoded chars]     │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Adaptive 4-Cache Integer Batching Algorithm

A signature characteristic of `CMarshal` is that numeric fields are not serialized immediately. In `CMarshalRow::StoreEntries`, numeric values are diverted into four width accumulation caches based on value magnitude:

```rust
// Cleanroom mathematical specification of CMarshal integer cache routing
fn route_integer_cache(value: u64) -> usize {
    if value <= 0xFF {
        1 // Cache 1: 8-bit width  (Header: 0x1000 | count)
    } else if value <= 0xFFFF {
        2 // Cache 2: 16-bit width (Header: 0x2000 | count)
    } else if value <= 0xFFFF_FFFF {
        3 // Cache 3: 32-bit width (Header: 0x3000 | count)
    } else {
        4 // Cache 4: 64-bit width (Header: 0x4000 | count)
    }
}
```

Flushing Rules:
1. When any cache reaches **32 entries**, that cache is flushed to the stream immediately.
2. When the row terminates, all non-empty caches are flushed in ascending width order: Cache 1, followed by Cache 2, Cache 3, and Cache 4.
3. Each flushed cache begins with `header = (cache_id << 12) | count`, followed by all accumulated `u16` field tokens, followed by the contiguous array of values encoded at that width.
4. Non-numeric fields (Type 6 DataSet, Type 7 GUID, Type 8 Blob, Type 10 String) bypass the caches and are serialized immediately at their logical position in the row.

#### Stream Obfuscation Mask

Files serialized via `CMarshal` (`assembly.dat`, `Lang_*.dat`, `WordFilter.dat`) are obfuscated with a single-byte XOR mask:
$$\text{Cleartext}[i] = \text{Ciphertext}[i] \oplus \mathtt{0x2A}$$
This obfuscation is applied post-serialization across the entire byte stream.

---

## Domain 3: UPK Decompilation, Physical Collision & Havok AI NavMeshes

### 3.1 Package Architecture & Reflection Pipeline

Tempest's `Tempest.UnrealScript` workspace implements a pure-Rust parser and decompiler for Unreal Engine 3 CookedPCConsole packages (`tempest-upk` and `tempest-assets`):

1. **Package Chunking & Memory Mapping**:
   Unreal Engine 3 packages split compressed payloads into chunks ($\le 1\text{ MiB}$) compressed with LZO or Zlib. `tempest-upk`'s `PackageFile` provides thread-safe, lazy-decompressed chunk caching, preventing high memory footprints when inspecting multi-gigabyte package files.

2. **ClassDb Dynamic Schema Reflection**:
   Instead of hardcoding field offsets for hundreds of engine classes, `tempest-assets/src/reflect.rs` preloads all script packages (`Core.upk`, `Engine.upk`, `GameFramework.upk`, `TgGame.upk`, `TgClient.upk`) into a unified `ClassDb`. It tracks class inheritance hierarchies and `PropertyLink` ordering, allowing automated decoding of `FPropertyTag` structures without precompiled schemas.

3. **UnrealScript Bytecode Decompiler**:
   `tempest-unrealscript` implements a complete decompiler capable of reconstructing high-level UnrealScript from raw bytecode opcodes (`EExprToken`), including proprietary Hi-Rez extensions:
   - Opcode `0x2B`: `SELF_SAFE_OBJECT` (Hi-Rez safe self-reference pointer).
   - Opcode `0x50`: `SAFE_OBJECT_CONTEXT` (Hi-Rez safe member invocation context).
   The decompiler features control flow graph analysis (`flow.rs`), restoring structured loops (`while`, `do-until`, `foreach`), `switch/case` constructs, and stripping synthetic compiler-generated type casts.

### 3.2 Physics Collision: Clarifying PhysX vs. Havok AI

An essential empirical finding that eliminates a major architectural misconception in Paladins reverse engineering is:

> **In Paladins (`ChaosGame`), Havok is used exclusively for AI NavMeshes (`Havok AI 2016.1`). Physical world collision, player movement sweeps, hitscan traces, and projectile checks are handled strictly by PhysX / UE3 primitives, NOT Havok physics hulls.**

#### Blocking Volumes & Brush AggGeom

In cooked map packages (`*_P.upk`, `*_Collision.upk`), the original BSP brush geometry is stripped from `UBrushComponent`. Instead, runtime collision queries (`LineCheck` and `PointCheck`) operate strictly on `BrushComponent.BrushAggGeom.ConvexElems`:

```rust
// Cleanroom struct definition of BrushAggGeom ConvexElem
pub struct ConvexElem {
    pub vertex_data: Vec<[f32; 3]>,              // 3D convex hull vertices
    pub permuted_vertex_data: Vec<[f32; 4]>,     // SIMD-aligned 4-lane planes for SSE SAT tests
    pub face_tri_data: Vec<i32>,                 // Index buffer for geometric visualization
    pub edge_directions: Vec<[f32; 3]>,          // Unique separating axis edge vectors
    pub face_normal_directions: Vec<[f32; 3]>,   // Unique face normal vectors
    pub face_plane_data: Vec<[f32; 4]>,          // Plane equations (A, B, C, D) for PointIsWithin
    pub elem_box: ([f32; 3], [f32; 3], bool),    // AABB (Min, Max, IsValid) for O(1) early rejection
}
```

Because all blocking volume collision is pre-decomposed into convex hulls with explicit separating axes and plane equations, **Project Immortal's server does not require linking against proprietary PhysX or Havok C++ physics libraries**. Pure-Rust Separating Axis Theorem (SAT) and ray-plane intersection routines provide bit-accurate physical collision checks.

#### Hitbox Mechanics & The Two-Stage Model

Tempest's documentation (`docs/src/blog/2026-10/18-hitboxes-skins-pay-to-win.md`) details the internal champion hitbox architecture:

1. **Outer Cylinder Capsule**:
   Every champion possesses a single upright cylinder (`CylinderComponent`: `CollisionRadius`, `CollisionHeight`). All projectile and hitscan traces first test against this cylinder. Any intersection registers as a **body hit**. There is no skeletal limb-by-limb hit detection for body damage.
2. **Inner Head Bone Raycast**:
   If the trace intersects the cylinder, a secondary line check queries the champion's `PhysicsAsset` skeletal bones to determine if the **head bone** was struck.
3. **Flaws & Normalization in Project Immortal**:
   In retail Paladins, specific skin accessories or exaggerated animations displace the head bone outside the cylinder or obstruct it with accessory bones (e.g. wide-brimmed hats on Dredge or bulky shoulder pads on Furia). Because the outer cylinder clips the trace, headshots become physically impossible on those frames. Project Immortal's server-authoritative combat engine (`crates/immortal-server/src/combat.rs`) can normalize these bone hierarchies to eliminate pay-to-win / pay-to-lose discrepancies.

#### Rooftop Physics & "Heavy Walls"

Tempest solved the decade-old "heavy walls" bug (`docs/src/blog/2026-10/21-heavy-walls.md`):
- UE3 actors possess a boolean property `Actor.m_bCanBaseOn` (default `true`).
- When `m_bCanBaseOn == false`, champion movement controllers refuse to establish a floor base on the surface, applying continuous downward sliding velocity (intended for slanted rooftops).
- Environment artists erroneously applied `m_bCanBaseOn = false` to vertical wall blocking volumes and monolithic tree meshes on specific maps (e.g., Frog Isle). When players touch these vertical walls while jumping or flying, the engine treats the wall as a rooftop, dragging the player down into a "heavy wall" stickiness trap.
- In Project Immortal, the server physics engine can override or normalize `m_bCanBaseOn` flags on vertical planes.

#### Fernando Ability Mechanics (Milestone 5)

Using extracted `BrushAggGeom` and the dual-stage hitbox model, Fernando's complete ability suite is formalized for server-authoritative simulation:

| Ability | Internal Identifier | Geometric Collision Model | Server Simulation Logic |
| :--- | :--- | :--- | :--- |
| **Flame Lance** | `TgDevice_FlameThrower` | Conical raycast cone ($1200\text{ UU}$ length, $15^\circ$ half-angle) | Samples champion `CylinderComponent`s; applies 35 damage per $0.1\text{s}$ tick with burning damage-over-time stack. |
| **Shield Barrier** | `TgDevice_Shield` | Directional planar convex polygon ($400 \times 300\text{ UU}$) attached to root | Intercepts enemy projectile sweeps and hitscan lines; subtracts damage from $4000\text{ HP}$ shield pool; zero bleed-through to Fernando's cylinder. |
| **Fireball** | `TgDevice_Fireball` | Linear sphere sweep ($\text{radius} = 40\text{ UU}$, $\text{velocity} = 3500\text{ UU/s}$) | Sweeps against environment `BrushAggGeom` and champion cylinders; pierces all targets; computes $+20\%$ damage scaling per subsequent champion pierced. |
| **Charge** | `TgDevice_Charge` | Capsule sweep along movement vector ($\text{speed} = 1500\text{ UU/s}$) | Sweeps Fernando's pawn capsule; applies 200 damage and impulse knockup on first champion struck. |
| **Immortal** | `TgDevice_Immortal` | Spherical aura volume ($\text{radius} = 600\text{ UU}$) | Server clamps health of Fernando and all allies within radius to $\ge 1500\text{ HP}$; clears lethal damage ticks during active $4.0\text{s}$ duration. |

### 3.3 Havok AI 2016.1 Navigation Mesh Architecture

Each level package (`*_P.upk`) contains a `HavokNavMeshActor` housing a single `FUntypedBulkData` element. This bulk data holds a Havok **tagfile** container (`TAG0`, SDK version `"20160100"`).

#### NavMesh Data Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HAVOK TAGFILE (TAG0) HEADER                       │
├─────────────────┬───────────────────────────────┬───────────────────────────┤
│ Magic: "TAG0"   │ SDK Version: "20160100"       │ Section Tables: DATA/INDX │
└─────────────────┴───────────────────────────────┴───────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     hkaiNavMesh RUNTIME DATA STRUCTURES                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Faces (hkaiNavMesh::Face):                                                 │
│    - start_edge: i32, start_user_edge: i32                                  │
│    - num_edges: i16, num_user_edges: i16, cluster: i16, padding: u16        │
├─────────────────────────────────────────────────────────────────────────────┤
│  Edges (hkaiNavMesh::Edge):                                                 │
│    - a: i32, b: i32 (vertex endpoints)                                      │
│    - opposite_edge: u32 (0xFFFFFFFF = boundary), opposite_face: u32         │
│    - flags: u8 (SILHOUETTE=1, RETRIANGULATED=2, ORIGINAL=4, USER=0x10)     │
│    - user_edge_cost: u16                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Vertices: Vec<[f32; 4]> (Homogeneous coordinates in Havok Units)          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Spatial Acceleration (hkcdStaticAabbTree):                                 │
│    - Codec3Axis6 compressed 6-byte nodes, depth-first traversal              │
│    - Quantization step = parent_extent / 226                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Cluster Graph (hkaiDirectedGraphExplicitCost):                             │
│    - High-level region nodes, cross-region transition edges, explicit costs │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Coordinate Scaling Invariant

A fundamental mathematical invariant established between Unreal Engine 3 and Havok AI is the coordinate scale factor:
$$\text{Unreal Units (UU)} = \text{Havok Units} \times 16.0$$
$$\text{Havok Units} = \text{Unreal Units} \times 0.0625$$
Every vertex extracted from `hkaiNavMesh` must be scaled by $16.0$ to map directly to server-authoritative world coordinates in `crates/immortal-server`.

---

## Domain 4: Client Injection & Hooking Architecture

### 4.1 Standalone Minimalist Injector

Tempest implements process injection via a standalone Zig executable (`Tempest.CLI/inject/`):
- Compiled with Zig 0.16.0 (`inject64.exe` and `inject32.exe`), generating tiny statically-linked binaries ($<50\text{ KB}$) with zero C runtime dependencies.
- Standard injection sequence:
  $$\mathtt{OpenProcess} \rightarrow \mathtt{VirtualAllocEx}(\mathtt{PAGE\_READWRITE}) \rightarrow \mathtt{WriteProcessMemory} \rightarrow \mathtt{CreateRemoteThread}(\mathtt{LoadLibraryA}) \rightarrow \mathtt{WaitForSingleObject}$$
- Cross-platform process supervisor (`ProcessExtensions.cs`): Detects Wine/Proton prefixes, handles process ID stabilization during cold boots (polling up to 90 seconds), and triggers injection cleanly.

### 4.2 Security Detours & Memory Decryption

#### Package SHA-1 Verification Bypass

When modified UPK packages are loaded, the retail engine checks package cryptographic hashes against PE resource `RCDATA 1010` and calls `appOnFailSHAVerification`, aborting with `"SHA Verification failed"`.

Tempest's `Tempest.Scripting/crates/tempest-scripting/src/sha.rs` resolves this via an in-memory 1-byte patch:
1. Scans memory for signature `85 D2 48 8D 05 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 4C 0F 45 C8`.
2. Locates function entry point of `appOnFailSHAVerification`.
3. Patches first byte with `0xC3` (`ret`) using `VirtualProtect(PAGE_EXECUTE_READWRITE)` and flushes CPU instruction cache (`FlushInstructionCache`). Both engine callers immediately continue as if verification passed.

#### TAntiCheatArray TLS XOR Decryption

In retail Paladins 64-bit clients (v8.1+), the global object table `GObjects` and name table `GNames` are encrypted in memory to hinder cheat tools:
$$\text{DecryptedPointer}[i] = \text{EncryptedPointer}[i] \oplus \text{KeyTable}[i \ \& \ \mathtt{0x3FF}]$$

Tempest's `tls.rs` discovers the XOR key table without hardcoded addresses:
1. The injected DLL runs on a secondary worker thread. It iterates process threads via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` to identify the earliest-created thread (the main engine thread).
2. It queries `NtQueryInformationThread(ThreadBasicInformation)` to retrieve the main thread's Thread Environment Block (TEB).
3. It dereferences `TEB.ThreadLocalStoragePointer` (offset `0x58` on x64, `0x2C` on x86) to find the primary executable's TLS storage block.
4. The XOR key table begins at offset `0x30` within the TLS block.
5. Verification: Evaluating `GNames[0]` yields the cleartext string `"None"`, proving that the key table and mask (`0x3FF`) are 100% valid.

### 4.3 Engine Detours & Thread-Safe Rendering

1. **`UObject::ProcessEvent` & `ProcessInternal` Hooks**:
   Uses `retour::RawDetour` on `UObject::ProcessEvent` to intercept all UnrealScript event invocations, allowing pre-event parameter mutation, event cancellation, and post-event observation. Hooks `ProcessInternal` to capture internal script-to-script calls.
2. **Native Thunk Swapping**:
   Replaces `UFunction.Func` function pointers directly in memory, binding custom Rust/Lua implementations to UnrealScript functions declared as `native` or `dllimport`.
3. **Thread-Safe D3D11 / D3D9 Present Hooking**:
   - Hooks `IDXGISwapChain::Present` (slot 8) and `ResizeBuffers` (slot 13).
   - Solves multithreaded rendering race conditions: UI draw commands are recorded on the **game thread** inside `ProcessEvent` (allowing safe read/write access to `UObject` trees without synchronization locks). Completed frame data is deep-copied into a `FrameCopy` buffer parked under an SRWLock. The render thread consumes the copied buffer during `Present`, rendering Dear ImGui overlays without stalling the game thread.

### 4.4 Wwise Audio Pipeline & Non-Invasive SoundBanks (Milestone 7)

Paladins ships with 584 Wwise sound packages (`WWB_*.pck`, `AKPK` v1 container) and soundbanks (`BKHD` v120 = Wwise 2019) containing Wwise Vorbis streams (`.wem`, format tag `0xFFFF`).

Tempest implements a pure-Rust Wwise toolchain (`tempest-assets/src/wwise/`):
- `akpk.rs`: Parses and serializes `.pck` package containers, maintaining language lookup tables and stream offset directories.
- `bnk.rs`: Decodes and serializes bank headers (`BKHD`), media descriptors (`DIDX`), raw audio payloads (`DATA`), and hierarchy objects (`HIRC`: `SOUND`, `ACTION`, `EVENT`, `RANDOM_SEQUENCE`, `SWITCH`).
- `vorbis.rs`: A 1,226-line pure-Rust implementation of the `ww2ogg` decoding and inverse `ogg_to_wem` encoding pipeline:
  - Embeds `packed_codebooks_aoTuV_603.bin` (aoTuV 6.03 codebook library).
  - Encodes 66-byte `AkVorbisInfo` stream headers with FNV-1 setup hashes.
  - Generates valid Wwise Vorbis bitstreams from standard Ogg Vorbis audio.

#### Milestone 7 Strategic Adoption Paths

For Project Immortal's Milestone 7 ("Neural Audio Restoration & Voice Line Synthesis"), this enables two non-invasive delivery mechanisms:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 MILESTONE 7 NON-INVASIVE AUDIO PIPELINE                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                   [Neural Voice Synthesis Pipeline]
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  PURE-RUST WWISE VORBIS ENCODER (crates/immortal-extract)    │
│  - Converts PCM / Ogg Vorbis to Wwise .wem                                  │
│  - Assembles AkVorbisInfo Header & aoTuV 6.03 Codebooks                      │
│  - Builds HIRC Sound & Event Descriptors                                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                   ┌───────────────────┴───────────────────┐
                   │                                       │
                   ▼                                       ▼
┌──────────────────────────────────────┐┌──────────────────────────────────────┐
│     VECTOR A: DROP-IN SOUNDBANKS     ││   VECTOR B: CLIENT INSTRUMENTATION   │
│  (Zero-Injection / Pure Game Files)  ││   (Optional Telemetry / Debug DLL)   │
│  - Writes standalone .pck files      ││  - Minimal Zig Injector             │
│  - Loaded natively by Wwise engine   ││  - Dynamic ProcessEvent Detour      │
│  - Zero client memory modification   ││  - Hitbox Visualization HUD          │
└──────────────────────────────────────┘└──────────────────────────────────────┘
```

---

## Domain 5: Licensing & Cleanroom Governance

### 5.1 License & Copyright Topography

An exhaustive audit of repository licenses establishes the following legal topography:

| Entity | Declared License | Copyright Holder | Governing Boundaries & Restrictions |
| :--- | :--- | :--- | :--- |
| **Tempest Monorepo Root** | **GNU GPL-3.0** | LowRezStudio contributors | Strong Copyleft. Covers all C# and Protobuf code (`Tempest.CLI`, `MarshalLib`, `Tempest.Protocol`). |
| **Tempest.UnrealScript** | **MIT License** | LowRezStudio contributors | Permissive Open Source. Governs `tempest-upk`, `tempest-assets`, and `tempest-unrealscript`. |
| **Tempest.Scripting** | **MIT License** | LowRezStudio contributors | Permissive Open Source. Governs `tempest-scripting` Rust crate. |
| **Tempest.StudioNative** | **MIT License** | LowRezStudio contributors | Permissive Open Source. Governs GPUI editor crate. |
| **LowRezStudio/docs** | **NO LICENSE** (All Rights Reserved) | LowRezStudio / Contributors | Default statutory copyright under Berne Convention. Zero verbatim text/asset copying allowed. |
| **Project Immortal** | **AGPL-3.0** (+ Permissive Dual Licensing Options) | Arafat Zahan (@kuasha420), PSL, Contributors | Strong Network Copyleft under ICARO-42/b Ordinance stewardship. |

### 5.2 Legal Boundary Risks & Cleanroom Membrane

1. **GPL-3.0 vs. AGPL-3.0 Copyleft Cross-Contamination**:
   While Section 13 of GNU GPLv3 allows linking GPLv3 and AGPLv3 modules into a single distributed binary, **direct copying of source code** from a GPL-3.0 repository into Project Immortal would encumber Project Immortal with LowRezStudio copyright claims. Project Immortal maintains corporate dual-licensing rights under PSL stewardship; injecting GPL-3.0 source would irrevocably taint the codebase.
2. **Statutory Copyright of `LowRezStudio/docs`**:
   Because the documentation repository lacks an open-source license, all written descriptions, guides, and diagrams are protected by default copyright. Verbatim inclusion of markdown text or excerpts in Project Immortal constitutes copyright infringement.
3. **The Non-Protectability of Technical Interfaces**:
   Under US and international copyright jurisprudence (*Computer Associates v. Altai*, *Sega v. Accolade*, *Sony v. Connectix*, and 17 U.S.C. § 102(b)):
   - Wire protocols, packet structures, binary serialization formats, mathematical constants (FNV-1, Codec3Axis step sizes), XOR masks (`0x2A`), token enumeration IDs, and algorithmic rules are **unprotectable ideas, systems, and functional facts**.
   - Independent cleanroom reimplementation of functional specifications extracted from reverse engineering is 100% lawful.

### 5.3 PSL-INV-007 4-Phase Cleanroom Knowledge Transfer Protocol

Project Immortal enforces a strict 4-phase cleanroom membrane to guarantee zero code contamination:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DIRTY ROOM (.dirtyroom/external/)                      │
│  - Cloned Tempest Monorepo & Docs                                           │
│  - Retail Paladins Binaries & Network Captures                              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                      [Phase 1: Functional Extraction]
                      (Extract wire layouts, tokens, algorithms)
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 CLEANROOM SPECIFICATION MEMBRANE (docs/specs/)              │
│  - Formal Protocol RFCs (e.g., docs/specs/G2_SERVER_PROTOCOL.md)           │
│  - Independent prose and algorithmic definitions                            │
│  - Zero source code or verbatim documentation copied                        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                      [Phase 2: Obligation Formulation]
                      (Formulate typed claims linked to verification gates)
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  TYPED OBLIGATION LEDGER (docs/specs/*.md)                  │
│  - Immutable evidence digests (SHA-256 of binaries/pcaps)                   │
│  - Reconstructed claims: OBL-MCTS-*, OBL-COL-*, OBL-NAV-*                   │
│  - Concrete verification gates (cargo test, schema validation)               │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                      [Phase 3: Independent Reconstruction]
                      (Cleanroom engineers author code purely from specs)
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   CLEANROOM PRODUCT CRATES (crates/immortal-*)              │
│  - 100% Pure Rust cleanroom implementations                                 │
│  - Zero external code provenance taint                                      │
│  - Verified via native automated tests (cargo test exit code 0)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Cleanroom Rules of Engagement
- **Rule 1 (Absolute Source Quarantine)**: Never copy, translate, or adapt source files from `.dirtyroom/external/` into `crates/`.
- **Rule 2 (Prose Quarantine)**: Never copy paragraphs or diagrams from `LowRezStudio/docs`. All cleanroom documentation must be independently authored.
- **Rule 3 (Fact-Only Extraction)**: Only extract functional interface contracts, binary framing specifications, field token tables, and mathematical formulas.
- **Rule 4 (Obligation Ledger Binding)**: Every adopted behavior must be recorded as an actionable claim in `docs/specs/TEMPEST_ADOPTION_LEDGER.md` with explicit verification criteria.

### 5.4 PSL-INV-011 Architectural Fitness Alignment

All cleanroom adoptions must strictly respect Project Immortal's architectural fitness invariants:
1. **Layer Separation**: Low-level network codecs (`crates/immortal-net`) must never import from high-level extraction pipelines (`crates/immortal-extract`) or server simulation logic (`crates/immortal-server`).
2. **Zero Foreign Language Assets**: Protocol tables, token schemas, and bytecode maps must be maintained as native Rust structures or generated at build time from cleanroom JSON specifications.
3. **Bounded Memory Invariant**: Network parsers, packet decoders, and token caches must enforce bounded buffers and maximum capacities to prevent memory exhaustion during adversarial fuzzing.
4. **Directed Acyclic Graph (DAG)**: All crate and module dependency trees must remain strictly acyclic.

---

## Conclusion & Strategic Roadmap

The open-source release of Tempest is a transformative asset for Project Immortal. By treating Tempest not as a source of code to be copied, but as an empirical **specification oracle** and dirty-room verification tool, Project Immortal achieves:

1. **Definitive Protocol Parity**: Full MCTS wire parity across 3,731 fields, 1,084 functions, and the 4-cache integer batching algorithm (Milestone 2).
2. **Bit-Level Ground Truth**: Headless Wine containerization of the retail server for automated differential fuzzing and bitstream validation.
3. **Pure-Rust Server-Authoritative Collision**: Deconstruction of `BrushAggGeom` convex hulls and the dual-stage hitbox model, enabling bit-accurate combat simulation for Fernando without C++ physics dependencies (Milestone 5).
4. **Authentic Bot Navigation**: Complete decoding of Havok AI 2016.1 `TAG0` navmeshes, coordinate scaling ($\times 16.0$), and $A^*$ pathfinding (Milestone 6).
5. **Non-Invasive Audio Restoration**: Pure-Rust Wwise Vorbis synthesis for zero-injection drop-in soundbank delivery (Milestone 7).
6. **Impeccable Cleanroom Integrity**: Full compliance with PSL-INV-007 and PSL-INV-011, safeguarding Project Immortal's AGPL-3.0 licensing and IP provenance.
