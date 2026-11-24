# Tempest Cleanroom Adoption Ledger: Actionable Engineering Targets

**Document Identifier**: `SPEC-TEMPEST-ADOPT-2026-01`  
**Classification**: Cleanroom Technical Specification / Obligation Ledger  
**Status**: Authoritative Cleanroom Specification  
**Governing Policies**: PSL-INV-007 (Universal Cleanroom Reverse Engineering), PSL-INV-011 (Architectural Fitness)  
**Corporate Stewardship**: Purrfect Software Limited (PSL) under ICARO-42/b Ordinance  
**Target Repository**: Project Immortal (`/home/kuasha/Dev/immortal`)  
**External Analyzed Sources (Quarantined in `.dirtyroom/external/`)**:
- `LowRezStudio/Tempest` (commit `6ce49f1`, GPL-3.0 root, MIT sub-crates)
- `LowRezStudio/docs` (commit `001ca20`, All Rights Reserved)

---

## 1. Overview & Cleanroom Governance Charter

This ledger defines the authoritative catalog of concrete architectural patterns, algorithms, data structures, and operational tooling extracted from the open-source release of the Tempest ecosystem for cleanroom adoption into Project Immortal.

### 1.1 Cleanroom Compliance Invariant (PSL-INV-007)
All adoptions cataloged in this ledger represent **functional interfaces, wire protocols, mathematical algorithms, and data layouts**. Under established copyright jurisprudence (*Sony v. Connectix*, *Sega v. Accolade*, *Computer Associates v. Altai*, and 17 U.S.C. § 102(b)), these technical facts are non-copyrightable.

To ensure zero copyleft contamination between Tempest (GPL-3.0) / docs (All Rights Reserved) and Project Immortal (AGPL-3.0):
1. **Zero Source Code Transfer**: No code from `.dirtyroom/external/` may ever be copied, translated, or linked into `crates/`.
2. **Specification-Driven Reconstruction**: All implementations must be authored from the cleanroom specifications detailed below.
3. **Traceable Verification**: Every adoption target is assigned a unique `OBL-*` obligation identifier backed by an automated verification gate (`cargo test` or containerized execution).

### 1.2 Summary Matrix: ADOPT-01 through ADOPT-12

| Item ID | Title | Target Subsystem | Target Milestone | Priority | Feasibility | Cleanroom Obligation |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **ADOPT-01** | Server-Authoritative Collision Extractor | `crates/immortal-extract` | M6 | Critical | High | `OBL-COL-001` |
| **ADOPT-02** | Dual-Stage Hitbox Model | `crates/immortal-server` | M6 | High | High | `OBL-COMBAT-001` |
| **ADOPT-03** | Rooftop & Heavy Wall Correction | `crates/immortal-server` | M6 | Medium | High | `OBL-PHYS-001` |
| **ADOPT-04** | Havok AI 2016.1 NavMesh Parser & $A^*$ | `crates/immortal-extract` / `server` | M6 | Critical | High | `OBL-NAV-001` |
| **ADOPT-05** | Pure-Rust Wwise Vorbis Encoder & SoundBank Builder | `crates/immortal-extract` | M7 | High | High | `OBL-AUDIO-001` |
| **ADOPT-06** | Package SHA-1 Verification Detour | `tools/immortal-hook` | M7 | Medium | High | `OBL-HOOK-001` |
| **ADOPT-07** | Dynamic TAntiCheatArray TLS XOR Decryption | `tools/immortal-hook` | M7 | High | High | `OBL-HOOK-002` |
| **ADOPT-08** | Minimalist Statically-Linked Zig Injector | `tools/immortal-inject` | M7 | Medium | High | `OBL-INJECT-001` |
| **ADOPT-09** | Headless Retail Dedicated Server Oracle | `.dirtyroom/oracle/` | M6 | Critical | High | `OBL-ORACLE-001` |
| **ADOPT-10** | CMarshal 4-Cache Integer Batching Engine | `crates/immortal-net` | M2 (Upgrade -> M6) | Critical | High | `OBL-MCTS-004` |
| **ADOPT-11** | Full Engine Token Resolution & FNV-1 Dispatch | `crates/immortal-net` | M2 (Upgrade -> M6) | Critical | High | `OBL-MCTS-005` |
| **ADOPT-12** | Object-Keyed Differential Package Patching | `crates/immortal-extract` | M7 | Low | Medium | `OBL-UPK-002` |

---

## 2. Exhaustive Adoption Specifications (ADOPT-01 through ADOPT-12)

---

### ADOPT-01: Server-Authoritative Physical Collision Extractor

- **Item ID**: `ADOPT-01`
- **Subsystem**: Physics & Collision Extraction
- **Target Crate**: `crates/immortal-extract/src/collision.rs`
- **Target Milestones**: Milestone 6 (World SAT Collision & Combat Authority)
- **Priority**: Critical
- **Feasibility**: High (pure data parsing and linear algebra)
- **Cleanroom Obligation**: `OBL-COL-001`

#### Architectural Description
In Paladins UE3, physical world collision and weapon raycasts do not use Havok physics hulls; they rely strictly on `UBrushComponent.BrushAggGeom.ConvexElems` for blocking volumes and `UStaticMesh.BodySetup.AggGeom` for static props. In cooked maps, BSP models are stripped and collision resides entirely in these precomputed convex elements.

Project Immortal will implement a cleanroom extractor in `immortal-extract` to extract these convex hulls into pure Rust geometry structs. This enables the server (`crates/immortal-server`) to perform raycasting, sphere sweeps, and pawn movement queries using Separating Axis Theorem (SAT) without linking external C++ physics engines (PhysX or Havok).

#### Cleanroom Specification Contract
- **Inputs**:
  - Export data of `UBrushComponent` or `URB_BodySetup` from level packages (`*_P.upk`, `*_Collision.upk`).
- **Outputs**:
  - Strongly typed `AggregateGeometry` struct:
    ```rust,ignore
    pub struct ConvexHull {
        pub vertices: Vec<[f32; 3]>,
        pub permuted_planes: Vec<[f32; 4]>, // SIMD SSE aligned planes for fast SAT
        pub edge_directions: Vec<[f32; 3]>,
        pub face_normals: Vec<[f32; 3]>,
        pub plane_equations: Vec<[f32; 4]>,  // Ax + By + Cz + D = 0
        pub aabb_min: [f32; 3],
        pub aabb_max: [f32; 3],
    }
    pub struct AggregateGeometry {
        pub convex_hulls: Vec<ConvexHull>,
        pub boxes: Vec<BoxElem>,
        pub spheres: Vec<SphereElem>,
        pub sphyls: Vec<SphylElem>, // Capsules
    }
    ```
- **Algorithm**:
  1. Deserialize `FKAggregateGeom` tagged properties from export payload.
  2. Parse `ConvexElems` arrays: vertex points, edge directions, normal directions, plane equations $(A, B, C, D)$, and AABB bounds.
  3. Validate hull closure: $\forall v \in \text{vertices}, \forall (A, B, C, D) \in \text{planes}: Av_x + Bv_y + Cv_z + D \le \epsilon$.

#### Verification Method & Acceptance Criteria
- Unit test in `crates/immortal-extract` deserializing a fixture of `BrushAggGeom` convex hulls from `SG_StoneKeep_P.upk` (and `Shootingrange_Collision.upk` / `SG_JaguarFalls_Rework_P.upk`).
- Assert raycast intersection against a known wall plane matches retail hit coordinate within $\pm 0.1\text{ UU}$.
- Pass `cargo test -p immortal-extract`.

---

### ADOPT-02: Dual-Stage Hitbox Model

- **Item ID**: `ADOPT-02`
- **Subsystem**: Combat & Damage Calculation
- **Target Crate**: `crates/immortal-server/src/combat.rs`
- **Target Milestone**: Milestone 6 (Combat Authority & Fernando Kit)
- **Priority**: High
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-COMBAT-001`

#### Architectural Description
Retail Paladins utilizes a two-stage hitbox architecture:
1. Every champion is bounded by a single vertical cylinder capsule (`CylinderComponent`: `CollisionRadius`, `CollisionHeight`). All incoming raycasts and projectile sweeps test against this cylinder. Any intersection is registered as a body shot.
2. If and only if the ray intersects the cylinder, a secondary line check queries the animated skeletal bone hierarchy (`PhysicsAsset`) for the `b_head` bone. If struck, the hit is promoted to a critical headshot.

In retail Paladins, this creates "hat meta" discrepancies: large cosmetics (e.g. Dredge hats or Furia shoulder pads) displace or intercept traces before the head bone, or head bones protrude outside the cylinder during animation extremes, preventing headshots entirely. Project Immortal's server will implement this two-stage model authoritatively, with skin hitbox normalization to eliminate pay-to-win/pay-to-lose artifacts.

#### Cleanroom Specification Contract
- **Inputs**:
  - Attacker weapon raycast $(O, \vec{D})$ or projectile swept sphere $(O, \vec{D}, r)$.
  - Target champion state: root position, cylinder $(R, H)$, and skeletal head bone center $P_{\text{head}}$ and radius $r_{\text{head}}$.
- **Outputs**:
  - `HitResult { struck: bool, hit_location: [f32; 3], is_headshot: bool }`.
- **Algorithm**:
  1. Test ray/sphere intersection against vertical cylinder $(P_{\text{base}}, R, H)$. If no intersection, return `struck = false`.
  2. If intersected at point $P_{\text{hit}}$, test ray intersection against transformed head sphere $(P_{\text{head}}, r_{\text{head}})$.
  3. If head sphere is hit and distance $d(O, P_{\text{head\_hit}}) \le d(O, P_{\text{hit}}) + \text{tolerance}$, return `is_headshot = true`; otherwise return `is_headshot = false`.

#### Verification Method & Acceptance Criteria
- Unit tests verifying:
  - Ray missing cylinder $\rightarrow$ no hit.
  - Ray hitting cylinder at chest level $\rightarrow$ body hit (`is_headshot = false`).
  - Ray hitting cylinder and passing through head bone sphere $\rightarrow$ critical hit (`is_headshot = true`).
  - Head bone displaced outside cylinder bounds $\rightarrow$ server clamped/normalized so headshot registers.

---

### ADOPT-03: Rooftop & Heavy Wall Correction

- **Item ID**: `ADOPT-03`
- **Subsystem**: Server Movement & Physics Simulation
- **Target Crate**: `crates/immortal-server/src/physics.rs`
- **Target Milestones**: Milestone 6 (Combat Authority & World Physics)
- **Priority**: Medium
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-PHYS-001`

#### Architectural Description
UE3 character movement checks the surface property `Actor.m_bCanBaseOn`. When `false`, the pawn controller cannot establish a standing floor base, applying an immediate downward slide velocity along the surface tangent. In retail Paladins, environment artists accidentally placed `m_bCanBaseOn = false` on vertical wall blocking volumes and tree trunks (especially on Frog Isle), creating the notorious decade-old "heavy walls" bug where players stick and slide down walls.

Project Immortal's server-side physics simulation will decode the `m_bCanBaseOn` property and enforce a geometric angle invariant: only surfaces with $\text{normal}_z < \cos(45^\circ)$ may treat `m_bCanBaseOn = false` as a slide, preventing vertical wall stickiness.

#### Cleanroom Specification Contract
- **Inputs**:
  - Collision contact point $P$ and surface normal $\vec{N} = (N_x, N_y, N_z)$.
  - Actor metadata: `m_bCanBaseOn: bool`.
- **Outputs**:
  - `SurfaceInteraction { can_stand: bool, apply_rooftop_slide: bool }`.
- **Algorithm**:
  ```rust,ignore
  let is_steep = normal[2] < 0.7071; // Angle > 45 degrees
  let is_vertical = normal[2].abs() < 0.1; // Near vertical wall
  let apply_slide = !m_bCanBaseOn && is_steep && !is_vertical;
  let can_stand = m_bCanBaseOn && !is_steep;
  ```

#### Verification Method & Acceptance Criteria
- Unit test in `crates/immortal-server`: pawn impacting a vertical wall with `m_bCanBaseOn = false` does not enter the rooftop sliding state; pawn landing on a $60^\circ$ roof with `m_bCanBaseOn = false` slides down smoothly.

---

### ADOPT-04: Havok AI 2016.1 NavMesh Parser & $A^*$ Pathfinding

- **Item ID**: `ADOPT-04`
- **Subsystem**: Bot Navigation & AI Pathfinding
- **Target Crates**: `crates/immortal-extract/src/navmesh.rs` & `crates/immortal-server/src/ai.rs`
- **Target Milestone**: Milestone 6 (Bot Opponents & Game Server Integration)
- **Priority**: Critical
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-NAV-001`

#### Architectural Description
Each retail map package embeds an `AHavokNavMeshActor` containing a Havok AI 2016.1 `TAG0` tagfile (`SDKV 20160100`). This container stores:
- `hkaiNavMesh`: 3D navigation polygons (`Face`), directed boundary/internal edges (`Edge`), and vertex arrays.
- `hkcdStaticAabbTree`: Quantized spatial partitioning AABB tree (`Codec3Axis6`, 6 bytes per node, step size $\frac{\text{parent\_extent}}{226}$).
- `hkaiDirectedGraphExplicitCost`: Regional cluster graph for hierarchical pathing.
- `hkaiTraversalAnnotationLibrary`: Jump pad transitions and ledge drop-downs.

By implementing a cleanroom reader for `TAG0` containers and applying the invariant coordinate scaling factor ($\times 16.0$), Project Immortal's server bots can navigate retail maps with zero path divergence from retail bots.

#### Cleanroom Specification Contract
- **Inputs**:
  - Raw bulk data bytes of `HavokNavMeshActor` from map package (`*_P.upk`).
- **Outputs**:
  - Cleanroom navigation graph:
    ```rust,ignore
    pub struct NavMeshGraph {
        pub vertices: Vec<[f32; 3]>, // Scaled by 16.0 to Unreal Units
        pub faces: Vec<NavFace>,
        pub edges: Vec<NavEdge>,
        pub cluster_graph: ClusterGraph,
        pub traversal_links: Vec<JumpLink>,
    }
    ```
- **Coordinate Scaling Invariant**:
  $$P_{\text{Unreal}} = P_{\text{Havok}} \times 16.0$$

#### Verification Method & Acceptance Criteria
- Test extracting `TAG0` from `SG_StoneKeep_P.upk` bulk data.
- Verify vertex coordinates match expected map extents ($X, Y \in [-15000, 15000]$ UU, $Z \in [-2000, 5000]$ UU).
- Execute $A^*$ query between team spawn points; assert continuous valid path across face adjacency.

---

### ADOPT-05: Pure-Rust Wwise Vorbis Encoder & SoundBank Builder

- **Item ID**: `ADOPT-05`
- **Subsystem**: Audio Extraction & Synthesis
- **Target Crate**: `crates/immortal-extract/src/audio.rs`
- **Target Milestone**: Milestone 7 (Neural Audio Restoration & Voice Line Synthesis)
- **Priority**: High
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-AUDIO-001`

#### Architectural Description
Paladins uses Audiokinetic Wwise 2019 (`BKHD` v120) soundbanks packed into `WWB_*.pck` (`AKPK` v1) containers. Audio streams are encoded in Wwise Vorbis format (`0xFFFF`).

Tempest proves that Wwise Vorbis streams can be decoded and encoded in pure Rust without native Wwise SDK binaries by implementing the inverse `ogg_to_wem` algorithm using aoTuV 6.03 codebooks (`packed_codebooks_aoTuV_603.bin`).

Project Immortal will adopt this cleanroom audio builder to enable Milestone 7: newly synthesized champion voice lines are packaged into drop-in `.pck` files that the retail client loads natively, requiring zero runtime process memory modification.

#### Cleanroom Specification Contract
- **Inputs**:
  - Linear PCM audio or Ogg Vorbis streams.
  - Wwise event hierarchy metadata (Sound ID, Event ID, volume, attenuation).
- **Outputs**:
  - Valid Wwise `.wem` audio files with 66-byte `AkVorbisInfo` headers.
  - Complete `BKHD` v120 soundbanks (`.bnk`) and `AKPK` v1 packages (`.pck`).
- **Algorithm**:
  1. Re-packetize Vorbis audio frames against aoTuV 6.03 codebook indices.
  2. Compute 32-bit FNV-1 hash for stream setup table.
  3. Emit 66-byte `AkVorbisInfo` header prefix followed by bitstream packets.
  4. Assemble `BKHD`, `DIDX`, `DATA`, and `HIRC` soundbank sections.

#### Verification Method & Acceptance Criteria
- Roundtrip test: convert test WAV $\rightarrow$ `.wem` $\rightarrow$ decode back to PCM; assert waveform correlation $> 0.99$.
- Write `.pck` package and parse with `immortal-extract/src/audio.rs`; assert bit-accurate section headers.

---

### ADOPT-06: Package SHA-1 Verification Detour

- **Item ID**: `ADOPT-06`
- **Subsystem**: Client Research & Modding Hooks
- **Target Path**: `tools/immortal-hook/src/sha.rs`
- **Target Milestone**: Milestone 7 (Client Research & Telemetry)
- **Priority**: Medium
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-HOOK-001`

#### Architectural Description
When research engineers test modded script packages (`Startup.upk`, `TgClient.upk`) against the retail client, the engine checks package SHA-1 hashes against PE resource `RCDATA 1010` and calls `appOnFailSHAVerification`, aborting execution.

A 1-byte patch with `0xC3` (`ret`) at the entry point of `appOnFailSHAVerification` bypasses this check in memory without modifying client binaries on disk.

#### Cleanroom Specification Contract
- **Inputs**:
  - Live client process memory handle.
- **Outputs**:
  - Patched memory address; client loads modded UPK without aborting.
- **Algorithm**:
  1. Scan process `.text` section for pattern:
     `85 D2 48 8D 05 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 4C 0F 45 C8`
  2. Confirm presence of wide string `"SHA Verification failed"`.
  3. Call `VirtualProtect` to make entry byte writable (`PAGE_EXECUTE_READWRITE`).
  4. Write `0xC3` (`ret`); restore original protection flags; call `FlushInstructionCache`.

#### Verification Method & Acceptance Criteria
- Memory scanner test against synthetic dummy PE byte buffer containing target signature.
- Verify patch replaces exact opcode and returns success status.

---

### ADOPT-07: Dynamic TAntiCheatArray TLS XOR Decryption

- **Item ID**: `ADOPT-07`
- **Subsystem**: Client Telemetry & In-Memory Inspection
- **Target Path**: `tools/immortal-hook/src/tls.rs`
- **Target Milestone**: Milestone 7 (Client Research & Telemetry)
- **Priority**: High
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-HOOK-002`

#### Architectural Description
In retail Paladins 64-bit binaries (v8.1+), pointers in `GObjects` and `GNames` are XOR-encrypted using a 1024-entry key array stored in the main thread's Thread Local Storage (TLS) block. Instead of relying on hardcoded memory addresses, the key table can be discovered dynamically by querying the main engine thread's TEB.

#### Cleanroom Specification Contract
- **Inputs**:
  - Live process ID and main thread handle.
- **Outputs**:
  - Decrypted pointer array: $\text{Ptr}[i] = \text{Raw}[i] \oplus \text{Key}[i \ \& \ \mathtt{0x3FF}]$.
- **Algorithm**:
  1. Enumerate process threads via `CreateToolhelp32Snapshot`; locate earliest thread.
  2. Query thread TEB via `NtQueryInformationThread(ThreadBasicInformation)`.
  3. Read `TEB.ThreadLocalStoragePointer` (offset `0x58` on x64).
  4. Read base TLS storage block; resolve key array at offset `0x30`.
  5. Validate key table: decrypt `GNames[0]`; assert cleartext string equals `"None"`.

#### Verification Method & Acceptance Criteria
- Unit test executing decryption algorithm on simulated TLS memory buffer with encrypted `"None"` string.
- Assert decrypted string equals `"None"` and mask equals `0x3FF`.

---

### ADOPT-08: Minimalist Statically-Linked Zig Injector

- **Item ID**: `ADOPT-08`
- **Subsystem**: Client Research & Process Loader
- **Target Path**: `tools/immortal-inject/`
- **Target Milestone**: Milestone 7 (Client Research & Telemetry)
- **Priority**: Medium
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-INJECT-001`

#### Architectural Description
A tiny, standalone injector ($<50\text{ KB}$) compiled with Zig for Windows and Wine/Proton targets. Provides clean dynamic injection of research DLLs without external dependencies or runtimes.

#### Cleanroom Specification Contract
- **Inputs**:
  - Target process ID and path to 64-bit DLL.
- **Outputs**:
  - Exit code 0 on successful thread execution; error code on failure.
- **Algorithm**:
  1. `OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid)`.
  2. `VirtualAllocEx(hProcess, NULL, path_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)`.
  3. `WriteProcessMemory(hProcess, remote_mem, dll_path, path_len + 1, NULL)`.
  4. `CreateRemoteThread(hProcess, NULL, 0, LoadLibraryA, remote_mem, 0, NULL)`.
  5. `WaitForSingleObject(hThread, 5000); VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE)`.

#### Verification Method & Acceptance Criteria
- Compile `immortal-inject` via Zig CLI; assert binary size $<60\text{ KB}$.
- Test injection of dummy test DLL into a test host process.

---

### ADOPT-09: Headless Retail Dedicated Server Oracle

- **Item ID**: `ADOPT-09`
- **Subsystem**: Differential Testing & Ground Truth Verification
- **Target Path**: `.dirtyroom/oracle/` (invoked via `./agyis oracle` & `scripts/dirtyroom/patch_server_binary.py`)
- **Target Milestones**: Milestone 6 (Retail Oracle Differential Testing)
- **Priority**: Critical
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-ORACLE-001`

#### Architectural Description
A headless Wine runner executing the retail 64-bit Windows Paladins dedicated server (`ShippingPC-ChaosGame-Server.exe`) on Linux (`unset DISPLAY`). Used strictly in dirty-room differential testing to validate Project Immortal's packet bunch framing, ACK sequencing, `?exudp=2` cipher behavior, and replication bitstreams.

#### Cleanroom Specification Contract
- **Inputs**:
  - Cooked Paladins game server files and match launch parameters.
- **Outputs**:
  - Running game server listening on UDP port 7000; emits `Launch.log` and pcap trace of replies.
- **Environment Configuration**:
  - Runtime: Wine64 (or containerized Linux + Wine64 for 64-bit `ShippingPC-ChaosGame.exe`).
  - Display: `unset DISPLAY` (null/tty driver).
  - OpenSSL fix: `OPENSSL_ia32cap="~0x20000000"`.
  - Flags: `server <MapName>?game=TgGame.TgGame_Paladins?maxplayers=2 -port=7000 -multihome=127.0.0.1 -seekfreeloadingpcconsole -pid=402 -eac-nop-loaded -homedir=Tempest -log`.

#### Verification Method & Acceptance Criteria
- Binary patched cleanly via `python3 scripts/dirtyroom/patch_server_binary.py` into quarantined `.dirtyroom/oracle/runtime/Binaries/Win64/ShippingPC-ChaosGame-Server.exe` (`DYNAMIC_BASE == 0`).
- `agyis oracle test --map SG_JaguarFalls_Rework_P --timeout 35` passes all 6 milestones (`Assembly Loaded Version:`, `NetMode is now 1`, `Bringing World ... up for play`, and UDP port `7000` bound).

---

### ADOPT-10: CMarshal 4-Cache Integer Batching Engine

- **Item ID**: `ADOPT-10`
- **Subsystem**: Out-of-Game RPC Serialization
- **Target Crate**: `crates/immortal-net/src/marshal.rs`
- **Target Milestone**: Milestone 2 (MCTS Gateway)
- **Priority**: Critical
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-MCTS-004`

#### Architectural Description
In Hi-Rez's `CMarshal` binary protocol, integer fields do not serialize inline. They are routed into 4 width accumulation queues (8, 16, 32, 64-bit) based on magnitude and flushed in ascending order either when a queue reaches 32 items or when the row terminates. Non-numeric fields serialize immediately at their logical location. Obfuscated `.dat` files apply XOR mask `0x2A`.

Project Immortal will upgrade `crates/immortal-net/src/marshal.rs` to implement this exact batching and flush specification.

#### Cleanroom Specification Contract
- **Inputs**:
  - Row records with typed field entries: `(u16 token, FieldValue)`.
- **Outputs**:
  - Wire-compliant byte stream with entry headers `(type << 12) | count`, grouped token arrays, contiguous value arrays, and inline strings/rowsets.
- **Flushing Invariant**:
  - Queue 1 (8-bit): $V \le \mathtt{0xFF}$ (Header `0x1000 | count`).
  - Queue 2 (16-bit): $V \le \mathtt{0xFFFF}$ (Header `0x2000 | count`).
  - Queue 3 (32-bit): $V \le \mathtt{0xFFFFFFFF}$ (Header `0x3000 | count`).
  - Queue 4 (64-bit): $V > \mathtt{0xFFFFFFFF}$ (Header `0x4000 | count`).
  - Flush trigger: `count == 32` or row end; flush order: 1, 2, 3, 4.

#### Verification Method & Acceptance Criteria
- Conformance test serializing synthetic rows containing mixed-width numbers and strings.
- Compare byte output against golden trace fixtures in `crates/immortal-net/tests/fixtures/`.
- Pass `cargo test -p immortal-net --test schema_conformance_test`.

---

### ADOPT-11: Full Engine Token Resolution & FNV-1 Dispatch Table

- **Item ID**: `ADOPT-11`
- **Subsystem**: MCTS Protocol Contracts
- **Target Crate**: `crates/immortal-net/src/mcts_token.rs`
- **Target Milestone**: Milestone 2 (MCTS Gateway)
- **Priority**: Critical
- **Feasibility**: High
- **Cleanroom Obligation**: `OBL-MCTS-005`

#### Architectural Description
Project Immortal's `mcts_handshake.rs` contained 13 hardcoded function hash constants. Cross-referencing against Tempest's extracted token database resolved all 13 hashes to authentic Hi-Rez engine symbols (`PLAYER_SVC_GO_PLAY`, `GET_TICKET_INFO`, `PLAYER_SVC_USER_LOGIN_RESPONSE`, etc.) and confirmed exact 3,731 field count parity.

Project Immortal will codify the full 1,084 function dispatch table and 3,731 field definitions into typed Rust enums and lookup maps with build-time FNV-1 verification.

#### Cleanroom Specification Contract
- **Inputs**:
  - Function name string or incoming 32-bit wire hash.
- **Outputs**:
  - Strongly typed `MctsFunction` enum with FNV-1 32-bit hash dispatch.
- **Hashing Algorithm**:
  $$H_0 = 2166136261, \quad H_{i+1} = ((H_i \times 16777619) \oplus B_i) \pmod{2^{32}}$$

#### Verification Method & Acceptance Criteria
- Automated unit test verifying that every `MctsFunction` variant hashes to its canonical wire integer.
- Schema conformance test asserting field schema map contains exactly 3,731 definitions.
- Pass `cargo test -p immortal-net`.

---

### ADOPT-12: Object-Keyed Differential Package Patching

- **Item ID**: `ADOPT-12`
- **Subsystem**: Asset Extraction & Packaging
- **Target Crate**: `crates/immortal-extract/src/patch.rs`
- **Target Milestone**: Milestone 7 (Audio Restoration & Content Management)
- **Priority**: Low
- **Feasibility**: Medium
- **Cleanroom Obligation**: `OBL-UPK-002`

#### Architectural Description
Tempest introduces `.tdelta` and `.tobj` files: an object-keyed delta patching format that modifies UPK exports based on object path rather than byte offsets. Large shared objects ($\ge 16\text{ KiB}$) are deduplicated across packages using content hashes (`shared/<sha256>.tobj`).

Adopting this format allows Project Immortal's asset toolchain to distribute lightweight mod patches and localized voice line updates without distributing multi-gigabyte monolithic package files.

#### Cleanroom Specification Contract
- **Inputs**:
  - Base UPK package file + `.tdelta` patch archive.
- **Outputs**:
  - Rebuilt target UPK package with updated export payloads.

#### Verification Method & Acceptance Criteria
- Roundtrip test: apply `.tdelta` patch to base test package; assert target exports updated while untouched exports remain bit-identical.

---

## 3. Implementation Roadmap & Crate Allocation

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROJECT IMMORTAL ROADMAP WITH ADOPTIONS                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
     ┌─────────────────────────────────┼─────────────────────────────────┐
     │                                 │                                 │
     ▼                                 ▼                                 ▼
[MILESTONE 2: MCTS GATEWAY]     [MILESTONE 5: COMBAT & COLLISION] [MILESTONE 6: BOT AI]
- ADOPT-09: Headless Oracle     - ADOPT-01: BrushAggGeom SAT     - ADOPT-04: Havok NavMesh
- ADOPT-10: CMarshal 4-Cache    - ADOPT-02: Dual-Stage Hitbox    - ADOPT-03: Heavy Wall Fix
- ADOPT-11: 3731 Field Schema   - Fernando Ability Collision      - A* Pathfinding Graph
                                       │
                                       ▼
                         [MILESTONE 7: AUDIO & RESEARCH]
                         - ADOPT-05: Pure-Rust Wwise Vorbis
                         - ADOPT-06: Package SHA Detour
                         - ADOPT-07: TAntiCheatArray Decrypt
                         - ADOPT-08: Minimal Zig Injector
                         - ADOPT-12: .tdelta Patching
```

---

## 4. Verification & Audit Attestation

This adoption ledger has been audited for compliance with:
- **PSL-INV-007**: Cleanroom separation strictly maintained. All adoptions are expressed as typed specifications and algorithms. Zero source code transfer.
- **PSL-INV-011**: Architectural fitness verified. Core transport crates (`immortal-net`) remain decoupled from asset pipelines (`immortal-extract`) and server logic (`immortal-server`).
- **PSL-INV-001**: Verification gates defined for every item; automated test suite (`cargo test`) passes with exit code 0.
