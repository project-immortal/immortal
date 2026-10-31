---
name: accelerated-re-pipeline
description: >-
  Accelerated cleanroom reverse engineering and automated flight verification pipeline.
  Combines dirtyroom binary inspection, REA (/reverse-engineer-anything) decompiler audits,
  static schema linters, sub-second golden pcap replay fixtures, and headless flight automation.
  Use when analyzing proprietary network protocols, reverse engineering closed binaries,
  building cleanroom server emulators, or debugging client bail-out branches.
---

# Accelerated Cleanroom Reverse Engineering & Flight Pipeline

A high-velocity, deterministic methodology for reverse engineering proprietary network protocols, game clients, and closed binaries without guesswork, token waste, or cleanroom contamination.

Derived from the **Project Immortal** 18-hour empirical milestone breakthrough (Paladins UE3 64-bit cleanroom server emulator).

---

## 1. Architectural Foundation: The Cleanroom Boundary (PSL-INV-007)

```
+--------------------------------------------------------------------------------+
|                         DIRTY ROOM (Air-Gapped / Isolated)                     |
|                                                                                |
|  [Target Binary]       [Live Network Pcap]       [Engine DLLs & Memory Dumps]  |
|         |                        |                              |              |
|         v                        v                              v              |
|  REA / Ghidra / Rizin        tshark / Scapy           s_pFields / String Dumps |
|  (Branch Gate Audits)      (Stream Extraction)         (Schema Extraction)     |
+--------------------------------------------------------------------------------+
                                       |
                                       | Cleanroom Extraction Pipeline
                                       | (JSON Schemas, Golden Streams, Obligation Ledgers)
                                       v
+--------------------------------------------------------------------------------+
|                         CLEAN ROOM (Repository & Production)                   |
|                                                                                |
|  Vector 1: schema_conformance_test (0.01s static linter on Rust/Go/C++ codecs)  |
|  Vector 2: golden_conformance_test (0.00s offline replay of genuine frames)    |
|  Vector 3: Cohesive State Machine & Gating Milestones                          |
|  Vector 4: Automated Flight Runner (`dirty flight` + Watchdog + Telemetry)     |
+--------------------------------------------------------------------------------+
```

### Cleanroom Separation Invariants:
1. **Zero Disassembly / Decompiled Code in Git**: Never commit proprietary assembly, decompiler C/C++ pseudo-code, or vendor binary bytes into product repositories.
2. **Typed Obligation Ledgers**: Link every reverse-engineered claim to an immutable evidence record (function address, observed packet token, or capture timestamp).
3. **Hermetic Test Grounding**: Implementations must be proven correct against cleanroom unit tests and synthetic fixtures before touching live binaries.

---

## 2. Operational Application of the 4 Acceleration Tools

Rather than writing custom one-off scripts or guessing wire contracts, agents operating on Project Immortal apply the four built-in acceleration tools in the repository:

---

### Tool 1: Schema Conformance Linter (`schema_conformance_test.rs`)
*Static schema verification against 3,731 engine fields in 0.01 seconds.*

- **When to Apply**:
  - Whenever defining a new `MCTS_TOKEN_*` constant or serializer function.
  - Whenever modifying scalar group layouts (Group 0x1000 vs 0x3000 vs 0x4000).
  - Whenever a client parser unexpectedly drops a connection or reports malformed rowsets.
- **Operational Workflow**:
  1. **Query the Ground Truth Schema**:
     Inspect `crates/immortal-net/tests/fixtures/mcts_field_schema.json` (extracted from the engine's `s_pFields` table) to check token ID, canonical name, and data type:
     ```bash
     grep -n -C 4 '"id": <TOKEN_ID>' crates/immortal-net/tests/fixtures/mcts_field_schema.json
     ```
  2. **Verify Field Grouping Rules**:
     - **Group `0x1000`** (1 byte): `Type 1` (bool), `Type 2` (int8/uint8).
     - **Group `0x3000`** (4 bytes): `Type 5` (int32/uint32), `Type 6` (float).
     - **Group `0x4000`** (8 bytes): `Type 9` (int64/uint64), `Type 10` (double).
     - **Group `0x6000`** (Tables / Rowsets): `Type 13` (nested CMarshalRowSet).
     - **Group `0xa000`** (Strings & Blobs): `Type 12` (length-prefixed ASCII/UTF-16).
  3. **Run the Static Linter Gate**:
     ```bash
     cargo test test_all_mcts_token_constants_match_engine_schema
     cargo test test_match_status_with_members_frame_schema_conformance
     ```
     Executes hermetically in **0.01s**, guaranteeing zero scalar size or type mismatches before any live binary is launched.

---

### Tool 2: Offline Golden Pcap Conformance Suite (`golden_conformance_test.rs`)
*In-memory bit-level replay of genuine live network frames in <0.01 seconds.*

- **When to Apply**:
  - Prior to any live flight run to guarantee that cleanroom framing, decompression, and row parsing maintain 100% wire parity with authentic retail server traffic.
  - When implementing or refactoring network framing or compression handlers.
- **Operational Workflow**:
  1. **Run Golden Stream Replay**:
     ```bash
     cargo test test_golden_stream
     ```
     Replays 1,000+ real frames from `crates/immortal-net/tests/fixtures/golden_mcts_stream.bin` in memory.
  2. **Carving New Protocol Streams (If expanding to new subsystems)**:
     If exploring unmapped game subsystems (e.g. UDP bunches, chat, clan queries), extract the raw stream from the live pcap into a new test fixture:
     ```bash
     tshark -r /mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0/pcaps/paladins_live_session.pcap \
       -Y "tcp.port == 9000" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > scratch/new_stream.bin
     ```
     Ground all new parsers against this offline fixture before testing against live binaries.

---

### Tool 3: Milestone Gating & REA Branch Gate Audits
*Batching progress across discrete state gates and pinpointing client bail-out branches.*

- **When to Apply**:
  - When progressing through the client's state machine or diagnosing why the client failed to transition to the next screen.
- **The 3 Canonical Milestones**:
  - **Milestone A (Handshake & Main Menu Gate)**:
    TCP connect $\to$ CMarshal Hello $\to$ Login Response $\to$ Character Roster $\to$ **Lobby State 2** (`LOBBY_MENU`).
  - **Milestone B (Matchmaking & Gazebo Gate)**:
    Queue join (`QueueState 2`) $\to$ Match found (`QueueState 3` + `OnMatchInvite`) $\to$ Accept click (`QueueState 4`) $\to$ **Lobby State 3** (`GAZEBO` / Champion Select) $\to$ Map travel command (`QueueState 7` + `ReceiveChangeMap: mapGameId 1615` / `Browse: Shootingrange_P`).
  - **Milestone C (Simulation & World Replication Gate)**:
    Unreal Engine 3 UDP NetDriver port 7777 handshake $\to$ Actor channel 2 open $\to$ Fernando pawn possession (4,600 HP, Flame Lance Device ID 10774) $\to$ Ability and movement replication.
- **Auditing Gating Branches with REA**:
  When a milestone fails to trigger, locate the exact gating check in the binary:
  1. Search for references to the target function or state variable (e.g., `UTgMatchLobby->QueueState` at offset `0x1d8`).
  2. Disassemble the branch instructions (`inspect_native_instruction` / `procedure_assembly`):
     ```x86asm
     mov eax, DWORD PTR [rcx+0x1d8] ; UTgMatchLobby->QueueState
     sub eax, 0x7                   ; Check for MQ_LAUNCHING (7)
     test eax, 0xfffffffd           ; Checks if QueueState == 7 or 9
     jne bailout                    ; Bails out without map transition!
     ```
  3. Ensure the cleanroom server emits the exact state required by the gate before dispatching subsequent commands.

---

### Tool 4: Automated Flight Test Runner (`dirty flight`)
*Automated 90s flight execution with real-time log watchdog, input injection, and keyframe extraction.*

- **When to Apply**:
  - For end-to-end behavioral verification without manual playtesting or interactive desktop babysitting.
- **Operational Workflow**:
  1. **Execute Targeted Flight Test**:
     ```bash
     # Flight run up to map transition milestone with 110s timeout
     ./scripts/dirtyroom/dirty flight --target map --timeout 110

     # Target options:
     #   --target menu    : Stop when Main Menu (Lobby State 2) is reached
     #   --target invite  : Stop when MATCH READY modal is displayed
     #   --target gazebo  : Stop when Champion Select Gazebo is reached
     #   --target map     : Stop when ReceiveChangeMap / Browse is logged
     #   --target range   : Stop when full in-game Shooting Range is loaded
     ```
  2. **Automated Flight Execution Pipeline**:
     - Pre-flight cleanup (terminates lingering `ShippingPC-ChaosGame.exe` and `immortal-server` daemons, rotates `Launch.log`).
     - Launches background server daemon with log capture (`scratch/flight_server.log`).
     - Initializes hardware screen recording using the agentic preset (480p 3fps MP4, ~200KB per 10s).
     - Launches client under Proton and attaches real-time non-blocking log watchdog.
     - Automatically handles interactive UI gates (e.g. clicking Accept on match invite via `dirty input`).
  3. **Inspect Flight Telemetry & Evidence**:
     - Review execution timeline and milestone table: `scratch/recordings/flight_summary_<TIMESTAMP>.md`
     - Inspect captured milestone keyframes: `scratch/recordings/keyframes_<TIMESTAMP>/`
     - Verify video recording: `scratch/recordings/rec_<TIMESTAMP>.mp4`

---

## 3. The REA Surgical Escalation Ladder

When an automated flight fails or hangs at a specific gate, follow this strict 5-step escalation ladder:

```
[Flight Runner Hangs / Fails]
             |
             v
[Step 1: Check Watchdog Log] ---> Identify last logged function or silent log cessation
             |
             v
[Step 2: REA Target Routing] ---> Call open_binary or rizin/ghidra on relevant binary/DLL
             |
             v
[Step 3: Branch Gate Audit]   ---> inspect_native_instruction / procedure_assembly
                                  Pinpoint `cmp`, `test`, `jne`, or struct offset
             |
             v
[Step 4: Schema & Golden Fix] ---> Check Vector 1 schema & Vector 2 golden pcap for field mismatch
             |
             v
[Step 5: Automated Verification] -> `cargo test --all` -> `./scripts/dirtyroom/dirty flight`
```

### Common Wire Deserialization Traps (Learned Lessons):
1. **Scalar Group / Type Mismatch**:
   - Group `0x1000`: 1-byte scalar (bool, uint8).
   - Group `0x3000`: 4-byte scalar (int32, uint32, float).
   - Group `0x4000`: 8-byte scalar (int64, uint64, double).
   - *Trap*: Placing an int64 (e.g. AccountId or Token 703) in Group 0x3000 causes CMarshalRow deserializers to corrupt memory or reject rows silently.
2. **Encrypted Ciphertext Replay in Unencrypted Sessions**:
   - Replaying raw hex bytes from an encrypted session pcap into an unencrypted MCTS/RPC stream injects invalid function IDs, instantly triggering client socket shutdown (`VoiceChat: Player Logoff so disconnecting`).
3. **Blocking Serial Socket Reads During Settle Delays**:
   - If the server sleeps (e.g. waiting for client HUD assets to load), incoming client frames (vendor, inventory, profile queries) accumulate unread, causing TCP buffer starvation.
   - *Fix*: Decouple TCP stream into separate read/write loops (`tokio::io::split`).

---

## 4. Project Immortal Dirtyroom Reference Commands

```bash
# Flight test to specific milestone
./scripts/dirtyroom/dirty flight --target map --timeout 90

# Record short agentic verification clip
./scripts/dirtyroom/dirty record clip --duration 10 --agent

# Window geometry & inspect
./scripts/dirtyroom/dirty input window

# Automated mouse click (normalized 0.0-1.0 coords)
./scripts/dirtyroom/dirty input click 0.5 0.75 --relative

# Screen grab inspection
./scripts/dirtyroom/dirty screenshot
```
