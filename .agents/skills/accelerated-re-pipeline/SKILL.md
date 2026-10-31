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

## 2. The 4 Velocity Acceleration Vectors

### Vector 1: Zero-Guesswork Global Schema Extraction & Linter
*Never guess wire types or token IDs one-by-one at runtime.*

1. **Locate the Binary's Schema / Reflection Table**:
   - Proprietary RPCs, marshalers, and serialization engines almost always embed a global field descriptor table (e.g. `s_pFields`, protobuf descriptors, Unreal reflection `UClass`/`UProperty`, or flatbuffers schemas).
   - Use REA (`search_strings`, `search_bytes`, `inspect_native_data_type`) or dirtyroom CLI to locate the table or extract it from memory.
2. **Dump Schema to Clean JSON**:
   - Extract fields into a clean JSON fixture:
     ```json
     {
       "fields": [
         {"token": 36, "name": "MFIELD_ACTIVE", "type": 1, "group": "0x1000", "size": 1},
         {"token": 703, "name": "MATCH_QUEUE_ID", "type": 9, "group": "0x4000", "size": 8},
         {"token": 912, "name": "MFIELD_TIMESTAMP", "type": 5, "group": "0x3000", "size": 4}
       ]
     }
     ```
3. **Implement a Native Sub-Second Schema Linter**:
   - Write a unit test (`schema_conformance_test.rs`) that statically checks every token constant and serializer layout against the JSON schema.
   - Run on every build (`cargo test`, `pytest`, `go test`). Catches scalar size mismatches (e.g. encoding an `int64` in a 4-byte group) in **0.01s** before any client is launched.

---

### Vector 2: Sub-Second Offline Golden Pcap Conformance Suite
*Never launch the target binary just to test if a packet parser works.*

1. **Carve Genuine Protocol Streams**:
   - From an authentic live packet capture (`.pcap`), isolate the raw TCP/UDP application payload stream using `tshark` or a python script:
     ```bash
     tshark -r capture.pcap -Y "tcp.port == 9000" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > golden_stream.bin
     ```
2. **Build an In-Memory Golden Replay Test**:
   - Read `golden_stream.bin` into memory during unit tests (`golden_conformance_test.rs`).
   - Validate framing, checksums, compression headers, and payload structures against cleanroom parsers.
   - Executes 1,000+ real frames in **<0.01s**, guaranteeing 100% wire parity hermetically.

---

### Vector 3: Cohesive Milestone Batching & Gating Architecture
*Stop thrashing between disparate subsystems; batch by state gates.*

1. **Deconstruct the State Machine into Distinct Milestones**:
   - **Milestone A (Handshake & Lobby Gate)**: Transport handshake, authentication, roster synchronization, and transition to initial UI.
   - **Milestone B (Session & Launch Gate)**: Matchmaking invite, queue states (`MQ_QUEUED` $\to$ `MQ_INVITED` $\to$ `MQ_ACCEPTED` $\to$ `MQ_LAUNCHING`), map change command.
   - **Milestone C (Simulation & World Replication Gate)**: UDP NetDriver handshake, world replication, entity spawn, pawn possession, movement/ability streaming.
2. **REA Gating Audit**:
   - When a transition does not trigger, use REA to find the gating instruction in the binary:
     ```x86asm
     mov eax, DWORD PTR [rcx+0x1d8] ; Read QueueState
     sub eax, 0x7                   ; Check for MQ_LAUNCHING
     test eax, 0xfffffffd           ; Gating condition
     jne bailout_address            ; Abort transition
     ```
   - Satisfy the exact gate before writing code for downstream states.

---

### Vector 4: Automated Flight Runner with Watchdog & Input Automation
*Replace manual 90s playtesting with headless automated flight execution.*

Implement `./scripts/dirtyroom/dirty flight` with the following loop:
1. **Pre-flight Cleanup**: Gracefully terminate lingering target processes (`killall -9 ShippingPC-ChaosGame.exe`), clear previous client logs (`Launch.log`), and ensure release server is built.
2. **Background Daemon Startup**: Launch the cleanroom server daemon in the background with output piped to a flight log.
3. **Agentic Screen Recording**:
   - Start hardware screen recording (`gpu-screen-recorder` or `ffmpeg`) with an agentic preset: **480p 3fps MP4** (<200KB per 10s).
   - Fast enough to capture all visual state transitions without eating disk or token context.
4. **Target Client Launch**: Launch client via native binary, Wine, or Proton.
5. **Non-Blocking Real-Time Log Watchdog**:
   - Continuously monitor client log in real-time.
   - Define regex milestone detectors:
     - `LOBBY_MENU`: Reached main menu.
     - `MATCH_INVITE`: Match invitation modal displayed.
     - `GAZEBO`: Champion select / staging area loaded.
     - `MAP_CHANGE`: Map travel command accepted.
6. **Automated Input Injection**:
   - When `MATCH_INVITE` is detected, use `dirty input` (`ydotool` / `xdotool`) to focus the target window, move mouse to the accept button `(X, Y)` or send `Return`.
7. **Post-Flight Evidence Extraction**:
   - Send `SIGINT` to the screen recorder for clean MP4 container finalization.
   - Extract keyframe JPEGs at detected milestone timestamps (`ffmpeg -ss <t> -i rec.mp4 -vframes 1 keyframe.jpg`).
   - Generate a concise flight summary markdown in `scratch/recordings/flight_summary_<timestamp>.md`.

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
