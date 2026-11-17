---
name: accelerated-re-pipeline
description: >-
  Project Immortal (Paladins UE3 64-bit) Layer 3 reverse engineering and automated flight
  pipeline extending Layer 1 re-ops. Covers MCTS schema conformance linting, golden pcap
  replay, Paladins state milestones and branch-gate offsets, agyis flight automation,
  MCTS wire traps, and workspace agyis ext commands.
---

# Project Immortal: Accelerated RE & Flight Pipeline (Layer 3)

> **Layer 1 Delegation**: This Layer 3 project skill extends **Layer 1 `re-ops`** (and upstream `reverse-engineer-anything`). Delegate all generic dirty-room preparation (`agyis re init`, `patch-rea`, `pre-analyze`, `seed`, `daemon`, `prime`, `find`, `decompile`, `disasm`, `xrefs`, `pcap`, `cache`, `clean`), cleanroom quarantine (`PSL-INV-007`), pre-analyzed Ghidra direct-mount caching (`PSL-INV-009`), and the generic 5-step REA surgical escalation ladder to `re-ops`.

This runbook captures **Paladins UE3 64-bit / MCTS** operational specifics only: schemas, golden captures, milestones, branch-gate offsets, flight automation, wire traps, and workspace `agyis ext` binary drop-ins.

---

## 1. Project Immortal 4-Vector Verification Bindings

### Vector 1 — MCTS Schema Conformance Linter (`schema_conformance_test.rs`)
*Static schema verification against 3,731 extracted engine `s_pFields` entries in 0.01s.*

- **Ground-Truth Schema**: `crates/immortal-net/tests/fixtures/mcts_field_schema.json`
  ```bash
  grep -n -C 4 '"id": <TOKEN_ID>' crates/immortal-net/tests/fixtures/mcts_field_schema.json || [ $? -eq 1 ]
  ```
- **MCTS Scalar Groups & Types**:
  - `0x1000` (1B): `Type 1` (`bool`), `Type 2` (`int8`/`uint8`)
  - `0x3000` (4B): `Type 5` (`int32`/`uint32`), `Type 6` (`float`)
  - `0x4000` (8B): `Type 9` (`int64`/`uint64`), `Type 10` (`double`)
  - `0x6000` (Tables / Rowsets): `Type 13` (nested `CMarshalRowSet`)
  - `0xa000` (Strings & Blobs): `Type 12` (length-prefixed ASCII/UTF-16)
- **Static Linter Gate**:
  ```bash
  cargo test test_all_mcts_token_constants_match_engine_schema
  cargo test test_match_status_with_members_frame_schema_conformance
  ```

### Vector 2 — Offline Golden Pcap Replay (`golden_conformance_test.rs`)
*In-memory bit-level replay of 1,000+ genuine MCTS frames (<0.01s) from `crates/immortal-net/tests/fixtures/golden_mcts_stream.bin`.*

- **Replay Gate**:
  ```bash
  cargo test test_golden_stream
  ```
- **Carving New Paladins Subsystems** (TCP port `9000` live capture):
  ```bash
  tshark -r /mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0/pcaps/paladins_live_session.pcap \
    -Y "tcp.port == 9000" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > scratch/new_stream.bin
  ```

### Vector 3 — Paladins State Milestones & Branch-Gate Offsets
- **Milestone A (`LOBBY_MENU`)**: TCP connect -> CMarshal Hello -> Login Response -> Character Roster -> **Lobby State 2** (`LOBBY_MENU`).
- **Milestone B (`GAZEBO` & Map Travel)**: `QueueState 2` (join) -> `3` (match found + `OnMatchInvite`) -> `4` (accept) -> **Lobby State 3** (`GAZEBO` / Champion Select) -> `QueueState 7` + `ReceiveChangeMap: mapGameId 1615` / `Browse: Shootingrange_P`.
- **Milestone C (UE3 World Simulation)**: UE3 UDP NetDriver port `7777` handshake -> Actor channel `2` open -> Fernando pawn possession (`4,600 HP`, Flame Lance Device ID `10774`) -> ability & movement replication.
- **Branch-Gate Bail-Out Example (`UTgMatchLobby->QueueState` at `[rcx+0x1d8]`)**:
  ```x86asm
  mov eax, DWORD PTR [rcx+0x1d8] ; UTgMatchLobby->QueueState
  sub eax, 0x7                   ; Check for MQ_LAUNCHING (7)
  test eax, 0xfffffffd           ; Checks if QueueState == 7 or 9
  jne bailout                    ; Bails out without map transition
  ```

### Vector 4 — Automated Flight Runner (`agyis flight`)
*Headless ~90s end-to-end verification with Proton lifecycle control, `Launch.log` watchdog, UI input injection, and screen recording.*

- **Targets**:
  - `--target menu`: Stop at Main Menu (Lobby State 2)
  - `--target invite`: Stop at `MATCH READY` modal
  - `--target gazebo`: Stop at Champion Select Gazebo (Lobby State 3)
  - `--target map`: Stop when `ReceiveChangeMap` / `Browse` is logged
  - `--target range`: Stop when full Shooting Range is loaded
- **Execution Pipeline**: Terminates lingering `ShippingPC-ChaosGame.exe` & `immortal-server` -> rotates `Launch.log` -> captures server logs (`scratch/flight_server.log`) -> starts 480p/3fps MP4 recording (~200KB/10s) -> launches Proton client with non-blocking `Launch.log` watchdog and `agyis input` UI gates.
- **Evidence Outputs** (`scratch/recordings/`): `flight_summary_<TIMESTAMP>.md`, `keyframes_<TIMESTAMP>/`, `rec_<TIMESTAMP>.mp4`.

---

## 2. Escalation Binding & Paladins / MCTS Wire Traps

- **Immortal Escalation Binding**: On flight hang or failure, inspect the `Launch.log` watchdog -> apply the Layer 1 `re-ops` 5-step REA escalation ladder -> cross-check Vector 1 schema & Vector 2 golden pcap -> verify with `cargo test --all && agyis flight`.
- **Scalar Group / Type Mismatch**: Placing an `int64` (e.g., `AccountId` or Token `703`) in Group `0x3000` (4B) instead of `0x4000` (8B) causes `CMarshalRow` deserializers to corrupt memory or silently drop rows.
- **Encrypted Ciphertext Replay**: Replaying raw hex bytes from an encrypted pcap into an unencrypted MCTS/RPC session injects invalid function IDs and triggers immediate socket disconnect (`VoiceChat: Player Logoff so disconnecting`).
- **Blocking Serial Socket Reads**: Sleeping on a single TCP loop during HUD settle delays leaves incoming client frames (vendor, inventory, profile queries) unread and starves buffers; decouple read/write loops via `tokio::io::split`.

---

## 3. Workspace `agyis ext` Binary Drop-Ins (`.agents/commands/manifest.json`)

List all discovered workspace extensions with `agyis ext list`:

| Command | Purpose |
| :--- | :--- |
| `agyis flight` | Vector 4 automated flight test runner and `Launch.log` watchdog |
| `agyis game` | Control and inspect Paladins client and `immortal-server` processes (`status`, `start`, `logs`, `kill`) |
| `agyis mcts` | Look up or calculate MCTS marshal tokens and scalar group headers |
| `agyis record` | Hardware-accelerated screen recording and clipping via `gpu-screen-recorder` |
| `agyis input` | Game window & uinput automation via `ydotoold` + `xdotool` (`window`, `click`, `key`, `type`, `console`) |
| `agyis screenshot` | Capture game window or desktop screenshot (`--window`, `--output`) |

### Quick Invocation Cheatsheet
```bash
# Automated flight tests & Paladins process control
agyis flight --target map --timeout 110        # Or ./agyis flight --target menu --timeout 50
agyis game status && agyis game logs client

# MCTS token lookup & Paladins symbol query (see Layer 1 re-ops for full agyis re lifecycle)
agyis mcts 0x847de68b
agyis re find "ChaosGame" --limit 5

# Agentic screen capture & input automation
agyis record clip --duration 10 --agent
agyis input window
agyis input click 0.5 0.75 --relative
agyis screenshot
```
