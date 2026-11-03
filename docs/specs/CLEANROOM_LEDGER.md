# Cleanroom Obligation Ledger: Project Immortal
<!-- SPDX-License-Identifier: AGPL-3.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->
<!-- Invariant: PSL-INV-007 (Universal Cleanroom Reverse Engineering Standard) -->

## 1. Immutable Evidence Registry

| Evidence ID | Artifact Subject | Source Location | SHA-256 Digest | Size (Bytes) | Provider Authority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `EV-BIN-001` | `ShippingPC-ChaosGame.exe` | `Binaries/Win64/ShippingPC-ChaosGame.exe` | `0c51d381dfe9...` | 66,942,976 | Host SHA-256 / Ghidra |
| `EV-BIN-002` | `MctsInterface.dll` | `Binaries/Win64/MctsInterface.dll` | `90ce02b7b820...` | 4,683,264 | Host SHA-256 / Ghidra |
| `EV-BIN-003` | `vivoxsdk_x64.dll` | `Binaries/Win64/vivoxsdk_x64.dll` | `1c4ad378fb8c...` | 5,238,272 | Host SHA-256 / Ghidra |
| `EV-NET-001` | MCTS TCP 9000 Capture | `.dirtyroom/pcaps/mcts_only.pcap` | `10b5ab2143fb...` | 3,402,552 | REA TShark (`ev_cbe0ba5ad...`) |
| `EV-NET-002` | Live Session Full Trace | `.dirtyroom/pcaps/paladins_live_session.pcap` | `0856a4bd9401...` | 229,638,144 | Tshark / WireShark |
| `EV-LOG-001` | MCTS Client Diagnostic Log | `Binaries/Logs/MCTS-*.log` | Observed 2026-10-29 | 1,440 | Unreal Client Engine |

---

## 2. Reconstructed Architectural Claims & Verification Obligations

### Claim 1: MCTS TCP Framing & Header Validation (`OBL-MCTS-001`)
- **Behavioral Requirement**: The MCTS TCP stream uses 4-byte framing: `[payload_len: u16, flags: u16]` in little-endian.
- **Evidence Reference**: `EV-NET-001` (Frames 4, 6, 8) and `EV-BIN-001` (`CPackSocket::SendPackage`).
- **Cleanroom Implementation**: `crates/immortal-net/src/gateway.rs` and `crates/immortal-net/src/framing.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (Framing unit and fuzz tests).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 2: MCTS RPC Function Dispatch & Hash Lookup (`OBL-MCTS-002`)
- **Behavioral Requirement**: Incoming marshal payloads begin with a 32-bit function identifier hashed using 64-bit FNV-1a (`0xcbf29ce484222325`, prime `0x100000001b3`) at `VA 0x140020ee3`. Invalid function hashes trigger `"Bad marshal, out of range function [%i]"`.
- **Evidence Reference**: `EV-LOG-001` (function `739393586` out of range) and `EV-BIN-001` disassembly at `0x140020fcb`.
- **Cleanroom Implementation**: `crates/immortal-net/src/marshal.rs` (`LoginRequest`, `LoginResponse`).
- **Verification Gate**: Integration test decoding client marshal calls.
- **Status**: 🟡 In Progress (Awaiting Ghidra pre-analysis to resolve exact function map).

### Claim 3: MCTS Programmatic Handshake Framing (`OBL-MCTS-003`)
- **Behavioral Requirement**: Handshake sequence operates via two-step wire framing:
  1. Client Auth Request (`len: 405`, `flags: 0x0000`) triggers Server Handshake Challenge (`len: 433`, `flags: 0x0100`).
  2. Client Crypto Ticket (`len: 1117`, `flags: 0x0100`) triggers Server Ticket ACK (`len: 21`, `flags: 0x0100`) and Session Subpackets (`len: 75`, containing 3 x 25-byte framed subpackets).
- **Evidence Reference**: `EV-NET-001` (Frames 1-10) and `EV-BIN-002` (`CPackSocket::WaitMarshal` at `0x18004e4e0`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` and `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_auth_gateway_live_mcts_two_step_exchange`). Zero raw binary captures committed to source tree.
- **Status**: 🟢 Verified (Exit code 0).

### Claim 4: MCTS `OnLoginResponse` Frame & Session Authorization (`OBL-MCTS-004`)
- **Behavioral Requirement**: Following authentication handshake completion, server emits `OnLoginResponse` (function hash `0x7a4036ab` / `2051028651`). Payload marshals `account_id` (token `118`), `player_name` (token `119`), and `session_token` (token `120`) without `0xCBBC` compression magic.
- **Evidence Reference**: `EV-BIN-001` (`CMarshalRow::Store` at `0x140020ee3`) and client state transition from `LOGGING IN` to `LOBBY_STATE_2` (Main Menu).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_login_response_frame`) and `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_mcts_login_response_frame_structure`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 5: MCTS `LaunchMapInstance` Server Socket Handoff & Table 312 Lobby Binding (`OBL-MCTS-005`)
- **Behavioral Requirement**: Server directs client to dedicated match instance using `PLAYER_SVC_LAUNCH_MAP_INSTANCE` (function hash `0x4bee2ed8` / `1273933528`). Payload contains Group `0x3002` (Token 721=5, Token 1839=60) and Group `0x4003` (Token 25=0, Token 700=match_id, Token 877=`sockaddr_in` containing target IPv4 and UDP port in network byte order). Additionally, matchmaking member binding in Table 312 (`DATA_SET_MEMBERS`) requires Token 838 (`POSITION` = 0, Group `0x3000`) and authentic 64-bit NetId (`Token 11` = `109775243102792335` / `0x0186000082462a8f`). Without Token 838 = 0 and 64-bit NetId matching `LocalNetId`, `UTgMatchLobby` classifies the local player as an opponent ('Enemy 1') on the right team, leaves friendly slots empty, and bails out of local QueueState progression.
- **Evidence Reference**: `EV-BIN-001` (`FUN_14008a5f0`, `UTgMatchLobby` member classification), `EV-BIN-002` (`MctsInterface.dll: FUN_1800eadd0` extracting Token 838 `POSITION`), and `EV-LOG-001` (`ReceiveChangeMap: mapGameId 1615`, `LocalNetId` initialization `109775243102792335`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_launch_map_instance_frame`, `create_mcts_match_status_with_members_frame`), `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_launch_map_instance_frame`, `test_create_mcts_match_status_with_members_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 6: MCTS `QUEUE_STATUS` / `SERVER_STATUS` Table 242 Dispatch (`OBL-MCTS-006`)
- **Behavioral Requirement**: Driving `CMctsQueue` and `UTgMatchLobby + 0x1d8` through the 4-stage matchmaking queue lifecycle (State 2 `MQ_QUEUED`, State 3 `MQ_INVITED`, State 4 `MQ_ACCEPTED`, State 7 `MQ_LAUNCHING`) requires dedicated server dispatch of Function ID `0x2cdbafe1` (`QUEUE_STATUS` / `SERVER_STATUS`) containing Table 242 (`MFIELD_QUEUE_STATUS`). Table 242 Row 0 encapsulates Token 36 (`MFIELD_QUEUE_STATE`, Group `0x3001`) and Token 703 (`MFIELD_QUEUE_ID` = 434, Group `0x4001`). Client binary analysis confirms `RecievedMatchStatus MCTS` does not read `QueueState` from `MATCH_STATUS` (Token 2191 is unparsed), but reads `[UTgMatchLobby + 0x1d8]`, which is populated exclusively by `QUEUE_STATUS`. Transition to `QueueState == 7` (`MQ_LAUNCHING`) is required at `0x1400d2560` in `UTgMatchLobby::Tick` to evaluate true and trigger `AUTOPICK` event `0x3af7`.
- **Evidence Reference**: `EV-NET-002` (`live_paladins_launch.log:1049-1055`), `EV-BIN-002` (`MctsInterface.dll: FUN_1800f5fd0` at `0x1800f617a`, `FUN_1800f3fb0`, `FUN_1800ec640`), and `ShippingPC-ChaosGame.exe` (`UTgMatchLobby` event handler at `0x1414dc043`, `UTgMatchLobby::Tick` at `0x1400d2560`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_queue_status_frame`), `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_queue_status_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 7: Server Queue Catalog Definition Specification (`OBL-MCTS-007`)
- **Behavioral Requirement**: Client matchmaking registration requires the server to define available match queues via Function ID `0xaf434825` (`MCTS_FUNCTION_ID_QUERY_SERVERS`) carrying Token 550 (`MCTS_TOKEN_QUEUE_CATEGORY` = 1, Group `0x3001`) and Table 242 (`MFIELD_QUEUE_STATUS`, Group `0x6001`). In `MctsInterface.dll: FUN_1800f41f0` (`CMctsMatchMaking::OnQueryServers`), parsing this table instantiates `CMctsQueue` instances and populates the client internal `std::map<uint32_t, CMctsQueue*>` stored at `[this + 0x50]`. Without this frame, `CMctsMatchMaking::FindQueueById` bails out at `0x1800f4169` during subsequent `QUEUE_STATUS` events, preventing queue state transitions to `QueueState == 7` (`MQ_LAUNCHING`) and blocking UnrealScript `AUTOPICK` event `0x3af7`.
- **Evidence Reference**: `EV-NET-002` (`live_paladins_launch.log:1049-1055`), `EV-BIN-002` (`MctsInterface.dll: FUN_1800f41f0`, `FUN_1800f3a00`, `FUN_1800f3fb0` at `0x1800f4024`), and `ShippingPC-ChaosGame.exe` (`UTgMatchLobby::Tick` at `0x1400d2560`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_queue_definition_frame`), `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_queue_definition_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 8: UDP PCom Connection Framing & Zero-Prefix Standard (`OBL-UDP-001`)
- **Behavioral Requirement**: Packets delivered to `UNetConnection::ReceivedPacket` (`0x140b36586`) prior to session encryption require bytes `0..2` to be `[0x00, 0x00, 0x00]`. Client sequence ACK is positioned at byte 5, and server sequence is placed at byte 6. Packets failing the zero prefix are discarded by the engine driver.
- **Evidence Reference**: `EV-BIN-001` (`0x140b36586` assembly check `cmp byte ptr [rcx], 0`) and live packet exchange log.
- **Cleanroom Implementation**: `crates/immortal-server/src/game_server.rs` (`wrap_pcom_packet`, `wrap_pcom_ack`).
- **Verification Gate**: `cargo test --package immortal-server` (`test_initial_20_byte_pcom_connection_handshake`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 9: UDP Initial 20-Byte Connection Datagram & Pawn Replication (`OBL-UDP-002`)
- **Behavioral Requirement**: On connect, the client emits an initial 20-byte datagram (`[00, 00, 00, 00, 00, 00, 03, 40, 02, 60, 01, d0, 00, 78, 00, 44, 00, 26, 00, 01]`). Server acknowledges sequence 0, emits `NMT_Welcome` and `NMT_NetSpeed` (24000), opens Actor Channel 2 (`bOpen = true`), and replicates authoritative pawn attributes (`TgPawn_Fernando`, 4600 HP, weapon device 10774, Team 1).
- **Evidence Reference**: `EV-NET-002` (Live UDP stream capture) and `crates/immortal-server/src/game_server.rs`.
- **Cleanroom Implementation**: `crates/immortal-server/src/game_server.rs` and `crates/immortal-server/src/replication.rs`.
- **Verification Gate**: `cargo test --all` (106 hermetic tests passing).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 10: Shooting Range Game ID & Travel URL Format (`OBL-MAP-001`)
- **Behavioral Requirement**: The authentic client maps `Shootingrange_P` to `mapGameId = 1615` (rather than legacy queue ID 5). The online travel URL generated by `TgGame_Paladins_ShootingRange` appends `Team=255` as default neutral player option.
- **Evidence Reference**: `EV-NET-002` / `EV-LOG-001` (`live_paladins_launch.log:1167` and `:1172`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` and `crates/immortal-net/src/bunch.rs`.
- **Verification Gate**: `cargo test --all`.
- **Status**: 🟢 Verified (Exit code 0).

### Claim 11: MCTS ChangeMap RPC Dispatch (`OBL-MCTS-008` / `0x847de68b`)
- **Behavioral Requirement**: Transitioning an active Gazebo match lobby into dedicated map travel requires dispatching authentic `ChangeMap` RPC (function hash `0x847de68b` / `2222843531`). The payload contains Token 1536 (`COMPEL` = true (Token 1536 = 0x01), Group `0x1001`), Token 682 (`MAP_GAME_ID` = 1615, Group `0x3001`), and Token 685 (`MAP_INSTANCE_ID` = 1282927737, Group `0x4001`). Unlike legacy function ID `0xe621824e` which triggers the virtual logoff routine `(*param_1 + 0xe8)()` when Gazebo is active (`ShippingPC-ChaosGame.exe: FUN_140d39e50`), `0x847de68b` is routed to `FUN_1800da6e0` in `MctsInterface.dll`, preserving client session state and initiating map progression.
- **Evidence Reference**: `EV-BIN-001` (`ShippingPC-ChaosGame.exe: FUN_140d39e50` line 85), `EV-BIN-002` (`MctsInterface.dll: CMctsGameServer::ProcessMarshal` at `0x1800db730` -> `FUN_1800da6e0`), `EV-NET-002` (Flight 021 diagnostic trace `[0037.40]`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_change_map_frame`, `MCTS_FUNCTION_ID_CHANGE_MAP`), `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_change_map_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 12: Gazebo QueueState 7 Launch Gate (`OBL-MCTS-009`)
- **Behavioral Requirement**: In `ShippingPC-ChaosGame.exe`, receipt of `MATCH_STATUS` (Function ID `0x392dcda5`) in Gazebo evaluates `UTgMatchLobby->QueueState` at offset `+0x1d8`. The client enforces that `QueueState == 7` (`MQ_LAUNCHING`) or `9`. If `QueueState` is not 7 or 9, execution bails out at `0x140d39f1b`, failing to arm the map session descriptors (`[rbx+0x874]` and `[rbx+0x88c]`), which causes downstream map travel (`ReceiveChangeMap` at `0x141576a00`) to fail silently. Furthermore, authentic retail traces (`live_paladins_launch.log` line 1090) confirm that `MATCH_STATUS` state 10 carries `QueueId: 0` (resetting from prior matchmaking queue selection) and `create_mcts_change_map_frame` requires `compel = true` (`Token 1536 = 0x01`) to enforce unconditional map travel.
- **Evidence Reference**: `EV-BIN-001` (`ShippingPC-ChaosGame.exe: FUN_140d39e50` at `0x140d39f0d`..`0x140d39f1b`), `EV-NET-002` (`live_paladins_launch.log:1090`), `EV-BIN-002` (`MctsInterface.dll: FUN_1800da6e0`).
- **Cleanroom Implementation**: `crates/immortal-net/src/gateway.rs`, `crates/immortal-net/src/mcts_handshake.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_gazebo_lifecycle_state8_to_state10_transition_invariants`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

---

## 3. Residual Unknowns Ledger

| Unknown ID | Description | Impact | Required Authority | Resolution Criteria |
| :--- | :--- | :--- | :--- | :--- |
| `UNK-MCTS-001` | Structure of MCTS "hello" packet expected by `0x14002eec0` | Client rejects handshake Chunk 1 and times out after 15s | Decompiled pseudocode of `0x14002eec0` | Exact field layout, function ID, and magic framing identified from Ghidra |
| `UNK-MCTS-002` | MCTS Function hash map for catalog rowsets | Required to stream Token 100/102/105 rows to populate UI | Ghidra MSVC RTTI and marshal dispatch table | Symbol table cross-reference linking hash values to C++ handlers |
