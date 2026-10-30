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

### Claim 5: MCTS `LaunchMapInstance` Server Socket Handoff (`OBL-MCTS-005`)
- **Behavioral Requirement**: Server directs client to dedicated match instance using `PLAYER_SVC_LAUNCH_MAP_INSTANCE` (function hash `0x4bee2ed8` / `1273933528`). Payload contains Group `0x3002` (Token 721=5, Token 1839=60) and Group `0x4003` (Token 25=0, Token 700=match_id, Token 877=`sockaddr_in` containing target IPv4 and UDP port in network byte order).
- **Evidence Reference**: `EV-BIN-001` (`FUN_14008a5f0`) and `EV-LOG-001` (`ReceiveChangeMap: mapGameId 1615`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_launch_map_instance_frame`).
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_launch_map_instance_frame`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 6: UDP PCom Connection Framing & Zero-Prefix Standard (`OBL-UDP-001`)
- **Behavioral Requirement**: Packets delivered to `UNetConnection::ReceivedPacket` (`0x140b36586`) prior to session encryption require bytes `0..2` to be `[0x00, 0x00, 0x00]`. Client sequence ACK is positioned at byte 5, and server sequence is placed at byte 6. Packets failing the zero prefix are discarded by the engine driver.
- **Evidence Reference**: `EV-BIN-001` (`0x140b36586` assembly check `cmp byte ptr [rcx], 0`) and live packet exchange log.
- **Cleanroom Implementation**: `crates/immortal-server/src/game_server.rs` (`wrap_pcom_packet`, `wrap_pcom_ack`).
- **Verification Gate**: `cargo test --package immortal-server` (`test_initial_20_byte_pcom_connection_handshake`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 7: UDP Initial 20-Byte Connection Datagram & Pawn Replication (`OBL-UDP-002`)
- **Behavioral Requirement**: On connect, the client emits an initial 20-byte datagram (`[00, 00, 00, 00, 00, 00, 03, 40, 02, 60, 01, d0, 00, 78, 00, 44, 00, 26, 00, 01]`). Server acknowledges sequence 0, emits `NMT_Welcome` and `NMT_NetSpeed` (24000), opens Actor Channel 2 (`bOpen = true`), and replicates authoritative pawn attributes (`TgPawn_Fernando`, 4600 HP, weapon device 10774, Team 1).
- **Evidence Reference**: `EV-NET-002` (Live UDP stream capture) and `crates/immortal-server/src/game_server.rs`.
- **Cleanroom Implementation**: `crates/immortal-server/src/game_server.rs` and `crates/immortal-server/src/replication.rs`.
- **Verification Gate**: `cargo test --all` (106 hermetic tests passing).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 8: Shooting Range Game ID & Travel URL Format (`OBL-MAP-001`)
- **Behavioral Requirement**: The authentic client maps `Shootingrange_P` to `mapGameId = 1615` (rather than legacy queue ID 5). The online travel URL generated by `TgGame_Paladins_ShootingRange` appends `Team=255` as default neutral player option.
- **Evidence Reference**: `EV-NET-002` / `EV-LOG-001` (`live_paladins_launch.log:1167` and `:1172`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` and `crates/immortal-net/src/bunch.rs`.
- **Verification Gate**: `cargo test --all`.
- **Status**: 🟢 Verified (Exit code 0).

---

## 3. Residual Unknowns Ledger

| Unknown ID | Description | Impact | Required Authority | Resolution Criteria |
| :--- | :--- | :--- | :--- | :--- |
| `UNK-MCTS-001` | Structure of MCTS "hello" packet expected by `0x14002eec0` | Client rejects handshake Chunk 1 and times out after 15s | Decompiled pseudocode of `0x14002eec0` | Exact field layout, function ID, and magic framing identified from Ghidra |
| `UNK-MCTS-002` | MCTS Function hash map for catalog rowsets | Required to stream Token 100/102/105 rows to populate UI | Ghidra MSVC RTTI and marshal dispatch table | Symbol table cross-reference linking hash values to C++ handlers |
