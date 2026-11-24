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
| `EV-NET-002` | Live Session Full Trace | `.dirtyroom/pcaps/paladins_live_session.pcap` | `c8bf4ebd0ced...` | 229,638,144 | Tshark / WireShark (SHA-256 `c8bf4ebd0ced626096f91a722b02c549bed97e6cbbabc6cc7632bd9d46ae653c`) |
| `EV-LOG-001` | MCTS Client Diagnostic Log | `Binaries/Logs/MCTS-*.log` | Observed 2026-10-29 | 1,440 | Unreal Client Engine |
| `EV-LOG-002` | Flight 034 Live Client UDP Capture | `scratch/flight_server.log` | Observed 2026-11-17 | 3 live datagrams (19B, 19B, 18B) | Project Immortal Flight 034 / Paladins 8.1.5839.0 |
| `EV-LOG-003` | Retail Paladins Launch Log | `.dirtyroom/pcaps/live_paladins_launch.log` | `e9f3a63cc765...` | 172,032 | Paladins 8.1.5839.0 (`NM_Standalone (0)` Shooting Range verification) |
| `EV-NET-003` | Bot Siege Dedicated UDP + MCTS Capture | `.dirtyroom/pcaps/CAP-01_bot_siege_20261119.pcapng` | `4f21c120e39c74dedc7803a781b8bc24a7a0998d76cb204538f4738cf39deb5d` | 36,412,416 | Project Immortal CAP-01 (46,252 packets on UDP port 9222 via nflog:42 cgroup-isolated) |
| `EV-LOG-004` | Bot Siege Paired Retail Launch Log | `.dirtyroom/pcaps/CAP-01_bot_siege_20261119_Launch.log` | `16376a1dd649d32e9c906e04d90cf7165998dffec6c8cc437f156537889c2463` | 710,553 | Paladins 8.1.5839.0 (8,245 log lines, paired retail launch log, clean exit) |
| `EV-NET-004` | Refreshed Shooting Range Isolated Trace | `.dirtyroom/pcaps/CAP-00_shooting_range_20261119.pcapng` | `9b3b78b0f3b813ac206bf49efc7d672092c9ae1238aa225cfe1ae681fcf4ee13` | 4,344,000 | Project Immortal CAP-00 (6,010 clean cgroup-isolated packets on nflog:42, zero host leak) |
| `EV-LOG-005` | Refreshed Shooting Range Paired Log | `.dirtyroom/pcaps/CAP-00_shooting_range_20261119_Launch.log` | `58009f20b948c15acd63668961d4775b7c9308ce63f7cacd5c729a87b2f0c294` | 159,808 | Paladins 8.1.5839.0 (Viktor/Fernando shooting range session, clean exit) |
| `EV-NET-005` | Custom Baseline Dedicated UDP + MCTS Capture | `.dirtyroom/pcaps/CAP-03_custom_baseline_20261119.pcapng` | `02a5fa92d0e7332e0e7a4ac26349366d6c20cab6e3e036e74351e6c055c92696` | 21,262,100 | Project Immortal CAP-03 (53,008 dedicated UDP packets on 20.33.35.9:9113, 1 human + 1 bot clean differential trace) |
| `EV-LOG-006` | Custom Baseline Paired Retail Launch Log | `.dirtyroom/pcaps/CAP-03_custom_baseline_20261119_Launch.log` | `a1c6c179ebba83e094cd5c0da4250fd1292dc51c1ea99957c71a7ca5eba3b567` | 247,287 | Paladins 8.1.5839.0 (2,866 lines, Fernando vs Evie on sg_jaguarfalls_rework_p, clean match exit) |
| `EV-UPK-006` | `Engine.upk` (UE3 v893 Cooked Package) | `ChaosGame/CookedPCConsole/Engine.upk` | `c8541aa0ab647d1952da0cbd0c7c36e236fcc1b6f12f48b6fc047bae19e91e48` | 3,813,766 | Host SHA-256 / `UProperty` & `UFunction` `NetIndex` verification |
| `EV-UPK-007` | `TgGame.upk` (UE3 v893 Cooked Package) | `ChaosGame/CookedPCConsole/TgGame.upk` | `dd1fa76a3583c64305a305f7d7177c441356463f31a2531bb25d1bf0921bdbf8` | 9,672,524 | Host SHA-256 / `FClassNetCache` `Tg*` schema verification |
| `EV-ORACLE-001` | Retail Oracle `?exudp=0` Loopback Probe Trace | Ephemeral session trace (`oracle_probe_trace.json`, `ADOPT-09`) | `d57c83353cf4fa531d8b546885b5726b9a9b2a0fc50170430ac28a93e404564e` | 464,255 | Headless Wine Retail Oracle (`127.0.0.1:7000`, `Shootingrange_P`, 91 actor opens + 150+ updates) |

---

## 2. Reconstructed Architectural Claims & Verification Obligations

### Claim 1: MCTS TCP Framing & Header Validation (`OBL-MCTS-001`)
- **Behavioral Requirement**: The MCTS TCP stream uses 4-byte framing: `[payload_len: u16, flags: u16]` in little-endian.
- **Evidence Reference**: `EV-NET-001` (Frames 4, 6, 8) and `EV-BIN-001` (`CPackSocket::SendPackage`).
- **Cleanroom Implementation**: `crates/immortal-net/src/gateway.rs` and `crates/immortal-net/src/framing.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (Framing unit and fuzz tests).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 2: MCTS RPC Function Dispatch & Hash Lookup (`OBL-MCTS-002`)
- **Behavioral Requirement**: Incoming marshal payloads begin with a 32-bit function identifier hashed using **32-bit FNV-1** ($H_0 = \mathtt{0x811c9dc5} = 2166136261$, prime $\mathtt{0x01000193} = 16777619$, $H_{i+1} = ((H_i \times 16777619) \oplus B_i) \pmod{2^{32}}$), matching verified MCTS hashes (`0x7a4036ab`, `0x847de68b`, `0x392dcda5`, `0x15c61937`). Invalid function hashes trigger `"Bad marshal, out of range function [%i]"`.
- **Evidence Reference**: `EV-LOG-001` (function `739393586` out of range), `EV-BIN-001` disassembly at `0x140020fcb`, and `TEMPEST_ADOPTION_LEDGER.md` (`ADOPT-11`).
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (live wire framing `[0x00, u32 fnv1, u16 count, 0x1000..0xA000]`). Note: `crates/immortal-net/src/marshal.rs` (`CMarshalMessage`) is an unaligned legacy schema unused by live MCTS (`ADOPT-10`/`ADOPT-11` pending).
- **Verification Gate**: Integration test decoding client marshal calls and build-time FNV-1 hash verification.
- **Status**: 🟡 In Progress (32-bit FNV-1 verified; generic `ADOPT-10`/`ADOPT-11` engine pending).

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
- **Behavioral Requirement**: Packets delivered to `UNetConnection::ReceivedPacket` (`0x140b36586`) prior to session encryption begin with a zero-prefixed outer header. *(Superseded for inner byte-6/byte-7 framing by Claim 16 / `OBL-UDP-002`; the 6-byte outer `PComNetConn` prefix rule is preserved under Claim 15 & Claim 16.)*
- **Evidence Reference**: `EV-BIN-001` (`0x140b36586` outer header check) and live packet exchange log.
- **Cleanroom Implementation**: Superseded by `crates/immortal-net/src/bitstream.rs`, `crates/immortal-net/src/bunch.rs` (`Ue3Packet`), and `crates/immortal-server/src/game_server.rs`.
- **Verification Gate**: `cargo test --all` (`test_flight034_full_staged_udp_handshake_to_welcome_and_join`).
- **Status**: 🟢 Verified (Superseded by Claim 16).

### Claim 9: UDP Initial Connection Datagram & Pawn Replication (`OBL-UDP-002` Legacy Entry)
- **Behavioral Requirement**: Initial connection framing and pawn replication attributes (`TgPawn_Fernando`, 4600 HP, weapon device 10774). *(Superseded for UDP 7777 wire framing and staged handshake sequence by Claim 16; `crates/immortal-server/src/replication.rs` implements a simulated byte-aligned prototype only; authentic post-`NMT_Join` Actor Channel bit-packing is reopened under Claim 18 / `UNK-UDP-004`.)*
- **Evidence Reference**: `EV-NET-002` and `EV-BIN-001`.
- **Cleanroom Implementation**: `crates/immortal-server/src/game_server.rs` and `crates/immortal-server/src/replication.rs` (simulated).
- **Verification Gate**: `cargo test --all`.
- **Status**: 🟡 Superseded / Simulated (Wire layout superseded by Claim 16 & [`UACTOR_CHANNEL_WIRE_SPEC.md`](UACTOR_CHANNEL_WIRE_SPEC.md); `replication.rs` remains simulated pending Rust integration & Live Flight 036 under `UNK-UDP-004`; `UNK-CRYPTO-001` Mathematically Bounded / Archived).

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
- **Behavioral Requirement**: In `ShippingPC-ChaosGame.exe`, receipt of `MATCH_STATUS` (Function ID `0x392dcda5`) in Gazebo evaluates `UTgMatchLobby->QueueState` at offset `+0x1d8`. The client enforces that `QueueState == 7` (`MQ_LAUNCHING`) or `9`. If `QueueState` is not 7 or 9, execution bails out at `0x140d39f1b`, failing to arm the map session descriptors (`[rbx+0x874]` and `[rbx+0x88c]`), which causes downstream map travel (`ReceiveChangeMap` at `0x141576a00`) to fail silently. `MATCH_STATUS` never writes `QueueState` directly, and `QUEUE_STATUS` (0x2cdbafe1) discards Token 1646 (`MCTS_TOKEN_QUEUE_STATE`). Token 1646 is parsed exclusively by `FUN_1400e5c50` under `OnQueryServers` (`0xaf434825` / `MCTS_FUNCTION_ID_QUERY_SERVERS`), updating `QueueEntry[queue_id].QueueState`. The auth gateway dispatches `OnQueryServers` (`create_mcts_queue_definition_frame(434, 1615, 7)`) to prime client memory prior to State 10. Transitioning `MATCH_STATUS` state 10 to `QueueId: 434` (from `0` in state 8) breaks the `UTgMatchLobby` queue cache, triggering `FindQueueById(434)` (`FUN_1800f4169`) and copying `QueueEntry[434].QueueState` (7) into `[UTgMatchLobby + 0x1d8]`, satisfying gate `0x140d39f1b`, while `create_mcts_change_map_frame` requires `compel = true` (`Token 1536 = 0x01`) to enforce unconditional map travel.
- **Evidence Reference**: `EV-BIN-001` (`ShippingPC-ChaosGame.exe: FUN_140d39e50` at `0x140d39f0d`..`0x140d39f1b`, `FUN_1400e5c50`, `FUN_1400e7500`), `EV-NET-002` (`live_paladins_launch.log:1090`), `EV-BIN-002` (`MctsInterface.dll: FUN_1800da6e0`, `FUN_1800f4169`), `MISSION-2026-IMMORTAL-RCA-QUEUE-STATE-001`.
- **Cleanroom Implementation**: `crates/immortal-net/src/gateway.rs`, `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_queue_definition_frame`).
- **Verification Gate**: `cargo test --package immortal-net` (`test_gazebo_lifecycle_state8_to_state10_transition_invariants`, `test_create_mcts_queue_definition_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 13: MCTS `MAP_INSTANCE_ASSIGNED` (`0x15c61937`), Table `1583` Match Composition & Bail-Out Exclusions (`OBL-MCTS-010`)
- **Behavioral Requirement**: `ShippingPC-ChaosGame.exe` statically links the MCTS client SDK (does not import `MctsInterface.dll`) and requires Function ID `0x15c61937` (`MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED`) to cache match composition and commit travel to `mapGameId = 1615`. The payload must supply Token `682` (`MAP_GAME_ID` = `1615`), Token `588` (`HOST_NET_ADDR` 8-byte `sockaddr_in`), Token `685` (`MAP_INSTANCE_ID`), Table `1583` (`DATA_SET_MATCH_COMPOSITION`), and Token `2287` (`PORTAL_SESSION_ID`), while omitting bail-out/offline triggers (omit or `0` Token `1116`, omit Token `2838`, omit offline codes `{15413, 15500, 15415}` in Token `2637`).
- **Evidence Reference**: `EV-BIN-001` (static-linked MCTS SDK in `ShippingPC-ChaosGame.exe`), Flight 033 client logs (`Match composition cached [96E3D70]`, `ReceiveChangeMap: mapGameId 1615`), and `EV-NET-002`.
- **Cleanroom Implementation**: `crates/immortal-net/src/mcts_handshake.rs` (`create_mcts_match_composition_frame`, `MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED`), `crates/immortal-net/src/gateway.rs`.
- **Verification Gate**: `cargo test --package immortal-net` (`test_create_mcts_match_composition_frame_structure`, `test_auth_gateway_live_mcts_two_step_exchange`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 14: MCTS TCP `0x07FE` Post-Login Zero-Length Chunk Framing (`OBL-MCTS-011`)
- **Behavioral Requirement**: Once post-login framing begins on TCP port `9000`, an incoming 4-byte framing header whose length field `field0 == 0` (such as `[00, 00, 08, 01]`) encodes a full `0x07FE` (`2046`-byte, `MAX_PAYLOAD_LEN`) payload chunk rather than a zero-byte frame.
- **Evidence Reference**: Flight 032/033 live MCTS TCP captures and `EV-NET-001`.
- **Cleanroom Implementation**: `crates/immortal-net/src/gateway.rs` (`handle_connection` post-login framing loop) and `crates/immortal-net/src/framing.rs` (`MAX_PAYLOAD_LEN`).
- **Verification Gate**: `cargo test --package immortal-net` (post-login `0x07fe` chunk integration tests).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 15: PComNetConn UDP 7777 Outer 6-Byte Prefix Stripping (`OBL-UDP-001`)
- **Behavioral Requirement**: Datagrams delivered to UDP port `7777` carry a 6-byte `PComNetConn` outer prefix: byte 0 (`0x00`), byte 1 monotonic QPC-seeded connection tag, and bytes 2..5 big-endian connection cookie. `ShippingPC-ChaosGame.exe` unconditionally strips the first 6 bytes in `UPComNetConn::ReceivedRawPacket` (`0x140bc8770`) before passing the remaining bytes to `UNetConnection::ReceivedRawPacket` (`0x140b37100`). Echoing the client's 6-byte `pcom_prefix` (`[0x00, token[0..5]]`) on server-to-client datagrams is accepted unconditionally by `0x140bc8770` and maintains prefix-echo symmetry. *(Note: The legacy byte-6 sequence / byte-7 control flags / unconditional trailing `0x01` description previously cited here is superseded by Claim 16 / `OBL-UDP-002`.)*
- **Evidence Reference**: `EV-BIN-001` (`ShippingPC-ChaosGame.exe` `0x140bc8770`, `0x140bd48e0`, `0x140b37100`, `0x140b36500`), Flight 033/034 live client captures (`EV-LOG-002`), and `EV-NET-002`.
- **Cleanroom Implementation**: `crates/immortal-net/src/bunch.rs` (`Ue3Packet::pcom_prefix`) and `crates/immortal-server/src/game_server.rs` (`ClientSession::pcom_prefix`, `handle_ue3_pcom_datagram`).
- **Verification Gate**: `cargo test --all` (`test_golden_flight034_udp_bitstream_roundtrip`, `test_flight034_full_staged_udp_handshake_to_welcome_and_join`, `test_game_server_pcom_driver_loopback_integration`).
- **Status**: 🟢 Verified (Outer 6-byte prefix retained; inner bitstream governed by Claim 16).

### Claim 16: UE3 Bit-Packed `FInBunch`/`Ue3Packet` Codec & Complete Staged UDP 7777 Handshake (`OBL-UDP-002`)
- **Behavioral Requirement**: After the 6-byte `PComNetConn` outer prefix is stripped, every UDP 7777 payload is an LSB-first UE3 `FBitReader`/`FBitWriter` bitstream terminated by a trailing single `1` stop bit and zero-padded to the byte boundary (`last_byte == 0x00` is rejected). With `bUsePacketHeader (+0xb0fc) == 0`, each packet begins with 14-bit `PacketId` (`MAX_PACKETID = 0x4000`, server 0-based) followed by zero or more ACK records (`IsAck = 1`, 14-bit `AckPacketId`) and bit-packed `FInBunch` records (`IsAck = 0`, `bControl`, optional `bOpen`/`bClose`, `bReliable`, 11-bit `ChIndex` [`MAX_CHANNELS = 0x800`], optional 10-bit 1-based `ChSequence` [`MAX_CHSEQUENCE = 0x400`], optional 3-bit `ChType` [`CHTYPE_MAX = 8`: `None=0, Control=1, Actor=2, File=3, Voice=4, Marshal=5`], variable-width `BunchDataBits = SerializeInt(MaxPacket * 8)`, and LSB-first payload bits). For standard UDP (`?exudp=0`/omitted), `MaxPacket = 0x240` (`576` bytes = `4608` bits), yielding a 12-bit length field for `512..=4095` bits (13-bit for `< 512` or `4096..=4607`); `?exudp>=1` uses `MaxPacket = 0x1F0` (`496` bytes = `3968` bits). Channel 0 (`CHTYPE_Control = 1`) executes the 7-stage Paladins control handshake: `0x1A NMT_HandshakeStart(u32)` -> `0x1B NMT_HandshakeChallenge(u32)` -> `0x1C NMT_HandshakeResponse(u32)` validated via signed `i32` `%d` formatting of `"895fcf626f55798667e4e94cb7a636af %d"` through MSB-first CRC32 (`0x04C11DB7`) over UTF-16LE code units -> `0x1D NMT_HandshakeComplete()` -> `0x20 NMT_ServerAuthRequest()` -> `0x1F NMT_ClientAuthRequest(ServerSteamId=0, 4×u32=0)` (zero-SteamId bypass) -> `0x00 NMT_Hello(u32 MinNetVer=9189, u32 NetVer=10897, u32 IsLittleEndian=1)` -> `0x03 NMT_Challenge(u32, FString)` -> `0x04 NMT_Netspeed(u32)` + `0x05 NMT_Login(FString Response, FString URL, u64 UniqueId, u64 PortalId)` -> `0x01 NMT_Welcome(bare "Shootingrange_P", "TgGame.TgGame_Paladins_ShootingRange")` -> `0x09 NMT_Join()`. Server Channel 0 replies use `bOpen = false, bClose = false, bReliable = true`, 1-based `ChSequence`, piggyback `ACK(client_packet_id)`, suppress ACK-of-ACK storms on pure ACK packets, and hold Actor Channel (`ChIndex = 3`) traffic cleanly at `SessionPhase::Replicating` until `UNK-UDP-004` is resolved.
- **Evidence Reference**: `EV-BIN-001` (`0x140b37100` `ev_c5ac8b37...`, `0x140b36500` `ev_f2751ca2...`, `0x140b36ee0` `ev_fc255f3b...`, `0x140b4deb0` `ev_16b7bab4...`, `0x140b34be0` `ev_6a824879...`, `0x140da9f10` `ev_f845fdac...`, `0x140861d20` `ev_460eeaf4...`, `0x1401c1ce0` `ev_c53d0936...`, `0x1401d7650` `ev_c3b6bec9...`, `0x140b557f0` `ev_bd3ab810...`, `0x140b26e20` `ev_ab60abce...`, `0x140bba970` `ev_4057ff18...`, `0x140b533b0` `ev_c507048e...`, `0x140d4d700`), `EV-LOG-002` (Flight 034 live client UDP Packets 0..2), `EV-NET-002`, and `EV-LOG-003`.
- **Cleanroom Implementation**: `crates/immortal-net/src/bitstream.rs`, `crates/immortal-net/src/bunch.rs`, `crates/immortal-net/src/lib.rs`, `crates/immortal-server/src/game_server.rs`, `crates/immortal-server/src/replication.rs`.
- **Verification Gate**: `cargo test --all` (`test_golden_flight034_udp_bitstream_roundtrip`, `test_golden_server_handshake_packets_bit_parity`, `test_flight034_full_staged_udp_handshake_to_welcome_and_join`, `test_game_server_pcom_driver_loopback_integration`).
- **Status**: 🟢 Verified (Exit code 0).

### Claim 17: Dedicated Server Extended UDP 10-Byte Prefix, `NMT_Uses*` / `NMT_Have`, Opcode `0x2A`, and Channel 1 `UMarshalChannel` (`OBL-UDP-003`)
- **Behavioral Requirement**:
  1. Dedicated server `?exudp=2` datagrams begin with an outer 10-byte prefix (`[conn_id: u32 LE][seq: u32 LE][flags: u16 LE]`; `0x0010` for unsequenced handshake/PMTU frames of 570B/46B/1440B/46B, `0x0001` for Salsa20+AES-MAC encrypted gameplay frames). **Retraction Notice (`PSL-INV-012`, `#42`)**: The earlier `"Seq 1 6-byte session token synchronization barrier"` claim in `CAP03_FRAMING_INVESTIGATION_REPORT.md` is **retracted**. `CAP-03` Frame 14612 XOR Frame 14613 = `000000000000 05800450401161ae7e2b63bb` proves `CCryptopp::GenSession` (`0x1400dcac0`) initializes both TX and RX Salsa20 streams with the identical key and IV, producing identical keystream over the 6 zero bytes of `PComNetConn` at `seq = 1`.
  2. Unencrypted `?exudp=0` Retail Oracle probing (`EV-ORACLE-001`) and static analysis (`UACTOR_CHANNEL_WIRE_SPEC.md`) verify exact bit-level wire layouts for `0x07 NMT_Uses`, `0x2C NMT_UsesOpt`, `0x2D NMT_UsesOptEx`, `0x08 NMT_Have`, `0x2A NMT_MapLoaded`, and Channel 1 `UMarshalChannel` (`CHTYPE_Marshal = 5`, `0x27`), proving that `281 × NMT_Have` + `0x2A` + `0x09 NMT_Join` unlocks live actor replication while `UMarshalChannel` emits `0` bunches before/during join.
- **Evidence Reference**: `EV-NET-003` (`CAP-01`, 46,252 packets), `EV-NET-005` (`CAP-03`), `EV-LOG-004` (`CAP-01_Launch.log` lines 1400–1416), `EV-BIN-001` (`0x140b4deb0`, `0x140b35cf0`, `0x140b55f20`, `0x140d50310`, `0x1400dcac0`), `EV-ORACLE-001`, and `UACTOR_CHANNEL_WIRE_SPEC.md`. *(Correction: `CAP03_FRAMING_INVESTIGATION_REPORT.md` previously mislabeled S->C Seq 28 Frame 14659 as C->S `NMT_MapLoaded` and misattributed Salsa20 keystream reuse on Frames 14612/14613 to a Seq 1 session token barrier.)*
- **Cleanroom Implementation**: `crates/immortal-net/src/bunch.rs` (`PcomPrefix::Dedicated`, `ControlMessage` variants `0x07`, `0x08`, `0x27`, `0x29`, `0x2A`, `0x2B`, `0x2C`, `0x2D`), `crates/immortal-server/src/game_server.rs`, and `.agents/commands/lib/pcapng.py`.
- **Verification Gate**: `cargo test --all`, `UACTOR_CHANNEL_WIRE_SPEC.md` bit-exact Retail Oracle parity (`ch=3,4,5,12,13,80,81`), and Live Flight 036 end-to-end verification.
- **Status**: 🟡 Partial — **Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress** (remains open until Flight 036 succeeds).

### Claim 18: Dedicated Server Actor Channel Replication & Pawn Carving (`OBL-UDP-004`)
- **Behavioral Requirement**: Reconstruct and verify post-`NMT_Join` bit-packed `UActorChannel` (`ChIndex >= 3`, `CHTYPE_Actor = 2`) serialization (`UPackageMapLevel::SerializeObject` / `SerializeName`, `SerializeCompressedVector` with `BitsMinus1 = Bits - 1`, `SerializeCompressedRotator`, `FClassNetCache` `RepIndex` properties/RPCs without `bHasRepCondition`) for `TgPlayerController`, `TgRepInfo_Game`, `TgRepInfo_Player`, `MatineeActor`, and `TgPawn_*` (`TgPawn_Fernando` HP 4600, `TgPawn_Viktor` HP 2200, `TgPawn_Ying` HP 2200). **Historical Retraction Notice (`PSL-INV-012`)**: Earlier claims against encrypted `CAP-03` `?exudp=2` frames (`14612, 14639, 15141`) remain retracted (`0/45` encrypted `0x0001` frames decode; `UNK-CRYPTO-001` Mathematically Bounded / Archived), and `crates/immortal-server/src/replication.rs` remains a simulated byte-aligned prototype until Rust codec integration completes.
- **Evidence Reference**: `EV-BIN-001` (`0x140b33b30`, `0x140b379f0`, `0x140b569e0`, `0x1401a1ee0`, `0x1401a1dc0`, `0x140178630`, `0x140b297b0`), `EV-UPK-006` (`Engine.upk`: 23,294 Property + 5,250 Function exports), `EV-UPK-007` (`TgGame.upk`: 38,009 Property + 13,796 Function exports), `EV-ORACLE-001` (`oracle_probe_trace.json`: `ch=3` `3203/3203`, `ch=4` `2413/2413`, `ch=5` `160/160`, `ch=12` `2525/2525`, `ch=13` `2525/2525`, `ch=80` `318/318`, `ch=81` `1224/1224`, `0` leftover bits), and [`UACTOR_CHANNEL_WIRE_SPEC.md`](UACTOR_CHANNEL_WIRE_SPEC.md).
- **Cleanroom Implementation**: [`docs/specs/UACTOR_CHANNEL_WIRE_SPEC.md`](UACTOR_CHANNEL_WIRE_SPEC.md) (bit-exact wire specification); Rust `immortal-extract` / `immortal-net` / `immortal-server` integration in progress (`crates/immortal-server/src/replication.rs` still awaiting replacement).
- **Verification Gate**: `cargo test --all` + bit-exact `oracle_probe_trace.json` Rust parity + Live Flight 036 end-to-end 3D Shooting Range spawn verification.
- **Status**: 🟡 In Progress — **Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress** (do NOT mark closed until Flight 036 succeeds).

### Claim 19: Fernando Card Deck Allocations & In-Game Item Purchases (`OBL-PROP-001`)
- **Behavioral Requirement**: Deterministic bit-level extraction of `TgPlayerReplicationInfo::m_CardDeck` property replication and `TgPlayerController::ServerPurchaseItem` (`0x140e712c0`) RPCs from unencrypted UDP capture bunches (`CAP-04` unencrypted Oracle blind-test matrix). **Retraction Notice (`PSL-INV-012`)**: Prior verification against `CAP-03` remains retracted: `crates/immortal-net/examples/extract_deck_items.rs` performs **log-correlation only** against `CAP-03_custom_baseline_20261119_Launch.log` (`EV-LOG-006`) over encrypted `?exudp=2` frames (`UNK-CRYPTO-001` **Mathematically Bounded / Archived** — unrecoverable offline). Unencrypted extraction is now unblocked via `?exudp=0` Retail Oracle (`ADOPT-09`) + `UACTOR_CHANNEL_WIRE_SPEC.md`, pending Rust integration and Live Flight 036 / `CAP-04`.
- **Evidence Reference**: `EV-LOG-006` (`CAP-03_Launch.log` log lines only), `EV-NET-005` (archived encrypted `?exudp=2` frames `17205, 19115, 19117, 46685`), `EV-BIN-001` (`0x1415caaf0`, `0x140e75ab0`, `0x140e712c0`), and [`UACTOR_CHANNEL_WIRE_SPEC.md`](UACTOR_CHANNEL_WIRE_SPEC.md).
- **Cleanroom Implementation**: `crates/immortal-net/examples/extract_deck_items.rs` (legacy log-correlation report; real bitstream decoder pending Rust `ActorBunchCodec` integration).
- **Verification Gate**: Real bitstream decoder executing on unencrypted `?exudp=0` Retail Oracle / `CAP-04` unencrypted Oracle blind-test matrix captures.
- **Status**: 🔴 Open (Unblocked on `?exudp=0` Oracle + `UACTOR_CHANNEL_WIRE_SPEC.md`; awaiting Rust codec integration, Live Flight 036, and `CAP-04` unencrypted Oracle matrix).

---

## 3. Residual Unknowns Ledger

| Unknown ID | Description | Impact | Required Authority | Resolution Criteria |
| :--- | :--- | :--- | :--- | :--- |
| `UNK-MCTS-001` | Structure of MCTS "hello" packet expected by `0x14002eec0` | Client rejects handshake Chunk 1 and times out after 15s | Decompiled pseudocode of `0x14002eec0` | Exact field layout, function ID, and magic framing identified from Ghidra |
| `UNK-MCTS-002` | MCTS Function hash map for catalog rowsets & generic 4-cache batching (`ADOPT-10`/`ADOPT-11`) | Required to replace hardcoded handshake frames with generic 32-bit FNV-1 dispatch | Ghidra MSVC RTTI and marshal dispatch table | Symbol table cross-reference linking 32-bit FNV-1 hashes to C++ handlers |
| `UNK-UDP-001` | Non-zero bytes in live `PComNetConn` UDP header `data[1..6]` observed on port `7777` in Flight 033 | RESOLVED by Claim 15 | REA Disassembly (`0x140bc8770`) & Flight 033/034 captures | Closed: Outer 6-byte prefix stored in `ClientSession::pcom_prefix` and echoed on outbound datagrams. |
| `UNK-UDP-002` | UE3 bit-packed `FInBunch`/`Ue3Packet` wire layout, `NMT_*` opcodes, and Paladins pre-Hello staged UDP 7777 handshake | RESOLVED by Claim 16 | REA analysis (`EV-BIN-001`) + Flight 034 live client captures (`EV-LOG-002`) | Closed: Bit-exact codec, signed `%d` CRC, 2x `u64` `NMT_Login`, bare `NMT_Welcome`, and full 7-stage handshake verified against Flight 034 Packets 0..2. |
| `UNK-UDP-005` | Runtime configuration of `UPComNetDriver + 0x240` (`MaxPacket` = `0x240` / `576` B vs `0x1F0` / `496` B) | RESOLVED by Claim 16 | `UPComNetDriver::CreateSocket` (`0x140d4d700`) + `UTcpipConnection::InitConnection` (`0x140bba970`) + Flight 034 Packet 0 (`EV-LOG-002`) | Closed: `0x1F0` (`496` B = `3968` bits) is enabled exclusively when `?exudp>=1`; standard UDP uses `0x240` (`576` B = `4608` bits), empirically locked by Flight 034 Packet 0. |
| `UNK-UDP-003` | Post-`NMT_Join` `NMT_Uses*` (`0x07`/`0x2C`/`0x2D`), `NMT_Have` (`0x08`), `0x2A`, and Channel 1 `UMarshalChannel` (`CHTYPE_Marshal = 5`, `0x27`) | **🟡 Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress** | `UACTOR_CHANNEL_WIRE_SPEC.md` + `EV-ORACLE-001` + `crates/immortal-net` / `immortal-server` + Flight 036 | Land Rust `0x07`/`0x08`/`0x27`/`0x2C`/`0x2D`/`0x2A` integration in `immortal-net`/`immortal-server` and pass Live Flight 036 end-to-end. |
| `UNK-UDP-004` | Post-`NMT_Join` bit-packed Actor Channel (`ChIndex >= 3`, `CHTYPE_Actor = 2`) replication layout for `TgPlayerController`, `TgPawn_*`, and `replication.rs` replacement | **🟡 Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress** | `UACTOR_CHANNEL_WIRE_SPEC.md` + `EV-UPK-006`/`007` + `EV-ORACLE-001` + Flight 036 | Replace simulated `replication.rs` with bit-exact Rust `FClassNetCache` / `UActorChannel` codec and verify live 3D Shooting Range spawn in Flight 036. |
| `UNK-PROP-001` | Dynamic property bunch & client RPC extraction for item purchases and card deck allocations (`CAP-04` unencrypted Oracle blind-test matrix) | **Open (`🔴`)**: Unblocked by `?exudp=0` Oracle & `UACTOR_CHANNEL_WIRE_SPEC.md`; awaiting Rust codec integration (`CAP-03` encrypted frames unrecoverable offline) | `UACTOR_CHANNEL_WIRE_SPEC.md` + `ADOPT-09` `?exudp=0` Retail Oracle + `UNK-UDP-004` Rust codec | Deterministic bit-level decoding of `TgPlayerReplicationInfo::m_CardDeck` and `ServerPurchaseItem` from unencrypted Oracle / `CAP-04` UDP bunches. |
| `UNK-CRYPTO-001` | `?exudp=2` dedicated UDP cipher (`RFC 5114` 2048-bit ephemeral DH + identical TX/RX `Salsa20` + 16B `AES-MAC`) | **Mathematically Bounded / Archived** (`#42`, `exudp2_crypto_re_report.md`): Offline decryption of `CAP-01`/`CAP-03` is mathematically impossible without runtime key capture or Hi-Rez private DH key (`CAP-03` Frame 14612 XOR Frame 14613 = `000000000000...` proves TX/RX Salsa20 keystream reuse over 6 zero bytes of `PComNetConn`, retracting the Seq 1 token barrier claim) | `EV-BIN-001` (`0x1400dc160..0x1400e0260`) + `EV-NET-005` (Archived) | **Superseded** by plaintext `?exudp=0` + `ADOPT-09` local Retail Oracle (only runtime hook of `CCryptopp::GenSession` `0x1400dcac0` can log live `?exudp=2` keys if ever needed). |
