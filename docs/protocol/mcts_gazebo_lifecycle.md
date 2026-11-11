<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->
<!-- Invariant: PSL-INV-007 (Universal Cleanroom Reverse Engineering Standard) -->

# MCTS Gazebo State Machine Lifecycle & ChangeMap Protocol Specification

> **Evidence Authority**: Shipped binaries `ShippingPC-ChaosGame.exe` (SHA-256: `0c51d381...`), `MctsInterface.dll` (SHA-256: `90ce02b7...`), client execution logs `Binaries/Logs/Launch.log`, and REA decompilation traces (`ev_cbe0ba5ad...`, `ev_9fae...`).

---

## 1. Executive Summary & Purpose

In Project Immortal's cleanroom architecture, the **Gazebo** state machine controls character selection, lobby lock-in, and handoff to dedicated map instances. Analysis of Flight 021 revealed an immediate client logoff/disconnect upon receiving frame `0xe621824e` post-Gazebo. Cleanroom reverse engineering identified that:

1. **`0xe621824e` is an explicit client disconnect routine** when Gazebo is active (`ShippingPC-ChaosGame.exe: FUN_140d39e50` line 85).
2. **`0x847de68b` is the authentic `ChangeMap` RPC** (`MctsInterface.dll: ProcessMarshal` at `0x1800db730` -> `FUN_1800da6e0`).
3. Advancing the Unreal client `UTgMatchLobby` state machine requires precise delta transitions across `MATCH_STATUS` (State 8 -> State 10).

---

## 2. Gazebo State Machine Transition Sequence

`UTgMatchLobby` and `CMctsMatchMaking` evaluate state transitions through incoming `MATCH_STATUS` (Function ID `0x392dcda5`) packets. The transition from Champion Selection to Map Launch follows an exact two-stage sequence:

### 2.1 State 8: Champion Selection / Gazebo Staging
- **Match Lobby State (`Token 1342`)**: `8` (`MATCH_LOBBY_STATE_SELECTING`)
- **Player Lobby State (`Token 1344`)**: `0` (`PLAYER_LOBBY_STATE_UNLOCKED`)
- **Queue ID (`Token 703`)**: `0` (Reset queue ID to force change-detection in subsequent states)
- **Launch Seconds (`Token 1690`)**: `30` (30-second countdown for champion pick)
- **Player Queue State (`Token 2191`)**: `4` (`MQ_ACCEPTED`)
- **Client Behavior**:
  - `TgClient::SetLobbyState 2 -> 3` (enters Gazebo scene).
  - Displays champion grid and countdown timer.
  - Keeps friendly slots open for member lock-in.

### 2.2 State 10: Match Finalized / Launching
- **Match Lobby State (`Token 1342`)**: `10` (`MATCH_LOBBY_STATE_LAUNCHING`)
- **Player Lobby State (`Token 1344`)**: `5` (`PLAYER_LOBBY_STATE_LOCKED`)
- **Queue ID (`Token 703`)**: `434` (Transitions from `0` in state 8 to `434` in state 10 specifically so `UTgMatchLobby` breaks its cache, executes `FindQueueById(434)`, and copies `QueueEntry[434].QueueState` into `[UTgMatchLobby + 0x1d8]`)
- **Launch Seconds (`Token 1690`)**: `0` (Countdown elapsed)
- **Player Queue State (`Token 2191`)**: `7` (`MQ_LAUNCHING`)
- **Client Behavior & Launch Gate Verification**:
  - The transition of `PlayerLobbyState` from `0` to `5` satisfies the launch gate condition:
    $$\text{PlayerLobbyState}_{\text{OLD}} < 1 \quad \land \quad \text{PlayerLobbyState}_{\text{NEW}} > 0 \quad \land \quad \text{MatchLobbyState} \neq 1$$
  - Fires UnrealScript `AUTOPICK` event (`0x3af7`).
  - **`QueueState 7` Map Session Descriptor Arming Gate (`FUN_140d39e50` at `0x140d39f0d`..`0x140d39f1b`)**:
    When `MATCH_STATUS` (Function ID `0x392dcda5`) is processed, `FUN_140d39e50` reads `UTgMatchLobby->QueueState` at offset `+0x1d8`. It evaluates:
    $$(\text{QueueState} - 7) \ \& \ \sim 2 == 0 \iff \text{QueueState} \in \{7, 9\}$$
    If `QueueState` is not 7 (`MQ_LAUNCHING`) or 9, the handler immediately branches to bailout (`0x140d3a1ed`), silently dropping the assignment of map session descriptors at `[this + 0x874]` and `[this + 0x88c]`.
  - **Token 1646 Wire Mechanism via `OnQueryServers` (`0xaf434825`)**:
    Decompiler analysis (`ShippingPC-ChaosGame.exe` & `MctsInterface.dll`, RCA `MISSION-2026-IMMORTAL-RCA-QUEUE-STATE-001`) reveals:
    1. `MATCH_STATUS` (0x392dcda5) never writes `QueueState` directly (Token 2191 is unparsed into lobby state).
    2. `QUEUE_STATUS` (0x2cdbafe1) only updates Token 36 and 912 in `FUN_1400e7500`, discarding Token 1646.
    3. Token 1646 (`MCTS_TOKEN_QUEUE_STATE`, `0x066e`) is parsed **EXCLUSIVELY** by `FUN_1400e5c50` under `OnQueryServers` (`0xaf434825` / `MCTS_FUNCTION_ID_QUERY_SERVERS`), which updates `QueueEntry[queue_id].QueueState = token_value`.
    4. Therefore, prior to dispatching State 10 `MATCH_STATUS`, the auth gateway MUST emit `OnQueryServers` (`0xaf434825`) with Token 1646 = 7 to prime `QueueEntry[434].QueueState = 7` in client memory.
    5. When `MATCH_STATUS` state 10 arrives with `queue_id = 434`, `UTgMatchLobby` breaks its cache check, calls `FindQueueById(434)` (`FUN_1800f4169`), and copies `QueueEntry[434].QueueState` (now 7!) into `[UTgMatchLobby + 0x1d8]`, satisfying the gate `0x140d39f1b` and arming the session descriptors for map travel.

---

## 3. Change Detection Mechanics in `UTgMatchLobby` and `MctsInterface.dll`

1. **`CMctsMatchMaking::OnQueryServers` (`FUN_1400e5c50`)**:
   - Parses Table 242 and extracts Token 1646 (`MCTS_TOKEN_QUEUE_STATE`), committing the value into `QueueEntry[queue_id].QueueState`.
2. **`CMctsMatchMaking::OnMatchStatus` (`FUN_1800f5390`)**:
   - Compares incoming `MATCH_STATUS` tokens against cached session values.
   - When `QueueId` transitions (`0 -> 434`), `FindQueueById(434)` retrieves the registered queue and synchronizes its `QueueEntry[434].QueueState` into `[UTgMatchLobby + 0x1d8]`.
3. **`UTgMatchLobby::Tick` (`0x1400d2560`)**:
   - In each tick, evaluates whether `QueueState == 7` and `MatchLobbyState == 10`.
   - When verified, terminates UI input processing and transitions the engine toward map travel.
4. **Map Session Descriptors**:
   - When `QueueState == 7`, `FUN_140d39e50` loads session tokens from session manager `[+0x480]` and stores them at `[rbx + 0x874]` and `[rbx + 0x88c]`.
   - Downstream `ReceiveChangeMap` (`0x141576a00`) requires these descriptors to initialize the transition manifest and execute map travel (`Browse: Shootingrange_P`).

---

## 4. RPC Wire Layout: `0x847de68b` (ChangeMap) vs `0x4bee2ed8` (LaunchMapInstance)

### 4.1 Function ID `0x847de68b` (`ChangeMap`)
- **Role**: Directs client to change map context to target game mode without triggering session teardown.
- **Processing Handler**: `MctsInterface.dll: FUN_1800da6e0` (dispatched from `0x1800db730`).
- **Framing**: TCP 4-byte header `[length: u16, flags: 0x0000]`.
- **Payload Layout (32 bytes)**:
  - Byte 0: `0x00` (`this[0x30]`)
  - Bytes 1..4: `0x847de68b` (Wire LE: `[0x8b, 0xe6, 0x7d, 0x84]`)
  - Bytes 5..6: Total fields count = `3` (`[0x03, 0x00]`)
  - **Group 0x1000** (1 field, header `0x1001`):
    - Token 1536 (`0x0600`, `MCTS_TOKEN_COMPEL_FLAG`): `0x01` (`true`, forces immediate engine map transition)
  - **Group 0x3000** (1 field, header `0x3001`):
    - Token 682 (`0x02aa`, `MCTS_TOKEN_MAP_GAME_ID`): `1615` (Shooting Range, `[0x4f, 0x06, 0x00, 0x00]`)
  - **Group 0x4000** (1 field, header `0x4001`):
    - Token 685 (`0x02ad`, `MCTS_TOKEN_MAP_INSTANCE_ID`): `1282927737` (`[0x79, 0xfc, 0x77, 0x4c, 0x00, 0x00, 0x00, 0x00]`)

### 4.2 Function ID `0x4bee2ed8` (`LaunchMapInstance`)
- **Role**: Communicates the game server host IP, UDP port (7777), match ID, and connection timeout to the client.
- **Payload Layout (60 bytes)**:
  - Byte 0: `0x00`
  - Bytes 1..4: `0x4bee2ed8` (Wire LE: `[0xd8, 0x2e, 0xee, 0x4b]`)
  - Bytes 5..6: Total fields count = `5` (`[0x05, 0x00]`)
  - **Group 0x3000** (2 fields, header `0x3002`):
    - Token 721 (`queue_id`): `434`
    - Token 1839 (`timeout_secs`): `60`
  - **Group 0x4000** (3 fields, header `0x4003`):
    - Token 25 (`instance_id`): `0`
    - Token 700 (`match_id`): `878850364`
    - Token 877 (`sockaddr_in`): 8-byte sockaddr structure (`[0x02, 0x00, port_high, port_low, ip0, ip1, ip2, ip3]`)

---

## 5. Disconnect Mechanism of `0xe621824e`

In Flight 021, the gateway emitted `0xe621824e` immediately following `match_status_10`, resulting in:
```text
[0037.40] Log: VoiceChat: Player Logoff so disconnecting
[0037.40] Log: TgClient: SetLobbyState 3 -> 1
```

Cleanroom decompiler analysis of `ShippingPC-ChaosGame.exe: FUN_140d39e50` (line 85) revealed:
- Function `FUN_140d38030()` queries active lobby context.
- When an active Gazebo session is running, `FUN_140d38030()` evaluates non-zero.
- In this branch, function `0xe621824e` invokes the virtual method at offset `+0xe8` on the client interface:
  $$\text{call } (*param_1 + 0xe8)()$$
- This virtual call initiates an immediate clean logoff and connection teardown.
- In non-lobby/standalone contexts (`FUN_140d38030() == 0`), `0xe621824e` routed to map loading (`FUN_140d42f60`). However, during active Gazebo match states, dispatching `0xe621824e` is functionally a terminate/kick command.
- Replacing `0xe621824e` with `0x847de68b` allows the client to transition seamlessly into map travel without aborting the session.

---

## 6. Map Instance Assignment (`0x15c61937`), Match Composition Cache & Flight 033 Verification

### 6.1 Function ID `0x15c61937` (`MAP_INSTANCE_ASSIGNED`) & Static-Link SDK Boundary
Cleanroom runtime and binary verification established that `ShippingPC-ChaosGame.exe` statically links the MCTS client SDK (it does **not** import `MctsInterface.dll` at runtime). After `MATCH_STATUS` State 10 arms the lobby descriptors, the client expects **`0x15c61937`** (`MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED`, implemented in `create_mcts_match_composition_frame`) to populate map routing and match composition state before/alongside `LaunchMapInstance` (`0x4bee2ed8`) and `ChangeMap` (`0x847de68b`):

- **Group `0x3000` (1 field, header `0x3001`)**:
  - **Token `682` (`MCTS_TOKEN_MAP_GAME_ID`)**: `1615` (`Shootingrange_P`).
- **Group `0x4000` (2 fields, header `0x4002`)**:
  - **Token `588` (`MCTS_TOKEN_MAP_HOST_NET_ADDR`)**: 8-byte `sockaddr_in` pointing to `127.0.0.1:7777`.
  - **Token `685` (`MCTS_TOKEN_MAP_INSTANCE_ID`)**: `1282927737` (`u64`).
- **Group `0x6000` (1 table, header `0x6001`) — Table `1583` (`DATA_SET_MATCH_COMPOSITION`)**:
  - Populates the client's local match composition cache (`Token 122` `BOT_ID`, `Token 1092` `TASK_FORCE = 1`, `Token 11` `PLAYER_ID`, `Token 700` `MATCH_ID`, `Token 703` `MATCH_QUEUE_ID`).
- **Group `0xa000` (1 string, header `0xa001`)**:
  - **Token `2287` (`MCTS_TOKEN_PORTAL_SESSION_ID`)**: Portal session identifier string (max `0x50` bytes).
- **Mandatory Bail-Out Exclusions**:
  - Omit Token `1116` (or set to `0`), omit Token `2838`, and omit offline server status flags `{15413, 15500, 15415}` in Token `2637` so the client does not abort map travel or mark the instance server offline.

### 6.2 `0x07FE` (`2046`-Byte) Post-Login Chunk Framing
Live Flight 032/033 client streams confirmed that once login completes, incoming client TCP frames carrying `field0 == 0` in their 4-byte framing header (for example `[00, 00, 08, 01]`) denote a full **`0x07FE` (`2046`-byte)** payload chunk rather than a zero-length payload. The TCP gateway (`crates/immortal-net/src/gateway.rs`) reads `MAX_PAYLOAD_LEN` (`2046`) bytes on `field0 == 0` to keep the MCTS stream aligned through champion selection and map transition.

### 6.3 Flight 033 Verified Milestones & Residual Blocker (`UNK-UDP-001`)
Live retail client execution in Flight 033 verified the entire MCTS-to-travel pipeline:
1. **`Match composition cached [96E3D70]`**: Client accepted `0x15c61937` with Table `1583` and Token `2287`.
2. **`ReceiveChangeMap: mapGameId 1615`**: Client processed `ChangeMap` and resolved `Shootingrange_P`.
3. **UDP `7777` Datagram Arrival**: Client opened its UDP socket and transmitted live datagrams to port `7777`.
4. **Current Blocker (`UNK-UDP-001`)**: Live client datagrams on UDP `7777` carry non-zero bytes in `data[1..6]` (e.g., `[00, 8a, ce, 31, c6, f6, 00, 80, ...]`) instead of the `[0; 5]` zero prefix previously assumed, causing the server driver to skip `NMT_Welcome` dispatch and leaving the client browsing `0.0.0.0:7777/LobbyMapV4_P?...`. Resolving `UNK-UDP-001` is the immediate gate to `BROWSE_RANGE` and Milestone 4.

