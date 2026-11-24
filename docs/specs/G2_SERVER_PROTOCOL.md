<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# G2 Specification: Cleanroom Auth Handshake & UE3 Bunch Protocol

> **Evidence Authority**: Shipped binaries `ShippingPC-ChaosGame.exe` (SHA-256: `81cf...`), `MctsInterface.dll` (SHA-256: `90ce02b7b82012ffd564e426d9b4e84d189c998dc4e6018efb9ad7e506a79a33`), client logs `Binaries/Logs/MCTS-*.log`, and REA decompilation traces (`ev_ae51...`, `ev_9fae...`, `ev_e5b2...`, `ev_771e...`, `ev_f143...`).

---

## 1. Network Topology & Port Allocations

Paladins multiplayer networking operates across two distinct protocol layers:

```text
[ Paladins Client ]
       │
       ├─ (1) Discovery & Auth Gateway (TCP / Port 9000)
       │       Target: 127.0.0.1:9000 (Emulated Gateway)
       │       Protocol: CPackCoder Framing (0xCBB0 / 0xCBBC) + CMarshal RPC
       │       Payload: Session Token, Player GUID, Account ID, Match Routing Ticket
       │
       └─ (2) Game Server Connection (UDP / Port 7777)
               Target: 127.0.0.1:7777 (Emulated Game Server)
               Protocol: CPackUdp Driver + UE3 UNetConnection Bit-Packed Bunches
               Payload: Channel 0 Control Handshake, Fernando Actor Replication
```

---

## 2. Developer Client CLI Bypasses & Overrides

The shipped game binary (`ShippingPC-ChaosGame.exe`) includes native command-line switches allowing direct backend redirection without requiring hosts file modification, TLS proxy certificates, or DLL hooking:

| Parameter | Function | Cleanroom Preservation Target |
| :--- | :--- | :--- |
| `-host=<IP>` | Overrides MCTS Gateway Host IP | `-host=127.0.0.1` |
| `-tcp=<Port>` | Overrides MCTS Gateway TCP Port | `-tcp=9000` |
| `-servicediscoveryhost=<Host>` | Overrides discovery server hostname | `-servicediscoveryhost=127.0.0.1:9000` |
| `-servicediscoveryurl=<URL>` | Overrides service discovery endpoint URL | `-servicediscoveryurl=http://127.0.0.1:9000/Discovery` |
| `-dumpmar` / `-dumpallmar` | Instructs engine to dump all marshal messages to client log | Enabled for local protocol forensics |
| `-pguid=<GUID>` | Sets client player GUID | Optional override |
| `-nosteam` / `-nomovie` | Bypasses Steam client requirement and intro cinematics | Enabled for hermetic local testing |

---

## 3. Layer 1: MCTS TCP Framing (`CPackCoder`)

All TCP traffic to port `9000` is packaged into structured transmission frames managed by `CPackCoder`:

### 3.1 Wire Framing Header Layout
Every packet frame begins with a 4-byte header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic Token          |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Data ...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Type | Expected Value | Description |
| :--- | :--- | :--- | :--- |
| `Magic Token` | `uint16` (LE) | `0xCBB0` or `0xCBBC` | `0xCBB0`: Payload is compressed using Zlib Deflate.<br/>`0xCBBC`: Payload is raw uncompressed bytes. |
| `Payload Length` | `uint16` (LE) | `0x0001`–`0x07FE` | Length in bytes of the following payload data (max 2,046 bytes per chunk). |
| `Payload Data` | `[u8]` | Variable | The serialized `CMarshal` package body. |

### 3.2 Post-Login `0x07FE` (`2046`-Byte) Chunk Framing
After login completes on TCP port `9000`, live client captures (`Flight 032/033`) show a distinct post-login wire framing convention where the 4-byte header has `field0 == 0` (for example `[00, 00, 08, 01]`). In this post-login state, `field0 == 0` encodes a full **`0x07FE` (`2046`-byte, `MAX_PAYLOAD_LEN`)** chunk payload rather than an empty frame, and the gateway (`crates/immortal-net/src/gateway.rs`) consumes `2046` payload bytes before parsing subsequent frames.

---

## 4. Layer 2: RPC Serialization (`CMarshal`)

Inside each `CPackage` payload, high-level game operations are serialized as `CMarshal` rows:

### 4.1 Message Header
- `FunctionId`: `uint32` (LE) at offset `+0x34` identifying the RPC method.
- `RowCount`: `uint32` (LE) number of serialized entries.

### 4.2 Key Token Definitions (`MFIELD_ENTRY`)
Fields are identified by 16-bit token IDs:

| Token ID | Token Name | Type Identifier | Description |
| :---: | :--- | :--- | :--- |
| `0x1A` (26) | `Status` | Integer (`0x5`) | Result code (`0` = Success). |
| `7` | `SessionToken` | WChar String (`0xC`) | Cryptographic session authorization string. |
| `10` | `AccountId` | Integer (`0x5`) | Unique player account identifier. |
| `100` | `ChampionRoster` | RowSet / Blob (`0xA`) | List of unlocked champions (`ChampionId`, `bOwned: bool`, e.g. Fernando `1026`). Populates `UIHudChampionSelect`. |
| `102` | `WeaponDevices` | RowSet / Blob (`0xA`) | Weapon and ability device inventory (`Device 10774` Flame Lance). |
| `105` | `DeckLoadouts` | RowSet / Blob (`0xA`) | Custom and default card loadouts (`Deck 16379` Fernando Starter Deck). |
| `500` | `MatchTicket` | RowSet / Blob (`0xA`) | Dedicated server IP, port, and authentication ticket routing to `127.0.0.1:7777`. |

### 4.3 MCTS Inventory Rowset Schema & Scaleform Dependencies
Empirical ground truth from packet captures (`pcaps/paladins_live_session.pcap`, `pcaps/mcts_stream_6761.raw`) demonstrates that the Scaleform Flash UI (`UIHudChampionSelect`, `UIStoreDetail`) renders blank grids if inventory rowsets are omitted during the login sequence. MCTS delivers inventory tables comprising:
- **Token 100 (`ChampionRoster`)**: Unlocked champion identifiers and ownership flags (`bOwned: bool`).
- **Token 102 (`WeaponDevices`)**: Active weapon devices (including Device `10774` Fernando Flame Lance).
- **Token 105 (`DeckLoadouts`)**: Available card loadouts and decks (including Deck `16379` Fernando Starter).

### 4.4 Login Handshake Sequence
1. **Client -> Server (`SendLogin`)**:
   - Client establishes TCP stream to `127.0.0.1:9000`.
   - Sends framing `0xCBBC` / `0xCBB0` containing Login Parameters (platform token, client version `8.1.5839.0`, language, EULA acceptance).
2. **Server -> Client (`OnLoginResponse`)**:
   - Server validates version and responds with `FunctionId` Login Reply.
   - Sets Token `0x1A = 0` (Success).
   - Sets Token `10 = 10001` (Mock Account ID).
   - Sets Token `7 = "IMMORTAL-DEV-SESSION-TICKET"`.
   - Populates Tokens `100`, `102`, and `105` with baseline Fernando unlocked inventory.
   - Sets Token `500 = MatchTicket` pointing to `127.0.0.1:7777`.

### 4.5 Map Instance Assignment (`0x15c61937` / `MAP_INSTANCE_ASSIGNED`) & Static-Link SDK Boundary
Runtime and binary analysis confirmed that `ShippingPC-ChaosGame.exe` statically links the MCTS client SDK and does **not** import `MctsInterface.dll` at runtime. During Gazebo-to-match transition, the gateway dispatches Function ID **`0x15c61937`** (`MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED` via `create_mcts_match_composition_frame` in `crates/immortal-net/src/mcts_handshake.rs`):

- **Group `0x3000` (`0x3001`)**: Token **`682`** (`MAP_GAME_ID` = `1615`, `Shootingrange_P`).
- **Group `0x4000` (`0x4002`)**:
  - Token **`588`** (`HOST_NET_ADDR`): 8-byte `sockaddr_in` pointing to `127.0.0.1:7777`.
  - Token **`685`** (`MAP_INSTANCE_ID`): `1282927737` (`u64`).
- **Group `0x6000` (`0x6001`) — Table `1583` (`DATA_SET_MATCH_COMPOSITION`)**: Populates the client's local match composition cache (Token `122` `BOT_ID`, Token `1092` `TASK_FORCE = 1`, Token `11` `PLAYER_ID`, Token `700` `MATCH_ID`, Token `703` `MATCH_QUEUE_ID`).
- **Group `0xa000` (`0xa001`)**: Token **`2287`** (`PORTAL_SESSION_ID`), UTF-8 portal session string (`<= 0x50` bytes).
- **Mandatory Bail-Out Exclusions**: Omit (or keep `0`) Token `1116`, omit Token `2838`, and omit offline status codes `{15413, 15500, 15415}` in Token `2637` so the client caches match composition (`Match composition cached [96E3D70]`) and commits `ReceiveChangeMap: mapGameId 1615`.

---

## 5. Layer 3: UDP Session & Wire Envelope (`CPackUdp` / `PComNetConn`)

Once authenticated via TCP port 9000, the client connects to the match server on UDP port `7777`.

### 5.1 UE3 `PComNetConn` UDP Datagram Wire Format (Port 7777)

Forensic binary analysis (`EV-BIN-001`) and live Flight 034 Paladins 8.1.5839.0 client captures (`EV-LOG-002`) establish the exact 3-layer `PComNetConn` + UE3 `UNetConnection` LSB-first bitstream wire format (`Claim 16` / `OBL-UDP-002`):

```text
Layer 0 — 6-Byte PComNetConn Outer Prefix (UPComNetConn::ReceivedRawPacket, 0x140bc8770):
  Bytes [0..6]:
    Client -> Server: [0x00, monotonic_conn_byte, be32(player_id_lo32 ^ session_cookie)]
    Server -> Client: [0x00; 6] or echoed 6-byte client pcom_prefix (stripped unconditionally on RX)
  Bytes [6..N]: UE3RawPacket passed directly to UNetConnection::ReceivedRawPacket (0x140b37100)

Layer 1 — Trailing Stop-Bit Framing (0x140b37100 / 0x140b29400):
  - Reject if UE3RawPacket is empty or UE3RawPacket[last] == 0x00.
  - Highest set '1' bit in UE3RawPacket[last] terminates the bitstream; exact payload bit length is:
      BitSize = UE3RawPacket.len() * 8 - 1 - leading_zeros(UE3RawPacket[last])
  - On TX: append a single '1' stop bit and zero-pad to the next byte boundary.

Layer 2 — LSB-First UNetConnection Bitstream (0x140b36500 / 0x140b3c2f0 / 0x140b3b690):
  - Optional 3-byte packet header disabled in standard Paladins sessions (bUsePacketHeader = 0).
  - PacketId: 14-bit unsigned integer (SerializeInt(MAX_PACKETID = 0x4000)); 0-based on server TX.
  - Repeated records until BitReader reaches BitSize:
      1. IsAck (1 bit):
         - If IsAck == 1: AckPacketId (14 bits, SerializeInt(0x4000)).
         - If IsAck == 0 (FInBunch):
             * bControl (1 bit): 1 iff bOpen || bClose; if 1, followed by bOpen (1 bit) and bClose (1 bit).
             * bReliable (1 bit).
             * ChIndex (11 bits, SerializeInt(MAX_CHANNELS = 0x800)).
             * ChSequence (10 bits, SerializeInt(MAX_CHSEQUENCE = 0x400), present iff bReliable == 1; 1-based).
             * ChType (3 bits, SerializeInt(CHTYPE_MAX = 8), present iff bReliable == 1 || bOpen == 1).
             * BunchDataBits (variable width, SerializeInt(MAX_PACKET_BITS)):
                 - Standard UDP (?exudp=0 / omitted): MaxPacket = 0x240 (576 B = 4608 bits)
                   -> 13 bits when BunchDataBits < 512 (or >= 4096); 12 bits when 512 <= BunchDataBits < 4096.
                 - Extended UDP (?exudp>=1): MaxPacket = 0x1F0 (496 B = 3968 bits).
             * BunchPayload: BunchDataBits raw LSB-first bits.
```

| Constant | Value | SerializeInt Width | Engine Authority |
| :--- | :---: | :--- | :--- |
| `PCOM_PREFIX_LEN` | `6` bytes | Fixed raw bytes | `UPComNetConn::ReceivedRawPacket` (`0x140bc8770`) |
| `MAX_PACKETID` | `0x4000` (`16384`) | 14 bits | `UNetConnection::ReceivedPacket` (`0x140b36500`) |
| `MAX_CHANNELS` | `0x800` (`2048`) | 11 bits | `UNetConnection::CreateChannel` (`0x140b25e90`) |
| `MAX_CHSEQUENCE` | `0x400` (`1024`) | 10 bits (1-based reliable) | `UChannel::ReceivedRawBunch` (`0x140b36ee0`) |
| `CHTYPE_MAX` | `8` | 3 bits (`1=Control, 2=Actor, 3=File, 4=Voice, 5=Marshal`) | `UChannel::ChannelClasses` (`0x143d27a30`) |
| `DEFAULT_MAX_PACKET_BITS` | `4608` (`576` B) | 13 bits (`<512`) / 12 bits (`>=512`) | `UTcpipConnection::InitConnection` (`0x140bba970`) |
| `EXUDP_MAX_PACKET_BITS` | `3968` (`496` B) | Variable (`?exudp>=1` only) | `UPComNetDriver::CreateSocket` (`0x140d4d700`) |

> **Engine Invariant (`Claim 15` & `Claim 16`)**: `UPComNetConn::ReceivedRawPacket` (`0x140bc8770`) unconditionally drops datagrams shorter than 6 bytes and strips the leading 6-byte prefix before handing the remainder directly to `UNetConnection::ReceivedRawPacket` (`0x140b37100`). Outbound server datagrams echo the client's 6-byte `pcom_prefix`, piggyback `ACK(client_packet_id)`, and suppress ACK-of-ACK storms on pure ACK datagrams.

### 5.2 CPackUdp Datagram Envelope (Legacy / Crypto Dispatch)

```text
+-----------------------+--------------------------------------------------------+
| Byte Offset           | Field Description                                      |
+-----------------------+--------------------------------------------------------+
| 0x00 - 0x1D (28 B)    | UDP Transport & Internal Dispatch Metadata / Link Hdr  |
| 0x1E - 0x1F (2 B)     | uint16 Packet Length (Little Endian)                   |
| 0x20 - 0x21 (2 B)     | uint16 Key ID / Crypto Session Token                   |
| 0x22 - 0x27 (6 B)     | Sequence / Timestamp / Connection Flag Padding         |
| 0x28 - 0x2F (8 B)     | uint64 Peer ID / Remote Address Representation         |
| 0x30 - 0x37 (8 B)     | Connection Session Pointer / Context Handle            |
| 0x38 - 0x59 (34 B)    | Peer Address & TG Authentication Descriptor (CTgNetId) |
| 0x5A - 0x5D (4 B)     | int32 Packet Function / Type ID (0 = Hello)            |
| 0x5E - 0x65 (8 B)     | Handshake Session Parameters                           |
| 0x66 - 0x265 (512 B)  | fcAllocCrypto Session Key Exchange Payload             |
| 0x266 - 0x269 (4 B)   | int32 SHA-256 Digest Length (= 0x20 / 32 bytes)        |
| 0x26A - 0x289 (32 B)  | SHA-256 HMAC / Digest (computed over 0x5A..0x265)      |
+-----------------------+--------------------------------------------------------+
```

### 5.3 Handshake Validation & State Transitions
1. **Hello Gate (`DoHello`, 0x18004c3f0)**:
   - Evaluates `*(ushort *)(packet + 0x1e) >= 0x23a` (570 bytes minimum length).
   - Validates `*(int *)(packet + 0x5a) == 0` (`HelloSend`).
   - Authenticates SHA-256 HMAC over 524 bytes (`0x20c`) from `packet + 0x5a` against digest at `packet + 0x26a`.
   - Imports crypto session keys via `fcAllocCrypto()->ImportSession(*(ushort *)(packet + 0x20), packet + 0x66)`.
2. **Acceptance & MTU (`Accept`, 0x18004a1c0)**:
   - Registers peer endpoint, updates state `conn + 0x110 = 3` (Active/Connected).
   - Negotiated path MTU is **1414** bytes. Packets exceeding MTU return error `0x1004` in `SendGame` (`0x18004d7f0`).
3. **Keepalive (`PingSend` / `PingRecv`)**:
   - Probes connection latency and MTU via echo datagrams.

### 5.4 Layer 4: UE3 UNetConnection & Staged Channel 0 Handshake

Inside `PComNetConn` UDP datagrams, Unreal Engine 3 Channel 0 (`ChIndex = 0`, `CHTYPE_Control = 1`) executes the complete 7-stage Paladins control handshake (`Claim 16` / `OBL-UDP-002`). Server replies use `bOpen = false`, `bClose = false`, `bReliable = true`, 1-based `ChSequence` (`1, 2, 3, ...`), and 0-based `PacketId`:

| Stage | Dir | Opcode | Message Name | Payload Layout (Little-Endian after 1-byte Opcode) |
| :---: | :---: | :---: | :--- | :--- |
| 1 | C -> S | `0x1A` | `NMT_HandshakeStart` | `uint32 PlatformFlag` (`0x40` on Win64 client; `bOpen = true, ChSeq = 1`) |
| 1 | S -> C | `0x1B` | `NMT_HandshakeChallenge` | `uint32 Challenge` (`ChSeq = 1`, piggybacks `ACK(0)`) |
| 2 | C -> S | `0x1C` | `NMT_HandshakeResponse` | `uint32 CrcResponse` (MSB-first CRC32 `0x04C11DB7` over UTF-16LE `"895fcf626f55798667e4e94cb7a636af %d"` with signed `i32` challenge) |
| 2 | S -> C | `0x1D` | `NMT_HandshakeComplete` | *(0 bytes)* |
| 3 | C -> S | `0x20` | `NMT_ServerAuthRequest` | *(0 bytes)* |
| 3 | S -> C | `0x1F` | `NMT_ClientAuthRequest` | `uint64 ServerSteamId = 0`, `4 x uint32 = 0` (24 bytes; `ServerSteamId == 0` bypasses Steam AuthBlob and triggers `NMT_Hello`) |
| 4 | C -> S | `0x00` | `NMT_Hello` | `uint32 MinNetVer` (`9189`), `uint32 NetVer` (`10897`), `uint32 IsLittleEndian` (`1`) |
| 4 | S -> C | `0x03` | `NMT_Challenge` | `uint32 ChallengeId` (`0`), `FString Challenge` (`"IMMORTAL"`) |
| 5 | C -> S | `0x04` | `NMT_Netspeed` | `uint32 CurrentNetSpeed` (may arrive packed in same datagram as `NMT_Login`) |
| 6 | C -> S | `0x05` | `NMT_Login` | `FString ClientResponse`, `FString URL`, `uint64 UniqueId`, `uint64 PortalId` (Paladins 2x `u64` trailing IDs; `>= 512` bits exercises 12-bit `SerializeInt(4608)`) |
| 6 | S -> C | `0x01` | `NMT_Welcome` | Bare `FString LevelName = "Shootingrange_P"`, `FString GameName = "TgGame.TgGame_Paladins_ShootingRange"` (`496` bits -> 13-bit length) |
| 7 | C -> S | `0x09` | `NMT_Join` | *(0 bytes)*; sent after `LoadMap: 0.0.0.0:7777/Shootingrange_P` -> server transitions to `SessionPhase::Replicating` |

Additional engine control opcodes (`FNetControlMessageInfo::Names` at `0x143d27a90`): `0x02 NMT_Upgrade(u32, u32)`, `0x06 NMT_Failure(FString)`, `0x07 NMT_Uses` (optional package map; not required to reach `Welcomed by server -> LoadMap -> NMT_Join`), `0x08 NMT_Have`, `0x0A NMT_JoinSplit`, `0x10 NMT_ActorChannelFailure(i32)`, `0x1E NMT_Redirect(FString)`.

> **FString Wire Format**: `int32 Length` (LE). `Length == 0` encodes an empty string (0 bytes); `Length > 0` encodes ASCII/UTF-8 bytes including trailing NUL; `Length < 0` encodes `-Length` UTF-16LE code units including trailing NUL.

### 5.5 Team Invariant Semantics & Post-`NMT_Join` Replication Boundary

Note that retail Paladins Shooting Range runs locally in `NM_Standalone (0)` without a remote UDP server (`EV-LOG-003`), whereas Project Immortal intentionally routes `MAP_INSTANCE_ASSIGNED (0x15c61937)` to `127.0.0.1:7777` so the client executes a full dedicated-server `UPComNetConn` session. In `NMT_Welcome (0x01)`, the authentic server supplies bare **`LevelName = "Shootingrange_P"`** and **`GameName = "TgGame.TgGame_Paladins_ShootingRange"`** (matching `PersistentLevel->GetOutermost()->GetName()` and `WorldInfo->Game->GetClass()->GetPathName()`).

When local travel URLs or authoritative pawn spawn options specify a `Team` parameter, the `Team` query option dictates pawn spawn behavior and collision volume processing:

| Team ID | Designation | Spawn Behavior & Safety Semantics |
| :---: | :--- | :--- |
| `Team=0` | **Order** (Friendly Player Team) | **Safe Spawn**: Spawns pawn on the central player pavilion. No harmful trigger volumes. Mandatory value for local URL references (`DEFAULT_SHOOTING_RANGE_MAP`) and player sessions. |
| `Team=1` | **Chaos** (Enemy Bot Team) | **Bot Lanes**: Used for dummy bot targets in the practice shooting lanes. |
| `Team=255` | **Spectator / Neutral** | **Hazard**: Spawns inside or immediately activates the spawn pavilion kill volume (`KillerPawn`), causing immediate pawn death upon spawn. |

**Post-`NMT_Join` Actor Channel & `?exudp=2` Boundaries (`UNK-UDP-004`, `UNK-CRYPTO-001`)**:
- Engine channel assignments (`UNetConnection::CreateChannel`, `0x140b25e90`): `Ch0 = Control (CHTYPE_Control = 1)`, `Ch1 = Marshal (CHTYPE_Marshal = 5)`, `Ch2 = Voice (CHTYPE_Voice = 4)`, `Ch3+ = Actor (CHTYPE_Actor = 2, ACTOR_CHANNEL_INDEX = 3)`.
- On `NMT_MapLoaded (0x2A)`, the server records `map_loaded`; upon receiving `NMT_Join (0x09)`, `immortal-server` enters `SessionPhase::Replicating`. The exact `UActorChannel`, `UPackageMap`, and `FClassNetCache` wire layouts are specified in [`UACTOR_CHANNEL_WIRE_SPEC.md`](UACTOR_CHANNEL_WIRE_SPEC.md) (**Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress**).
- On dedicated retail servers (`?exudp=2`), sequenced `0x0001` datagrams from Seq 1 onward use RFC 5114 2048-bit ephemeral DH + identical TX/RX `Salsa20` + 16B `AES-MAC` (`UNK-CRYPTO-001` **Mathematically Bounded / Archived**; superseded by plaintext `?exudp=0` + `ADOPT-09` local Retail Oracle).
