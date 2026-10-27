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
| `500` | `MatchTicket` | RowSet / Blob (`0xA`) | Dedicated server IP, port, and authentication ticket routing to `127.0.0.1:7777`. |

### 4.3 Login Handshake Sequence
1. **Client -> Server (`SendLogin`)**:
   - Client establishes TCP stream to `127.0.0.1:9000`.
   - Sends framing `0xCBBC` / `0xCBB0` containing Login Parameters (platform token, client version `8.1.5839.0`, language, EULA acceptance).
2. **Server -> Client (`OnLoginResponse`)**:
   - Server validates version and responds with `FunctionId` Login Reply.
   - Sets Token `0x1A = 0` (Success).
   - Sets Token `10 = 10001` (Mock Account ID).
   - Sets Token `7 = "IMMORTAL-DEV-SESSION-TICKET"`.
   - Sets Token `500 = MatchTicket` pointing to `127.0.0.1:7777`.

---

## 5. Layer 3: UDP Session & Handshake Protocol (`CPackUdp`)

Once authenticated, the client connects to the emulated match server on UDP port `7777`:

### 5.1 CPackUdp Driver Initial Exchange
1. `HelloSend`:
   - Client sends initial datagram to `127.0.0.1:7777`.
2. `HelloRecvReply`:
   - Server acknowledges connection request and assigns client connection session.
3. `PingSend` / `PingRecv`:
   - MTU discovery exchange with standard MTU `1414` bytes.

### 5.2 UE3 Channel 0 Control Handshake
After UDP session framing is established, the client initiates the standard Unreal Engine 3 `Control Channel` (Channel 0):
- `NMT_Hello` (`0x00`): Client presents engine version, licensee version, and map URL.
- `NMT_NetSpeed` (`0x03`): Client requests transfer data rate (e.g. `24000` / `48000`).
- `NMT_Welcome` (`0x01`): Server replies with Level URL:
  ```text
  ShootingRange?game=ChaosGame.ChaosGameInfo
  ```
- Server opens Actor Channel 2 for `PlayerController`, spawns Fernando pawn (`ChampionId::Fernando = 1026`), and replicates initial player transform.
