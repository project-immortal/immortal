<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# G2 Specification: Cleanroom Auth Handshake & UE3 Bunch Protocol

## 1. Architecture Overview

Paladins multiplayer networking operates across two distinct protocol layers:

```text
[ Paladins Client ]
       │
       ├─ (1) Auth & Lobby Gateway Handshake (TCP / HTTP / JSON / XML)
       │       Target: 127.0.0.1:9000 (Emulated Gateway)
       │       Payload: Session Token, Player GUID, Game Version Match
       │
       └─ (2) Game Server Connection (UDP / Unreal Engine 3 Bitstream)
               Target: 127.0.0.1:7777 (Emulated Game Server)
               Protocol: UE3 UNetConnection Bit-Packed Bunches
```

---

## 2. Layer 1: Auth & Gateway Protocol

1. **Client Startup Handshake**:
   - Client queries configuration endpoints to retrieve gateway server IP, auth URLs, and maintenance status.
   - Client presents authentication credentials (e.g. Steam Auth Ticket or local offline developer bypass).
2. **Emulated Gateway Response**:
   - Emulated gateway accepts the connection on `127.0.0.1:9000`.
   - Returns a successful auth response with a mock Player GUID, account level, unlocked champions (including Fernando), and an active match ticket routing the client to `127.0.0.1:7777`.

---

## 3. Layer 2: Unreal Engine 3 UDP Bunch Protocol

### 3.1 Packet Layout
Every UDP datagram received by the game server follows standard UE3 packet framing:
- `Connection Packet Header`:
  - `PacketId`: Sequence number of the packet.
  - `AckPacketId`: Last received packet ID from the remote peer.
  - `bHasAcks`: Flag indicating trailing acknowledgement bitmask.

### 3.2 Channels & Bunch Framing
Within each packet payload, data is multiplexed across logical channels:
- **Channel 0 (`Control Channel`)**:
  - Handles initial handshake, client URL requests (`HELLO`, `WELCOME`, `UPGRADE`, `FAILURE`).
  - Negotiates package map / checksum verification.
- **Channel 1 (`Voice Channel`)**:
  - Encoded audio packets.
- **Channel 2+ (`Actor Channels`)**:
  - Dedicated actor replication channels (pawns, projectiles, game state).
  - Bunch header format:
    - `bOpen`: Channel open flag.
    - `bClose`: Channel close flag.
    - `bPartial`: Fragmented bunch flag.
    - `ChIndex`: Channel index.
    - `ChType`: Channel type identifier.
    - `BunchData`: Bit-packed serialization archive.

---

## 4. MVP Target Milestone: Shooting Range / Bot Sandbox

- Client sends initial connection request to `127.0.0.1:7777`.
- Server acknowledges Channel 0 handshake, sends `WELCOME` with Level URL: `ShootingRange?game=ChaosGame.ChaosGameInfo`.
- Server opens Actor Channel 2 for `PlayerController`, spawns default champion pawn (`Fernando`), and replicates initial player transform `(X, Y, Z, Pitch, Yaw, Roll)`.
