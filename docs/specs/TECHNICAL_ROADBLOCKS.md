# Technical Roadblocks & De-risking Invariants: Project Immortal
<!-- SPDX-License-Identifier: AGPL-3.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->
<!-- Invariant: PSL-INV-007 (Universal Cleanroom Reverse Engineering Standard) -->

This document formalizes the five deep technical roadblocks identified in the Unreal Engine 3 / Paladins cleanroom architecture across the G1–G6 milestones, along with their concrete de-risking invariants.

---

## 1. The 1-Bit Desync Trap: UE3 Dynamic Bitstream Serialization

### The Challenge
Unreal Engine 3 UDP networking does not use JSON, protobuf, or byte-aligned packet headers. Packets sent over UDP 7777 are packed via `FBitWriter` and `FBitReader` down to arbitrary bit boundaries:
- Booleans are serialized as single individual bits (`1 bit`).
- Quantized coordinates and vectors utilize variable-bit encodings based on bounding volume ranges.
- Rotators pack Pitch, Yaw, and Roll into 8 or 16 bits per axis.
- Replicated property IDs are transmitted as variable-length Elias gamma/delta or bit-range indices (`NetFieldExportGroup`).

### The Failure Mode
If the server serializes a float as 32 bits when the client expects a 16-bit compressed representation, or if a dynamic array count is misaligned by even **one single bit**, all subsequent properties in that bunch are corrupted. The client throws an internal `Bunch Overflow` error and abruptly drops the network connection.

### De-risking Invariant & Strategy (`OBL-NET-004`)
1. **Zero Guessing Policy**: Replicated property indices and quantization parameters must never be hand-guessed.
2. **Automated Schema Extraction**: The `UClass` property replication tables and flags (`REP_Initial`, `REP_Owner`, `REP_Skip`) exist in the client binary's MSVC RTTI structures and UPK package headers. We extract these tables directly via `immortal-extract` from `TgGame.upk` and compile them into strongly-typed Rust serializers in `crates/immortal-net`.

---

## 2. Client-Side Prediction & Rubber-Banding

### The Challenge
Paladins utilizes authoritative client-side prediction:
- The local player runs movement prediction (`AutonomousProxy`), transmitting compressed movement deltas (`FSavedMove`: timestamp, acceleration vector, buttons pressed).
- The server executes the move on its authoritative `ATgPawn` and compares the resulting position with the client's predicted position.
- If the server's simulated physics diverges (e.g. due to sub-tick differences or geometry discrepancies), the server transmits `ClientAdjustPosition`. Frequent corrections result in violent, unplayable rubber-banding.

### De-risking Invariant & Strategy (`OBL-SIM-001`)
1. **Optimistic Bounding Tolerance (Month 1–2)**: For early Shooting Range and local sandbox validation, the server validates velocity limits, teleport thresholds, and basic floor bounds, acknowledging the client's predicted coordinates (`ClientAckGoodMove`) rather than re-simulating sub-tick PhysX collision.
2. **Cleanroom Collision Extraction (Month 3)**: Extract map collision hulls (`.upk` collision geometry) into a lightweight spatial acceleration structure in Rust (e.g. Rapier or Bounding Volume Hierarchy) to provide server-authoritative collision matching.

---

## 3. Flash/Scaleform (GFx) UI Rowset Starvation

### The Challenge
Paladins' user interface is powered by Autodesk Scaleform GFx (Flash/ActionScript 3 embedded in UE3). When the player opens "Champions", "Decks", or enters the Match Lobby:
- The UI requests MCTS rowsets: Token `100` (Champion unlocks), Token `102` (Mastery levels), Token `105` (Card decks), and Token `120` (Talents).
- If the server returns `OnLoginResponse` without streaming these catalog rowsets, the ActionScript state machine waits indefinitely, displaying empty champion portraits or infinite loading spinners.

### De-risking Invariant & Strategy (`OBL-MCTS-004`)
1. **Reverse-Engineered `CMarshalRowSet::Store` (`0x180038710`)**: Group `0x6001` nested rowset structure allows arbitrary tabular streaming.
2. **Static "God-Mode" Profile**: Pre-construct a complete default profile streaming 100% unlocked champions (all 59 champions at level 50, all 16 cards per champion available) the moment the client requests catalog synchronization, bypassing microtransaction bottlenecks.

---

## 4. UE3 Map Travel Handshake (`NMT_Hello` → `NMT_Welcome`)

### The Challenge
When transitioning from the 2D UI into the 3D map (`Shootingrange_P` or `LobbyMapV4_P`), UE3 switches transport from MCTS TCP 9000 to the game server UDP 7777:
- The client sends `NMT_Hello` on Control Channel 0 with client version (`8.1.5839.0`).
- The server must reply with `NMT_Challenge` containing a cryptographic cookie.
- The client answers with `NMT_Login` containing the player's session token and URL travel string (`?Name=Fernando#IMMORTAL_SESSION_001`).
- The server validates the ticket and replies with `NMT_Welcome`, specifying the level name (`Shootingrange_P`) and player pawn index.

### De-risking Invariant & Strategy (`OBL-NET-005`)
Any control message ID mismatch aborts travel back to the main menu. This handshake is hermetically isolated and tested in `crates/immortal-net/src/handshake.rs` and `crates/immortal-server/src/game_server.rs`.

---

## 5. Client Watchdogs & Keep-Alive Timers

### The Challenge
Retail binaries launched with `-NoEAC` maintain internal session watchdog timers:
- In `MctsInterface.dll`: `CommThread(): Rx Ping Timeout in CPackSession - Closing socket ...` occurs if no packet is received for 60 seconds (`0x18033a880`).
- Unhandled background watchdog timers can silently terminate the client after several minutes of inactivity.

### De-risking Invariant & Strategy (`OBL-NET-006`)
Implement a periodic 30-second ping/heartbeat task on the TCP gateway stream to keep `CPackSession` continuously fed and active.
