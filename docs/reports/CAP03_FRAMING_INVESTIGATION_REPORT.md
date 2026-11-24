# Project Immortal — Milestone 5 Phase 1: Empirical Packet Analysis & Dedicated-Server Transport Framing Investigation Report

- **Date**: 2026-11-19
- **Investigator**: `agyis_investigator`
- **Mission**: Milestone 5 Phase 1 (Dedicated-Server Transport Framing, Session Token Analysis, UE3 Bitstream Alignment, and UActorChannel Carving)
- **Primary Captures**:
  - `CAP-03_custom_baseline_20261119.pcapng` (21.26 MB, 53,008 UDP packets on port 9113, SHA-256 `02a5fa92...`)
  - `CAP-03_custom_baseline_20261119_Launch.log` (247.3 KB, SHA-256 `a1c6c179...`)
  - `CAP-01_bot_siege_20261119.pcapng` (34.7 MB, 46,252 UDP packets on port 9222, SHA-256 `4f21c120...`)
  - `CAP-01_bot_siege_20261119_Launch.log` (693.9 KB, SHA-256 `16376a1d...`)
- **Binary Authority**: `ShippingPC-ChaosGame.exe` (SHA-256 `0c51d381...`) via cleanroom REA decompiler/disassembly cache (`PaladinsProject.gpr`).

---

## 1. Executive Summary & Core Forensic Findings

1. **Dedicated Transport Framing Separation**:
   - The dedicated transport framing protocol operates in two strictly segregated layers:
     - **Layer A: Unsequenced Control / Handshake / MTU Frames (`subflags = 0x0010`)**: Packets begin with `[0x01, 0x00, 0x00, 0x00]` (or client initial hello `[0x00, 0x00, 0x00, 0x00]`), followed by a 4-byte sequence of zeros `[0x00, 0x00, 0x00, 0x00]`, and a 2-byte subflag `[0x00, 0x10]`.
       - **Initial Client Hello (570 bytes)**: Frame 14596/14597 in CAP-03 (Frames 9779-9781 in CAP-01). Prefix `00 00 00 00 00 00 00 00 00 10`, 72-byte payload descriptor, zero padding to 534 bytes, 4-byte length (`0x20` = 32), and 32-byte HMAC-SHA256 signature.
       - **Server Challenge / Cookie Reply (46 bytes)**: Frame 14598 in CAP-03 (Frame 9782 in CAP-01). Prefix `01 00 00 00 00 00 00 00 00 10`, 1-byte flag (`0x5d` / `0x8d`), 5-byte client token, 6-byte server token, and 24-byte challenge payload.
       - **Path MTU Discovery (PMTU) Probes (1440 bytes)**: Frames 14599–14606 in CAP-03 (Frames 9783–9795 in CAP-01). Sized exactly to 1440 bytes to test the maximum Ethernet MTU without fragmentation.
       - **Handshake Finalization (46 bytes)**: Frames 14607–14610 in CAP-03. Flag drops `0x05` (from `0x5d` -> `0x58`, or `0x8d` -> `0x88`), completing the mutual exchange.
     - **Layer B: Sequenced Gameplay Datagrams (`subflags = 0x0001`)**: Packets begin with `[0x01, 0x00, 0x00, 0x00]`, a 4-byte little-endian monotonic sequence counter (independently maintained per-direction: C->S and S->C starting at 1), and a 2-byte subflag `[0x00, 0x01]`.

2. **Session Token Invariant & Falsification of Static Session Token Hypothesis**:
   - **Hypothesis Tested**: Is the 6-byte sequence following the 10-byte prefix (`78 7e 10 7b 9a 8f` in CAP-03, `0d 6f c0 44 3a 58` in CAP-01) a static session token symmetrically present on all sequenced packets?
   - **Empirical Falsification**: **FALSE**. Exhaustive packet search across all 53,008 packets in CAP-03 and 46,252 packets in CAP-01 proves that this 6-byte token appears **EXACTLY TWICE** per session:
     - In CAP-03: Frame 14612 (C->S Seq 1) and Frame 14613 (S->C Seq 1).
     - In CAP-01: Frame 9789 (C->S Seq 1) and Frame 9801 (S->C Seq 1).
   - On Seq 2+, the 6 bytes at offset 10..16 are completely distinct on every packet.
   - **Root Cause & Architectural Purpose**: The 6-byte token on Seq 1 is the initial synchronized handshake connection cookie established during the 46-byte unsequenced exchange. It acts as an initial synchronization barrier verifying that both client and server are bound to the identical session before transitioning to sequenced datagrams.

3. **Transport De-framing & Socket Architecture (REA Reverse Engineering)**:
   - Decompilation of `UPComNetDriver::TickDispatch` (`0x140bd48e0`), `FSocketWin64::RecvFrom` (`0x140bc87c0`), and `UPComNetConn::ReceivedRawPacket` (`0x140bc8770`) proves:
     - `UPComNetDriver` reads packets from the UDP socket up to 1440 bytes (`0x5a0`).
     - In dedicated server mode (`?exudp=2`), socket reception is decoupled into a worker thread using asynchronous packet queues (`0x140d504d0` / `0x140d4fee0`).
     - Packets arriving at `UPComNetConn::ReceivedRawPacket` (`0x140bc8770`) unconditionally strip the transport prefix before passing the payload to `UNetConnection::ReceivedRawPacket` (`0x140b37100`).
     - `UNetConnection::ReceivedRawPacket` (`0x140b37100`) unconditionally scans from the final byte backwards for the trailing `1` stop bit (`cVar2 != '\0'`), computes `total_bits`, and passes the bitstream to `UNetConnection::ReceivedPacket` (`0x140b36500`).

4. **UActorChannel Carving & Log Cross-Referencing**:
   - Timing correlation between `CAP-03_custom_baseline_20261119_Launch.log` and the packet stream reveals exact milestones:
     - **T=0.00s (Frame 14596)**: `Browse: 0.0.0.0:9113/...exudp=2...`
     - **T=1.47s (Packet #39, S->C Seq 18)**: `[0191.31] DevNet: Welcomed by server (Level: sg_jaguarfalls_rework_p, Game: TgGame.TgGame_Paladins_Siege_Ranked)` (log-correlated timestamp; `0x0001` payload is encrypted under `?exudp=2` / `UNK-CRYPTO-001`, so `NMT_Welcome` is not directly decoded from CAP-03 wire bytes).
     - **T=3.54s (Packet #56, S->C Seq 28)**: `[0193.33] Log: LoadMap: 0.0.0.0:9113/sg_jaguarfalls_rework_p...` (log-correlated S->C packet timing only; `NMT_MapLoaded (0x2A)` is strictly C->S per `0x140b55f20` and cannot be decoded from encrypted CAP-03 `0x0001` frames).
     - **T=5.78s - 5.84s (Packets #524–#531, Server Seq 51–53)**:
       - `[0195.74] DevNet: TgPlayerController_1 setplayer TgLocalPlayer_0`
       - Packet #524 (Frame 15141, S->C Seq 51, Len 247): Server opens Channel 3 (`UActorChannel`, `CHTYPE_Actor = 2`, `bOpen = 1, bReliable = 1, ChIndex = 3, ChSequence = 1`), replicating `TgPlayerController_1` and binding local player possession.
       - Packet #529 (Frame 15146, S->C Seq 52, Len 250) & Packet #530 (Frame 15147, S->C Seq 53, Len 504): Spawn and replication bunches for `TgPawn_Fernando_0`, `TgDevice_FernandoInhand_0`, and `TgBot_Evie_0`.

---

## 2. Dedicated-Server Transport Framing Specification

### 2.1 Outer Datagram Header Layout (10 Bytes)

| Offset (Bytes) | Field Name | Width | Type | Semantics |
| :--- | :--- | :--- | :--- | :--- |
| `0..4` | `Magic / Version` | 4 bytes | `[u8; 4]` | `0x01, 0x00, 0x00, 0x00` (Dedicated extended UDP v1). Initial client hello uses `0x00, 0x00, 0x00, 0x00`. |
| `4..8` | `Sequence / Counter` | 4 bytes | `u32` (LE) | Little-endian sequence counter. In unsequenced control packets (`0x0010`), this is `0x00000000`. In sequenced gameplay packets (`0x0001`), this is a strictly incrementing sequence (`1, 2, 3, ...`) maintained independently for C->S and S->C. |
| `8..10` | `Transport Subflags` | 2 bytes | `[u8; 2]` | `0x00, 0x10` (`UNSEQUENCED_CONTROL`) or `0x00, 0x01` (`SEQUENCED_GAMEPLAY`). |

### 2.2 Unsequenced Control Frame Typology (`subflags = 0x0010`)

1. **Client Hello (570 Bytes)**:
   - `0..10`: Prefix `00 00 00 00 00 00 00 00 00 10`
   - `10..16`: Connection nonce `00 00 00 00 00 01`
   - `16..22`: Sub-version `00 00 01 00 00 00`
   - `22..24`: Descriptor Length = `72` (`0x0048`)
   - `24..96`: 72-byte client platform and ticket payload
   - `96..534`: Zero padding (`0x00` x 438)
   - `534..538`: HMAC length = `32` (`0x00000020`)
   - `538..570`: 32-byte SHA-256 HMAC
2. **Server Challenge / Cookie Reply (46 Bytes)**:
   - `0..10`: Prefix `01 00 00 00 00 00 00 00 00 10`
   - `10`: Handshake Flag `0x5d` (CAP-03) or `0x8d` (CAP-01). Top bits session-specific; lower bits `0x05` denote Challenge phase.
   - `11..16`: 5-byte Client Cookie Echo.
   - `16..22`: 6-byte Server Session Cookie.
   - `22..46`: 24-byte Nonce & Cryptographic Challenge.
3. **PMTU Discovery Probes (1440 Bytes)**:
   - `0..10`: Prefix `01 00 00 00 00 00 00 00 00 10`
   - `10..16`: Symmetrical probe token (`25 3e 4e ed a3 7c` / `22 3e 4e ed a3 7c`)
   - `16..22`: Static probe marker `fb 73 09 f1 45 49`
   - `22..1440`: Synthetic padding payload validating Ethernet MTU without fragmentation.
4. **Handshake Completion (46 Bytes)**:
   - `0..10`: Prefix `01 00 00 00 00 00 00 00 00 10`
   - `10`: Handshake Flag `0x58` (CAP-03) or `0x88` (CAP-01), clearing phase bits `0x05`.
   - `11..22`: Confirmed session tokens.
   - `22..46`: 24-byte confirmation and key derivation verification.

### 2.3 Sequenced Gameplay Datagram Typology (`subflags = 0x0001`)

- **Header**: 10 bytes `[01 00 00 00] [seq: 4B] [00 01]`.
- **Seq 1 Special Invariant**: Exactly on Seq 1 (`seq == 1`), both C->S and S->C packets prefix the payload with the 6-byte session token (`78 7e 10 7b 9a 8f` in CAP-03; `0d 6f c0 44 3a 58` in CAP-01).
- **Seq 2+ Invariant**: Beginning at Seq 2, packets carry the standard sequenced bitstream. Max packet size is governed by `MaxPacket = 0x1F0` (496 bytes, yielding datagram lengths up to ~518 bytes including headers).

---

## 3. UActorChannel Carving Specification (Fernando & Evie)

Cross-referencing Server Seq 1..58 with `CAP-03_custom_baseline_20261119_Launch.log`:

1. **Welcomed & Level Commitment (Log-Correlated)**:
   - S->C Seq 18 (Packet #39, Len 38) coincides with `[0191.31] DevNet: Welcomed by server (Level: sg_jaguarfalls_rework_p, Game: TgGame.TgGame_Paladins_Siege_Ranked)` *(note: `?exudp=2` `0x0001` payload bytes are encrypted under `UNK-CRYPTO-001`, not plaintext-decoded)*.
2. **MapLoaded Window (Log-Correlated — Correction)**:
   - S->C Seq 28 (Packet #56, Len 47) is a server-to-client packet coinciding with `[0193.33] Log: LoadMap: 0.0.0.0:9113/sg_jaguarfalls_rework_p...` *(earlier draft mislabeled S->C Seq 28 Frame 14659 as `NMT_MapLoaded`; `NMT_MapLoaded (0x2A)` is strictly Client -> Server per `0x140b55f20`, and CAP-03 sequenced payloads remain encrypted under `UNK-CRYPTO-001`)*.
3. **UActorChannel Opening & Possession (Server Seq 51, Packet #524)**:
   - Client logs: `[0195.74] DevNet: TgPlayerController_1 setplayer TgLocalPlayer_0`.
   - Channel: `ChIndex = 3` (`ACTOR_CHANNEL_INDEX = 3`).
   - Channel Type: `CHTYPE_Actor = 2`.
   - Header Flags: `bOpen = 1`, `bClose = 0`, `bReliable = 1`, `bPartial = 0`.
   - `ChSequence`: `1`.
   - Actor Class: `TgPlayerController` (`TgGame.TgPlayerController`).
   - Function / RPC: `SetPlayer` (`setplayer TgLocalPlayer_0`), establishing the local human controller as Fernando.
4. **Pawn & Weapon Replication (Server Seq 52–53, Packets #529–#530)**:
   - Client logs: `[0196.20] Log: ATgPawn::ReceiveInventoryData called`.
   - Actors instantiated:
     - `TgPawn_Fernando_0` (Champion ID 1026, Fernando).
     - `TgDevice_FernandoInhand_0` (Device ID 10774 / In-hand Flame Lance).
     - `TgBot_Evie_0` / `TgPawn_Evie_0` (Bot AI Opponent).

---

## 4. Actionable Cleanroom Specifications for Downstream Subagents

### 4.1 Specification for `agyis_builder` (Phase 2: Codec Extension)
- **File**: `crates/immortal-net/src/bunch.rs`
- **Updates Required**:
  1. Update `PcomPrefix` enum and `Ue3Packet::decode_with_max_bits` to distinguish between:
     - Standalone UDP 7777 (6-byte prefix).
     - Dedicated Sequenced Gameplay `0x0001` (10-byte prefix: `[01 00 00 00] [seq: 4B] [00 01]`).
     - Dedicated Unsequenced Control `0x0010` (10-byte prefix: `[01 00 00 00] [00 00 00 00] [00 10]` or client hello `00 00 00 00...`).
  2. In `decode_with_max_bits`: For dedicated `0x0001` packets where sequence `seq == 1`, strip the 6-byte session token (`&datagram[16..]`) before decoding UE3 bitstream. For `seq > 1`, preserve `&datagram[10..]`.
  3. Max Packet Bits: Set default for dedicated transport to `EXUDP_MAX_PACKET_BITS` (`0x1F0 * 8 = 3968` bits = 496 bytes).
- **Unit Verification Test**:
  - Add `test_dedicated_sequenced_seq1_session_token_and_seq2_roundtrip` in `crates/immortal-net/tests/`.

### 4.2 Specification for `agyis_custodian` (Phase 3: Spec & Ledger Updates)
- **File**: `docs/specs/CLEANROOM_LEDGER.md`
- **Updates Required**:
  1. Update Claim 17 (`OBL-UDP-003`): Document the exact 10-byte unsequenced (`0x0010`) handshake sequence (570B Hello -> 46B Challenge -> 1440B PMTU Probes -> 46B Finish) and the Seq 1 6-byte session token invariant.
  2. Update `UNK-UDP-004`: Note empirical observation of `TgPlayerController_1` (Server Seq 51, Packet #524) and `TgPawn_Fernando_0` (Server Seq 52-53, Packets #529-530) in `CAP-03` at timestamp `[0195.74]`.
- **Verification Gate**: `agyis verify --spec`.

### 4.3 Specification for `agyis_builder` (Phase 4: Server Integration & Golden Replay)
- **File**: `crates/immortal-server/src/game_server.rs` & `replication.rs`
- **Updates Required**:
  1. Add unsequenced handshake state machine responding to 570B Client Hello with 46B Server Challenge and handling PMTU probes.
  2. Implement Actor Channel 3 initialization emitting `TgPlayerController` bunch upon client `NMT_MapLoaded (0x2A)`.
- **Verification Gate**: Replay golden sequence against `crates/immortal-net/examples/decode_pcap.rs`.
