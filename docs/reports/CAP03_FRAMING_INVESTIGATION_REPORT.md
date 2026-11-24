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

2. **Retraction (`PSL-INV-012`) — Falsification of `"Seq 1 6-Byte Session Token Synchronization Barrier"` Claim**:
   - **Prior Hypothesis (Retracted)**: An earlier draft of this report claimed that the identical 6-byte prefix at bytes `10..16` on Seq 1 in both directions (`78 7e 10 7b 9a 8f` in `CAP-03` Frames 14612/14613; `0d 6f c0 44 3a 58` in `CAP-01` Frames 9789/9801) was a `"Seq 1 6-byte session token synchronization barrier"` established during the `0x0010` handshake.
   - **Empirical & Binary Falsification (`#42`, `exudp2_crypto_re_report.md`)**: **FALSE — RETRACTED.** Binary reverse engineering of `ShippingPC-ChaosGame.exe` (`0c51d381...`) proves `CCryptopp::GenSession` (`0x1400dcac0`) initializes **both** TX (`+0x200`) and RX (`+0x208`) `CryptoPP::Salsa20` instances with the **identical 32-byte key and 8-byte base IV**, seeking to `(seq == 0 ? 1 : seq) * payload_len`. Because `CAP-03` `Frame 14612` (`C->S`, `seq=1`, `44B` total, `18B` encrypted payload) and `Frame 14613` (`S->C`, `seq=1`, `44B` total, `18B` encrypted payload) share identical `(seq, payload_len)`, XORing their encrypted payloads yields:
     - `Frame 14612[10:28] ^ Frame 14613[10:28] = 000000000000 05800450401161ae7e2b63bb`
     - The leading 6 bytes cancel completely to `000000000000` because both directions prepend a 6-byte zero `PComNetConn` prefix (`00 00 00 00 00 00`) prior to Salsa20 encryption. Thus `78 7e 10 7b 9a 8f` is **NOT** a plaintext session token synchronization barrier, but `000000000000 ^ Salsa20(K, IV).Seek(1 * 18)[0:6]` arising from bidirectional TX/RX Salsa20 keystream reuse. On `Seq 2+`, `(seq * payload_len)` and differing payload lengths yield distinct keystream slices on every packet.

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

1. **Client Hello (570 Bytes, `0x23a`)** *(corrected per `#42` / `exudp2_crypto_re_report.md`)*:
   - `0..10`: Prefix `00 00 00 00 00 00 00 00 00 10` (`conn_id=0, seq=0, flags=0x0010`)
   - `10..14`: Function `00 00 00 00` (`0`)
   - `14..18`: DH public key size `00 01 00 00` (`0x100 = 256` bytes)
   - `18..22`: Local connection handle `01 00 00 00` (`1`)
   - `22..24`: Plaintext session secret length = `72` (`0x0048`)
   - `24..120` (`0x18..0x78`, 96 B): Rijndael (AES-256) encrypted 72-byte ephemeral session secret (padded to `0x60`) under RFC 5114 2048-bit DH shared secret
   - `120..376` (`0x78..0x178`, 256 B): Client's ephemeral 2048-bit DH public key
   - `376..392` (`0x178..0x188`, 16 B): AES-MAC tag over `0x16..0x178` (`354` bytes)
   - `392..534` (`0x188..0x216`, 142 B): Zero padding *(corrects earlier draft which misstated zeros began at byte 96)*
   - `534..538` (`0x216..0x21a`, 4 B): SHA-256 length = `32` (`0x00000020`)
   - `538..570` (`0x21a..0x23a`, 32 B): `GenUserSHA256` digest over `0x00a..0x216` (`524` bytes)
2. **Server Challenge / Finish & PMTU (`46` Bytes / `1440` Bytes)**:
   - `[0..10]`: Outer prefix `01 00 00 00 00 00 00 00 00 10` (`seq=0, flags=0x0010`).
   - `[10..len-16]`: Salsa20-encrypted payload at seek offset `1 * payload_len` (`20` B for 46B Challenge/Finish; `1414` B for 1440B PMTU probe).
   - `[len-16..len]`: 16-byte AES-MAC tag over `[10B outer header || encrypted payload]` using `session_mac_iv ^ 1`.

### 2.3 Sequenced Gameplay Datagram Typology (`subflags = 0x0001`)

- **Header**: 10 bytes `[conn_id: 4B LE] [seq: 4B LE] [00 01]`.
- **Encrypted Payload (`[10..len-16]`)**: Salsa20-encrypted `[6B PComNetConn prefix || UE3 bitstream]` at seek offset `seq * payload_len`, followed by a **16-byte AES-MAC** tag (`[len-16..len]`).
- **Retraction on Seq 1 (`PSL-INV-012`, `#42`)**: The earlier claim that Seq 1 prepends a plaintext 6-byte `"session token synchronization barrier"` is **retracted**. `78 7e 10 7b 9a 8f` (`CAP-03` Frames 14612/14613) and `0d 6f c0 44 3a 58` (`CAP-01` Frames 9789/9801) are Salsa20 keystream output XORed with 6 zero bytes (`00 00 00 00 00 00`) of `PComNetConn` due to identical TX/RX Salsa20 key+IV initialization (`CCryptopp::GenSession` `0x1400dcac0`). Because `UNK-CRYPTO-001` uses an ephemeral 2048-bit DH handshake (`ShippingPC-ChaosGame.exe` holds only the server's public key, not the private key), historical `?exudp=2` `0x0001` captures cannot be decrypted offline. Max unencrypted inner packet size remains `MaxPacket = 0x1F0` (496 bytes) for `?exudp>=1`.

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

## 4. Historical Actionable Specifications & Subsequent Supersedence (`PSL-INV-012`)

> [!IMPORTANT]
> **Supersedence Notice (`#42` & `#43` / `UACTOR_CHANNEL_WIRE_SPEC.md`)**: Section 4 below is retained as historical record of the Milestone 5 Phase 1 handoff. Subsequent cleanroom verification (`#42`) retracted the Seq 1 `"session token"` strip (`decode_with_max_bits` `&datagram[16..]` was a misinterpretation of TX/RX Salsa20 keystream reuse over 6 zero bytes of `PComNetConn`) and proved `?exudp=2` historical pcaps cannot be decrypted offline (`UNK-CRYPTO-001` **Mathematically Bounded / Archived**). Active actor-channel implementation (`UNK-UDP-003` / `UNK-UDP-004`) now proceeds directly via unencrypted `?exudp=0` against the headless Wine Retail Oracle (`ADOPT-09`) under [`docs/specs/UACTOR_CHANNEL_WIRE_SPEC.md`](../specs/UACTOR_CHANNEL_WIRE_SPEC.md).

### 4.1 Historical Specification for `agyis_builder` (Phase 2: Codec Extension)
- **File**: `crates/immortal-net/src/bunch.rs`
- **Historical Notes (Retracted on Seq 1 Strip)**:
  1. Distinguish between Standalone UDP 7777 (6-byte prefix) and Dedicated `?exudp=2` 10-byte outer header (`0x0001` / `0x0010`).
  2. *(Retracted)* Stripping a 6-byte Seq 1 `"session token"` (`&datagram[16..]`) is invalid because `0x0001` payloads in `CAP-01`/`CAP-03` are Salsa20-encrypted + 16B AES-MAC (`UNK-CRYPTO-001`).
  3. Max Packet Bits for `?exudp>=1`: `EXUDP_MAX_PACKET_BITS` (`0x1F0 * 8 = 3968` bits = 496 bytes).

### 4.2 Historical Specification for `agyis_custodian` (Phase 3: Spec & Ledger Updates)
- **File**: `docs/specs/CLEANROOM_LEDGER.md`
- **Updated Status**:
  1. Claim 17 (`OBL-UDP-003`): Retracted the Seq 1 6-byte session token barrier claim (`#42`), documented `?exudp=2` 10-byte outer framing & `0x0010` sizes, and verified `NMT_Uses*` / `0x2A` / `UMarshalChannel` wire layouts against `?exudp=0` Retail Oracle (`UACTOR_CHANNEL_WIRE_SPEC.md`).
  2. `UNK-UDP-004`: Reached bit-exact wire spec verification against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust integration & Live Flight 036 in progress.

### 4.3 Specification for `agyis_builder` (Phase 4: Server Integration & Golden Replay)
- **File**: `crates/immortal-server/src/game_server.rs` & `replication.rs`
- **Updates Required**:
  1. Add unsequenced handshake state machine responding to 570B Client Hello with 46B Server Challenge and handling PMTU probes.
  2. Implement Actor Channel 3 initialization emitting `TgPlayerController` bunch upon client `NMT_MapLoaded (0x2A)`.
- **Verification Gate**: Replay golden sequence against `crates/immortal-net/examples/decode_pcap.rs`.
