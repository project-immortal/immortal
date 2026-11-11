<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Shooting Range Developer Runbook 🎯🏹

This runbook documents the architecture, launch procedures, and troubleshooting steps for booting the official Paladins client directly into the 3D Shooting Range sandbox using the Project Immortal cleanroom server stack (`immortal-server`).

---

## 1. Architecture Overview: Client-Server Flow

Project Immortal connects to the unmodified *Paladins: Champions of the Realm* retail client via cleanroom protocol emulation across two network ports:

```text
┌────────────────────────────────────────────────────────┐
│             Paladins Client (ShippingPC-ChaosGame.exe) │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼ (1) TCP :9000 [MCTS Gateway]
  ┌─────────────────────────────────────────────────────┐
  │ - CPackCoder Framing (0xCBBC / 0xCBB0)              │
  │ - SendLogin (Platform token, Version 8.1.5839.0)    │
  │ - OnLoginResponse (Session ticket, Match ticket)    │
  │ - Inventory Rowsets:                                │
  │     Token 100: ChampionRoster (bOwned = true)       │
  │     Token 102: WeaponDevices (Device 10774)         │
  │     Token 105: DeckLoadouts (Deck 16379)            │
  └─────────────────────┬───────────────────────────────┘
                        │
                        ▼ (2) UDP :7777 [PComNetConn Game Server]
  ┌─────────────────────────────────────────────────────┐
  │ - 6 zero bytes prefix [0,0,0,0,0,0] (or UNK-UDP-001)│
  │ - Client Seq, Control Flags (0x40 ACK, 0x80 bunch)  │
  │ - Server Sequence Monotonic Increment               │
  │ - Channel 0 Handshake (NMT_Hello, NMT_NetSpeed)     │
  │ - NMT_Welcome Level URL Travel:                     │
  │   Shootingrange_P?game=TgGame...&Team=0             │
  │ - Trailing BitReader Termination Marker (0x01)      │
  └─────────────────────┬───────────────────────────────┘
                        │
                        ▼ (3) Level Travel & Walkability
  ┌─────────────────────────────────────────────────────┐
  │ - Client loads Shootingrange_P.upk package          │
  │ - Actor Channel 2 Fernando (TgPawn_Knight) spawns   │
  │ - Safe player pavilion spawn (Team=0 Order)         │
  └─────────────────────────────────────────────────────┘
```

---

## 2. Starting the Cleanroom Server Daemon

The `immortal-server` binary hosts both the MCTS TCP 9000 Auth Gateway and the UDP 7777 Game Server concurrently.

### Run with Cargo

```bash
# Run server in debug mode with informative tracing
RUST_LOG=info cargo run -p immortal-server

# Or run optimized release build
RUST_LOG=info cargo run -p immortal-server --release
```

Expected log output confirming healthy daemon initialization:
```text
INFO immortal_server: 🔥 Starting Project Immortal Server Daemon
INFO immortal_server: 🌐 Auth Gateway listening on 127.0.0.1:9000
INFO immortal_server: 🎮 Game Server listening on UDP 0.0.0.0:7777
INFO immortal_server: 🚀 Cleanroom server services successfully started. Press Ctrl+C to terminate.
```

---

## 3. Launching Paladins Client

Launch the retail game client with CLI switches redirecting networking to the local loopback server without altering DLLs or hosts files.

### Standard Steam Client Launch

In the Steam Library:
1. Right-click **Paladins** -> **Properties** -> **General** -> **Launch Options**.
2. Paste the following launch parameters:

```text
-nosteam -host=127.0.0.1 -tcp=9000 -servicediscoveryhost=127.0.0.1:9000
```

### Direct Linux / Proton CLI Launch

To launch directly via terminal or custom scripts under Proton on Linux:

```bash
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/root"
export STEAM_COMPAT_DATA_PATH="$HOME/.steam/root/steamapps/compatdata/444090"
export PROTON_DIST_PATH="$HOME/.steam/root/steamapps/common/Proton - Experimental"

"$PROTON_DIST_PATH/proton" run \
  "$PALADINS_INSTALL_PATH/Binaries/Win64/ShippingPC-ChaosGame.exe" \
  -nosteam \
  -host=127.0.0.1 \
  -tcp=9000 \
  -servicediscoveryhost=127.0.0.1:9000
```

---

## 4. Verification Checklist & Automated Flight Gate

Run the automated flight harness to execute end-to-end verification against the cleanroom daemon:
```bash
agyis flight --target range --timeout 120
```

Verified Flight 033 progression and remaining gate:
1. **TCP Port 9000 Connection (Verified)**:
   - Daemon logs `Accepted MCTS connection from 127.0.0.1:<port>` and handles `0x07FE` (`2046`-byte) post-login chunk framing (`field0 == 0`).
   - Gateway delivers `OnLoginResponse`, `OnQueryServers` (`0xaf434825`), `MATCH_STATUS` State 10, `MAP_INSTANCE_ASSIGNED` (`0x15c61937` with Table `1583` & Token `2287`), `LaunchMapInstance` (`0x4bee2ed8`), and `ChangeMap` (`0x847de68b`).
   - Retail client logs `Match composition cached [96E3D70]` and `ReceiveChangeMap: mapGameId 1615`.
2. **UDP Port 7777 Handshake (Blocked on `UNK-UDP-001`)**:
   - Live client UDP `7777` packets now arrive at `immortal-server`, carrying non-zero bytes in `data[1..6]` (e.g., `[00, 8a, ce, 31, c6, f6, 00, 80, ...]`).
   - Until `UNK-UDP-001` header parsing is resolved, `NMT_Welcome` (`Shootingrange_P?...&Team=0`) cannot fire and `BROWSE_RANGE` remains pending.
3. **In-Game 3D Viewport (Target Gate)**:
   - Once `UNK-UDP-001` is resolved, the client transitions to `Shootingrange_P`, spawns Fernando upright on the circular stone pavilion, and accepts WASD movement and mouselook.

---

## 5. Troubleshooting Guide

### 5.1 Spawn Autokill Fix (`Accessed None 'KillerPawn'`)
- **Symptom**: The client loads into the Shooting Range, but the screen instantly turns grayscale, plays a death sound, or displays death camera spectator view. Client log records: `Accessed None 'KillerPawn'` or kill volume triggers.
- **Root Cause**: The level URL was provided with `Team=255` (Spectator/Neutral) or missing team assignment, causing the engine to place the pawn inside the pavilion containment kill volume.
- **Fix**: Ensure the `level_url` in `immortal-net` / `immortal-server` contains `Team=0`:
  ```text
  Shootingrange_P?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0?Team=0
  ```
  `Team=0` designates the Order team (friendly player team) which bypasses the kill volume.

### 5.2 Empty Champion Select / Missing Inventory Fix
- **Symptom**: In-game HUD or champion selection displays an empty grid with zero selectable champions or abilities.
- **Root Cause**: The Scaleform Flash interface (`UIHudChampionSelect`) requires serialized inventory tables from MCTS during the TCP 9000 handshake.
- **Fix**: Verify `OnLoginResponse` includes the inventory rowsets:
  - **Token 100 (`ChampionRoster`)**: Unlocks champion IDs (`bOwned: bool`).
  - **Token 102 (`WeaponDevices`)**: Unlocks weapon devices (e.g., Device `10774` Flame Lance).
  - **Token 105 (`DeckLoadouts`)**: Sets loadouts (e.g., Deck `16379` Fernando Starter).

### 5.3 Proton & RADV GPU Environment Variables (Linux)
On Linux workstations using AMD / Mesa RADV or Intel graphics:
- If experiencing shader compilation stutters or crashes during map loading:
  ```bash
  # Enable Mesa RADV graphics pipeline library
  export RADV_PERFTEST=gpl
  # Force DX11 backend
  export PROTON_USE_WINED3D=0
  export DXVK_ASYNC=1
  ```
- If the game hangs on a black window:
  - Add `-nomovie` to client launch options to skip pre-rendered Bink video playback.
