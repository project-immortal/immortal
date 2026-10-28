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
  │ - 6 zero bytes prefix [0, 0, 0, 0, 0, 0]            │
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

## 4. Verification Checklist & Success Criteria

When both daemon and client run, verify the following sequence:

1. **TCP Port 9000 Connection**:
   - Daemon logs `Accepted MCTS connection from 127.0.0.1:<port>`.
   - Client sends `SendLogin` RPC.
   - Server returns `OnLoginResponse` with Tokens `100`, `102`, `105`, and `500` (pointing to `127.0.0.1:7777`).
2. **UDP Port 7777 Handshake**:
   - Daemon logs `Ingested PComNetConn bunch from 127.0.0.1:<port>`.
   - Server acknowledges client packets and transmits `NMT_Welcome` with level URL `Shootingrange_P?...&Team=0`.
3. **In-Game 3D Viewport**:
   - Game transitions from loading screen to the 3D Shooting Range map.
   - Character spawns upright on the circular stone pavilion.
   - WASD movement and camera mouselook are fully responsive.

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
