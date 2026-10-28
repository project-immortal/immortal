<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->

# MCTS Inventory & Session Template Specification

## 1. Overview & Verified Empirical Ground Truth

From the live session packet capture (`pcaps/paladins_live_session.pcap`, stream 6761) and `Launch.log`:
1. **Level Travel URL**:
   ```text
   Shootingrange_P?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0?Team=0
   ```
2. **Team Invariant**:
   - `Team=0`: Order (Friendly player team). Spawns safely on the player pavilion without damage volumes.
   - `Team=1`: Chaos (Enemy bot team).
   - `Team=255`: Spectator/Neutral. Triggers spawn area kill volume (`Accessed None 'KillerPawn'`).
3. **Inventory Dependency**:
   - The in-game Scaleform UI (`UIHudChampionSelect`, `UIStoreDetail`) renders empty grids if the client has not received inventory rowsets from MCTS (TCP 9000).
   - MCTS streams 94 frames of serialized tables totaling ~3 MB on initial login.

---

## 2. Token & Rowset Layout (TCP 9000 `OnLoginResponse`)

| Token ID | Field Name | Type | Value / Purpose |
| :--- | :--- | :--- | :--- |
| `0x1A` (26) | `Status` | Integer (`0x05`) | `0` (Success) |
| `10` | `AccountId` | Integer (`0x05`) | `8302401` (Player Account ID) |
| `7` | `SessionToken` | WChar String (`0x0C`) | Session Ticket |
| `100` | `ChampionRoster` | RowSet / Blob (`0x0A`) | List of unlocked champions (`1026` Fernando, etc.) |
| `102` | `WeaponDevices` | RowSet / Blob (`0x0A`) | Device `10774` (Fernando Flame Lance) |
| `105` | `DeckLoadouts` | RowSet / Blob (`0x0A`) | Deck `16379` (Fernando Starter Deck) |
| `500` | `MatchTicket` | RowSet / Blob (`0x0A`) | Host `127.0.0.1`, Port `7777`, Level URL |

---

## 3. Champion & Device Constants

```rust
pub const CHAMPION_FERNANDO: u32 = 1026;
pub const CHAMPION_VIKTOR: u32 = 1025;
pub const CHAMPION_CASSIE: u32 = 1024;

pub const DEVICE_FERNANDO_FLAME_LANCE: u32 = 10774;
pub const DECK_FERNANDO_STARTER: u32 = 16379;
```

---

## 4. Swarm Workstream Allocation (Divide & Conquer)

1. **Track A (Asset Preservation Specialist)**:
   - Target: `crates/immortal-extract`
   - Mission: Parse `DEVICE10774_ASSETS_SF.upk` and `FERNANDO_ASSETS_SF.upk` export tables, extracting Flame Lance mesh and Fernando skeleton.
2. **Track B (Server Protocol Specialist)**:
   - Target: `crates/immortal-net` & `crates/immortal-server`
   - Mission: Implement `ChampionRoster` and `InventoryManager` in `marshal.rs` and `gateway.rs`, replying with all champions unlocked so `UIHudChampionSelect` populates.
3. **Track C (Developer Scaffolding)**:
   - Target: `docs/dev/` & `docs/specs/`
   - Mission: Document the ground truth team constants and level URL in `docs/specs/G2_SERVER_PROTOCOL.md`.
