# Project Immortal 🔥🛡️
> *"I will not die, not yet, amigo!"* — Fernando, *Paladins: Champions of the Realm*

Project Immortal is an open-source, cleanroom game preservation initiative and server emulator designed for *Paladins: Champions of the Realm* (Unreal Engine 3 64-bit, target version `8.1.5839.0`).

## Mission & Purpose
The modern gaming landscape suffers from catastrophic server sunsets and live-service obsolescence. When central servers are powered off, multiplayer games are effectively erased from digital history.

Project Immortal guarantees permanent, decentralized playability by:
1. Re-implementing the server network daemon and auth gateway using high-performance, memory-safe Rust.
2. Automating the extraction of local client assets (models, textures, audio) without distributing proprietary assets.
3. Providing community server software that any player or gaming community can host locally or publicly under the GNU AGPLv3.

---

## Current Verified Status
- **Live Client Flight 036 (`ACTORS_REPLICATED`, `Shootingrange_P`)**: Retail `8.1.5839.0` client connects cleanly via MCTS TCP `9000` -> UDP `7777` `?exudp=0` (`NMT_UsesOpt` + `NMT_Have` gate + `NMT_MapLoaded` + `NMT_Join`), opens bit-packed `UActorChannel`s (`ch=3, 4, 57, 61, 80, 81`), initializes `TgHUD` (`UIHudCredits` `500` + crosshair reticle in 3D courtyard), and streams decoded inbound `C->S` RPCs back to `immortal-server`. Remaining M6 follow-ups are external bot skin streaming (`FERNANDO_ASSETS_SF`) and playable `PlayerWalking` possession (`UNK-PROP-001` `ServerMove` / `ServerPurchaseItem`).
- **Retail Oracle Ground Truth (`CAP-04` / `ADOPT-09`)**: Local headless Wine retail dedicated server (`127.0.0.1:7000`, `?exudp=0`) captured and decoded **3,898 / 3,898** non-empty UDP datagrams (`0` errors), superseding historical `?exudp=2` captures (`UNK-CRYPTO-001` mathematically bounded).
- **Workspace Health**: `200` passing Rust workspace tests, `0` clippy warnings, `66` CLI tests, and verified cleanroom obligation ledger (`agyis verify`).

---

## Nominative Fair Use Notice
*Paladins* and *Paladins: Champions of the Realm* are registered trademarks of Hi-Rez Studios / Evil Mojo Games. Project Immortal is an independent community preservation project and is not affiliated with, endorsed by, or sponsored by Hi-Rez Studios or Evil Mojo Games.
