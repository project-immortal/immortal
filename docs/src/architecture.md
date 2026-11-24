# System Architecture & Crates 🏗️

The Project Immortal workspace is structured as a modular Rust workspace:

```text
crates/
├── immortal-core/       # [Apache-2.0 / MIT] Primitives, game IDs, champion enums
├── immortal-extract/    # [Apache-2.0 / MIT] Cooked UPK v893 parser, LZO/0x202 XOR decompressor, FPropertyTag, FClassNetCache, ADOPT-01 SAT collision, TFC/Wwise
├── immortal-net/        # [AGPL-3.0] UE3 bit-packed bunches, UPackageMapLevel, ActorBunchCodec, Channel 0 NMT_UsesOpt/NMT_Have, MCTS gateway
└── immortal-server/     # [AGPL-3.0] Tokio MCTS + UDP 7777 game daemon, live UActorChannel opens, ADOPT-02 combat, ADOPT-03 physics
```

## Protocol Overview
1. **Auth & Lobby Gateway Handshake (`127.0.0.1:9000`)**:
   - Client completes two-step MCTS handshake and receives session ticket, player GUID, queue status, champion roster, and `MAP_INSTANCE_ASSIGNED` (`0x15c61937`) routing to `127.0.0.1:7777`.
2. **Game Server UDP Bunch Protocol (`127.0.0.1:7777`, `?exudp=0`)**:
   - Control Channel 0 exchanges `NMT_HandshakeStart`..`NMT_Login` (`UniqueId=0`), `NMT_UsesOpt` package manifest, `NMT_DownloadMgr`, `NMT_Welcome`, `NMT_Have` acks, `NMT_MapLoaded` (`0x2A`), and `NMT_Join` (`0x09`).
   - Actor Channels (`CHTYPE_Actor = 2`, `ChIndex >= 3`) replicate bit-packed `TgPlayerController` (`ch=3`, `ClientSetHUD(TgHUD)`, `ClientGotoState(Spectating)`), `TgPawn_Fernando` (`ch=4`), `TgRepInfo_TaskForce` (`ch=57`), Bot/Local PRIs (`ch=61, 80`), and `TgRepInfo_Game` (`ch=81`) plus inbound `C->S` RPC decoding (`Flight 036 Core Verified Live`; external bot skin streaming and playable `PlayerWalking` / `UNK-PROP-001` `ServerMove` & `ServerPurchaseItem` remain M6 follow-ups).
   - Historical `?exudp=2` encrypted captures (`UNK-CRYPTO-001`) are mathematically bounded (RFC 5114 2048-bit ephemeral DH + Salsa20/AES-MAC) and superseded by plaintext `?exudp=0` + local `ADOPT-09` Retail Dedicated Server Oracle (`CAP-04`).
