# System Architecture & Crates 🏗️

The Project Immortal workspace is structured as a modular Rust workspace:

```
crates/
├── immortal-core/       # [Apache-2.0 / MIT] Primitives, game IDs, champion enums
├── immortal-extract/    # [Apache-2.0 / MIT] Cooked UPK package parser, LZO decompressor, TFC resolver
├── immortal-net/        # [AGPL-3.0] UE3 bunch serializer, Channel 0 handshake, bitstream
└── immortal-server/     # [AGPL-3.0] Tokio-based game server daemon and emulated auth gateway
```

## Protocol Overview
1. **Auth & Lobby Gateway Handshake**:
   - Client sends startup request to `127.0.0.1:9000`.
   - Gateway returns valid session ticket, player GUID, and match routing to `127.0.0.1:7777`.
2. **Game Server UDP Bunch Protocol**:
   - Connection established over UDP port `7777`.
   - Control Channel 0 exchanges `NMT_Hello`, `NMT_NetSpeed`, and `NMT_Welcome`.
   - Actor Channel 2 spawns PlayerController and replicates Fernando transform.
