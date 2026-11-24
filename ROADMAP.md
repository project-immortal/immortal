<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Project Immortal Contributors -->
<!-- Governed by: Cleanroom Preservation Standard & Community IP Framework -->

# Project Immortal: Living Engineering Roadmap 🗺️🛡️

The canonical living engineering roadmap for Project Immortal is maintained in the documentation book:

👉 **[Read the Full Living Engineering Roadmap](docs/specs/ROADMAP.md)** (or in mdBook format at [`docs/src/specs/ROADMAP.md`](docs/src/specs/ROADMAP.md))

---

## Strategic Milestone Overview

| Milestone | Title | Focus Area | Status | Target Timeline |
| :---: | :--- | :--- | :---: | :--- |
| **M0** | **Cleanroom Tooling & Binary Intelligence** | Headless Ghidra pipeline, SQLite index (356k functions), PCAP inspector | **Complete** | Completed |
| **M1** | **MCTS Auth & Retail Lobby Unfreeze** | TCP 9000 gateway, `OnLoginResponse`, retail main menu in 3D D3D11 | **Complete** | Completed |
| **M2** | **Map Orchestration & Sandbox Travel** | `0x15c61937` + Table `1583`, `ChangeMap` (`mapGameId 1615`), `0x07FE` framing; `LoadMap` & `Bringing World shootingrange_p.TheWorld up for play` verified in Flight 035 | **Complete** | Completed |
| **M3** | **UDP 7777 Protocol Handshake Driver** | `UNK-UDP-001`, `UNK-UDP-002`, `UNK-UDP-005` closed (`7a15b5d`); 7-stage bit-packed UE3 handshake -> `NMT_Welcome` (`24 ms`) verified in Flight 035; post-load opcode `0x2A` + `NMT_Join` next | **Complete (Post-Load `0x2A` -> M4)** | Completed |
| **M4** | **Retail Captures & Protocol Forensics** | CAP-00 to CAP-03 quarantined, Opcode `0x2A` (`NMT_MapLoaded`) & 10-byte dedicated framing proved | **Complete** | Completed |
| **M5** | **Dedicated-Server Codec & Actor Replication** | `UNK-CRYPTO-001` **Mathematically Bounded / Archived** (`RFC 5114` 2048-bit DH + `Salsa20`/`AES-MAC`; superseded by `?exudp=0` + `ADOPT-09` Oracle); `UNK-UDP-004` & `UNK-UDP-003` **Wire Spec Verified Bit-Exact Against Retail Oracle (`ch=3,4,5,12,13,80,81`); Rust Integration & Live Flight 036 In Progress** (`replication.rs` still simulated); Tempest adoption ledger (`ADOPT-01..12`) & `PSL-INV-012` | **In Progress (Wire Spec Verified; Rust & Flight 036 Pending)** | In Progress |
| **M6** | **Combat Authority, World SAT Collision & Retail Oracle** | Headless Wine oracle (`ADOPT-09`) live on `127.0.0.1:7000` (`SG_JaguarFalls_Rework_P` & `Shootingrange_P`); `FPropertyTag` & SAT world collision (`ADOPT-01`), dual-stage hitboxes (`ADOPT-02`), and rooftop/heavy-wall physics (`ADOPT-03`) landed; server tick wiring, `ADOPT-04` navmesh, & [`paladinscat.com`](https://paladinscat.com) G4/M6 metadata cross-ref (UPK/Oracle authoritative per `PSL-INV-012`) | **Active** | Month 2.5–3 |
| **M7** | **Client Enhancement, Meritocratic Progression & Eternal Preservation** | 100% de-monetized progression, neural Wwise voice restoration, `CAP-04` unencrypted Oracle blind-test matrix | **Scheduled** | Post-Gold |

For complete architectural diagrams, client vs. server responsibility matrices, and risk mitigation strategies, see [`docs/specs/ROADMAP.md`](docs/specs/ROADMAP.md).
