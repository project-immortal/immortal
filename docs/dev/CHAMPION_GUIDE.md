<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Modular Champion Integration Guide ⚔️🛡️

This handbook establishes the standardized process for community contributors and autonomous agents to integrate new playable champions into **Project Immortal** beyond Fernando (such as Viktor, Cassie, Ying, Androxus, or Barik).

Every champion integration involves asset discovery, package decompression, bulk data extraction, cleanroom data model registration, and network bunch handling.

---

## 1. Champion Asset Discovery

All champion assets in *Paladins: Champions of the Realm* reside in cooked Unreal Engine 3 package archives located within your local client installation:

```
$PALADINS_INSTALL_PATH/ChaosGame/CookedPCConsole/
```

### Primary Champion Package Naming

Each champion has a dedicated asset package following the naming convention `<CHAMPION>_ASSETS_SF.upk`:

| Champion | Primary Package Name | Character Class | Primary Role |
| :--- | :--- | :--- | :--- |
| **Fernando** | `FERNANDO_ASSETS_SF.upk` | `TgPawn_Fernando` | Front Line |
| **Viktor** | `VIKTOR_ASSETS_SF.upk` | `TgPawn_Viktor` | Damage |
| **Cassie** | `CASSIE_ASSETS_SF.upk` | `TgPawn_Cassie` | Damage |
| **Ying** | `YING_ASSETS_SF.upk` | `TgPawn_Ying` | Support |

### Unreal Package (UPK) Binary Structure

Each champion package begins with the standard Unreal Engine package summary:

```
+-------------------------------------------------------------------+
| Unreal Package Summary (FPackageFileSummary)                      |
|  - Tag: 0x9E2A83C1 (Unreal Signature)                             |
|  - FileVersion: >= 860                                            |
|  - PackageFlags: PKG_Cooked | PKG_Compressed (0x02000000)         |
|  - CompressionFlags: COMPRESS_LZO (0x02) or COMPRESS_ZLIB (0x01)  |
+-------------------------------------------------------------------+
| NameTable (FTableEntry)                                           |
|  - Array of FString names, referenced by 0-indexed NameIndex       |
+-------------------------------------------------------------------+
| ImportTable (FObjectImport)                                       |
|  - External references to Core, Engine, and ChaosGame classes     |
+-------------------------------------------------------------------+
| ExportTable (FObjectExport)                                       |
|  - SkeletalMesh, AnimSet, PhysicsAsset, MaterialInstanceConstant  |
+-------------------------------------------------------------------+
| Compressed Chunk Table (if PKG_Compressed)                        |
|  - Array of FCompressedChunkHeader (Uncompressed/Compressed Size) |
+-------------------------------------------------------------------+
```

---

## 2. Texture & Audio Bank Extraction

### 1. Bulk Data & Texture File Cache (`.tfc`)

Champion character textures (diffuse, normal, specular, mask maps) are rarely stored directly inside the UPK file itself. Instead, Unreal Engine cooks mipmaps into shared **Texture File Cache** files:

```
ChaosGame/CookedPCConsole/CharNormals0.tfc
ChaosGame/CookedPCConsole/Char_Textures.tfc
ChaosGame/CookedPCConsole/Textures.tfc
```

#### Resolving Mipmaps
When inspecting a `UTexture2D` object in the package:
1. Parse the `FTexture2DMipMap` array.
2. For each mip level, read the `FByteBulkData` descriptor.
3. Check the bulk data flags:
   - `BULKDATA_StoreInSeparateFile`: The texture data resides in the external `.tfc` container referenced by filename.
   - `BULKDATA_CompressedLZO` / `BULKDATA_CompressedZLIB`: Payload chunk must be decompressed before saving.
4. Extract the top mip level to standard PNG/DDS format using `immortal-extract`.

### 2. Audio Bank Preservation (Wwise & FSB)

Sound assets for champion voice lines, weapon fire effects, and ultimate abilities are packaged as Audiokinetic Wwise soundbanks (`.pck`, `.wem`) and FMOD soundbanks (`.bank`):

```
ChaosGame/CookedPCConsole/Wwise_SoundBank_Default.pck
ChaosGame/CookedPCConsole/<CHAMPION>_VOICE.pck
```

#### Audio Extraction Pipeline
- Locate sound cue references (`SoundCue`, `AkAudioEvent`) within the champion's `ExportTable`.
- Extract `.wem` streams from the corresponding soundbank.
- Map the Sound Event ID to the champion's cleanroom ability trigger table.

---

## 3. Cleanroom Registration in `immortal-core`

Once a new champion's constants and parameters are verified, register them into the cleanroom data structures in `crates/immortal-core/src/lib.rs`.

### Step 1: Update `ChampionId` Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ChampionId {
    Unknown = 0,
    Viktor = 1024,
    Cassie = 1025,
    Fernando = 1026,
    Ying = 1027,
    // Add new champions here:
    // Androxus = 1028,
}

impl ChampionId {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fernando => "Fernando",
            Self::Viktor => "Viktor",
            Self::Cassie => "Cassie",
            Self::Ying => "Ying",
            Self::Unknown => "Unknown",
        }
    }

    pub fn from_id(id: u32) -> Self {
        match id {
            1024 => Self::Viktor,
            1025 => Self::Cassie,
            1026 => Self::Fernando,
            1027 => Self::Ying,
            _ => Self::Unknown,
        }
    }
}
```

### Step 2: Define Weapon & Pawn Actor Classes

Each champion utilizes specific Unreal Engine actor classes for movement simulation and weapon fire:
- `TgPawn_<CHAMPION>`: Player pawn controlling movement physics, health pools, collision cylinders, and hitbox extents.
- `TgWeapon_<CHAMPION>`: Weapon actor controlling projectile fire rates, spread cones, damage falloff, and reload timings.

### Step 3: Author Hermetic Unit Tests

Add unit test verification in `crates/immortal-core/src/lib.rs`:

```rust
#[test]
fn test_new_champion_resolution() {
    let champ = ChampionId::from_id(1024);
    assert_eq!(champ, ChampionId::Viktor);
    assert_eq!(champ.name(), "Viktor");
}
```

Verify that all tests pass in sub-second time:
```bash
cargo test -p immortal-core
```

---

## 4. Network Bunch Handling & Replication

When emulating matches in `immortal-server` and `immortal-net`, each champion actor replicates state to clients over Channel 2+:

```
+------------------------------------------------------------------------+
| UNetConnection Channel 2 (Actor Channel)                               |
|  - Actor: TgPawn_<CHAMPION> (Spawned with NetGUID)                     |
|  - Bunch Flags: BUNCH_Open | BUNCH_Reliable                            |
+------------------------------------------------------------------------+
| Replicated Properties:                                                 |
|  - Location (FVector: X, Y, Z packed)                                  |
|  - Rotation (FRotator: Pitch, Yaw, Roll packed)                        |
|  - Health / Shield Values (Packed Float/Int)                           |
|  - Active Abilities & Cooldown States                                  |
+------------------------------------------------------------------------+
```

---

## 5. Tool-Native Reverse Engineering Reminder

> [!CAUTION]
> **No Throwaway Python Scripts**: Inspecting package export tables, name tables, and property offsets must always be performed using the native `rea` CLI tool or the official `immortal-extract` utility. Never author ad-hoc Python scrapers, which risk copyright contamination and data drift.

```bash
# Analyze champion package structure natively with REA
rea analyze "$PALADINS_INSTALL_PATH/ChaosGame/CookedPCConsole/VIKTOR_ASSETS_SF.upk"

# Search for pawn export definitions
rea search --pattern "TgPawn_" "$PALADINS_INSTALL_PATH/ChaosGame/CookedPCConsole/VIKTOR_ASSETS_SF.upk"
```

---

## 6. Champion Contribution Checklist

Before submitting a champion integration PR, ensure every step is checked:

- [ ] **Asset Discovery**: Verified UPK and TFC locations in legally acquired client.
- [ ] **Native REA Inspection**: Export table inspected natively; findings recorded.
- [ ] **Obligations Ledger**: New claim recorded in `.agents/ledger/obligations.json`.
- [ ] **Core Registration**: `ChampionId` enum and helper methods updated in `immortal-core`.
- [ ] **Sub-Second Tests**: `cargo test --workspace` passes hermetically in <0.5s.
- [ ] **Cleanroom Verification**: `agyis verify` passes with exit code 0.
- [ ] **DCO Sign-off**: Commit signed off with `git commit -s`.
