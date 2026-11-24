<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->
<!-- Invariant: PSL-INV-007 (Universal Cleanroom Reverse Engineering Standard) -->
<!-- Invariant: PSL-INV-012 (Anti-Guess, Absolute Truth & Zero-Facade Invariant) -->

# Paladins UE3 v893 `UActorChannel`, `UPackageMap`, `FClassNetCache`, and `.upk` Replication Wire Specification

> **Document Standard**: `SPEC-2026-IMMORTAL-UACTOR-001`  
> **Related Obligations**: `OBL-UDP-003` (`UNK-UDP-003`), `OBL-UDP-004` (`UNK-UDP-004`)  
> **Binary Authority (`EV-BIN-001`)**: `ShippingPC-ChaosGame.exe` (Paladins `8.1.5839.0`, PE32+ x86_64, SHA-256 `0c51d381dfe9ecbc1f571ab36603478626375704f4e4e40482524a1adafd6f75`)  
> **Package Authority (`EV-UPK-006`, `EV-UPK-007`)**:  
> - `Engine.upk` (UE3 v893, licensee `0`, cooker `393358`, `3,813,766` bytes, SHA-256 `c8541aa0ab647d1952da0cbd0c7c36e236fcc1b6f12f48b6fc047bae19e91e48`)  
> - `TgGame.upk` (UE3 v893, licensee `0`, cooker `393358`, `9,672,524` bytes, SHA-256 `dd1fa76a3583c64305a305f7d7177c441356463f31a2531bb25d1bf0921bdbf8`)  
> **Empirical Parity Proof**: Verified bit-exact (`0` leftover bits, `0` parse errors) against live headless Wine Retail Oracle (`ADOPT-09`, `?exudp=0`) bunches (`ch=3, 4, 5, 12, 13, 80, 81`) captured in `oracle_probe_trace.json` (`464,255` bytes, SHA-256 `d57c83353cf4fa531d8b546885b5726b9a9b2a0fc50170430ac28a93e404564e`) and full-session `CAP-04` (`EV-PCAP-004`, `3,912` UDP 7000 datagrams; `3,898/3,898` non-empty decoded, `91/91` S->C channels `ch=3..93` & `907/907` S->C bunches, `2,785/2,785` C->S bunches, `0` errors), plus `1,895/1,895` Flight 036 C->S bunches.  
> **Current Status**: **Flight 036 Core Verified Live** — `crates/immortal-extract`, `crates/immortal-net`, and `crates/immortal-server` emit bit-exact `UActorChannel` opens (`ch=3, 4, 57, 61, 80, 81`) accepted by retail `8.1.5839.0` with `0` errors, live Scaleform HUD (`UIHudCredits` `500` + crosshair), and decoded inbound C->S RPCs. Remaining M6 follow-ups: external archway Fernando skin (`FERNANDO_ASSETS_SF` manifest) and interactive `PlayerWalking` (`Hard(915)`) pawn possession.

---

## 1. `UActorChannel` Bitstream Framing & Channel Open Header

*(Derived from `UActorChannel::ReceivedBunch` `0x140b33b30` and `UActorChannel::ReplicateActor` `0x140b379f0`.)*

### 1.1 Exact Bit Order on Channel Open (`bOpen = 1`, `ChType = 2`, `Actor == NULL`)

```text
Bit Offset  Field                       Encoding / Condition
----------  --------------------------  --------------------------------------------------------
[0]         bDynamicActor               1 bit (UPackageMapLevel::SerializeObject, 0x140b569e0)
                                          0 = Static object / Archetype / CDO:
                                              ObjectRef = SerializeInt(0x80000000) [30..31 bits]
                                          1 = Existing Channel Actor:
                                              ChIndex   = SerializeInt(0x800)      [10..11 bits]
            (Note: under -SEEKFREEPACKAGEMAP, UPackageMapSeekFree encodes i32 LE + optional FString)

--- IFF resolved UObject has (ObjectFlags & 0x600) != 0 (RF_ClassDefaultObject=0x200 | RF_ArchetypeObject=0x400) ---
            Location                    SerializeCompressedVector (0x1401a1ee0) [always present for spawned]
            [Optional] Rotation         IFF Actor->bNetInitialRotation is set on Archetype:
                                          SerializeCompressedRotator (0x1401a1dc0) [3..27 bits]
            [NO Velocity in header]     Spawn header serializes ONLY Location and conditional Rotation.
                                        Velocity is replicated as a normal FClassNetCache property (RepIndex=23).

--- Always binds Actor via UActorChannel::SetChannelActor (0x140b3d430) ---
            [Optional] NetPlayerIndex   IFF Actor->GetAPlayerController() != NULL:
                                          u8 NetPlayerIndex (8 bits):
                                            0   -> ServerConnection->HandleClientPlayer(PC)
                                            > 0 -> Child split-screen connection index (NetPlayerIndex - 1)

--- Property & RPC Replication Loop (repeats until BitReader reaches end / IsError) ---
            RepIndex                    SerializeInt(MaxIndex), MaxIndex = Cache->FieldsBase + Cache->FieldsNum
            ...                         (see Section 3)
```

### 1.2 Exact Bit-Level Encodings of Sub-Primitives

1. **`FBitWriter::WriteInt` (`0x14018cb40`) / `FBitReader::SerializeInt` (`0x140181d60`)**:
   - Variable-width LSB-first unsigned integer bounded by `Max`:
     ```python
     val, mask = 0, 1
     while val + mask < Max:
         if read_bit(): val += mask
         mask <<= 1
     ```
   - **Width trap**: For `Max = 20`, values `0..3` take **5 bits** (`16 + val < 20`), whereas values `4..19` take **4 bits** (`16 + val >= 20`). For `Max = 0x80000000`, values `< 0x40000000` take **31 bits** (total `1 + 31 = 32` bits for static `SerializeObject`).

2. **`SerializeCompressedVector` (`0x1401a1ee0`)**:
   - The wire header writes **`BitsMinus1 = Bits - 1`** (`0..19`) using **`SerializeInt(BitsMinus1, 20)`**, NOT `Bits`.
   - `Bias = 1 << (BitsMinus1 + 1)`
   - `Max  = 1 << (BitsMinus1 + 2)`
   - `X = float(SerializeInt(Max) - Bias)`
   - `Y = float(SerializeInt(Max) - Bias)`
   - `Z = float(SerializeInt(Max) - Bias)`
   - Used for **both** spawn `Location` in `bOpen = 1` AND every `FVector` `StructProperty` (`Actor.Location`, `Actor.Velocity`, `Pawn.TakeHitLocation`, etc.).

3. **`SerializeCompressedRotator` (`0x1401a1dc0`)**:
   - Component order: **Pitch**, **Yaw**, **Roll**.
   - For each component: `1 bit bNonZero`; if `1`, `1 byte u8` (`Component >> 8`, restored as `(u32)byte << 8`).
   - **Retail observation (`Shootingrange_P`)**: `TgPlayerController`, `TgPawn_Fernando`, `TgPawn_Viktor`, `TgPawn_Ying`, `MatineeActor`, `TgRepInfo_Player`, and `TgRepInfo_Game` all have `bNetInitialRotation = 0` (`has_rot = false` in `bOpen = 1`), replicating initial rotation instead via `Actor.Rotation` (`RepIndex = 22`).

---

## 2. `UPackageMap`, `NMT_Uses*`, `NMT_Have`, and Channel 1 `UMarshalChannel`

### 2.1 `UPackageMap::SerializeObject` Modes

| Mode | Authority VAs | `SerializeObject` Wire Format | `SerializeName` Wire Format |
| :--- | :--- | :--- | :--- |
| **`UPackageMapLevel`** *(retail default)* | `0x140b569e0`, `0x140189960`, `0x14018c3c0` | `1 bit bDyn`: `0` -> `SerializeInt(ObjIdx, 0x80000000)`; `1` -> `SerializeInt(ChIdx, 0x800)` | `1 bit bHardcoded` (`NameIndex < 0x4e3`): `1` -> `SerializeInt(NameIndex, 0x4e3)` (`MAX_NETNAME_INDEX = 1251`); `0` -> `FString NameStr` + `i32 Number` (`4B LE`) |
| **`UPackageMapSeekFree`** *(`-SEEKFREEPACKAGEMAP`)* | `0x140b56e60`, `0x140b56840`, `0x140071f50` | `i32 Val` (4B LE): `0` = NULL, `-1` + `FString Path` (`StaticFindObject`), `1..2047` = `ChIndex` | `FString` + `i32 Number` |

- **`UPackageMapLevel` Index Resolution (`0x14017bfa0`, `0x140180080`, `0x140174d90`)**:
  - `PackageMap->List` stores `FPackageInfo` entries containing `PackageName` (`FName`), `Linker` (`ULinkerLoad*`), `Guid` (`FGuid`, 16 bytes), `ObjectBase` (`i32`, cumulative sum of preceding entries' `ObjectCount`), `ObjectCount` (`i32`, `min(Linker.Summary.Generations[LocalGen - 1].NetObjectCount, ...)`), `LocalGeneration` (`i32`), and `RemoteGeneration` (`i32`, forced to `1` for `0x2C`/`0x2D` per `0x140b31b70`).
  - Every `UObject` with `NetIndex >= 0` maps to `Info.ObjectBase + Obj.NetIndex`.

### 2.2 `NMT_Uses` (`0x07`) / `NMT_UsesOpt` (`0x2C`) / `NMT_UsesOptEx` (`0x2D`) / `NMT_Have` (`0x08`) / `NMT_DownloadMgr` (`0x0B`)

| Opcode | Name | Authority VA | Wire Payload Fields (After 1-Byte Opcode) |
| :---: | :--- | :--- | :--- |
| `0x07` | `NMT_Uses` | `0x140b26ec0` | `FGuid (4×u32)`, `FString PackageName`, `FString Extension`, `FString URL`, `u32 PackageFlags`, `u32 RemoteGeneration`, `FString LocalPackageName`, `u8 bLoadingFromCache` |
| `0x2C` | `NMT_UsesOpt` | `0x140b27810` | `FGuid (4×u32)`, `FString PackageName`, `u32 PackageFlags`, `i32 CachedExtIndex` (`-1` = none; else index into cached parent extension table populated by `0x2D`) |
| `0x2D` | `NMT_UsesOptEx` | `0x140b27940` | `FGuid (4×u32)`, `FString PackageName`, `u32 PackageFlags`, `i32 GenOrFlags`, `FString ExtensionOrParent` (appended to extension table; maps forced-export subpackage `PackageName -> ExtensionOrParent` in `0x140b4deb0` via `0x140b57220` so `Linker` loads from the parent `.upk`) |
| `0x08` | `NMT_Have` | `0x14058adb0` | `FGuid (4×u32)`, `i32 Generation` (`4B LE`) |
| `0x0B` | `NMT_DownloadMgr` | `oracle_probe_trace.json` | `FString ClassName`, `FString Params`, `u32 bCompression` (4-byte LE UE3 `UBOOL`, verified empirically in `oracle_probe_trace.json`) |

- **Empirical `NMT_Have` Gate**: Client emits `NMT_Have` per package received in `0x07`/`0x2C`/`0x2D`. Without client `NMT_Have`, retail server logs `Join succeeded` after `NMT_Join` but stalls emitting only keepalives.
- **Package Ordering Before `NMT_Welcome` -> `0x2A` -> `NMT_Join`**:
  - Under `UPackageMapLevel`, the server MUST send `NMT_Uses`/`0x2C`/`0x2D` **before `NMT_Welcome`** covering every package whose `UClass`es, `UProperty`/`UFunction` `FClassNetCache` fields, `Archetype`s (`Default__*`), or static level actors are referenced by `SerializeObject`.
  - **Minimal Shooting Range core set** (verified from `oracle_probe_trace.json`):
    1. `Core.upk` (`NetObjectCount = 1562`)
    2. `Engine.upk` (`NetObjectCount = 35793`)
    3. `GFxUI.upk` (`901`), `GameFramework.upk` (`3838`), `PlatformCommon.upk` (`1247`), `Vivox.upk` (`64`), `AkAudio.upk` (`98`) *(required where superclass/import chains cross them; e.g. `PComPlayerController` inherits from `PlatformCommon`)*
    4. `TgGame.upk` (`NetObjectCount = 66967`)
    5. `Shootingrange_P.upk` (`NetObjectCount = 1038`) + streamed sublevels if referenced (`TRM_Courtyard_ABC`, `TRM_Room_D`, `TRM_Room_E-Room_G`, `TRM_Room_F-Hallway`, `TRM_Sky`)
  - *Note*: Retail Oracle sends `281` packages (`254 × 0x2C` + `27 × 0x2D`, including forced-export `0x20000001` subpackages whose server-side `NetObjectCount` offsets subsequent `ObjectBase` values). A cleanroom server sending only the minimal `.upk` list computes deterministic `ObjectBase` offsets directly from those `.upk` headers.

### 2.3 Channel 1 (`UMarshalChannel`, `CHTYPE_Marshal = 5`, Opcode `0x27`)

- Pre-allocated locally on `Channels[1]`; **not required before or during map join** (`0` Channel 1 bunches emitted in `oracle_probe_trace.json` through 91 actor opens).
- **`0x27` Wire Layout (`0x140d50310`)**:
  - When `BytesRemaining == 0`: `SerializeInt(TotalSize, 0x80000)` (19-bit max; rejected if `> 0x800000`).
  - Always: `SerializeInt(ChunkSize, 0x200)` (9-bit max; sender caps `<= 0x1cc`), followed by `ChunkSize` raw bytes.
- Server must never send `bOpen = 1` on `ChIndex = 1, ChType = 5` (`UWorld::NotifyAcceptingChannel` `0x140853100` refuses any server-opened channel except `CHTYPE_Actor = 2`).

---

## 3. `FClassNetCache` & Property / RPC Replication Stream

### 3.1 Construction & `RepIndex` Assignment (`0x14017e0b0`, `0x14016d0f0`, `0x140178630`, `0x140b297b0`)

1. **`UClass::Link` (`0x14017e0b0`)** constructs `UClass::NetFields`:
   - Walks `Class->Children`, collecting every `UProperty` with `CPF_Net` (`0x20`) and every **base** `UFunction` with `FUNC_Net` (`0x40`) where `Func->SuperField == NULL`.
   - Sorts `NetFields` in **strictly ascending order of `UObject::NetIndex`** (`0x14016d0f0`).
2. **`UPackageMap::GetClassNetCache(UClass*)` (`0x140178630`)**:
   - Recursively builds `SuperCache = GetClassNetCache(Class->SuperClass)`.
   - Sets `FieldsBase = SuperCache.FieldsBase + SuperCache.FieldsNum`.
   - Appends `FFieldNetCache { UField* Object, i32 FieldNetIndex, i32 ConditionIndex }` for each `Field` in `Class.NetFields` where `PackageMap->SupportsObject(Field)` is true.
   - `MaxIndex = cache.FieldsBase + cache.FieldsNum`.
3. **`FClassNetCache::GetFromIndex(RepIndex)` (`0x140b297b0`)**:
   - Walks `cache -> Super` until `FieldsBase <= RepIndex < FieldsBase + FieldsNum`.

### 3.2 Wire Dispatch: Property vs. RPC, `ArrayIndex`, `bHasRepCondition`

*(From `UActorChannel::ReceivedBunch` `0x140b33b30` and `ReplicateActor` `0x140b379f0`.)*

1. Read `RepIndex = SerializeInt(MaxIndex)`.
2. Inspect `Field->Class->ClassFlags`:
   - **Property (`ClassFlags & 0x8000 != 0`)**:
     - **`ArrayIndex`**: Iff `Prop.ArrayDim != 1`, read **`u8 ArrayIndex`** (8 bits). If `ArrayDim == 1`, **0 bits** are read (`ArrayIndex = 0`). *(Static arrays only; 0 `ArrayProperty` exports carry `CPF_Net` in `Engine.upk` / `TgGame.upk`.)*
     - **`bHasRepCondition`**: **NOT transmitted on the wire.** `ConditionIndex` is server-internal only (`0x140b379f0`).
     - **`NetSerializeItem` Value Encoding**:

| Unreal Property Class | Wire Bit Layout |
| :--- | :--- |
| `BoolProperty` | **1 bit** |
| `ByteProperty` | `SerializeInt(Val, Enum.Names.Num())` if `Enum != NULL`, else **8 bits (`u8`)** |
| `IntProperty` | `i32` (**32 bits LE**) |
| `FloatProperty` | `f32` (**32 bits LE**) |
| `ObjectProperty` / `ClassProperty` | `UPackageMap::SerializeObject` |
| `NameProperty` | `UPackageMap::SerializeName` (`1 bit bHardcoded` + `SerializeInt(0x4e3)` or `FString + i32`) |
| `StrProperty` | `FString` (`i32 Len` + chars) |
| `StructProperty` (`FVector`) | `SerializeCompressedVector` |
| `StructProperty` (`FRotator`) | `SerializeCompressedRotator` |
| `StructProperty` (`FUniqueNetId`) | `8 bytes` (64 bits) |
| `StructProperty` (other `UScriptStruct`) | Inner fields serialized sequentially in `Children -> Next` order (static arrays loop `0..ArrayDim - 1` without `u8 ArrayIndex`) |

   - **RPC (`ClassFlags & 0x80000 != 0`)**:
     - Iterates `Func.Children` parameters where `(PropertyFlags & 0x480) == 0x80` (`CPF_Parm` and `!CPF_ReturnParm`) and `PackageMap.SupportsObject(Prop)` is true:
       - **Presence bit**: If `UBoolProperty` (`ClassFlags & 0x20000 != 0`), **no presence bit** (1-bit value always serialized); otherwise **1 bit `bHasParam`** (if `1`, serializes all `ArrayDim` elements via `NetSerializeItem` without `u8 ArrayIndex`).
     - Server inbound RPCs pass through `0x140d96030` (`FUNC_Net = 0x40`, `FUNC_NetServer = 0x200000`, `FUNC_NetClient = 0x1000000`, registered RPC table, and rate limiter).

---

## 4. UE3 v893 `.upk` Binary Serialization for `immortal-extract`

Verified across **all** `23,294 + 38,009 = 61,303` Property exports and `5,250 + 13,796 = 19,046` Function exports in `Engine.upk` (`EV-UPK-006`) and `TgGame.upk` (`EV-UPK-007`) with **0 parse failures**:

1. **Chunk Compression Flag `0x200` (`0x202`)**:
   - Both `Engine.upk` and `TgGame.upk` use `compression_flags = 0x202` (`COMPRESS_LZO | 0x200`). Every compressed block payload must be XORed byte-wise with **`0x2A`** before `lzo1x_decompress_safe` (when `compressed_size < uncompressed_size`).

2. **`UProperty` Export Layout (starting at `serial_offset`)**:

| Offset | Size | Field | Notes |
| :--- | :---: | :--- | :--- |
| `+0x00` | `4B` | `i32 NetIndex` | Exact sort key for `UClass::NetFields` |
| `+0x04` | `8B` | `FName` | Typically `None` |
| `+0x0c` | `4B` | `i32 Next` | `PackageIndex` (`UField::Next`) |
| `+0x10` | `2B` | `u16 ArrayDim` | Static array dimension (`1` for scalar) |
| `+0x12` | `2B` | `u16 ElementSizeFlags` | Element size / flags |
| `+0x14` | `8B` | `u64 PropertyFlags` | `0x20 = CPF_Net`, `0x80 = CPF_Parm`, `0x400 = CPF_ReturnParm`, `0x100000000 = CPF_RepNotify` |
| `+0x1c` | `8B` | `FName Category` | Property category |
| `+0x24` | `4B` | `i32 ArraySizeEnum` | `PackageIndex` |
| `+0x28` | `2B` | `u16 RepOffset` | **Conditional**: present iff `PropertyFlags & 0x20 != 0` |
| *Tail* | *Var* | Subclass-specific tail | `Int`/`Float`/`Bool`/`Str`/`NameProperty`: `0B`; `ByteProperty`: `i32 Enum` (`4B`); `Object`/`Component`/`InterfaceProperty`: `i32 PropertyClass` (`4B`); `StructProperty`: `i32 Struct` (`4B`); `ArrayProperty`: `i32 Inner` (`4B`); `ClassProperty`: `i32 PropertyClass` (`4B`) + `i32 MetaClass` (`4B`); `DelegateProperty`: `i32 Function` (`4B`) + `i32 SourceDelegate` (`4B`) |

3. **`UFunction` Export Layout (starting at `serial_offset`)**:

| Offset | Size | Field | Notes |
| :--- | :---: | :--- | :--- |
| `+0x00` | `4B` | `i32 NetIndex` | Sort key for `UClass::NetFields` |
| `+0x04` | `8B` | `FName` | Typically `None` |
| `+0x0c` | `4B` | `i32 Next` | `PackageIndex` (`UField::Next`) |
| `+0x10` | `4B` | `i32 SuperField` | `PackageIndex`; **`0` iff base declaration included in `NetFields`** |
| `+0x14` | `4B` | `i32 ScriptText` | `PackageIndex` |
| `+0x18` | `4B` | `i32 Children` | `PackageIndex` |
| `+0x1c` | `4B` | `i32 CppText` | `PackageIndex` |
| `+0x20` | `4B` | `i32 Line` | Source line |
| `+0x24` | `4B` | `i32 TextPos` | Text offset |
| `+0x28` | `4B` | `i32 ScriptBytecodeSize` | Unserialized bytecode length |
| `+0x2c` | `4B` | `i32 ScriptStorageSize` | Serialized bytecode length |
| `+0x30` | `ScriptStorageSize` | UE3 Script Bytecode | Raw bytecode payload |
| *Tail* | `2B + 1B + 4B` | `u16 iNative`, `u8 OperPrecedence`, `u32 FunctionFlags` | `0x40 = FUNC_Net`, `0x200000 = FUNC_NetServer`, `0x1000000 = FUNC_NetClient` |
| *Cond.* | `2B` | `u16 RepOffset` | Present iff `FunctionFlags & 0x40 != 0` |
| *End* | `8B` | `FName FriendlyName` | Function friendly name |

4. **`UEnum` Export Layout**:
   - `+0x00` (`4B`) `i32 NetIndex`, `+0x04` (`8B`) `FName(None)`, `+0x0c` (`4B`) `i32 Next`, `+0x10` (`4B`) `i32 Count`, followed by `Count × FName`.

---

## 5. Empirical Verification Results Against Retail Oracle (`oracle_probe_trace.json`)

Verified bit-exact (`0` leftover bits, `0` parse errors) against live headless Wine Retail Oracle bunches (`ADOPT-09`, `?exudp=0`):

| Channel | Class | Total Bits | Decoded Bits | Key Verified Fields |
| :---: | :--- | :---: | :---: | :--- |
| **`ch=3`** | `TgPlayerController` | `3203` | **`3203/3203`** | `loc=(-224,0,203)`, `npc=0`, `Role=ROLE_AutonomousProxy(2)`, `r_bInputEnabled[0..19]=1`, `ClientCapBandwidth(24000)`, `9× ClientUpdateLevelStreamingStatus`, `ClientGotoState` |
| **`ch=3`** *(updates)* | `TgPlayerController` | `41` / `62` | **`41/41`** | `RepIndex=291` `r_fServerTimeStamp=183.3048..183.5270`; `RepIndex=29` `PlayerReplicationInfo=chan(80)` |
| **`ch=4`** | `TgPawn_Fernando` | `2413` | **`2413/2413`** | `loc=(1890,239,259)`, `Rotation=(0,64512,0)`, `Physics=PHYS_Walking(1)`, `Health=4600`, `r_nPawnId=64`, `r_nProfileId=2071`, `r_fCachedMaxHealth=4600.0` |
| **`ch=5`** | `MatineeActor` | `160` | **`160/160`** | `loc=(0,0,0)`, `InterpAction`, `bIsPlaying=True`, `PlayRate=1.75`, `Position=8.5931` |
| **`ch=12`** | `TgPawn_Viktor` | `2525` | **`2525/2525`** | `loc=(254,-1969,254)`, `Rotation=(0,16384,0)`, `Health=2200`, `r_nPawnId=50`, `r_nProfileId=2285` |
| **`ch=13`** | `TgPawn_Ying` | `2525` | **`2525/2525`** | `loc=(4,-1977,249)`, `Rotation=(0,16384,0)`, `Health=2200`, `r_nPawnId=36`, `r_nProfileId=2267` |
| **`ch=80`** | `TgRepInfo_Player` | `318` | **`318/318`** | `PlayerName="Player"`, `StartTime=183`, `PlayerID=257`, `r_nCredits=500`, `r_nEarnedCredits=500` |
| **`ch=81`** | `TgRepInfo_Game` | `1224` | **`1224/1224`** | `bMatchHasBegun=True`, `ElapsedTime=183`, `r_DifficultyDebugData`, `r_fPlayerViewDistance=7200.0`, `r_GameType=7` |

---

## 6. Empirically Decoded `CAP-04` S->C HUD/State & C->S Inbound RPCs

Verified bit-exact (`0` errors, `0` leftover bits) across `CAP-04` (`EV-PCAP-004`, `3,912` UDP 7000 datagrams, `91/91` S->C channels `ch=3..93`, `907/907` S->C bunches, `2,785/2,785` C->S bunches) and Flight 036 (`1,895/1,895` C->S bunches).

### 6.1 S->C `ch=3` `TgPlayerController` HUD, Streaming & State RPCs (`MaxIndex = 303`)

In `CAP-04` Frame 713 (`bOpen=1`, `3203/3203` bits), after replicating `bCollideWorld=True` (`Rep=2`), `Role=ENetRole(2)` (`Rep=13`), `bNetOwner=True` (`Rep=5`), and `r_bInputEnabled[0..19]=1` (`Rep=292`), the server emits these RPCs in wire order:

| `RepIndex` | RPC Signature | Observed `CAP-04` Wire Values & Notes |
| :---: | :--- | :--- |
| `207` | `TgPlayerController.ClientSetReadyState(bReadyToPlay: Bool)` | `False` |
| `71` | `PlayerController.ClientCapBandwidth(Cap: Int)` | `25000` |
| `118` | `PlayerController.ClientVoiceHandshakeComplete()` | *(no params)* |
| `45` | `PlayerController.ClientSetHUD(newHUDType: Class)` | `Static(89536)` (`TgGame` `NetIndex=45835` -> `TgGame.TgHUD`; initializes Scaleform `UIHud`, `UIHudCredits` `500`, `UIHudCenter`, `UIWorldOverlay`, `Cursor`) |
| `46` | `PlayerController.ClientSetSecondaryHUD(newHUDType: Class)` | `bHasParam=0` (omitted) |
| `109` | `PlayerController.ClientUpdateLevelStreamingStatus(PackageName: Name, ...)` | 9× (`shootingrange_{lighting,collision,vfx,sound}`, `trm_{courtyard_abc,room_d,room_e-room_g,room_f-hallway,sky}`), `bHardcoded=0`, `number=0`, `3 × Bool(False)` |
| `114` | `PlayerController.ClientFlushLevelStreaming()` | *(no params)* |
| `117` | `PlayerController.ClientSetOnlineStatus()` | *(no params)* |
| `131` | `PlayerController.ClientStartNetworkedVoice()` | *(no params)* |
| `41` | `PlayerController.ClientGotoState(NewState: Name, NewLabel: Name)` | `NewState=Hard(920)` (`"Spectating"`), `NewLabel` omitted (`bHasParam=0`); also re-sent every `2.00s` (`bReliable=1`, `22` bits) |

- **Hardcoded `ClientGotoState` FName Indices** (`ShippingPC-ChaosGame.exe` `0x1401dc332..0x1401dc3e1`):
  - `915` (`0x393`) = `"PlayerWalking"`
  - `920` (`0x398`) = `"Spectating"`
  - `921` (`0x399`) = `"PlayerWaiting"`
  - `922` (`0x39a`) = `"WaitingForPawn"`

### 6.2 C->S Inbound Actor Channel RPCs (`CAP-04` `ch=3, 87` & Flight 036 `ch=3, 80`)

| Channel | Class | `RepIndex` | RPC Signature | Observed Wire Values & Cadence |
| :---: | :--- | :---: | :--- | :--- |
| `ch=3` | `TgPlayerController` | `95` | `PlayerController.ServerSetSpectatorLocation(NewLoc: FVector)` | `(-224.0, 0.0, 203.0)` (`Bits=8`, paired with `Rep=79` in `84`-bit `CAP-04` / `81`-bit Flight 036 `bReliable=0` bunches) |
| `ch=3` | `TgPlayerController` | `79` | `PlayerController.ServerUpdateCamera(CamLoc: FVector, CamPitchAndYaw: Optional Int)` | `(-474.0, 0.0, 233.0)` (`CAP-04`) / `(0.0, 0.0, 160.0)` (`Flight 036`); `CamPitchAndYaw` omitted (`bHasParam=0`) |
| `ch=3` | `TgPlayerController` | `98` | `PlayerController.ServerViewSelf(TransitionParams: FViewTargetTransitionParams)` | `{BlendTime: 0.0, BlendFunction: 1, BlendExp: 2.0, bLockOutgoing: False}` (`161` bits, followed by `Rep=95`, `Rep=79`) |
| `ch=3` | `TgPlayerController` | `110` | `PlayerController.ServerUpdateLevelVisibility(PackageName: Name, bIsVisible: Bool)` | 9× sublevel names (`bIsVisible=True`, bundled with `Rep=186` `ServerSetToggleZoom(False)` and `Rep=184` `ServerSetAutoPurchase(False)` in `1965`-bit reliable bunch) |
| `ch=3` | `TgPlayerController` | `173` | `TgPlayerController.ServerRequestGraphData()` | `8` bits (`bReliable=1`) |
| `ch=3` | `TgPlayerController` | `38`, `44` | `ServerShortTimeout()`, `ServerAcknowledgePossession(P: Actor)` | Observed in pre-fix Flight 036 when `ch=4` had `Controller=chan(3)` (`112` bits) |
| `ch=87`/`80` | `TgRepInfo_Player` | `26` | `PlayerReplicationInfo.ServerUpdateRemoteUserData(Index: Optional Int, Value: Int)` | `Index` omitted (`bHasParam=0`), 10× (`387`-bit reliable bunch) |
| `ch=87`/`80` | `TgRepInfo_Player` | `25` | `PlayerReplicationInfo.ServerFinalizeRemoteUserData(bGuest: Bool)` | `False` |

> **`PSL-INV-012` Scope Boundary (`OBL-PROP-001` / `UNK-PROP-001`)**: Because `CAP-04` stayed in `Spectating` (`ClientGotoState(Hard(920))`), **0** `ServerMove` (`Rep=65`), `ServerPurchaseItem` (`Rep=165`), or `m_CardDeck` wire payloads fired in `CAP-04`; only their UPK `FClassNetCache` `RepIndex` schemas are extracted.
