<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# G1 Specification: Cleanroom Asset Preservation & UPK Extraction Pipeline

## 1. Engine & Package Baseline

- **Target Engine**: Modified Unreal Engine 3 (64-bit architecture, `ChaosGame`).
- **Target Game Version**: `8.1.5839.0` (as verified in `Binaries/GameVersion.txt`).
- **Target Asset Root**: `ChaosGame/CookedPCConsole/`.

## 2. Unreal Package (`.upk`) Binary Specification

### 2.1 Package File Header Structure
Every CookedPCConsole package begins with a standard Unreal package summary:

| Field | Type | Offset | Description / Expected Value |
| :--- | :--- | :--- | :--- |
| `Tag` | `uint32` | `0x00` | Unreal Magic Number: `0x9E2A83C1` |
| `FileVersion` | `uint16` | `0x04` | Package format version (UE3 range: 800–895) |
| `LicenseeVersion` | `uint16` | `0x06` | Hi-Rez customized licensee version |
| `TotalHeaderSize` | `uint32` | `0x08` | Size in bytes of the package header table |
| `FolderName` | `FString` | `0x0C` | Cooked package folder path |
| `PackageFlags` | `uint32` | Variable | Bitflags (e.g. `PKG_Cooked = 0x00000200`, `PKG_Compressed = 0x02000000`) |

### 2.2 Compression Chunks
When `PackageFlags & 0x02000000` (`PKG_Compressed`) is set:
- Header specifies compression format: `COMPRESS_LZO` (`0x02`), `COMPRESS_ZLIB` (`0x01`), or `COMPRESS_LZMA` (`0x04`).
- Compressed packages contain an array of `FCompressedChunk` entries specifying uncompressed offset/size and compressed offset/size.
- The extraction engine reads compressed blocks, passes them to the appropriate decompressor (e.g. minilzo / flate2), and streams the uncompressed payload.

## 3. External Bulk Data & Texture File Cache (`.tfc`)

- High-resolution mipmaps are stripped from individual `.upk` files and stored in monolithic texture caches (`ChaosGame/CookedPCConsole/*.tfc`, e.g. `Textures.tfc`, `Char_Textures.tfc`).
- Package export table contains `FTexture2DMipMap` references pointing to external bulk data with `BulkDataFlags & BULKDATA_PayloadInFile == 0`.
- The extractor resolves the `.tfc` container path, seeks to `BulkDataOffsetInFile`, and reconstructs standard `.dds` / `.png` textures.

## 4. Audio Preservation (FMOD Studio / FSB)

- Audio banks reside in `ChaosGame/CookedPCConsole/*.bank` and embedded SoundNodeWave objects.
- Standard FSB5 format with Vorbis or IMA ADPCM compression.
- Extractor unrolls audio streams into standard `.wav` / `.flac` files locally.
