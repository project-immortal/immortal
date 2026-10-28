// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Extract
//! Cleanroom Unreal Engine 3 CookedPCConsole Package (`.upk`), Texture File Cache (`.tfc`),
//! and audio asset extractor adhering to the BYOD ("Bring Your Own Data") standard.

pub mod audio;
pub mod chunk;
pub mod error;
pub mod export;
pub mod fstring;
pub mod import;
pub mod index;
pub mod mesh;
pub mod name;
pub mod package;
pub mod summary;
pub mod tfc;
pub mod weapon;

pub use audio::{
    convert_wem_to_wav, create_bkhd, export_to_wav, parse_bkhd, parse_wav, PckArchive, PckEntry,
    SoundBankHeader, WavSpec, AKPK_MAGIC, BKHD_MAGIC,
};
pub use chunk::{
    compress_lzo, compress_zlib, decompress_chunk, decompress_lzo, decompress_zlib,
    write_compressed_chunk, FCompressedChunk, FCompressedChunkBlock, FCompressedChunkHeader,
    COMPRESS_LZMA, COMPRESS_LZO, COMPRESS_ZLIB,
};
pub use error::ExtractError;
pub use export::{ExportTable, ObjectExport};
pub use fstring::{read_fstring, write_fstring};
pub use import::{ImportTable, ObjectImport};
pub use index::PackageIndex;
pub use mesh::{
    convert_coord_ue3_to_gltf, convert_quat_ue3_to_gltf, export_skeletal_mesh_to_gltf, FMeshBone,
    FSkeletalMeshLODModel, GPUSkinVertex, GltfExport, RefSkeleton,
};
pub use name::{FName, NameEntry, NameTable};
pub use package::UpkPackage;
pub use summary::{GenerationInfo, PackageSummary, PKG_COMPRESSED, PKG_COOKED};
pub use tfc::{
    build_dds_header, export_dds, export_dds_with_mips, write_tfc_chunk, FByteBulkData,
    FTexture2DMipMap, TextureFormat, TfcResolver, BULKDATA_COMPRESSED_LZO,
    BULKDATA_COMPRESSED_ZLIB, BULKDATA_STORE_IN_SEPARATE_FILE,
};
pub use weapon::{
    export_weapon_skeletal_mesh, export_weapon_static_mesh, extract_weapon_texture,
    get_weapon_mapping, get_weapon_mapping_for_champion, inspect_weapon_package,
    WeaponAssetInventory, WeaponDeviceMapping, WeaponExtractionPipeline, WeaponMeshExport,
    WeaponTextureExport, CHAMPION_FERNANDO, DEVICE_FERNANDO_FLAME_LANCE, KNOWN_WEAPON_MAPPINGS,
};

/// Unreal Engine 3 UPK magic identifier (`0x9E2A83C1`).
pub const UPK_MAGIC: u32 = 0x9E2A83C1;

/// Lightweight package header summary for backwards compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpkHeader {
    pub tag: u32,
    pub file_version: u16,
    pub license_mode: u16,
    pub package_flags: u32,
}

impl UpkHeader {
    pub fn is_valid_ue3_package(&self) -> bool {
        self.tag == UPK_MAGIC
    }
}

impl From<&PackageSummary> for UpkHeader {
    fn from(summary: &PackageSummary) -> Self {
        Self {
            tag: summary.tag,
            file_version: summary.file_version,
            license_mode: summary.licensee_version,
            package_flags: summary.package_flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upk_magic() {
        let header = UpkHeader {
            tag: UPK_MAGIC,
            file_version: 860,
            license_mode: 0,
            package_flags: 0,
        };
        assert!(header.is_valid_ue3_package());
    }
}
