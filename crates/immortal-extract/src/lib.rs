// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Extract
//! Cleanroom Unreal Engine 3 CookedPCConsole Package (`.upk`), Texture File Cache (`.tfc`),
//! and audio asset extractor adhering to the BYOD ("Bring Your Own Data") standard.

pub mod chunk;
pub mod error;
pub mod export;
pub mod fstring;
pub mod import;
pub mod index;
pub mod name;
pub mod package;
pub mod summary;

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
pub use name::{FName, NameEntry, NameTable};
pub use package::UpkPackage;
pub use summary::{GenerationInfo, PackageSummary, PKG_COMPRESSED, PKG_COOKED};

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
