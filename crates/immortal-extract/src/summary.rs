// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 CookedPCConsole Package Summary reader and writer.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::chunk::FCompressedChunk;
use crate::error::ExtractError;
use crate::fstring::{read_fstring, write_fstring};
use crate::UPK_MAGIC;

/// Package flags bitfield definitions
/// In UE3 CookedPCConsole packages, `PKG_Cooked` is `0x00000008`.
/// In UE4 / transitional specs, `PKG_Cooked` is `0x00000200`.
pub const PKG_COOKED: u32 = 0x00000008;
pub const PKG_COOKED_UE4: u32 = 0x00000200;
pub const PKG_COMPRESSED: u32 = 0x02000000;

/// Generation information entry in the package header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenerationInfo {
    pub export_count: i32,
    pub name_count: i32,
    pub net_object_count: i32,
}

impl GenerationInfo {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let export_count = reader.read_i32::<LittleEndian>()?;
        let name_count = reader.read_i32::<LittleEndian>()?;
        let net_object_count = reader.read_i32::<LittleEndian>()?;
        Ok(Self {
            export_count,
            name_count,
            net_object_count,
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_i32::<LittleEndian>(self.export_count)?;
        writer.write_i32::<LittleEndian>(self.name_count)?;
        writer.write_i32::<LittleEndian>(self.net_object_count)?;
        Ok(())
    }
}

/// Unreal Engine 3 CookedPCConsole Package Summary (`FPackageFileSummary`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageSummary {
    pub tag: u32,
    pub file_version: u16,
    pub licensee_version: u16,
    pub total_header_size: u32,
    pub folder_name: String,
    pub package_flags: u32,
    pub name_count: u32,
    pub name_offset: u32,
    pub export_count: u32,
    pub export_offset: u32,
    pub import_count: u32,
    pub import_offset: u32,
    pub depends_offset: u32,
    pub import_export_guids_offset: u32,
    pub import_guids_count: u32,
    pub export_guids_count: u32,
    pub thumbnail_table_offset: u32,
    pub guid: [u8; 16],
    pub generations: Vec<GenerationInfo>,
    pub engine_version: u32,
    pub cooker_version: u32,
    pub compression_flags: u32,
    pub compressed_chunks: Vec<FCompressedChunk>,
}

impl PackageSummary {
    /// Returns true if the package summary has a valid UE3 magic tag.
    pub fn has_valid_magic(&self) -> bool {
        self.tag == UPK_MAGIC
    }

    /// Returns true if `PKG_Cooked` is set in `package_flags`.
    pub fn is_cooked(&self) -> bool {
        (self.package_flags & (PKG_COOKED | PKG_COOKED_UE4)) != 0
    }

    /// Returns true if `PKG_Compressed` is set in `package_flags`.
    pub fn is_compressed(&self) -> bool {
        (self.package_flags & PKG_COMPRESSED) != 0
    }

    /// Reads a CookedPCConsole package summary from a stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let tag = reader.read_u32::<LittleEndian>()?;
        if tag != UPK_MAGIC {
            return Err(ExtractError::InvalidMagic {
                expected: UPK_MAGIC,
                found: tag,
            });
        }

        let file_version = reader.read_u16::<LittleEndian>()?;
        let licensee_version = reader.read_u16::<LittleEndian>()?;
        let total_header_size = reader.read_u32::<LittleEndian>()?;

        let folder_name = read_fstring(reader)?;
        let package_flags = reader.read_u32::<LittleEndian>()?;

        let name_count = reader.read_u32::<LittleEndian>()?;
        let name_offset = reader.read_u32::<LittleEndian>()?;
        let export_count = reader.read_u32::<LittleEndian>()?;
        let export_offset = reader.read_u32::<LittleEndian>()?;
        let import_count = reader.read_u32::<LittleEndian>()?;
        let import_offset = reader.read_u32::<LittleEndian>()?;

        let depends_offset = reader.read_u32::<LittleEndian>()?;
        let import_export_guids_offset = reader.read_u32::<LittleEndian>()?;
        let import_guids_count = reader.read_u32::<LittleEndian>()?;
        let export_guids_count = reader.read_u32::<LittleEndian>()?;
        let thumbnail_table_offset = reader.read_u32::<LittleEndian>()?;

        let mut guid = [0u8; 16];
        reader.read_exact(&mut guid)?;

        let generation_count = reader.read_i32::<LittleEndian>()?;
        let mut generations = Vec::with_capacity(generation_count.max(0) as usize);
        for _ in 0..generation_count {
            generations.push(GenerationInfo::read(reader)?);
        }

        let engine_version = reader.read_u32::<LittleEndian>()?;
        let cooker_version = reader.read_u32::<LittleEndian>()?;

        let is_comp = (package_flags & PKG_COMPRESSED) != 0;

        let (compression_flags, compressed_chunks) = if is_comp {
            let flags = reader.read_u32::<LittleEndian>()?;
            let chunk_count = reader.read_i32::<LittleEndian>()?;
            let count = chunk_count.max(0) as usize;
            let mut chunks = Vec::with_capacity(count);
            for _ in 0..count {
                chunks.push(FCompressedChunk::read(reader)?);
            }
            (flags, chunks)
        } else {
            (0u32, Vec::new())
        };

        Ok(Self {
            tag,
            file_version,
            licensee_version,
            total_header_size,
            folder_name,
            package_flags,
            name_count,
            name_offset,
            export_count,
            export_offset,
            import_count,
            import_offset,
            depends_offset,
            import_export_guids_offset,
            import_guids_count,
            export_guids_count,
            thumbnail_table_offset,
            guid,
            generations,
            engine_version,
            cooker_version,
            compression_flags,
            compressed_chunks,
        })
    }

    /// Writes the package summary to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.tag)?;
        writer.write_u16::<LittleEndian>(self.file_version)?;
        writer.write_u16::<LittleEndian>(self.licensee_version)?;
        writer.write_u32::<LittleEndian>(self.total_header_size)?;

        write_fstring(writer, &self.folder_name, false)?;
        writer.write_u32::<LittleEndian>(self.package_flags)?;

        writer.write_u32::<LittleEndian>(self.name_count)?;
        writer.write_u32::<LittleEndian>(self.name_offset)?;
        writer.write_u32::<LittleEndian>(self.export_count)?;
        writer.write_u32::<LittleEndian>(self.export_offset)?;
        writer.write_u32::<LittleEndian>(self.import_count)?;
        writer.write_u32::<LittleEndian>(self.import_offset)?;

        writer.write_u32::<LittleEndian>(self.depends_offset)?;
        writer.write_u32::<LittleEndian>(self.import_export_guids_offset)?;
        writer.write_u32::<LittleEndian>(self.import_guids_count)?;
        writer.write_u32::<LittleEndian>(self.export_guids_count)?;
        writer.write_u32::<LittleEndian>(self.thumbnail_table_offset)?;

        writer.write_all(&self.guid)?;

        writer.write_i32::<LittleEndian>(self.generations.len() as i32)?;
        for gen in &self.generations {
            gen.write(writer)?;
        }

        writer.write_u32::<LittleEndian>(self.engine_version)?;
        writer.write_u32::<LittleEndian>(self.cooker_version)?;

        if self.is_compressed() {
            writer.write_u32::<LittleEndian>(self.compression_flags)?;
            writer.write_i32::<LittleEndian>(self.compressed_chunks.len() as i32)?;
            for chunk in &self.compressed_chunks {
                chunk.write(writer)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::COMPRESS_LZO;
    use std::io::Cursor;

    #[test]
    fn test_package_summary_roundtrip() {
        let summary = PackageSummary {
            tag: UPK_MAGIC,
            file_version: 893,
            licensee_version: 0,
            total_header_size: 1024,
            folder_name: "None".to_string(),
            package_flags: PKG_COOKED | PKG_COMPRESSED,
            name_count: 50,
            name_offset: 500,
            export_count: 10,
            export_offset: 600,
            import_count: 5,
            import_offset: 700,
            depends_offset: 800,
            import_export_guids_offset: 900,
            import_guids_count: 0,
            export_guids_count: 0,
            thumbnail_table_offset: 0,
            guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            generations: vec![GenerationInfo {
                export_count: 10,
                name_count: 50,
                net_object_count: 0,
            }],
            engine_version: 10897,
            cooker_version: 393358,
            compression_flags: COMPRESS_LZO,
            compressed_chunks: vec![FCompressedChunk {
                uncompressed_offset: 500,
                uncompressed_size: 2048,
                compressed_offset: 1024,
                compressed_size: 512,
            }],
        };

        let mut buf = Vec::new();
        summary.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = PackageSummary::read(&mut cursor).unwrap();

        assert_eq!(summary, parsed);
        assert!(parsed.has_valid_magic());
        assert!(parsed.is_cooked());
        assert!(parsed.is_compressed());
    }
}
