// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Texture File Cache (`.tfc`) reader, UE3 `FTexture2DMipMap` bulk data parser,
//! and DirectDraw Surface (`.dds`) exporter.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::chunk::{
    compress_lzo, compress_zlib, decompress_lzo, decompress_zlib, FCompressedChunkBlock,
    FCompressedChunkHeader, COMPRESS_ZLIB,
};
use crate::error::ExtractError;
use crate::UPK_MAGIC;

/// Bulk data flags in Unreal Engine 3.
pub const BULKDATA_STORE_IN_SEPARATE_FILE: u32 = 0x0040;
pub const BULKDATA_COMPRESSED_ZLIB: u32 = 0x0002;
pub const BULKDATA_COMPRESSED_LZO: u32 = 0x0010;
pub const BULKDATA_COMPRESSED_LZMA: u32 = 0x0008;
pub const BULKDATA_UNUSED: u32 = 0x0020;

/// DirectDraw Surface (DDS) Magic identifier (`0x20534444` -> `"DDS "`).
pub const DDS_MAGIC: u32 = 0x20534444;

/// DDS Header size (124 bytes).
pub const DDS_HEADER_SIZE: u32 = 124;

/// DDS PixelFormat size (32 bytes).
pub const DDS_PIXELFORMAT_SIZE: u32 = 32;

// DDS Flags
pub const DDSD_CAPS: u32 = 0x00000001;
pub const DDSD_HEIGHT: u32 = 0x00000002;
pub const DDSD_WIDTH: u32 = 0x00000004;
pub const DDSD_PITCH: u32 = 0x00000008;
pub const DDSD_PIXELFORMAT: u32 = 0x00001000;
pub const DDSD_MIPMAPCOUNT: u32 = 0x00020000;
pub const DDSD_LINEARSIZE: u32 = 0x00080000;

// DDS Caps
pub const DDSCAPS_COMPLEX: u32 = 0x00000008;
pub const DDSCAPS_TEXTURE: u32 = 0x00001000;
pub const DDSCAPS_MIPMAP: u32 = 0x00400000;

// DDS Pixel Format Flags
pub const DDPF_ALPHAPIXELS: u32 = 0x00000001;
pub const DDPF_FOURCC: u32 = 0x00000004;
pub const DDPF_RGB: u32 = 0x00000040;

/// FourCC codes for texture formats.
pub const FOURCC_DXT1: u32 = 0x31545844; // "DXT1"
pub const FOURCC_DXT5: u32 = 0x35545844; // "DXT5"
pub const FOURCC_BC7: u32 = 0x00374342;  // "BC7\0"

/// Supported texture formats for DDS export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextureFormat {
    Dxt1,
    Dxt5,
    Bc7,
    Rgba8,
    Bgra8,
}

impl TextureFormat {
    pub fn four_cc(&self) -> Option<u32> {
        match self {
            Self::Dxt1 => Some(FOURCC_DXT1),
            Self::Dxt5 => Some(FOURCC_DXT5),
            Self::Bc7 => Some(FOURCC_BC7),
            Self::Rgba8 | Self::Bgra8 => None,
        }
    }
}

/// UE3 `FByteBulkData` header describing payload storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FByteBulkData {
    pub bulk_data_flags: u32,
    pub element_count: u32,
    pub size_on_disk: u32,
    pub offset_in_file: i64,
}

impl FByteBulkData {
    /// Reads `FByteBulkData` descriptor from a binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let bulk_data_flags = reader.read_u32::<LittleEndian>()?;
        let element_count = reader.read_u32::<LittleEndian>()?;
        let size_on_disk = reader.read_u32::<LittleEndian>()?;
        let offset_in_file = reader.read_i64::<LittleEndian>()?;

        Ok(Self {
            bulk_data_flags,
            element_count,
            size_on_disk,
            offset_in_file,
        })
    }

    /// Writes `FByteBulkData` descriptor to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), ExtractError> {
        writer.write_u32::<LittleEndian>(self.bulk_data_flags)?;
        writer.write_u32::<LittleEndian>(self.element_count)?;
        writer.write_u32::<LittleEndian>(self.size_on_disk)?;
        writer.write_i64::<LittleEndian>(self.offset_in_file)?;
        Ok(())
    }

    /// Returns true if bulk data is stored in an external `.tfc` file.
    pub fn is_separate_file(&self) -> bool {
        (self.bulk_data_flags & BULKDATA_STORE_IN_SEPARATE_FILE) != 0
    }

    /// Returns true if bulk data is compressed with LZO or ZLIB.
    pub fn is_compressed(&self) -> bool {
        (self.bulk_data_flags & (BULKDATA_COMPRESSED_LZO | BULKDATA_COMPRESSED_ZLIB | BULKDATA_COMPRESSED_LZMA)) != 0
    }
}

/// UE3 `FTexture2DMipMap` containing bulk data descriptor and dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTexture2DMipMap {
    pub bulk_data: FByteBulkData,
    pub size_x: u32,
    pub size_y: u32,
    pub inline_data: Option<Vec<u8>>,
}

impl FTexture2DMipMap {
    /// Reads an `FTexture2DMipMap` from a stream.
    /// If bulk data is internal (not stored in separate file) and size > 0,
    /// and `read_inline` is true, attempts to read the inline bulk payload.
    pub fn read<R: Read + Seek>(reader: &mut R, read_inline: bool) -> Result<Self, ExtractError> {
        let bulk_data = FByteBulkData::read(reader)?;
        let size_x = reader.read_u32::<LittleEndian>()?;
        let size_y = reader.read_u32::<LittleEndian>()?;

        let mut inline_data = None;
        if read_inline && !bulk_data.is_separate_file() && bulk_data.size_on_disk > 0 {
            let start_pos = reader.stream_position()?;
            if bulk_data.offset_in_file > 0 && bulk_data.offset_in_file as u64 != start_pos {
                reader.seek(SeekFrom::Start(bulk_data.offset_in_file as u64))?;
            }
            let mut buf = vec![0u8; bulk_data.size_on_disk as usize];
            reader.read_exact(&mut buf)?;

            // If compressed chunk header present, decompress
            let decompressed = decompress_bulk_payload(&buf, bulk_data.element_count, bulk_data.bulk_data_flags)?;
            inline_data = Some(decompressed);

            // Restore stream position if jumped
            if bulk_data.offset_in_file > 0 && bulk_data.offset_in_file as u64 != start_pos {
                reader.seek(SeekFrom::Start(start_pos))?;
            }
        }

        Ok(Self {
            bulk_data,
            size_x,
            size_y,
            inline_data,
        })
    }

    /// Writes an `FTexture2DMipMap` descriptor and optional inline data.
    pub fn write<W: Write + Seek>(&self, writer: &mut W) -> Result<(), ExtractError> {
        let mut bulk = self.bulk_data.clone();
        if let Some(ref data) = self.inline_data {
            if !bulk.is_separate_file() {
                bulk.size_on_disk = data.len() as u32;
                bulk.element_count = data.len() as u32;
                let current_pos = writer.stream_position()?;
                // BulkData descriptor is 20 bytes, size_x/y is 8 bytes
                bulk.offset_in_file = (current_pos + 20 + 8) as i64;
            }
        }

        bulk.write(writer)?;
        writer.write_u32::<LittleEndian>(self.size_x)?;
        writer.write_u32::<LittleEndian>(self.size_y)?;

        if let Some(ref data) = self.inline_data {
            if !self.bulk_data.is_separate_file() {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }
}

/// Decompresses raw bulk data payload buffer if compressed, or returns payload as is.
pub fn decompress_bulk_payload(
    payload: &[u8],
    expected_uncompressed_size: u32,
    flags: u32,
) -> Result<Vec<u8>, ExtractError> {
    if payload.len() < 16 {
        return Ok(payload.to_vec());
    }

    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if magic == UPK_MAGIC {
        // Standard UE3 Chunk Header:
        // magic (4), block_size (4), compressed_size (4), uncompressed_size (4)
        let block_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let _comp_size = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let uncomp_size = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);

        if block_size == 0 {
            return Err(ExtractError::CorruptChunk {
                reason: "Block size is 0 in chunk header".to_string(),
            });
        }

        let num_blocks = uncomp_size.div_ceil(block_size);
        let block_table_size = (num_blocks as usize) * 8;
        if payload.len() < 16 + block_table_size {
            return Err(ExtractError::CorruptChunk {
                reason: format!("Payload truncated before block table (need {}, got {})", 16 + block_table_size, payload.len()),
            });
        }

        let mut blocks = Vec::with_capacity(num_blocks as usize);
        let mut cursor = 16;
        for _ in 0..num_blocks {
            let b_comp = u32::from_le_bytes([payload[cursor], payload[cursor + 1], payload[cursor + 2], payload[cursor + 3]]);
            let b_uncomp = u32::from_le_bytes([payload[cursor + 4], payload[cursor + 5], payload[cursor + 6], payload[cursor + 7]]);
            blocks.push(FCompressedChunkBlock {
                compressed_size: b_comp,
                uncompressed_size: b_uncomp,
            });
            cursor += 8;
        }

        let mut out = Vec::with_capacity(uncomp_size as usize);
        let use_zlib = (flags & BULKDATA_COMPRESSED_ZLIB) != 0;

        for block in blocks {
            let block_end = cursor + block.compressed_size as usize;
            if block_end > payload.len() {
                return Err(ExtractError::CorruptChunk {
                    reason: format!(
                        "Compressed block payload truncated (need {block_end} bytes, available {})",
                        payload.len()
                    ),
                });
            }
            let block_bytes = &payload[cursor..block_end];
            cursor = block_end;

            let decompressed_block = if use_zlib {
                decompress_zlib(block_bytes, block.uncompressed_size as usize)?
            } else {
                match decompress_lzo(block_bytes, block.uncompressed_size as usize) {
                    Ok(b) => b,
                    Err(_) => decompress_zlib(block_bytes, block.uncompressed_size as usize)?,
                }
            };
            out.extend_from_slice(&decompressed_block);
        }

        return Ok(out);
    }

    // Not chunk header: check explicit flags
    if (flags & BULKDATA_COMPRESSED_ZLIB) != 0 {
        return decompress_zlib(payload, expected_uncompressed_size as usize);
    }
    if (flags & BULKDATA_COMPRESSED_LZO) != 0 {
        return decompress_lzo(payload, expected_uncompressed_size as usize);
    }

    Ok(payload.to_vec())
}

/// Resolves external Texture File Cache (`.tfc`) paths and reads texture mips.
#[derive(Debug, Clone)]
pub struct TfcResolver {
    pub base_path: PathBuf,
}

impl TfcResolver {
    /// Creates a resolver with the specified base game path.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Resolves external `.tfc` path from `ChaosGame/CookedPCConsole/<TFCName>.tfc`.
    pub fn resolve_tfc_path(&self, tfc_name: &str) -> PathBuf {
        let clean_name = if tfc_name.to_lowercase().ends_with(".tfc") {
            tfc_name.to_string()
        } else {
            format!("{tfc_name}.tfc")
        };

        // Candidate 1: Standard CookedPCConsole relative to game root
        let candidate1 = self.base_path
            .join("ChaosGame")
            .join("CookedPCConsole")
            .join(&clean_name);
        if candidate1.exists() {
            return candidate1;
        }

        // Candidate 2: Directly under CookedPCConsole
        let candidate2 = self.base_path
            .join("CookedPCConsole")
            .join(&clean_name);
        if candidate2.exists() {
            return candidate2;
        }

        // Candidate 3: Directly under base path
        let candidate3 = self.base_path.join(&clean_name);
        if candidate3.exists() {
            return candidate3;
        }

        // Default to candidate 1
        candidate1
    }

    /// Extracts mip data from an external `.tfc` container or from reader.
    pub fn extract_mip_from_reader<R: Read + Seek>(
        &self,
        reader: &mut R,
        mip: &FTexture2DMipMap,
    ) -> Result<Vec<u8>, ExtractError> {
        if let Some(ref data) = mip.inline_data {
            return Ok(data.clone());
        }

        if mip.bulk_data.size_on_disk == 0 {
            return Ok(Vec::new());
        }

        if mip.bulk_data.offset_in_file < 0 {
            return Err(ExtractError::InvalidBulkData {
                reason: format!(
                    "Negative bulk data offset in file: {}",
                    mip.bulk_data.offset_in_file
                ),
            });
        }

        reader.seek(SeekFrom::Start(mip.bulk_data.offset_in_file as u64))?;
        let mut raw = vec![0u8; mip.bulk_data.size_on_disk as usize];
        reader.read_exact(&mut raw)?;

        decompress_bulk_payload(
            &raw,
            mip.bulk_data.element_count,
            mip.bulk_data.bulk_data_flags,
        )
    }

    /// Extracts mip data from the named `.tfc` container on disk.
    pub fn extract_mip_from_tfc(
        &self,
        tfc_name: &str,
        mip: &FTexture2DMipMap,
    ) -> Result<Vec<u8>, ExtractError> {
        let path = self.resolve_tfc_path(tfc_name);
        if !path.exists() {
            return Err(ExtractError::TfcNotFound {
                tfc_name: tfc_name.to_string(),
                path: path.display().to_string(),
            });
        }

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);
        self.extract_mip_from_reader(&mut reader, mip)
    }
}

/// Builds a standard 128-byte DirectDraw Surface (`.dds`) header.
pub fn build_dds_header(
    width: u32,
    height: u32,
    format: TextureFormat,
    mip_count: u32,
) -> [u8; 128] {
    let mut header = [0u8; 128];
    let mut cursor = 0;

    // 0..4: Magic "DDS "
    header[0..4].copy_from_slice(&DDS_MAGIC.to_le_bytes());
    cursor += 4;

    // 4..8: dwSize (124)
    header[cursor..cursor + 4].copy_from_slice(&DDS_HEADER_SIZE.to_le_bytes());
    cursor += 4;

    // 8..12: dwFlags
    let mut flags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
    if mip_count > 1 {
        flags |= DDSD_MIPMAPCOUNT;
    }
    match format {
        TextureFormat::Dxt1 | TextureFormat::Dxt5 | TextureFormat::Bc7 => {
            flags |= DDSD_LINEARSIZE;
        }
        TextureFormat::Rgba8 | TextureFormat::Bgra8 => {
            flags |= DDSD_PITCH;
        }
    }
    header[cursor..cursor + 4].copy_from_slice(&flags.to_le_bytes());
    cursor += 4;

    // 12..16: dwHeight
    header[cursor..cursor + 4].copy_from_slice(&height.to_le_bytes());
    cursor += 4;

    // 16..20: dwWidth
    header[cursor..cursor + 4].copy_from_slice(&width.to_le_bytes());
    cursor += 4;

    // 20..24: dwPitchOrLinearSize
    let pitch_or_linear = match format {
        TextureFormat::Dxt1 => {
            let blocks_x = width.div_ceil(4).max(1);
            let blocks_y = height.div_ceil(4).max(1);
            blocks_x * blocks_y * 8
        }
        TextureFormat::Dxt5 | TextureFormat::Bc7 => {
            let blocks_x = width.div_ceil(4).max(1);
            let blocks_y = height.div_ceil(4).max(1);
            blocks_x * blocks_y * 16
        }
        TextureFormat::Rgba8 | TextureFormat::Bgra8 => width * 4,
    };
    header[cursor..cursor + 4].copy_from_slice(&pitch_or_linear.to_le_bytes());
    cursor += 4;

    // 24..28: dwDepth
    header[cursor..cursor + 4].copy_from_slice(&0u32.to_le_bytes());
    cursor += 4;

    // 28..32: dwMipMapCount
    let mips = if mip_count > 0 { mip_count } else { 1 };
    header[cursor..cursor + 4].copy_from_slice(&mips.to_le_bytes());
    cursor += 4;

    // 32..76: dwReserved1 (11 * 4 = 44 bytes) - zeroed
    cursor += 44;

    // 76..108: DDS_PIXELFORMAT (32 bytes)
    // 76..80: dwSize (32)
    header[cursor..cursor + 4].copy_from_slice(&DDS_PIXELFORMAT_SIZE.to_le_bytes());
    cursor += 4;

    // 80..84: dwFlags
    let pf_flags = if format.four_cc().is_some() {
        DDPF_FOURCC
    } else {
        DDPF_RGB | DDPF_ALPHAPIXELS
    };
    header[cursor..cursor + 4].copy_from_slice(&pf_flags.to_le_bytes());
    cursor += 4;

    // 84..88: dwFourCC
    let four_cc = format.four_cc().unwrap_or(0);
    header[cursor..cursor + 4].copy_from_slice(&four_cc.to_le_bytes());
    cursor += 4;

    // 88..92: dwRGBBitCount
    let rgb_bits = match format {
        TextureFormat::Rgba8 | TextureFormat::Bgra8 => 32u32,
        _ => 0u32,
    };
    header[cursor..cursor + 4].copy_from_slice(&rgb_bits.to_le_bytes());
    cursor += 4;

    // 92..96: dwRBitMask
    let r_mask = match format {
        TextureFormat::Rgba8 => 0x000000FFu32,
        TextureFormat::Bgra8 => 0x00FF0000u32,
        _ => 0,
    };
    header[cursor..cursor + 4].copy_from_slice(&r_mask.to_le_bytes());
    cursor += 4;

    // 96..100: dwGBitMask
    let g_mask = match format {
        TextureFormat::Rgba8 | TextureFormat::Bgra8 => 0x0000FF00u32,
        _ => 0,
    };
    header[cursor..cursor + 4].copy_from_slice(&g_mask.to_le_bytes());
    cursor += 4;

    // 100..104: dwBBitMask
    let b_mask = match format {
        TextureFormat::Rgba8 => 0x00FF0000u32,
        TextureFormat::Bgra8 => 0x000000FFu32,
        _ => 0,
    };
    header[cursor..cursor + 4].copy_from_slice(&b_mask.to_le_bytes());
    cursor += 4;

    // 104..108: dwABitMask
    let a_mask = match format {
        TextureFormat::Rgba8 | TextureFormat::Bgra8 => 0xFF000000u32,
        _ => 0,
    };
    header[cursor..cursor + 4].copy_from_slice(&a_mask.to_le_bytes());
    cursor += 4;

    // 108..112: dwCaps
    let mut caps = DDSCAPS_TEXTURE;
    if mip_count > 1 {
        caps |= DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
    }
    header[cursor..cursor + 4].copy_from_slice(&caps.to_le_bytes());

    // 112..116: dwCaps2 (0)
    // 116..120: dwCaps3 (0)
    // 120..124: dwCaps4 (0)
    // 124..128: dwReserved2 (0)
    // already 0 initialized

    header
}

/// Exports raw mip data into a valid `.dds` binary buffer.
pub fn export_dds(
    width: u32,
    height: u32,
    format: TextureFormat,
    mip_data: &[u8],
) -> Vec<u8> {
    let header = build_dds_header(width, height, format, 1);
    let mut output = Vec::with_capacity(128 + mip_data.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(mip_data);
    output
}

/// Exports multiple mips into a single mipmapped `.dds` binary buffer.
pub fn export_dds_with_mips(
    width: u32,
    height: u32,
    format: TextureFormat,
    mip_chain: &[&[u8]],
) -> Vec<u8> {
    let total_len: usize = mip_chain.iter().map(|m| m.len()).sum();
    let header = build_dds_header(width, height, format, mip_chain.len() as u32);
    let mut output = Vec::with_capacity(128 + total_len);
    output.extend_from_slice(&header);
    for mip in mip_chain {
        output.extend_from_slice(mip);
    }
    output
}

/// Helper function to write a compressed or uncompressed chunk into a TFC container stream.
/// Returns `(offset, size_on_disk)`.
pub fn write_tfc_chunk<W: Write + Seek>(
    writer: &mut W,
    data: &[u8],
    compression: Option<u32>,
) -> Result<(u64, u32), ExtractError> {
    let offset = writer.stream_position()?;

    if let Some(comp_flag) = compression {
        let block_size = 131072u32;
        let uncompressed_size = data.len() as u32;

        let num_blocks = uncompressed_size.div_ceil(block_size);
        let mut compressed_blocks = Vec::with_capacity(num_blocks as usize);
        let mut block_descriptors = Vec::with_capacity(num_blocks as usize);

        let mut offset_in_data = 0;
        for _ in 0..num_blocks {
            let block_uncomp = ((data.len() - offset_in_data) as u32).min(block_size);
            let slice = &data[offset_in_data..offset_in_data + block_uncomp as usize];
            offset_in_data += block_uncomp as usize;

            let comp = if comp_flag == COMPRESS_ZLIB {
                compress_zlib(slice)?
            } else {
                compress_lzo(slice)?
            };

            block_descriptors.push(FCompressedChunkBlock {
                compressed_size: comp.len() as u32,
                uncompressed_size: block_uncomp,
            });
            compressed_blocks.push(comp);
        }

        let total_payload_comp: u32 = compressed_blocks.iter().map(|b| b.len() as u32).sum();
        let chunk_header = FCompressedChunkHeader {
            magic: UPK_MAGIC,
            block_size,
            compressed_size: total_payload_comp,
            uncompressed_size,
        };

        chunk_header.write(writer)?;
        for desc in &block_descriptors {
            desc.write(writer)?;
        }
        for block in &compressed_blocks {
            writer.write_all(block)?;
        }

        let end_pos = writer.stream_position()?;
        let size_on_disk = (end_pos - offset) as u32;
        Ok((offset, size_on_disk))
    } else {
        writer.write_all(data)?;
        let size_on_disk = data.len() as u32;
        Ok((offset, size_on_disk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::COMPRESS_LZO;
    use std::io::Cursor;

    #[test]
    fn test_bulk_data_flags() {
        let bulk = FByteBulkData {
            bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE | BULKDATA_COMPRESSED_LZO,
            element_count: 1024,
            size_on_disk: 512,
            offset_in_file: 2048,
        };
        assert!(bulk.is_separate_file());
        assert!(bulk.is_compressed());

        let mut buf = Vec::new();
        bulk.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 20);

        let mut cursor = Cursor::new(buf);
        let decoded = FByteBulkData::read(&mut cursor).unwrap();
        assert_eq!(decoded, bulk);
    }

    #[test]
    fn test_dds_header_dxt1() {
        let header = build_dds_header(256, 128, TextureFormat::Dxt1, 1);
        assert_eq!(header.len(), 128);
        assert_eq!(&header[0..4], b"DDS ");
        let four_cc = u32::from_le_bytes([header[84], header[85], header[86], header[87]]);
        assert_eq!(four_cc, FOURCC_DXT1);

        let width = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        let height = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        assert_eq!(width, 256);
        assert_eq!(height, 128);
    }

    #[test]
    fn test_dds_header_dxt5_and_bc7() {
        let dxt5_hdr = build_dds_header(512, 512, TextureFormat::Dxt5, 1);
        let four_cc_dxt5 = u32::from_le_bytes([dxt5_hdr[84], dxt5_hdr[85], dxt5_hdr[86], dxt5_hdr[87]]);
        assert_eq!(four_cc_dxt5, FOURCC_DXT5);

        let bc7_hdr = build_dds_header(1024, 1024, TextureFormat::Bc7, 1);
        let four_cc_bc7 = u32::from_le_bytes([bc7_hdr[84], bc7_hdr[85], bc7_hdr[86], bc7_hdr[87]]);
        assert_eq!(four_cc_bc7, FOURCC_BC7);
    }

    #[test]
    fn test_dds_export_rgba8() {
        let raw_pixels = vec![255u8; 64 * 64 * 4];
        let dds = export_dds(64, 64, TextureFormat::Rgba8, &raw_pixels);
        assert_eq!(dds.len(), 128 + raw_pixels.len());
        assert_eq!(&dds[0..4], b"DDS ");
    }

    #[test]
    fn test_tfc_chunk_roundtrip_uncompressed() {
        let original_data = vec![0x42u8; 4096];
        let mut tfc_stream = Cursor::new(Vec::new());
        let (offset, size_on_disk) = write_tfc_chunk(&mut tfc_stream, &original_data, None).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(size_on_disk, 4096);

        let mip = FTexture2DMipMap {
            bulk_data: FByteBulkData {
                bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE,
                element_count: 4096,
                size_on_disk,
                offset_in_file: offset as i64,
            },
            size_x: 64,
            size_y: 64,
            inline_data: None,
        };

        let resolver = TfcResolver::new(".");
        let extracted = resolver.extract_mip_from_reader(&mut tfc_stream, &mip).unwrap();
        assert_eq!(extracted, original_data);
    }

    #[test]
    fn test_tfc_chunk_roundtrip_lzo_compressed() {
        let original_data = vec![0xABu8; 65536];
        let mut tfc_stream = Cursor::new(Vec::new());
        let (offset, size_on_disk) = write_tfc_chunk(&mut tfc_stream, &original_data, Some(COMPRESS_LZO)).unwrap();

        let mip = FTexture2DMipMap {
            bulk_data: FByteBulkData {
                bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE | BULKDATA_COMPRESSED_LZO,
                element_count: 65536,
                size_on_disk,
                offset_in_file: offset as i64,
            },
            size_x: 256,
            size_y: 256,
            inline_data: None,
        };

        let resolver = TfcResolver::new(".");
        let extracted = resolver.extract_mip_from_reader(&mut tfc_stream, &mip).unwrap();
        assert_eq!(extracted, original_data);
    }

    #[test]
    fn test_tfc_chunk_roundtrip_zlib_compressed() {
        let original_data = b"Cleanroom Paladins Texture Cache test with ZLIB compression".repeat(100);
        let mut tfc_stream = Cursor::new(Vec::new());
        let (offset, size_on_disk) = write_tfc_chunk(&mut tfc_stream, &original_data, Some(COMPRESS_ZLIB)).unwrap();

        let mip = FTexture2DMipMap {
            bulk_data: FByteBulkData {
                bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE | BULKDATA_COMPRESSED_ZLIB,
                element_count: original_data.len() as u32,
                size_on_disk,
                offset_in_file: offset as i64,
            },
            size_x: 128,
            size_y: 128,
            inline_data: None,
        };

        let resolver = TfcResolver::new(".");
        let extracted = resolver.extract_mip_from_reader(&mut tfc_stream, &mip).unwrap();
        assert_eq!(extracted, original_data);
    }

    #[test]
    fn test_internal_bulk_data_roundtrip() {
        let payload = vec![0x77u8; 256];
        let mip = FTexture2DMipMap {
            bulk_data: FByteBulkData {
                bulk_data_flags: 0,
                element_count: 256,
                size_on_disk: 256,
                offset_in_file: 0,
            },
            size_x: 16,
            size_y: 16,
            inline_data: Some(payload.clone()),
        };

        let mut stream = Cursor::new(Vec::new());
        mip.write(&mut stream).unwrap();

        stream.seek(SeekFrom::Start(0)).unwrap();
        let read_mip = FTexture2DMipMap::read(&mut stream, true).unwrap();
        assert_eq!(read_mip.size_x, 16);
        assert_eq!(read_mip.size_y, 16);
        assert_eq!(read_mip.inline_data, Some(payload));
    }

    #[test]
    fn test_negative_bulk_data_offset() {
        let mip = FTexture2DMipMap {
            bulk_data: FByteBulkData {
                bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE,
                element_count: 100,
                size_on_disk: 100,
                offset_in_file: -1,
            },
            size_x: 10,
            size_y: 10,
            inline_data: None,
        };

        let resolver = TfcResolver::new(".");
        let mut stream = Cursor::new(vec![0u8; 100]);
        let err = resolver.extract_mip_from_reader(&mut stream, &mip).unwrap_err();
        match err {
            ExtractError::InvalidBulkData { reason } => {
                assert!(reason.contains("Negative bulk data offset"));
            }
            other => panic!("Expected InvalidBulkData, got: {other:?}"),
        }
    }

    #[test]
    fn test_truncated_compressed_bulk_payload() {
        // Construct a chunk header claiming 1 block of 500 compressed bytes, but only provide 20 bytes of payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&UPK_MAGIC.to_le_bytes()); // magic
        payload.extend_from_slice(&131072u32.to_le_bytes()); // block_size
        payload.extend_from_slice(&500u32.to_le_bytes()); // compressed_size
        payload.extend_from_slice(&1000u32.to_le_bytes()); // uncompressed_size
        // Block descriptor: 500 compressed, 1000 uncompressed
        payload.extend_from_slice(&500u32.to_le_bytes());
        payload.extend_from_slice(&1000u32.to_le_bytes());
        // Truncated block payload: only 10 bytes instead of 500
        payload.extend_from_slice(&[0u8; 10]);

        let err = decompress_bulk_payload(&payload, 1000, 0).unwrap_err();
        match err {
            ExtractError::CorruptChunk { reason } => {
                assert!(reason.contains("truncated"));
            }
            other => panic!("Expected CorruptChunk, got: {other:?}"),
        }
    }
}
