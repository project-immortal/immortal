// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 Chunked Decompression implementation.
//! Supports LZO (`COMPRESS_LZO = 0x02`) and Zlib (`COMPRESS_ZLIB = 0x01`).

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::ExtractError;
use crate::UPK_MAGIC;

/// UE3 compression algorithm flags
pub const COMPRESS_ZLIB: u32 = 0x01;
pub const COMPRESS_LZO: u32 = 0x02;
pub const COMPRESS_LZMA: u32 = 0x04;

/// Represents an entry in the package header's chunk table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FCompressedChunk {
    /// Offset of the uncompressed chunk data in the virtual package file.
    pub uncompressed_offset: u32,
    /// Uncompressed size of this chunk.
    pub uncompressed_size: u32,
    /// Offset of the compressed chunk in the file on disk.
    pub compressed_offset: u32,
    /// Total compressed size of this chunk (header + block headers + payload).
    pub compressed_size: u32,
}

impl FCompressedChunk {
    /// Reads an `FCompressedChunk` entry from the chunk table.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let uncompressed_offset = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        let compressed_offset = reader.read_u32::<LittleEndian>()?;
        let compressed_size = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            uncompressed_offset,
            uncompressed_size,
            compressed_offset,
            compressed_size,
        })
    }

    /// Writes an `FCompressedChunk` entry to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.uncompressed_offset)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        writer.write_u32::<LittleEndian>(self.compressed_offset)?;
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        Ok(())
    }
}

/// Header located at `compressed_offset` at the start of a compressed chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FCompressedChunkHeader {
    /// Magic tag, must match `UPK_MAGIC` (0x9E2A83C1).
    pub magic: u32,
    /// Maximum uncompressed size of individual blocks (typically 131072 / 0x20000).
    pub block_size: u32,
    /// Total compressed size of all block payloads (excluding chunk header and block table).
    pub compressed_size: u32,
    /// Total uncompressed size of all blocks.
    pub uncompressed_size: u32,
}

impl FCompressedChunkHeader {
    /// Reads a chunk header from a stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != UPK_MAGIC {
            return Err(ExtractError::InvalidMagic {
                expected: UPK_MAGIC,
                found: magic,
            });
        }

        let block_size = reader.read_u32::<LittleEndian>()?;
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            magic,
            block_size,
            compressed_size,
            uncompressed_size,
        })
    }

    /// Writes a chunk header to a stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.magic)?;
        writer.write_u32::<LittleEndian>(self.block_size)?;
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        Ok(())
    }
}

/// Describes an individual compressed block within a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FCompressedChunkBlock {
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

impl FCompressedChunkBlock {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        Ok(Self {
            compressed_size,
            uncompressed_size,
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        Ok(())
    }
}

/// Decompresses an LZO compressed byte buffer.
pub fn decompress_lzo(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, ExtractError> {
    minilzo::decompress(compressed, expected_size).map_err(|e| ExtractError::DecompressionFailed {
        reason: format!("LZO decompress error: {e}"),
    })
}

/// Compresses a buffer using LZO (used for creating synthetic fixtures).
pub fn compress_lzo(input: &[u8]) -> Result<Vec<u8>, ExtractError> {
    minilzo::compress(input).map_err(|e| ExtractError::DecompressionFailed {
        reason: format!("LZO compress error: {e}"),
    })
}

/// Decompresses a Zlib compressed byte buffer.
pub fn decompress_zlib(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, ExtractError> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(expected_size);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::DecompressionFailed {
            reason: format!("Zlib decompress error: {e}"),
        })?;

    if decompressed.len() != expected_size {
        return Err(ExtractError::CorruptChunk {
            reason: format!(
                "Zlib decompressed size mismatch: expected {expected_size}, got {}",
                decompressed.len()
            ),
        });
    }

    Ok(decompressed)
}

/// Compresses a buffer using Zlib (used for creating synthetic fixtures).
pub fn compress_zlib(input: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| ExtractError::DecompressionFailed {
            reason: format!("Zlib compress write error: {e}"),
        })?;
    encoder
        .finish()
        .map_err(|e| ExtractError::DecompressionFailed {
            reason: format!("Zlib compress finish error: {e}"),
        })
}

/// Decompresses an entire chunk from the specified reader.
pub fn decompress_chunk<R: Read + Seek>(
    reader: &mut R,
    chunk: &FCompressedChunk,
    compression_flags: u32,
) -> Result<Vec<u8>, ExtractError> {
    reader.seek(SeekFrom::Start(chunk.compressed_offset as u64))?;

    let chunk_header = FCompressedChunkHeader::read(reader)?;

    if chunk_header.uncompressed_size != chunk.uncompressed_size {
        return Err(ExtractError::CorruptChunk {
            reason: format!(
                "Chunk uncompressed size mismatch: table says {}, header says {}",
                chunk.uncompressed_size, chunk_header.uncompressed_size
            ),
        });
    }

    let block_size = chunk_header.block_size;
    if block_size == 0 {
        return Err(ExtractError::CorruptChunk {
            reason: "Chunk block size cannot be zero".to_string(),
        });
    }
    let num_blocks = chunk_header.uncompressed_size.div_ceil(block_size);

    // Sanity check: each block requires at least 8 bytes in the block header table
    // and cannot exceed the total compressed chunk size or reasonable upper bound.
    const MAX_CHUNK_BLOCKS: u32 = 65_536;
    if num_blocks > MAX_CHUNK_BLOCKS || (num_blocks * 8) > chunk.compressed_size {
        return Err(ExtractError::CorruptChunk {
            reason: format!(
                "Invalid num_blocks: {num_blocks} exceeds bounds (chunk compressed size: {})",
                chunk.compressed_size
            ),
        });
    }

    let mut blocks = Vec::with_capacity(num_blocks as usize);
    for _ in 0..num_blocks {
        blocks.push(FCompressedChunkBlock::read(reader)?);
    }

    let is_lzo = (compression_flags & COMPRESS_LZO) != 0;
    let is_zlib = (compression_flags & COMPRESS_ZLIB) != 0;

    if !is_lzo && !is_zlib {
        return Err(ExtractError::UnsupportedCompression {
            flags: compression_flags,
        });
    }

    let mut decompressed = Vec::with_capacity(chunk.uncompressed_size as usize);

    for block in blocks {
        let mut block_comp_buf = vec![0u8; block.compressed_size as usize];
        reader.read_exact(&mut block_comp_buf)?;

        let block_decomp = if is_lzo {
            decompress_lzo(&block_comp_buf, block.uncompressed_size as usize)?
        } else {
            decompress_zlib(&block_comp_buf, block.uncompressed_size as usize)?
        };

        if block_decomp.len() != block.uncompressed_size as usize {
            return Err(ExtractError::CorruptChunk {
                reason: format!(
                    "Block uncompressed size mismatch: expected {}, got {}",
                    block.uncompressed_size,
                    block_decomp.len()
                ),
            });
        }

        decompressed.extend_from_slice(&block_decomp);
    }

    if decompressed.len() != chunk.uncompressed_size as usize {
        return Err(ExtractError::CorruptChunk {
            reason: format!(
                "Total chunk uncompressed size mismatch: expected {}, got {}",
                chunk.uncompressed_size,
                decompressed.len()
            ),
        });
    }

    Ok(decompressed)
}

/// Helper for tests: writes a compressed chunk containing data into a writer.
/// Returns the `FCompressedChunk` metadata describing the written chunk.
pub fn write_compressed_chunk<W: Write>(
    writer: &mut W,
    uncompressed_offset: u32,
    compressed_offset: u32,
    uncompressed_data: &[u8],
    block_size: u32,
    compression_flags: u32,
) -> Result<FCompressedChunk, ExtractError> {
    let uncompressed_size = uncompressed_data.len() as u32;
    let block_sz = if block_size == 0 { 131072 } else { block_size };
    let num_blocks = uncompressed_size.div_ceil(block_sz);

    let is_lzo = (compression_flags & COMPRESS_LZO) != 0;
    let is_zlib = (compression_flags & COMPRESS_ZLIB) != 0;

    let mut blocks = Vec::with_capacity(num_blocks as usize);
    let mut compressed_payloads = Vec::with_capacity(num_blocks as usize);

    for i in 0..num_blocks {
        let start = (i * block_sz) as usize;
        let end = ((i + 1) * block_sz).min(uncompressed_size) as usize;
        let slice = &uncompressed_data[start..end];

        let comp = if is_lzo {
            compress_lzo(slice)?
        } else if is_zlib {
            compress_zlib(slice)?
        } else {
            return Err(ExtractError::UnsupportedCompression {
                flags: compression_flags,
            });
        };

        blocks.push(FCompressedChunkBlock {
            compressed_size: comp.len() as u32,
            uncompressed_size: slice.len() as u32,
        });
        compressed_payloads.push(comp);
    }

    let payload_comp_size: u32 = blocks.iter().map(|b| b.compressed_size).sum();

    let header = FCompressedChunkHeader {
        magic: UPK_MAGIC,
        block_size: block_sz,
        compressed_size: payload_comp_size,
        uncompressed_size,
    };

    // Calculate total chunk compressed size: 16 (header) + blocks * 8 + payload_comp_size
    let total_compressed_size = 16 + (blocks.len() as u32 * 8) + payload_comp_size;

    header.write(writer)?;
    for block in &blocks {
        block.write(writer)?;
    }
    for payload in &compressed_payloads {
        writer.write_all(payload)?;
    }

    Ok(FCompressedChunk {
        uncompressed_offset,
        uncompressed_size,
        compressed_offset,
        compressed_size: total_compressed_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_lzo_block_roundtrip() {
        let original = b"Immortal Engine Cleanroom Asset Pipeline UPK Decompressor".repeat(100);
        let compressed = compress_lzo(&original).unwrap();
        let decompressed = decompress_lzo(&compressed, original.len()).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_zlib_block_roundtrip() {
        let original = b"Immortal Zlib Chunk Roundtrip Test Synthetic Payload".repeat(100);
        let compressed = compress_zlib(&original).unwrap();
        let decompressed = decompress_zlib(&compressed, original.len()).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_chunk_lzo_roundtrip() {
        let mut buffer = Vec::new();
        let payload = b"Test multi-block chunk decompression with LZO".repeat(3000);
        let block_size = 4096;

        let chunk =
            write_compressed_chunk(&mut buffer, 0, 0, &payload, block_size, COMPRESS_LZO).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decompressed = decompress_chunk(&mut cursor, &chunk, COMPRESS_LZO).unwrap();
        assert_eq!(payload.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_chunk_zlib_roundtrip() {
        let mut buffer = Vec::new();
        let payload = b"Test multi-block chunk decompression with Zlib".repeat(3000);
        let block_size = 4096;

        let chunk =
            write_compressed_chunk(&mut buffer, 1024, 0, &payload, block_size, COMPRESS_ZLIB)
                .unwrap();

        let mut cursor = Cursor::new(buffer);
        let decompressed = decompress_chunk(&mut cursor, &chunk, COMPRESS_ZLIB).unwrap();
        assert_eq!(payload.as_slice(), decompressed.as_slice());
    }
}
