// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! High-level Unreal Package (`.upk`) abstraction for reading and decompressing packages.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::chunk::{decompress_chunk, FCompressedChunk};
use crate::error::ExtractError;
use crate::summary::PackageSummary;

/// An opened Unreal Engine 3 CookedPCConsole UPK package.
#[derive(Debug)]
pub struct UpkPackage<R> {
    reader: R,
    summary: PackageSummary,
}

impl UpkPackage<BufReader<File>> {
    /// Opens a UPK file from the filesystem.
    pub fn open_file<P: AsRef<Path>>(path: P) -> Result<Self, ExtractError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::open(reader)
    }
}

impl<R: Read + Seek> UpkPackage<R> {
    /// Opens and parses a UPK package from an arbitrary seekable reader.
    pub fn open(mut reader: R) -> Result<Self, ExtractError> {
        reader.seek(SeekFrom::Start(0))?;
        let summary = PackageSummary::read(&mut reader)?;
        Ok(Self { reader, summary })
    }

    /// Returns a reference to the package summary header.
    pub fn summary(&self) -> &PackageSummary {
        &self.summary
    }

    /// Returns the slice of compressed chunks in this package.
    pub fn compressed_chunks(&self) -> &[FCompressedChunk] {
        &self.summary.compressed_chunks
    }

    /// Decompresses an individual chunk by index.
    pub fn decompress_chunk_at(&mut self, index: usize) -> Result<Vec<u8>, ExtractError> {
        let chunk = self.summary.compressed_chunks.get(index).ok_or_else(|| {
            ExtractError::CorruptChunk {
                reason: format!("Chunk index {index} out of bounds"),
            }
        })?;

        decompress_chunk(&mut self.reader, chunk, self.summary.compression_flags)
    }

    /// Decompresses all chunks and reconstructs the full uncompressed virtual package stream.
    /// If the package is uncompressed, reads the entire file into a buffer.
    pub fn decompress_all(&mut self) -> Result<Vec<u8>, ExtractError> {
        if !self.summary.is_compressed() {
            self.reader.seek(SeekFrom::Start(0))?;
            let mut buf = Vec::new();
            self.reader.read_to_end(&mut buf)?;
            return Ok(buf);
        }

        // For compressed packages, header bytes up to first chunk's uncompressed offset
        // are copied directly from the file header.
        let first_uncomp_off = self
            .summary
            .compressed_chunks
            .first()
            .map(|c| c.uncompressed_offset as usize)
            .unwrap_or(0);

        self.reader.seek(SeekFrom::Start(0))?;
        let mut full_package = vec![0u8; first_uncomp_off];
        self.reader.read_exact(&mut full_package)?;

        for chunk in &self.summary.compressed_chunks {
            let decompressed =
                decompress_chunk(&mut self.reader, chunk, self.summary.compression_flags)?;

            // If there's a gap between current length and chunk uncompressed offset, pad with zeroes
            if full_package.len() < chunk.uncompressed_offset as usize {
                full_package.resize(chunk.uncompressed_offset as usize, 0);
            }

            full_package.extend_from_slice(&decompressed);
        }

        Ok(full_package)
    }

    /// Reads an arbitrary slice of bytes from the virtual uncompressed package.
    pub fn read_bytes(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, ExtractError> {
        if !self.summary.is_compressed() {
            self.reader.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; size];
            self.reader.read_exact(&mut buf)?;
            return Ok(buf);
        }

        let first_uncomp_off = self
            .summary
            .compressed_chunks
            .first()
            .map(|c| c.uncompressed_offset as u64)
            .unwrap_or(0);

        let mut result = Vec::with_capacity(size);
        let end_offset = offset + size as u64;

        // 1. If read begins within the uncompressed header prefix, read that prefix slice
        if offset < first_uncomp_off {
            let header_slice_end = end_offset.min(first_uncomp_off);
            let header_bytes_to_read = (header_slice_end - offset) as usize;
            self.reader.seek(SeekFrom::Start(offset))?;
            let mut prefix_buf = vec![0u8; header_bytes_to_read];
            self.reader.read_exact(&mut prefix_buf)?;
            result.extend_from_slice(&prefix_buf);
        }

        // 2. If end_offset extends into the compressed chunk region, decompress and append chunk slices
        if end_offset > first_uncomp_off {
            for chunk in &self.summary.compressed_chunks {
                let chunk_start = chunk.uncompressed_offset as u64;
                let chunk_end = chunk_start + chunk.uncompressed_size as u64;

                if chunk_end <= offset || chunk_start >= end_offset {
                    continue;
                }

                let decompressed =
                    decompress_chunk(&mut self.reader, chunk, self.summary.compression_flags)?;

                let slice_start = if offset > chunk_start {
                    (offset - chunk_start) as usize
                } else {
                    0
                };

                let slice_end = if end_offset < chunk_end {
                    (end_offset - chunk_start) as usize
                } else {
                    decompressed.len()
                };

                if slice_start < decompressed.len() {
                    let actual_end = slice_end.min(decompressed.len());
                    result.extend_from_slice(&decompressed[slice_start..actual_end]);
                }
            }
        }

        if result.len() != size {
            return Err(ExtractError::BufferOverflow {
                required: size,
                available: result.len(),
            });
        }

        Ok(result)
    }
}
