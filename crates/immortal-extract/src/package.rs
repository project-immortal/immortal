// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! High-level Unreal Package (`.upk`) abstraction for reading and decompressing packages.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use crate::chunk::{decompress_chunk, FCompressedChunk, COMPRESS_XOR_MASK};
use crate::error::ExtractError;
use crate::export::{ExportTable, ObjectExport};
use crate::import::ImportTable;
use crate::index::PackageIndex;
use crate::name::NameTable;
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

/// Parses the Name, Import, and Export tables from an already-decompressed virtual stream.
pub fn read_tables_from_bytes(
    virtual_stream: &[u8],
    summary: &PackageSummary,
) -> Result<(NameTable, ImportTable, ExportTable), ExtractError> {
    let name_offset = summary.name_offset as usize;
    let import_offset = summary.import_offset as usize;
    let export_offset = summary.export_offset as usize;
    let name_count = summary.name_count as usize;
    let import_count = summary.import_count as usize;
    let export_count = summary.export_count as usize;

    let max_offset = name_offset.max(import_offset).max(export_offset);
    if max_offset > virtual_stream.len() {
        return Err(ExtractError::BufferOverflow {
            required: max_offset,
            available: virtual_stream.len(),
        });
    }

    let mut name_cursor = Cursor::new(&virtual_stream[name_offset..]);
    let name_table = NameTable::read(&mut name_cursor, name_count)?;

    let mut import_cursor = Cursor::new(&virtual_stream[import_offset..]);
    let import_table = ImportTable::read(&mut import_cursor, import_count)?;

    let mut export_cursor = Cursor::new(&virtual_stream[export_offset..]);
    let export_table = ExportTable::read(&mut export_cursor, export_count)?;

    Ok((name_table, import_table, export_table))
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

    /// Returns `true` if the package uses the `0x200` XOR payload mask (`0x2A` per byte).
    pub fn is_xor_compressed(&self) -> bool {
        (self.summary.compression_flags & COMPRESS_XOR_MASK) != 0
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

    /// Reads the serialized raw payload bytes for an `ObjectExport`.
    pub fn read_export_data(&mut self, export: &ObjectExport) -> Result<Vec<u8>, ExtractError> {
        if export.serial_size <= 0 {
            return Ok(Vec::new());
        }
        if export.serial_offset < 0 {
            return Err(ExtractError::BufferOverflow {
                required: export.serial_size as usize,
                available: 0,
            });
        }
        self.read_bytes(export.serial_offset as u64, export.serial_size as usize)
    }

    /// Reads and parses the package's Name Table, Import Table, and Export Table.
    pub fn read_tables(&mut self) -> Result<(NameTable, ImportTable, ExportTable), ExtractError> {
        let name_offset = self.summary.name_offset as u64;
        let import_offset = self.summary.import_offset as u64;
        let export_offset = self.summary.export_offset as u64;
        let name_count = self.summary.name_count as usize;
        let import_count = self.summary.import_count as usize;
        let export_count = self.summary.export_count as usize;

        // If package is compressed and Chunk 0 appears to contain the tables:
        if self.summary.is_compressed() && !self.summary.compressed_chunks.is_empty() {
            let chunk0 = &self.summary.compressed_chunks[0];
            let c0_start = chunk0.uncompressed_offset as u64;
            let c0_end = c0_start + chunk0.uncompressed_size as u64;
            let min_exp_end =
                export_offset + (export_count as u64 * ObjectExport::MIN_SERIALIZED_SIZE as u64);

            if name_offset >= c0_start
                && import_offset >= c0_start
                && export_offset >= c0_start
                && min_exp_end <= c0_end
            {
                let chunk0_data = self.decompress_chunk_at(0)?;

                let name_rel = (name_offset - c0_start) as usize;
                let import_rel = (import_offset - c0_start) as usize;
                let export_rel = (export_offset - c0_start) as usize;

                if name_rel > chunk0_data.len()
                    || import_rel > chunk0_data.len()
                    || export_rel > chunk0_data.len()
                {
                    return Err(ExtractError::BufferOverflow {
                        required: export_rel,
                        available: chunk0_data.len(),
                    });
                }

                let mut name_cursor = Cursor::new(&chunk0_data[name_rel..]);
                let mut import_cursor = Cursor::new(&chunk0_data[import_rel..]);
                let mut export_cursor = Cursor::new(&chunk0_data[export_rel..]);

                // Variable-length `ObjectExport` entries can spill across the chunk 0 boundary;
                // fast-path only if all three tables parse completely within chunk 0.
                if let (Ok(name_table), Ok(import_table), Ok(export_table)) = (
                    NameTable::read(&mut name_cursor, name_count),
                    ImportTable::read(&mut import_cursor, import_count),
                    ExportTable::read(&mut export_cursor, export_count),
                ) {
                    return Ok((name_table, import_table, export_table));
                }
            }

            // Tables span across chunks: decompress full virtual package stream
            let virtual_stream = self.decompress_all()?;
            return read_tables_from_bytes(&virtual_stream, &self.summary);
        }

        // Direct uncompressed seek
        self.reader.seek(SeekFrom::Start(name_offset))?;
        let name_table = NameTable::read(&mut self.reader, name_count)?;

        self.reader.seek(SeekFrom::Start(import_offset))?;
        let import_table = ImportTable::read(&mut self.reader, import_count)?;

        self.reader.seek(SeekFrom::Start(export_offset))?;
        let export_table = ExportTable::read(&mut self.reader, export_count)?;

        Ok((name_table, import_table, export_table))
    }

    /// Walks the outer chain for a given `PackageIndex`, resolving the complete hierarchy:
    /// e.g. `Package.Group.ObjectName`.
    pub fn resolve_full_path(
        &self,
        name_table: &NameTable,
        import_table: &ImportTable,
        export_table: &ExportTable,
        index: PackageIndex,
    ) -> String {
        if index.is_null() {
            return "None".to_string();
        }

        let mut parts = Vec::new();
        let mut current = index;
        let mut depth = 0;
        let mut visited = HashSet::new();
        const MAX_OUTER_DEPTH: usize = 128;

        while !current.is_null() && depth < MAX_OUTER_DEPTH {
            if !visited.insert(current) {
                // Cycle detected in outer chain
                break;
            }
            depth += 1;

            if let Some(exp_idx) = current.to_export_index() {
                if let Some(export) = export_table.get(exp_idx) {
                    let name = export
                        .object_name
                        .resolve(name_table)
                        .unwrap_or_else(|| format!("UnknownExport_{exp_idx}"));
                    parts.push(name);
                    current = export.outer_index;
                } else {
                    parts.push(format!("CorruptExport_{exp_idx}"));
                    break;
                }
            } else if let Some(imp_idx) = current.to_import_index() {
                if let Some(import) = import_table.get(imp_idx) {
                    let name = import
                        .object_name
                        .resolve(name_table)
                        .unwrap_or_else(|| format!("UnknownImport_{imp_idx}"));
                    parts.push(name);
                    current = import.outer_index;
                } else {
                    parts.push(format!("CorruptImport_{imp_idx}"));
                    break;
                }
            } else {
                break;
            }
        }

        if parts.is_empty() {
            "None".to_string()
        } else {
            parts.reverse();
            parts.join(".")
        }
    }

    /// Resolves the object name for a given `PackageIndex`.
    pub fn resolve_object_name(
        &self,
        name_table: &NameTable,
        import_table: &ImportTable,
        export_table: &ExportTable,
        index: PackageIndex,
    ) -> Option<String> {
        if index.is_null() {
            return Some("None".to_string());
        }
        if let Some(exp_idx) = index.to_export_index() {
            return export_table
                .get(exp_idx)
                .and_then(|e| e.object_name.resolve(name_table));
        }
        if let Some(imp_idx) = index.to_import_index() {
            return import_table
                .get(imp_idx)
                .and_then(|i| i.object_name.resolve(name_table));
        }
        None
    }

    /// Resolves the class name for an `ObjectExport`.
    pub fn resolve_class_name(
        &self,
        export: &ObjectExport,
        name_table: &NameTable,
        import_table: &ImportTable,
        export_table: &ExportTable,
    ) -> Option<String> {
        export.resolve_class_name(name_table, import_table, export_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{write_compressed_chunk, COMPRESS_LZO_XOR};
    use crate::name::{FName, NameEntry};
    use crate::summary::{GenerationInfo, PKG_COMPRESSED, PKG_COOKED};
    use crate::UPK_MAGIC;

    #[test]
    fn test_chunked_package_lzo_xor_roundtrip() {
        let names = NameTable::new(vec![
            NameEntry::new("None", 0),
            NameEntry::new("Core", 0),
            NameEntry::new("Object", 0),
            NameEntry::new("TestActor", 0),
        ]);
        let imports = ImportTable::new(vec![]);
        let exports = ExportTable::new(vec![ObjectExport {
            class_index: PackageIndex::NULL,
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(3, 0),
            archetype: PackageIndex::NULL,
            object_flags: 0x1,
            serial_size: 64,
            serial_offset: 0,
            export_flags: 0,
            generation_net_object_count: vec![],
            guid: [0u8; 16],
            package_flags: 0,
        }]);

        let mut chunk_payload = Vec::new();
        let name_off = 0usize;
        names.write(&mut chunk_payload).unwrap();
        let import_off = chunk_payload.len();
        imports.write(&mut chunk_payload).unwrap();
        let export_off = chunk_payload.len();
        exports.write(&mut chunk_payload).unwrap();
        let data_off = chunk_payload.len();
        let marker = b"XOR_MASKED_UPK_PAYLOAD_0123456789ABCDEF_REPEAT_TO_COMPRESS_";
        let repeated = marker.repeat(12);
        chunk_payload.extend_from_slice(&repeated);

        let mut placeholder_summary = PackageSummary {
            tag: UPK_MAGIC,
            file_version: 893,
            licensee_version: 0,
            total_header_size: 0,
            folder_name: "None".to_string(),
            package_flags: PKG_COOKED | PKG_COMPRESSED,
            name_count: names.len() as u32,
            name_offset: 0,
            export_count: exports.len() as u32,
            export_offset: 0,
            import_count: imports.len() as u32,
            import_offset: 0,
            depends_offset: 0,
            import_export_guids_offset: 0,
            import_guids_count: 0,
            export_guids_count: 0,
            thumbnail_table_offset: 0,
            guid: [0x2A; 16],
            generations: vec![GenerationInfo {
                export_count: 1,
                name_count: 4,
                net_object_count: 10,
            }],
            engine_version: 10897,
            cooker_version: 393358,
            compression_flags: COMPRESS_LZO_XOR,
            compressed_chunks: vec![FCompressedChunk {
                uncompressed_offset: 0,
                uncompressed_size: 0,
                compressed_offset: 0,
                compressed_size: 0,
            }],
        };

        let mut header_probe = Vec::new();
        placeholder_summary.write(&mut header_probe).unwrap();
        let header_len = header_probe.len() as u32;

        let mut chunk_bytes = Vec::new();
        let chunk_meta = write_compressed_chunk(
            &mut chunk_bytes,
            header_len,
            header_len,
            &chunk_payload,
            4096,
            COMPRESS_LZO_XOR,
        )
        .unwrap();

        placeholder_summary.total_header_size = header_len;
        placeholder_summary.name_offset = header_len + name_off as u32;
        placeholder_summary.import_offset = header_len + import_off as u32;
        placeholder_summary.export_offset = header_len + export_off as u32;
        placeholder_summary.compressed_chunks = vec![chunk_meta];

        let mut file_bytes = Vec::new();
        placeholder_summary.write(&mut file_bytes).unwrap();
        file_bytes.extend_from_slice(&chunk_bytes);

        let mut pkg = UpkPackage::open(Cursor::new(file_bytes)).unwrap();
        assert!(pkg.is_xor_compressed());
        assert_eq!(pkg.summary().compression_flags, COMPRESS_LZO_XOR);

        let (parsed_names, parsed_imports, parsed_exports) = pkg.read_tables().unwrap();
        assert_eq!(parsed_names, names);
        assert_eq!(parsed_imports, imports);
        assert_eq!(parsed_exports, exports);

        let all = pkg.decompress_all().unwrap();
        assert_eq!(
            &all[header_len as usize + data_off..header_len as usize + data_off + repeated.len()],
            repeated.as_slice()
        );

        let slice = pkg
            .read_bytes((header_len as usize + data_off) as u64, repeated.len())
            .unwrap();
        assert_eq!(slice, repeated);
    }
}
