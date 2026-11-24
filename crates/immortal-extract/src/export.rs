// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 Export Table and `ObjectExport` (`FObjectExport`).
//!
//! The Export Table describes all objects serialized within this package.
//! In Paladins UE3 (version 893), each `FObjectExport` has a 68-byte fixed layout
//! plus a variable-length `TArray<int32>` for `generation_net_object_count`.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::error::ExtractError;
use crate::import::ImportTable;
use crate::index::PackageIndex;
use crate::name::{FName, NameTable};

/// An entry in the package's Export Table (`FObjectExport`).
/// Minimum 68 bytes serialized in CookedPCConsole format when `generation_net_object_count` is empty.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectExport {
    /// Class index in the package index hierarchy (points to an Import or Export).
    pub class_index: PackageIndex,
    /// Super class index.
    pub super_index: PackageIndex,
    /// Outer object index (`0` if top-level).
    pub outer_index: PackageIndex,
    /// Name of this object (`FName`).
    pub object_name: FName,
    /// Archetype object index.
    pub archetype: PackageIndex,
    /// 64-bit Unreal object flags (`EObjectFlags`).
    pub object_flags: u64,
    /// Size of this object's serialized data stream in bytes.
    pub serial_size: i32,
    /// Offset of this object's serialized data within the uncompressed virtual package stream.
    pub serial_offset: i32,
    /// Export flags (`EF_ForcedExport`, etc.).
    pub export_flags: u32,
    /// Generation net object counts (`TArray<int32>`).
    pub generation_net_object_count: Vec<i32>,
    /// 16-byte object GUID.
    pub guid: [u8; 16],
    /// Package flags associated with this export.
    pub package_flags: u32,
}

impl ObjectExport {
    /// Minimum binary serialized size of an `ObjectExport` entry in Paladins UE3 (68 bytes when `generation_net_object_count` is empty).
    pub const MIN_SERIALIZED_SIZE: usize = 68;

    /// Returns the exact binary serialized size of this `ObjectExport` entry in bytes.
    pub fn serialized_size(&self) -> usize {
        Self::MIN_SERIALIZED_SIZE + self.generation_net_object_count.len() * 4
    }

    /// Reads an `ObjectExport` entry from a binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let class_index = PackageIndex::read(reader)?;
        let super_index = PackageIndex::read(reader)?;
        let outer_index = PackageIndex::read(reader)?;
        let object_name = FName::read(reader)?;
        let archetype = PackageIndex::read(reader)?;
        let object_flags = reader.read_u64::<LittleEndian>()?;
        let serial_size = reader.read_i32::<LittleEndian>()?;
        let serial_offset = reader.read_i32::<LittleEndian>()?;
        let export_flags = reader.read_u32::<LittleEndian>()?;
        let net_count = reader.read_i32::<LittleEndian>()?;
        if net_count < 0 {
            return Err(ExtractError::CorruptChunk {
                reason: format!("Negative generation_net_object_count length: {net_count}"),
            });
        }
        let net_len = net_count as usize;
        let mut generation_net_object_count = Vec::with_capacity(net_len.min(1024));
        for _ in 0..net_len {
            generation_net_object_count.push(reader.read_i32::<LittleEndian>()?);
        }
        let mut guid = [0u8; 16];
        reader.read_exact(&mut guid)?;
        let package_flags = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            class_index,
            super_index,
            outer_index,
            object_name,
            archetype,
            object_flags,
            serial_size,
            serial_offset,
            export_flags,
            generation_net_object_count,
            guid,
            package_flags,
        })
    }

    /// Writes an `ObjectExport` entry to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.class_index.write(writer)?;
        self.super_index.write(writer)?;
        self.outer_index.write(writer)?;
        self.object_name.write(writer)?;
        self.archetype.write(writer)?;
        writer.write_u64::<LittleEndian>(self.object_flags)?;
        writer.write_i32::<LittleEndian>(self.serial_size)?;
        writer.write_i32::<LittleEndian>(self.serial_offset)?;
        writer.write_u32::<LittleEndian>(self.export_flags)?;
        writer.write_i32::<LittleEndian>(self.generation_net_object_count.len() as i32)?;
        for &count in &self.generation_net_object_count {
            writer.write_i32::<LittleEndian>(count)?;
        }
        writer.write_all(&self.guid)?;
        writer.write_u32::<LittleEndian>(self.package_flags)?;
        Ok(())
    }

    /// Resolves the object's name against a `NameTable`.
    pub fn resolve_object_name(&self, name_table: &NameTable) -> Option<String> {
        self.object_name.resolve(name_table)
    }

    /// Resolves the class name of this export object.
    ///
    /// If `class_index` is an import (typical for engine/native classes), resolves via `import_table`.
    /// If `class_index` is an export (e.g. blueprint/archetype class), resolves via `export_table`.
    /// If `class_index` is null (`0`), represents `"Class"`.
    pub fn resolve_class_name(
        &self,
        name_table: &NameTable,
        import_table: &ImportTable,
        export_table: &ExportTable,
    ) -> Option<String> {
        if self.class_index.is_null() {
            return Some("Class".to_string());
        }
        if let Some(imp_idx) = self.class_index.to_import_index() {
            return import_table
                .get(imp_idx)
                .and_then(|imp| imp.object_name.resolve(name_table));
        }
        if let Some(exp_idx) = self.class_index.to_export_index() {
            return export_table
                .get(exp_idx)
                .and_then(|exp| exp.object_name.resolve(name_table));
        }
        None
    }
}

/// The Export Table container for a UPK package.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ExportTable {
    entries: Vec<ObjectExport>,
}

impl ExportTable {
    /// Creates a new `ExportTable` from a vector of `ObjectExport` items.
    pub fn new(entries: Vec<ObjectExport>) -> Self {
        Self { entries }
    }

    /// Returns a reference to the export entry at `index`, if within bounds.
    pub fn get(&self, index: usize) -> Option<&ObjectExport> {
        self.entries.get(index)
    }

    /// Returns the number of entries in the Export Table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the Export Table contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all export entries.
    pub fn entries(&self) -> &[ObjectExport] {
        &self.entries
    }

    /// Reads `count` export entries from a binary reader.
    pub fn read<R: Read>(reader: &mut R, count: usize) -> Result<Self, ExtractError> {
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(ObjectExport::read(reader)?);
        }
        Ok(Self { entries })
    }

    /// Writes all export entries to a binary writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for entry in &self.entries {
            entry.write(writer)?;
        }
        Ok(())
    }
}

impl From<Vec<ObjectExport>> for ExportTable {
    fn from(entries: Vec<ObjectExport>) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_export_entry_binary_roundtrip() {
        let export = ObjectExport {
            class_index: PackageIndex::from_import_index(3),
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(10, 0),
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 4096,
            serial_offset: 1048576,
            export_flags: 0x01,
            generation_net_object_count: vec![],
            guid: [0x77; 16],
            package_flags: 0,
        };

        let mut buf = Vec::new();
        export.write(&mut buf).unwrap();
        assert_eq!(buf.len(), ObjectExport::MIN_SERIALIZED_SIZE);
        assert_eq!(buf.len(), export.serialized_size());

        let mut cursor = Cursor::new(buf);
        let parsed = ObjectExport::read(&mut cursor).unwrap();
        assert_eq!(export, parsed);
    }

    #[test]
    fn test_export_entry_variable_net_object_counts() {
        let export = ObjectExport {
            class_index: PackageIndex::from_import_index(2),
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::from_export_index(0),
            object_name: FName::new(42, 1),
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 512,
            serial_offset: 8192,
            export_flags: 0x04,
            generation_net_object_count: vec![12, 34, 56],
            guid: [0xAB; 16],
            package_flags: 0x08,
        };

        let mut buf = Vec::new();
        export.write(&mut buf).unwrap();
        assert_eq!(buf.len(), ObjectExport::MIN_SERIALIZED_SIZE + 12);
        assert_eq!(buf.len(), export.serialized_size());

        let mut cursor = Cursor::new(buf);
        let parsed = ObjectExport::read(&mut cursor).unwrap();
        assert_eq!(export, parsed);
    }

    #[test]
    fn test_export_table_roundtrip() {
        let table = ExportTable::new(vec![
            ObjectExport {
                class_index: PackageIndex::from_import_index(0),
                super_index: PackageIndex::NULL,
                outer_index: PackageIndex::NULL,
                object_name: FName::new(1, 0),
                archetype: PackageIndex::NULL,
                object_flags: 0x00000004,
                serial_size: 100,
                serial_offset: 500,
                export_flags: 0,
                generation_net_object_count: vec![3, 7],
                guid: [1; 16],
                package_flags: 0,
            },
            ObjectExport {
                class_index: PackageIndex::NULL,
                super_index: PackageIndex::NULL,
                outer_index: PackageIndex::from_export_index(0),
                object_name: FName::new(2, 0),
                archetype: PackageIndex::NULL,
                object_flags: 0x00000004,
                serial_size: 200,
                serial_offset: 600,
                export_flags: 0,
                generation_net_object_count: vec![],
                guid: [2; 16],
                package_flags: 0,
            },
        ]);

        let mut buf = Vec::new();
        table.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 2 * ObjectExport::MIN_SERIALIZED_SIZE + 8);

        let mut cursor = Cursor::new(buf);
        let parsed = ExportTable::read(&mut cursor, table.len()).unwrap();
        assert_eq!(table, parsed);
    }
}
