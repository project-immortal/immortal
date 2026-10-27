// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 Import Table and `ObjectImport` (`FObjectImport`).
//!
//! The Import Table describes all external objects, packages, and classes referenced
//! by the current package.

use std::io::{Read, Write};

use crate::error::ExtractError;
use crate::index::PackageIndex;
use crate::name::{FName, NameTable};

/// An entry in the package's Import Table (`FObjectImport`).
/// Exactly 28 bytes serialized in CookedPCConsole format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct ObjectImport {
    /// Name of the package that defines the object's class.
    pub class_package: FName,
    /// Name of the object's class.
    pub class_name: FName,
    /// Outer index in the package index hierarchy (`0` if top-level / package).
    pub outer_index: PackageIndex,
    /// Object name.
    pub object_name: FName,
}

impl ObjectImport {
    /// Exact binary serialized size of an `ObjectImport` entry (28 bytes).
    pub const SERIALIZED_SIZE: usize = 28;

    /// Reads an `ObjectImport` entry from a binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let class_package = FName::read(reader)?;
        let class_name = FName::read(reader)?;
        let outer_index = PackageIndex::read(reader)?;
        let object_name = FName::read(reader)?;
        Ok(Self {
            class_package,
            class_name,
            outer_index,
            object_name,
        })
    }

    /// Writes an `ObjectImport` entry to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.class_package.write(writer)?;
        self.class_name.write(writer)?;
        self.outer_index.write(writer)?;
        self.object_name.write(writer)?;
        Ok(())
    }

    /// Resolves the object's name against a `NameTable`.
    pub fn resolve_object_name(&self, name_table: &NameTable) -> Option<String> {
        self.object_name.resolve(name_table)
    }

    /// Resolves the object's class name against a `NameTable`.
    pub fn resolve_class_name(&self, name_table: &NameTable) -> Option<String> {
        self.class_name.resolve(name_table)
    }

    /// Resolves the class package name against a `NameTable`.
    pub fn resolve_class_package(&self, name_table: &NameTable) -> Option<String> {
        self.class_package.resolve(name_table)
    }
}

/// The Import Table container for a UPK package.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ImportTable {
    entries: Vec<ObjectImport>,
}

impl ImportTable {
    /// Creates a new `ImportTable` from a vector of `ObjectImport` items.
    pub fn new(entries: Vec<ObjectImport>) -> Self {
        Self { entries }
    }

    /// Returns a reference to the import entry at `index`, if within bounds.
    pub fn get(&self, index: usize) -> Option<&ObjectImport> {
        self.entries.get(index)
    }

    /// Returns the number of entries in the Import Table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the Import Table contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all import entries.
    pub fn entries(&self) -> &[ObjectImport] {
        &self.entries
    }

    /// Reads `count` import entries from a binary reader.
    pub fn read<R: Read>(reader: &mut R, count: usize) -> Result<Self, ExtractError> {
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(ObjectImport::read(reader)?);
        }
        Ok(Self { entries })
    }

    /// Writes all import entries to a binary writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for entry in &self.entries {
            entry.write(writer)?;
        }
        Ok(())
    }
}

impl From<Vec<ObjectImport>> for ImportTable {
    fn from(entries: Vec<ObjectImport>) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_import_entry_binary_roundtrip() {
        let import = ObjectImport {
            class_package: FName::new(1, 0),
            class_name: FName::new(2, 0),
            outer_index: PackageIndex::NULL,
            object_name: FName::new(3, 0),
        };

        let mut buf = Vec::new();
        import.write(&mut buf).unwrap();
        assert_eq!(buf.len(), ObjectImport::SERIALIZED_SIZE);

        let mut cursor = Cursor::new(buf);
        let parsed = ObjectImport::read(&mut cursor).unwrap();
        assert_eq!(import, parsed);
    }

    #[test]
    fn test_import_table_roundtrip() {
        let table = ImportTable::new(vec![
            ObjectImport {
                class_package: FName::new(0, 0),
                class_name: FName::new(1, 0),
                outer_index: PackageIndex::NULL,
                object_name: FName::new(2, 0),
            },
            ObjectImport {
                class_package: FName::new(0, 0),
                class_name: FName::new(3, 0),
                outer_index: PackageIndex::from_import_index(0),
                object_name: FName::new(4, 1),
            },
        ]);

        let mut buf = Vec::new();
        table.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 2 * ObjectImport::SERIALIZED_SIZE);

        let mut cursor = Cursor::new(buf);
        let parsed = ImportTable::read(&mut cursor, table.len()).unwrap();
        assert_eq!(table, parsed);
    }
}
