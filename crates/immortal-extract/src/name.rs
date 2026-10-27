// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 Name Table and `FName` resolution.
//!
//! In Unreal packages, names are stored in a centralized Name Table (`FTableEntry`):
//! each entry contains a string (`FString`) and 64-bit object/name flags.
//! Names are referenced in imports, exports, and bytecode via `FName` (index + instance number).

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{Read, Write};

use crate::error::ExtractError;
use crate::fstring::{read_fstring, write_fstring};

/// Reference to a name in the package's Name Table with an instance number (`FName`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct FName {
    /// 0-based index into the Name Table.
    pub index: i32,
    /// Instance number. If `number > 0`, formatted as `"{name}_{number-1}"`, otherwise `"{name}"`.
    pub number: i32,
}

impl FName {
    /// Creates a new `FName`.
    pub const fn new(index: i32, number: i32) -> Self {
        Self { index, number }
    }

    /// Reads an `FName` from a little-endian binary stream (8 bytes: i32 index, i32 number).
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let index = reader.read_i32::<LittleEndian>()?;
        let number = reader.read_i32::<LittleEndian>()?;
        Ok(Self { index, number })
    }

    /// Writes an `FName` to a little-endian binary stream (8 bytes).
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_i32::<LittleEndian>(self.index)?;
        writer.write_i32::<LittleEndian>(self.number)?;
        Ok(())
    }

    /// Formats a base name string with an instance number.
    /// If `number > 0`, formatted as `"{base_name}_{number - 1}"`, otherwise `"{base_name}"`.
    pub fn format_instance(base_name: &str, number: i32) -> String {
        if number > 0 {
            format!("{base_name}_{}", number - 1)
        } else {
            base_name.to_string()
        }
    }

    /// Resolves and formats this `FName` against a `NameTable`.
    pub fn resolve(&self, table: &NameTable) -> Option<String> {
        if self.index < 0 {
            return None;
        }
        table
            .get(self.index as usize)
            .map(|entry| Self::format_instance(&entry.name, self.number))
    }

    /// Resolves and formats this `FName` against a `NameTable` (alias for `resolve`).
    pub fn format_with_table(&self, table: &NameTable) -> Option<String> {
        self.resolve(table)
    }
}

impl fmt::Display for FName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.number > 0 {
            write!(f, "FName({}_{})", self.index, self.number - 1)
        } else {
            write!(f, "FName({})", self.index)
        }
    }
}

/// An individual name entry stored in the package Name Table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NameEntry {
    /// String representation of the name.
    pub name: String,
    /// 64-bit object and serialization flags.
    pub flags: u64,
}

impl NameEntry {
    /// Creates a new `NameEntry`.
    pub fn new(name: impl Into<String>, flags: u64) -> Self {
        Self {
            name: name.into(),
            flags,
        }
    }

    /// Reads a `NameEntry` from a binary stream (`FString` followed by 64-bit flags).
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let name = read_fstring(reader)?;
        let flags = reader.read_u64::<LittleEndian>()?;
        Ok(Self { name, flags })
    }

    /// Writes a `NameEntry` to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let is_utf16 = !self.name.is_ascii();
        write_fstring(writer, &self.name, is_utf16)?;
        writer.write_u64::<LittleEndian>(self.flags)?;
        Ok(())
    }
}

/// The Name Table container for a UPK package.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct NameTable {
    entries: Vec<NameEntry>,
}

impl NameTable {
    /// Creates a new `NameTable` from a vector of `NameEntry` items.
    pub fn new(entries: Vec<NameEntry>) -> Self {
        Self { entries }
    }

    /// Returns a reference to the entry at `index`, if within bounds.
    pub fn get(&self, index: usize) -> Option<&NameEntry> {
        self.entries.get(index)
    }

    /// Returns the string for the entry at `index`, if within bounds.
    pub fn get_name(&self, index: usize) -> Option<&str> {
        self.get(index).map(|e| e.name.as_str())
    }

    /// Resolves an `FName` against this Name Table.
    pub fn resolve_fname(&self, fname: &FName) -> Option<String> {
        fname.resolve(self)
    }

    /// Returns the number of entries in the Name Table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the Name Table contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all name entries.
    pub fn entries(&self) -> &[NameEntry] {
        &self.entries
    }

    /// Reads `count` name entries from a binary reader.
    pub fn read<R: Read>(reader: &mut R, count: usize) -> Result<Self, ExtractError> {
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(NameEntry::read(reader)?);
        }
        Ok(Self { entries })
    }

    /// Writes all name entries to a binary writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for entry in &self.entries {
            entry.write(writer)?;
        }
        Ok(())
    }
}

impl From<Vec<NameEntry>> for NameTable {
    fn from(entries: Vec<NameEntry>) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_fname_formatting() {
        assert_eq!(FName::format_instance("Fernando", 0), "Fernando");
        assert_eq!(FName::format_instance("Fernando", 1), "Fernando_0");
        assert_eq!(FName::format_instance("Fernando", 42), "Fernando_41");
    }

    #[test]
    fn test_fname_resolve() {
        let table = NameTable::new(vec![
            NameEntry::new("None", 0),
            NameEntry::new("wwb_pc_knight", 0x00070010),
            NameEntry::new("akbank", 0),
        ]);

        let fname0 = FName::new(0, 0);
        assert_eq!(fname0.resolve(&table).as_deref(), Some("None"));

        let fname1 = FName::new(1, 0);
        assert_eq!(fname1.resolve(&table).as_deref(), Some("wwb_pc_knight"));

        let fname1_inst = FName::new(1, 3);
        assert_eq!(
            fname1_inst.resolve(&table).as_deref(),
            Some("wwb_pc_knight_2")
        );

        let fname_oob = FName::new(99, 0);
        assert_eq!(fname_oob.resolve(&table), None);
    }

    #[test]
    fn test_name_table_roundtrip() {
        let table = NameTable::new(vec![
            NameEntry::new("Core", 0),
            NameEntry::new("Engine", 10),
            NameEntry::new("Fernando", 20),
            NameEntry::new("wwb_pc_knight", 30),
        ]);

        let mut buf = Vec::new();
        table.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = NameTable::read(&mut cursor, table.len()).unwrap();
        assert_eq!(table, parsed);
    }
}
