// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 `FPackageIndex` resolution.
//!
//! In Unreal packages, object references are represented as 32-bit signed integers:
//! - `0`: Null reference (`None`).
//! - `> 0`: Export reference. 1-based index into the Export Table (`index - 1`).
//! - `< 0`: Import reference. 1-based negative index into the Import Table (`-index - 1`).

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{Read, Write};

use crate::error::ExtractError;

/// Unreal Engine 3 package index reference (`FPackageIndex`).
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
pub struct PackageIndex(pub i32);

impl PackageIndex {
    /// Null object reference (`0`).
    pub const NULL: Self = Self(0);

    /// Creates a new `PackageIndex` from a raw signed 32-bit integer.
    pub const fn new(val: i32) -> Self {
        Self(val)
    }

    /// Returns raw 32-bit signed integer value.
    pub const fn as_i32(&self) -> i32 {
        self.0
    }

    /// Returns `true` if this index represents a null reference (`0`).
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this index refers to an entry in the package's Export Table (`> 0`).
    pub const fn is_export(&self) -> bool {
        self.0 > 0
    }

    /// Returns `true` if this index refers to an entry in the package's Import Table (`< 0`).
    pub const fn is_import(&self) -> bool {
        self.0 < 0
    }

    /// Converts this index to a 0-based Export Table index, if positive.
    pub fn to_export_index(&self) -> Option<usize> {
        if self.0 > 0 {
            Some((self.0 - 1) as usize)
        } else {
            None
        }
    }

    /// Converts this index to a 0-based Import Table index, if negative.
    pub fn to_import_index(&self) -> Option<usize> {
        if self.0 < 0 {
            let inverted = -(self.0 as i64) - 1;
            Some(inverted as usize)
        } else {
            None
        }
    }

    /// Constructs a `PackageIndex` referencing a 0-based index in the Export Table.
    pub fn from_export_index(idx: usize) -> Self {
        Self((idx + 1) as i32)
    }

    /// Constructs a `PackageIndex` referencing a 0-based index in the Import Table.
    pub fn from_import_index(idx: usize) -> Self {
        Self(-((idx + 1) as i32))
    }

    /// Reads a `PackageIndex` from a little-endian binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let val = reader.read_i32::<LittleEndian>()?;
        Ok(Self(val))
    }

    /// Writes a `PackageIndex` to a little-endian binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_i32::<LittleEndian>(self.0)?;
        Ok(())
    }
}

impl From<i32> for PackageIndex {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

impl From<PackageIndex> for i32 {
    fn from(idx: PackageIndex) -> Self {
        idx.0
    }
}

impl fmt::Display for PackageIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "null")
        } else if let Some(exp) = self.to_export_index() {
            write!(f, "Export({exp})")
        } else if let Some(imp) = self.to_import_index() {
            write!(f, "Import({imp})")
        } else {
            write!(f, "PackageIndex({})", self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_package_index_semantics() {
        let null_idx = PackageIndex::NULL;
        assert!(null_idx.is_null());
        assert!(!null_idx.is_export());
        assert!(!null_idx.is_import());
        assert_eq!(null_idx.to_export_index(), None);
        assert_eq!(null_idx.to_import_index(), None);
        assert_eq!(null_idx.to_string(), "null");

        let exp_0 = PackageIndex::from_export_index(0);
        assert_eq!(exp_0.0, 1);
        assert!(exp_0.is_export());
        assert!(!exp_0.is_import());
        assert!(!exp_0.is_null());
        assert_eq!(exp_0.to_export_index(), Some(0));
        assert_eq!(exp_0.to_import_index(), None);
        assert_eq!(exp_0.to_string(), "Export(0)");

        let exp_42 = PackageIndex::from_export_index(42);
        assert_eq!(exp_42.0, 43);
        assert_eq!(exp_42.to_export_index(), Some(42));

        let imp_0 = PackageIndex::from_import_index(0);
        assert_eq!(imp_0.0, -1);
        assert!(imp_0.is_import());
        assert!(!imp_0.is_export());
        assert!(!imp_0.is_null());
        assert_eq!(imp_0.to_import_index(), Some(0));
        assert_eq!(imp_0.to_export_index(), None);
        assert_eq!(imp_0.to_string(), "Import(0)");

        let imp_7 = PackageIndex::from_import_index(7);
        assert_eq!(imp_7.0, -8);
        assert_eq!(imp_7.to_import_index(), Some(7));
    }

    #[test]
    fn test_package_index_binary_roundtrip() {
        let mut buf = Vec::new();
        let original = PackageIndex::from_export_index(1337);
        original.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = PackageIndex::read(&mut cursor).unwrap();
        assert_eq!(original, parsed);
    }
}
