// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 `FPropertyTag` tagged-property deserializer for version 893 UPK exports.
//!
//! Supports `IntProperty`, `FloatProperty`, `BoolProperty`, `ByteProperty`, `NameProperty`,
//! `ObjectProperty`, `StrProperty`, `StructProperty`, and `ArrayProperty`.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::error::ExtractError;
use crate::fstring::read_fstring;
use crate::index::PackageIndex;
use crate::name::{FName, NameTable};

/// Header preceding the tagged `FPropertyTag` chain in a serialized `UObject` export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectPropertyHeader {
    /// Present for `UComponent` subclasses (`UBrushComponent`, etc.).
    pub template_owner_class: Option<PackageIndex>,
    /// Replication `NetIndex` (`i32`).
    pub net_index: i32,
}

impl ObjectPropertyHeader {
    /// Reads the pre-property object header (`TemplateOwnerClass` if `is_component`, then `NetIndex`).
    pub fn read<R: Read>(reader: &mut R, is_component: bool) -> Result<Self, ExtractError> {
        let template_owner_class = if is_component {
            Some(PackageIndex::read(reader)?)
        } else {
            None
        };
        let net_index = reader.read_i32::<LittleEndian>()?;
        Ok(Self {
            template_owner_class,
            net_index,
        })
    }
}

/// Decoded atomic or nested value of a UE3 `StructProperty`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StructValue {
    /// Tagged-property struct (e.g. `KAggregateGeom`, `KConvexElem`, `KBoxElem`, etc.).
    Tagged(Vec<FPropertyTag>),
    /// Atomic 3D vector (`FVector`: 12 bytes).
    Vector([f32; 3]),
    /// Atomic 4D plane (`FPlane`: 16 bytes, stored in UE3 v893 as `[W, X, Y, Z]`).
    Plane([f32; 4]),
    /// Atomic 4x4 matrix (`FMatrix`: 64 bytes, 4 `FPlane`s converted to row-major `[[f32; 4]; 4]`).
    Matrix([[f32; 4]; 4]),
    /// Atomic axis-aligned bounding box (`FBox`: 25 bytes).
    Box {
        min: [f32; 3],
        max: [f32; 3],
        is_valid: bool,
    },
    /// Uninterpreted atomic struct bytes.
    Raw(Vec<u8>),
}

/// Decoded value of a UE3 `FPropertyTag`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PropertyValue {
    Int(i32),
    Float(f32),
    Bool(bool),
    Byte(u8),
    Enum {
        enum_name: String,
        value: FName,
    },
    Name(FName, Option<String>),
    Object(PackageIndex),
    Str(String),
    Struct {
        struct_name: String,
        data: StructValue,
    },
    Array {
        count: u32,
        raw_elements: Vec<u8>,
    },
    Raw(Vec<u8>),
}

/// A single deserialized UE3 `FPropertyTag`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FPropertyTag {
    pub name: String,
    pub prop_type: String,
    pub size: u32,
    pub array_index: u32,
    pub value: PropertyValue,
}

impl FPropertyTag {
    /// If this property is a `StructProperty` with tagged sub-properties, returns those tags.
    pub fn as_tagged_struct(&self) -> Option<&[FPropertyTag]> {
        match &self.value {
            PropertyValue::Struct {
                data: StructValue::Tagged(tags),
                ..
            } => Some(tags),
            _ => None,
        }
    }

    /// If this property is an `ArrayProperty` of tagged structs, parses each of the `count` elements.
    pub fn parse_struct_array(
        &self,
        name_table: &NameTable,
    ) -> Result<Vec<Vec<FPropertyTag>>, ExtractError> {
        match &self.value {
            PropertyValue::Array {
                count,
                raw_elements,
            } => parse_tagged_array_elements(raw_elements, *count, name_table),
            _ => Err(ExtractError::InvalidProperty {
                reason: format!("Property '{}' is not an ArrayProperty", self.name),
            }),
        }
    }
}

/// Finds the first property matching `name` (ASCII case-insensitive) in a tag slice.
pub fn find_property<'a>(tags: &'a [FPropertyTag], name: &str) -> Option<&'a FPropertyTag> {
    tags.iter().find(|t| t.name.eq_ignore_ascii_case(name))
}

/// Resolves an `FName` from a binary stream against `name_table`, returning an error on invalid index.
fn read_resolved_fname<R: Read>(
    reader: &mut R,
    name_table: &NameTable,
) -> Result<(FName, String), ExtractError> {
    let fname = FName::read(reader)?;
    let resolved = fname
        .resolve(name_table)
        .ok_or_else(|| ExtractError::InvalidProperty {
            reason: format!("Invalid FName index {} in property stream", fname.index),
        })?;
    Ok((fname, resolved))
}

/// Parses an array of `count` tagged-property structs from `raw_elements` (bytes after `count: u32`).
pub fn parse_tagged_array_elements(
    raw_elements: &[u8],
    count: u32,
    name_table: &NameTable,
) -> Result<Vec<Vec<FPropertyTag>>, ExtractError> {
    let mut cursor = Cursor::new(raw_elements);
    let mut items = Vec::with_capacity((count as usize).min(4096));
    for _ in 0..count {
        items.push(read_property_chain(&mut cursor, name_table)?);
    }
    Ok(items)
}

/// Reads an `FObject` export's pre-property header and tagged `FPropertyTag` chain.
/// Returns `(header, tags, bytes_consumed)`.
pub fn read_object_properties(
    raw_export: &[u8],
    name_table: &NameTable,
    is_component: bool,
) -> Result<(ObjectPropertyHeader, Vec<FPropertyTag>, usize), ExtractError> {
    let mut cursor = Cursor::new(raw_export);
    let header = ObjectPropertyHeader::read(&mut cursor, is_component)?;
    let tags = read_property_chain(&mut cursor, name_table)?;
    let consumed = cursor.position() as usize;
    Ok((header, tags, consumed))
}

/// Reads a chain of `FPropertyTag` entries until a `"None"` terminator `FName`.
pub fn read_property_chain<R: Read + Seek>(
    reader: &mut R,
    name_table: &NameTable,
) -> Result<Vec<FPropertyTag>, ExtractError> {
    let mut tags = Vec::new();

    loop {
        let (_, prop_name) = read_resolved_fname(reader, name_table)?;
        if prop_name.eq_ignore_ascii_case("None") {
            break;
        }

        let (_, prop_type) = read_resolved_fname(reader, name_table)?;
        let size = reader.read_u32::<LittleEndian>()?;
        let array_index = reader.read_u32::<LittleEndian>()?;

        let value = match prop_type.to_ascii_lowercase().as_str() {
            "intproperty" => {
                if size != 4 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("IntProperty '{prop_name}' has unexpected size {size}"),
                    });
                }
                PropertyValue::Int(reader.read_i32::<LittleEndian>()?)
            }
            "floatproperty" => {
                if size != 4 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("FloatProperty '{prop_name}' has unexpected size {size}"),
                    });
                }
                PropertyValue::Float(reader.read_f32::<LittleEndian>()?)
            }
            "boolproperty" => {
                if size != 0 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("BoolProperty '{prop_name}' has unexpected size {size}"),
                    });
                }
                let b = reader.read_u8()?;
                PropertyValue::Bool(b != 0)
            }
            "byteproperty" => {
                let (_, enum_name) = read_resolved_fname(reader, name_table)?;
                if enum_name.eq_ignore_ascii_case("None") && size == 1 {
                    PropertyValue::Byte(reader.read_u8()?)
                } else if size == 8 {
                    let (val_fname, _) = read_resolved_fname(reader, name_table)?;
                    PropertyValue::Enum {
                        enum_name,
                        value: val_fname,
                    }
                } else {
                    let mut buf = vec![0u8; size as usize];
                    reader.read_exact(&mut buf)?;
                    PropertyValue::Raw(buf)
                }
            }
            "nameproperty" => {
                if size != 8 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("NameProperty '{prop_name}' has unexpected size {size}"),
                    });
                }
                let fname = FName::read(reader)?;
                let resolved = fname.resolve(name_table);
                PropertyValue::Name(fname, resolved)
            }
            "objectproperty" => {
                if size != 4 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("ObjectProperty '{prop_name}' has unexpected size {size}"),
                    });
                }
                PropertyValue::Object(PackageIndex::read(reader)?)
            }
            "strproperty" => {
                let start = reader.stream_position()?;
                let s = read_fstring(reader)?;
                let expected_end = start + size as u64;
                if reader.stream_position()? != expected_end {
                    reader.seek(SeekFrom::Start(expected_end))?;
                }
                PropertyValue::Str(s)
            }
            "structproperty" => {
                let (_, struct_name) = read_resolved_fname(reader, name_table)?;
                let data = read_struct_value(reader, &struct_name, size, name_table)?;
                PropertyValue::Struct { struct_name, data }
            }
            "arrayproperty" => {
                if size < 4 {
                    return Err(ExtractError::InvalidProperty {
                        reason: format!("ArrayProperty '{prop_name}' size {size} < 4"),
                    });
                }
                let count = reader.read_u32::<LittleEndian>()?;
                let mut raw_elements = vec![0u8; (size - 4) as usize];
                reader.read_exact(&mut raw_elements)?;
                PropertyValue::Array {
                    count,
                    raw_elements,
                }
            }
            _ => {
                let mut raw = vec![0u8; size as usize];
                reader.read_exact(&mut raw)?;
                PropertyValue::Raw(raw)
            }
        };

        tags.push(FPropertyTag {
            name: prop_name,
            prop_type,
            size,
            array_index,
            value,
        });
    }

    Ok(tags)
}

fn read_struct_value<R: Read + Seek>(
    reader: &mut R,
    struct_name: &str,
    size: u32,
    name_table: &NameTable,
) -> Result<StructValue, ExtractError> {
    let start_pos = reader.stream_position()?;
    let end_pos = start_pos + size as u64;
    let lower = struct_name.to_ascii_lowercase();

    match lower.as_str() {
        "vector" if size == 12 => {
            let x = reader.read_f32::<LittleEndian>()?;
            let y = reader.read_f32::<LittleEndian>()?;
            let z = reader.read_f32::<LittleEndian>()?;
            Ok(StructValue::Vector([x, y, z]))
        }
        "plane" if size == 16 => {
            let w = reader.read_f32::<LittleEndian>()?;
            let x = reader.read_f32::<LittleEndian>()?;
            let y = reader.read_f32::<LittleEndian>()?;
            let z = reader.read_f32::<LittleEndian>()?;
            Ok(StructValue::Plane([w, x, y, z]))
        }
        "matrix" if size == 64 => {
            // In Paladins UE3 v893, FMatrix is 4 FPlane entries each serialized as (W, X, Y, Z).
            // Convert each plane into standard row-major [X, Y, Z, W] so row 3 is translation.
            let mut rows = [[0.0f32; 4]; 4];
            for row in &mut rows {
                let w = reader.read_f32::<LittleEndian>()?;
                let x = reader.read_f32::<LittleEndian>()?;
                let y = reader.read_f32::<LittleEndian>()?;
                let z = reader.read_f32::<LittleEndian>()?;
                *row = [x, y, z, w];
            }
            Ok(StructValue::Matrix(rows))
        }
        "box" if size == 25 => {
            let min = [
                reader.read_f32::<LittleEndian>()?,
                reader.read_f32::<LittleEndian>()?,
                reader.read_f32::<LittleEndian>()?,
            ];
            let max = [
                reader.read_f32::<LittleEndian>()?,
                reader.read_f32::<LittleEndian>()?,
                reader.read_f32::<LittleEndian>()?,
            ];
            let is_valid = reader.read_u8()? != 0;
            Ok(StructValue::Box { min, max, is_valid })
        }
        "rotator" | "color" | "linearcolor" | "guid" | "vector2d" | "intpoint" | "quat" => {
            let mut buf = vec![0u8; size as usize];
            reader.read_exact(&mut buf)?;
            Ok(StructValue::Raw(buf))
        }
        _ => {
            // Try tagged property deserialization if payload consumes exact `size` bytes.
            let mut buf = vec![0u8; size as usize];
            reader.read_exact(&mut buf)?;
            let mut sub_cursor = Cursor::new(buf.as_slice());
            if let Ok(sub_tags) = read_property_chain(&mut sub_cursor, name_table) {
                if sub_cursor.position() == size as u64 {
                    return Ok(StructValue::Tagged(sub_tags));
                }
            }
            reader.seek(SeekFrom::Start(end_pos))?;
            Ok(StructValue::Raw(buf))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fstring::write_fstring;
    use crate::name::NameEntry;
    use byteorder::WriteBytesExt;

    fn build_test_name_table() -> NameTable {
        NameTable::new(vec![
            NameEntry::new("None", 0),
            NameEntry::new("IntProperty", 0),
            NameEntry::new("FloatProperty", 0),
            NameEntry::new("BoolProperty", 0),
            NameEntry::new("ByteProperty", 0),
            NameEntry::new("NameProperty", 0),
            NameEntry::new("ObjectProperty", 0),
            NameEntry::new("StrProperty", 0),
            NameEntry::new("StructProperty", 0),
            NameEntry::new("ArrayProperty", 0),
            NameEntry::new("PrecachedPhysDataVersion", 0),
            NameEntry::new("Radius", 0),
            NameEntry::new("bNoRBCollision", 0),
            NameEntry::new("CollisionFlag", 0),
            NameEntry::new("BoneName", 0),
            NameEntry::new("PhysMaterial", 0),
            NameEntry::new("Label", 0),
            NameEntry::new("ElemBox", 0),
            NameEntry::new("Box", 0),
            NameEntry::new("VertexData", 0),
            NameEntry::new("AggGeom", 0),
            NameEntry::new("KAggregateGeom", 0),
        ])
    }

    fn write_fname(buf: &mut Vec<u8>, idx: i32) {
        buf.write_i32::<LittleEndian>(idx).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap();
    }

    #[test]
    fn test_read_all_supported_property_tag_types() {
        let names = build_test_name_table();
        let mut buf = Vec::new();

        // Component header: TemplateOwnerClass = 0, NetIndex = 7
        buf.write_i32::<LittleEndian>(0).unwrap();
        buf.write_i32::<LittleEndian>(7).unwrap();

        // 1. IntProperty
        write_fname(&mut buf, 10);
        write_fname(&mut buf, 1);
        buf.write_u32::<LittleEndian>(4).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_i32::<LittleEndian>(42).unwrap();

        // 2. FloatProperty
        write_fname(&mut buf, 11);
        write_fname(&mut buf, 2);
        buf.write_u32::<LittleEndian>(4).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_f32::<LittleEndian>(12.5).unwrap();

        // 3. BoolProperty (size 0, 1-byte value)
        write_fname(&mut buf, 12);
        write_fname(&mut buf, 3);
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_u8(1).unwrap();

        // 4. ByteProperty (raw byte: enum = None)
        write_fname(&mut buf, 13);
        write_fname(&mut buf, 4);
        buf.write_u32::<LittleEndian>(1).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut buf, 0); // None
        buf.write_u8(3).unwrap();

        // 5. NameProperty
        write_fname(&mut buf, 14);
        write_fname(&mut buf, 5);
        buf.write_u32::<LittleEndian>(8).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut buf, 11); // "Radius"

        // 6. ObjectProperty
        write_fname(&mut buf, 15);
        write_fname(&mut buf, 6);
        buf.write_u32::<LittleEndian>(4).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_i32::<LittleEndian>(-2).unwrap(); // Import(1)

        // 7. StrProperty
        let mut str_bytes = Vec::new();
        write_fstring(&mut str_bytes, "Fernando", false).unwrap();
        write_fname(&mut buf, 16);
        write_fname(&mut buf, 7);
        buf.write_u32::<LittleEndian>(str_bytes.len() as u32)
            .unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.extend_from_slice(&str_bytes);

        // 8. StructProperty (Box)
        write_fname(&mut buf, 17);
        write_fname(&mut buf, 8);
        buf.write_u32::<LittleEndian>(25).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut buf, 18); // Box
        for f in [-1.0f32, -2.0, -3.0, 1.0, 2.0, 3.0] {
            buf.write_f32::<LittleEndian>(f).unwrap();
        }
        buf.write_u8(1).unwrap();

        // 9. ArrayProperty (1 Vector)
        write_fname(&mut buf, 19);
        write_fname(&mut buf, 9);
        buf.write_u32::<LittleEndian>(4 + 12).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap();
        for f in [10.0f32, 20.0, 30.0] {
            buf.write_f32::<LittleEndian>(f).unwrap();
        }

        // Terminator None
        write_fname(&mut buf, 0);

        let (hdr, tags, consumed) = read_object_properties(&buf, &names, true).unwrap();
        assert_eq!(hdr.template_owner_class, Some(PackageIndex::NULL));
        assert_eq!(hdr.net_index, 7);
        assert_eq!(consumed, buf.len());
        assert_eq!(tags.len(), 9);

        assert_eq!(tags[0].value, PropertyValue::Int(42));
        assert_eq!(tags[1].value, PropertyValue::Float(12.5));
        assert_eq!(tags[2].value, PropertyValue::Bool(true));
        assert_eq!(tags[3].value, PropertyValue::Byte(3));
        assert_eq!(
            tags[4].value,
            PropertyValue::Name(FName::new(11, 0), Some("Radius".to_string()))
        );
        assert_eq!(
            tags[5].value,
            PropertyValue::Object(PackageIndex::from_import_index(1))
        );
        assert_eq!(tags[6].value, PropertyValue::Str("Fernando".to_string()));
        assert_eq!(
            tags[7].value,
            PropertyValue::Struct {
                struct_name: "Box".to_string(),
                data: StructValue::Box {
                    min: [-1.0, -2.0, -3.0],
                    max: [1.0, 2.0, 3.0],
                    is_valid: true,
                }
            }
        );
        match &tags[8].value {
            PropertyValue::Array {
                count,
                raw_elements,
            } => {
                assert_eq!(*count, 1);
                assert_eq!(raw_elements.len(), 12);
            }
            other => panic!("Expected Array, got {other:?}"),
        }
    }
}
