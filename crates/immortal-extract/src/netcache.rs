// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Cleanroom UE3 v893 `UProperty`, `UFunction`, `UEnum`, `UStruct`/`UClass`,
//! `FClassNetCache`, and `UPackageMap` manifest builder.
//!
//! Parses serialized property, function, enum, struct, and class exports from
//! Unreal Engine 3 (file version 893) packages to deterministically reconstruct
//! per-class replication tables (`RepIndex`, `FieldsBase`, `MaxIndex`) and
//! cumulative `UPackageMapLevel` object index ranges.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};

use crate::error::ExtractError;
use crate::export::{ExportTable, ObjectExport};
use crate::import::ImportTable;
use crate::index::PackageIndex;
use crate::name::{FName, NameTable};
use crate::package::{read_tables_from_bytes, UpkPackage};
use crate::summary::PackageSummary;

/// `CPF_Net`: Property is replicated over the network (implies `u16 RepOffset`).
pub const CPF_NET: u64 = 0x0000_0000_0000_0020;
/// `CPF_Parm`: Property is a function parameter.
pub const CPF_PARM: u64 = 0x0000_0000_0000_0080;
/// `CPF_ReturnParm`: Property is a function return value.
pub const CPF_RETURN_PARM: u64 = 0x0000_0000_0000_0400;
/// `CPF_RepNotify`: Property triggers a `ReplicatedEvent` notification on change.
pub const CPF_REP_NOTIFY: u64 = 0x0000_0001_0000_0000;

/// `FUNC_Net`: Function is replicated as an RPC (implies `u16 RepOffset`).
pub const FUNC_NET: u32 = 0x0000_0040;
/// `FUNC_NetServer`: Function executes on the server.
pub const FUNC_NET_SERVER: u32 = 0x0020_0000;
/// `FUNC_NetClient`: Function executes on the owning client.
pub const FUNC_NET_CLIENT: u32 = 0x0100_0000;

/// Maximum number of classes stored in `NetCacheRegistry` (`PSL-INV-011` bounded cache).
pub const MAX_NETCACHE_CLASSES: usize = 65_536;
/// Maximum number of packages in a `PackageMapManifest` (`PSL-INV-011` bounded cache).
pub const MAX_PACKAGE_MANIFEST_ENTRIES: usize = 1024;
/// Maximum traversal depth for `SuperClass` and `Children -> Next` chains.
pub const MAX_FIELD_CHAIN_DEPTH: usize = 4096;
/// Maximum number of entries allowed in a single `UEnum` export.
pub const MAX_ENUM_NAMES: usize = 65_536;
/// Maximum allowed `UFunction` script bytecode storage size (16 MiB).
pub const MAX_SCRIPT_STORAGE_SIZE: usize = 16 * 1024 * 1024;

/// Core Paladins package load order for `UPackageMapLevel` Shooting Range manifests.
pub const MINIMAL_SHOOTING_RANGE_PACKAGES: &[&str] = &[
    "Core",
    "Engine",
    "GFxUI",
    "GameFramework",
    "PlatformCommon",
    "Vivox",
    "AkAudio",
    "TgGame",
    "Shootingrange_P",
];

/// Supported UE3 `UProperty` subclass kinds in CookedPCConsole v893 packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PropertyClass {
    IntProperty,
    FloatProperty,
    BoolProperty,
    ByteProperty,
    StrProperty,
    NameProperty,
    ObjectProperty,
    ClassProperty,
    ComponentProperty,
    InterfaceProperty,
    StructProperty,
    ArrayProperty,
    DelegateProperty,
    MapProperty,
}

impl PropertyClass {
    /// Maps a UE3 class name string to a `PropertyClass`, if it is a `UProperty` subclass.
    pub fn from_class_name(name: &str) -> Option<Self> {
        match name {
            "IntProperty" => Some(Self::IntProperty),
            "FloatProperty" => Some(Self::FloatProperty),
            "BoolProperty" => Some(Self::BoolProperty),
            "ByteProperty" => Some(Self::ByteProperty),
            "StrProperty" => Some(Self::StrProperty),
            "NameProperty" => Some(Self::NameProperty),
            "ObjectProperty" => Some(Self::ObjectProperty),
            "ClassProperty" => Some(Self::ClassProperty),
            "ComponentProperty" => Some(Self::ComponentProperty),
            "InterfaceProperty" => Some(Self::InterfaceProperty),
            "StructProperty" => Some(Self::StructProperty),
            "ArrayProperty" => Some(Self::ArrayProperty),
            "DelegateProperty" => Some(Self::DelegateProperty),
            "MapProperty" => Some(Self::MapProperty),
            _ => None,
        }
    }

    /// Returns the canonical UE3 class name for this property kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntProperty => "IntProperty",
            Self::FloatProperty => "FloatProperty",
            Self::BoolProperty => "BoolProperty",
            Self::ByteProperty => "ByteProperty",
            Self::StrProperty => "StrProperty",
            Self::NameProperty => "NameProperty",
            Self::ObjectProperty => "ObjectProperty",
            Self::ClassProperty => "ClassProperty",
            Self::ComponentProperty => "ComponentProperty",
            Self::InterfaceProperty => "InterfaceProperty",
            Self::StructProperty => "StructProperty",
            Self::ArrayProperty => "ArrayProperty",
            Self::DelegateProperty => "DelegateProperty",
            Self::MapProperty => "MapProperty",
        }
    }

    /// Returns the expected subclass tail size in bytes after `RepOffset` (or `ArraySizeEnum`).
    pub const fn tail_bytes(self) -> usize {
        match self {
            Self::IntProperty
            | Self::FloatProperty
            | Self::BoolProperty
            | Self::StrProperty
            | Self::NameProperty => 0,
            Self::ByteProperty
            | Self::ObjectProperty
            | Self::ComponentProperty
            | Self::InterfaceProperty
            | Self::StructProperty
            | Self::ArrayProperty => 4,
            Self::ClassProperty | Self::DelegateProperty | Self::MapProperty => 8,
        }
    }
}

/// Subclass-specific trailing fields on a serialized UE3 `UProperty` export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyTail {
    /// `IntProperty`, `FloatProperty`, `BoolProperty`, `StrProperty`, `NameProperty`.
    None,
    /// `ByteProperty`: optional enum index (`0` if raw `u8`).
    Byte { enum_index: PackageIndex },
    /// `ObjectProperty`, `ComponentProperty`, `InterfaceProperty`.
    Object { property_class: PackageIndex },
    /// `StructProperty`: referenced `UScriptStruct`.
    Struct { struct_index: PackageIndex },
    /// `ArrayProperty`: inner element `UProperty`.
    Array { inner_index: PackageIndex },
    /// `ClassProperty`: base class (`Class`) and `MetaClass`.
    Class {
        property_class: PackageIndex,
        meta_class: PackageIndex,
    },
    /// `DelegateProperty`: target function and source delegate.
    Delegate {
        function_index: PackageIndex,
        source_delegate: PackageIndex,
    },
    /// `MapProperty`: key and value properties.
    Map {
        key_index: PackageIndex,
        value_index: PackageIndex,
    },
}

impl PropertyTail {
    /// Returns the primary referenced `PackageIndex` from the subclass tail, if any.
    pub const fn primary_type_index(&self) -> Option<PackageIndex> {
        match *self {
            Self::None => None,
            Self::Byte { enum_index } => Some(enum_index),
            Self::Object { property_class } => Some(property_class),
            Self::Struct { struct_index } => Some(struct_index),
            Self::Array { inner_index } => Some(inner_index),
            Self::Class { property_class, .. } => Some(property_class),
            Self::Delegate { function_index, .. } => Some(function_index),
            Self::Map { key_index, .. } => Some(key_index),
        }
    }
}

/// Parsed UE3 v893 `UProperty` export payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UPropertyExport {
    pub export_index: PackageIndex,
    pub name: String,
    pub class_kind: PropertyClass,
    pub net_index: i32,
    pub sentinel_name: FName,
    pub next: PackageIndex,
    pub array_dim: u16,
    pub element_size_flags: u16,
    pub property_flags: u64,
    pub category: FName,
    pub array_size_enum: PackageIndex,
    pub rep_offset: Option<u16>,
    pub tail: PropertyTail,
    pub tail_type_name: Option<String>,
}

impl UPropertyExport {
    /// Returns `true` if `CPF_Net` (`0x20`) is set.
    pub const fn is_net(&self) -> bool {
        (self.property_flags & CPF_NET) != 0
    }

    /// Returns `true` if this property is an inbound/outbound RPC parameter (`CPF_Parm && !CPF_ReturnParm`).
    pub const fn is_rpc_param(&self) -> bool {
        (self.property_flags & (CPF_PARM | CPF_RETURN_PARM)) == CPF_PARM
    }

    /// Returns `true` if `CPF_RepNotify` (`0x100000000`) is set.
    pub const fn is_rep_notify(&self) -> bool {
        (self.property_flags & CPF_REP_NOTIFY) != 0
    }

    /// Parses a UE3 v893 `UProperty` export from its serialized byte slice.
    pub fn parse(
        data: &[u8],
        class_kind: PropertyClass,
        name: String,
        export_index: PackageIndex,
        none_name_index: Option<i32>,
    ) -> Result<Self, ExtractError> {
        let mut cursor = Cursor::new(data);
        let net_index = cursor.read_i32::<LittleEndian>()?;
        let sentinel_name = FName::read(&mut cursor)?;
        verify_sentinel(&name, "UProperty", sentinel_name, none_name_index)?;

        let next = PackageIndex::read(&mut cursor)?;
        let array_dim = cursor.read_u16::<LittleEndian>()?;
        let element_size_flags = cursor.read_u16::<LittleEndian>()?;
        let property_flags = cursor.read_u64::<LittleEndian>()?;
        let category = FName::read(&mut cursor)?;
        let array_size_enum = PackageIndex::read(&mut cursor)?;

        let rep_offset = if (property_flags & CPF_NET) != 0 {
            Some(cursor.read_u16::<LittleEndian>()?)
        } else {
            None
        };

        let tail = match class_kind {
            PropertyClass::IntProperty
            | PropertyClass::FloatProperty
            | PropertyClass::BoolProperty
            | PropertyClass::StrProperty
            | PropertyClass::NameProperty => PropertyTail::None,
            PropertyClass::ByteProperty => PropertyTail::Byte {
                enum_index: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::ObjectProperty
            | PropertyClass::ComponentProperty
            | PropertyClass::InterfaceProperty => PropertyTail::Object {
                property_class: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::StructProperty => PropertyTail::Struct {
                struct_index: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::ArrayProperty => PropertyTail::Array {
                inner_index: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::ClassProperty => PropertyTail::Class {
                property_class: PackageIndex::read(&mut cursor)?,
                meta_class: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::DelegateProperty => PropertyTail::Delegate {
                function_index: PackageIndex::read(&mut cursor)?,
                source_delegate: PackageIndex::read(&mut cursor)?,
            },
            PropertyClass::MapProperty => PropertyTail::Map {
                key_index: PackageIndex::read(&mut cursor)?,
                value_index: PackageIndex::read(&mut cursor)?,
            },
        };

        let consumed = cursor.position() as usize;
        if consumed != data.len() {
            return Err(ExtractError::InvalidProperty {
                reason: format!(
                    "UProperty '{name}' ({}) length mismatch: parsed {consumed} bytes, export is {} bytes",
                    class_kind.as_str(),
                    data.len()
                ),
            });
        }

        Ok(Self {
            export_index,
            name,
            class_kind,
            net_index,
            sentinel_name,
            next,
            array_dim,
            element_size_flags,
            property_flags,
            category,
            array_size_enum,
            rep_offset,
            tail,
            tail_type_name: None,
        })
    }
}

/// Parsed UE3 v893 `UFunction` export payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UFunctionExport {
    pub export_index: PackageIndex,
    pub name: String,
    pub net_index: i32,
    pub sentinel_name: FName,
    pub next: PackageIndex,
    pub super_field: PackageIndex,
    pub script_text: PackageIndex,
    pub children: PackageIndex,
    pub cpp_text: PackageIndex,
    pub line: i32,
    pub text_pos: i32,
    pub script_bytecode_size: i32,
    pub script_storage_size: i32,
    pub native_index: u16,
    pub oper_precedence: u8,
    pub function_flags: u32,
    pub rep_offset: Option<u16>,
    pub friendly_name: FName,
    pub params: Vec<UPropertyExport>,
}

impl UFunctionExport {
    /// Returns `true` if `FUNC_Net` (`0x40`) is set.
    pub const fn is_net(&self) -> bool {
        (self.function_flags & FUNC_NET) != 0
    }

    /// Returns `true` if this is a base replicated RPC included in `UClass::NetFields`
    /// (`FUNC_Net` set, `SuperField == 0`, and `NetIndex >= 0`).
    pub const fn is_base_net_rpc(&self) -> bool {
        self.is_net() && self.super_field.is_null() && self.net_index >= 0
    }

    /// Parses a UE3 v893 `UFunction` export from its serialized byte slice.
    pub fn parse(
        data: &[u8],
        name: String,
        export_index: PackageIndex,
        none_name_index: Option<i32>,
    ) -> Result<Self, ExtractError> {
        let mut cursor = Cursor::new(data);
        let net_index = cursor.read_i32::<LittleEndian>()?;
        let sentinel_name = FName::read(&mut cursor)?;
        verify_sentinel(&name, "UFunction", sentinel_name, none_name_index)?;

        let next = PackageIndex::read(&mut cursor)?;
        let super_field = PackageIndex::read(&mut cursor)?;
        let script_text = PackageIndex::read(&mut cursor)?;
        let children = PackageIndex::read(&mut cursor)?;
        let cpp_text = PackageIndex::read(&mut cursor)?;
        let line = cursor.read_i32::<LittleEndian>()?;
        let text_pos = cursor.read_i32::<LittleEndian>()?;
        let script_bytecode_size = cursor.read_i32::<LittleEndian>()?;
        let script_storage_size = cursor.read_i32::<LittleEndian>()?;

        if script_storage_size < 0 || (script_storage_size as usize) > MAX_SCRIPT_STORAGE_SIZE {
            return Err(ExtractError::InvalidProperty {
                reason: format!(
                    "UFunction '{name}' has invalid ScriptStorageSize: {script_storage_size}"
                ),
            });
        }

        let skip_len = script_storage_size as usize;
        let pos = cursor.position() as usize;
        if pos + skip_len > data.len() {
            return Err(ExtractError::BufferOverflow {
                required: pos + skip_len,
                available: data.len(),
            });
        }
        cursor.set_position((pos + skip_len) as u64);

        let native_index = cursor.read_u16::<LittleEndian>()?;
        let oper_precedence = cursor.read_u8()?;
        let function_flags = cursor.read_u32::<LittleEndian>()?;

        let rep_offset = if (function_flags & FUNC_NET) != 0 {
            Some(cursor.read_u16::<LittleEndian>()?)
        } else {
            None
        };

        let friendly_name = FName::read(&mut cursor)?;

        let consumed = cursor.position() as usize;
        if consumed != data.len() {
            return Err(ExtractError::InvalidProperty {
                reason: format!(
                    "UFunction '{name}' length mismatch: parsed {consumed} bytes, export is {} bytes",
                    data.len()
                ),
            });
        }

        Ok(Self {
            export_index,
            name,
            net_index,
            sentinel_name,
            next,
            super_field,
            script_text,
            children,
            cpp_text,
            line,
            text_pos,
            script_bytecode_size,
            script_storage_size,
            native_index,
            oper_precedence,
            function_flags,
            rep_offset,
            friendly_name,
            params: Vec::new(),
        })
    }
}

/// Parsed UE3 v893 `UEnum` export payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UEnumExport {
    pub export_index: PackageIndex,
    pub name: String,
    pub net_index: i32,
    pub sentinel_name: FName,
    pub next: PackageIndex,
    pub names: Vec<FName>,
    pub resolved_names: Vec<String>,
}

impl UEnumExport {
    /// Parses a UE3 v893 `UEnum` export from its serialized byte slice.
    pub fn parse(
        data: &[u8],
        name: String,
        export_index: PackageIndex,
        name_table: &NameTable,
        none_name_index: Option<i32>,
    ) -> Result<Self, ExtractError> {
        let mut cursor = Cursor::new(data);
        let net_index = cursor.read_i32::<LittleEndian>()?;
        let sentinel_name = FName::read(&mut cursor)?;
        verify_sentinel(&name, "UEnum", sentinel_name, none_name_index)?;

        let next = PackageIndex::read(&mut cursor)?;
        let count = cursor.read_i32::<LittleEndian>()?;
        if count < 0 || (count as usize) > MAX_ENUM_NAMES {
            return Err(ExtractError::InvalidProperty {
                reason: format!("UEnum '{name}' has invalid element count: {count}"),
            });
        }

        let count_usize = count as usize;
        let mut names = Vec::with_capacity(count_usize);
        let mut resolved_names = Vec::with_capacity(count_usize);
        for _ in 0..count_usize {
            let entry = FName::read(&mut cursor)?;
            let resolved = entry
                .resolve(name_table)
                .unwrap_or_else(|| format!("<bad_fname:{}>", entry.index));
            names.push(entry);
            resolved_names.push(resolved);
        }

        let consumed = cursor.position() as usize;
        if consumed != data.len() {
            return Err(ExtractError::InvalidProperty {
                reason: format!(
                    "UEnum '{name}' length mismatch: parsed {consumed} bytes, export is {} bytes",
                    data.len()
                ),
            });
        }

        Ok(Self {
            export_index,
            name,
            net_index,
            sentinel_name,
            next,
            names,
            resolved_names,
        })
    }
}

/// Parsed UE3 v893 `UScriptStruct` or `UClass` chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UStructExport {
    pub export_index: PackageIndex,
    pub package_name: String,
    pub name: String,
    pub is_class: bool,
    pub net_index: i32,
    pub next: PackageIndex,
    pub super_field: PackageIndex,
    pub super_name: Option<String>,
    pub children: PackageIndex,
    pub fields: Vec<UPropertyExport>,
}

impl UStructExport {
    /// Parses the leading `UObject`/`UField`/`UStruct` header for a `ScriptStruct` export.
    pub fn parse_script_struct_header(
        data: &[u8],
        package_name: String,
        name: String,
        export_index: PackageIndex,
        super_name: Option<String>,
        none_name_index: Option<i32>,
    ) -> Result<Self, ExtractError> {
        let mut cursor = Cursor::new(data);
        let net_index = cursor.read_i32::<LittleEndian>()?;
        let sentinel_name = FName::read(&mut cursor)?;
        verify_sentinel(&name, "ScriptStruct", sentinel_name, none_name_index)?;

        let next = PackageIndex::read(&mut cursor)?;
        let super_field = PackageIndex::read(&mut cursor)?;
        let _script_text = PackageIndex::read(&mut cursor)?;
        let children = PackageIndex::read(&mut cursor)?;

        Ok(Self {
            export_index,
            package_name,
            name,
            is_class: false,
            net_index,
            next,
            super_field,
            super_name,
            children,
            fields: Vec::new(),
        })
    }

    /// Parses the leading `UField`/`UStruct` header for a `UClass` export (`class_index == 0`).
    pub fn parse_class_header(
        data: &[u8],
        package_name: String,
        name: String,
        export_index: PackageIndex,
        export_super_index: PackageIndex,
        super_name: Option<String>,
    ) -> Result<Self, ExtractError> {
        let mut cursor = Cursor::new(data);
        let net_index = cursor.read_i32::<LittleEndian>()?;
        let next = PackageIndex::read(&mut cursor)?;
        let serialized_super = PackageIndex::read(&mut cursor)?;
        let _script_text = PackageIndex::read(&mut cursor)?;
        let children = PackageIndex::read(&mut cursor)?;

        let super_field = if !export_super_index.is_null() {
            export_super_index
        } else {
            serialized_super
        };

        Ok(Self {
            export_index,
            package_name,
            name,
            is_class: true,
            net_index,
            next,
            super_field,
            super_name,
            children,
            fields: Vec::new(),
        })
    }
}

/// Parameter descriptor for a replicated `UFunction` RPC in `ClassNetCache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcParamSchema {
    pub name: String,
    pub property_class: PropertyClass,
    pub array_dim: u16,
    pub property_flags: u64,
    pub tail_type_name: Option<String>,
}

/// Discriminated metadata for an entry in `ClassNetCache` (`Property` vs `Function` RPC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetFieldKind {
    Property {
        property_class: PropertyClass,
        array_dim: u16,
        property_flags: u64,
        rep_offset: u16,
        tail_type_name: Option<String>,
    },
    Function {
        function_flags: u32,
        rep_offset: u16,
        params: Vec<RpcParamSchema>,
    },
}

/// A single replicated field (`FFieldNetCache` equivalent) inside a `ClassNetCache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldNetCacheEntry {
    pub rep_index: u32,
    pub owner_class: String,
    pub package_name: String,
    pub field_name: String,
    pub object_net_index: i32,
    pub global_object_index: Option<u32>,
    pub kind: NetFieldKind,
}

/// Reconstructed UE3 `FClassNetCache` for a `UClass`, including inherited `FieldsBase` and `MaxIndex`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassNetCache {
    pub class_name: String,
    pub super_class: Option<String>,
    pub package_name: String,
    pub fields_base: u32,
    pub own_fields: Vec<FieldNetCacheEntry>,
    pub max_index: u32,
}

impl ClassNetCache {
    /// Looks up a `RepIndex` within this class's own `[fields_base, max_index)` range.
    pub fn lookup_own(&self, rep_index: u32) -> Option<&FieldNetCacheEntry> {
        if rep_index < self.fields_base || rep_index >= self.max_index {
            return None;
        }
        self.own_fields.get((rep_index - self.fields_base) as usize)
    }
}

/// Entry in an ordered `UPackageMapLevel` manifest (`FPackageInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMapEntry {
    pub package_name: String,
    pub guid: [u8; 16],
    pub object_base: u32,
    pub object_count: u32,
    pub local_generation: u32,
    pub remote_generation: u32,
    pub package_flags: u32,
}

/// Cumulative `UPackageMapLevel` manifest computing `ObjectBase + ObjectCount` across ordered `.upk` packages.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PackageMapManifest {
    pub entries: Vec<PackageMapEntry>,
    pub total_objects: u32,
}

impl PackageMapManifest {
    /// Builds a `PackageMapManifest` from ordered `(package_name, &PackageSummary)` pairs
    /// using `Generations[0].net_object_count` as each package's `ObjectCount`.
    pub fn from_summaries<'a, I>(summaries: I) -> Result<Self, ExtractError>
    where
        I: IntoIterator<Item = (&'a str, &'a PackageSummary)>,
    {
        let mut entries = Vec::new();
        let mut running_base: u32 = 0;

        for (package_name, summary) in summaries {
            if entries.len() >= MAX_PACKAGE_MANIFEST_ENTRIES {
                return Err(ExtractError::CorruptChunk {
                    reason: format!(
                        "PackageMapManifest exceeded maximum {MAX_PACKAGE_MANIFEST_ENTRIES} entries"
                    ),
                });
            }

            let raw_net_count = summary
                .generations
                .first()
                .map(|g| g.net_object_count)
                .unwrap_or(0);
            if raw_net_count < 0 {
                return Err(ExtractError::CorruptChunk {
                    reason: format!(
                        "Package '{package_name}' has negative Generations[0].net_object_count: {raw_net_count}"
                    ),
                });
            }

            let object_count = raw_net_count as u32;
            let object_base = running_base;
            running_base = running_base
                .checked_add(object_count)
                .ok_or_else(|| ExtractError::CorruptChunk {
                    reason: format!(
                        "PackageMapManifest ObjectBase overflow at package '{package_name}'"
                    ),
                })?;

            entries.push(PackageMapEntry {
                package_name: package_name.to_string(),
                guid: summary.guid,
                object_base,
                object_count,
                local_generation: 1,
                remote_generation: 1,
                package_flags: summary.package_flags,
            });
        }

        Ok(Self {
            entries,
            total_objects: running_base,
        })
    }

    /// Builds a `PackageMapManifest` by reading headers from an ordered list of `.upk` paths.
    pub fn from_package_paths<P: AsRef<Path>>(paths: &[P]) -> Result<Self, ExtractError> {
        let mut parsed = Vec::with_capacity(paths.len().min(MAX_PACKAGE_MANIFEST_ENTRIES));
        for path in paths {
            let p = path.as_ref();
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| ExtractError::InvalidString {
                    reason: format!("Invalid package filename: {}", p.display()),
                })?
                .to_string();
            let pkg = UpkPackage::open_file(p)?;
            parsed.push((stem, pkg.summary().clone()));
        }

        Self::from_summaries(parsed.iter().map(|(name, summary)| (name.as_str(), summary)))
    }

    /// Looks up a package entry by package stem name.
    pub fn get(&self, package_name: &str) -> Option<&PackageMapEntry> {
        self.entries
            .iter()
            .find(|e| e.package_name.eq_ignore_ascii_case(package_name))
    }

    /// Computes `ObjectBase + NetIndex` for a `UObject` in the named package.
    pub fn resolve_global_index(&self, package_name: &str, net_index: i32) -> Option<u32> {
        if net_index < 0 {
            return None;
        }
        let entry = self.get(package_name)?;
        let ni = net_index as u32;
        if ni >= entry.object_count {
            return None;
        }
        Some(entry.object_base + ni)
    }

    /// Resolves a global `UPackageMapLevel` object index back to `(PackageMapEntry, local_net_index)`.
    pub fn resolve_net_index(&self, global_index: u32) -> Option<(&PackageMapEntry, u32)> {
        for entry in &self.entries {
            let end = entry.object_base.saturating_add(entry.object_count);
            if global_index >= entry.object_base && global_index < end {
                return Some((entry, global_index - entry.object_base));
            }
        }
        None
    }
}

/// Summary statistics for a single parsed `.upk` package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageParseStats {
    pub package_name: String,
    pub file_version: u16,
    pub licensee_version: u16,
    pub compression_flags: u32,
    pub net_object_count: i32,
    pub properties_parsed: usize,
    pub properties_failed: usize,
    pub net_properties: usize,
    pub functions_parsed: usize,
    pub functions_failed: usize,
    pub net_functions: usize,
    pub enums_parsed: usize,
    pub structs_parsed: usize,
    pub classes_parsed: usize,
}

#[derive(Debug, Clone)]
struct LoadedClassRecord {
    package_name: String,
    super_name: Option<String>,
    own_net_fields: Vec<RawNetField>,
}

#[derive(Debug, Clone)]
enum RawNetField {
    Prop(UPropertyExport),
    Func(UFunctionExport),
}

impl RawNetField {
    const fn net_index(&self) -> i32 {
        match self {
            Self::Prop(p) => p.net_index,
            Self::Func(f) => f.net_index,
        }
    }

    const fn export_index_i32(&self) -> i32 {
        match self {
            Self::Prop(p) => p.export_index.as_i32(),
            Self::Func(f) => f.export_index.as_i32(),
        }
    }
}

/// Cleanroom registry holding parsed UE3 v893 packages and bounded `ClassNetCache` instances.
#[derive(Debug, Default)]
pub struct NetCacheRegistry {
    classes: HashMap<String, LoadedClassRecord>,
    enums: HashMap<String, UEnumExport>,
    structs: HashMap<String, UStructExport>,
    cache_memo: BTreeMap<String, ClassNetCache>,
    manifest: Option<PackageMapManifest>,
    stats: Vec<PackageParseStats>,
}

impl NetCacheRegistry {
    /// Creates an empty `NetCacheRegistry`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a `NetCacheRegistry` configured with a `PackageMapManifest` for global object indices.
    pub fn with_manifest(manifest: PackageMapManifest) -> Self {
        Self {
            manifest: Some(manifest),
            ..Self::default()
        }
    }

    /// Attaches or replaces the `PackageMapManifest` and invalidates cached `ClassNetCache` entries.
    pub fn set_manifest(&mut self, manifest: PackageMapManifest) {
        self.manifest = Some(manifest);
        self.cache_memo.clear();
    }

    /// Returns the attached `PackageMapManifest`, if any.
    pub fn manifest(&self) -> Option<&PackageMapManifest> {
        self.manifest.as_ref()
    }

    /// Returns per-package parse telemetry for all loaded packages.
    pub fn package_stats(&self) -> &[PackageParseStats] {
        &self.stats
    }

    /// Looks up a parsed `UEnumExport` by name.
    pub fn get_enum(&self, enum_name: &str) -> Option<&UEnumExport> {
        self.enums.get(enum_name)
    }

    /// Looks up a parsed `UStructExport` (`ScriptStruct`) by name.
    pub fn get_struct(&self, struct_name: &str) -> Option<&UStructExport> {
        self.structs.get(struct_name)
    }

    /// Loads and parses a `.upk` file from disk into the registry.
    pub fn load_package_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<PackageParseStats, ExtractError> {
        let path_ref = path.as_ref();
        let package_name = path_ref
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ExtractError::InvalidString {
                reason: format!("Invalid package filename: {}", path_ref.display()),
            })?
            .to_string();
        let mut pkg = UpkPackage::open_file(path_ref)?;
        self.load_package(&package_name, &mut pkg)
    }

    /// Loads and parses an opened `UpkPackage` into the registry.
    pub fn load_package<R: Read + Seek>(
        &mut self,
        package_name: &str,
        pkg: &mut UpkPackage<R>,
    ) -> Result<PackageParseStats, ExtractError> {
        let summary = pkg.summary().clone();
        let virtual_stream = pkg.decompress_all()?;
        let (name_table, import_table, export_table) =
            read_tables_from_bytes(&virtual_stream, &summary)?;

        let none_name_index = name_table
            .entries()
            .iter()
            .position(|entry| entry.name == "None")
            .map(|idx| idx as i32);

        let mut stats = PackageParseStats {
            package_name: package_name.to_string(),
            file_version: summary.file_version,
            licensee_version: summary.licensee_version,
            compression_flags: summary.compression_flags,
            net_object_count: summary
                .generations
                .first()
                .map(|g| g.net_object_count)
                .unwrap_or(0),
            properties_parsed: 0,
            properties_failed: 0,
            net_properties: 0,
            functions_parsed: 0,
            functions_failed: 0,
            net_functions: 0,
            enums_parsed: 0,
            structs_parsed: 0,
            classes_parsed: 0,
        };

        let mut parsed_props: HashMap<i32, UPropertyExport> = HashMap::new();
        let mut parsed_funcs: Vec<(i32, UFunctionExport)> = Vec::new();
        let mut parsed_structs: Vec<UStructExport> = Vec::new();
        let mut class_exports: HashMap<i32, (String, Option<String>)> = HashMap::new();

        for (idx, export) in export_table.entries().iter().enumerate() {
            let exp_pkg_idx = PackageIndex::from_export_index(idx);
            let exp_name = export
                .resolve_object_name(&name_table)
                .unwrap_or_else(|| format!("Export_{idx}"));
            let class_name = export
                .resolve_class_name(&name_table, &import_table, &export_table)
                .unwrap_or_default();

            let slice = slice_export_bytes(&virtual_stream, export)?;

            if export.class_index.is_null() {
                // Cooked map packages contain stripped 0-byte placeholder exports with class_idx=0.
                if export.serial_size <= 0 {
                    continue;
                }
                if self.classes.len() >= MAX_NETCACHE_CLASSES {
                    return Err(ExtractError::CorruptChunk {
                        reason: format!(
                            "NetCacheRegistry exceeded MAX_NETCACHE_CLASSES ({MAX_NETCACHE_CLASSES})"
                        ),
                    });
                }
                let super_name = resolve_package_index_name(
                    export.super_index,
                    &name_table,
                    &import_table,
                    &export_table,
                );
                let _header = UStructExport::parse_class_header(
                    slice,
                    package_name.to_string(),
                    exp_name.clone(),
                    exp_pkg_idx,
                    export.super_index,
                    super_name.clone(),
                )?;
                class_exports.insert(exp_pkg_idx.as_i32(), (exp_name.clone(), super_name.clone()));
                self.classes.insert(
                    exp_name,
                    LoadedClassRecord {
                        package_name: package_name.to_string(),
                        super_name,
                        own_net_fields: Vec::new(),
                    },
                );
                stats.classes_parsed += 1;
                continue;
            }

            if let Some(prop_kind) = PropertyClass::from_class_name(&class_name) {
                match UPropertyExport::parse(slice, prop_kind, exp_name, exp_pkg_idx, none_name_index) {
                    Ok(mut prop) => {
                        prop.tail_type_name = prop.tail.primary_type_index().and_then(|tidx| {
                            resolve_package_index_name(
                                tidx,
                                &name_table,
                                &import_table,
                                &export_table,
                            )
                        });
                        if prop.is_net() {
                            stats.net_properties += 1;
                        }
                        stats.properties_parsed += 1;
                        parsed_props.insert(exp_pkg_idx.as_i32(), prop);
                    }
                    Err(_) => {
                        stats.properties_failed += 1;
                    }
                }
            } else if class_name == "Function" {
                match UFunctionExport::parse(slice, exp_name, exp_pkg_idx, none_name_index) {
                    Ok(func) => {
                        if func.is_net() {
                            stats.net_functions += 1;
                        }
                        stats.functions_parsed += 1;
                        parsed_funcs.push((export.outer_index.as_i32(), func));
                    }
                    Err(_) => {
                        stats.functions_failed += 1;
                    }
                }
            } else if class_name == "Enum" {
                let enum_exp = UEnumExport::parse(
                    slice,
                    exp_name.clone(),
                    exp_pkg_idx,
                    &name_table,
                    none_name_index,
                )?;
                self.enums.insert(exp_name, enum_exp);
                stats.enums_parsed += 1;
            } else if class_name == "ScriptStruct" {
                let super_name = resolve_package_index_name(
                    export.super_index,
                    &name_table,
                    &import_table,
                    &export_table,
                );
                let struct_exp = UStructExport::parse_script_struct_header(
                    slice,
                    package_name.to_string(),
                    exp_name,
                    exp_pkg_idx,
                    super_name,
                    none_name_index,
                )?;
                parsed_structs.push(struct_exp);
                stats.structs_parsed += 1;
            }
        }

        // Populate ordered RPC parameter lists via each UFunction's `Children -> Next` chain.
        for (outer_i32, mut func) in parsed_funcs {
            func.params = collect_children_properties(
                func.children,
                &parsed_props,
                &virtual_stream,
                &export_table,
                true,
            )?;

            if let Some((cls_name, _)) = class_exports.get(&outer_i32) {
                if func.is_base_net_rpc() {
                    if let Some(record) = self.classes.get_mut(cls_name) {
                        record.own_net_fields.push(RawNetField::Func(func));
                    }
                }
            }
        }

        // Populate ScriptStruct field lists in `Children -> Next` order.
        for mut st in parsed_structs {
            st.fields = collect_children_properties(
                st.children,
                &parsed_props,
                &virtual_stream,
                &export_table,
                false,
            )?;
            self.structs.insert(st.name.clone(), st);
        }

        // Attach CPF_Net properties owned directly by each UClass (outer_index == class export).
        for (prop_id, prop) in parsed_props {
            if !prop.is_net() || prop.net_index < 0 {
                continue;
            }
            if let Some(exp_idx) = PackageIndex::new(prop_id).to_export_index() {
                if let Some(export) = export_table.get(exp_idx) {
                    if let Some((cls_name, _)) = class_exports.get(&export.outer_index.as_i32()) {
                        if let Some(record) = self.classes.get_mut(cls_name) {
                            record.own_net_fields.push(RawNetField::Prop(prop));
                        }
                    }
                }
            }
        }

        // Invalidate cached ClassNetCache entries when a new package is loaded.
        self.cache_memo.clear();
        self.stats.push(stats.clone());
        Ok(stats)
    }

    /// Recursively constructs (or returns cached) `ClassNetCache` for `class_name`.
    pub fn build_class_net_cache(&mut self, class_name: &str) -> Result<ClassNetCache, ExtractError> {
        let mut visiting = HashSet::new();
        self.build_class_net_cache_inner(class_name, &mut visiting, 0)
    }

    fn build_class_net_cache_inner(
        &mut self,
        class_name: &str,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> Result<ClassNetCache, ExtractError> {
        if let Some(cached) = self.cache_memo.get(class_name) {
            return Ok(cached.clone());
        }

        if depth >= MAX_FIELD_CHAIN_DEPTH {
            return Err(ExtractError::CorruptChunk {
                reason: format!("Class inheritance depth exceeded {MAX_FIELD_CHAIN_DEPTH} at '{class_name}'"),
            });
        }

        if !visiting.insert(class_name.to_string()) {
            return Err(ExtractError::CorruptChunk {
                reason: format!("Cycle detected in class inheritance at '{class_name}'"),
            });
        }

        let record = match self.classes.get(class_name) {
            Some(rec) => rec.clone(),
            None => {
                visiting.remove(class_name);
                return Ok(ClassNetCache {
                    class_name: class_name.to_string(),
                    super_class: None,
                    package_name: String::new(),
                    fields_base: 0,
                    own_fields: Vec::new(),
                    max_index: 0,
                });
            }
        };

        let fields_base = if let Some(ref sup_name) = record.super_name {
            let sup_cache =
                self.build_class_net_cache_inner(sup_name, visiting, depth + 1)?;
            sup_cache.max_index
        } else {
            0
        };

        let mut sorted = record.own_net_fields;
        sorted.sort_by_key(|field| (field.net_index(), field.export_index_i32()));

        let mut own_fields = Vec::with_capacity(sorted.len());
        for (offset, field) in sorted.into_iter().enumerate() {
            let rep_index = fields_base + offset as u32;
            let object_net_index = field.net_index();
            let global_object_index = self
                .manifest
                .as_ref()
                .and_then(|m| m.resolve_global_index(&record.package_name, object_net_index));

            let (field_name, kind) = match field {
                RawNetField::Prop(prop) => (
                    prop.name,
                    NetFieldKind::Property {
                        property_class: prop.class_kind,
                        array_dim: prop.array_dim,
                        property_flags: prop.property_flags,
                        rep_offset: prop.rep_offset.unwrap_or(0),
                        tail_type_name: prop.tail_type_name,
                    },
                ),
                RawNetField::Func(func) => {
                    let params = func
                        .params
                        .into_iter()
                        .map(|p| RpcParamSchema {
                            name: p.name,
                            property_class: p.class_kind,
                            array_dim: p.array_dim,
                            property_flags: p.property_flags,
                            tail_type_name: p.tail_type_name,
                        })
                        .collect();
                    (
                        func.name,
                        NetFieldKind::Function {
                            function_flags: func.function_flags,
                            rep_offset: func.rep_offset.unwrap_or(0),
                            params,
                        },
                    )
                }
            };

            own_fields.push(FieldNetCacheEntry {
                rep_index,
                owner_class: class_name.to_string(),
                package_name: record.package_name.clone(),
                field_name,
                object_net_index,
                global_object_index,
                kind,
            });
        }

        let max_index = fields_base + own_fields.len() as u32;
        let cache = ClassNetCache {
            class_name: class_name.to_string(),
            super_class: record.super_name,
            package_name: record.package_name,
            fields_base,
            own_fields,
            max_index,
        };

        visiting.remove(class_name);

        if self.cache_memo.len() < MAX_NETCACHE_CLASSES {
            self.cache_memo.insert(class_name.to_string(), cache.clone());
        }

        Ok(cache)
    }

    /// Resolves a `RepIndex` across `class_name` and its superclass chain (`FClassNetCache::GetFromIndex`).
    pub fn lookup_rep_field(
        &mut self,
        class_name: &str,
        rep_index: u32,
    ) -> Result<Option<FieldNetCacheEntry>, ExtractError> {
        let mut current = Some(class_name.to_string());
        let mut visited = HashSet::new();

        while let Some(cname) = current {
            if visited.len() >= MAX_FIELD_CHAIN_DEPTH || !visited.insert(cname.clone()) {
                break;
            }
            let cache = self.build_class_net_cache(&cname)?;
            if let Some(entry) = cache.lookup_own(rep_index) {
                return Ok(Some(entry.clone()));
            }
            current = cache.super_class;
        }

        Ok(None)
    }
}

fn verify_sentinel(
    object_name: &str,
    kind: &str,
    sentinel: FName,
    none_name_index: Option<i32>,
) -> Result<(), ExtractError> {
    if let Some(expected_none) = none_name_index {
        if sentinel.index != expected_none || sentinel.number != 0 {
            return Err(ExtractError::InvalidProperty {
                reason: format!(
                    "{kind} '{object_name}' sentinel FName mismatch: expected None ({expected_none}, 0), got ({}, {})",
                    sentinel.index, sentinel.number
                ),
            });
        }
    }
    Ok(())
}

fn slice_export_bytes<'a>(
    virtual_stream: &'a [u8],
    export: &ObjectExport,
) -> Result<&'a [u8], ExtractError> {
    if export.serial_size <= 0 {
        return Ok(&[]);
    }
    if export.serial_offset < 0 {
        return Err(ExtractError::BufferOverflow {
            required: export.serial_size as usize,
            available: 0,
        });
    }
    let start = export.serial_offset as usize;
    let end = start.saturating_add(export.serial_size as usize);
    virtual_stream
        .get(start..end)
        .ok_or(ExtractError::BufferOverflow {
            required: end,
            available: virtual_stream.len(),
        })
}

fn resolve_package_index_name(
    index: PackageIndex,
    name_table: &NameTable,
    import_table: &ImportTable,
    export_table: &ExportTable,
) -> Option<String> {
    if index.is_null() {
        return None;
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

fn collect_children_properties(
    first_child: PackageIndex,
    parsed_props: &HashMap<i32, UPropertyExport>,
    virtual_stream: &[u8],
    export_table: &ExportTable,
    rpc_params_only: bool,
) -> Result<Vec<UPropertyExport>, ExtractError> {
    let mut out = Vec::new();
    let mut current = first_child;
    let mut visited = HashSet::new();

    while let Some(exp_idx) = current.to_export_index() {
        if visited.len() >= MAX_FIELD_CHAIN_DEPTH || !visited.insert(current.as_i32()) {
            break;
        }

        if let Some(prop) = parsed_props.get(&current.as_i32()) {
            if !rpc_params_only || prop.is_rpc_param() {
                out.push(prop.clone());
            }
            current = prop.next;
            continue;
        }

        // Non-standard UField node (e.g. SafeObjectProperty inside a ScriptStruct): read `Next` at +0x0c.
        let Some(export) = export_table.get(exp_idx) else {
            break;
        };
        let bytes = slice_export_bytes(virtual_stream, export)?;
        if bytes.len() < 16 {
            break;
        }
        let mut cursor = Cursor::new(&bytes[12..16]);
        current = PackageIndex::read(&mut cursor)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{write_compressed_chunk, FCompressedChunk, COMPRESS_LZO_XOR};
    use crate::export::ObjectExport;
    use crate::import::ObjectImport;
    use crate::name::NameEntry;
    use crate::summary::{GenerationInfo, PKG_COMPRESSED, PKG_COOKED};
    use crate::UPK_MAGIC;
    use byteorder::WriteBytesExt;

    struct TestPropSpec<'a> {
        net_index: i32,
        none_idx: i32,
        next: i32,
        array_dim: u16,
        elem_flags: u16,
        property_flags: u64,
        category: FName,
        rep_offset: Option<u16>,
        tail_indices: &'a [i32],
    }

    fn write_uproperty_bytes(spec: TestPropSpec<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_i32::<LittleEndian>(spec.net_index).unwrap();
        FName::new(spec.none_idx, 0).write(&mut buf).unwrap();
        buf.write_i32::<LittleEndian>(spec.next).unwrap();
        buf.write_u16::<LittleEndian>(spec.array_dim).unwrap();
        buf.write_u16::<LittleEndian>(spec.elem_flags).unwrap();
        buf.write_u64::<LittleEndian>(spec.property_flags).unwrap();
        spec.category.write(&mut buf).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap();
        if let Some(ro) = spec.rep_offset {
            buf.write_u16::<LittleEndian>(ro).unwrap();
        }
        for &idx in spec.tail_indices {
            buf.write_i32::<LittleEndian>(idx).unwrap();
        }
        buf
    }

    struct TestFuncSpec<'a> {
        net_index: i32,
        none_idx: i32,
        next: i32,
        super_field: i32,
        children: i32,
        bytecode: &'a [u8],
        function_flags: u32,
        rep_offset: Option<u16>,
        friendly_name: FName,
    }

    fn write_ufunction_bytes(spec: TestFuncSpec<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_i32::<LittleEndian>(spec.net_index).unwrap();
        FName::new(spec.none_idx, 0).write(&mut buf).unwrap();
        buf.write_i32::<LittleEndian>(spec.next).unwrap();
        buf.write_i32::<LittleEndian>(spec.super_field).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap(); // ScriptText
        buf.write_i32::<LittleEndian>(spec.children).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap(); // CppText
        buf.write_i32::<LittleEndian>(1).unwrap(); // Line
        buf.write_i32::<LittleEndian>(0).unwrap(); // TextPos
        buf.write_i32::<LittleEndian>(spec.bytecode.len() as i32)
            .unwrap();
        buf.write_i32::<LittleEndian>(spec.bytecode.len() as i32)
            .unwrap();
        buf.extend_from_slice(spec.bytecode);
        buf.write_u16::<LittleEndian>(0).unwrap();
        buf.write_u8(0).unwrap();
        buf.write_u32::<LittleEndian>(spec.function_flags).unwrap();
        if let Some(ro) = spec.rep_offset {
            buf.write_u16::<LittleEndian>(ro).unwrap();
        }
        spec.friendly_name.write(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_parse_uproperty_all_subclasses_and_rep_offset() {
        let none_idx = 0;
        let cases: &[(PropertyClass, u64, Option<u16>, &[i32])] = &[
            (PropertyClass::IntProperty, CPF_NET, Some(0x0120), &[]),
            (PropertyClass::FloatProperty, 0, None, &[]),
            (PropertyClass::BoolProperty, CPF_NET | CPF_REP_NOTIFY, Some(0x0044), &[]),
            (PropertyClass::StrProperty, 0, None, &[]),
            (PropertyClass::NameProperty, 0, None, &[]),
            (PropertyClass::ByteProperty, CPF_NET, Some(0x0010), &[-3]),
            (PropertyClass::ObjectProperty, CPF_NET, Some(0x0200), &[-4]),
            (PropertyClass::ComponentProperty, 0, None, &[-5]),
            (PropertyClass::InterfaceProperty, 0, None, &[-6]),
            (PropertyClass::StructProperty, CPF_NET, Some(0x0080), &[-7]),
            (PropertyClass::ArrayProperty, 0, None, &[12]),
            (PropertyClass::ClassProperty, CPF_NET, Some(0x0090), &[-8, -9]),
            (PropertyClass::DelegateProperty, 0, None, &[15, 16]),
            (PropertyClass::MapProperty, 0, None, &[17, 18]),
        ];

        for &(kind, flags, rep_off, tail) in cases {
            let bytes = write_uproperty_bytes(TestPropSpec {
                net_index: 77,
                none_idx,
                next: 5,
                array_dim: 2,
                elem_flags: 4,
                property_flags: flags,
                category: FName::new(1, 0),
                rep_offset: rep_off,
                tail_indices: tail,
            });
            let parsed = UPropertyExport::parse(
                &bytes,
                kind,
                format!("Prop_{}", kind.as_str()),
                PackageIndex::from_export_index(0),
                Some(none_idx),
            )
            .unwrap();
            assert_eq!(parsed.net_index, 77);
            assert_eq!(parsed.next, PackageIndex::new(5));
            assert_eq!(parsed.array_dim, 2);
            assert_eq!(parsed.property_flags, flags);
            assert_eq!(parsed.rep_offset, rep_off);
            assert_eq!(parsed.is_net(), (flags & CPF_NET) != 0);
        }

        // Trailing garbage byte must be rejected
        let mut bad = write_uproperty_bytes(TestPropSpec {
            net_index: 1,
            none_idx,
            next: 0,
            array_dim: 1,
            elem_flags: 4,
            property_flags: 0,
            category: FName::new(1, 0),
            rep_offset: None,
            tail_indices: &[],
        });
        bad.push(0xAA);
        assert!(UPropertyExport::parse(
            &bad,
            PropertyClass::IntProperty,
            "BadProp".to_string(),
            PackageIndex::from_export_index(0),
            Some(none_idx),
        )
        .is_err());
    }

    #[test]
    fn test_parse_ufunction_and_uenum() {
        let none_idx = 0;
        let bytecode = [0x0B, 0x53, 0x01, 0x00];
        let fn_bytes = write_ufunction_bytes(TestFuncSpec {
            net_index: 310,
            none_idx,
            next: 9,
            super_field: 0,
            children: 11,
            bytecode: &bytecode,
            function_flags: FUNC_NET | FUNC_NET_SERVER,
            rep_offset: Some(0x0018),
            friendly_name: FName::new(2, 0),
        });
        let parsed_fn = UFunctionExport::parse(
            &fn_bytes,
            "ServerPing".to_string(),
            PackageIndex::from_export_index(4),
            Some(none_idx),
        )
        .unwrap();
        assert_eq!(parsed_fn.net_index, 310);
        assert_eq!(parsed_fn.script_storage_size, 4);
        assert_eq!(parsed_fn.rep_offset, Some(0x0018));
        assert!(parsed_fn.is_base_net_rpc());

        // UEnum
        let table = NameTable::new(vec![
            NameEntry::new("None", 0),
            NameEntry::new("ROLE_None", 0),
            NameEntry::new("ROLE_SimulatedProxy", 0),
            NameEntry::new("ROLE_Authority", 0),
        ]);
        let mut enum_bytes = Vec::new();
        enum_bytes.write_i32::<LittleEndian>(42).unwrap();
        FName::new(0, 0).write(&mut enum_bytes).unwrap();
        enum_bytes.write_i32::<LittleEndian>(0).unwrap();
        enum_bytes.write_i32::<LittleEndian>(3).unwrap();
        FName::new(1, 0).write(&mut enum_bytes).unwrap();
        FName::new(2, 0).write(&mut enum_bytes).unwrap();
        FName::new(3, 0).write(&mut enum_bytes).unwrap();

        let parsed_enum = UEnumExport::parse(
            &enum_bytes,
            "ENetRole".to_string(),
            PackageIndex::from_export_index(5),
            &table,
            Some(0),
        )
        .unwrap();
        assert_eq!(
            parsed_enum.resolved_names,
            vec!["ROLE_None", "ROLE_SimulatedProxy", "ROLE_Authority"]
        );
    }

    #[test]
    fn test_synthetic_class_netcache_and_package_map_manifest() {
        // Build two synthetic summaries for PackageMapManifest
        let summary_core = PackageSummary {
            tag: UPK_MAGIC,
            file_version: 893,
            licensee_version: 0,
            total_header_size: 0,
            folder_name: "None".to_string(),
            package_flags: PKG_COOKED,
            name_count: 0,
            name_offset: 0,
            export_count: 0,
            export_offset: 0,
            import_count: 0,
            import_offset: 0,
            depends_offset: 0,
            import_export_guids_offset: 0,
            import_guids_count: 0,
            export_guids_count: 0,
            thumbnail_table_offset: 0,
            guid: [1; 16],
            generations: vec![GenerationInfo {
                export_count: 10,
                name_count: 10,
                net_object_count: 100,
            }],
            engine_version: 10897,
            cooker_version: 393358,
            compression_flags: 0,
            compressed_chunks: vec![],
        };
        let mut summary_game = summary_core.clone();
        summary_game.guid = [2; 16];
        summary_game.generations[0].net_object_count = 250;

        let manifest = PackageMapManifest::from_summaries([
            ("Core", &summary_core),
            ("TgGame", &summary_game),
        ])
        .unwrap();
        assert_eq!(manifest.total_objects, 350);
        assert_eq!(manifest.resolve_global_index("Core", 15), Some(15));
        assert_eq!(manifest.resolve_global_index("TgGame", 42), Some(142));
        assert_eq!(manifest.resolve_global_index("Core", 100), None);
        let (entry, local) = manifest.resolve_net_index(142).unwrap();
        assert_eq!(entry.package_name, "TgGame");
        assert_eq!(local, 42);

        // Build synthetic XOR-compressed UPK with BaseActor -> ChildPawn net fields sorted by NetIndex
        let names = NameTable::new(vec![
            NameEntry::new("None", 0),            // 0
            NameEntry::new("Core", 0),            // 1
            NameEntry::new("IntProperty", 0),     // 2
            NameEntry::new("BoolProperty", 0),    // 3
            NameEntry::new("Function", 0),        // 4
            NameEntry::new("BaseActor", 0),       // 5
            NameEntry::new("ChildPawn", 0),       // 6
            NameEntry::new("Health", 0),          // 7
            NameEntry::new("bHidden", 0),         // 8
            NameEntry::new("ServerJump", 0),      // 9
            NameEntry::new("OverrideNoBase", 0),  // 10
            NameEntry::new("ParamBool", 0),       // 11
        ]);
        let imports = ImportTable::new(vec![
            ObjectImport {
                class_package: FName::new(1, 0),
                class_name: FName::new(1, 0),
                outer_index: PackageIndex::NULL,
                object_name: FName::new(2, 0), // -1: IntProperty
            },
            ObjectImport {
                class_package: FName::new(1, 0),
                class_name: FName::new(1, 0),
                outer_index: PackageIndex::NULL,
                object_name: FName::new(3, 0), // -2: BoolProperty
            },
            ObjectImport {
                class_package: FName::new(1, 0),
                class_name: FName::new(1, 0),
                outer_index: PackageIndex::NULL,
                object_name: FName::new(4, 0), // -3: Function
            },
        ]);

        // Export 1: BaseActor (class_idx = 0)
        // Export 2: BaseActor.Health (IntProperty, NetIndex=50, CPF_Net)
        // Export 3: BaseActor.bHidden (BoolProperty, NetIndex=10, CPF_Net) -> sorts BEFORE Health!
        // Export 4: ChildPawn (class_idx = 0, super_idx = Export 1)
        // Export 5: ChildPawn.ServerJump (Function, NetIndex=5, FUNC_Net, SuperField=0, Children=Export 6)
        // Export 6: ChildPawn.ServerJump.ParamBool (BoolProperty, NetIndex=6, CPF_Parm)
        // Export 7: ChildPawn.OverrideNoBase (Function, NetIndex=4, FUNC_Net, SuperField=Export 5 -> excluded!)
        let mut class_base_bytes = Vec::new();
        for v in [100i32, 0, 0, 0, 2] {
            class_base_bytes.write_i32::<LittleEndian>(v).unwrap();
        }
        let mut class_child_bytes = Vec::new();
        for v in [200i32, 0, 1, 0, 5] {
            class_child_bytes.write_i32::<LittleEndian>(v).unwrap();
        }
        let health_bytes = write_uproperty_bytes(TestPropSpec {
            net_index: 50,
            none_idx: 0,
            next: 0,
            array_dim: 1,
            elem_flags: 4,
            property_flags: CPF_NET,
            category: FName::new(0, 0),
            rep_offset: Some(0x10),
            tail_indices: &[],
        });
        let hidden_bytes = write_uproperty_bytes(TestPropSpec {
            net_index: 10,
            none_idx: 0,
            next: 0,
            array_dim: 1,
            elem_flags: 1,
            property_flags: CPF_NET,
            category: FName::new(0, 0),
            rep_offset: Some(0x14),
            tail_indices: &[],
        });
        let jump_bytes = write_ufunction_bytes(TestFuncSpec {
            net_index: 5,
            none_idx: 0,
            next: 0,
            super_field: 0,
            children: 6,
            bytecode: &[0x53],
            function_flags: FUNC_NET | FUNC_NET_SERVER,
            rep_offset: Some(0x20),
            friendly_name: FName::new(9, 0),
        });
        let param_bytes = write_uproperty_bytes(TestPropSpec {
            net_index: 6,
            none_idx: 0,
            next: 0,
            array_dim: 1,
            elem_flags: 1,
            property_flags: CPF_PARM,
            category: FName::new(0, 0),
            rep_offset: None,
            tail_indices: &[],
        });
        let override_bytes = write_ufunction_bytes(TestFuncSpec {
            net_index: 4,
            none_idx: 0,
            next: 0,
            super_field: 5, // SuperField != 0 -> must NOT enter NetFields!
            children: 0,
            bytecode: &[0x53],
            function_flags: FUNC_NET,
            rep_offset: Some(0x24),
            friendly_name: FName::new(10, 0),
        });

        let payloads = [
            class_base_bytes,
            health_bytes,
            hidden_bytes,
            class_child_bytes,
            jump_bytes,
            param_bytes,
            override_bytes,
        ];

        let mut raw_exports = vec![
            (PackageIndex::NULL, PackageIndex::NULL, PackageIndex::NULL, FName::new(5, 0)),
            (PackageIndex::from_import_index(0), PackageIndex::NULL, PackageIndex::from_export_index(0), FName::new(7, 0)),
            (PackageIndex::from_import_index(1), PackageIndex::NULL, PackageIndex::from_export_index(0), FName::new(8, 0)),
            (PackageIndex::NULL, PackageIndex::from_export_index(0), PackageIndex::NULL, FName::new(6, 0)),
            (PackageIndex::from_import_index(2), PackageIndex::NULL, PackageIndex::from_export_index(3), FName::new(9, 0)),
            (PackageIndex::from_import_index(1), PackageIndex::NULL, PackageIndex::from_export_index(4), FName::new(11, 0)),
            (PackageIndex::from_import_index(2), PackageIndex::NULL, PackageIndex::from_export_index(3), FName::new(10, 0)),
        ];

        let mut chunk_payload = Vec::new();
        let name_off = 0usize;
        names.write(&mut chunk_payload).unwrap();
        let import_off = chunk_payload.len();
        imports.write(&mut chunk_payload).unwrap();
        let export_off = chunk_payload.len();
        let placeholder_exports = ExportTable::new(
            raw_exports
                .iter()
                .map(|(cls, sup, out, nm)| ObjectExport {
                    class_index: *cls,
                    super_index: *sup,
                    outer_index: *out,
                    object_name: *nm,
                    archetype: PackageIndex::NULL,
                    object_flags: 1,
                    serial_size: 0,
                    serial_offset: 0,
                    export_flags: 0,
                    generation_net_object_count: vec![],
                    guid: [0; 16],
                    package_flags: 0,
                })
                .collect(),
        );
        placeholder_exports.write(&mut chunk_payload).unwrap();
        let mut serial_offsets = Vec::new();
        for p in &payloads {
            serial_offsets.push(chunk_payload.len());
            chunk_payload.extend_from_slice(p);
        }

        let mut summary = PackageSummary {
            tag: UPK_MAGIC,
            file_version: 893,
            licensee_version: 0,
            total_header_size: 0,
            folder_name: "None".to_string(),
            package_flags: PKG_COOKED | PKG_COMPRESSED,
            name_count: names.len() as u32,
            name_offset: 0,
            export_count: raw_exports.len() as u32,
            export_offset: 0,
            import_count: imports.len() as u32,
            import_offset: 0,
            depends_offset: 0,
            import_export_guids_offset: 0,
            import_guids_count: 0,
            export_guids_count: 0,
            thumbnail_table_offset: 0,
            guid: [2; 16],
            generations: vec![GenerationInfo {
                export_count: raw_exports.len() as i32,
                name_count: names.len() as i32,
                net_object_count: 250,
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

        let mut hdr_probe = Vec::new();
        summary.write(&mut hdr_probe).unwrap();
        let hdr_len = hdr_probe.len() as u32;

        // Patch final serial_offsets relative to virtual uncompressed stream
        let final_exports = ExportTable::new(
            raw_exports
                .drain(..)
                .enumerate()
                .map(|(i, (cls, sup, out, nm))| ObjectExport {
                    class_index: cls,
                    super_index: sup,
                    outer_index: out,
                    object_name: nm,
                    archetype: PackageIndex::NULL,
                    object_flags: 1,
                    serial_size: payloads[i].len() as i32,
                    serial_offset: hdr_len as i32 + serial_offsets[i] as i32,
                    export_flags: 0,
                    generation_net_object_count: vec![],
                    guid: [0; 16],
                    package_flags: 0,
                })
                .collect(),
        );
        let mut rebuilt_exports = Vec::new();
        final_exports.write(&mut rebuilt_exports).unwrap();
        chunk_payload[export_off..export_off + rebuilt_exports.len()]
            .copy_from_slice(&rebuilt_exports);

        let mut chunk_bytes = Vec::new();
        let chunk_meta = write_compressed_chunk(
            &mut chunk_bytes,
            hdr_len,
            hdr_len,
            &chunk_payload,
            4096,
            COMPRESS_LZO_XOR,
        )
        .unwrap();

        summary.total_header_size = hdr_len;
        summary.name_offset = hdr_len + name_off as u32;
        summary.import_offset = hdr_len + import_off as u32;
        summary.export_offset = hdr_len + export_off as u32;
        summary.compressed_chunks = vec![chunk_meta];

        let mut upk_bytes = Vec::new();
        summary.write(&mut upk_bytes).unwrap();
        upk_bytes.extend_from_slice(&chunk_bytes);

        let mut pkg = UpkPackage::open(Cursor::new(upk_bytes)).unwrap();
        let mut reg = NetCacheRegistry::with_manifest(manifest);
        let stats = reg.load_package("TgGame", &mut pkg).unwrap();
        assert_eq!(stats.properties_parsed, 3);
        assert_eq!(stats.properties_failed, 0);
        assert_eq!(stats.functions_parsed, 2);
        assert_eq!(stats.functions_failed, 0);
        assert_eq!(stats.classes_parsed, 2);

        let base_cache = reg.build_class_net_cache("BaseActor").unwrap();
        assert_eq!(base_cache.fields_base, 0);
        assert_eq!(base_cache.max_index, 2);
        assert_eq!(base_cache.own_fields[0].field_name, "bHidden");
        assert_eq!(base_cache.own_fields[0].rep_index, 0);
        assert_eq!(base_cache.own_fields[0].global_object_index, Some(110));
        assert_eq!(base_cache.own_fields[1].field_name, "Health");
        assert_eq!(base_cache.own_fields[1].rep_index, 1);
        assert_eq!(base_cache.own_fields[1].global_object_index, Some(150));

        let child_cache = reg.build_class_net_cache("ChildPawn").unwrap();
        assert_eq!(child_cache.fields_base, 2);
        assert_eq!(child_cache.max_index, 3);
        assert_eq!(child_cache.own_fields.len(), 1);
        assert_eq!(child_cache.own_fields[0].field_name, "ServerJump");
        assert_eq!(child_cache.own_fields[0].rep_index, 2);
        assert_eq!(child_cache.own_fields[0].global_object_index, Some(105));
        if let NetFieldKind::Function { params, .. } = &child_cache.own_fields[0].kind {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "ParamBool");
        } else {
            panic!("Expected Function kind for ServerJump");
        }

        // Lookup across inheritance chain
        let inherited = reg.lookup_rep_field("ChildPawn", 0).unwrap().unwrap();
        assert_eq!(inherited.field_name, "bHidden");
        assert_eq!(inherited.owner_class, "BaseActor");
    }
}
