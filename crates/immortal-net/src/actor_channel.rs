// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Unreal Engine 3 `UActorChannel`, `UPackageMapLevel`, and `FClassNetCache` Codec
//! Cleanroom schema-driven codec for UE3 v893 / Paladins actor channel replication
//! (`UActorChannel::ReceivedBunch` / `ReplicateActor`, `UPackageMapLevel`, and
//! `FClassNetCache`). Decoupled from `immortal-extract` via [`ClassNetCacheView`]
//! and [`NetFieldSchema`].

use std::collections::BTreeMap;

use crate::bitstream::{BitReader, BitWriter};
use crate::bunch::{Bunch, BunchFlags, BunchHeader, Ue3ChannelType, MAX_CHANNELS};
use crate::error::NetError;

/// Maximum static object index serialized by `UPackageMapLevel::SerializeObject` (`0x80000000`).
pub const MAX_STATIC_OBJECT_INDEX: u32 = 0x8000_0000;

/// Maximum dynamic actor channel index serialized by `UPackageMapLevel::SerializeObject` (`0x800`).
pub const MAX_DYNAMIC_CHANNEL_INDEX: u32 = MAX_CHANNELS;

/// Maximum hardcoded `FName` index serialized by `UPackageMapLevel::SerializeName` (`0x4E3 = 1251`).
pub const MAX_NETNAME_INDEX: u32 = 0x4E3;

/// Maximum recursive `UScriptStruct` nesting depth (`PSL-INV-011`).
pub const MAX_STRUCT_DEPTH: usize = 16;

/// Object reference resolved via `UPackageMapLevel::SerializeObject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectRef {
    /// `bDynamicActor = 0`: Static object, archetype, CDO, or level actor (`SerializeInt(0x80000000)`).
    Static(u32),
    /// `bDynamicActor = 1`: Existing actor channel index (`SerializeInt(0x800)`).
    DynamicChannel(u32),
}

/// Net-serialized `FName` resolved via `UPackageMapLevel::SerializeName`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetName {
    /// `bHardcoded = 1`: Engine hardcoded name table index `< 0x4E3` (`SerializeInt(0x4E3)`).
    Hardcoded(u32),
    /// `bHardcoded = 0`: Dynamic `FString` + `i32` instance number.
    Dynamic { name: String, number: i32 },
}

/// Wire helpers for UE3 `UPackageMapLevel::SerializeObject` and `SerializeName`.
pub struct PackageMapLevel;

impl PackageMapLevel {
    /// Writes an [`ObjectRef`] using `UPackageMapLevel::SerializeObject` encoding.
    pub fn write_object_ref(w: &mut BitWriter, obj: ObjectRef) -> Result<(), NetError> {
        write_object_ref(w, obj)
    }

    /// Reads an [`ObjectRef`] using `UPackageMapLevel::SerializeObject` encoding.
    pub fn read_object_ref(r: &mut BitReader<'_>) -> Result<ObjectRef, NetError> {
        read_object_ref(r)
    }

    /// Writes a [`NetName`] using `UPackageMapLevel::SerializeName` encoding.
    pub fn write_net_name(w: &mut BitWriter, name: &NetName) -> Result<(), NetError> {
        write_net_name(w, name)
    }

    /// Reads a [`NetName`] using `UPackageMapLevel::SerializeName` encoding.
    pub fn read_net_name(r: &mut BitReader<'_>) -> Result<NetName, NetError> {
        read_net_name(r)
    }
}

/// Writes an [`ObjectRef`] (`1b bDyn`: `0` -> `SerializeInt(0x80000000)`, `1` -> `SerializeInt(0x800)`).
pub fn write_object_ref(w: &mut BitWriter, obj: ObjectRef) -> Result<(), NetError> {
    match obj {
        ObjectRef::Static(idx) => {
            w.write_bit(false);
            w.write_int(idx, MAX_STATIC_OBJECT_INDEX)?;
        }
        ObjectRef::DynamicChannel(ch_idx) => {
            w.write_bit(true);
            w.write_int(ch_idx, MAX_DYNAMIC_CHANNEL_INDEX)?;
        }
    }
    Ok(())
}

/// Reads an [`ObjectRef`] (`1b bDyn`: `0` -> `SerializeInt(0x80000000)`, `1` -> `SerializeInt(0x800)`).
pub fn read_object_ref(r: &mut BitReader<'_>) -> Result<ObjectRef, NetError> {
    if r.read_bit()? {
        Ok(ObjectRef::DynamicChannel(
            r.read_int(MAX_DYNAMIC_CHANNEL_INDEX)?,
        ))
    } else {
        Ok(ObjectRef::Static(r.read_int(MAX_STATIC_OBJECT_INDEX)?))
    }
}

/// Writes a [`NetName`] (`1b bHardcoded`: `1` -> `SerializeInt(0x4E3)`, `0` -> `FString + i32`).
pub fn write_net_name(w: &mut BitWriter, name: &NetName) -> Result<(), NetError> {
    match name {
        NetName::Hardcoded(idx) => {
            w.write_bit(true);
            w.write_int(*idx, MAX_NETNAME_INDEX)?;
        }
        NetName::Dynamic { name, number } => {
            w.write_bit(false);
            w.write_fstring(name);
            w.write_i32(*number);
        }
    }
    Ok(())
}

/// Reads a [`NetName`] (`1b bHardcoded`: `1` -> `SerializeInt(0x4E3)`, `0` -> `FString + i32`).
pub fn read_net_name(r: &mut BitReader<'_>) -> Result<NetName, NetError> {
    if r.read_bit()? {
        Ok(NetName::Hardcoded(r.read_int(MAX_NETNAME_INDEX)?))
    } else {
        let name = r.read_fstring()?;
        let number = r.read_i32()?;
        Ok(NetName::Dynamic { name, number })
    }
}

/// Caller-supplied layout flags resolved from the target archetype / class on channel open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActorSpawnLayout {
    /// True when the resolved object has `RF_ClassDefaultObject | RF_ArchetypeObject` (`0x600`).
    pub has_location: bool,
    /// True when `has_location` and `Actor->bNetInitialRotation` is set.
    pub has_rotation: bool,
    /// True when `Actor->GetAPlayerController() != NULL`.
    pub is_player_controller: bool,
}

/// Leading actor-open header decoded when `bOpen = 1` on a `CHTYPE_Actor` channel.
#[derive(Debug, Clone, PartialEq)]
pub struct ActorOpenHeader {
    pub object_ref: ObjectRef,
    pub location: Option<[f32; 3]>,
    pub rotation: Option<[i32; 3]>,
    pub net_player_index: Option<u8>,
}

impl ActorOpenHeader {
    /// Decodes an [`ActorOpenHeader`] according to `layout`.
    pub fn decode(r: &mut BitReader<'_>, layout: ActorSpawnLayout) -> Result<Self, NetError> {
        let object_ref = read_object_ref(r)?;
        let location = if layout.has_location {
            Some(r.read_compressed_vector()?)
        } else {
            None
        };
        let rotation = if layout.has_location && layout.has_rotation {
            Some(r.read_compressed_rotator()?)
        } else {
            None
        };
        let net_player_index = if layout.is_player_controller {
            Some(r.read_u8()?)
        } else {
            None
        };
        Ok(Self {
            object_ref,
            location,
            rotation,
            net_player_index,
        })
    }

    /// Encodes an [`ActorOpenHeader`] to `w`.
    pub fn encode(&self, w: &mut BitWriter) -> Result<(), NetError> {
        if self.rotation.is_some() && self.location.is_none() {
            return Err(NetError::BunchError(
                "ActorOpenHeader cannot carry rotation without location".to_string(),
            ));
        }
        write_object_ref(w, self.object_ref)?;
        if let Some(loc) = self.location {
            w.write_compressed_vector(loc)?;
        }
        if let Some(rot) = self.rotation {
            w.write_compressed_rotator(rot);
        }
        if let Some(idx) = self.net_player_index {
            w.write_u8(idx);
        }
        Ok(())
    }
}

/// Struct serialization strategy for `StructProperty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetStructKind {
    /// UE3 `FVector` (`SerializeCompressedVector`).
    Vector,
    /// UE3 `FRotator` (`SerializeCompressedRotator`).
    Rotator,
    /// UE3 `FUniqueNetId` (8 raw bytes).
    UniqueNetId,
    /// Generic `UScriptStruct` whose fields serialize sequentially in `Children -> Next` order.
    ScriptStruct {
        name: String,
        fields: Vec<NetStructField>,
    },
}

/// Field descriptor inside a [`NetStructKind::ScriptStruct`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetStructField {
    pub name: String,
    pub prop_type: Box<NetPropertyType>,
    pub array_dim: u16,
}

/// Wire property type supported by `UProperty::NetSerializeItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetPropertyType {
    /// `BoolProperty`: 1 bit.
    Bool,
    /// `ByteProperty`: `SerializeInt(enum_count)` when `Some(count)`, or 8-bit `u8` when `None`.
    Byte { enum_count: Option<u32> },
    /// `IntProperty`: 32-bit little-endian `i32`.
    Int,
    /// `FloatProperty`: 32-bit little-endian `f32`.
    Float,
    /// `ObjectProperty`, `ClassProperty`, `ComponentProperty`, `InterfaceProperty`: `ObjectRef`.
    Object,
    /// `NameProperty`: `NetName`.
    Name,
    /// `StrProperty`: `FString`.
    Str,
    /// `StructProperty`: built-in or recursive `UScriptStruct`.
    Struct(NetStructKind),
}

/// Non-return `CPF_Parm` parameter descriptor for a replicated RPC (`UFunction`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRpcParam {
    pub name: String,
    pub prop_type: NetPropertyType,
    pub array_dim: u16,
}

/// Replication field kind in `FClassNetCache`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetFieldKind {
    Property {
        prop_type: NetPropertyType,
        array_dim: u16,
    },
    Rpc {
        params: Vec<NetRpcParam>,
    },
}

/// Single entry in a [`ClassNetCacheView`] (`FFieldNetCache`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFieldSchema {
    pub rep_index: u32,
    pub name: String,
    pub owner_class: String,
    pub kind: NetFieldKind,
}

/// Schema-driven `FClassNetCache` view for a single UE3 class (decoupled from `immortal-extract`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassNetCacheView {
    pub class_name: String,
    pub max_index: u32,
    fields: BTreeMap<u32, NetFieldSchema>,
}

impl ClassNetCacheView {
    /// Creates an empty [`ClassNetCacheView`] with `max_index = super_max + own_count`.
    pub fn new(class_name: impl Into<String>, max_index: u32) -> Self {
        Self {
            class_name: class_name.into(),
            max_index,
            fields: BTreeMap::new(),
        }
    }

    /// Inserts a [`NetFieldSchema`] entry, rejecting `rep_index >= max_index`.
    pub fn insert(&mut self, field: NetFieldSchema) -> Result<(), NetError> {
        if field.rep_index >= self.max_index {
            return Err(NetError::BunchError(format!(
                "RepIndex {} out of bounds for class {} (max_index={})",
                field.rep_index, self.class_name, self.max_index
            )));
        }
        self.fields.insert(field.rep_index, field);
        Ok(())
    }

    /// Builder-style insertion of a single [`NetFieldSchema`].
    pub fn with_field(mut self, field: NetFieldSchema) -> Result<Self, NetError> {
        self.insert(field)?;
        Ok(self)
    }

    /// Builder-style insertion of multiple [`NetFieldSchema`] entries.
    pub fn with_fields<I: IntoIterator<Item = NetFieldSchema>>(
        mut self,
        fields: I,
    ) -> Result<Self, NetError> {
        for field in fields {
            self.insert(field)?;
        }
        Ok(self)
    }

    /// Looks up a field schema by `rep_index`.
    #[inline]
    pub fn get(&self, rep_index: u32) -> Option<&NetFieldSchema> {
        self.fields.get(&rep_index)
    }

    /// Iterates over registered fields in ascending `rep_index` order.
    #[inline]
    pub fn fields(&self) -> impl Iterator<Item = &NetFieldSchema> {
        self.fields.values()
    }

    /// Number of registered fields in this view.
    #[inline]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns `true` if no fields are registered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Decoded field entry inside a [`NetValue::Struct`].
#[derive(Debug, Clone, PartialEq)]
pub struct NetStructFieldValue {
    pub name: String,
    pub values: Vec<NetValue>,
}

/// Runtime value decoded/encoded by [`ActorBunchCodec`].
#[derive(Debug, Clone, PartialEq)]
pub enum NetValue {
    Bool(bool),
    Byte(u8),
    Enum(u32),
    Int(i32),
    Float(f32),
    Object(ObjectRef),
    Name(NetName),
    Str(String),
    Vector([f32; 3]),
    Rotator([i32; 3]),
    UniqueNetId([u8; 8]),
    Struct(Vec<NetStructFieldValue>),
}

/// Decoded/encoded parameter passed to a replicated RPC.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcParamValue {
    pub name: String,
    /// `None` when `bHasParam = 0` (only valid for non-`Bool` parameters).
    /// `Some(values)` holds `array_dim` elements (`1` for scalar parameters).
    pub values: Option<Vec<NetValue>>,
}

/// Single replicated property or RPC item inside an actor bunch.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicatedItem {
    Property {
        rep_index: u32,
        name: String,
        array_index: u8,
        value: NetValue,
    },
    Rpc {
        rep_index: u32,
        name: String,
        params: Vec<RpcParamValue>,
    },
}

/// Complete decoded `UActorChannel` bunch (optional open header + replicated items).
#[derive(Debug, Clone, PartialEq)]
pub struct ActorBunch {
    pub open_header: Option<ActorOpenHeader>,
    pub items: Vec<ReplicatedItem>,
}

/// Schema-driven encoder/decoder for UE3 `UActorChannel` bunches.
pub struct ActorBunchCodec;

impl ActorBunchCodec {
    /// Decodes a `bOpen = 1` actor bunch from `reader` using `cache` and `layout`.
    pub fn decode_open_bunch(
        reader: &mut BitReader<'_>,
        cache: &ClassNetCacheView,
        layout: ActorSpawnLayout,
    ) -> Result<ActorBunch, NetError> {
        let open_header = ActorOpenHeader::decode(reader, layout)?;
        let items = Self::decode_replication_loop(reader, cache)?;
        Ok(ActorBunch {
            open_header: Some(open_header),
            items,
        })
    }

    /// Decodes a `bOpen = 0` actor update bunch from `reader` using `cache`.
    pub fn decode_update_bunch(
        reader: &mut BitReader<'_>,
        cache: &ClassNetCacheView,
    ) -> Result<ActorBunch, NetError> {
        let items = Self::decode_replication_loop(reader, cache)?;
        Ok(ActorBunch {
            open_header: None,
            items,
        })
    }

    /// Decodes a [`Bunch`] (`bOpen = 1` uses `layout`, `bOpen = 0` ignores `layout`),
    /// asserting that all `bunch.num_bits` bits are consumed with 0 leftover bits.
    pub fn decode_bunch(
        bunch: &Bunch,
        cache: &ClassNetCacheView,
        layout: Option<ActorSpawnLayout>,
    ) -> Result<ActorBunch, NetError> {
        let mut reader = BitReader::new(&bunch.data, bunch.num_bits)?;
        let decoded = if bunch.header.flags.b_open {
            Self::decode_open_bunch(&mut reader, cache, layout.unwrap_or_default())?
        } else {
            Self::decode_update_bunch(&mut reader, cache)?
        };
        if !reader.at_end() {
            return Err(NetError::BunchError(format!(
                "ActorBunchCodec left {} unread bits on class {}",
                reader.bits_left(),
                cache.class_name
            )));
        }
        Ok(decoded)
    }

    /// Encodes an [`ActorBunch`] directly into `writer` using `cache`.
    pub fn encode_bunch(
        writer: &mut BitWriter,
        cache: &ClassNetCacheView,
        actor_bunch: &ActorBunch,
    ) -> Result<(), NetError> {
        if let Some(ref open) = actor_bunch.open_header {
            open.encode(writer)?;
        }
        for item in &actor_bunch.items {
            match item {
                ReplicatedItem::Property {
                    rep_index,
                    array_index,
                    value,
                    ..
                } => {
                    let schema = cache.get(*rep_index).ok_or_else(|| {
                        NetError::BunchError(format!(
                            "Unmapped RepIndex {} on class {} (max_index={})",
                            rep_index, cache.class_name, cache.max_index
                        ))
                    })?;
                    let NetFieldKind::Property {
                        prop_type,
                        array_dim,
                    } = &schema.kind
                    else {
                        return Err(NetError::BunchError(format!(
                            "RepIndex {} ({}) on {} is an RPC, not a Property",
                            rep_index, schema.name, cache.class_name
                        )));
                    };
                    if *array_dim == 0 {
                        return Err(NetError::BunchError(format!(
                            "Property {} has invalid array_dim == 0",
                            schema.name
                        )));
                    }
                    writer.write_int(*rep_index, cache.max_index)?;
                    if *array_dim > 1 {
                        if u16::from(*array_index) >= *array_dim {
                            return Err(NetError::BunchError(format!(
                                "Property {} array_index {} >= array_dim {}",
                                schema.name, array_index, array_dim
                            )));
                        }
                        writer.write_u8(*array_index);
                    } else if *array_index != 0 {
                        return Err(NetError::BunchError(format!(
                            "Scalar property {} requires array_index == 0, got {}",
                            schema.name, array_index
                        )));
                    }
                    Self::encode_property_value(writer, prop_type, value, 0)?;
                }
                ReplicatedItem::Rpc {
                    rep_index, params, ..
                } => {
                    let schema = cache.get(*rep_index).ok_or_else(|| {
                        NetError::BunchError(format!(
                            "Unmapped RepIndex {} on class {} (max_index={})",
                            rep_index, cache.class_name, cache.max_index
                        ))
                    })?;
                    let NetFieldKind::Rpc {
                        params: param_schemas,
                    } = &schema.kind
                    else {
                        return Err(NetError::BunchError(format!(
                            "RepIndex {} ({}) on {} is a Property, not an RPC",
                            rep_index, schema.name, cache.class_name
                        )));
                    };
                    if params.len() != param_schemas.len() {
                        return Err(NetError::BunchError(format!(
                            "RPC {} expected {} params, got {}",
                            schema.name,
                            param_schemas.len(),
                            params.len()
                        )));
                    }
                    writer.write_int(*rep_index, cache.max_index)?;
                    for (pschema, pval) in param_schemas.iter().zip(params.iter()) {
                        let is_bool = matches!(pschema.prop_type, NetPropertyType::Bool);
                        match &pval.values {
                            Some(vals) => {
                                if vals.len() != usize::from(pschema.array_dim) {
                                    return Err(NetError::BunchError(format!(
                                        "RPC {} param {} expected {} elements, got {}",
                                        schema.name,
                                        pschema.name,
                                        pschema.array_dim,
                                        vals.len()
                                    )));
                                }
                                if !is_bool {
                                    writer.write_bit(true);
                                }
                                for v in vals {
                                    Self::encode_property_value(writer, &pschema.prop_type, v, 0)?;
                                }
                            }
                            None => {
                                if is_bool {
                                    return Err(NetError::BunchError(format!(
                                        "RPC {} bool param {} cannot be omitted (no presence bit)",
                                        schema.name, pschema.name
                                    )));
                                }
                                writer.write_bit(false);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Encodes an [`ActorBunch`] into a [`Bunch`] with exact `num_bits`.
    pub fn encode_to_bunch(
        ch_index: u32,
        ch_sequence: u32,
        b_reliable: bool,
        cache: &ClassNetCacheView,
        actor_bunch: &ActorBunch,
    ) -> Result<Bunch, NetError> {
        let mut writer = BitWriter::new();
        Self::encode_bunch(&mut writer, cache, actor_bunch)?;
        let num_bits = writer.num_bits();
        let data = writer.into_bytes();
        Ok(Bunch::with_bits(
            BunchHeader {
                ch_index,
                ch_type: Ue3ChannelType::Actor,
                flags: BunchFlags {
                    b_open: actor_bunch.open_header.is_some(),
                    b_close: false,
                    b_reliable,
                    b_partial: false,
                },
                ch_sequence,
            },
            num_bits,
            data,
        ))
    }

    /// Decodes a single property value according to `prop_type`.
    pub fn decode_property_value(
        reader: &mut BitReader<'_>,
        prop_type: &NetPropertyType,
    ) -> Result<NetValue, NetError> {
        Self::decode_property_value_depth(reader, prop_type, 0)
    }

    /// Encodes a single property value according to `prop_type`.
    pub fn encode_property_value(
        writer: &mut BitWriter,
        prop_type: &NetPropertyType,
        value: &NetValue,
        depth: usize,
    ) -> Result<(), NetError> {
        if depth > MAX_STRUCT_DEPTH {
            return Err(NetError::BunchError(format!(
                "Struct nesting depth exceeded limit {}",
                MAX_STRUCT_DEPTH
            )));
        }
        match (prop_type, value) {
            (NetPropertyType::Bool, NetValue::Bool(b)) => {
                writer.write_bit(*b);
            }
            (NetPropertyType::Byte { enum_count: None }, NetValue::Byte(b)) => {
                writer.write_u8(*b);
            }
            (NetPropertyType::Byte { enum_count: Some(count) }, NetValue::Enum(v)) => {
                writer.write_int(*v, *count)?;
            }
            (NetPropertyType::Int, NetValue::Int(i)) => {
                writer.write_i32(*i);
            }
            (NetPropertyType::Float, NetValue::Float(f)) => {
                writer.write_f32(*f);
            }
            (NetPropertyType::Object, NetValue::Object(obj)) => {
                write_object_ref(writer, *obj)?;
            }
            (NetPropertyType::Name, NetValue::Name(name)) => {
                write_net_name(writer, name)?;
            }
            (NetPropertyType::Str, NetValue::Str(s)) => {
                writer.write_fstring(s);
            }
            (NetPropertyType::Struct(NetStructKind::Vector), NetValue::Vector(v)) => {
                writer.write_compressed_vector(*v)?;
            }
            (NetPropertyType::Struct(NetStructKind::Rotator), NetValue::Rotator(rot)) => {
                writer.write_compressed_rotator(*rot);
            }
            (NetPropertyType::Struct(NetStructKind::UniqueNetId), NetValue::UniqueNetId(id)) => {
                writer.write_bytes(id);
            }
            (
                NetPropertyType::Struct(NetStructKind::ScriptStruct { name, fields }),
                NetValue::Struct(val_fields),
            ) => {
                if fields.len() != val_fields.len() {
                    return Err(NetError::BunchError(format!(
                        "Struct {} expected {} fields, got {}",
                        name,
                        fields.len(),
                        val_fields.len()
                    )));
                }
                for (fschema, fval) in fields.iter().zip(val_fields.iter()) {
                    if fval.values.len() != usize::from(fschema.array_dim) {
                        return Err(NetError::BunchError(format!(
                            "Struct {}.{} expected {} elements, got {}",
                            name,
                            fschema.name,
                            fschema.array_dim,
                            fval.values.len()
                        )));
                    }
                    for elem in &fval.values {
                        Self::encode_property_value(
                            writer,
                            &fschema.prop_type,
                            elem,
                            depth + 1,
                        )?;
                    }
                }
            }
            (expected, got) => {
                return Err(NetError::BunchError(format!(
                    "Property type mismatch: expected {:?}, got {:?}",
                    expected, got
                )));
            }
        }
        Ok(())
    }

    fn decode_replication_loop(
        reader: &mut BitReader<'_>,
        cache: &ClassNetCacheView,
    ) -> Result<Vec<ReplicatedItem>, NetError> {
        let mut items = Vec::new();
        while !reader.at_end() {
            let start_pos = reader.position();
            let rep_index = reader.read_int(cache.max_index)?;
            let schema = cache.get(rep_index).ok_or_else(|| {
                NetError::BunchError(format!(
                    "Unmapped RepIndex {} on class {} (max_index={})",
                    rep_index, cache.class_name, cache.max_index
                ))
            })?;

            match &schema.kind {
                NetFieldKind::Property {
                    prop_type,
                    array_dim,
                } => {
                    if *array_dim == 0 {
                        return Err(NetError::BunchError(format!(
                            "Property {} has invalid array_dim == 0",
                            schema.name
                        )));
                    }
                    let array_index = if *array_dim > 1 {
                        reader.read_u8()?
                    } else {
                        0
                    };
                    let value = Self::decode_property_value_depth(reader, prop_type, 0)?;
                    items.push(ReplicatedItem::Property {
                        rep_index,
                        name: schema.name.clone(),
                        array_index,
                        value,
                    });
                }
                NetFieldKind::Rpc { params } => {
                    let mut decoded_params = Vec::with_capacity(params.len());
                    for param in params {
                        let is_bool = matches!(param.prop_type, NetPropertyType::Bool);
                        let present = if is_bool { true } else { reader.read_bit()? };
                        let values = if present {
                            let mut arr = Vec::with_capacity(usize::from(param.array_dim));
                            for _ in 0..param.array_dim {
                                arr.push(Self::decode_property_value_depth(
                                    reader,
                                    &param.prop_type,
                                    0,
                                )?);
                            }
                            Some(arr)
                        } else {
                            None
                        };
                        decoded_params.push(RpcParamValue {
                            name: param.name.clone(),
                            values,
                        });
                    }
                    items.push(ReplicatedItem::Rpc {
                        rep_index,
                        name: schema.name.clone(),
                        params: decoded_params,
                    });
                }
            }

            if reader.position() == start_pos {
                return Err(NetError::BunchError(format!(
                    "Zero-bit progress decoding RepIndex {} ({}) on class {}",
                    rep_index, schema.name, cache.class_name
                )));
            }
        }
        Ok(items)
    }

    fn decode_property_value_depth(
        reader: &mut BitReader<'_>,
        prop_type: &NetPropertyType,
        depth: usize,
    ) -> Result<NetValue, NetError> {
        if depth > MAX_STRUCT_DEPTH {
            return Err(NetError::BunchError(format!(
                "Struct nesting depth exceeded limit {}",
                MAX_STRUCT_DEPTH
            )));
        }
        match prop_type {
            NetPropertyType::Bool => Ok(NetValue::Bool(reader.read_bit()?)),
            NetPropertyType::Byte { enum_count: None } => Ok(NetValue::Byte(reader.read_u8()?)),
            NetPropertyType::Byte {
                enum_count: Some(count),
            } => Ok(NetValue::Enum(reader.read_int(*count)?)),
            NetPropertyType::Int => Ok(NetValue::Int(reader.read_i32()?)),
            NetPropertyType::Float => Ok(NetValue::Float(reader.read_f32()?)),
            NetPropertyType::Object => Ok(NetValue::Object(read_object_ref(reader)?)),
            NetPropertyType::Name => Ok(NetValue::Name(read_net_name(reader)?)),
            NetPropertyType::Str => Ok(NetValue::Str(reader.read_fstring()?)),
            NetPropertyType::Struct(kind) => match kind {
                NetStructKind::Vector => Ok(NetValue::Vector(reader.read_compressed_vector()?)),
                NetStructKind::Rotator => Ok(NetValue::Rotator(reader.read_compressed_rotator()?)),
                NetStructKind::UniqueNetId => {
                    let bytes = reader.read_bytes(8)?;
                    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                        NetError::BunchError("UniqueNetId length mismatch".to_string())
                    })?;
                    Ok(NetValue::UniqueNetId(arr))
                }
                NetStructKind::ScriptStruct { fields, .. } => {
                    let mut out = Vec::with_capacity(fields.len());
                    for field in fields {
                        let mut values = Vec::with_capacity(usize::from(field.array_dim));
                        for _ in 0..field.array_dim {
                            values.push(Self::decode_property_value_depth(
                                reader,
                                &field.prop_type,
                                depth + 1,
                            )?);
                        }
                        out.push(NetStructFieldValue {
                            name: field.name.clone(),
                            values,
                        });
                    }
                    Ok(NetValue::Struct(out))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_map_level_object_ref_and_net_name_roundtrip() {
        let obj_cases = [
            (ObjectRef::Static(0), 32usize),
            (ObjectRef::Static(62_665), 32),
            (ObjectRef::Static(0x7FFF_FFFF), 32),
            (ObjectRef::DynamicChannel(3), 12),
            (ObjectRef::DynamicChannel(80), 12),
            (ObjectRef::DynamicChannel(0x7FF), 12),
        ];
        for (obj, expected_bits) in obj_cases {
            let mut w = BitWriter::new();
            PackageMapLevel::write_object_ref(&mut w, obj).unwrap();
            assert_eq!(w.num_bits(), expected_bits);
            let bits = w.num_bits();
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, bits).unwrap();
            assert_eq!(PackageMapLevel::read_object_ref(&mut r).unwrap(), obj);
            assert!(r.at_end());
        }

        let name_cases = [
            NetName::Hardcoded(0),
            NetName::Hardcoded(920),
            NetName::Hardcoded(MAX_NETNAME_INDEX - 1),
            NetName::Dynamic {
                name: "shootingrange_lighting".to_string(),
                number: 0,
            },
            NetName::Dynamic {
                name: "Actor".to_string(),
                number: 42,
            },
        ];
        for name in &name_cases {
            let mut w = BitWriter::new();
            PackageMapLevel::write_net_name(&mut w, name).unwrap();
            let bits = w.num_bits();
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, bits).unwrap();
            assert_eq!(&PackageMapLevel::read_net_name(&mut r).unwrap(), name);
            assert!(r.at_end());
        }

        let mut w = BitWriter::new();
        assert!(write_object_ref(&mut w, ObjectRef::Static(MAX_STATIC_OBJECT_INDEX)).is_err());
        assert!(
            write_object_ref(&mut w, ObjectRef::DynamicChannel(MAX_DYNAMIC_CHANNEL_INDEX)).is_err()
        );
        assert!(write_net_name(&mut w, &NetName::Hardcoded(MAX_NETNAME_INDEX)).is_err());
    }

    #[test]
    fn test_actor_open_header_roundtrip_variants() {
        let cases = [
            (
                ActorOpenHeader {
                    object_ref: ObjectRef::Static(62_665),
                    location: Some([-224.0, 0.0, 203.0]),
                    rotation: None,
                    net_player_index: Some(0),
                },
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: false,
                    is_player_controller: true,
                },
            ),
            (
                ActorOpenHeader {
                    object_ref: ObjectRef::Static(92_990),
                    location: Some([1890.0, 239.0, 259.0]),
                    rotation: Some([0, 64512, 0]),
                    net_player_index: None,
                },
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: true,
                    is_player_controller: false,
                },
            ),
            (
                ActorOpenHeader {
                    object_ref: ObjectRef::DynamicChannel(12),
                    location: None,
                    rotation: None,
                    net_player_index: None,
                },
                ActorSpawnLayout {
                    has_location: false,
                    has_rotation: false,
                    is_player_controller: false,
                },
            ),
        ];

        for (hdr, layout) in cases {
            let mut w = BitWriter::new();
            hdr.encode(&mut w).unwrap();
            let bits = w.num_bits();
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, bits).unwrap();
            let dec = ActorOpenHeader::decode(&mut r, layout).unwrap();
            assert_eq!(dec, hdr);
            assert!(r.at_end());
        }

        let invalid = ActorOpenHeader {
            object_ref: ObjectRef::Static(100),
            location: None,
            rotation: Some([0, 256, 0]),
            net_player_index: None,
        };
        let mut w = BitWriter::new();
        assert!(invalid.encode(&mut w).is_err());
    }

    #[test]
    fn test_actor_bunch_property_and_rpc_roundtrip() {
        let nested_struct = NetPropertyType::Struct(NetStructKind::ScriptStruct {
            name: "InnerPair".to_string(),
            fields: vec![
                NetStructField {
                    name: "Weights".to_string(),
                    prop_type: Box::new(NetPropertyType::Float),
                    array_dim: 2,
                },
                NetStructField {
                    name: "Active".to_string(),
                    prop_type: Box::new(NetPropertyType::Bool),
                    array_dim: 1,
                },
            ],
        });

        let outer_struct = NetPropertyType::Struct(NetStructKind::ScriptStruct {
            name: "OuterState".to_string(),
            fields: vec![
                NetStructField {
                    name: "NetId".to_string(),
                    prop_type: Box::new(NetPropertyType::Struct(NetStructKind::UniqueNetId)),
                    array_dim: 1,
                },
                NetStructField {
                    name: "Inner".to_string(),
                    prop_type: Box::new(nested_struct),
                    array_dim: 1,
                },
            ],
        });

        let cache = ClassNetCacheView::new("TestActor", 32)
            .with_fields([
                NetFieldSchema {
                    rep_index: 1,
                    name: "bReady".to_string(),
                    owner_class: "TestActor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Bool,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 2,
                    name: "Role".to_string(),
                    owner_class: "Actor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Byte {
                            enum_count: Some(5),
                        },
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 3,
                    name: "RawByte".to_string(),
                    owner_class: "TestActor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Byte { enum_count: None },
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 4,
                    name: "Health".to_string(),
                    owner_class: "Pawn".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Int,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 5,
                    name: "Stats".to_string(),
                    owner_class: "TestActor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Float,
                        array_dim: 10,
                    },
                },
                NetFieldSchema {
                    rep_index: 6,
                    name: "Location".to_string(),
                    owner_class: "Actor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Struct(NetStructKind::Vector),
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 7,
                    name: "Rotation".to_string(),
                    owner_class: "Actor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Struct(NetStructKind::Rotator),
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 8,
                    name: "PlayerName".to_string(),
                    owner_class: "PRI".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Str,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 9,
                    name: "StateName".to_string(),
                    owner_class: "TestActor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Name,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 10,
                    name: "Owner".to_string(),
                    owner_class: "Actor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: NetPropertyType::Object,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 11,
                    name: "Outer".to_string(),
                    owner_class: "TestActor".to_string(),
                    kind: NetFieldKind::Property {
                        prop_type: outer_struct,
                        array_dim: 1,
                    },
                },
                NetFieldSchema {
                    rep_index: 12,
                    name: "ClientGotoState".to_string(),
                    owner_class: "PlayerController".to_string(),
                    kind: NetFieldKind::Rpc {
                        params: vec![
                            NetRpcParam {
                                name: "NewState".to_string(),
                                prop_type: NetPropertyType::Name,
                                array_dim: 1,
                            },
                            NetRpcParam {
                                name: "bImmediate".to_string(),
                                prop_type: NetPropertyType::Bool,
                                array_dim: 1,
                            },
                            NetRpcParam {
                                name: "NewLabel".to_string(),
                                prop_type: NetPropertyType::Name,
                                array_dim: 1,
                            },
                        ],
                    },
                },
            ])
            .unwrap();

        let original = ActorBunch {
            open_header: Some(ActorOpenHeader {
                object_ref: ObjectRef::Static(55_555),
                location: Some([100.0, -250.0, 64.0]),
                rotation: None,
                net_player_index: Some(0),
            }),
            items: vec![
                ReplicatedItem::Property {
                    rep_index: 1,
                    name: "bReady".to_string(),
                    array_index: 0,
                    value: NetValue::Bool(true),
                },
                ReplicatedItem::Property {
                    rep_index: 2,
                    name: "Role".to_string(),
                    array_index: 0,
                    value: NetValue::Enum(2),
                },
                ReplicatedItem::Property {
                    rep_index: 3,
                    name: "RawByte".to_string(),
                    array_index: 0,
                    value: NetValue::Byte(0xAB),
                },
                ReplicatedItem::Property {
                    rep_index: 4,
                    name: "Health".to_string(),
                    array_index: 0,
                    value: NetValue::Int(4600),
                },
                ReplicatedItem::Property {
                    rep_index: 5,
                    name: "Stats".to_string(),
                    array_index: 7,
                    value: NetValue::Float(12.5),
                },
                ReplicatedItem::Property {
                    rep_index: 6,
                    name: "Location".to_string(),
                    array_index: 0,
                    value: NetValue::Vector([100.0, -250.0, 64.0]),
                },
                ReplicatedItem::Property {
                    rep_index: 7,
                    name: "Rotation".to_string(),
                    array_index: 0,
                    value: NetValue::Rotator([0, 16384, 0]),
                },
                ReplicatedItem::Property {
                    rep_index: 8,
                    name: "PlayerName".to_string(),
                    array_index: 0,
                    value: NetValue::Str("Player".to_string()),
                },
                ReplicatedItem::Property {
                    rep_index: 9,
                    name: "StateName".to_string(),
                    array_index: 0,
                    value: NetValue::Name(NetName::Dynamic {
                        name: "trm_sky".to_string(),
                        number: 0,
                    }),
                },
                ReplicatedItem::Property {
                    rep_index: 10,
                    name: "Owner".to_string(),
                    array_index: 0,
                    value: NetValue::Object(ObjectRef::DynamicChannel(3)),
                },
                ReplicatedItem::Property {
                    rep_index: 11,
                    name: "Outer".to_string(),
                    array_index: 0,
                    value: NetValue::Struct(vec![
                        NetStructFieldValue {
                            name: "NetId".to_string(),
                            values: vec![NetValue::UniqueNetId([1, 2, 3, 4, 5, 6, 7, 8])],
                        },
                        NetStructFieldValue {
                            name: "Inner".to_string(),
                            values: vec![NetValue::Struct(vec![
                                NetStructFieldValue {
                                    name: "Weights".to_string(),
                                    values: vec![NetValue::Float(1.25), NetValue::Float(2.5)],
                                },
                                NetStructFieldValue {
                                    name: "Active".to_string(),
                                    values: vec![NetValue::Bool(false)],
                                },
                            ])],
                        },
                    ]),
                },
                ReplicatedItem::Rpc {
                    rep_index: 12,
                    name: "ClientGotoState".to_string(),
                    params: vec![
                        RpcParamValue {
                            name: "NewState".to_string(),
                            values: Some(vec![NetValue::Name(NetName::Hardcoded(920))]),
                        },
                        RpcParamValue {
                            name: "bImmediate".to_string(),
                            values: Some(vec![NetValue::Bool(true)]),
                        },
                        RpcParamValue {
                            name: "NewLabel".to_string(),
                            values: None,
                        },
                    ],
                },
            ],
        };

        let layout = ActorSpawnLayout {
            has_location: true,
            has_rotation: false,
            is_player_controller: true,
        };
        let bunch = ActorBunchCodec::encode_to_bunch(3, 1, true, &cache, &original).unwrap();
        let decoded = ActorBunchCodec::decode_bunch(&bunch, &cache, Some(layout)).unwrap();
        assert_eq!(decoded, original);

        let reencoded = ActorBunchCodec::encode_to_bunch(3, 1, true, &cache, &decoded).unwrap();
        assert_eq!(reencoded.num_bits, bunch.num_bits);
        assert_eq!(reencoded.data, bunch.data);
    }

    #[test]
    fn test_unmapped_rep_index_rejected() {
        let cache = ClassNetCacheView::new("Empty", 16);
        let mut w = BitWriter::new();
        w.write_int(5, 16).unwrap();
        w.write_bit(true);
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes, 5).unwrap();
        let err = ActorBunchCodec::decode_update_bunch(&mut r, &cache).unwrap_err();
        assert!(matches!(err, NetError::BunchError(_)));
    }
}
