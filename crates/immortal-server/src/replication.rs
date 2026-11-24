// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Actor Replication & Fernando Pawn Spawning
//! Cleanroom implementation of Unreal Engine 3 `UActorChannel` (`ACTOR_CHANNEL_INDEX = 3`)
//! bit-exact replication (`ActorBunchCodec` / `UPackageMapLevel` / `FClassNetCache`),
//! Fernando (`TgPawn_Fernando`, `ChampionId::Fernando = 1026`) pawn lifecycle,
//! and verified hooks into `physics.rs` and `combat.rs`.
//!
//! ## `PSL-INV-012` Protocol Truth & Residual Unknowns
//! - **Verified S->C `UActorChannel` opens (`UNK-UDP-004` resolved)**:
//!   Bit-exact `ActorOpenHeader` + `FClassNetCache` `RepIndex` encoding/decoding for
//!   `ch=3` (`TgPlayerController`), `ch=4` (`TgPawn_Fernando`), `ch=80` (`TgRepInfo_Player`),
//!   and `ch=81` (`TgRepInfo_Game`) verified against live Oracle captures (`#40`, `#43`).
//! - **Pending `CAP-04` / `UNK-PROP-001` (uncaptured C->S RPCs)**:
//!   Inbound client-to-server movement/combat/loadout RPCs (`ServerMove`, combat firing RPCs,
//!   `m_CardDeck`, `ServerPurchaseItem`) have NOT yet been captured on the wire and remain
//!   explicitly documented as pending `CAP-04` / `UNK-PROP-001`. No speculative C->S RPC
//!   bitstreams are synthesized (`PSL-INV-012`).

use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use immortal_core::ChampionId;
use immortal_extract::netcache::{
    NetCacheRegistry, NetFieldKind as ExtractNetFieldKind, PackageMapManifest, PropertyClass,
    MINIMAL_SHOOTING_RANGE_PACKAGES,
};
use immortal_extract::package::read_tables_from_bytes;
use immortal_extract::{PackageSummary, UpkPackage};
pub use immortal_net::{FBitReader, FBitWriter, FInBunch};
use immortal_net::{
    ActorBunch, ActorBunchCodec, ActorOpenHeader, ActorSpawnLayout, BitReader, BitWriter, Bunch,
    BunchFlags, BunchHeader, ClassNetCacheView, NetError, NetFieldKind, NetFieldSchema,
    NetPropertyType, NetRpcParam, NetStructField, NetStructKind, NetValue, ObjectRef,
    ReplicatedItem, Ue3ChannelType, ACTOR_CHANNEL_INDEX, MAX_CHSEQUENCE, MAX_STRUCT_DEPTH,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read, Write};
use std::path::Path;

pub const FERNANDO_CHAMPION_ID: u32 = 1026;
pub const FERNANDO_PAWN_CLASS: &str = "TgPawn_Fernando";
pub const FERNANDO_SPAWN_X: f32 = 0.0;
pub const FERNANDO_SPAWN_Y: f32 = 0.0;
pub const FERNANDO_SPAWN_Z: f32 = 100.0;
pub const FERNANDO_BASE_HEALTH: f32 = 4600.0;
pub const DEVICE_FERNANDO_FLAME_LANCE: u32 = 10774;
/// Order (friendly player team) per `G2_SERVER_PROTOCOL.md` (`Team=0`).
pub const FERNANDO_DEFAULT_TEAM: u8 = 0;

pub const EVIE_CHAMPION_ID: u32 = 1030;
pub const EVIE_PAWN_CLASS: &str = "TgPawn_Evie";
pub const EVIE_BOT_CLASS: &str = "TgBot_Evie";
pub const EVIE_SPAWN_X: f32 = 500.0;
pub const EVIE_SPAWN_Y: f32 = 500.0;
pub const EVIE_SPAWN_Z: f32 = 100.0;
pub const EVIE_BASE_HEALTH: f32 = 1800.0;
/// Chaos (enemy bot team) per `G2_SERVER_PROTOCOL.md` (`Team=1`).
pub const EVIE_DEFAULT_TEAM: u8 = 1;

pub const PLAYER_CONTROLLER_CLASS: &str = "TgPlayerController";
pub const LOCAL_PLAYER_NAME: &str = "TgLocalPlayer_0";
pub const CONTROLLER_NAME: &str = "TgPlayerController_1";
pub const DEVICE_FERNANDO_INHAND: &str = "TgDevice_FernandoInhand_0";
pub const BOT_EVIE_NAME: &str = "TgBot_Evie_0";
pub const PAWN_EVIE_NAME: &str = "TgPawn_Evie_0";
pub const PAWN_FERNANDO_NAME: &str = "TgPawn_Fernando_0";

// Legacy/Simulated Replication Message Sub-Opcodes (synthetic harness only)
pub const REP_OP_OPEN_CHANNEL: u8 = 0x01;
pub const REP_OP_SPAWN_ACTOR: u8 = 0x02;
pub const REP_OP_UPDATE_TRANSFORM: u8 = 0x03;
pub const REP_OP_DESTROY_ACTOR: u8 = 0x04;
pub const REP_OP_POSSESS: u8 = 0x05;
pub const REP_OP_SPAWN_DEVICE: u8 = 0x06;
pub const REP_OP_SPAWN_BOT: u8 = 0x07;

// Verified UE3 v893 / Paladins Shooting Range UActorChannel constants (`#40`, `#43`)
pub const PLAYER_CONTROLLER_CHANNEL_INDEX: u32 = ACTOR_CHANNEL_INDEX;
pub const PLAYER_PAWN_CHANNEL_INDEX: u32 = 4;
pub const PRI_CHANNEL_INDEX: u32 = 80;
pub const GRI_CHANNEL_INDEX: u32 = 81;

pub const REP_INFO_PLAYER_CLASS: &str = "TgRepInfo_Player";
pub const REP_INFO_GAME_CLASS: &str = "TgRepInfo_Game";

pub const ROLE_AUTONOMOUS_PROXY: u32 = 2;
pub const PHYS_WALKING: u32 = 1;
pub const TG_GAME_TYPE_SHOOTING_RANGE: u32 = 7;
pub const DEFAULT_PLAYER_NAME: &str = "Player";
pub const DEFAULT_PLAYER_ID: i32 = 257;
pub const DEFAULT_PLAYER_CREDITS: i32 = 500;
pub const DEFAULT_CONTROLLER_SPAWN_X: f32 = -224.0;
pub const DEFAULT_CONTROLLER_SPAWN_Y: f32 = 0.0;
pub const DEFAULT_CONTROLLER_SPAWN_Z: f32 = 203.0;

// Verified TgGame.upk NetIndex values for Default__ archetypes (offset by TgGame ObjectBase=43503)
const HERMETIC_MINIMAL_NET_COUNTS: &[(&str, i32, u32)] = &[
    ("Core", 1562, 0xE2AA_0008),
    ("Engine", 35793, 0xE2AA_0008),
    ("GFxUI", 901, 0xE2AA_0009),
    ("GameFramework", 3838, 0xE2AA_0008),
    ("PlatformCommon", 1247, 0xE2AA_0009),
    ("Vivox", 64, 0xE2AA_0009),
    ("AkAudio", 98, 0xE2AA_0009),
    ("TgGame", 66967, 0xE2AA_0009),
    ("Shootingrange_P", 1038, 0xA28A_0009),
];
const NET_INDEX_DEFAULT_TG_PLAYER_CONTROLLER: i32 = 18_964;
const NET_INDEX_DEFAULT_TG_PAWN_FERNANDO: i32 = 49_289;
const NET_INDEX_DEFAULT_TG_REP_INFO_PLAYER: i32 = 54_728;
const NET_INDEX_DEFAULT_TG_REP_INFO_GAME: i32 = 41_505;

/// Global `UPackageMapLevel` static object indices for Shooting Range actor archetypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorArchetypeRefs {
    pub tg_player_controller: u32,
    pub tg_pawn_fernando: u32,
    pub tg_rep_info_player: u32,
    pub tg_rep_info_game: u32,
}

/// Loaded `PackageMapManifest` and `ClassNetCacheView` schemas driving bit-exact
/// `UActorChannel` replication (`ch=3, 4, 80, 81`).
#[derive(Debug, Clone)]
pub struct ActorReplicationSchemas {
    pub manifest: PackageMapManifest,
    pub archetypes: ActorArchetypeRefs,
    pub player_controller: ClassNetCacheView,
    pub pawn_fernando: ClassNetCacheView,
    pub rep_info_player: ClassNetCacheView,
    pub rep_info_game: ClassNetCacheView,
    pub from_real_upk: bool,
}

impl ActorReplicationSchemas {
    /// Loads the minimal Shooting Range package manifest and builds `ClassNetCacheView`
    /// schemas directly from cooked `.upk` packages in `upk_dir`.
    pub fn from_upk_dir(upk_dir: &Path) -> Result<Self> {
        for required in ["Core", "Engine", "TgGame", "Shootingrange_P"] {
            let p = upk_dir.join(format!("{required}.upk"));
            if !p.exists() {
                return Err(anyhow!(
                    "Required UPK package {} not found in {}",
                    p.display(),
                    upk_dir.display()
                ));
            }
        }

        let ordered_paths: Vec<_> = MINIMAL_SHOOTING_RANGE_PACKAGES
            .iter()
            .map(|stem| upk_dir.join(format!("{stem}.upk")))
            .filter(|p| p.exists())
            .collect();

        let manifest = PackageMapManifest::from_package_paths(&ordered_paths)
            .context("Failed to build PackageMapManifest from UPK directory")?;

        let mut registry = NetCacheRegistry::with_manifest(manifest.clone());
        for path in &ordered_paths {
            registry
                .load_package_file(path)
                .with_context(|| format!("Failed to load UPK into NetCacheRegistry: {}", path.display()))?;
        }

        let player_controller = class_net_cache_to_view(&mut registry, PLAYER_CONTROLLER_CLASS)?;
        let pawn_fernando = class_net_cache_to_view(&mut registry, FERNANDO_PAWN_CLASS)?;
        let rep_info_player = class_net_cache_to_view(&mut registry, REP_INFO_PLAYER_CLASS)?;
        let rep_info_game = class_net_cache_to_view(&mut registry, REP_INFO_GAME_CLASS)?;

        let tg_game_path = upk_dir.join("TgGame.upk");
        let archetypes = resolve_tggame_archetypes(&tg_game_path, &manifest)?;

        Ok(Self {
            manifest,
            archetypes,
            player_controller,
            pawn_fernando,
            rep_info_player,
            rep_info_game,
            from_real_upk: true,
        })
    }

    /// Builds a deterministic, hermetic manifest and `ClassNetCacheView` registry for
    /// tests/environments where Paladins `.upk` files are absent (`PSL-INV-001`).
    pub fn hermetic() -> Self {
        let summaries: Vec<(&str, PackageSummary)> = HERMETIC_MINIMAL_NET_COUNTS
            .iter()
            .enumerate()
            .map(|(idx, (name, net_count, flags))| {
                let mut guid = [0u8; 16];
                guid[0..4].copy_from_slice(&((idx as u32) + 1).to_le_bytes());
                guid[4..8].copy_from_slice(&0x494D_4D4Fu32.to_le_bytes()); // "IMMO"
                let mut summary = PackageSummary {
                    tag: immortal_extract::UPK_MAGIC,
                    file_version: 893,
                    licensee_version: 0,
                    total_header_size: 0,
                    folder_name: "None".to_string(),
                    package_flags: *flags,
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
                    guid,
                    generations: vec![immortal_extract::GenerationInfo {
                        export_count: 0,
                        name_count: 0,
                        net_object_count: *net_count,
                    }],
                    engine_version: 10897,
                    cooker_version: 393358,
                    compression_flags: 0,
                    compressed_chunks: Vec::new(),
                };
                // Keep Shootingrange_P lowercase package_name in NMT_UsesOpt matching trace if desired;
                // PackageMapManifest stores the stem name.
                summary.package_flags = *flags;
                (*name, summary)
            })
            .collect();

        let manifest = PackageMapManifest::from_summaries(
            summaries.iter().map(|(name, summary)| (*name, summary)),
        )
        .expect("Hermetic PackageMapManifest must never overflow");

        let archetypes = ActorArchetypeRefs {
            tg_player_controller: manifest
                .resolve_global_index("TgGame", NET_INDEX_DEFAULT_TG_PLAYER_CONTROLLER)
                .expect("TgGame Default__TgPlayerController index in range"),
            tg_pawn_fernando: manifest
                .resolve_global_index("TgGame", NET_INDEX_DEFAULT_TG_PAWN_FERNANDO)
                .expect("TgGame Default__TgPawn_Fernando index in range"),
            tg_rep_info_player: manifest
                .resolve_global_index("TgGame", NET_INDEX_DEFAULT_TG_REP_INFO_PLAYER)
                .expect("TgGame Default__TgRepInfo_Player index in range"),
            tg_rep_info_game: manifest
                .resolve_global_index("TgGame", NET_INDEX_DEFAULT_TG_REP_INFO_GAME)
                .expect("TgGame Default__TgRepInfo_Game index in range"),
        };

        Self {
            manifest,
            archetypes,
            player_controller: hermetic_player_controller_view(),
            pawn_fernando: hermetic_fernando_view(),
            rep_info_player: hermetic_rep_info_player_view(),
            rep_info_game: hermetic_rep_info_game_view(),
            from_real_upk: false,
        }
    }

    /// Returns the `ClassNetCacheView` for a supported actor class name.
    pub fn for_class(&self, class_name: &str) -> Option<&ClassNetCacheView> {
        match class_name {
            PLAYER_CONTROLLER_CLASS => Some(&self.player_controller),
            FERNANDO_PAWN_CLASS => Some(&self.pawn_fernando),
            REP_INFO_PLAYER_CLASS => Some(&self.rep_info_player),
            REP_INFO_GAME_CLASS => Some(&self.rep_info_game),
            _ => None,
        }
    }

    /// Returns `(ClassNetCacheView, ActorSpawnLayout)` for the standard Shooting Range channels.
    pub fn for_channel(&self, ch_index: u32) -> Option<(&ClassNetCacheView, ActorSpawnLayout)> {
        match ch_index {
            PLAYER_CONTROLLER_CHANNEL_INDEX => Some((
                &self.player_controller,
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: false,
                    is_player_controller: true,
                },
            )),
            PLAYER_PAWN_CHANNEL_INDEX => Some((
                &self.pawn_fernando,
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: false,
                    is_player_controller: false,
                },
            )),
            PRI_CHANNEL_INDEX => Some((
                &self.rep_info_player,
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: false,
                    is_player_controller: false,
                },
            )),
            GRI_CHANNEL_INDEX => Some((
                &self.rep_info_game,
                ActorSpawnLayout {
                    has_location: true,
                    has_rotation: false,
                    is_player_controller: false,
                },
            )),
            _ => None,
        }
    }
}

fn resolve_tggame_archetypes(
    tg_game_path: &Path,
    manifest: &PackageMapManifest,
) -> Result<ActorArchetypeRefs> {
    let mut pkg = UpkPackage::open_file(tg_game_path)
        .with_context(|| format!("Failed to open {}", tg_game_path.display()))?;
    let virtual_stream = pkg.decompress_all()?;
    let (name_table, _import_table, export_table) =
        read_tables_from_bytes(&virtual_stream, pkg.summary())?;

    let mut targets: BTreeMap<&str, Option<u32>> = BTreeMap::from([
        ("Default__TgPlayerController", None),
        ("Default__TgPawn_Fernando", None),
        ("Default__TgRepInfo_Player", None),
        ("Default__TgRepInfo_Game", None),
    ]);

    for export in export_table.entries() {
        let Some(name) = export.resolve_object_name(&name_table) else {
            continue;
        };
        if let Some(slot) = targets.get_mut(name.as_str()) {
            if let Ok(off) = usize::try_from(export.serial_offset) {
                if export.serial_size >= 4 && off + 4 <= virtual_stream.len() {
                    let net_index = i32::from_le_bytes(
                        virtual_stream[off..off + 4]
                            .try_into()
                            .expect("4-byte slice"),
                    );
                    *slot = manifest.resolve_global_index("TgGame", net_index);
                }
            }
        }
    }

    let get_idx = |name: &str| -> Result<u32> {
        targets
            .get(name)
            .and_then(|v| *v)
            .ok_or_else(|| anyhow!("Missing or invalid NetIndex for {name} in TgGame.upk"))
    };

    Ok(ActorArchetypeRefs {
        tg_player_controller: get_idx("Default__TgPlayerController")?,
        tg_pawn_fernando: get_idx("Default__TgPawn_Fernando")?,
        tg_rep_info_player: get_idx("Default__TgRepInfo_Player")?,
        tg_rep_info_game: get_idx("Default__TgRepInfo_Game")?,
    })
}

fn class_net_cache_to_view(
    registry: &mut NetCacheRegistry,
    class_name: &str,
) -> Result<ClassNetCacheView> {
    let root = registry
        .build_class_net_cache(class_name)
        .with_context(|| format!("Failed to build ClassNetCache for {class_name}"))?;
    let mut view = ClassNetCacheView::new(class_name, root.max_index);

    let mut current = Some(class_name.to_string());
    let mut visited = HashSet::new();
    while let Some(cname) = current {
        if !visited.insert(cname.clone()) {
            break;
        }
        let cache = registry.build_class_net_cache(&cname)?;
        for entry in &cache.own_fields {
            if let Some(schema) = convert_field_entry(registry, entry) {
                view.insert(schema)
                    .map_err(|e| anyhow!("ClassNetCacheView insert failed: {e}"))?;
            }
        }
        current = cache.super_class;
    }

    Ok(view)
}

fn convert_field_entry(
    registry: &NetCacheRegistry,
    entry: &immortal_extract::netcache::FieldNetCacheEntry,
) -> Option<NetFieldSchema> {
    let kind = match &entry.kind {
        ExtractNetFieldKind::Property {
            property_class,
            array_dim,
            tail_type_name,
            ..
        } => {
            let prop_type = convert_property_type(registry, *property_class, tail_type_name.as_deref(), 0)?;
            NetFieldKind::Property {
                prop_type,
                array_dim: *array_dim,
            }
        }
        ExtractNetFieldKind::Function { params, .. } => {
            let mut converted_params = Vec::with_capacity(params.len());
            for p in params {
                let prop_type =
                    convert_property_type(registry, p.property_class, p.tail_type_name.as_deref(), 0)?;
                converted_params.push(NetRpcParam {
                    name: p.name.clone(),
                    prop_type,
                    array_dim: p.array_dim,
                });
            }
            NetFieldKind::Rpc {
                params: converted_params,
            }
        }
    };

    Some(NetFieldSchema {
        rep_index: entry.rep_index,
        name: entry.field_name.clone(),
        owner_class: entry.owner_class.clone(),
        kind,
    })
}

fn convert_property_type(
    registry: &NetCacheRegistry,
    class_kind: PropertyClass,
    tail_type_name: Option<&str>,
    depth: usize,
) -> Option<NetPropertyType> {
    if depth >= MAX_STRUCT_DEPTH {
        return None;
    }
    match class_kind {
        PropertyClass::BoolProperty => Some(NetPropertyType::Bool),
        PropertyClass::ByteProperty => {
            let enum_count = tail_type_name
                .and_then(|name| registry.get_enum(name))
                .map(|en| en.names.len() as u32);
            Some(NetPropertyType::Byte { enum_count })
        }
        PropertyClass::IntProperty => Some(NetPropertyType::Int),
        PropertyClass::FloatProperty => Some(NetPropertyType::Float),
        PropertyClass::ObjectProperty
        | PropertyClass::ClassProperty
        | PropertyClass::ComponentProperty
        | PropertyClass::InterfaceProperty => Some(NetPropertyType::Object),
        PropertyClass::NameProperty => Some(NetPropertyType::Name),
        PropertyClass::StrProperty => Some(NetPropertyType::Str),
        PropertyClass::StructProperty => {
            let sname = tail_type_name?;
            match sname {
                "Vector" => Some(NetPropertyType::Struct(NetStructKind::Vector)),
                "Rotator" => Some(NetPropertyType::Struct(NetStructKind::Rotator)),
                "UniqueNetId" => Some(NetPropertyType::Struct(NetStructKind::UniqueNetId)),
                _ => {
                    let fields = collect_struct_fields(registry, sname, depth + 1)?;
                    Some(NetPropertyType::Struct(NetStructKind::ScriptStruct {
                        name: sname.to_string(),
                        fields,
                    }))
                }
            }
        }
        PropertyClass::ArrayProperty
        | PropertyClass::DelegateProperty
        | PropertyClass::MapProperty => None,
    }
}

fn collect_struct_fields(
    registry: &NetCacheRegistry,
    struct_name: &str,
    depth: usize,
) -> Option<Vec<NetStructField>> {
    if depth > MAX_STRUCT_DEPTH {
        return None;
    }
    let st = registry.get_struct(struct_name)?;
    let mut fields = Vec::new();
    if let Some(ref sup) = st.super_name {
        if registry.get_struct(sup).is_some() {
            fields.extend(collect_struct_fields(registry, sup, depth + 1)?);
        }
    }
    for prop in &st.fields {
        let prop_type = convert_property_type(
            registry,
            prop.class_kind,
            prop.tail_type_name.as_deref(),
            depth + 1,
        )?;
        fields.push(NetStructField {
            name: prop.name.clone(),
            prop_type: Box::new(prop_type),
            array_dim: prop.array_dim,
        });
    }
    Some(fields)
}

fn hermetic_prop(
    rep_index: u32,
    owner_class: &str,
    name: &str,
    prop_type: NetPropertyType,
    array_dim: u16,
) -> NetFieldSchema {
    NetFieldSchema {
        rep_index,
        name: name.to_string(),
        owner_class: owner_class.to_string(),
        kind: NetFieldKind::Property {
            prop_type,
            array_dim,
        },
    }
}

fn hermetic_player_controller_view() -> ClassNetCacheView {
    ClassNetCacheView::new(PLAYER_CONTROLLER_CLASS, 303)
        .with_fields([
            hermetic_prop(
                13,
                "Actor",
                "Role",
                NetPropertyType::Byte {
                    enum_count: Some(5),
                },
                1,
            ),
            hermetic_prop(
                19,
                "Actor",
                "Location",
                NetPropertyType::Struct(NetStructKind::Vector),
                1,
            ),
            hermetic_prop(29, "Controller", "PlayerReplicationInfo", NetPropertyType::Object, 1),
            hermetic_prop(291, PLAYER_CONTROLLER_CLASS, "r_fServerTimeStamp", NetPropertyType::Float, 1),
            hermetic_prop(292, PLAYER_CONTROLLER_CLASS, "r_bInputEnabled", NetPropertyType::Int, 20),
        ])
        .expect("Hermetic TgPlayerController ClassNetCacheView")
}

fn hermetic_fernando_view() -> ClassNetCacheView {
    ClassNetCacheView::new(FERNANDO_PAWN_CLASS, 264)
        .with_fields([
            hermetic_prop(
                10,
                "Actor",
                "Physics",
                NetPropertyType::Byte {
                    enum_count: Some(19),
                },
                1,
            ),
            hermetic_prop(
                19,
                "Actor",
                "Location",
                NetPropertyType::Struct(NetStructKind::Vector),
                1,
            ),
            hermetic_prop(
                22,
                "Actor",
                "Rotation",
                NetPropertyType::Struct(NetStructKind::Rotator),
                1,
            ),
            hermetic_prop(
                23,
                "Actor",
                "Velocity",
                NetPropertyType::Struct(NetStructKind::Vector),
                1,
            ),
            hermetic_prop(35, "Pawn", "Health", NetPropertyType::Int, 1),
            hermetic_prop(52, "Pawn", "Controller", NetPropertyType::Object, 1),
            hermetic_prop(149, "TgPawn", "r_fCachedMaxHealth", NetPropertyType::Float, 1),
        ])
        .expect("Hermetic TgPawn_Fernando ClassNetCacheView")
}

fn hermetic_rep_info_player_view() -> ClassNetCacheView {
    ClassNetCacheView::new(REP_INFO_PLAYER_CLASS, 150)
        .with_fields([
            hermetic_prop(41, "PlayerReplicationInfo", "PlayerID", NetPropertyType::Int, 1),
            hermetic_prop(44, "PlayerReplicationInfo", "PlayerName", NetPropertyType::Str, 1),
            hermetic_prop(89, REP_INFO_PLAYER_CLASS, "r_nCredits", NetPropertyType::Int, 1),
        ])
        .expect("Hermetic TgRepInfo_Player ClassNetCacheView")
}

fn hermetic_rep_info_game_view() -> ClassNetCacheView {
    ClassNetCacheView::new(REP_INFO_GAME_CLASS, 198)
        .with_fields([
            hermetic_prop(32, "GameReplicationInfo", "bMatchHasBegun", NetPropertyType::Bool, 1),
            hermetic_prop(
                196,
                REP_INFO_GAME_CLASS,
                "r_GameType",
                NetPropertyType::Byte {
                    enum_count: Some(50),
                },
                1,
            ),
        ])
        .expect("Hermetic TgRepInfo_Game ClassNetCacheView")
}

fn lookup_rep_index(cache: &ClassNetCacheView, field_name: &str) -> Result<u32> {
    cache
        .fields()
        .find(|f| f.name == field_name)
        .map(|f| f.rep_index)
        .ok_or_else(|| {
            anyhow!(
                "Missing replicated field '{field_name}' in ClassNetCacheView for {}",
                cache.class_name
            )
        })
}

/// 3D Spatial Vector for Unreal Engine 3 actor replication.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vector3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    pub fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0)
    }

    pub fn distance_to(&self, other: &Self) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }

    pub fn write_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_f32::<LittleEndian>(self.x)?;
        w.write_f32::<LittleEndian>(self.y)?;
        w.write_f32::<LittleEndian>(self.z)?;
        Ok(())
    }

    pub fn read_bytes<R: Read>(r: &mut R) -> std::io::Result<Self> {
        let x = r.read_f32::<LittleEndian>()?;
        let y = r.read_f32::<LittleEndian>()?;
        let z = r.read_f32::<LittleEndian>()?;
        Ok(Self { x, y, z })
    }
}

/// Angular orientation in UE3 rotator units (65536 units = 360 degrees).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Rotator {
    pub pitch: i32,
    pub yaw: i32,
    pub roll: i32,
}

impl Rotator {
    pub const fn new(pitch: i32, yaw: i32, roll: i32) -> Self {
        Self { pitch, yaw, roll }
    }

    pub fn from_degrees(pitch_deg: f32, yaw_deg: f32, roll_deg: f32) -> Self {
        let to_unit = |deg: f32| ((deg / 360.0) * 65536.0) as i32;
        Self {
            pitch: to_unit(pitch_deg),
            yaw: to_unit(yaw_deg),
            roll: to_unit(roll_deg),
        }
    }

    pub fn write_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_i32::<LittleEndian>(self.pitch)?;
        w.write_i32::<LittleEndian>(self.yaw)?;
        w.write_i32::<LittleEndian>(self.roll)?;
        Ok(())
    }

    pub fn read_bytes<R: Read>(r: &mut R) -> std::io::Result<Self> {
        let pitch = r.read_i32::<LittleEndian>()?;
        let yaw = r.read_i32::<LittleEndian>()?;
        let roll = r.read_i32::<LittleEndian>()?;
        Ok(Self { pitch, yaw, roll })
    }
}

/// PlayerController actor definition replicated across Channel 3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlayerControllerActor {
    pub actor_id: u32,
    pub channel_index: u32,
    pub pawn_actor_id: u32,
    pub controller_name: String,
    pub local_player_name: String,
    pub view_rotation: Rotator,
}

impl Default for PlayerControllerActor {
    fn default() -> Self {
        Self {
            actor_id: 10,
            channel_index: ACTOR_CHANNEL_INDEX,
            pawn_actor_id: 100,
            controller_name: CONTROLLER_NAME.to_string(),
            local_player_name: LOCAL_PLAYER_NAME.to_string(),
            view_rotation: Rotator::default(),
        }
    }
}

/// Weapon / Device actor definition (e.g. `TgDevice_FernandoInhand_0`, Device ID 10774).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceActor {
    pub device_id: u32,
    pub device_name: String,
    pub owner_pawn_id: u32,
}

impl Default for DeviceActor {
    fn default() -> Self {
        Self {
            device_id: DEVICE_FERNANDO_FLAME_LANCE,
            device_name: DEVICE_FERNANDO_INHAND.to_string(),
            owner_pawn_id: 100,
        }
    }
}

/// Bot AI Opponent definition (e.g. `TgBot_Evie_0` / `TgPawn_Evie_0`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotActor {
    pub bot_id: u32,
    pub bot_name: String,
    pub pawn_name: String,
    pub champion_id: ChampionId,
    pub team: u8,
    pub location: Vector3,
    pub rotation: Rotator,
    pub health: f32,
    pub max_health: f32,
}

impl Default for BotActor {
    fn default() -> Self {
        Self {
            bot_id: 200,
            bot_name: BOT_EVIE_NAME.to_string(),
            pawn_name: PAWN_EVIE_NAME.to_string(),
            champion_id: ChampionId::Evie,
            team: EVIE_DEFAULT_TEAM,
            location: Vector3::new(EVIE_SPAWN_X, EVIE_SPAWN_Y, EVIE_SPAWN_Z),
            rotation: Rotator::default(),
            health: EVIE_BASE_HEALTH,
            max_health: EVIE_BASE_HEALTH,
        }
    }
}

/// Fernando Pawn Actor definition and replicated properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PawnActor {
    pub actor_id: u32,
    pub class_name: String,
    pub champion_id: ChampionId,
    pub weapon_device_id: u32,
    pub team: u8,
    pub location: Vector3,
    pub rotation: Rotator,
    pub velocity: Vector3,
    pub health: f32,
    pub max_health: f32,
}

impl Default for PawnActor {
    fn default() -> Self {
        Self {
            actor_id: 100,
            class_name: FERNANDO_PAWN_CLASS.to_string(),
            champion_id: ChampionId::Fernando,
            weapon_device_id: DEVICE_FERNANDO_FLAME_LANCE,
            team: FERNANDO_DEFAULT_TEAM,
            location: Vector3::new(FERNANDO_SPAWN_X, FERNANDO_SPAWN_Y, FERNANDO_SPAWN_Z),
            rotation: Rotator::default(),
            velocity: Vector3::zero(),
            health: FERNANDO_BASE_HEALTH,
            max_health: FERNANDO_BASE_HEALTH,
        }
    }
}

/// High-level replication manager for a connected game client session.
#[derive(Debug, Clone)]
pub struct ReplicationSession {
    pub controller: PlayerControllerActor,
    pub pawn: PawnActor,
    pub weapon_device: DeviceActor,
    pub bot_opponent: BotActor,
    pub player_name: String,
    pub player_id: i32,
    pub credits: i32,
    pub game_type: u32,
    pub match_has_begun: bool,
    pub controller_location: Vector3,
    pub channel_opened: bool,
    pub real_channels_opened: bool,
    pub player_possessed: bool,
    pub pawn_spawned: bool,
    pub weapon_spawned: bool,
    pub bot_spawned: bool,
    pub actor_sequence: u32,
    pub bot_sequence: u32,
    pub pawn_channel_sequence: u32,
    pub pri_sequence: u32,
    pub gri_sequence: u32,
}

impl Default for ReplicationSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationSession {
    pub fn new() -> Self {
        Self {
            controller: PlayerControllerActor::default(),
            pawn: PawnActor::default(),
            weapon_device: DeviceActor::default(),
            bot_opponent: BotActor::default(),
            player_name: DEFAULT_PLAYER_NAME.to_string(),
            player_id: DEFAULT_PLAYER_ID,
            credits: DEFAULT_PLAYER_CREDITS,
            game_type: TG_GAME_TYPE_SHOOTING_RANGE,
            match_has_begun: true,
            controller_location: Vector3::new(
                DEFAULT_CONTROLLER_SPAWN_X,
                DEFAULT_CONTROLLER_SPAWN_Y,
                DEFAULT_CONTROLLER_SPAWN_Z,
            ),
            channel_opened: false,
            real_channels_opened: false,
            player_possessed: false,
            pawn_spawned: false,
            weapon_spawned: false,
            bot_spawned: false,
            actor_sequence: 1,
            bot_sequence: 1,
            pawn_channel_sequence: 1,
            pri_sequence: 1,
            gri_sequence: 1,
        }
    }

    /// Allocates the next 10-bit UE3 Actor Channel 3 reliable `ChSequence` modulo `MAX_CHSEQUENCE`.
    pub fn next_actor_seq(&mut self) -> u32 {
        let seq = self.actor_sequence;
        self.actor_sequence = (self.actor_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }

    /// Allocates the next 10-bit UE3 Actor Channel 4 (bot / pawn) reliable `ChSequence` modulo `MAX_CHSEQUENCE`.
    pub fn next_bot_seq(&mut self) -> u32 {
        let seq = self.bot_sequence;
        self.bot_sequence = (self.bot_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }

    /// Allocates the next 10-bit UE3 Actor Channel 4 (`TgPawn_Fernando`) reliable `ChSequence`.
    pub fn next_pawn_seq(&mut self) -> u32 {
        let seq = self.pawn_channel_sequence;
        self.pawn_channel_sequence = (self.pawn_channel_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }

    /// Allocates the next 10-bit UE3 Actor Channel 80 (`TgRepInfo_Player`) reliable `ChSequence`.
    pub fn next_pri_seq(&mut self) -> u32 {
        let seq = self.pri_sequence;
        self.pri_sequence = (self.pri_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }

    /// Allocates the next 10-bit UE3 Actor Channel 81 (`TgRepInfo_Game`) reliable `ChSequence`.
    pub fn next_gri_seq(&mut self) -> u32 {
        let seq = self.gri_sequence;
        self.gri_sequence = (self.gri_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }

    /// Emits bit-exact UE3 v893 `UActorChannel` open bunches for Shooting Range:
    /// - `ch=80` `TgRepInfo_Player` (`PlayerName`, `PlayerID`, `r_nCredits = 500`)
    /// - `ch=81` `TgRepInfo_Game` (`bMatchHasBegun = true`, `r_GameType`)
    /// - `ch=3` `TgPlayerController` (`Location`, `NetPlayerIndex = 0`, `Role = ROLE_AutonomousProxy (2)`,
    ///   `r_bInputEnabled`, `PlayerReplicationInfo -> DynamicChannel(80)`)
    /// - `ch=4` `TgPawn_Fernando` (`Location`, `Rotation`, `Physics = PHYS_Walking (1)`, `Health = 4600`,
    ///   `r_fCachedMaxHealth = 4600.0`, `Controller -> DynamicChannel(3)`)
    ///
    /// Note (`PSL-INV-012`): C->S inbound RPCs (`ServerMove`, combat firing RPCs, `m_CardDeck`,
    /// `ServerPurchaseItem`) remain uncaptured and pending `CAP-04` / `UNK-PROP-001`.
    pub fn open_real_actor_channels(
        &mut self,
        schemas: &ActorReplicationSchemas,
    ) -> Result<Vec<Bunch>> {
        self.real_channels_opened = true;
        self.channel_opened = true;
        self.pawn_spawned = true;

        // 1. ch=80: TgRepInfo_Player (opened first so ch=3 PRI DynamicChannel(80) resolves cleanly)
        let pri_cache = &schemas.rep_info_player;
        let pri_bunch_data = ActorBunch {
            open_header: Some(ActorOpenHeader {
                object_ref: ObjectRef::Static(schemas.archetypes.tg_rep_info_player),
                location: Some([0.0, 0.0, 0.0]),
                rotation: None,
                net_player_index: None,
            }),
            items: vec![
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pri_cache, "PlayerName")?,
                    name: "PlayerName".to_string(),
                    array_index: 0,
                    value: NetValue::Str(self.player_name.clone()),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pri_cache, "PlayerID")?,
                    name: "PlayerID".to_string(),
                    array_index: 0,
                    value: NetValue::Int(self.player_id),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pri_cache, "r_nCredits")?,
                    name: "r_nCredits".to_string(),
                    array_index: 0,
                    value: NetValue::Int(self.credits),
                },
            ],
        };
        let pri_seq = self.next_pri_seq();
        let ch80 = ActorBunchCodec::encode_to_bunch(
            PRI_CHANNEL_INDEX,
            pri_seq,
            true,
            pri_cache,
            &pri_bunch_data,
        )?;

        // 2. ch=81: TgRepInfo_Game
        let gri_cache = &schemas.rep_info_game;
        let gri_bunch_data = ActorBunch {
            open_header: Some(ActorOpenHeader {
                object_ref: ObjectRef::Static(schemas.archetypes.tg_rep_info_game),
                location: Some([0.0, 0.0, 0.0]),
                rotation: None,
                net_player_index: None,
            }),
            items: vec![
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(gri_cache, "bMatchHasBegun")?,
                    name: "bMatchHasBegun".to_string(),
                    array_index: 0,
                    value: NetValue::Bool(self.match_has_begun),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(gri_cache, "r_GameType")?,
                    name: "r_GameType".to_string(),
                    array_index: 0,
                    value: NetValue::Enum(self.game_type),
                },
            ],
        };
        let gri_seq = self.next_gri_seq();
        let ch81 = ActorBunchCodec::encode_to_bunch(
            GRI_CHANNEL_INDEX,
            gri_seq,
            true,
            gri_cache,
            &gri_bunch_data,
        )?;

        // 3. ch=3: TgPlayerController
        let pc_cache = &schemas.player_controller;
        let role_rep = lookup_rep_index(pc_cache, "Role")?;
        let input_rep = lookup_rep_index(pc_cache, "r_bInputEnabled")?;
        let pri_rep = lookup_rep_index(pc_cache, "PlayerReplicationInfo")?;

        let mut pc_items = Vec::with_capacity(22);
        pc_items.push(ReplicatedItem::Property {
            rep_index: role_rep,
            name: "Role".to_string(),
            array_index: 0,
            value: NetValue::Enum(ROLE_AUTONOMOUS_PROXY),
        });
        for idx in 0..20u8 {
            pc_items.push(ReplicatedItem::Property {
                rep_index: input_rep,
                name: "r_bInputEnabled".to_string(),
                array_index: idx,
                value: NetValue::Int(1),
            });
        }
        pc_items.push(ReplicatedItem::Property {
            rep_index: pri_rep,
            name: "PlayerReplicationInfo".to_string(),
            array_index: 0,
            value: NetValue::Object(ObjectRef::DynamicChannel(PRI_CHANNEL_INDEX)),
        });

        let pc_bunch_data = ActorBunch {
            open_header: Some(ActorOpenHeader {
                object_ref: ObjectRef::Static(schemas.archetypes.tg_player_controller),
                location: Some([
                    self.controller_location.x,
                    self.controller_location.y,
                    self.controller_location.z,
                ]),
                rotation: None,
                net_player_index: Some(0),
            }),
            items: pc_items,
        };
        let pc_seq = self.next_actor_seq();
        let ch3 = ActorBunchCodec::encode_to_bunch(
            PLAYER_CONTROLLER_CHANNEL_INDEX,
            pc_seq,
            true,
            pc_cache,
            &pc_bunch_data,
        )?;

        // 4. ch=4: TgPawn_Fernando (opened after ch=3 so Controller -> DynamicChannel(3) resolves cleanly)
        let pawn_cache = &schemas.pawn_fernando;
        let pawn_bunch_data = ActorBunch {
            open_header: Some(ActorOpenHeader {
                object_ref: ObjectRef::Static(schemas.archetypes.tg_pawn_fernando),
                location: Some([
                    self.pawn.location.x,
                    self.pawn.location.y,
                    self.pawn.location.z,
                ]),
                rotation: None,
                net_player_index: None,
            }),
            items: vec![
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Location")?,
                    name: "Location".to_string(),
                    array_index: 0,
                    value: NetValue::Vector([
                        self.pawn.location.x,
                        self.pawn.location.y,
                        self.pawn.location.z,
                    ]),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Rotation")?,
                    name: "Rotation".to_string(),
                    array_index: 0,
                    value: NetValue::Rotator([
                        self.pawn.rotation.pitch,
                        self.pawn.rotation.yaw,
                        self.pawn.rotation.roll,
                    ]),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Physics")?,
                    name: "Physics".to_string(),
                    array_index: 0,
                    value: NetValue::Enum(PHYS_WALKING),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Health")?,
                    name: "Health".to_string(),
                    array_index: 0,
                    value: NetValue::Int(self.pawn.health.round() as i32),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "r_fCachedMaxHealth")?,
                    name: "r_fCachedMaxHealth".to_string(),
                    array_index: 0,
                    value: NetValue::Float(self.pawn.max_health),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Controller")?,
                    name: "Controller".to_string(),
                    array_index: 0,
                    value: NetValue::Object(ObjectRef::DynamicChannel(
                        PLAYER_CONTROLLER_CHANNEL_INDEX,
                    )),
                },
            ],
        };
        let pawn_seq = self.next_pawn_seq();
        let ch4 = ActorBunchCodec::encode_to_bunch(
            PLAYER_PAWN_CHANNEL_INDEX,
            pawn_seq,
            true,
            pawn_cache,
            &pawn_bunch_data,
        )?;

        Ok(vec![ch80, ch81, ch3, ch4])
    }

    /// Encodes a bit-exact `ch=4` (`TgPawn_Fernando`) transform update bunch via `ActorBunchCodec`.
    pub fn encode_pawn_state_update(&mut self, schemas: &ActorReplicationSchemas) -> Result<Bunch> {
        let pawn_cache = &schemas.pawn_fernando;
        let update = ActorBunch {
            open_header: None,
            items: vec![
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Location")?,
                    name: "Location".to_string(),
                    array_index: 0,
                    value: NetValue::Vector([
                        self.pawn.location.x,
                        self.pawn.location.y,
                        self.pawn.location.z,
                    ]),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Rotation")?,
                    name: "Rotation".to_string(),
                    array_index: 0,
                    value: NetValue::Rotator([
                        self.pawn.rotation.pitch,
                        self.pawn.rotation.yaw,
                        self.pawn.rotation.roll,
                    ]),
                },
                ReplicatedItem::Property {
                    rep_index: lookup_rep_index(pawn_cache, "Velocity")?,
                    name: "Velocity".to_string(),
                    array_index: 0,
                    value: NetValue::Vector([
                        self.pawn.velocity.x,
                        self.pawn.velocity.y,
                        self.pawn.velocity.z,
                    ]),
                },
            ],
        };
        let seq = self.next_pawn_seq();
        ActorBunchCodec::encode_to_bunch(
            PLAYER_PAWN_CHANNEL_INDEX,
            seq,
            false,
            pawn_cache,
            &update,
        )
        .map_err(Into::into)
    }

    /// Verified hook into `physics.rs`: resolves surface velocity against `surface_normal`
    /// (`m_bCanBaseOn`), integrates pawn location over `dt_sec`, and encodes a bit-exact
    /// `UActorChannel` `ch=4` transform update bunch.
    /// (Inbound C->S `ServerMove` RPCs remain uncaptured pending `CAP-04` / `PSL-INV-012`.)
    pub fn step_physics_movement(
        &mut self,
        schemas: &ActorReplicationSchemas,
        surface_normal: [f32; 3],
        m_b_can_base_on: bool,
        dt_sec: f32,
    ) -> Result<Bunch> {
        let vel = [
            self.pawn.velocity.x,
            self.pawn.velocity.y,
            self.pawn.velocity.z,
        ];
        let (resolved, _interaction) =
            crate::physics::resolve_surface_velocity(vel, surface_normal, m_b_can_base_on, 980.0, dt_sec);
        self.pawn.velocity = Vector3::new(resolved[0], resolved[1], resolved[2]);
        self.pawn.location.x += resolved[0] * dt_sec;
        self.pawn.location.y += resolved[1] * dt_sec;
        self.pawn.location.z += resolved[2] * dt_sec;
        self.encode_pawn_state_update(schemas)
    }

    /// Verified hook into `combat.rs`: applies incoming damage (with optional Fernando Immortal
    /// aura floor clamp via `apply_immortal_aura_clamp`), updates `pawn.health`, and emits a
    /// bit-exact `UActorChannel` `ch=4` `Health` update bunch.
    /// (Inbound C->S combat RPCs remain uncaptured pending `CAP-04` / `PSL-INV-012`.)
    pub fn apply_combat_damage(
        &mut self,
        schemas: &ActorReplicationSchemas,
        raw_damage: f32,
        immortal_aura_active: bool,
    ) -> Result<(f32, Bunch)> {
        let post_damage = (self.pawn.health - raw_damage.max(0.0)).clamp(0.0, self.pawn.max_health);
        let clamped_next = if immortal_aura_active {
            let pos = [
                self.pawn.location.x,
                self.pawn.location.y,
                self.pawn.location.z,
            ];
            crate::combat::apply_immortal_aura_clamp(pos, pos, post_damage, self.pawn.max_health)
        } else {
            post_damage
        };
        let actual_damage = (self.pawn.health - clamped_next).max(0.0);
        self.pawn.health = clamped_next;

        let pawn_cache = &schemas.pawn_fernando;
        let update = ActorBunch {
            open_header: None,
            items: vec![ReplicatedItem::Property {
                rep_index: lookup_rep_index(pawn_cache, "Health")?,
                name: "Health".to_string(),
                array_index: 0,
                value: NetValue::Int(self.pawn.health.round() as i32),
            }],
        };
        let seq = self.next_pawn_seq();
        let bunch = ActorBunchCodec::encode_to_bunch(
            PLAYER_PAWN_CHANNEL_INDEX,
            seq,
            true,
            pawn_cache,
            &update,
        )?;
        Ok((actual_damage, bunch))
    }

    /// Verified hook into `combat.rs` hitbox collision: evaluates a dual-stage ray against the
    /// pawn's normalized cylinder + head hitbox anchored at `self.pawn.location`.
    pub fn evaluate_pawn_hit(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        head_center_offset_z: f32,
    ) -> crate::combat::HitResult {
        let base = [
            self.pawn.location.x,
            self.pawn.location.y,
            self.pawn.location.z,
        ];
        let cylinder = crate::combat::CylinderHitbox::new(base, 45.0, 180.0);
        let head = crate::combat::HeadHitbox::new(
            [base[0], base[1], base[2] + head_center_offset_z],
            22.0,
        );
        let target = crate::combat::TargetHitbox::new_normalized(
            self.pawn.champion_id,
            cylinder,
            head,
        );
        target.evaluate_ray_hit(origin, dir, None)
    }

    /// Generates a bunch that opens Actor Channel (`ACTOR_CHANNEL_INDEX = 3`) for `PlayerController`.
    /// Sets `bOpen = true, bReliable = true, ChSequence = 1, ChType = 2 (CHTYPE_Actor)`.
    pub fn open_channel_3(&mut self) -> Bunch {
        self.channel_opened = true;
        let payload = ReplicationPayload::OpenChannel {
            actor_id: self.controller.actor_id,
            channel_index: self.controller.channel_index,
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, true, payload.encode())
    }

    /// Backward-compatibility alias for `open_channel_3`.
    pub fn open_channel_2(&mut self) -> Bunch {
        self.open_channel_3()
    }

    /// Generates possession bunch (`TgPlayerController_1 setplayer TgLocalPlayer_0`).
    pub fn possess_player_controller(&mut self) -> Bunch {
        self.player_possessed = true;
        let payload = ReplicationPayload::PossessPlayer {
            actor_id: self.controller.actor_id,
            controller_name: self.controller.controller_name.clone(),
            local_player_name: self.controller.local_player_name.clone(),
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, false, payload.encode())
    }

    /// Spawns and replicates Fernando pawn (`TgPawn_Fernando`, `ChampionId::Fernando = 1026`)
    /// with Weapon Device ID 10774 (`DEVICE_FERNANDO_FLAME_LANCE`) and Team 0 (Order)
    /// at spawn coordinates `(0.0, 0.0, 100.0)`.
    pub fn spawn_fernando(&mut self) -> Bunch {
        self.pawn_spawned = true;
        let payload = ReplicationPayload::SpawnActor {
            actor_id: self.pawn.actor_id,
            champion_id: self.pawn.champion_id,
            weapon_device_id: self.pawn.weapon_device_id,
            team: self.pawn.team,
            class_name: self.pawn.class_name.clone(),
            location: self.pawn.location,
            rotation: self.pawn.rotation,
            health: self.pawn.health,
            max_health: self.pawn.max_health,
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, false, payload.encode())
    }

    /// Replicates Fernando in-hand weapon device (`TgDevice_FernandoInhand_0`, Device ID 10774 / Flame Lance).
    pub fn spawn_fernando_weapon(&mut self) -> Bunch {
        self.weapon_spawned = true;
        let payload = ReplicationPayload::SpawnDevice {
            device_id: self.weapon_device.device_id,
            device_name: self.weapon_device.device_name.clone(),
            owner_pawn_id: self.weapon_device.owner_pawn_id,
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, false, payload.encode())
    }

    /// Replicates bot opponent: `TgBot_Evie_0` / `TgPawn_Evie_0` on Channel 4.
    /// Sets `bOpen = true` only on the first call and increments Channel 4 `ChSequence` monotonically.
    pub fn spawn_bot_opponent(&mut self) -> Bunch {
        let is_open = !self.bot_spawned;
        self.bot_spawned = true;
        let payload = ReplicationPayload::SpawnBot {
            bot_id: self.bot_opponent.bot_id,
            bot_name: self.bot_opponent.bot_name.clone(),
            pawn_name: self.bot_opponent.pawn_name.clone(),
            champion_id: self.bot_opponent.champion_id,
            team: self.bot_opponent.team,
            location: self.bot_opponent.location,
            health: self.bot_opponent.health,
        };
        let data = payload.encode();
        let seq = self.next_bot_seq();
        Bunch::new(
            BunchHeader {
                ch_index: 4,
                ch_type: Ue3ChannelType::Actor,
                flags: BunchFlags {
                    b_open: is_open,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence: seq,
            },
            data,
        )
    }

    /// Simulated/placeholder initial replication bunches (legacy/synthetic harness only).
    /// Note (`Claim 16` / `UNK-UDP-004`): Authentic `PComNetConn` UDP 7777 sessions MUST NOT
    /// emit these invented `ReplicationPayload` bytes on `NMT_MapLoaded (0x2A)` or `NMT_Join (0x09)`
    /// until `UNK-UDP-004` (`UActorChannel` bitstream) is verified from unencrypted Flight 036 / Oracle captures.
    pub fn initial_replication_bunches(&mut self) -> Vec<Bunch> {
        vec![
            self.open_channel_3(),
            self.possess_player_controller(),
            self.spawn_fernando(),
            self.spawn_fernando_weapon(),
            self.spawn_bot_opponent(),
            self.stream_baseline_delta(0.016),
        ]
    }

    /// Applies movement deltas to Fernando's pawn location and rotation, generating an update bunch.
    pub fn apply_movement_delta(
        &mut self,
        dx: f32,
        dy: f32,
        dz: f32,
        new_rotation: Option<Rotator>,
    ) -> Bunch {
        self.pawn.location.x += dx;
        self.pawn.location.y += dy;
        self.pawn.location.z += dz;
        if let Some(rot) = new_rotation {
            self.pawn.rotation = rot;
        }

        let payload = ReplicationPayload::UpdateTransform {
            actor_id: self.pawn.actor_id,
            location: self.pawn.location,
            rotation: self.pawn.rotation,
            velocity: self.pawn.velocity,
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, false, payload.encode())
    }

    /// Streams baseline actor position/rotation delta so client can walk around Shooting Range.
    pub fn stream_baseline_delta(&mut self, _dt_seconds: f32) -> Bunch {
        let payload = ReplicationPayload::UpdateTransform {
            actor_id: self.pawn.actor_id,
            location: self.pawn.location,
            rotation: self.pawn.rotation,
            velocity: self.pawn.velocity,
        };
        let seq = self.next_actor_seq();
        Bunch::actor(seq, false, payload.encode())
    }
}

/// Parsed replication payload from Actor Channel.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationPayload {
    OpenChannel {
        actor_id: u32,
        channel_index: u32,
    },
    PossessPlayer {
        actor_id: u32,
        controller_name: String,
        local_player_name: String,
    },
    SpawnActor {
        actor_id: u32,
        champion_id: ChampionId,
        weapon_device_id: u32,
        team: u8,
        class_name: String,
        location: Vector3,
        rotation: Rotator,
        health: f32,
        max_health: f32,
    },
    SpawnDevice {
        device_id: u32,
        device_name: String,
        owner_pawn_id: u32,
    },
    SpawnBot {
        bot_id: u32,
        bot_name: String,
        pawn_name: String,
        champion_id: ChampionId,
        team: u8,
        location: Vector3,
        health: f32,
    },
    UpdateTransform {
        actor_id: u32,
        location: Vector3,
        rotation: Rotator,
        velocity: Vector3,
    },
    Unknown(Vec<u8>),
}

impl ReplicationPayload {
    /// Serializes this replication payload to raw bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Self::OpenChannel {
                actor_id,
                channel_index,
            } => {
                data.push(REP_OP_OPEN_CHANNEL);
                data.write_u32::<LittleEndian>(*actor_id).unwrap();
                data.write_u32::<LittleEndian>(*channel_index).unwrap();
            }
            Self::PossessPlayer {
                actor_id,
                controller_name,
                local_player_name,
            } => {
                data.push(REP_OP_POSSESS);
                data.write_u32::<LittleEndian>(*actor_id).unwrap();
                let ctrl_bytes = controller_name.as_bytes();
                data.write_u16::<LittleEndian>(ctrl_bytes.len() as u16).unwrap();
                data.extend_from_slice(ctrl_bytes);
                let ply_bytes = local_player_name.as_bytes();
                data.write_u16::<LittleEndian>(ply_bytes.len() as u16).unwrap();
                data.extend_from_slice(ply_bytes);
            }
            Self::SpawnActor {
                actor_id,
                champion_id,
                weapon_device_id,
                team,
                class_name,
                location,
                rotation,
                health,
                max_health,
            } => {
                data.push(REP_OP_SPAWN_ACTOR);
                data.write_u32::<LittleEndian>(*actor_id).unwrap();
                data.write_u32::<LittleEndian>(*champion_id as u32).unwrap();
                data.write_u32::<LittleEndian>(*weapon_device_id).unwrap();
                data.push(*team);
                let class_bytes = class_name.as_bytes();
                data.write_u16::<LittleEndian>(class_bytes.len() as u16).unwrap();
                data.extend_from_slice(class_bytes);
                location.write_bytes(&mut data).unwrap();
                rotation.write_bytes(&mut data).unwrap();
                data.write_f32::<LittleEndian>(*health).unwrap();
                data.write_f32::<LittleEndian>(*max_health).unwrap();
            }
            Self::SpawnDevice {
                device_id,
                device_name,
                owner_pawn_id,
            } => {
                data.push(REP_OP_SPAWN_DEVICE);
                data.write_u32::<LittleEndian>(*device_id).unwrap();
                let dev_bytes = device_name.as_bytes();
                data.write_u16::<LittleEndian>(dev_bytes.len() as u16).unwrap();
                data.extend_from_slice(dev_bytes);
                data.write_u32::<LittleEndian>(*owner_pawn_id).unwrap();
            }
            Self::SpawnBot {
                bot_id,
                bot_name,
                pawn_name,
                champion_id,
                team,
                location,
                health,
            } => {
                data.push(REP_OP_SPAWN_BOT);
                data.write_u32::<LittleEndian>(*bot_id).unwrap();
                let b_bytes = bot_name.as_bytes();
                data.write_u16::<LittleEndian>(b_bytes.len() as u16).unwrap();
                data.extend_from_slice(b_bytes);
                let p_bytes = pawn_name.as_bytes();
                data.write_u16::<LittleEndian>(p_bytes.len() as u16).unwrap();
                data.extend_from_slice(p_bytes);
                data.write_u32::<LittleEndian>(*champion_id as u32).unwrap();
                data.push(*team);
                location.write_bytes(&mut data).unwrap();
                data.write_f32::<LittleEndian>(*health).unwrap();
            }
            Self::UpdateTransform {
                actor_id,
                location,
                rotation,
                velocity,
            } => {
                data.push(REP_OP_UPDATE_TRANSFORM);
                data.write_u32::<LittleEndian>(*actor_id).unwrap();
                location.write_bytes(&mut data).unwrap();
                rotation.write_bytes(&mut data).unwrap();
                velocity.write_bytes(&mut data).unwrap();
            }
            Self::Unknown(raw) => {
                data.extend_from_slice(raw);
            }
        }
        data
    }

    /// Serializes this replication payload into a UE3 `BitWriter` / `FBitWriter`.
    pub fn encode_bits(&self, writer: &mut BitWriter) -> Result<(), NetError> {
        let bytes = self.encode();
        writer.write_bytes(&bytes);
        Ok(())
    }

    /// Deserializes a replication payload from raw bytes.
    pub fn decode(bytes: &[u8]) -> std::io::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::Unknown(Vec::new()));
        }
        let mut cursor = Cursor::new(bytes);
        let opcode = cursor.read_u8()?;

        match opcode {
            REP_OP_OPEN_CHANNEL => {
                let actor_id = cursor.read_u32::<LittleEndian>()?;
                let channel_index = cursor.read_u32::<LittleEndian>()?;
                Ok(Self::OpenChannel {
                    actor_id,
                    channel_index,
                })
            }
            REP_OP_POSSESS => {
                let actor_id = cursor.read_u32::<LittleEndian>()?;
                let ctrl_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut ctrl_buf = vec![0u8; ctrl_len];
                cursor.read_exact(&mut ctrl_buf)?;
                let controller_name = String::from_utf8_lossy(&ctrl_buf).to_string();

                let ply_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut ply_buf = vec![0u8; ply_len];
                cursor.read_exact(&mut ply_buf)?;
                let local_player_name = String::from_utf8_lossy(&ply_buf).to_string();

                Ok(Self::PossessPlayer {
                    actor_id,
                    controller_name,
                    local_player_name,
                })
            }
            REP_OP_SPAWN_ACTOR => {
                let actor_id = cursor.read_u32::<LittleEndian>()?;
                let champ_raw = cursor.read_u32::<LittleEndian>()?;
                let champ_id = ChampionId::from_id(champ_raw);
                let weapon_device_id = cursor.read_u32::<LittleEndian>()?;
                let team = cursor.read_u8()?;

                let class_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut class_buf = vec![0u8; class_len];
                cursor.read_exact(&mut class_buf)?;
                let class_name = String::from_utf8_lossy(&class_buf).to_string();

                let location = Vector3::read_bytes(&mut cursor)?;
                let rotation = Rotator::read_bytes(&mut cursor)?;
                let health = cursor.read_f32::<LittleEndian>()?;
                let max_health = cursor.read_f32::<LittleEndian>()?;

                Ok(Self::SpawnActor {
                    actor_id,
                    champion_id: champ_id,
                    weapon_device_id,
                    team,
                    class_name,
                    location,
                    rotation,
                    health,
                    max_health,
                })
            }
            REP_OP_SPAWN_DEVICE => {
                let device_id = cursor.read_u32::<LittleEndian>()?;
                let dev_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut dev_buf = vec![0u8; dev_len];
                cursor.read_exact(&mut dev_buf)?;
                let device_name = String::from_utf8_lossy(&dev_buf).to_string();
                let owner_pawn_id = cursor.read_u32::<LittleEndian>()?;

                Ok(Self::SpawnDevice {
                    device_id,
                    device_name,
                    owner_pawn_id,
                })
            }
            REP_OP_SPAWN_BOT => {
                let bot_id = cursor.read_u32::<LittleEndian>()?;
                let b_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut b_buf = vec![0u8; b_len];
                cursor.read_exact(&mut b_buf)?;
                let bot_name = String::from_utf8_lossy(&b_buf).to_string();

                let p_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut p_buf = vec![0u8; p_len];
                cursor.read_exact(&mut p_buf)?;
                let pawn_name = String::from_utf8_lossy(&p_buf).to_string();

                let champ_raw = cursor.read_u32::<LittleEndian>()?;
                let champ_id = ChampionId::from_id(champ_raw);
                let team = cursor.read_u8()?;
                let location = Vector3::read_bytes(&mut cursor)?;
                let health = cursor.read_f32::<LittleEndian>()?;

                Ok(Self::SpawnBot {
                    bot_id,
                    bot_name,
                    pawn_name,
                    champion_id: champ_id,
                    team,
                    location,
                    health,
                })
            }
            REP_OP_UPDATE_TRANSFORM => {
                let actor_id = cursor.read_u32::<LittleEndian>()?;
                let location = Vector3::read_bytes(&mut cursor)?;
                let rotation = Rotator::read_bytes(&mut cursor)?;
                let velocity = Vector3::read_bytes(&mut cursor)?;
                Ok(Self::UpdateTransform {
                    actor_id,
                    location,
                    rotation,
                    velocity,
                })
            }
            _ => Ok(Self::Unknown(bytes.to_vec())),
        }
    }

    /// Deserializes a replication payload from a UE3 `BitReader` / `FBitReader`.
    pub fn decode_bits(reader: &mut BitReader) -> Result<Self, NetError> {
        let bits_left = reader.bits_left();
        let bytes_left = bits_left / 8;
        if bytes_left == 0 {
            return Ok(Self::Unknown(Vec::new()));
        }
        let raw = reader.read_bytes(bytes_left)?;
        Self::decode(&raw).map_err(|e| NetError::BunchError(format!("Replication decode error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fernando_spawn_constants() {
        assert_eq!(FERNANDO_CHAMPION_ID, 1026);
        assert_eq!(FERNANDO_PAWN_CLASS, "TgPawn_Fernando");
        assert_eq!(FERNANDO_SPAWN_X, 0.0);
        assert_eq!(FERNANDO_SPAWN_Y, 0.0);
        assert_eq!(FERNANDO_SPAWN_Z, 100.0);
        assert_eq!(FERNANDO_BASE_HEALTH, 4600.0);
        assert_eq!(DEVICE_FERNANDO_FLAME_LANCE, 10774);
        assert_eq!(FERNANDO_DEFAULT_TEAM, 0);
        assert_eq!(DEVICE_FERNANDO_INHAND, "TgDevice_FernandoInhand_0");
    }

    #[test]
    fn test_evie_bot_constants() {
        assert_eq!(EVIE_CHAMPION_ID, 1030);
        assert_eq!(EVIE_PAWN_CLASS, "TgPawn_Evie");
        assert_eq!(EVIE_BOT_CLASS, "TgBot_Evie");
        assert_eq!(EVIE_BASE_HEALTH, 1800.0);
        assert_eq!(EVIE_DEFAULT_TEAM, 1);
        assert_eq!(BOT_EVIE_NAME, "TgBot_Evie_0");
        assert_eq!(PAWN_EVIE_NAME, "TgPawn_Evie_0");
    }

    #[test]
    fn test_open_channel_3_bunch() {
        let mut session = ReplicationSession::new();
        assert!(!session.channel_opened);

        let bunch = session.open_channel_3();
        assert!(session.channel_opened);
        assert_eq!(bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(bunch.header.ch_index, 3);
        assert_eq!(bunch.header.ch_sequence, 1);
        assert!(bunch.header.flags.b_open);
        assert!(bunch.header.flags.b_reliable);
        assert_eq!(bunch.header.ch_type, Ue3ChannelType::Actor);

        let parsed = ReplicationPayload::decode(&bunch.data).unwrap();
        match parsed {
            ReplicationPayload::OpenChannel {
                actor_id,
                channel_index,
            } => {
                assert_eq!(actor_id, 10);
                assert_eq!(channel_index, ACTOR_CHANNEL_INDEX);
            }
            other => panic!("Expected OpenChannel, got {:?}", other),
        }
    }

    #[test]
    fn test_possess_player_controller_bunch() {
        let mut session = ReplicationSession::new();
        let _ = session.open_channel_3();
        let possess_bunch = session.possess_player_controller();

        assert!(session.player_possessed);
        assert_eq!(possess_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(possess_bunch.header.ch_sequence, 2);
        assert!(!possess_bunch.header.flags.b_open);
        assert!(possess_bunch.header.flags.b_reliable);

        let parsed = ReplicationPayload::decode(&possess_bunch.data).unwrap();
        match parsed {
            ReplicationPayload::PossessPlayer {
                actor_id,
                controller_name,
                local_player_name,
            } => {
                assert_eq!(actor_id, 10);
                assert_eq!(controller_name, "TgPlayerController_1");
                assert_eq!(local_player_name, "TgLocalPlayer_0");
            }
            other => panic!("Expected PossessPlayer, got {:?}", other),
        }
    }

    #[test]
    fn test_spawn_fernando_and_weapon_bunch() {
        let mut session = ReplicationSession::new();
        let _ = session.open_channel_3();
        let spawn_bunch = session.spawn_fernando();
        let weapon_bunch = session.spawn_fernando_weapon();

        assert!(session.pawn_spawned);
        assert!(session.weapon_spawned);
        assert_eq!(spawn_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(weapon_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);

        let spawn_parsed = ReplicationPayload::decode(&spawn_bunch.data).unwrap();
        match spawn_parsed {
            ReplicationPayload::SpawnActor {
                actor_id,
                champion_id,
                weapon_device_id,
                team,
                class_name,
                location,
                health,
                ..
            } => {
                assert_eq!(actor_id, 100);
                assert_eq!(champion_id, ChampionId::Fernando);
                assert_eq!(weapon_device_id, 10774);
                assert_eq!(team, 0);
                assert_eq!(class_name, "TgPawn_Fernando");
                assert_eq!(location.x, 0.0);
                assert_eq!(location.y, 0.0);
                assert_eq!(location.z, 100.0);
                assert_eq!(health, 4600.0);
            }
            other => panic!("Expected SpawnActor, got {:?}", other),
        }

        let weapon_parsed = ReplicationPayload::decode(&weapon_bunch.data).unwrap();
        match weapon_parsed {
            ReplicationPayload::SpawnDevice {
                device_id,
                device_name,
                owner_pawn_id,
            } => {
                assert_eq!(device_id, 10774);
                assert_eq!(device_name, "TgDevice_FernandoInhand_0");
                assert_eq!(owner_pawn_id, 100);
            }
            other => panic!("Expected SpawnDevice, got {:?}", other),
        }
    }

    #[test]
    fn test_spawn_bot_opponent_bunch() {
        let mut session = ReplicationSession::new();
        let bot_bunch = session.spawn_bot_opponent();

        assert!(session.bot_spawned);
        assert_eq!(bot_bunch.header.ch_index, 4);
        assert!(bot_bunch.header.flags.b_open);
        assert!(bot_bunch.header.flags.b_reliable);
        assert_eq!(bot_bunch.header.ch_type, Ue3ChannelType::Actor);

        let parsed = ReplicationPayload::decode(&bot_bunch.data).unwrap();
        match parsed {
            ReplicationPayload::SpawnBot {
                bot_id,
                bot_name,
                pawn_name,
                champion_id,
                team,
                location,
                health,
            } => {
                assert_eq!(bot_id, 200);
                assert_eq!(bot_name, "TgBot_Evie_0");
                assert_eq!(pawn_name, "TgPawn_Evie_0");
                assert_eq!(champion_id, ChampionId::Evie);
                assert_eq!(team, 1);
                assert_eq!(location.x, 500.0);
                assert_eq!(health, 1800.0);
            }
            other => panic!("Expected SpawnBot, got {:?}", other),
        }

        let bot_bunch_2 = session.spawn_bot_opponent();
        assert_eq!(bot_bunch_2.header.ch_index, 4);
        assert!(!bot_bunch_2.header.flags.b_open);
        assert_eq!(bot_bunch_2.header.ch_sequence, 2);
    }

    #[test]
    fn test_initial_replication_bunches_sequence() {
        let mut session = ReplicationSession::new();
        let bunches = session.initial_replication_bunches();
        assert_eq!(bunches.len(), 6);

        // Bunch 0: Open Channel 3
        assert_eq!(bunches[0].header.ch_index, 3);
        assert!(bunches[0].header.flags.b_open);
        assert_eq!(bunches[0].header.ch_sequence, 1);

        // Bunch 1: Possess TgPlayerController_1 -> TgLocalPlayer_0
        assert_eq!(bunches[1].header.ch_index, 3);
        assert_eq!(bunches[1].header.ch_sequence, 2);

        // Bunch 2: Spawn Fernando Pawn
        assert_eq!(bunches[2].header.ch_index, 3);
        assert_eq!(bunches[2].header.ch_sequence, 3);

        // Bunch 3: Spawn Fernando Weapon Device 10774
        assert_eq!(bunches[3].header.ch_index, 3);
        assert_eq!(bunches[3].header.ch_sequence, 4);

        // Bunch 4: Spawn Bot Evie on Channel 4
        assert_eq!(bunches[4].header.ch_index, 4);
        assert!(bunches[4].header.flags.b_open);

        // Bunch 5: Transform delta
        assert_eq!(bunches[5].header.ch_index, 3);
        assert_eq!(bunches[5].header.ch_sequence, 5);
    }

    #[test]
    fn test_bitwriter_fbitwriter_roundtrip() {
        let payload = ReplicationPayload::PossessPlayer {
            actor_id: 10,
            controller_name: "TgPlayerController_1".to_string(),
            local_player_name: "TgLocalPlayer_0".to_string(),
        };

        let mut writer = FBitWriter::with_capacity_bits(128);
        payload.encode_bits(&mut writer).unwrap();
        let bytes = writer.into_bytes();

        let mut reader = FBitReader::new(&bytes, bytes.len() * 8).unwrap();
        let decoded = ReplicationPayload::decode_bits(&mut reader).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_movement_delta_streaming() {
        let mut session = ReplicationSession::new();
        let _ = session.open_channel_2();
        let _ = session.spawn_fernando();

        // Move Fernando forward by 50 units in X and 20 in Y
        let move_bunch = session.apply_movement_delta(50.0, 20.0, 0.0, None);
        assert_eq!(session.pawn.location.x, 50.0);
        assert_eq!(session.pawn.location.y, 20.0);
        assert_eq!(session.pawn.location.z, 100.0);

        let parsed = ReplicationPayload::decode(&move_bunch.data).unwrap();
        match parsed {
            ReplicationPayload::UpdateTransform { location, .. } => {
                assert_eq!(location.x, 50.0);
                assert_eq!(location.y, 20.0);
                assert_eq!(location.z, 100.0);
            }
            other => panic!("Expected UpdateTransform, got {:?}", other),
        }
    }

    #[test]
    fn test_actor_sequence_wraps_mod_max_chsequence() {
        let mut session = ReplicationSession::new();
        session.actor_sequence = MAX_CHSEQUENCE - 1;

        let b_last = session.stream_baseline_delta(0.016);
        assert_eq!(b_last.header.ch_sequence, MAX_CHSEQUENCE - 1);
        assert_eq!(session.actor_sequence, 0);

        let b_wrap = session.stream_baseline_delta(0.016);
        assert_eq!(b_wrap.header.ch_sequence, 0);
        assert_eq!(session.actor_sequence, 1);

        let b_next = session.stream_baseline_delta(0.016);
        assert_eq!(b_next.header.ch_sequence, 1);
        assert_eq!(session.actor_sequence, 2);
    }

    fn verify_four_actor_channel_opens(schemas: &ActorReplicationSchemas) {
        let mut session = ReplicationSession::new();
        let bunches = session.open_real_actor_channels(schemas).unwrap();
        assert_eq!(bunches.len(), 4);
        assert!(session.real_channels_opened);

        let mut decoded_by_ch = BTreeMap::new();
        for b in &bunches {
            assert!(b.header.flags.b_open);
            assert!(b.header.flags.b_reliable);
            assert_eq!(b.header.ch_type, Ue3ChannelType::Actor);
            assert_eq!(b.header.ch_sequence, 1);
            let (cache, layout) = schemas
                .for_channel(b.header.ch_index)
                .expect("Channel schema must exist");
            let dec = ActorBunchCodec::decode_bunch(b, cache, Some(layout))
                .expect("ActorBunchCodec must decode with 0 leftover bits");
            decoded_by_ch.insert(b.header.ch_index, dec);
        }

        // ch=3: TgPlayerController
        let pc = decoded_by_ch.get(&PLAYER_CONTROLLER_CHANNEL_INDEX).unwrap();
        let pc_hdr = pc.open_header.as_ref().unwrap();
        assert_eq!(
            pc_hdr.object_ref,
            ObjectRef::Static(schemas.archetypes.tg_player_controller)
        );
        assert_eq!(pc_hdr.location, Some([-224.0, 0.0, 203.0]));
        assert_eq!(pc_hdr.net_player_index, Some(0));
        assert!(pc.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Enum(2), .. } if name == "Role"
        )));
        assert!(pc.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property {
                name,
                value: NetValue::Object(ObjectRef::DynamicChannel(80)),
                ..
            } if name == "PlayerReplicationInfo"
        )));
        let input_count = pc
            .items
            .iter()
            .filter(|it| {
                matches!(
                    it,
                    ReplicatedItem::Property { name, value: NetValue::Int(1), .. } if name == "r_bInputEnabled"
                )
            })
            .count();
        assert_eq!(input_count, 20);

        // ch=4: TgPawn_Fernando
        let pawn = decoded_by_ch.get(&PLAYER_PAWN_CHANNEL_INDEX).unwrap();
        let pawn_hdr = pawn.open_header.as_ref().unwrap();
        assert_eq!(
            pawn_hdr.object_ref,
            ObjectRef::Static(schemas.archetypes.tg_pawn_fernando)
        );
        assert_eq!(pawn_hdr.location, Some([0.0, 0.0, 100.0]));
        assert_eq!(pawn_hdr.rotation, None);
        assert_eq!(pawn_hdr.net_player_index, None);
        assert!(pawn.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Enum(1), .. } if name == "Physics"
        )));
        assert!(pawn.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Int(4600), .. } if name == "Health"
        )));
        assert!(pawn.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Float(v), .. } if name == "r_fCachedMaxHealth" && (*v - 4600.0).abs() < f32::EPSILON
        )));
        assert!(pawn.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property {
                name,
                value: NetValue::Object(ObjectRef::DynamicChannel(3)),
                ..
            } if name == "Controller"
        )));

        // ch=80: TgRepInfo_Player
        let pri = decoded_by_ch.get(&PRI_CHANNEL_INDEX).unwrap();
        assert!(pri.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Str(s), .. } if name == "PlayerName" && s == "Player"
        )));
        assert!(pri.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Int(257), .. } if name == "PlayerID"
        )));
        assert!(pri.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Int(500), .. } if name == "r_nCredits"
        )));

        // ch=81: TgRepInfo_Game
        let gri = decoded_by_ch.get(&GRI_CHANNEL_INDEX).unwrap();
        assert!(gri.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Bool(true), .. } if name == "bMatchHasBegun"
        )));
        assert!(gri.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Enum(7), .. } if name == "r_GameType"
        )));
    }

    #[test]
    fn test_real_uactor_channel_open_bunches_hermetic_roundtrip() {
        let schemas = ActorReplicationSchemas::hermetic();
        assert!(!schemas.from_real_upk);
        assert_eq!(schemas.manifest.entries.len(), 9);
        assert_eq!(schemas.player_controller.max_index, 303);
        assert_eq!(schemas.pawn_fernando.max_index, 264);
        assert_eq!(schemas.rep_info_player.max_index, 150);
        assert_eq!(schemas.rep_info_game.max_index, 198);
        verify_four_actor_channel_opens(&schemas);
    }

    #[test]
    fn test_real_uactor_channel_schemas_from_real_upks_if_present() {
        let upk_dir = Path::new(
            "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole",
        );
        if !upk_dir.join("TgGame.upk").exists() {
            return;
        }
        let schemas = ActorReplicationSchemas::from_upk_dir(upk_dir)
            .expect("from_upk_dir must succeed on real CookedPCConsole");
        assert!(schemas.from_real_upk);
        assert_eq!(schemas.manifest.entries.len(), 9);
        assert_eq!(schemas.player_controller.max_index, 303);
        assert_eq!(schemas.pawn_fernando.max_index, 264);
        assert_eq!(schemas.rep_info_player.max_index, 150);
        assert_eq!(schemas.rep_info_game.max_index, 198);
        verify_four_actor_channel_opens(&schemas);
    }

    #[test]
    fn test_physics_and_combat_replication_hooks() {
        let schemas = ActorReplicationSchemas::hermetic();
        let mut session = ReplicationSession::new();
        session.pawn.velocity = Vector3::new(300.0, 0.0, -200.0);

        let move_bunch = session
            .step_physics_movement(&schemas, [0.0, 0.0, 1.0], true, 0.5)
            .unwrap();
        let decoded_move =
            ActorBunchCodec::decode_bunch(&move_bunch, &schemas.pawn_fernando, None).unwrap();
        assert!(decoded_move.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Vector(v), .. }
                if name == "Location" && (v[0] - 150.0).abs() < 1.0 && (v[2] - 100.0).abs() < 1.0
        )));

        let hit = session.evaluate_pawn_hit([-200.0, 0.0, 260.0], [1.0, 0.0, 0.0], 160.0);
        assert!(hit.struck);
        assert!(hit.is_headshot);

        // Immortal aura clamps Fernando's health at IMMORTAL_MIN_HEALTH_FLOOR (1500)
        let (_dmg, hp_bunch) = session
            .apply_combat_damage(&schemas, 10_000.0, true)
            .unwrap();
        let decoded_hp =
            ActorBunchCodec::decode_bunch(&hp_bunch, &schemas.pawn_fernando, None).unwrap();
        assert!(decoded_hp.items.iter().any(|it| matches!(
            it,
            ReplicatedItem::Property { name, value: NetValue::Int(1500), .. } if name == "Health"
        )));
    }
}
