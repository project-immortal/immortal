// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Live Retail Oracle Trace Parity Tests (`PSL-INV-012`)
//! Reads `/home/kuasha/.gemini/antigravity/brain/9238fc8d-1813-4cdb-9056-13f7774e8251/scratch/oracle_probe_trace.json`
//! when present on disk (gracefully skips on CI when absent) and verifies bit-exact
//! decode + re-encode parity for Channel 0 control bunches and `UActorChannel`
//! bunches (`ch=3, 4, 5, 80, 81`). Zero proprietary dumps are checked into git (`PSL-INV-007`).

use std::path::Path;

use immortal_net::{
    ActorBunchCodec, ActorSpawnLayout, Bunch, BunchFlags, BunchHeader, ClassNetCacheView,
    ControlMessage, NetFieldKind, NetFieldSchema, NetPropertyType, NetRpcParam, NetStructField,
    NetStructKind, NetValue, ReplicatedItem, Ue3ChannelType,
};
use serde::Deserialize;

const TRACE_PATH: &str =
    "/home/kuasha/.gemini/antigravity/brain/9238fc8d-1813-4cdb-9056-13f7774e8251/scratch/oracle_probe_trace.json";

#[derive(Debug, Deserialize)]
struct TraceRoot {
    events: Vec<TraceEvent>,
}

#[derive(Debug, Deserialize)]
struct TraceEvent {
    #[serde(default)]
    decoded: Option<TraceDecoded>,
}

#[derive(Debug, Deserialize)]
struct TraceDecoded {
    #[serde(default)]
    bunches: Vec<TraceBunch>,
}

#[derive(Debug, Deserialize)]
struct TraceBunch {
    ch_index: u32,
    ch_type: u8,
    b_open: bool,
    b_close: bool,
    b_reliable: bool,
    ch_sequence: u32,
    num_bits: usize,
    data_hex: String,
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn prop(
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

fn rpc(
    rep_index: u32,
    owner_class: &str,
    name: &str,
    params: Vec<(&str, NetPropertyType, u16)>,
) -> NetFieldSchema {
    NetFieldSchema {
        rep_index,
        name: name.to_string(),
        owner_class: owner_class.to_string(),
        kind: NetFieldKind::Rpc {
            params: params
                .into_iter()
                .map(|(pname, prop_type, array_dim)| NetRpcParam {
                    name: pname.to_string(),
                    prop_type,
                    array_dim,
                })
                .collect(),
        },
    }
}

fn sfield(name: &str, prop_type: NetPropertyType, array_dim: u16) -> NetStructField {
    NetStructField {
        name: name.to_string(),
        prop_type: Box::new(prop_type),
        array_dim,
    }
}

fn schema_tg_player_controller() -> ClassNetCacheView {
    ClassNetCacheView::new("TgPlayerController", 303)
        .with_fields([
            prop(2, "Actor", "bCollideWorld", NetPropertyType::Bool, 1),
            prop(5, "Actor", "bNetOwner", NetPropertyType::Bool, 1),
            prop(
                13,
                "Actor",
                "Role",
                NetPropertyType::Byte {
                    enum_count: Some(5),
                },
                1,
            ),
            prop(
                29,
                "Controller",
                "PlayerReplicationInfo",
                NetPropertyType::Object,
                1,
            ),
            rpc(
                41,
                "PlayerController",
                "ClientGotoState",
                vec![
                    ("NewState", NetPropertyType::Name, 1),
                    ("NewLabel", NetPropertyType::Name, 1),
                ],
            ),
            rpc(
                45,
                "PlayerController",
                "ClientSetHUD",
                vec![("newHUDType", NetPropertyType::Object, 1)],
            ),
            rpc(
                46,
                "PlayerController",
                "ClientSetSecondaryHUD",
                vec![("newHUDType", NetPropertyType::Object, 1)],
            ),
            rpc(
                71,
                "PlayerController",
                "ClientCapBandwidth",
                vec![("Cap", NetPropertyType::Int, 1)],
            ),
            rpc(
                109,
                "PlayerController",
                "ClientUpdateLevelStreamingStatus",
                vec![
                    ("PackageName", NetPropertyType::Name, 1),
                    ("bNewShouldBeLoaded", NetPropertyType::Bool, 1),
                    ("bNewShouldBeVisible", NetPropertyType::Bool, 1),
                    ("bNewShouldBlockOnLoad", NetPropertyType::Bool, 1),
                ],
            ),
            rpc(114, "PlayerController", "ClientFlushLevelStreaming", vec![]),
            rpc(117, "PlayerController", "ClientSetOnlineStatus", vec![]),
            rpc(
                118,
                "PlayerController",
                "ClientVoiceHandshakeComplete",
                vec![],
            ),
            rpc(131, "PlayerController", "ClientStartNetworkedVoice", vec![]),
            rpc(
                207,
                "TgPlayerController",
                "ClientSetReadyState",
                vec![("bReadyToPlay", NetPropertyType::Bool, 1)],
            ),
            prop(
                291,
                "TgPlayerController",
                "r_fServerTimeStamp",
                NetPropertyType::Float,
                1,
            ),
            prop(
                292,
                "TgPlayerController",
                "r_bInputEnabled",
                NetPropertyType::Int,
                20,
            ),
        ])
        .unwrap()
}

fn schema_tg_pawn_fernando() -> ClassNetCacheView {
    let equip_device_info = NetPropertyType::Struct(NetStructKind::ScriptStruct {
        name: "EquipDeviceInfo".to_string(),
        fields: vec![
            sfield("nDeviceId", NetPropertyType::Int, 1),
            sfield("nDeviceInstanceId", NetPropertyType::Int, 1),
            sfield("nMode", NetPropertyType::Int, 1),
        ],
    });
    let dword_struct = NetPropertyType::Struct(NetStructKind::ScriptStruct {
        name: "dword".to_string(),
        fields: vec![sfield("A", NetPropertyType::Int, 1)],
    });

    ClassNetCacheView::new("TgPawn_Fernando", 264)
        .with_fields([
            prop(6, "Actor", "bNetRelevant", NetPropertyType::Bool, 1),
            prop(
                10,
                "Actor",
                "Physics",
                NetPropertyType::Byte {
                    enum_count: Some(19),
                },
                1,
            ),
            prop(16, "Actor", "Base", NetPropertyType::Object, 1),
            prop(
                19,
                "Actor",
                "Location",
                NetPropertyType::Struct(NetStructKind::Vector),
                1,
            ),
            prop(
                22,
                "Actor",
                "Rotation",
                NetPropertyType::Struct(NetStructKind::Rotator),
                1,
            ),
            prop(
                23,
                "Actor",
                "Velocity",
                NetPropertyType::Struct(NetStructKind::Vector),
                1,
            ),
            prop(
                33,
                "Pawn",
                "PlayerReplicationInfo",
                NetPropertyType::Object,
                1,
            ),
            prop(35, "Pawn", "Health", NetPropertyType::Int, 1),
            prop(
                148,
                "TgPawn",
                "r_CurrentPropValues",
                NetPropertyType::Float,
                153,
            ),
            prop(
                149,
                "TgPawn",
                "r_fCachedMaxHealth",
                NetPropertyType::Float,
                1,
            ),
            prop(160, "TgPawn", "r_fIntroOffset", NetPropertyType::Float, 1),
            prop(
                181,
                "TgPawn",
                "r_nFirstValidFlashEventIdx",
                NetPropertyType::Int,
                1,
            ),
            prop(189, "TgPawn", "r_nMountSkinId", NetPropertyType::Int, 1),
            prop(190, "TgPawn", "r_nPacingType", NetPropertyType::Int, 1),
            prop(192, "TgPawn", "r_nPawnId", NetPropertyType::Int, 1),
            prop(194, "TgPawn", "r_nPhysicalType", NetPropertyType::Int, 1),
            prop(196, "TgPawn", "r_nProfileId", NetPropertyType::Int, 1),
            prop(199, "TgPawn", "r_nSkinId", NetPropertyType::Int, 1),
            prop(202, "TgPawn", "r_nWeaponSkinId", NetPropertyType::Int, 1),
            prop(212, "TgPawn", "r_EffectManager", NetPropertyType::Object, 1),
            prop(228, "TgPawn", "r_EquipDeviceInfo", equip_device_info, 49),
            prop(229, "TgPawn", "r_eVoicePref", dword_struct, 1),
        ])
        .unwrap()
}

fn schema_matinee_actor() -> ClassNetCacheView {
    ClassNetCacheView::new("MatineeActor", 32)
        .with_fields([
            prop(26, "MatineeActor", "Position", NetPropertyType::Float, 1),
            prop(27, "MatineeActor", "PlayRate", NetPropertyType::Float, 1),
            prop(30, "MatineeActor", "bIsPlaying", NetPropertyType::Bool, 1),
            prop(
                31,
                "MatineeActor",
                "InterpAction",
                NetPropertyType::Object,
                1,
            ),
        ])
        .unwrap()
}

fn schema_tg_rep_info_player() -> ClassNetCacheView {
    ClassNetCacheView::new("TgRepInfo_Player", 150)
        .with_fields([
            prop(
                31,
                "PlayerReplicationInfo",
                "bIsSpectator",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                32,
                "PlayerReplicationInfo",
                "bOnlySpectator",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                33,
                "PlayerReplicationInfo",
                "bOutOfLives",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                41,
                "PlayerReplicationInfo",
                "PlayerID",
                NetPropertyType::Int,
                1,
            ),
            prop(
                42,
                "PlayerReplicationInfo",
                "StartTime",
                NetPropertyType::Int,
                1,
            ),
            prop(
                44,
                "PlayerReplicationInfo",
                "PlayerName",
                NetPropertyType::Str,
                1,
            ),
            prop(
                88,
                "TgRepInfo_Player",
                "r_nEarnedCredits",
                NetPropertyType::Int,
                1,
            ),
            prop(
                89,
                "TgRepInfo_Player",
                "r_nCredits",
                NetPropertyType::Int,
                1,
            ),
        ])
        .unwrap()
}

fn schema_tg_rep_info_game() -> ClassNetCacheView {
    let skill_pct_data = NetPropertyType::Struct(NetStructKind::ScriptStruct {
        name: "SkillLevelPercentageData".to_string(),
        fields: vec![
            sfield("NumDeathsPercentage", NetPropertyType::Float, 1),
            sfield("DamagePercentage", NetPropertyType::Float, 1),
            sfield("KillsPercentage", NetPropertyType::Float, 1),
            sfield("SoloKillsPercentage", NetPropertyType::Float, 1),
            sfield("AssistsPercentage", NetPropertyType::Float, 1),
            sfield("HealingPercentage", NetPropertyType::Float, 1),
            sfield("CreditsPercentage", NetPropertyType::Float, 1),
            sfield("ObjectiveTimePercentage", NetPropertyType::Float, 1),
            sfield("ShieldingPercentage", NetPropertyType::Float, 1),
            sfield("KillstreakMultiplier", NetPropertyType::Float, 1),
        ],
    });
    let bot_difficulty_debug = NetPropertyType::Struct(NetStructKind::ScriptStruct {
        name: "BotDifficultyDebugData".to_string(),
        fields: vec![
            sfield("CurrentlyActive", NetPropertyType::Bool, 1),
            sfield("DisparityDetected", NetPropertyType::Bool, 1),
            sfield("ChangesLockedOut", NetPropertyType::Bool, 1),
            sfield("TimeBeforeTrigger", NetPropertyType::Int, 1),
            sfield(
                "TaskForce1BotDifficulty",
                NetPropertyType::Byte {
                    enum_count: Some(10),
                },
                1,
            ),
            sfield(
                "TaskForce2BotDifficulty",
                NetPropertyType::Byte {
                    enum_count: Some(10),
                },
                1,
            ),
            sfield("TaskForce1Skill", NetPropertyType::Float, 1),
            sfield("TaskForce2Skill", NetPropertyType::Float, 1),
            sfield("SkillPercentages", skill_pct_data, 2),
        ],
    });

    ClassNetCacheView::new("TgRepInfo_Game", 198)
        .with_fields([
            prop(
                25,
                "GameReplicationInfo",
                "ServerName",
                NetPropertyType::Str,
                1,
            ),
            prop(
                29,
                "GameReplicationInfo",
                "ElapsedTime",
                NetPropertyType::Int,
                1,
            ),
            prop(
                32,
                "GameReplicationInfo",
                "bMatchHasBegun",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                34,
                "GameReplicationInfo",
                "GameClass",
                NetPropertyType::Object,
                1,
            ),
            prop(
                42,
                "TgRepInfo_Game",
                "r_DifficultyDebugData",
                bot_difficulty_debug,
                1,
            ),
            prop(
                47,
                "TgRepInfo_Game",
                "r_fRemountLockoutTime",
                NetPropertyType::Float,
                1,
            ),
            prop(
                55,
                "TgRepInfo_Game",
                "r_fPlayerViewDistance",
                NetPropertyType::Float,
                1,
            ),
            prop(
                114,
                "TgRepInfo_Game",
                "r_fMissionTime",
                NetPropertyType::Float,
                1,
            ),
            prop(
                115,
                "TgRepInfo_Game",
                "r_nMissionTimerStateChange",
                NetPropertyType::Int,
                1,
            ),
            prop(
                116,
                "TgRepInfo_Game",
                "r_fMissionRemainingTime",
                NetPropertyType::Float,
                1,
            ),
            prop(
                134,
                "TgRepInfo_Game",
                "r_bEnableHeadshots",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                142,
                "TgRepInfo_Game",
                "r_bAllowWeaponLagPrediction",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                143,
                "TgRepInfo_Game",
                "r_bUseInstantFireMeshTrace",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                173,
                "TgRepInfo_Game",
                "r_bDisablePlayerMovement",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                176,
                "TgRepInfo_Game",
                "r_bLoadoutSelectionEnabled",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                178,
                "TgRepInfo_Game",
                "r_bCanPurchaseMasterRiding",
                NetPropertyType::Bool,
                1,
            ),
            prop(
                192,
                "TgRepInfo_Game",
                "r_eGameTimerState",
                NetPropertyType::Byte {
                    enum_count: Some(10),
                },
                1,
            ),
            prop(
                193,
                "TgRepInfo_Game",
                "r_nMissionTimerState",
                NetPropertyType::Byte {
                    enum_count: Some(4),
                },
                1,
            ),
            prop(
                194,
                "TgRepInfo_Game",
                "r_eTalentsEnabled",
                NetPropertyType::Byte {
                    enum_count: Some(4),
                },
                1,
            ),
            prop(
                196,
                "TgRepInfo_Game",
                "r_GameType",
                NetPropertyType::Byte {
                    enum_count: Some(50),
                },
                1,
            ),
        ])
        .unwrap()
}

fn to_wire_bunch(tb: &TraceBunch) -> Bunch {
    Bunch::with_bits(
        BunchHeader {
            ch_index: tb.ch_index,
            ch_type: Ue3ChannelType::from_u8(tb.ch_type).expect("valid channel type"),
            flags: BunchFlags {
                b_open: tb.b_open,
                b_close: tb.b_close,
                b_reliable: tb.b_reliable,
                b_partial: false,
            },
            ch_sequence: tb.ch_sequence,
        },
        tb.num_bits,
        decode_hex(&tb.data_hex),
    )
}

#[test]
fn test_live_retail_oracle_trace_parity() {
    let path = Path::new(TRACE_PATH);
    if !path.exists() {
        eprintln!(
            "Skipping test_live_retail_oracle_trace_parity: {} not found on disk",
            TRACE_PATH
        );
        return;
    }

    let raw = std::fs::read_to_string(path).expect("read oracle_probe_trace.json");
    let trace: TraceRoot = serde_json::from_str(&raw).expect("parse oracle_probe_trace.json");

    let mut ch0_count = 0usize;
    let mut saw_download_mgr = false;
    let mut saw_uses_opt = false;
    let mut saw_uses_opt_ex = false;
    let mut saw_have = false;

    for ev in &trace.events {
        let Some(ref dec) = ev.decoded else { continue };
        for tb in &dec.bunches {
            if tb.ch_index != 0 {
                continue;
            }
            let raw_bytes = decode_hex(&tb.data_hex);
            let msgs = ControlMessage::decode_all(&raw_bytes, tb.num_bits).unwrap_or_else(|e| {
                panic!("ch=0 decode_all failed ({} bits): {:?}", tb.num_bits, e)
            });
            let mut re_writer = immortal_net::BitWriter::new();
            for m in &msgs {
                match m {
                    ControlMessage::DownloadMgr { .. } => saw_download_mgr = true,
                    ControlMessage::UsesOpt { .. } => saw_uses_opt = true,
                    ControlMessage::UsesOptEx { .. } => saw_uses_opt_ex = true,
                    ControlMessage::Have { .. } => saw_have = true,
                    _ => {}
                }
                m.encode_into(&mut re_writer).unwrap();
            }
            assert_eq!(re_writer.num_bits(), tb.num_bits);
            assert_eq!(re_writer.into_bytes(), raw_bytes);
            ch0_count += 1;
        }
    }
    assert!(ch0_count > 0);
    assert!(saw_download_mgr && saw_uses_opt && saw_uses_opt_ex && saw_have);

    let pc_cache = schema_tg_player_controller();
    let fernando_cache = schema_tg_pawn_fernando();
    let matinee_cache = schema_matinee_actor();
    let pri_cache = schema_tg_rep_info_player();
    let gri_cache = schema_tg_rep_info_game();

    let mut ch3_open_verified = false;
    let mut ch3_41bit_updates = 0usize;
    let mut ch4_open_verified = false;
    let mut ch5_open_verified = false;
    let mut ch80_open_verified = false;
    let mut ch81_open_verified = false;

    for ev in &trace.events {
        let Some(ref dec) = ev.decoded else { continue };
        for tb in &dec.bunches {
            let (cache, layout) = match tb.ch_index {
                3 => (
                    &pc_cache,
                    ActorSpawnLayout {
                        has_location: true,
                        has_rotation: false,
                        is_player_controller: true,
                    },
                ),
                4 => (
                    &fernando_cache,
                    ActorSpawnLayout {
                        has_location: true,
                        has_rotation: false,
                        is_player_controller: false,
                    },
                ),
                5 => (
                    &matinee_cache,
                    ActorSpawnLayout {
                        has_location: true,
                        has_rotation: false,
                        is_player_controller: false,
                    },
                ),
                80 => (
                    &pri_cache,
                    ActorSpawnLayout {
                        has_location: true,
                        has_rotation: false,
                        is_player_controller: false,
                    },
                ),
                81 => (
                    &gri_cache,
                    ActorSpawnLayout {
                        has_location: true,
                        has_rotation: false,
                        is_player_controller: false,
                    },
                ),
                _ => continue,
            };

            let bunch = to_wire_bunch(tb);
            let decoded = ActorBunchCodec::decode_bunch(&bunch, cache, Some(layout))
                .unwrap_or_else(|e| {
                    panic!(
                        "ActorBunchCodec decode failed on ch={} open={} bits={}: {:?}",
                        tb.ch_index, tb.b_open, tb.num_bits, e
                    )
                });
            let reencoded = ActorBunchCodec::encode_to_bunch(
                tb.ch_index,
                tb.ch_sequence,
                tb.b_reliable,
                cache,
                &decoded,
            )
            .unwrap();
            assert_eq!(
                reencoded.num_bits, bunch.num_bits,
                "bit length mismatch on ch={} open={}",
                tb.ch_index, tb.b_open
            );
            assert_eq!(
                reencoded.data, bunch.data,
                "bit-exact re-encode mismatch on ch={} open={} bits={}",
                tb.ch_index, tb.b_open, tb.num_bits
            );

            if tb.ch_index == 3 && tb.b_open {
                assert_eq!(tb.num_bits, 3203);
                let hdr = decoded.open_header.as_ref().unwrap();
                assert_eq!(hdr.location, Some([-224.0, 0.0, 203.0]));
                assert_eq!(hdr.net_player_index, Some(0));
                ch3_open_verified = true;
            } else if tb.ch_index == 3 && !tb.b_open && tb.num_bits == 41 {
                assert_eq!(decoded.items.len(), 1);
                match &decoded.items[0] {
                    ReplicatedItem::Property {
                        rep_index: 291,
                        name,
                        value: NetValue::Float(ts),
                        ..
                    } => {
                        assert_eq!(name, "r_fServerTimeStamp");
                        assert!(*ts > 180.0);
                    }
                    other => panic!("Unexpected 41-bit ch=3 item: {:?}", other),
                }
                ch3_41bit_updates += 1;
            } else if tb.ch_index == 4 && tb.b_open {
                assert_eq!(tb.num_bits, 2413);
                let health = decoded.items.iter().find_map(|it| match it {
                    ReplicatedItem::Property {
                        name,
                        value: NetValue::Int(v),
                        ..
                    } if name == "Health" => Some(*v),
                    _ => None,
                });
                assert_eq!(health, Some(4600));
                ch4_open_verified = true;
            } else if tb.ch_index == 5 && tb.b_open {
                assert_eq!(tb.num_bits, 160);
                ch5_open_verified = true;
            } else if tb.ch_index == 80 && tb.b_open {
                assert_eq!(tb.num_bits, 318);
                let pname = decoded.items.iter().find_map(|it| match it {
                    ReplicatedItem::Property {
                        name,
                        value: NetValue::Str(s),
                        ..
                    } if name == "PlayerName" => Some(s.as_str()),
                    _ => None,
                });
                assert_eq!(pname, Some("Player"));
                ch80_open_verified = true;
            } else if tb.ch_index == 81 && tb.b_open {
                assert_eq!(tb.num_bits, 1224);
                let gtype = decoded.items.iter().find_map(|it| match it {
                    ReplicatedItem::Property {
                        name,
                        value: NetValue::Enum(v),
                        ..
                    } if name == "r_GameType" => Some(*v),
                    _ => None,
                });
                assert_eq!(gtype, Some(7));
                ch81_open_verified = true;
            }
        }
    }

    assert!(ch3_open_verified);
    assert!(ch3_41bit_updates > 0);
    assert!(ch4_open_verified);
    assert!(ch5_open_verified);
    assert!(ch80_open_verified);
    assert!(ch81_open_verified);
}
