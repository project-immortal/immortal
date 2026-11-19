// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Actor Replication & Fernando Pawn Spawning
//! Cleanroom implementation of Unreal Engine 3 Actor Channel (`ACTOR_CHANNEL_INDEX = 3`)
//! replication, Fernando (`TgPawn_Fernando`, `ChampionId::Fernando = 1026`) pawn lifecycle,
//! and spatial position/rotation delta streaming in the Shooting Range.
//! Note: Post-`NMT_Join` bit-packed Actor Channel emission over `PComNetConn` UDP 7777 is
//! deferred until `UNK-UDP-004` completes REA verification of `UActorChannel::ReceivedBunch`.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use immortal_core::ChampionId;
pub use immortal_net::{FBitReader, FBitWriter, FInBunch};
use immortal_net::{
    BitReader, BitWriter, Bunch, BunchFlags, BunchHeader, NetError, Ue3ChannelType,
    ACTOR_CHANNEL_INDEX, MAX_CHSEQUENCE,
};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};

pub const FERNANDO_CHAMPION_ID: u32 = 1026;
pub const FERNANDO_PAWN_CLASS: &str = "TgPawn_Fernando";
pub const FERNANDO_SPAWN_X: f32 = 0.0;
pub const FERNANDO_SPAWN_Y: f32 = 0.0;
pub const FERNANDO_SPAWN_Z: f32 = 100.0;
pub const FERNANDO_BASE_HEALTH: f32 = 4600.0;
pub const DEVICE_FERNANDO_FLAME_LANCE: u32 = 10774;
pub const FERNANDO_DEFAULT_TEAM: u8 = 1;

pub const EVIE_CHAMPION_ID: u32 = 1030;
pub const EVIE_PAWN_CLASS: &str = "TgPawn_Evie";
pub const EVIE_BOT_CLASS: &str = "TgBot_Evie";
pub const EVIE_SPAWN_X: f32 = 500.0;
pub const EVIE_SPAWN_Y: f32 = 500.0;
pub const EVIE_SPAWN_Z: f32 = 100.0;
pub const EVIE_BASE_HEALTH: f32 = 1800.0;
pub const EVIE_DEFAULT_TEAM: u8 = 2;

pub const PLAYER_CONTROLLER_CLASS: &str = "TgPlayerController";
pub const LOCAL_PLAYER_NAME: &str = "TgLocalPlayer_0";
pub const CONTROLLER_NAME: &str = "TgPlayerController_1";
pub const DEVICE_FERNANDO_INHAND: &str = "TgDevice_FernandoInhand_0";
pub const BOT_EVIE_NAME: &str = "TgBot_Evie_0";
pub const PAWN_EVIE_NAME: &str = "TgPawn_Evie_0";
pub const PAWN_FERNANDO_NAME: &str = "TgPawn_Fernando_0";

// Replication Message Sub-Opcodes
pub const REP_OP_OPEN_CHANNEL: u8 = 0x01;
pub const REP_OP_SPAWN_ACTOR: u8 = 0x02;
pub const REP_OP_UPDATE_TRANSFORM: u8 = 0x03;
pub const REP_OP_DESTROY_ACTOR: u8 = 0x04;
pub const REP_OP_POSSESS: u8 = 0x05;
pub const REP_OP_SPAWN_DEVICE: u8 = 0x06;
pub const REP_OP_SPAWN_BOT: u8 = 0x07;

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
    pub channel_opened: bool,
    pub player_possessed: bool,
    pub pawn_spawned: bool,
    pub weapon_spawned: bool,
    pub bot_spawned: bool,
    pub actor_sequence: u32,
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
            channel_opened: false,
            player_possessed: false,
            pawn_spawned: false,
            weapon_spawned: false,
            bot_spawned: false,
            actor_sequence: 1,
        }
    }

    /// Allocates the next 10-bit UE3 Actor Channel reliable `ChSequence` modulo `MAX_CHSEQUENCE`.
    pub fn next_actor_seq(&mut self) -> u32 {
        let seq = self.actor_sequence;
        self.actor_sequence = (self.actor_sequence + 1) % MAX_CHSEQUENCE;
        seq
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
    /// with Weapon Device ID 10774 (`DEVICE_FERNANDO_FLAME_LANCE`) and Team 1
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

    /// Replicates bot opponent: `TgBot_Evie_0` / `TgPawn_Evie_0` (on Channel 4 with `bOpen = true`).
    pub fn spawn_bot_opponent(&mut self) -> Bunch {
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
        Bunch::new(
            BunchHeader {
                ch_index: 4,
                ch_type: Ue3ChannelType::Actor,
                flags: BunchFlags {
                    b_open: true,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence: 1,
            },
            data,
        )
    }

    /// Queues all initial replication bunches upon client map loading (`NMT_MapLoaded 0x2A`):
    /// Channel 3 open, controller possession, Fernando pawn spawn, Flame Lance weapon spawn,
    /// Evie bot opponent spawn, and baseline movement transform delta.
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
        assert_eq!(FERNANDO_DEFAULT_TEAM, 1);
        assert_eq!(DEVICE_FERNANDO_INHAND, "TgDevice_FernandoInhand_0");
    }

    #[test]
    fn test_evie_bot_constants() {
        assert_eq!(EVIE_CHAMPION_ID, 1030);
        assert_eq!(EVIE_PAWN_CLASS, "TgPawn_Evie");
        assert_eq!(EVIE_BOT_CLASS, "TgBot_Evie");
        assert_eq!(EVIE_BASE_HEALTH, 1800.0);
        assert_eq!(EVIE_DEFAULT_TEAM, 2);
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
                assert_eq!(team, 1);
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
                assert_eq!(team, 2);
                assert_eq!(location.x, 500.0);
                assert_eq!(health, 1800.0);
            }
            other => panic!("Expected SpawnBot, got {:?}", other),
        }
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
}
