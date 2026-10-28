// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Actor Replication & Fernando Pawn Spawning
//! Cleanroom implementation of Unreal Engine 3 Actor Channel 2 replication,
//! Fernando (`TgPawn_Knight`, `ChampionId::Fernando = 1026`) pawn lifecycle,
//! and spatial position/rotation delta streaming in the Shooting Range.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use immortal_core::ChampionId;
use immortal_net::{Bunch, ACTOR_CHANNEL_INDEX};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};

pub const FERNANDO_CHAMPION_ID: u32 = 1026;
pub const FERNANDO_PAWN_CLASS: &str = "TgPawn_Knight";
pub const FERNANDO_SPAWN_X: f32 = 0.0;
pub const FERNANDO_SPAWN_Y: f32 = 0.0;
pub const FERNANDO_SPAWN_Z: f32 = 100.0;
pub const FERNANDO_BASE_HEALTH: f32 = 4600.0;

// Replication Message Sub-Opcodes
pub const REP_OP_OPEN_CHANNEL: u8 = 0x01;
pub const REP_OP_SPAWN_ACTOR: u8 = 0x02;
pub const REP_OP_UPDATE_TRANSFORM: u8 = 0x03;
pub const REP_OP_DESTROY_ACTOR: u8 = 0x04;

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

/// PlayerController actor replicated across Channel 2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlayerControllerActor {
    pub actor_id: u32,
    pub channel_index: u32,
    pub pawn_actor_id: u32,
    pub view_rotation: Rotator,
}

impl Default for PlayerControllerActor {
    fn default() -> Self {
        Self {
            actor_id: 10,
            channel_index: ACTOR_CHANNEL_INDEX,
            pawn_actor_id: 100,
            view_rotation: Rotator::default(),
        }
    }
}

/// Fernando Pawn Actor definition and replicated properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PawnActor {
    pub actor_id: u32,
    pub class_name: String,
    pub champion_id: ChampionId,
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
    pub channel_opened: bool,
    pub pawn_spawned: bool,
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
            channel_opened: false,
            pawn_spawned: false,
            actor_sequence: 0,
        }
    }

    /// Generates a bunch that opens Actor Channel 2 for `PlayerController`.
    /// Opens with `ch_sequence = 0` when `b_open = true`.
    pub fn open_channel_2(&mut self) -> Bunch {
        self.channel_opened = true;
        let mut data = Vec::new();
        data.push(REP_OP_OPEN_CHANNEL);
        data.write_u32::<LittleEndian>(self.controller.actor_id)
            .unwrap();
        data.write_u32::<LittleEndian>(self.controller.channel_index)
            .unwrap();

        let bunch = Bunch::actor(self.actor_sequence, true, data);
        self.actor_sequence += 1;
        bunch
    }

    /// Spawns and replicates Fernando pawn (`TgPawn_Knight`, `ChampionId::Fernando = 1026`)
    /// at spawn coordinates `(0.0, 0.0, 100.0)`.
    pub fn spawn_fernando(&mut self) -> Bunch {
        self.pawn_spawned = true;
        let mut data = Vec::new();
        data.push(REP_OP_SPAWN_ACTOR);
        data.write_u32::<LittleEndian>(self.pawn.actor_id).unwrap();
        data.write_u32::<LittleEndian>(self.pawn.champion_id as u32)
            .unwrap();

        let class_bytes = self.pawn.class_name.as_bytes();
        data.write_u16::<LittleEndian>(class_bytes.len() as u16)
            .unwrap();
        data.extend_from_slice(class_bytes);

        self.pawn.location.write_bytes(&mut data).unwrap();
        self.pawn.rotation.write_bytes(&mut data).unwrap();
        data.write_f32::<LittleEndian>(self.pawn.health).unwrap();
        data.write_f32::<LittleEndian>(self.pawn.max_health)
            .unwrap();

        let bunch = Bunch::actor(self.actor_sequence, false, data);
        self.actor_sequence += 1;
        bunch
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

        let mut data = Vec::new();
        data.push(REP_OP_UPDATE_TRANSFORM);
        data.write_u32::<LittleEndian>(self.pawn.actor_id).unwrap();
        self.pawn.location.write_bytes(&mut data).unwrap();
        self.pawn.rotation.write_bytes(&mut data).unwrap();
        self.pawn.velocity.write_bytes(&mut data).unwrap();

        let bunch = Bunch::actor(self.actor_sequence, false, data);
        self.actor_sequence += 1;
        bunch
    }

    /// Streams baseline actor position/rotation delta so client can walk around Shooting Range.
    pub fn stream_baseline_delta(&mut self, _dt_seconds: f32) -> Bunch {
        let mut data = Vec::new();
        data.push(REP_OP_UPDATE_TRANSFORM);
        data.write_u32::<LittleEndian>(self.pawn.actor_id).unwrap();
        self.pawn.location.write_bytes(&mut data).unwrap();
        self.pawn.rotation.write_bytes(&mut data).unwrap();
        self.pawn.velocity.write_bytes(&mut data).unwrap();

        let bunch = Bunch::actor(self.actor_sequence, false, data);
        self.actor_sequence += 1;
        bunch
    }
}

/// Parsed replication payload from Actor Channel 2.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationPayload {
    OpenChannel {
        actor_id: u32,
        channel_index: u32,
    },
    SpawnActor {
        actor_id: u32,
        champion_id: ChampionId,
        class_name: String,
        location: Vector3,
        rotation: Rotator,
        health: f32,
        max_health: f32,
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
            REP_OP_SPAWN_ACTOR => {
                let actor_id = cursor.read_u32::<LittleEndian>()?;
                let champ_raw = cursor.read_u32::<LittleEndian>()?;
                let champ_id = ChampionId::from_id(champ_raw);

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
                    class_name,
                    location,
                    rotation,
                    health,
                    max_health,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fernando_spawn_constants() {
        assert_eq!(FERNANDO_CHAMPION_ID, 1026);
        assert_eq!(FERNANDO_PAWN_CLASS, "TgPawn_Knight");
        assert_eq!(FERNANDO_SPAWN_X, 0.0);
        assert_eq!(FERNANDO_SPAWN_Y, 0.0);
        assert_eq!(FERNANDO_SPAWN_Z, 100.0);
    }

    #[test]
    fn test_open_channel_2_bunch() {
        let mut session = ReplicationSession::new();
        assert!(!session.channel_opened);

        let bunch = session.open_channel_2();
        assert!(session.channel_opened);
        assert_eq!(bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert!(bunch.header.flags.b_open);

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
    fn test_spawn_fernando_bunch() {
        let mut session = ReplicationSession::new();
        let _ = session.open_channel_2();
        let spawn_bunch = session.spawn_fernando();

        assert!(session.pawn_spawned);
        assert_eq!(spawn_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);

        let parsed = ReplicationPayload::decode(&spawn_bunch.data).unwrap();
        match parsed {
            ReplicationPayload::SpawnActor {
                actor_id,
                champion_id,
                class_name,
                location,
                health,
                ..
            } => {
                assert_eq!(actor_id, 100);
                assert_eq!(champion_id, ChampionId::Fernando);
                assert_eq!(class_name, "TgPawn_Knight");
                assert_eq!(location.x, 0.0);
                assert_eq!(location.y, 0.0);
                assert_eq!(location.z, 100.0);
                assert_eq!(health, 4600.0);
            }
            other => panic!("Expected SpawnActor, got {:?}", other),
        }
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
}
