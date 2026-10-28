// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Server Library
//! Cleanroom game server implementation, UE3 Channel 0 bunch handshake engine,
//! and Fernando pawn actor replication.

pub mod game_server;
pub mod replication;

pub use game_server::{
    wrap_pcom_ack, wrap_pcom_packet, ClientSession, GameServer, GameServerConfig, GameServerHandle,
    SessionPhase,
};
pub use replication::{
    PawnActor, PlayerControllerActor, ReplicationPayload, ReplicationSession, Rotator, Vector3,
    DEVICE_FERNANDO_FLAME_LANCE, FERNANDO_BASE_HEALTH, FERNANDO_CHAMPION_ID, FERNANDO_DEFAULT_TEAM,
    FERNANDO_PAWN_CLASS, FERNANDO_SPAWN_X, FERNANDO_SPAWN_Y, FERNANDO_SPAWN_Z,
    REP_OP_DESTROY_ACTOR, REP_OP_OPEN_CHANNEL, REP_OP_SPAWN_ACTOR, REP_OP_UPDATE_TRANSFORM,
};
