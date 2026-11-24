// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Server Library
//! Cleanroom game server implementation, UE3 Channel 0 bunch handshake engine,
//! server-authoritative combat/physics foundations (`ADOPT-02`, `ADOPT-03`),
//! and Fernando pawn actor replication.

pub mod combat;
pub mod game_server;
pub mod physics;
pub mod replication;

pub use combat::{
    apply_immortal_aura_clamp, evaluate_charge_sweep, evaluate_fireball_sweep,
    evaluate_flame_lance_cone, fireball_pierce_damage, normalize_head_to_cylinder,
    ChargeSweepResult, CylinderHitbox, HeadHitbox, HitResult, ShieldBarrier,
    ShieldInterceptResult, TargetHitbox, CHARGE_DAMAGE, CHARGE_SPEED_UU_PER_SEC,
    FIREBALL_PIERCE_BONUS_RATIO, FIREBALL_RADIUS_UU, FIREBALL_VELOCITY_UU_PER_SEC,
    FLAME_LANCE_HALF_ANGLE_DEG, FLAME_LANCE_RANGE_UU, FLAME_LANCE_TICK_DAMAGE,
    FLAME_LANCE_TICK_INTERVAL_SEC, HEAD_BONE_NAME, IMMORTAL_AURA_RADIUS_UU,
    IMMORTAL_DURATION_SEC, IMMORTAL_MIN_HEALTH_FLOOR, SHIELD_HEIGHT_UU, SHIELD_MAX_HP,
    SHIELD_WIDTH_UU,
};
pub use game_server::{
    ClientSession, GameServer, GameServerConfig, GameServerHandle, SessionConfig, SessionPhase,
    DEFAULT_PALADINS_UPK_DIR, ENV_IMMORTAL_UPK_DIR, MAX_SESSIONS,
};
pub use physics::{
    evaluate_surface_interaction, resolve_surface_velocity, SurfaceInteraction,
    STEEP_SURFACE_COS_45, VERTICAL_WALL_NORMAL_Z_EPS,
};
pub use replication::{
    ActorArchetypeRefs, ActorReplicationSchemas, BotActor, DeviceActor, PawnActor,
    PlayerControllerActor, ReplicationPayload, ReplicationSession, Rotator, Vector3,
    ARCHWAY_FERNANDO_SPAWN_X, ARCHWAY_FERNANDO_SPAWN_Y, ARCHWAY_FERNANDO_SPAWN_Z,
    ARCHWAY_FERNANDO_YAW, BOT_PRI_CHANNEL_INDEX, DEFAULT_PLAYER_CREDITS, DEFAULT_PLAYER_ID,
    DEFAULT_PLAYER_NAME, DEVICE_FERNANDO_FLAME_LANCE, EVIE_DEFAULT_TEAM, FERNANDO_BASE_HEALTH,
    FERNANDO_CHAMPION_ID, FERNANDO_DEFAULT_TEAM, FERNANDO_PAWN_CLASS, FERNANDO_SPAWN_X,
    FERNANDO_SPAWN_Y, FERNANDO_SPAWN_Z, GRI_CHANNEL_INDEX, PHYS_WALKING,
    PLAYER_CONTROLLER_CHANNEL_INDEX, PLAYER_PAWN_CHANNEL_INDEX, PRI_CHANNEL_INDEX,
    REP_INFO_GAME_CLASS, REP_INFO_PLAYER_CLASS, REP_INFO_TASK_FORCE_CLASS, REP_OP_DESTROY_ACTOR,
    REP_OP_OPEN_CHANNEL, REP_OP_SPAWN_ACTOR, REP_OP_UPDATE_TRANSFORM, ROLE_AUTONOMOUS_PROXY,
    STATE_NAME_SPECTATING, TASK_FORCE_CHANNEL_INDEX, TG_GAME_TYPE_SHOOTING_RANGE,
};
