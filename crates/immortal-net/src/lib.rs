// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net
//! Cleanroom Unreal Engine 3 bit-packed bunch protocol parser, control channel state
//! machine, and MCTS auth gateway protocol definitions.

pub mod bitstream;
pub mod bunch;
pub mod error;
pub mod framing;
pub mod gateway;
pub mod marshal;
pub mod mcts_handshake;
pub mod udp_framing;

pub use bitstream::{
    strip_stop_bit, ue3_handshake_crc, ue3_str_crc, BitReader, BitWriter, HANDSHAKE_CRC_SALT,
    MAX_FSTRING_LEN, UE3_CRC32_POLY,
};
pub type FBitWriter = BitWriter;
pub type FBitReader<'a> = BitReader<'a>;

pub use bunch::{
    Bunch, BunchFlags, BunchHeader, ControlChannelHandshake, ControlMessage, DedicatedControlFrame,
    FInBunch, HandshakePhase, Ue3ChannelType, Ue3Packet, ACTOR_CHANNEL_INDEX, CHTYPE_MAX, CONTROL_CHANNEL_INDEX,
    DEDICATED_PREFIX_LEN, DEFAULT_ENGINE_MIN_NET_VERSION, DEFAULT_ENGINE_NET_VERSION, DEFAULT_GAME_CLASS,
    DEFAULT_HANDSHAKE_CHALLENGE, DEFAULT_MAX_PACKET, DEFAULT_MAX_PACKET_BITS, DEFAULT_NET_SPEED,
    DEFAULT_SHOOTING_RANGE_LEVEL, DEFAULT_SHOOTING_RANGE_MAP, EXUDP_MAX_PACKET_BITS,
    MARSHAL_CHANNEL_INDEX, MAX_ALLOWED_PACKET_BITS, MAX_CHANNELS, MAX_CHSEQUENCE, MAX_PACKETID, NMT_ACTOR_CHANNEL_FAILURE,
    NMT_CHALLENGE, NMT_CLIENT_AUTH_REQUEST, NMT_FAILURE, NMT_HANDSHAKE_CHALLENGE,
    NMT_HANDSHAKE_COMPLETE, NMT_HANDSHAKE_RESPONSE, NMT_HANDSHAKE_START, NMT_HAVE, NMT_HELLO,
    NMT_JOIN, NMT_JOIN_SPLIT, NMT_LOGIN, NMT_MAP_LOADED, NMT_NETSPEED, NMT_REDIRECT,
    NMT_SERVER_AUTH_REQUEST, NMT_UPGRADE, NMT_USES, NMT_WELCOME, PCOM_PREFIX_LEN, PcomPrefix,
    SESSION_TOKEN_LEN, SUBFLAG_SEQUENCED, SUBFLAG_UNSEQUENCED, VOICE_CHANNEL_INDEX,
};
pub use error::{NetError, PcomError};
pub use framing::{CPackFrame, MagicToken, HEADER_LEN, MAX_PAYLOAD_LEN};
pub use gateway::{AuthGateway, AuthGatewayConfig, AuthGatewayHandle};
pub use marshal::{
    create_default_inventory, CMarshalMessage, ChampionRosterEntry, DeckEntry, DeviceEntry,
    FieldValue, InventoryResponse, LoginRequest, LoginResponse, MarshalField, MatchTicket,
    CHAMPION_CASSIE, CHAMPION_FERNANDO, CHAMPION_VIKTOR, DECK_FERNANDO_STARTER,
    DEVICE_FERNANDO_FLAME_LANCE, FUNCTION_ID_ON_LOGIN_RESPONSE, FUNCTION_ID_SEND_LOGIN,
    TOKEN_ACCOUNT_ID, TOKEN_CHAMPION_ROSTER, TOKEN_DECK_LOADOUTS, TOKEN_MATCH_TICKET,
    TOKEN_SESSION_TOKEN, TOKEN_STATUS, TOKEN_WEAPON_DEVICES,
};
#[allow(deprecated)]
pub use mcts_handshake::{
    create_mcts_champion_roster_frame, create_mcts_change_map_frame,
    create_mcts_launch_map_instance_frame, create_mcts_login_response_frame,
    create_mcts_map_transition_frame, create_mcts_match_composition_frame,
    create_mcts_match_invitation_frame, create_mcts_match_status_frame,
    create_mcts_match_status_with_members_frame,
    create_mcts_match_status_with_queue_and_members_frame, create_mcts_on_match_invite_frame,
    create_mcts_player_svc_change_map_frame, create_mcts_queue_definition_frame,
    create_mcts_queue_state_update_frame, create_mcts_queue_status_frame, BOT_ID_FERNANDO,
    BOT_ID_VIKTOR, CHUNK1_HANDSHAKE, CHUNK2_ACK, CHUNK3_SESSION, MAP_GAME_ID_SHOOTING_RANGE,
    MAP_INSTANCE_ID_SHOOTING_RANGE, MCTS_CHAMPION_SELECT_ACK_FRAME, MCTS_CLIENT_AUTH_REQUEST_FLAGS,
    MCTS_CLIENT_AUTH_REQUEST_LEN, MCTS_CLIENT_CRYPTO_TICKET_FLAGS, MCTS_CLIENT_CRYPTO_TICKET_LEN,
    MCTS_FUNCTION_ID_CHAMPION_ROSTER, MCTS_FUNCTION_ID_CHANGE_MAP,
    MCTS_FUNCTION_ID_MAP_INSTANCE_ASSIGNED, MCTS_FUNCTION_ID_MAP_TRANSITION,
    MCTS_FUNCTION_ID_MATCH_INVITATION, MCTS_FUNCTION_ID_MATCH_STATUS,
    MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE, MCTS_FUNCTION_ID_ON_MATCH_INVITE,
    MCTS_FUNCTION_ID_ON_MATCH_STATUS, MCTS_FUNCTION_ID_PLAYER_SVC_CHANGE_MAP,
    MCTS_FUNCTION_ID_PLAYER_SVC_CHANGE_MAP_BE, MCTS_FUNCTION_ID_PLAYER_SVC_CHANGE_MAP_LE,
    MCTS_FUNCTION_ID_PLAYER_SVC_LAUNCH_MAP_INSTANCE, MCTS_FUNCTION_ID_QUERY_SERVERS,
    MCTS_FUNCTION_ID_QUEUE_STATE_UPDATE, MCTS_FUNCTION_ID_QUEUE_STATUS,
    MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP, MCTS_FUNCTION_ID_TERMINATE_SESSION, MCTS_HANDSHAKE_CHUNK1,
    MCTS_HANDSHAKE_CHUNK2_ACK, MCTS_HANDSHAKE_CHUNK3_SESSION, MCTS_HELLO_RESPONSE_FRAME,
    MCTS_HELLO_RESPONSE_PAYLOAD, MCTS_TOKEN_ACCOUNT_ID, MCTS_TOKEN_BOT_ID,
    MCTS_TOKEN_CHAMPION_ROSTER, MCTS_TOKEN_COMPEL_FLAG, MCTS_TOKEN_INVITED_MEMBERS,
    MCTS_TOKEN_INVITE_PRIVILEGES, MCTS_TOKEN_LAUNCH_SECONDS, MCTS_TOKEN_MAP_GAME_ID,
    MCTS_TOKEN_MAP_HOST_NET_ADDR, MCTS_TOKEN_MAP_INSTANCE_ID, MCTS_TOKEN_MATCH_COMPOSITION,
    MCTS_TOKEN_MATCH_ID, MCTS_TOKEN_MATCH_LOBBY_STATE, MCTS_TOKEN_MATCH_QUEUE_ID,
    MCTS_TOKEN_MEMBERS, MCTS_TOKEN_PLAYER_ID, MCTS_TOKEN_PLAYER_LOBBY_STATE,
    MCTS_TOKEN_PLAYER_QUEUE_STATE, MCTS_TOKEN_PORTAL_SESSION_ID, MCTS_TOKEN_POSITION,
    MCTS_TOKEN_PROFILE_ID, MCTS_TOKEN_QUEUE_ACTIVE, MCTS_TOKEN_QUEUE_CATEGORY,
    MCTS_TOKEN_QUEUE_STATE, MCTS_TOKEN_QUEUE_STATUS, MCTS_TOKEN_STATUS_CODE, MCTS_TOKEN_TASK_FORCE,
    MCTS_TOKEN_TIMEOUT_WARNING, MCTS_TOKEN_TIMESTAMP, MCTS_WIRE_FLAG_CHUNK,
};
pub use udp_framing::{
    current_time_millis, hmac_sha256, parse_cpack_udp, sha256, CPackUdpPacket, HelloRecvReply,
    HelloSend, PingRecv, PingSend, CPACK_OP_BUNCH, CPACK_OP_HELLO_REPLY, CPACK_OP_HELLO_SEND,
    CPACK_OP_PING_RECV, CPACK_OP_PING_SEND, DEFAULT_HMAC_KEY, HELLO_FULL_LEN, HELLO_HMAC_OFFSET,
    HELLO_MIN_LEN, HELLO_PAYLOAD_LEN, HELLO_PAYLOAD_OFFSET, NEGOTIATED_MTU,
};

pub const DEFAULT_GAME_PORT: u16 = 7777;
pub const DEFAULT_AUTH_PORT: u16 = 9000;

/// Unified 1-based UE3 channel type (`CHTYPE_Control = 1..=5`).
pub type ChannelType = Ue3ChannelType;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports() {
        assert_eq!(DEFAULT_GAME_PORT, 7777);
        assert_eq!(DEFAULT_AUTH_PORT, 9000);
    }
}
