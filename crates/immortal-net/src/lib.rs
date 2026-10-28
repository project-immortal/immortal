// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net
//! Cleanroom Unreal Engine 3 bit-packed bunch protocol parser, control channel state
//! machine, and MCTS auth gateway protocol definitions.

pub mod bunch;
pub mod error;
pub mod framing;
pub mod gateway;
pub mod marshal;
pub mod udp_framing;

pub use bunch::{
    Bunch, BunchFlags, BunchHeader, ControlChannelHandshake, ControlMessage, HandshakePhase,
    Ue3ChannelType, ACTOR_CHANNEL_INDEX, CONTROL_CHANNEL_INDEX, DEFAULT_GAME_CLASS,
    DEFAULT_NET_SPEED, DEFAULT_SHOOTING_RANGE_MAP, NMT_CHALLENGE, NMT_FAILURE, NMT_HELLO,
    NMT_NET_SPEED, NMT_UPGRADE, NMT_WELCOME,
};
pub use error::NetError;
pub use framing::{CPackFrame, MagicToken, HEADER_LEN, MAX_PAYLOAD_LEN};
pub use gateway::{AuthGateway, AuthGatewayConfig, AuthGatewayHandle};
pub use marshal::{
    CMarshalMessage, ChampionRoster, DeckLoadoutEntry, DeckLoadouts, FieldValue, LoginRequest,
    LoginResponse, MarshalField, MatchTicket, WeaponDeviceEntry, WeaponDevices, CHAMPION_CASSIE,
    CHAMPION_FERNANDO, CHAMPION_VIKTOR, DECK_FERNANDO_STARTER, DEVICE_FERNANDO_FLAME_LANCE,
    FUNCTION_ID_ON_LOGIN_RESPONSE, FUNCTION_ID_SEND_LOGIN, TOKEN_ACCOUNT_ID, TOKEN_CHAMPION_ROSTER,
    TOKEN_DECK_LOADOUTS, TOKEN_MATCH_TICKET, TOKEN_SESSION_TOKEN, TOKEN_STATUS,
    TOKEN_WEAPON_DEVICES,
};
pub use udp_framing::{
    current_time_millis, hmac_sha256, parse_cpack_udp, sha256, CPackUdpPacket, HelloRecvReply,
    HelloSend, PingRecv, PingSend, CPACK_OP_BUNCH, CPACK_OP_HELLO_REPLY, CPACK_OP_HELLO_SEND,
    CPACK_OP_PING_RECV, CPACK_OP_PING_SEND, DEFAULT_HMAC_KEY, HELLO_FULL_LEN, HELLO_HMAC_OFFSET,
    HELLO_MIN_LEN, HELLO_PAYLOAD_LEN, HELLO_PAYLOAD_OFFSET, NEGOTIATED_MTU,
};

pub const DEFAULT_GAME_PORT: u16 = 7777;
pub const DEFAULT_AUTH_PORT: u16 = 9000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelType {
    Control = 0,
    Actor = 1,
    File = 2,
    Voice = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports() {
        assert_eq!(DEFAULT_GAME_PORT, 7777);
        assert_eq!(DEFAULT_AUTH_PORT, 9000);
    }
}
