// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Unreal Engine 3 Bit-Packed Bunch Protocol & Channel 0 Handshake
//! Cleanroom implementation of Unreal Engine 3 `UNetConnection` bunch transport,
//! Channel 0 control messages (`NMT_Hello`, `NMT_Welcome`, `NMT_NetSpeed`), and
//! connection handshake state machine for Project Immortal.

use crate::error::NetError;
use crate::udp_framing::CPACK_OP_BUNCH;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

pub const DEFAULT_SHOOTING_RANGE_MAP: &str = "ShootingRange?game=ChaosGame.ChaosGameInfo";
pub const DEFAULT_NET_SPEED: u32 = 24000;
pub const MAX_FSTRING_LEN: usize = 4096;

pub const CONTROL_CHANNEL_INDEX: u32 = 0;
pub const ACTOR_CHANNEL_INDEX: u32 = 2;

// UE3 Control Message Type Opcodes
pub const NMT_HELLO: u8 = 0x00;
pub const NMT_WELCOME: u8 = 0x01;
pub const NMT_UPGRADE: u8 = 0x02;
pub const NMT_NET_SPEED: u8 = 0x03;
pub const NMT_FAILURE: u8 = 0x04;
pub const NMT_CHALLENGE: u8 = 0x05;

/// UE3 Channel Type Indexing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ue3ChannelType {
    Control = 0,
    Actor = 1,
    File = 2,
    Voice = 3,
}

impl Ue3ChannelType {
    pub fn from_u8(val: u8) -> Result<Self, NetError> {
        match val {
            0 => Ok(Self::Control),
            1 => Ok(Self::Actor),
            2 => Ok(Self::File),
            3 => Ok(Self::Voice),
            other => Err(NetError::InvalidUdpPacket(format!(
                "Invalid channel type 0x{:02x}",
                other
            ))),
        }
    }
}

/// Bit-packed header flags for UE3 bunch transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BunchFlags {
    pub b_open: bool,
    pub b_close: bool,
    pub b_reliable: bool,
    pub b_partial: bool,
}

impl BunchFlags {
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.b_open {
            b |= 0x01;
        }
        if self.b_close {
            b |= 0x02;
        }
        if self.b_reliable {
            b |= 0x04;
        }
        if self.b_partial {
            b |= 0x08;
        }
        b
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            b_open: (b & 0x01) != 0,
            b_close: (b & 0x02) != 0,
            b_reliable: (b & 0x04) != 0,
            b_partial: (b & 0x08) != 0,
        }
    }
}

/// Unreal Engine 3 Bunch Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BunchHeader {
    pub ch_index: u32,
    pub ch_type: Ue3ChannelType,
    pub flags: BunchFlags,
    pub ch_sequence: u32,
}

/// Unreal Engine 3 UNetConnection Bunch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bunch {
    pub header: BunchHeader,
    pub data: Vec<u8>,
}

impl Bunch {
    pub fn new(header: BunchHeader, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    /// Helper to create a Channel 0 reliable control bunch.
    pub fn control(ch_sequence: u32, data: Vec<u8>) -> Self {
        Self {
            header: BunchHeader {
                ch_index: CONTROL_CHANNEL_INDEX,
                ch_type: Ue3ChannelType::Control,
                flags: BunchFlags {
                    b_open: ch_sequence == 0,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence,
            },
            data,
        }
    }

    /// Helper to create an Actor Channel (Channel 2) bunch.
    pub fn actor(ch_sequence: u32, b_open: bool, data: Vec<u8>) -> Self {
        Self {
            header: BunchHeader {
                ch_index: ACTOR_CHANNEL_INDEX,
                ch_type: Ue3ChannelType::Actor,
                flags: BunchFlags {
                    b_open,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence,
            },
            data,
        }
    }

    /// Serializes bunch into binary wire format.
    /// Wire layout:
    /// `[ch_index: u32 LE, ch_type: u8, flags: u8, ch_sequence: u32 LE, data_len: u32 LE, data: [u8]]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14 + self.data.len());
        buf.write_u32::<LittleEndian>(self.header.ch_index).unwrap();
        buf.write_u8(self.header.ch_type as u8).unwrap();
        buf.write_u8(self.header.flags.to_byte()).unwrap();
        buf.write_u32::<LittleEndian>(self.header.ch_sequence).unwrap();
        buf.write_u32::<LittleEndian>(self.data.len() as u32).unwrap();
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserializes bunch from wire bytes.
    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 14 {
            return Err(NetError::PacketTooSmall {
                expected: 14,
                actual: data.len(),
            });
        }
        let mut cursor = Cursor::new(data);
        let ch_index = cursor.read_u32::<LittleEndian>()?;
        let ch_type = Ue3ChannelType::from_u8(cursor.read_u8()?)?;
        let flags = BunchFlags::from_byte(cursor.read_u8()?);
        let ch_sequence = cursor.read_u32::<LittleEndian>()?;
        let data_len = cursor.read_u32::<LittleEndian>()? as usize;

        let remaining = data.len() - 14;
        if remaining < data_len {
            return Err(NetError::IncompleteData {
                needed: data_len,
                available: remaining,
            });
        }

        let mut payload = vec![0u8; data_len];
        cursor.read_exact(&mut payload)?;

        Ok(Self {
            header: BunchHeader {
                ch_index,
                ch_type,
                flags,
                ch_sequence,
            },
            data: payload,
        })
    }

    /// Serializes bunch prefixed with CPACK_OP_BUNCH (0x04) for UDP datagram transmission.
    pub fn encode_cpack_udp(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 14 + self.data.len());
        buf.push(CPACK_OP_BUNCH);
        buf.extend_from_slice(&self.encode());
        buf
    }

    /// Deserializes bunch from wire bytes that may optionally include the CPACK_OP_BUNCH (0x04) prefix.
    pub fn decode_cpack_udp(data: &[u8]) -> Result<Self, NetError> {
        if !data.is_empty() && data[0] == CPACK_OP_BUNCH {
            Self::decode(&data[1..])
        } else {
            Self::decode(data)
        }
    }
}

// ============================================================================
// Channel 0 Control Messages
// ============================================================================

/// Cleanroom representation of UE3 Control Channel messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// NMT_Hello (0x00): Ingested from client.
    Hello {
        engine_version: u32,
        licensee_version: u32,
        map_url: String,
    },
    /// NMT_Welcome (0x01): Sent by server specifying level URL.
    Welcome {
        level_url: String,
        game_class: String,
    },
    /// NMT_Upgrade (0x02): Server informs client of upgrade requirement.
    Upgrade {
        engine_version: u32,
    },
    /// NMT_NetSpeed (0x03): Sent by server/client to negotiate transfer rate.
    NetSpeed {
        rate: u32,
    },
    /// NMT_Failure (0x04): Error or disconnect reason.
    Failure {
        reason: String,
    },
}

impl ControlMessage {
    /// Serializes control message into bunch payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Hello {
                engine_version,
                licensee_version,
                map_url,
            } => {
                buf.write_u8(NMT_HELLO).unwrap();
                buf.write_u32::<LittleEndian>(*engine_version).unwrap();
                buf.write_u32::<LittleEndian>(*licensee_version).unwrap();
                write_fstring(&mut buf, map_url);
            }
            Self::Welcome {
                level_url,
                game_class,
            } => {
                buf.write_u8(NMT_WELCOME).unwrap();
                write_fstring(&mut buf, level_url);
                write_fstring(&mut buf, game_class);
            }
            Self::Upgrade { engine_version } => {
                buf.write_u8(NMT_UPGRADE).unwrap();
                buf.write_u32::<LittleEndian>(*engine_version).unwrap();
            }
            Self::NetSpeed { rate } => {
                buf.write_u8(NMT_NET_SPEED).unwrap();
                buf.write_u32::<LittleEndian>(*rate).unwrap();
            }
            Self::Failure { reason } => {
                buf.write_u8(NMT_FAILURE).unwrap();
                write_fstring(&mut buf, reason);
            }
        }
        buf
    }

    /// Deserializes control message from bunch payload bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        if payload.is_empty() {
            return Err(NetError::PacketTooSmall {
                expected: 1,
                actual: 0,
            });
        }

        let mut cursor = Cursor::new(payload);
        let msg_type = cursor.read_u8()?;

        match msg_type {
            NMT_HELLO => {
                if payload.len() < 9 {
                    return Err(NetError::PacketTooSmall {
                        expected: 9,
                        actual: payload.len(),
                    });
                }
                let engine_version = cursor.read_u32::<LittleEndian>()?;
                let licensee_version = cursor.read_u32::<LittleEndian>()?;
                let map_url = read_fstring(&mut cursor)?;
                Ok(Self::Hello {
                    engine_version,
                    licensee_version,
                    map_url,
                })
            }
            NMT_WELCOME => {
                let level_url = read_fstring(&mut cursor)?;
                let game_class = if cursor.position() < payload.len() as u64 {
                    read_fstring(&mut cursor)?
                } else {
                    String::new()
                };
                Ok(Self::Welcome {
                    level_url,
                    game_class,
                })
            }
            NMT_UPGRADE => {
                let engine_version = cursor.read_u32::<LittleEndian>()?;
                Ok(Self::Upgrade { engine_version })
            }
            NMT_NET_SPEED => {
                if payload.len() < 5 {
                    return Err(NetError::PacketTooSmall {
                        expected: 5,
                        actual: payload.len(),
                    });
                }
                let rate = cursor.read_u32::<LittleEndian>()?;
                Ok(Self::NetSpeed { rate })
            }
            NMT_FAILURE => {
                let reason = read_fstring(&mut cursor)?;
                Ok(Self::Failure { reason })
            }
            other => Err(NetError::InvalidUdpPacket(format!(
                "Unknown Control Message opcode 0x{:02x}",
                other
            ))),
        }
    }
}

/// Helper writing length-prefixed ASCII string.
fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    // In UE3, ASCII strings have positive length including null terminator: len + 1
    let len_with_null = (bytes.len() as i32) + 1;
    buf.write_i32::<LittleEndian>(len_with_null).unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0x00);
}

/// Helper reading length-prefixed string from cursor.
pub fn read_fstring<R: Read>(reader: &mut R) -> Result<String, NetError> {
    let raw_len = reader.read_i32::<LittleEndian>()?;
    if raw_len == 0 {
        return Ok(String::new());
    }
    if raw_len > 0 {
        let len = raw_len as usize;
        if len > MAX_FSTRING_LEN {
            return Err(NetError::PayloadTooLarge {
                length: len,
                max: MAX_FSTRING_LEN,
            });
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        // Strip trailing null byte if present
        if buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).map_err(NetError::Utf8)
    } else {
        // UTF-16 Unicode string (negative length)
        let positive_len = raw_len.checked_neg().ok_or_else(|| {
            NetError::InvalidUdpPacket(format!("Integer negation overflow on raw_len {}", raw_len))
        })?;
        let len = positive_len as usize;
        if len > MAX_FSTRING_LEN {
            return Err(NetError::PayloadTooLarge {
                length: len,
                max: MAX_FSTRING_LEN,
            });
        }
        let mut u16_buf = vec![0u16; len];
        for val in u16_buf.iter_mut() {
            *val = reader.read_u16::<LittleEndian>()?;
        }
        if u16_buf.last() == Some(&0) {
            u16_buf.pop();
        }
        String::from_utf16(&u16_buf).map_err(NetError::Utf16)
    }
}

// ============================================================================
// Channel 0 Handshake State Machine
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    AwaitingHello,
    HelloReceived,
    HandshakeCompleted,
}

/// State machine driving the Unreal Engine 3 Channel 0 handshake.
#[derive(Debug, Clone)]
pub struct ControlChannelHandshake {
    pub phase: HandshakePhase,
    pub level_url: String,
    pub net_speed: u32,
    pub client_engine_version: u32,
    pub client_licensee_version: u32,
    pub client_map_url: String,
}

impl Default for ControlChannelHandshake {
    fn default() -> Self {
        Self {
            phase: HandshakePhase::AwaitingHello,
            level_url: DEFAULT_SHOOTING_RANGE_MAP.to_string(),
            net_speed: DEFAULT_NET_SPEED,
            client_engine_version: 0,
            client_licensee_version: 0,
            client_map_url: String::new(),
        }
    }
}

impl ControlChannelHandshake {
    pub fn new(level_url: Option<&str>, net_speed: Option<u32>) -> Self {
        Self {
            phase: HandshakePhase::AwaitingHello,
            level_url: level_url
                .unwrap_or(DEFAULT_SHOOTING_RANGE_MAP)
                .to_string(),
            net_speed: net_speed.unwrap_or(DEFAULT_NET_SPEED),
            client_engine_version: 0,
            client_licensee_version: 0,
            client_map_url: String::new(),
        }
    }

    /// Ingests incoming control message and produces necessary server reply messages.
    /// On `NMT_Hello`, replies with `NMT_NetSpeed` followed by `NMT_Welcome`.
    pub fn handle_control_message(
        &mut self,
        msg: &ControlMessage,
    ) -> Result<Vec<ControlMessage>, NetError> {
        match msg {
            ControlMessage::Hello {
                engine_version,
                licensee_version,
                map_url,
            } => {
                self.client_engine_version = *engine_version;
                self.client_licensee_version = *licensee_version;
                self.client_map_url = map_url.clone();
                self.phase = HandshakePhase::HandshakeCompleted;

                // Handshake logic:
                // 1. Reply with NMT_NetSpeed (0x03)
                // 2. Send NMT_Welcome (0x01) specifying Level URL ShootingRange?game=ChaosGame.ChaosGameInfo
                let net_speed_msg = ControlMessage::NetSpeed {
                    rate: self.net_speed,
                };
                let welcome_msg = ControlMessage::Welcome {
                    level_url: self.level_url.clone(),
                    game_class: "ChaosGame.ChaosGameInfo".to_string(),
                };

                Ok(vec![net_speed_msg, welcome_msg])
            }
            ControlMessage::NetSpeed { rate } => {
                self.net_speed = *rate;
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bunch_binary_roundtrip() {
        let original = Bunch::control(
            1,
            vec![NMT_NET_SPEED, 0xC0, 0x5D, 0x00, 0x00], // NetSpeed 24000
        );

        let encoded = original.encode();
        assert!(encoded.len() >= 14);

        let decoded = Bunch::decode(&encoded).expect("Failed to decode bunch");
        assert_eq!(decoded.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(decoded.header.ch_type, Ue3ChannelType::Control);
        assert_eq!(decoded.header.ch_sequence, 1);
        assert_eq!(decoded.data, original.data);
    }

    #[test]
    fn test_actor_channel_bunch() {
        let actor_bunch = Bunch::actor(0, true, vec![0x10, 0x20, 0x30]);
        assert_eq!(actor_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(actor_bunch.header.ch_type, Ue3ChannelType::Actor);
        assert!(actor_bunch.header.flags.b_open);

        let encoded = actor_bunch.encode();
        let decoded = Bunch::decode(&encoded).unwrap();
        assert_eq!(decoded.header.ch_index, 2);
        assert!(decoded.header.flags.b_open);
    }

    #[test]
    fn test_control_messages_roundtrip() {
        // Hello
        let hello = ControlMessage::Hello {
            engine_version: 10897,
            licensee_version: 0,
            map_url: "ShootingRange".to_string(),
        };
        let hello_bytes = hello.encode();
        let hello_decoded = ControlMessage::decode(&hello_bytes).unwrap();
        assert_eq!(hello, hello_decoded);

        // NetSpeed
        let netspeed = ControlMessage::NetSpeed { rate: 24000 };
        let netspeed_bytes = netspeed.encode();
        let netspeed_decoded = ControlMessage::decode(&netspeed_bytes).unwrap();
        assert_eq!(netspeed, netspeed_decoded);

        // Welcome
        let welcome = ControlMessage::Welcome {
            level_url: "ShootingRange?game=ChaosGame.ChaosGameInfo".to_string(),
            game_class: "ChaosGame.ChaosGameInfo".to_string(),
        };
        let welcome_bytes = welcome.encode();
        let welcome_decoded = ControlMessage::decode(&welcome_bytes).unwrap();
        assert_eq!(welcome, welcome_decoded);
    }

    #[test]
    fn test_handshake_state_machine_flow() {
        let mut handshake = ControlChannelHandshake::default();
        assert_eq!(handshake.phase, HandshakePhase::AwaitingHello);

        let incoming_hello = ControlMessage::Hello {
            engine_version: 10897,
            licensee_version: 0,
            map_url: "EntryMap".to_string(),
        };

        let replies = handshake
            .handle_control_message(&incoming_hello)
            .expect("Failed to handle hello");

        assert_eq!(handshake.phase, HandshakePhase::HandshakeCompleted);
        assert_eq!(replies.len(), 2);

        // First reply is NMT_NetSpeed (0x03)
        assert_eq!(replies[0], ControlMessage::NetSpeed { rate: 24000 });

        // Second reply is NMT_Welcome (0x01) with ShootingRange URL
        match &replies[1] {
            ControlMessage::Welcome { level_url, .. } => {
                assert_eq!(level_url, "ShootingRange?game=ChaosGame.ChaosGameInfo");
            }
            other => panic!("Expected Welcome message, found {:?}", other),
        }
    }

    #[test]
    fn test_read_fstring_i32_min_negation_safe() {
        let mut data = Vec::new();
        data.write_i32::<LittleEndian>(i32::MIN).unwrap();
        let mut cursor = Cursor::new(data);
        let res = read_fstring(&mut cursor);
        assert!(matches!(res, Err(NetError::InvalidUdpPacket(_))));
    }

    #[test]
    fn test_read_fstring_oversized_positive_rejection() {
        let mut data = Vec::new();
        data.write_i32::<LittleEndian>((MAX_FSTRING_LEN as i32) + 1).unwrap();
        let mut cursor = Cursor::new(data);
        let res = read_fstring(&mut cursor);
        assert!(matches!(res, Err(NetError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_read_fstring_oversized_negative_rejection() {
        let mut data = Vec::new();
        data.write_i32::<LittleEndian>(-((MAX_FSTRING_LEN as i32) + 1)).unwrap();
        let mut cursor = Cursor::new(data);
        let res = read_fstring(&mut cursor);
        assert!(matches!(res, Err(NetError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_bunch_cpack_udp_framing() {
        let bunch = Bunch::actor(1, false, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let udp_framed = bunch.encode_cpack_udp();
        assert_eq!(udp_framed[0], CPACK_OP_BUNCH);

        let decoded = Bunch::decode_cpack_udp(&udp_framed).expect("Failed to decode framed bunch");
        assert_eq!(decoded.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(decoded.header.ch_sequence, 1);
        assert_eq!(decoded.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
