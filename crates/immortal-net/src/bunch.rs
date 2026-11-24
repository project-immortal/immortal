// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Unreal Engine 3 Bit-Packed Bunch Protocol & Staged Channel 0 Handshake
//! Cleanroom implementation of Unreal Engine 3 / Paladins `PComNetConn` +
//! `UNetConnection` bit-packed packet/bunch transport, Channel 0 control messages
//! (`0x00..=0x20`), and the 7-stage UDP 7777 connection handshake state machine
//! (`OBL-UDP-002` / Claim 16).

use crate::bitstream::{strip_stop_bit, ue3_handshake_crc, BitReader, BitWriter};
use crate::error::NetError;
use crate::udp_framing::CPACK_OP_BUNCH;

pub use crate::bitstream::MAX_FSTRING_LEN;

// ============================================================================
// Verified UE3 / Paladins Transport & Channel Constants (Claim 16 / OBL-UDP-002)
// ============================================================================

/// Outer `PComNetConn` prefix length unconditionally stripped by `UPComNetConn::ReceivedRawPacket`.
pub const PCOM_PREFIX_LEN: usize = 6;

/// Outer 10-byte prefix length for Paladins dedicated extended UDP (`?exudp>=1`).
pub const DEDICATED_PREFIX_LEN: usize = 10;

/// Length of the initial 6-byte session token present exclusively on Seq 1.
pub const SESSION_TOKEN_LEN: usize = 6;

/// Dedicated transport subflag for sequenced gameplay datagrams (`[0x00, 0x01]`).
pub const SUBFLAG_SEQUENCED: u16 = 0x0001;

/// Dedicated transport subflag for unsequenced control/handshake/PMTU frames (`[0x00, 0x10]`).
pub const SUBFLAG_UNSEQUENCED: u16 = 0x0010;

/// Outer packet prefix stripped by UE3 network connection layers.
/// In Paladins standalone UDP transport, this is a 6-byte prefix (`PCOM_PREFIX_LEN`).
/// In Paladins dedicated-server captures, this is a 10-byte prefix:
/// `[magic: 4B] [sequence: 4B LE] [subflags: 2B BE]`, optionally followed by
/// a 6-byte session token on Seq 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcomPrefix {
    /// Standalone UDP 7777 framing (6 bytes: 4-byte sequence LE + 2-byte subflag BE).
    Standalone {
        sequence: u32,
        subflag: u16,
    },
    /// Dedicated server sequenced gameplay datagram (10 bytes, or 16 bytes on Seq 1 with session token).
    DedicatedSequenced {
        sequence: u32,
        subflag: u16,
        session_token: Option<[u8; 6]>,
    },
    /// Dedicated server unsequenced control / handshake / PMTU frame (10 bytes).
    DedicatedUnsequenced {
        magic: [u8; 4],
        subflag: u16,
    },
    /// Raw unparsed prefix fallback.
    Raw(Vec<u8>),
}

impl PcomPrefix {
    /// Creates a standalone 6-byte prefix from sequence and subflag.
    #[inline]
    pub fn standalone(sequence: u32, subflag: u16) -> Self {
        Self::Standalone { sequence, subflag }
    }

    /// Creates a dedicated sequenced prefix.
    #[inline]
    pub fn dedicated_sequenced(sequence: u32, session_token: Option<[u8; 6]>) -> Self {
        Self::DedicatedSequenced {
            sequence,
            subflag: SUBFLAG_SEQUENCED,
            session_token,
        }
    }

    /// Creates a dedicated unsequenced control prefix.
    #[inline]
    pub fn dedicated_unsequenced(magic: [u8; 4], subflag: u16) -> Self {
        Self::DedicatedUnsequenced { magic, subflag }
    }

    /// Returns the sequence counter if present.
    #[inline]
    pub fn sequence(&self) -> Option<u32> {
        match self {
            Self::Standalone { sequence, .. } => Some(*sequence),
            Self::DedicatedSequenced { sequence, .. } => Some(*sequence),
            Self::DedicatedUnsequenced { .. } => Some(0),
            Self::Raw(_) => None,
        }
    }

    /// Returns the transport subflag if present.
    #[inline]
    pub fn subflag(&self) -> Option<u16> {
        match self {
            Self::Standalone { subflag, .. } => Some(*subflag),
            Self::DedicatedSequenced { subflag, .. } => Some(*subflag),
            Self::DedicatedUnsequenced { subflag, .. } => Some(*subflag),
            Self::Raw(_) => None,
        }
    }

    /// Returns the optional 6-byte session token if present.
    #[inline]
    pub fn session_token(&self) -> Option<&[u8; 6]> {
        match self {
            Self::DedicatedSequenced { session_token, .. } => session_token.as_ref(),
            _ => None,
        }
    }

    /// Serializes this prefix to its wire byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Standalone { sequence, subflag } => {
                let mut b = Vec::with_capacity(6);
                b.extend_from_slice(&sequence.to_le_bytes());
                b.extend_from_slice(&subflag.to_be_bytes());
                b
            }
            Self::DedicatedSequenced {
                sequence,
                subflag,
                session_token,
            } => {
                let mut b = Vec::with_capacity(if session_token.is_some() { 16 } else { 10 });
                b.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                b.extend_from_slice(&sequence.to_le_bytes());
                b.extend_from_slice(&subflag.to_be_bytes());
                if let Some(token) = session_token {
                    b.extend_from_slice(token);
                }
                b
            }
            Self::DedicatedUnsequenced { magic, subflag } => {
                let mut b = Vec::with_capacity(10);
                b.extend_from_slice(magic);
                b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                b.extend_from_slice(&subflag.to_be_bytes());
                b
            }
            Self::Raw(bytes) => bytes.clone(),
        }
    }

    /// Returns a borrowed or owned slice of bytes representing this prefix.
    #[inline]
    pub fn as_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        match self {
            Self::Raw(b) => std::borrow::Cow::Borrowed(b.as_slice()),
            _ => std::borrow::Cow::Owned(self.to_bytes()),
        }
    }

    /// Returns the byte length of this prefix on the wire.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Standalone { .. } => 6,
            Self::DedicatedSequenced { session_token, .. } => {
                if session_token.is_some() {
                    16
                } else {
                    10
                }
            }
            Self::DedicatedUnsequenced { .. } => 10,
            Self::Raw(bytes) => bytes.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for PcomPrefix {
    fn default() -> Self {
        Self::Standalone {
            sequence: 0,
            subflag: SUBFLAG_SEQUENCED,
        }
    }
}

impl From<[u8; PCOM_PREFIX_LEN]> for PcomPrefix {
    fn from(arr: [u8; PCOM_PREFIX_LEN]) -> Self {
        let sequence = u32::from_le_bytes(arr[0..4].try_into().unwrap());
        let subflag = u16::from_be_bytes(arr[4..6].try_into().unwrap());
        Self::Standalone { sequence, subflag }
    }
}

impl From<[u8; 10]> for PcomPrefix {
    fn from(arr: [u8; 10]) -> Self {
        let magic = [arr[0], arr[1], arr[2], arr[3]];
        let sequence = u32::from_le_bytes(arr[4..8].try_into().unwrap());
        let subflag = u16::from_be_bytes(arr[8..10].try_into().unwrap());
        if subflag == SUBFLAG_UNSEQUENCED || sequence == 0 {
            Self::DedicatedUnsequenced { magic, subflag }
        } else {
            Self::DedicatedSequenced {
                sequence,
                subflag,
                session_token: None,
            }
        }
    }
}

impl PartialEq<[u8; PCOM_PREFIX_LEN]> for PcomPrefix {
    fn eq(&self, other: &[u8; PCOM_PREFIX_LEN]) -> bool {
        self.to_bytes().as_slice() == other.as_slice()
    }
}

impl PartialEq<PcomPrefix> for [u8; PCOM_PREFIX_LEN] {
    fn eq(&self, other: &PcomPrefix) -> bool {
        self.as_slice() == other.to_bytes().as_slice()
    }
}

impl PartialEq<[u8; 10]> for PcomPrefix {
    fn eq(&self, other: &[u8; 10]) -> bool {
        self.to_bytes().as_slice() == other.as_slice()
    }
}

impl PartialEq<PcomPrefix> for [u8; 10] {
    fn eq(&self, other: &PcomPrefix) -> bool {
        self.as_slice() == other.to_bytes().as_slice()
    }
}

/// Dedicated server unsequenced control frame representations (`subflags == 0x0010`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedicatedControlFrame {
    /// Client Hello (570 bytes) - Initial connection request
    ClientHello {
        magic: [u8; 4],
        connection_nonce: [u8; 6],
        sub_version: [u8; 6],
        descriptor_len: u16,
        ticket_payload: Vec<u8>,
        hmac: [u8; 32],
    },
    /// Server Challenge / Cookie Reply (46 bytes)
    ServerChallenge {
        magic: [u8; 4],
        handshake_flag: u8,
        client_cookie: [u8; 5],
        server_cookie: [u8; 6],
        challenge: [u8; 24],
    },
    /// Path MTU Discovery (PMTU) Probes (1440 bytes)
    PmtuProbe {
        magic: [u8; 4],
        probe_token: [u8; 6],
        probe_marker: [u8; 6],
        total_len: usize,
    },
    /// Handshake Completion (46 bytes)
    HandshakeComplete {
        magic: [u8; 4],
        handshake_flag: u8,
        session_tokens: [u8; 11],
        confirmation: [u8; 24],
    },
    /// Generic or unparsed unsequenced control frame
    Other {
        magic: [u8; 4],
        subflags: u16,
        payload: Vec<u8>,
    },
}

impl DedicatedControlFrame {
    /// Parses an unsequenced control frame from raw datagram bytes.
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < 10 {
            return None;
        }
        let magic = [datagram[0], datagram[1], datagram[2], datagram[3]];
        let subflags = u16::from_be_bytes([datagram[8], datagram[9]]);
        if subflags != SUBFLAG_UNSEQUENCED {
            return None;
        }
        let payload = &datagram[10..];

        if datagram.len() == 570 {
            let mut connection_nonce = [0u8; 6];
            let mut sub_version = [0u8; 6];
            let mut hmac = [0u8; 32];
            connection_nonce.copy_from_slice(&payload[0..6]);
            sub_version.copy_from_slice(&payload[6..12]);
            let descriptor_len = u16::from_le_bytes(payload[12..14].try_into().unwrap());
            let ticket_end = 14 + (descriptor_len as usize).min(payload.len().saturating_sub(46));
            let ticket_payload = payload[14..ticket_end].to_vec();
            hmac.copy_from_slice(&datagram[538..570]);
            Some(Self::ClientHello {
                magic,
                connection_nonce,
                sub_version,
                descriptor_len,
                ticket_payload,
                hmac,
            })
        } else if datagram.len() == 46 {
            let handshake_flag = payload[0];
            if (handshake_flag & 0x05) == 0x05 {
                let mut client_cookie = [0u8; 5];
                let mut server_cookie = [0u8; 6];
                let mut challenge = [0u8; 24];
                client_cookie.copy_from_slice(&payload[1..6]);
                server_cookie.copy_from_slice(&payload[6..12]);
                challenge.copy_from_slice(&payload[12..36]);
                Some(Self::ServerChallenge {
                    magic,
                    handshake_flag,
                    client_cookie,
                    server_cookie,
                    challenge,
                })
            } else {
                let mut session_tokens = [0u8; 11];
                let mut confirmation = [0u8; 24];
                session_tokens.copy_from_slice(&payload[1..12]);
                confirmation.copy_from_slice(&payload[12..36]);
                Some(Self::HandshakeComplete {
                    magic,
                    handshake_flag,
                    session_tokens,
                    confirmation,
                })
            }
        } else if datagram.len() == 1440 {
            let mut probe_token = [0u8; 6];
            let mut probe_marker = [0u8; 6];
            probe_token.copy_from_slice(&payload[0..6]);
            probe_marker.copy_from_slice(&payload[6..12]);
            Some(Self::PmtuProbe {
                magic,
                probe_token,
                probe_marker,
                total_len: datagram.len(),
            })
        } else {
            Some(Self::Other {
                magic,
                subflags,
                payload: payload.to_vec(),
            })
        }
    }

    /// Serializes this unsequenced control frame into raw wire datagram bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::ClientHello {
                magic,
                connection_nonce,
                sub_version,
                descriptor_len,
                ticket_payload,
                hmac,
            } => {
                let mut buf = vec![0u8; 570];
                buf[0..4].copy_from_slice(magic);
                buf[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                buf[8..10].copy_from_slice(&SUBFLAG_UNSEQUENCED.to_be_bytes());
                buf[10..16].copy_from_slice(connection_nonce);
                buf[16..22].copy_from_slice(sub_version);
                buf[22..24].copy_from_slice(&descriptor_len.to_le_bytes());
                let t_len = ticket_payload.len().min(510);
                buf[24..24 + t_len].copy_from_slice(&ticket_payload[..t_len]);
                buf[534..538].copy_from_slice(&32u32.to_le_bytes());
                buf[538..570].copy_from_slice(hmac);
                buf
            }
            Self::ServerChallenge {
                magic,
                handshake_flag,
                client_cookie,
                server_cookie,
                challenge,
            } => {
                let mut buf = Vec::with_capacity(46);
                buf.extend_from_slice(magic);
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                buf.extend_from_slice(&SUBFLAG_UNSEQUENCED.to_be_bytes());
                buf.push(*handshake_flag);
                buf.extend_from_slice(client_cookie);
                buf.extend_from_slice(server_cookie);
                buf.extend_from_slice(challenge);
                buf
            }
            Self::PmtuProbe {
                magic,
                probe_token,
                probe_marker,
                total_len,
            } => {
                let len = (*total_len).max(22);
                let mut buf = vec![0u8; len];
                buf[0..4].copy_from_slice(magic);
                buf[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                buf[8..10].copy_from_slice(&SUBFLAG_UNSEQUENCED.to_be_bytes());
                buf[10..16].copy_from_slice(probe_token);
                buf[16..22].copy_from_slice(probe_marker);
                buf
            }
            Self::HandshakeComplete {
                magic,
                handshake_flag,
                session_tokens,
                confirmation,
            } => {
                let mut buf = Vec::with_capacity(46);
                buf.extend_from_slice(magic);
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                buf.extend_from_slice(&SUBFLAG_UNSEQUENCED.to_be_bytes());
                buf.push(*handshake_flag);
                buf.extend_from_slice(session_tokens);
                buf.extend_from_slice(confirmation);
                buf
            }
            Self::Other {
                magic,
                subflags,
                payload,
            } => {
                let mut buf = Vec::with_capacity(10 + payload.len());
                buf.extend_from_slice(magic);
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                buf.extend_from_slice(&subflags.to_be_bytes());
                buf.extend_from_slice(payload);
                buf
            }
        }
    }
}

/// Type alias aligning with UE3 `FInBunch` bit-packed bunch structure.
pub type FInBunch = Bunch;

/// `MAX_PACKETID` = `0x4000` (16384 -> 14-bit `SerializeInt`).
pub const MAX_PACKETID: u32 = 0x4000;

/// `MAX_CHANNELS` = `0x800` (2048 -> 11-bit `SerializeInt`).
pub const MAX_CHANNELS: u32 = 0x800;

/// `MAX_CHSEQUENCE` = `0x400` (1024 -> 10-bit `SerializeInt`, 1-based reliable sequence).
pub const MAX_CHSEQUENCE: u32 = 0x400;

/// `CHTYPE_MAX` = `8` (3-bit `SerializeInt`).
pub const CHTYPE_MAX: u32 = 8;

/// Standard UDP `MaxPacket` = `0x240` (`576` bytes; `UTcpipConnection::InitConnection`).
pub const DEFAULT_MAX_PACKET: usize = 0x240;

/// Standard UDP `MaxPacket * 8` = `4608` bits (`13` bits for `< 512`, `12` bits for `512..=4095`).
pub const DEFAULT_MAX_PACKET_BITS: usize = DEFAULT_MAX_PACKET * 8;

/// Extended UDP (`?exudp>=1`) `MaxPacket * 8` = `0x1F0 * 8` = `3968` bits (`496` bytes).
pub const EXUDP_MAX_PACKET_BITS: usize = 0x1F0 * 8;

/// Dedicated server / Ethernet standard MTU `1440 * 8` = `11520` bits (`1440` bytes).
pub const MAX_ALLOWED_PACKET_BITS: usize = 1440 * 8;

/// Engine minimum network version (`GEngineMinNetVersion = 9189`).
pub const DEFAULT_ENGINE_MIN_NET_VERSION: u32 = 9189;

/// Engine network version (`GEngineVersion = 10897`).
pub const DEFAULT_ENGINE_NET_VERSION: u32 = 10897;

/// Default deterministic challenge nonce for `NMT_HandshakeChallenge (0x1B)`.
pub const DEFAULT_HANDSHAKE_CHALLENGE: u32 = 0x1234_5678;

/// Default negotiated network speed in bytes/sec.
pub const DEFAULT_NET_SPEED: u32 = 24000;

/// Bare map level name sent in `NMT_Welcome (0x01)` (`PersistentLevel->GetOutermost()->GetName()`).
pub const DEFAULT_SHOOTING_RANGE_LEVEL: &str = "Shootingrange_P";

/// Local Shooting Range reference travel URL (`Team=0` safe player spawn per G2 §5.5).
pub const DEFAULT_SHOOTING_RANGE_MAP: &str =
    "Shootingrange_P?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0?Team=0";

/// Shooting Range GameInfo class path sent in `NMT_Welcome (0x01)`.
pub const DEFAULT_GAME_CLASS: &str = "TgGame.TgGame_Paladins_ShootingRange";

// Engine Channel Index Assignments (`UNetConnection::CreateChannel`)
pub const CONTROL_CHANNEL_INDEX: u32 = 0;
pub const MARSHAL_CHANNEL_INDEX: u32 = 1;
pub const VOICE_CHANNEL_INDEX: u32 = 2;
pub const ACTOR_CHANNEL_INDEX: u32 = 3;

// UE3 / Paladins Control Channel Message Opcodes (`FNetControlMessageInfo::Names`)
pub const NMT_HELLO: u8 = 0x00;
pub const NMT_WELCOME: u8 = 0x01;
pub const NMT_UPGRADE: u8 = 0x02;
pub const NMT_CHALLENGE: u8 = 0x03;
pub const NMT_NETSPEED: u8 = 0x04;
pub const NMT_LOGIN: u8 = 0x05;
pub const NMT_FAILURE: u8 = 0x06;
pub const NMT_USES: u8 = 0x07;
pub const NMT_HAVE: u8 = 0x08;
pub const NMT_JOIN: u8 = 0x09;
pub const NMT_JOIN_SPLIT: u8 = 0x0A;
pub const NMT_ACTOR_CHANNEL_FAILURE: u8 = 0x10;
pub const NMT_HANDSHAKE_START: u8 = 0x1A;
pub const NMT_HANDSHAKE_CHALLENGE: u8 = 0x1B;
pub const NMT_HANDSHAKE_RESPONSE: u8 = 0x1C;
pub const NMT_HANDSHAKE_COMPLETE: u8 = 0x1D;
pub const NMT_REDIRECT: u8 = 0x1E;
pub const NMT_CLIENT_AUTH_REQUEST: u8 = 0x1F;
pub const NMT_SERVER_AUTH_REQUEST: u8 = 0x20;
pub const NMT_MARSHAL_PACKAGE: u8 = 0x27;
pub const NMT_PLAY_TIME: u8 = 0x29;
pub const NMT_MAP_LOADED: u8 = 0x2A;
pub const NMT_TIME_LAPSE: u8 = 0x2B;
pub const NMT_USES_OPT: u8 = 0x2C;
pub const NMT_USES_OPT_EX: u8 = 0x2D;

/// UE3 Channel Type Indexing (`UChannel::ChannelClasses[8]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ue3ChannelType {
    None = 0,
    Control = 1,
    Actor = 2,
    File = 3,
    Voice = 4,
    Marshal = 5,
}

impl Ue3ChannelType {
    pub fn from_u8(val: u8) -> Result<Self, NetError> {
        match val {
            0 => Ok(Self::None),
            1 => Ok(Self::Control),
            2 => Ok(Self::Actor),
            3 => Ok(Self::File),
            4 => Ok(Self::Voice),
            5 => Ok(Self::Marshal),
            other => Err(NetError::InvalidUdpPacket(format!(
                "Invalid UE3 channel type 0x{:02x}",
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
    /// Returns `true` when `b_open || b_close` (the UE3 `bControl` header flag).
    #[inline]
    pub fn is_control(&self) -> bool {
        self.b_open || self.b_close
    }

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

/// Unreal Engine 3 `FInBunch` / `FOutBunch` bit-packed payload unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bunch {
    pub header: BunchHeader,
    pub num_bits: usize,
    pub data: Vec<u8>,
}

impl Bunch {
    /// Creates a byte-aligned `Bunch` with `num_bits = data.len() * 8`.
    pub fn new(header: BunchHeader, data: Vec<u8>) -> Self {
        let num_bits = data.len() * 8;
        Self {
            header,
            num_bits,
            data,
        }
    }

    /// Creates a `Bunch` with an explicit bit length `num_bits`.
    pub fn with_bits(header: BunchHeader, num_bits: usize, data: Vec<u8>) -> Self {
        Self {
            header,
            num_bits,
            data,
        }
    }

    /// Creates a Channel 0 reliable control bunch (`b_open = false, b_close = false, b_reliable = true`).
    /// Server-to-client Channel 0 bunches use `b_open = false` and 1-based `ch_sequence`.
    pub fn control(ch_sequence: u32, data: Vec<u8>) -> Self {
        let num_bits = data.len() * 8;
        Self {
            header: BunchHeader {
                ch_index: CONTROL_CHANNEL_INDEX,
                ch_type: Ue3ChannelType::Control,
                flags: BunchFlags {
                    b_open: false,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence,
            },
            num_bits,
            data,
        }
    }

    /// Creates a Channel 0 opening reliable control bunch (`b_open = true, b_reliable = true`).
    pub fn control_open(ch_sequence: u32, data: Vec<u8>) -> Self {
        let num_bits = data.len() * 8;
        Self {
            header: BunchHeader {
                ch_index: CONTROL_CHANNEL_INDEX,
                ch_type: Ue3ChannelType::Control,
                flags: BunchFlags {
                    b_open: true,
                    b_close: false,
                    b_reliable: true,
                    b_partial: false,
                },
                ch_sequence,
            },
            num_bits,
            data,
        }
    }

    /// Creates an Actor Channel (`ACTOR_CHANNEL_INDEX = 3`) reliable bunch.
    pub fn actor(ch_sequence: u32, b_open: bool, data: Vec<u8>) -> Self {
        let num_bits = data.len() * 8;
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
            num_bits,
            data,
        }
    }

    /// Writes the bit-packed UE3 bunch header and payload bits into `writer`
    /// (`UNetConnection::SendRawBunch` layout; caller writes the leading `IsAck = 0` bit
    /// when packing inside a `Ue3Packet`).
    pub fn encode_bits(
        &self,
        writer: &mut BitWriter,
        max_packet_bits: usize,
    ) -> Result<(), NetError> {
        if max_packet_bits == 0 || max_packet_bits > u32::MAX as usize {
            return Err(NetError::BunchError(format!(
                "Invalid max_packet_bits {}",
                max_packet_bits
            )));
        }
        if self.num_bits >= max_packet_bits {
            return Err(NetError::PayloadTooLarge {
                length: self.num_bits,
                max: max_packet_bits.saturating_sub(1),
            });
        }
        let b_control = self.header.flags.is_control();
        writer.write_bit(b_control);
        if b_control {
            writer.write_bit(self.header.flags.b_open);
            writer.write_bit(self.header.flags.b_close);
        }
        writer.write_bit(self.header.flags.b_reliable);
        writer.write_int(self.header.ch_index, MAX_CHANNELS)?;
        if self.header.flags.b_reliable {
            writer.write_int(self.header.ch_sequence, MAX_CHSEQUENCE)?;
        }
        if self.header.flags.b_reliable || self.header.flags.b_open {
            writer.write_int(self.header.ch_type as u32, CHTYPE_MAX)?;
        }
        writer.write_int(self.num_bits as u32, max_packet_bits as u32)?;
        writer.write_bits(&self.data, self.num_bits)?;
        Ok(())
    }

    /// Reads a bit-packed UE3 bunch header and payload from `reader`
    /// (`UNetConnection::ReceivedPacket` layout; caller consumes the leading `IsAck = 0` bit).
    pub fn decode_bits(
        reader: &mut BitReader<'_>,
        max_packet_bits: usize,
    ) -> Result<Self, NetError> {
        if max_packet_bits == 0 || max_packet_bits > u32::MAX as usize {
            return Err(NetError::BunchError(format!(
                "Invalid max_packet_bits {}",
                max_packet_bits
            )));
        }
        let b_control = reader.read_bit()?;
        let (b_open, b_close) = if b_control {
            (reader.read_bit()?, reader.read_bit()?)
        } else {
            (false, false)
        };
        let b_reliable = reader.read_bit()?;
        let ch_index = reader.read_int(MAX_CHANNELS)?;
        let ch_sequence = if b_reliable {
            reader.read_int(MAX_CHSEQUENCE)?
        } else {
            0
        };
        let ch_type = if b_reliable || b_open {
            Ue3ChannelType::from_u8(reader.read_int(CHTYPE_MAX)? as u8)?
        } else {
            Ue3ChannelType::None
        };
        let num_bits = reader.read_int(max_packet_bits as u32)? as usize;
        let data = reader.read_bits(num_bits)?;

        Ok(Self {
            header: BunchHeader {
                ch_index,
                ch_type,
                flags: BunchFlags {
                    b_open,
                    b_close,
                    b_reliable,
                    b_partial: false,
                },
                ch_sequence,
            },
            num_bits,
            data,
        })
    }

    /// Serializes this bunch into a standalone UE3 bit-packed byte stream terminated with a stop bit.
    pub fn encode(&self) -> Result<Vec<u8>, NetError> {
        let mut writer = BitWriter::with_capacity_bits(48 + self.num_bits);
        self.encode_bits(&mut writer, DEFAULT_MAX_PACKET_BITS)?;
        Ok(writer.finish_with_stop_bit())
    }

    /// Deserializes a standalone stop-bit-terminated bit-packed bunch.
    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        let total_bits = strip_stop_bit(data)?;
        let mut reader = BitReader::new(data, total_bits)?;
        Self::decode_bits(&mut reader, DEFAULT_MAX_PACKET_BITS)
    }

    /// Serializes bunch prefixed with `CPACK_OP_BUNCH (0x04)` for legacy CPackUdp transport.
    pub fn encode_cpack_udp(&self) -> Result<Vec<u8>, NetError> {
        let encoded = self.encode()?;
        let mut buf = Vec::with_capacity(1 + encoded.len());
        buf.push(CPACK_OP_BUNCH);
        buf.extend_from_slice(&encoded);
        Ok(buf)
    }

    /// Deserializes bunch from wire bytes that may optionally include the `CPACK_OP_BUNCH (0x04)` prefix.
    pub fn decode_cpack_udp(data: &[u8]) -> Result<Self, NetError> {
        if !data.is_empty() && data[0] == CPACK_OP_BUNCH {
            Self::decode(&data[1..])
        } else {
            Self::decode(data)
        }
    }
}

// ============================================================================
// Complete UE3 / PComNetConn UDP 7777 Datagram Packet Codec
// ============================================================================

/// Cleanroom representation of a full UE3 `PComNetConn` UDP 7777 datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ue3Packet {
    pub pcom_prefix: PcomPrefix,
    pub packet_id: u16,
    pub acks: Vec<u16>,
    pub bunches: Vec<Bunch>,
}

impl Ue3Packet {
    /// Creates a new `Ue3Packet` with the given 6-byte outer prefix and 14-bit `packet_id`.
    pub fn new(pcom_prefix: [u8; PCOM_PREFIX_LEN], packet_id: u16) -> Self {
        Self::new_with_prefix(PcomPrefix::from(pcom_prefix), packet_id)
    }

    /// Creates a new `Ue3Packet` with a dynamic `PcomPrefix` and 14-bit `packet_id`.
    pub fn new_with_prefix(pcom_prefix: PcomPrefix, packet_id: u16) -> Self {
        Self {
            pcom_prefix,
            packet_id,
            acks: Vec::new(),
            bunches: Vec::new(),
        }
    }

    /// Encodes the packet using `DEFAULT_MAX_PACKET_BITS` (`4608` bits = `576` bytes).
    pub fn encode(&self) -> Result<Vec<u8>, NetError> {
        self.encode_with_max_bits(DEFAULT_MAX_PACKET_BITS)
    }

    /// Encodes the packet into a full PCom wire datagram with its transport prefix.
    /// Equivalent to `encode_with_max_bits(max_packet_bits)`.
    pub fn encode_pcom(&self, max_packet_bits: usize) -> Result<Vec<u8>, NetError> {
        self.encode_with_max_bits(max_packet_bits)
    }

    /// Encodes the packet with an explicit `max_packet_bits` (`4608` standard UDP or `3968` `?exudp>=1`).
    pub fn encode_with_max_bits(&self, max_packet_bits: usize) -> Result<Vec<u8>, NetError> {
        if max_packet_bits == 0 || max_packet_bits > MAX_ALLOWED_PACKET_BITS {
            return Err(NetError::BunchError(format!(
                "max_packet_bits {} out of bounds (1..={})",
                max_packet_bits, MAX_ALLOWED_PACKET_BITS
            )));
        }
        let mut writer = BitWriter::with_capacity_bits(64);
        writer.write_int(u32::from(self.packet_id), MAX_PACKETID)?;

        for &ack_id in &self.acks {
            writer.write_bit(true);
            writer.write_int(u32::from(ack_id), MAX_PACKETID)?;
        }

        for bunch in &self.bunches {
            writer.write_bit(false);
            bunch.encode_bits(&mut writer, max_packet_bits)?;
        }

        if writer.num_bits() >= max_packet_bits {
            return Err(NetError::PayloadTooLarge {
                length: writer.num_bits() + 1,
                max: max_packet_bits,
            });
        }

        let ue3_bytes = writer.finish_with_stop_bit();
        let prefix_bytes = self.pcom_prefix.to_bytes();
        let mut out = Vec::with_capacity(prefix_bytes.len() + ue3_bytes.len());
        out.extend_from_slice(&prefix_bytes);
        out.extend_from_slice(&ue3_bytes);
        Ok(out)
    }

    /// Decodes a `PComNetConn` UDP datagram using `DEFAULT_MAX_PACKET_BITS` (`4608` bits).
    pub fn decode(datagram: &[u8]) -> Result<Self, NetError> {
        Self::decode_with_max_bits(datagram, DEFAULT_MAX_PACKET_BITS)
    }

    /// Decodes a `PComNetConn` UDP datagram with explicit `max_packet_bits` bounds enforcement.
    pub fn decode_with_max_bits(datagram: &[u8], max_packet_bits: usize) -> Result<Self, NetError> {
        if max_packet_bits == 0 || max_packet_bits > MAX_ALLOWED_PACKET_BITS {
            return Err(NetError::BunchError(format!(
                "max_packet_bits {} out of bounds (1..={})",
                max_packet_bits, MAX_ALLOWED_PACKET_BITS
            )));
        }

        let (pcom_prefix, ue3_bytes) = if datagram.len() >= 10
            && (datagram.starts_with(&[0x01, 0x00, 0x00, 0x00])
                || datagram.starts_with(&[0x00, 0x00, 0x00, 0x00]))
            && (datagram[8..10] == [0x00, 0x01] || datagram[8..10] == [0x00, 0x10])
        {
            let magic = [datagram[0], datagram[1], datagram[2], datagram[3]];
            let seq = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
            let subflag = u16::from_be_bytes(datagram[8..10].try_into().unwrap());

            if subflag == SUBFLAG_UNSEQUENCED {
                return Err(NetError::UnsequencedControlFrame {
                    magic,
                    subflags: subflag,
                    len: datagram.len(),
                });
            }

            if seq == 1 {
                if datagram.len() < 16 + 1 {
                    return Err(NetError::PacketTooSmall {
                        expected: 17,
                        actual: datagram.len(),
                    });
                }
                let mut token = [0u8; 6];
                token.copy_from_slice(&datagram[10..16]);
                (
                    PcomPrefix::DedicatedSequenced {
                        sequence: seq,
                        subflag,
                        session_token: Some(token),
                    },
                    &datagram[16..],
                )
            } else {
                if datagram.len() < 10 + 1 {
                    return Err(NetError::PacketTooSmall {
                        expected: 11,
                        actual: datagram.len(),
                    });
                }
                (
                    PcomPrefix::DedicatedSequenced {
                        sequence: seq,
                        subflag,
                        session_token: None,
                    },
                    &datagram[10..],
                )
            }
        } else if datagram.len() >= 7 && (datagram[0] == 0x00 || (datagram.len() >= 6 && datagram[4..6] == [0x00, 0x01])) {
            let seq = u32::from_le_bytes(datagram[0..4].try_into().unwrap());
            let subflag = u16::from_be_bytes(datagram[4..6].try_into().unwrap());
            (
                PcomPrefix::Standalone {
                    sequence: seq,
                    subflag,
                },
                &datagram[PCOM_PREFIX_LEN..],
            )
        } else if datagram.len() > PCOM_PREFIX_LEN {
            (
                PcomPrefix::Raw(datagram[..PCOM_PREFIX_LEN].to_vec()),
                &datagram[PCOM_PREFIX_LEN..],
            )
        } else {
            return Err(NetError::PacketTooSmall {
                expected: PCOM_PREFIX_LEN + 1,
                actual: datagram.len(),
            });
        };

        let max_ue3_bytes = max_packet_bits.div_ceil(8);
        if ue3_bytes.len() > max_ue3_bytes {
            return Err(NetError::PayloadTooLarge {
                length: ue3_bytes.len(),
                max: max_ue3_bytes,
            });
        }

        let total_bits = strip_stop_bit(ue3_bytes)?;
        if total_bits >= max_packet_bits {
            return Err(NetError::PayloadTooLarge {
                length: total_bits + 1,
                max: max_packet_bits,
            });
        }

        let mut reader = BitReader::new(ue3_bytes, total_bits)?;
        let packet_id = reader.read_int(MAX_PACKETID)? as u16;
        let mut acks = Vec::new();
        let mut bunches = Vec::new();

        // Each record consumes at least 15 bits (1-bit IsAck + 14-bit AckId),
        // bounding loop iterations strictly to <= max_packet_bits / 15 (307 for 4608).
        let max_records = max_packet_bits / 15 + 1;
        let mut record_count = 0usize;
        while !reader.at_end() {
            record_count += 1;
            if record_count > max_records {
                return Err(NetError::BunchError(format!(
                    "Packet record count exceeded bound {}",
                    max_records
                )));
            }
            if reader.read_bit()? {
                let ack_id = reader.read_int(MAX_PACKETID)? as u16;
                acks.push(ack_id);
            } else {
                bunches.push(Bunch::decode_bits(&mut reader, max_packet_bits)?);
            }
        }

        Ok(Self {
            pcom_prefix,
            packet_id,
            acks,
            bunches,
        })
    }
}

// ============================================================================
// Channel 0 Control Messages (`FNetControlMessageInfo::Names`)
// ============================================================================

/// Cleanroom representation of verified UE3 / Paladins Control Channel messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// `NMT_Hello (0x00)`: C -> S (`MinNetVer`, `NetVer`, `IsLittleEndian`).
    Hello {
        min_net_ver: u32,
        net_ver: u32,
        is_little_endian: u32,
    },
    /// `NMT_Welcome (0x01)`: S -> C (`LevelName`, `GameName`).
    Welcome {
        level_name: String,
        game_name: String,
    },
    /// `NMT_Upgrade (0x02)`: S -> C (`RemoteNetVer`, `RemoteNetFeatures`).
    Upgrade {
        remote_net_ver: u32,
        remote_net_features: u32,
    },
    /// `NMT_Challenge (0x03)`: S -> C (`ChallengeId`, `Challenge`).
    Challenge {
        challenge_id: u32,
        challenge: String,
    },
    /// `NMT_Netspeed (0x04)`: C <-> S (`CurrentNetSpeed`).
    NetSpeed { rate: u32 },
    /// `NMT_Login (0x05)`: C -> S (Paladins 2x `u64` trailing IDs).
    Login {
        client_response: String,
        url: String,
        unique_id: u64,
        portal_id: u64,
    },
    /// `NMT_Failure (0x06)`: S -> C (`ErrorMsg`).
    Failure { reason: String },
    /// `NMT_Uses (0x07)`: C <-> S (`FGuid`, `PackageName`, `Extension`, `URL`, `PackageFlags`, `RemoteGeneration`, `LocalPackageName`, `bLoadingFromCache`).
    Uses {
        guid: [u32; 4],
        package_name: String,
        extension: String,
        url: String,
        package_flags: u32,
        remote_generation: u32,
        local_package_name: String,
        loading_from_cache: u8,
    },
    /// `NMT_Have (0x08)`: C -> S (`FGuid`, `Generation`).
    Have { guid: [u32; 4], generation: i32 },
    /// `NMT_Join (0x09)`: C -> S (0 bytes).
    Join,
    /// `NMT_ActorChannelFailure (0x10)`: C -> S (`ChIndex`).
    ActorChannelFailure { ch_index: i32 },
    /// `NMT_HandshakeStart (0x1A)`: C -> S (`PlatformFlag`, `0x40` on Win64).
    HandshakeStart { platform_flag: u32 },
    /// `NMT_HandshakeChallenge (0x1B)`: S -> C (`Challenge`).
    HandshakeChallenge { challenge: u32 },
    /// `NMT_HandshakeResponse (0x1C)`: C -> S (`CrcResponse`).
    HandshakeResponse { crc_response: u32 },
    /// `NMT_HandshakeComplete (0x1D)`: S -> C (0 bytes).
    HandshakeComplete,
    /// `NMT_Redirect (0x1E)`: S -> C (`RedirectAddr`).
    Redirect { redirect_addr: String },
    /// `NMT_ClientAuthRequest (0x1F)`: S -> C (`ServerSteamId` + 4x `u32`).
    ClientAuthRequest {
        server_steam_id: u64,
        param_a: u32,
        param_b: u32,
        param_c: u32,
        param_d: u32,
    },
    /// `NMT_ServerAuthRequest (0x20)`: C -> S (0 bytes).
    ServerAuthRequest,
    /// `NMT_MarshalPackage (0x27)`: C <-> S (`total_size` 19-bit on first chunk, `chunk_size` 9-bit + raw `CMarshal` bytes).
    MarshalPackage {
        total_size: Option<u32>,
        chunk: Vec<u8>,
    },
    /// `NMT_PlayTime (0x29)`: C <-> S (`u32`).
    PlayTime { play_time: u32 },
    /// `NMT_MapLoaded (0x2A)`: C -> S (0 bytes). Client notification that local map load has finished.
    MapLoaded,
    /// `NMT_TimeLapse (0x2B)`: C <-> S (`u32`, `u32`).
    TimeLapse { param_a: u32, param_b: u32 },
    /// `NMT_UsesOpt (0x2C)`: S -> C (`FGuid`, `PackageName`, `PackageFlags`, `CachedExtIndex`).
    UsesOpt {
        guid: [u32; 4],
        package_name: String,
        package_flags: u32,
        cached_ext_index: i32,
    },
    /// `NMT_UsesOptEx (0x2D)`: S -> C (`FGuid`, `PackageName`, `PackageFlags`, `GenOrFlags`, `ExtensionOrParent`).
    UsesOptEx {
        guid: [u32; 4],
        package_name: String,
        package_flags: u32,
        gen_or_flags: i32,
        extension_or_parent: String,
    },
}

impl ControlMessage {
    /// Constructs `NMT_ClientAuthRequest (0x1F)` with `server_steam_id = 0`,
    /// instructing the client to bypass Steam AuthBlob and immediately emit `NMT_Hello (0x00)`.
    pub fn client_auth_request_bypass() -> Self {
        Self::ClientAuthRequest {
            server_steam_id: 0,
            param_a: 0,
            param_b: 0,
            param_c: 0,
            param_d: 0,
        }
    }

    /// Serializes control message into bunch payload bytes and returns `(bytes, exact_num_bits)`.
    pub fn try_encode_bits(&self) -> Result<(Vec<u8>, usize), NetError> {
        let mut w = BitWriter::new();
        self.encode_into(&mut w)?;
        let num_bits = w.num_bits();
        Ok((w.into_bytes(), num_bits))
    }

    /// Serializes control message into an existing `BitWriter` without trailing byte padding.
    pub fn encode_into(&self, w: &mut BitWriter) -> Result<(), NetError> {
        match self {
            Self::Hello {
                min_net_ver,
                net_ver,
                is_little_endian,
            } => {
                w.write_u8(NMT_HELLO);
                w.write_u32(*min_net_ver);
                w.write_u32(*net_ver);
                w.write_u32(*is_little_endian);
            }
            Self::Welcome {
                level_name,
                game_name,
            } => {
                w.write_u8(NMT_WELCOME);
                w.write_fstring(level_name);
                w.write_fstring(game_name);
            }
            Self::Upgrade {
                remote_net_ver,
                remote_net_features,
            } => {
                w.write_u8(NMT_UPGRADE);
                w.write_u32(*remote_net_ver);
                w.write_u32(*remote_net_features);
            }
            Self::Challenge {
                challenge_id,
                challenge,
            } => {
                w.write_u8(NMT_CHALLENGE);
                w.write_u32(*challenge_id);
                w.write_fstring(challenge);
            }
            Self::NetSpeed { rate } => {
                w.write_u8(NMT_NETSPEED);
                w.write_u32(*rate);
            }
            Self::Login {
                client_response,
                url,
                unique_id,
                portal_id,
            } => {
                w.write_u8(NMT_LOGIN);
                w.write_fstring(client_response);
                w.write_fstring(url);
                w.write_u64(*unique_id);
                w.write_u64(*portal_id);
            }
            Self::Failure { reason } => {
                w.write_u8(NMT_FAILURE);
                w.write_fstring(reason);
            }
            Self::Uses {
                guid,
                package_name,
                extension,
                url,
                package_flags,
                remote_generation,
                local_package_name,
                loading_from_cache,
            } => {
                w.write_u8(NMT_USES);
                for &part in guid {
                    w.write_u32(part);
                }
                w.write_fstring(package_name);
                w.write_fstring(extension);
                w.write_fstring(url);
                w.write_u32(*package_flags);
                w.write_u32(*remote_generation);
                w.write_fstring(local_package_name);
                w.write_u8(*loading_from_cache);
            }
            Self::Have { guid, generation } => {
                w.write_u8(NMT_HAVE);
                for &part in guid {
                    w.write_u32(part);
                }
                w.write_i32(*generation);
            }
            Self::Join => {
                w.write_u8(NMT_JOIN);
            }
            Self::ActorChannelFailure { ch_index } => {
                w.write_u8(NMT_ACTOR_CHANNEL_FAILURE);
                w.write_i32(*ch_index);
            }
            Self::HandshakeStart { platform_flag } => {
                w.write_u8(NMT_HANDSHAKE_START);
                w.write_u32(*platform_flag);
            }
            Self::HandshakeChallenge { challenge } => {
                w.write_u8(NMT_HANDSHAKE_CHALLENGE);
                w.write_u32(*challenge);
            }
            Self::HandshakeResponse { crc_response } => {
                w.write_u8(NMT_HANDSHAKE_RESPONSE);
                w.write_u32(*crc_response);
            }
            Self::HandshakeComplete => {
                w.write_u8(NMT_HANDSHAKE_COMPLETE);
            }
            Self::Redirect { redirect_addr } => {
                w.write_u8(NMT_REDIRECT);
                w.write_fstring(redirect_addr);
            }
            Self::ClientAuthRequest {
                server_steam_id,
                param_a,
                param_b,
                param_c,
                param_d,
            } => {
                w.write_u8(NMT_CLIENT_AUTH_REQUEST);
                w.write_u64(*server_steam_id);
                w.write_u32(*param_a);
                w.write_u32(*param_b);
                w.write_u32(*param_c);
                w.write_u32(*param_d);
            }
            Self::ServerAuthRequest => {
                w.write_u8(NMT_SERVER_AUTH_REQUEST);
            }
            Self::MarshalPackage { total_size, chunk } => {
                w.write_u8(NMT_MARSHAL_PACKAGE);
                if let Some(total) = total_size {
                    w.write_int(*total, 0x80000)?;
                }
                w.write_int(chunk.len() as u32, 0x200)?;
                w.write_bytes(chunk);
            }
            Self::PlayTime { play_time } => {
                w.write_u8(NMT_PLAY_TIME);
                w.write_u32(*play_time);
            }
            Self::MapLoaded => {
                w.write_u8(NMT_MAP_LOADED);
            }
            Self::TimeLapse { param_a, param_b } => {
                w.write_u8(NMT_TIME_LAPSE);
                w.write_u32(*param_a);
                w.write_u32(*param_b);
            }
            Self::UsesOpt {
                guid,
                package_name,
                package_flags,
                cached_ext_index,
            } => {
                w.write_u8(NMT_USES_OPT);
                for &part in guid {
                    w.write_u32(part);
                }
                w.write_fstring(package_name);
                w.write_u32(*package_flags);
                w.write_i32(*cached_ext_index);
            }
            Self::UsesOptEx {
                guid,
                package_name,
                package_flags,
                gen_or_flags,
                extension_or_parent,
            } => {
                w.write_u8(NMT_USES_OPT_EX);
                for &part in guid {
                    w.write_u32(part);
                }
                w.write_fstring(package_name);
                w.write_u32(*package_flags);
                w.write_i32(*gen_or_flags);
                w.write_fstring(extension_or_parent);
            }
        }
        Ok(())
    }

    /// Serializes control message into bunch payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let (bytes, _) = self
            .try_encode_bits()
            .expect("ControlMessage payload exceeds UE3 SerializeInt bounds");
        bytes
    }

    /// Returns the wire opcode for this control message.
    pub fn opcode(&self) -> u8 {
        match self {
            Self::Hello { .. } => NMT_HELLO,
            Self::Welcome { .. } => NMT_WELCOME,
            Self::Upgrade { .. } => NMT_UPGRADE,
            Self::Challenge { .. } => NMT_CHALLENGE,
            Self::NetSpeed { .. } => NMT_NETSPEED,
            Self::Login { .. } => NMT_LOGIN,
            Self::Failure { .. } => NMT_FAILURE,
            Self::Uses { .. } => NMT_USES,
            Self::Have { .. } => NMT_HAVE,
            Self::Join => NMT_JOIN,
            Self::ActorChannelFailure { .. } => NMT_ACTOR_CHANNEL_FAILURE,
            Self::HandshakeStart { .. } => NMT_HANDSHAKE_START,
            Self::HandshakeChallenge { .. } => NMT_HANDSHAKE_CHALLENGE,
            Self::HandshakeResponse { .. } => NMT_HANDSHAKE_RESPONSE,
            Self::HandshakeComplete => NMT_HANDSHAKE_COMPLETE,
            Self::Redirect { .. } => NMT_REDIRECT,
            Self::ClientAuthRequest { .. } => NMT_CLIENT_AUTH_REQUEST,
            Self::ServerAuthRequest => NMT_SERVER_AUTH_REQUEST,
            Self::MarshalPackage { .. } => NMT_MARSHAL_PACKAGE,
            Self::PlayTime { .. } => NMT_PLAY_TIME,
            Self::MapLoaded => NMT_MAP_LOADED,
            Self::TimeLapse { .. } => NMT_TIME_LAPSE,
            Self::UsesOpt { .. } => NMT_USES_OPT,
            Self::UsesOptEx { .. } => NMT_USES_OPT_EX,
        }
    }

    /// Decodes a `NMT_MarshalPackage (0x27)` message with explicit reassembly state.
    pub fn decode_marshal_package_with_state(
        reader: &mut BitReader<'_>,
        is_start: bool,
    ) -> Result<Self, NetError> {
        let total_size = if is_start {
            Some(reader.read_int(0x80000)?)
        } else {
            None
        };
        let chunk_size = reader.read_int(0x200)? as usize;
        let chunk = reader.read_bytes(chunk_size)?;
        Ok(Self::MarshalPackage { total_size, chunk })
    }

    fn decode_from_reader(reader: &mut BitReader<'_>) -> Result<Self, NetError> {
        let opcode = reader.read_u8()?;
        match opcode {
            NMT_HELLO => {
                let min_net_ver = reader.read_u32()?;
                let net_ver = reader.read_u32()?;
                let is_little_endian = reader.read_u32()?;
                Ok(Self::Hello {
                    min_net_ver,
                    net_ver,
                    is_little_endian,
                })
            }
            NMT_WELCOME => {
                let level_name = reader.read_fstring()?;
                let game_name = reader.read_fstring()?;
                Ok(Self::Welcome {
                    level_name,
                    game_name,
                })
            }
            NMT_UPGRADE => {
                let remote_net_ver = reader.read_u32()?;
                let remote_net_features = reader.read_u32()?;
                Ok(Self::Upgrade {
                    remote_net_ver,
                    remote_net_features,
                })
            }
            NMT_CHALLENGE => {
                let challenge_id = reader.read_u32()?;
                let challenge = reader.read_fstring()?;
                Ok(Self::Challenge {
                    challenge_id,
                    challenge,
                })
            }
            NMT_NETSPEED => {
                let rate = reader.read_u32()?;
                Ok(Self::NetSpeed { rate })
            }
            NMT_LOGIN => {
                let client_response = reader.read_fstring()?;
                let url = reader.read_fstring()?;
                let unique_id = reader.read_u64()?;
                let portal_id = reader.read_u64()?;
                Ok(Self::Login {
                    client_response,
                    url,
                    unique_id,
                    portal_id,
                })
            }
            NMT_FAILURE => {
                let reason = reader.read_fstring()?;
                Ok(Self::Failure { reason })
            }
            NMT_USES => {
                let guid = [
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                ];
                let package_name = reader.read_fstring()?;
                let extension = reader.read_fstring()?;
                let url = reader.read_fstring()?;
                let package_flags = reader.read_u32()?;
                let remote_generation = reader.read_u32()?;
                let local_package_name = reader.read_fstring()?;
                let loading_from_cache = reader.read_u8()?;
                Ok(Self::Uses {
                    guid,
                    package_name,
                    extension,
                    url,
                    package_flags,
                    remote_generation,
                    local_package_name,
                    loading_from_cache,
                })
            }
            NMT_HAVE => {
                let guid = [
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                ];
                let generation = reader.read_i32()?;
                Ok(Self::Have { guid, generation })
            }
            NMT_JOIN => Ok(Self::Join),
            NMT_ACTOR_CHANNEL_FAILURE => {
                let ch_index = reader.read_i32()?;
                Ok(Self::ActorChannelFailure { ch_index })
            }
            NMT_HANDSHAKE_START => {
                let platform_flag = reader.read_u32()?;
                Ok(Self::HandshakeStart { platform_flag })
            }
            NMT_HANDSHAKE_CHALLENGE => {
                let challenge = reader.read_u32()?;
                Ok(Self::HandshakeChallenge { challenge })
            }
            NMT_HANDSHAKE_RESPONSE => {
                let crc_response = reader.read_u32()?;
                Ok(Self::HandshakeResponse { crc_response })
            }
            NMT_HANDSHAKE_COMPLETE => Ok(Self::HandshakeComplete),
            NMT_REDIRECT => {
                let redirect_addr = reader.read_fstring()?;
                Ok(Self::Redirect { redirect_addr })
            }
            NMT_CLIENT_AUTH_REQUEST => {
                let server_steam_id = reader.read_u64()?;
                let param_a = reader.read_u32()?;
                let param_b = reader.read_u32()?;
                let param_c = reader.read_u32()?;
                let param_d = reader.read_u32()?;
                Ok(Self::ClientAuthRequest {
                    server_steam_id,
                    param_a,
                    param_b,
                    param_c,
                    param_d,
                })
            }
            NMT_SERVER_AUTH_REQUEST => Ok(Self::ServerAuthRequest),
            NMT_MARSHAL_PACKAGE => {
                let rem = reader.bits_left();
                if rem >= 28 && (rem % 8) == 4 {
                    Self::decode_marshal_package_with_state(reader, true)
                } else if rem >= 9 && (rem % 8) == 1 {
                    Self::decode_marshal_package_with_state(reader, false)
                } else {
                    // Byte-padded standalone payload fallback: probe start vs continuation chunk
                    let mut probe_start = reader.clone();
                    if rem >= 32 {
                        if let Ok(Self::MarshalPackage { total_size, chunk }) =
                            Self::decode_marshal_package_with_state(&mut probe_start, true)
                        {
                            if probe_start.bits_left() == 4 {
                                let _ = probe_start.read_bits(4)?;
                                *reader = probe_start;
                                return Ok(Self::MarshalPackage { total_size, chunk });
                            }
                        }
                    }
                    let mut probe_cont = reader.clone();
                    let msg = Self::decode_marshal_package_with_state(&mut probe_cont, false)?;
                    if probe_cont.bits_left() == 7 {
                        let _ = probe_cont.read_bits(7)?;
                    }
                    *reader = probe_cont;
                    Ok(msg)
                }
            }
            NMT_PLAY_TIME => {
                let play_time = reader.read_u32()?;
                Ok(Self::PlayTime { play_time })
            }
            NMT_MAP_LOADED => Ok(Self::MapLoaded),
            NMT_TIME_LAPSE => {
                let param_a = reader.read_u32()?;
                let param_b = reader.read_u32()?;
                Ok(Self::TimeLapse { param_a, param_b })
            }
            NMT_USES_OPT => {
                let guid = [
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                ];
                let package_name = reader.read_fstring()?;
                let package_flags = reader.read_u32()?;
                let cached_ext_index = reader.read_i32()?;
                Ok(Self::UsesOpt {
                    guid,
                    package_name,
                    package_flags,
                    cached_ext_index,
                })
            }
            NMT_USES_OPT_EX => {
                let guid = [
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                ];
                let package_name = reader.read_fstring()?;
                let package_flags = reader.read_u32()?;
                let gen_or_flags = reader.read_i32()?;
                let extension_or_parent = reader.read_fstring()?;
                Ok(Self::UsesOptEx {
                    guid,
                    package_name,
                    package_flags,
                    gen_or_flags,
                    extension_or_parent,
                })
            }
            other => Err(NetError::InvalidUdpPacket(format!(
                "Unknown Control Message opcode 0x{:02x}",
                other
            ))),
        }
    }

    /// Deserializes a single control message from byte-aligned payload bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        if payload.is_empty() {
            return Err(NetError::PacketTooSmall {
                expected: 1,
                actual: 0,
            });
        }
        let mut reader = BitReader::new(payload, payload.len() * 8)?;
        Self::decode_from_reader(&mut reader)
    }

    /// Deserializes all concatenated control messages packed inside a Channel 0 bunch.
    /// Returns `Ok(vec![])` when `num_bits == 0` (e.g. empty `bClose = true` bunch).
    pub fn decode_all(payload: &[u8], num_bits: usize) -> Result<Vec<Self>, NetError> {
        if num_bits == 0 {
            return Ok(Vec::new());
        }
        let mut reader = BitReader::new(payload, num_bits)?;
        let mut messages = Vec::new();
        while !reader.at_end() {
            messages.push(Self::decode_from_reader(&mut reader)?);
        }
        Ok(messages)
    }
}

// ============================================================================
// Staged Channel 0 Handshake State Machine (7-Stage Paladins Cadence)
// ============================================================================

/// Staged Paladins Control Channel handshake lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    AwaitingHandshakeStart,
    ChallengeSent,
    HandshakeComplete,
    AuthRequested,
    AwaitingLogin,
    Welcomed,
    Joined,
}

/// State machine driving the complete 7-stage Paladins UE3 Channel 0 handshake:
/// `0x1A -> 0x1B -> 0x1C (CRC) -> 0x1D -> 0x20 -> 0x1F(0) -> 0x00 -> 0x03 -> 0x04/0x05 -> 0x01 -> 0x09`.
#[derive(Debug, Clone)]
pub struct ControlChannelHandshake {
    pub phase: HandshakePhase,
    pub level_name: String,
    pub game_name: String,
    pub net_speed: u32,
    pub handshake_challenge: u32,
    pub platform_flag: u32,
    pub client_min_net_version: u32,
    pub client_net_version: u32,
    pub client_is_little_endian: u32,
    pub client_login_url: String,
    pub client_unique_id: u64,
    pub client_portal_id: u64,
}

impl Default for ControlChannelHandshake {
    fn default() -> Self {
        Self {
            phase: HandshakePhase::AwaitingHandshakeStart,
            level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
            game_name: DEFAULT_GAME_CLASS.to_string(),
            net_speed: DEFAULT_NET_SPEED,
            handshake_challenge: DEFAULT_HANDSHAKE_CHALLENGE,
            platform_flag: 0,
            client_min_net_version: 0,
            client_net_version: 0,
            client_is_little_endian: 1,
            client_login_url: String::new(),
            client_unique_id: 0,
            client_portal_id: 0,
        }
    }
}

impl ControlChannelHandshake {
    pub fn new(level_name: Option<&str>, game_name: Option<&str>, net_speed: Option<u32>) -> Self {
        Self {
            level_name: level_name
                .unwrap_or(DEFAULT_SHOOTING_RANGE_LEVEL)
                .to_string(),
            game_name: game_name.unwrap_or(DEFAULT_GAME_CLASS).to_string(),
            net_speed: net_speed.unwrap_or(DEFAULT_NET_SPEED),
            ..Self::default()
        }
    }

    /// Overrides the handshake challenge nonce used in `NMT_HandshakeChallenge (0x1B)`.
    pub fn with_challenge(mut self, challenge: u32) -> Self {
        self.handshake_challenge = challenge;
        self
    }

    /// Ingests an incoming Channel 0 `ControlMessage` and returns the ordered server replies.
    pub fn handle_control_message(
        &mut self,
        msg: &ControlMessage,
    ) -> Result<Vec<ControlMessage>, NetError> {
        match msg {
            ControlMessage::HandshakeStart { platform_flag } => {
                self.platform_flag = *platform_flag;
                self.phase = HandshakePhase::ChallengeSent;
                Ok(vec![ControlMessage::HandshakeChallenge {
                    challenge: self.handshake_challenge,
                }])
            }
            ControlMessage::HandshakeResponse { crc_response } => {
                let expected = ue3_handshake_crc(self.handshake_challenge);
                if *crc_response != expected {
                    return Err(NetError::BunchError(format!(
                        "NMT_HandshakeResponse CRC mismatch: expected 0x{:08x}, got 0x{:08x}",
                        expected, crc_response
                    )));
                }
                self.phase = HandshakePhase::HandshakeComplete;
                Ok(vec![ControlMessage::HandshakeComplete])
            }
            ControlMessage::ServerAuthRequest => {
                self.phase = HandshakePhase::AuthRequested;
                Ok(vec![ControlMessage::client_auth_request_bypass()])
            }
            ControlMessage::Hello {
                min_net_ver,
                net_ver,
                is_little_endian,
            } => {
                self.client_min_net_version = *min_net_ver;
                self.client_net_version = *net_ver;
                self.client_is_little_endian = *is_little_endian;
                self.phase = HandshakePhase::AwaitingLogin;
                Ok(vec![ControlMessage::Challenge {
                    challenge_id: 0,
                    challenge: "IMMORTAL".to_string(),
                }])
            }
            ControlMessage::NetSpeed { rate } => {
                self.net_speed = *rate;
                Ok(Vec::new())
            }
            ControlMessage::Login {
                client_response: _,
                url,
                unique_id,
                portal_id,
            } => {
                self.client_login_url = url.clone();
                self.client_unique_id = *unique_id;
                self.client_portal_id = *portal_id;
                self.phase = HandshakePhase::Welcomed;
                Ok(vec![ControlMessage::Welcome {
                    level_name: self.level_name.clone(),
                    game_name: self.game_name.clone(),
                }])
            }
            ControlMessage::Join => {
                self.phase = HandshakePhase::Joined;
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_PREFIX: [u8; 6] = [0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6];

    #[test]
    fn test_flight034_packets_0_1_2_bit_exact_roundtrip() {
        // Packet 0: InPacketId=0, Ch0(Control, Open=1, Rel=1, Seq=1, 40b) NMT_HandshakeStart(0x40)
        let pkt0: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x00, 0x80, 0x05, 0x40, 0x00, 0x41, 0x01, 0x1A,
            0x40, 0x00, 0x00, 0x00, 0x01,
        ];
        let d0 = Ue3Packet::decode(pkt0).expect("decode Flight 034 pkt0");
        assert_eq!(d0.pcom_prefix, SYNTHETIC_PREFIX);
        assert_eq!(d0.packet_id, 0);
        assert!(d0.acks.is_empty());
        assert_eq!(d0.bunches.len(), 1);
        let b0 = &d0.bunches[0];
        assert!(b0.header.flags.b_open);
        assert!(!b0.header.flags.b_close);
        assert!(b0.header.flags.b_reliable);
        assert_eq!(b0.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(b0.header.ch_sequence, 1);
        assert_eq!(b0.header.ch_type, Ue3ChannelType::Control);
        assert_eq!(b0.num_bits, 40);
        let msgs0 = ControlMessage::decode_all(&b0.data, b0.num_bits).unwrap();
        assert_eq!(
            msgs0,
            vec![ControlMessage::HandshakeStart {
                platform_flag: 0x40
            }]
        );
        assert_eq!(d0.encode().unwrap(), pkt0);

        // Packet 1: InPacketId=1, ACKs=[1,2,3], Ch0(Control, Close=1, Rel=1, Seq=2, 0b)
        let pkt1: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x01, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0xD0,
            0x00, 0x10, 0x20, 0x00, 0x20,
        ];
        let d1 = Ue3Packet::decode(pkt1).expect("decode Flight 034 pkt1");
        assert_eq!(d1.packet_id, 1);
        assert_eq!(d1.acks, vec![1, 2, 3]);
        assert_eq!(d1.bunches.len(), 1);
        let b1 = &d1.bunches[0];
        assert!(!b1.header.flags.b_open);
        assert!(b1.header.flags.b_close);
        assert!(b1.header.flags.b_reliable);
        assert_eq!(b1.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(b1.header.ch_sequence, 2);
        assert_eq!(b1.header.ch_type, Ue3ChannelType::Control);
        assert_eq!(b1.num_bits, 0);
        assert!(ControlMessage::decode_all(&b1.data, b1.num_bits)
            .unwrap()
            .is_empty());
        assert_eq!(d1.encode().unwrap(), pkt1);

        // Packet 2: InPacketId=2, ACKs=[1,2,3,4,5], Bunches=[]
        let pkt2: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x02, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0x48,
            0x00, 0x2C, 0x00, 0x02,
        ];
        let d2 = Ue3Packet::decode(pkt2).expect("decode Flight 034 pkt2");
        assert_eq!(d2.packet_id, 2);
        assert_eq!(d2.acks, vec![1, 2, 3, 4, 5]);
        assert!(d2.bunches.is_empty());
        assert_eq!(d2.encode().unwrap(), pkt2);
    }

    #[test]
    fn test_variable_width_length_lt_512_welcome_and_ge_512_login() {
        // Bare NMT_Welcome: 1 + (4 + 16) + (4 + 37) = 62 bytes = 496 bits (< 512 -> 13-bit len)
        let welcome = ControlMessage::Welcome {
            level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
            game_name: DEFAULT_GAME_CLASS.to_string(),
        };
        let welcome_bytes = welcome.encode();
        assert_eq!(welcome_bytes.len() * 8, 496);
        let mut w_pkt = Ue3Packet::new(SYNTHETIC_PREFIX, 4);
        w_pkt.acks.push(4);
        w_pkt.bunches.push(Bunch::control(5, welcome_bytes));
        let wire_w = w_pkt.encode().unwrap();
        // Total data bits: 14(PktId) + 15(ACK) + (1+1+1+11+10+3+13)(40b bunch hdr) + 496 = 565 bits
        let bits_w = strip_stop_bit(&wire_w[PCOM_PREFIX_LEN..]).unwrap();
        assert_eq!(bits_w, 14 + 15 + 40 + 496);
        let dec_w = Ue3Packet::decode(&wire_w).unwrap();
        assert_eq!(dec_w, w_pkt);
        assert_eq!(
            ControlMessage::decode_all(&dec_w.bunches[0].data, dec_w.bunches[0].num_bits).unwrap(),
            vec![welcome]
        );

        // NMT_Login with 2x u64 (>= 512 bits -> 12-bit len -> 39-bit bunch hdr including IsAck)
        let login = ControlMessage::Login {
            client_response: "0".to_string(),
            url: "Shootingrange_P?Name=Player?Team=0?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0".to_string(),
            unique_id: 8_302_401,
            portal_id: 0x0186_0000_8246_2A8F,
        };
        let login_bytes = login.encode();
        let login_bits = login_bytes.len() * 8;
        assert!(login_bits >= 512, "Expected >=512 bits, got {}", login_bits);
        let mut l_pkt = Ue3Packet::new(SYNTHETIC_PREFIX, 5);
        l_pkt.bunches.push(Bunch::control(6, login_bytes));
        let wire_l = l_pkt.encode().unwrap();
        // Total data bits: 14(PktId) + (1+1+1+11+10+3+12)(39b bunch hdr) + login_bits
        let bits_l = strip_stop_bit(&wire_l[PCOM_PREFIX_LEN..]).unwrap();
        assert_eq!(bits_l, 14 + 39 + login_bits);
        let dec_l = Ue3Packet::decode(&wire_l).unwrap();
        assert_eq!(dec_l, l_pkt);
        assert_eq!(
            ControlMessage::decode_all(&dec_l.bunches[0].data, dec_l.bunches[0].num_bits).unwrap(),
            vec![login]
        );
    }

    #[test]
    fn test_exudp_3968_bit_roundtrip_and_multi_bunch_packet() {
        let netspeed = ControlMessage::NetSpeed { rate: 24000 };
        let login = ControlMessage::Login {
            client_response: "0".to_string(),
            url: "Shootingrange_P?Name=Player?Team=0".to_string(),
            unique_id: 42,
            portal_id: 99,
        };

        let mut pkt = Ue3Packet::new(SYNTHETIC_PREFIX, 4);
        pkt.acks.push(3);
        pkt.bunches.push(Bunch::control(5, netspeed.encode()));
        pkt.bunches.push(Bunch::control(6, login.encode()));

        // Standard 4608-bit roundtrip
        let wire_std = pkt.encode().unwrap();
        let dec_std = Ue3Packet::decode(&wire_std).unwrap();
        assert_eq!(dec_std, pkt);
        assert_eq!(dec_std.bunches.len(), 2);

        // Alternate ?exudp>=1 3968-bit roundtrip
        let wire_ex = pkt.encode_with_max_bits(EXUDP_MAX_PACKET_BITS).unwrap();
        let dec_ex = Ue3Packet::decode_with_max_bits(&wire_ex, EXUDP_MAX_PACKET_BITS).unwrap();
        assert_eq!(dec_ex, pkt);
    }

    #[test]
    fn test_bunch_standalone_and_cpack_udp_roundtrip() {
        let ctrl = Bunch::control(1, ControlMessage::NetSpeed { rate: 24000 }.encode());
        assert!(!ctrl.header.flags.b_open);
        assert!(ctrl.header.flags.b_reliable);
        let enc = ctrl.encode().unwrap();
        let dec = Bunch::decode(&enc).unwrap();
        assert_eq!(dec, ctrl);

        let actor = Bunch::actor(1, true, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(actor.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(actor.header.ch_type, Ue3ChannelType::Actor);
        let udp_framed = actor.encode_cpack_udp().unwrap();
        assert_eq!(udp_framed[0], CPACK_OP_BUNCH);
        let dec_actor = Bunch::decode_cpack_udp(&udp_framed).unwrap();
        assert_eq!(dec_actor, actor);
    }

    #[test]
    fn test_full_seven_stage_handshake_and_crc_rejection() {
        // Exercise negative signed i32 challenge (0xDEAD_BEEF = -559038737)
        let challenge = 0xDEAD_BEEF;
        let mut hs = ControlChannelHandshake::default().with_challenge(challenge);
        assert_eq!(hs.phase, HandshakePhase::AwaitingHandshakeStart);

        // Stage 1: HandshakeStart -> HandshakeChallenge
        let r1 = hs
            .handle_control_message(&ControlMessage::HandshakeStart {
                platform_flag: 0x40,
            })
            .unwrap();
        assert_eq!(hs.phase, HandshakePhase::ChallengeSent);
        assert_eq!(r1, vec![ControlMessage::HandshakeChallenge { challenge }]);

        // Reject wrong CRC without advancing state
        let bad = hs.handle_control_message(&ControlMessage::HandshakeResponse {
            crc_response: ue3_handshake_crc(challenge) ^ 1,
        });
        assert!(bad.is_err());
        assert_eq!(hs.phase, HandshakePhase::ChallengeSent);

        // Stage 2: Valid signed %d HandshakeResponse -> HandshakeComplete
        let r2 = hs
            .handle_control_message(&ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(challenge),
            })
            .unwrap();
        assert_eq!(hs.phase, HandshakePhase::HandshakeComplete);
        assert_eq!(r2, vec![ControlMessage::HandshakeComplete]);

        // Stage 3: ServerAuthRequest -> ClientAuthRequest(ServerSteamId = 0)
        let r3 = hs
            .handle_control_message(&ControlMessage::ServerAuthRequest)
            .unwrap();
        assert_eq!(hs.phase, HandshakePhase::AuthRequested);
        assert_eq!(r3, vec![ControlMessage::client_auth_request_bypass()]);

        // Stage 4: Hello -> Challenge
        let r4 = hs
            .handle_control_message(&ControlMessage::Hello {
                min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
                net_ver: DEFAULT_ENGINE_NET_VERSION,
                is_little_endian: 1,
            })
            .unwrap();
        assert_eq!(hs.phase, HandshakePhase::AwaitingLogin);
        assert_eq!(
            r4,
            vec![ControlMessage::Challenge {
                challenge_id: 0,
                challenge: "IMMORTAL".to_string(),
            }]
        );

        // Stage 5: NetSpeed -> records speed, 0 replies
        let r5 = hs
            .handle_control_message(&ControlMessage::NetSpeed { rate: 48000 })
            .unwrap();
        assert!(r5.is_empty());
        assert_eq!(hs.net_speed, 48000);

        // Stage 6: Login -> bare NMT_Welcome("Shootingrange_P", "TgGame.TgGame_Paladins_ShootingRange")
        let r6 = hs
            .handle_control_message(&ControlMessage::Login {
                client_response: "0".to_string(),
                url: "Shootingrange_P?Name=Player".to_string(),
                unique_id: 10001,
                portal_id: 20002,
            })
            .unwrap();
        assert_eq!(hs.phase, HandshakePhase::Welcomed);
        assert_eq!(
            r6,
            vec![ControlMessage::Welcome {
                level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
                game_name: DEFAULT_GAME_CLASS.to_string(),
            }]
        );

        // Stage 7: Join -> Joined
        let r7 = hs.handle_control_message(&ControlMessage::Join).unwrap();
        assert_eq!(hs.phase, HandshakePhase::Joined);
        assert!(r7.is_empty());
    }

    #[test]
    fn test_nmt_map_loaded_roundtrip() {
        let msg = ControlMessage::MapLoaded;
        assert_eq!(msg.opcode(), NMT_MAP_LOADED);
        let encoded = msg.encode();
        assert_eq!(encoded, vec![NMT_MAP_LOADED]);

        let decoded = ControlMessage::decode(&encoded).expect("decode MapLoaded");
        assert_eq!(decoded, ControlMessage::MapLoaded);
        assert_eq!(decoded.opcode(), NMT_MAP_LOADED);

        let bunch_data = encoded.clone();
        let msgs = ControlMessage::decode_all(&bunch_data, bunch_data.len() * 8)
            .expect("decode_all MapLoaded");
        assert_eq!(msgs, vec![ControlMessage::MapLoaded]);
    }

    #[test]
    fn test_dedicated_10byte_prefix_packet_roundtrip() {
        let dedicated_prefix: [u8; 10] = [
            0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01,
        ];
        let mut pkt = Ue3Packet::new_with_prefix(
            PcomPrefix::from(dedicated_prefix),
            42,
        );
        pkt.acks.push(10);
        pkt.bunches.push(Bunch::control(
            1,
            ControlMessage::MapLoaded.encode(),
        ));

        let encoded = pkt.encode().expect("encode dedicated packet");
        assert!(encoded.len() >= 11);
        assert_eq!(&encoded[..10], &dedicated_prefix);

        let decoded = Ue3Packet::decode(&encoded).expect("decode dedicated packet");
        assert_eq!(decoded.pcom_prefix, PcomPrefix::from(dedicated_prefix));
        assert_eq!(decoded.pcom_prefix.len(), 10);
        assert_eq!(decoded.pcom_prefix.to_bytes().as_slice(), &dedicated_prefix);
        assert_eq!(decoded.packet_id, 42);
        assert_eq!(decoded.acks, vec![10]);
        assert_eq!(decoded.bunches.len(), 1);

        let msgs = ControlMessage::decode_all(
            &decoded.bunches[0].data,
            decoded.bunches[0].num_bits,
        )
        .expect("decode control messages from bunch");
        assert_eq!(msgs, vec![ControlMessage::MapLoaded]);

        let reencoded = decoded.encode().expect("re-encode dedicated packet");
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_dedicated_10byte_prefix_unsequenced_0010_rejection() {
        // [0x00, 0x10] unsequenced / control frame must return NetError::UnsequencedControlFrame
        let unseq_wire: [u8; 10] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        let err = Ue3Packet::decode(&unseq_wire).unwrap_err();
        match err {
            NetError::UnsequencedControlFrame { magic, subflags, len } => {
                assert_eq!(magic, [0x01, 0x00, 0x00, 0x00]);
                assert_eq!(subflags, 0x0010);
                assert_eq!(len, 10);
            }
            other => panic!("Expected UnsequencedControlFrame, got {:?}", other),
        }
    }

    #[test]
    fn test_dedicated_1440b_mtu_roundtrip() {
        let dedicated_prefix: [u8; 10] = [
            0x01, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut pkt = Ue3Packet::new_with_prefix(
            PcomPrefix::from(dedicated_prefix),
            1337,
        );
        pkt.acks.push(99);

        // Build a large bunch filling up toward 1440-byte MTU buffer (e.g. 1200 bytes)
        let large_payload = vec![0xA5; 1200];
        pkt.bunches.push(Bunch::actor(5, false, large_payload.clone()));

        // Encode with 1440-byte MTU ladder (11520 bits)
        let encoded = pkt
            .encode_with_max_bits(MAX_ALLOWED_PACKET_BITS)
            .expect("encode large dedicated packet");
        assert!(encoded.len() > 1200);
        assert_eq!(&encoded[..10], &dedicated_prefix);

        // Decoding with 576-byte MTU must fail with PayloadTooLarge
        let err_default = Ue3Packet::decode(&encoded).unwrap_err();
        match err_default {
            NetError::PayloadTooLarge { length, max } => {
                assert!(length > max);
                assert_eq!(max, DEFAULT_MAX_PACKET_BITS / 8);
            }
            other => panic!("Expected PayloadTooLarge, got {:?}", other),
        }

        // Decoding with 1440-byte MTU must succeed
        let decoded = Ue3Packet::decode_with_max_bits(&encoded, MAX_ALLOWED_PACKET_BITS)
            .expect("decode large dedicated packet with 11520 bits");
        assert_eq!(decoded.pcom_prefix, PcomPrefix::from(dedicated_prefix));
        assert_eq!(decoded.packet_id, 1337);
        assert_eq!(decoded.acks, vec![99]);
        assert_eq!(decoded.bunches.len(), 1);
        assert_eq!(decoded.bunches[0].data, large_payload);

        let reencoded = decoded
            .encode_with_max_bits(MAX_ALLOWED_PACKET_BITS)
            .expect("re-encode large dedicated packet");
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_dedicated_sequenced_seq1_session_token_and_seq2_roundtrip() {
        let token = [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F];
        let mut pkt_seq1 = Ue3Packet::new_with_prefix(
            PcomPrefix::dedicated_sequenced(1, Some(token)),
            100,
        );
        pkt_seq1.bunches.push(Bunch::control(1, ControlMessage::MapLoaded.encode()));

        let enc_seq1 = pkt_seq1
            .encode_with_max_bits(EXUDP_MAX_PACKET_BITS)
            .expect("encode seq1");
        assert_eq!(&enc_seq1[..10], &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&enc_seq1[10..16], &token);

        let dec_seq1 = Ue3Packet::decode_with_max_bits(&enc_seq1, EXUDP_MAX_PACKET_BITS)
            .expect("decode seq1");
        assert_eq!(dec_seq1.pcom_prefix, PcomPrefix::dedicated_sequenced(1, Some(token)));
        assert_eq!(dec_seq1.pcom_prefix.session_token(), Some(&token));
        assert_eq!(dec_seq1.pcom_prefix.sequence(), Some(1));
        assert_eq!(dec_seq1.packet_id, 100);
        assert_eq!(dec_seq1.bunches.len(), 1);
        assert_eq!(dec_seq1.encode_pcom(EXUDP_MAX_PACKET_BITS).unwrap(), enc_seq1);

        // Seq 2 roundtrip (no session token)
        let mut pkt_seq2 = Ue3Packet::new_with_prefix(
            PcomPrefix::dedicated_sequenced(2, None),
            101,
        );
        pkt_seq2.acks.push(100);
        pkt_seq2.bunches.push(Bunch::control(2, ControlMessage::Join.encode()));

        let enc_seq2 = pkt_seq2
            .encode_with_max_bits(EXUDP_MAX_PACKET_BITS)
            .expect("encode seq2");
        assert_eq!(&enc_seq2[..10], &[0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(enc_seq2.len(), 10 + (enc_seq2.len() - 10));

        let dec_seq2 = Ue3Packet::decode_with_max_bits(&enc_seq2, EXUDP_MAX_PACKET_BITS)
            .expect("decode seq2");
        assert_eq!(dec_seq2.pcom_prefix, PcomPrefix::dedicated_sequenced(2, None));
        assert_eq!(dec_seq2.pcom_prefix.session_token(), None);
        assert_eq!(dec_seq2.pcom_prefix.sequence(), Some(2));
        assert_eq!(dec_seq2.packet_id, 101);
        assert_eq!(dec_seq2.acks, vec![100]);
        assert_eq!(dec_seq2.bunches.len(), 1);
        assert_eq!(dec_seq2.encode_pcom(EXUDP_MAX_PACKET_BITS).unwrap(), enc_seq2);
    }

    #[test]
    fn test_extended_control_messages_roundtrip() {
        let messages = [
            ControlMessage::Uses {
                guid: [0x1122_3344, 0x5566_7788, 0x99AA_BBCC, 0xDDEE_FF00],
                package_name: "Shootingrange_P".to_string(),
                extension: "upk".to_string(),
                url: "Shootingrange_P?Name=Player".to_string(),
                package_flags: 0x0000_0001,
                remote_generation: 3,
                local_package_name: "Shootingrange_P".to_string(),
                loading_from_cache: 1,
            },
            ControlMessage::Have {
                guid: [0xAABB_CCDD, 0x1234_5678, 0x9ABC_DEF0, 0x0F1E_2D3C],
                generation: 42,
            },
            ControlMessage::MarshalPackage {
                total_size: Some(920),
                chunk: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
            },
            ControlMessage::MarshalPackage {
                total_size: None,
                chunk: vec![0xCA, 0xFE, 0xBA, 0xBE],
            },
            ControlMessage::PlayTime { play_time: 123456 },
            ControlMessage::TimeLapse {
                param_a: 1000,
                param_b: 2000,
            },
            ControlMessage::UsesOpt {
                guid: [1, 2, 3, 4],
                package_name: "TgClient".to_string(),
                package_flags: 0x40,
                cached_ext_index: -1,
            },
            ControlMessage::UsesOptEx {
                guid: [5, 6, 7, 8],
                package_name: "Startup".to_string(),
                package_flags: 0x80,
                gen_or_flags: 7,
                extension_or_parent: "upk".to_string(),
            },
        ];

        for (idx, msg) in messages.iter().enumerate() {
            let encoded = msg.encode();
            assert_eq!(encoded[0], msg.opcode());
            let decoded = ControlMessage::decode(&encoded).unwrap_or_else(|e| {
                panic!("Failed standalone decode for msg #{} ({:?}): {:?}", idx, msg, e)
            });
            assert_eq!(&decoded, msg, "Standalone roundtrip mismatch for msg #{}", idx);

            // Bit-exact Ue3Packet / Bunch roundtrip
            let (raw_bits, num_bits) = msg.try_encode_bits().unwrap();
            let mut pkt = Ue3Packet::new(SYNTHETIC_PREFIX, idx as u16);
            pkt.bunches.push(Bunch::with_bits(
                BunchHeader {
                    ch_index: CONTROL_CHANNEL_INDEX,
                    ch_type: Ue3ChannelType::Control,
                    flags: BunchFlags {
                        b_open: false,
                        b_close: false,
                        b_reliable: true,
                        b_partial: false,
                    },
                    ch_sequence: (idx as u32) + 1,
                },
                num_bits,
                raw_bits,
            ));
            let wire = pkt.encode().unwrap();
            let dec_pkt = Ue3Packet::decode(&wire).unwrap();
            let dec_msgs = ControlMessage::decode_all(
                &dec_pkt.bunches[0].data,
                dec_pkt.bunches[0].num_bits,
            )
            .unwrap();
            assert_eq!(dec_msgs, vec![msg.clone()]);
        }
    }
}
