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
    pub pcom_prefix: [u8; PCOM_PREFIX_LEN],
    pub packet_id: u16,
    pub acks: Vec<u16>,
    pub bunches: Vec<Bunch>,
}

impl Ue3Packet {
    /// Creates a new `Ue3Packet` with the given 6-byte outer prefix and 14-bit `packet_id`.
    pub fn new(pcom_prefix: [u8; PCOM_PREFIX_LEN], packet_id: u16) -> Self {
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

    /// Encodes the packet with an explicit `max_packet_bits` (`4608` standard UDP or `3968` `?exudp>=1`).
    pub fn encode_with_max_bits(&self, max_packet_bits: usize) -> Result<Vec<u8>, NetError> {
        if max_packet_bits == 0 || max_packet_bits > DEFAULT_MAX_PACKET_BITS {
            return Err(NetError::BunchError(format!(
                "max_packet_bits {} out of bounds (1..={})",
                max_packet_bits, DEFAULT_MAX_PACKET_BITS
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
        let mut out = Vec::with_capacity(PCOM_PREFIX_LEN + ue3_bytes.len());
        out.extend_from_slice(&self.pcom_prefix);
        out.extend_from_slice(&ue3_bytes);
        Ok(out)
    }

    /// Decodes a `PComNetConn` UDP datagram using `DEFAULT_MAX_PACKET_BITS` (`4608` bits).
    pub fn decode(datagram: &[u8]) -> Result<Self, NetError> {
        Self::decode_with_max_bits(datagram, DEFAULT_MAX_PACKET_BITS)
    }

    /// Decodes a `PComNetConn` UDP datagram with explicit `max_packet_bits` bounds enforcement.
    pub fn decode_with_max_bits(datagram: &[u8], max_packet_bits: usize) -> Result<Self, NetError> {
        if max_packet_bits == 0 || max_packet_bits > DEFAULT_MAX_PACKET_BITS {
            return Err(NetError::BunchError(format!(
                "max_packet_bits {} out of bounds (1..={})",
                max_packet_bits, DEFAULT_MAX_PACKET_BITS
            )));
        }
        if datagram.len() < PCOM_PREFIX_LEN + 1 {
            return Err(NetError::PacketTooSmall {
                expected: PCOM_PREFIX_LEN + 1,
                actual: datagram.len(),
            });
        }

        let mut pcom_prefix = [0u8; PCOM_PREFIX_LEN];
        pcom_prefix.copy_from_slice(&datagram[..PCOM_PREFIX_LEN]);
        let ue3_bytes = &datagram[PCOM_PREFIX_LEN..];

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

    /// Serializes control message into bunch payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
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
        }
        w.into_bytes()
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
}
