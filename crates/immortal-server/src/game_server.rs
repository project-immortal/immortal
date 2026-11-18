// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Cleanroom Game Server Daemon (Port 7777)
//! High-performance asynchronous UDP server handling authentic UE3 / `PComNetConn`
//! bit-packed datagrams (`Ue3Packet`), the 7-stage Paladins Channel 0 Control Handshake
//! (`0x1A -> 0x1B -> 0x1C -> 0x1D -> 0x20 -> 0x1F(0) -> 0x00 -> 0x03 -> 0x04/0x05 -> 0x01 -> 0x09`),
//! bounded session management (`MAX_SESSIONS`), and legacy `CPackUdp` dispatch.

use crate::replication::ReplicationSession;
use anyhow::{anyhow, Result};
use immortal_net::{
    current_time_millis, parse_cpack_udp, Bunch, CPackUdpPacket, ControlChannelHandshake,
    ControlMessage, HandshakePhase, HelloRecvReply, PingRecv, Ue3Packet, ACTOR_CHANNEL_INDEX,
    CONTROL_CHANNEL_INDEX, DEFAULT_GAME_CLASS, DEFAULT_GAME_PORT, DEFAULT_HMAC_KEY,
    DEFAULT_MAX_PACKET, DEFAULT_MAX_PACKET_BITS, DEFAULT_NET_SPEED, DEFAULT_SHOOTING_RANGE_LEVEL,
    HELLO_MIN_LEN, HELLO_PAYLOAD_OFFSET, MAX_CHSEQUENCE, MAX_PACKETID, PCOM_PREFIX_LEN,
    PcomPrefix,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

/// Upper capacity bound for tracked UDP client sessions (`PSL-INV-011 §4`).
pub const MAX_SESSIONS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Connected,
    HelloCompleted,
    HandshakeCompleted,
    Replicating,
}

/// Client session state tracked by the Game Server.
pub struct ClientSession {
    pub addr: SocketAddr,
    pub session_id: u32,
    pub phase: SessionPhase,
    pub pcom_prefix: PcomPrefix,
    pub server_packet_id: u16,
    pub ctrl_sequence: u32,
    pub in_reliable_ctrl: u16,
    pub map_loaded: bool,
    pub handshake: ControlChannelHandshake,
    pub replication: ReplicationSession,
    pub last_seen: Instant,
}

impl ClientSession {
    pub fn new(
        addr: SocketAddr,
        session_id: u32,
        level_url: &str,
        game_class: &str,
        net_speed: u32,
    ) -> Self {
        Self {
            addr,
            session_id,
            phase: SessionPhase::Connected,
            pcom_prefix: PcomPrefix::default(),
            server_packet_id: 0,
            ctrl_sequence: 1,
            in_reliable_ctrl: 0,
            map_loaded: false,
            handshake: ControlChannelHandshake::new(
                Some(level_url),
                Some(game_class),
                Some(net_speed),
            ),
            replication: ReplicationSession::new(),
            last_seen: Instant::now(),
        }
    }

    /// Allocates the next 0-based 14-bit UE3 server `PacketId` modulo `MAX_PACKETID`.
    pub fn next_packet_id(&mut self) -> u16 {
        let id = self.server_packet_id;
        self.server_packet_id = ((u32::from(self.server_packet_id) + 1) % MAX_PACKETID) as u16;
        id
    }

    /// Allocates the next 1-based 10-bit UE3 Channel 0 reliable `ChSequence` modulo `MAX_CHSEQUENCE`.
    pub fn next_ctrl_seq(&mut self) -> u32 {
        let seq = self.ctrl_sequence;
        self.ctrl_sequence = (self.ctrl_sequence + 1) % MAX_CHSEQUENCE;
        seq
    }
}

/// Game Server configuration parameters.
#[derive(Debug, Clone)]
pub struct GameServerConfig {
    pub bind_addr: SocketAddr,
    pub level_url: String,
    pub game_class: String,
    pub hmac_key: Vec<u8>,
    pub net_speed: u32,
}

impl Default for GameServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_GAME_PORT)),
            level_url: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
            game_class: DEFAULT_GAME_CLASS.to_string(),
            hmac_key: DEFAULT_HMAC_KEY.to_vec(),
            net_speed: DEFAULT_NET_SPEED,
        }
    }
}

/// Handle allowing graceful shutdown and inspection of running Game Server.
pub struct GameServerHandle {
    shutdown_tx: broadcast::Sender<()>,
    local_addr: SocketAddr,
    join_handle: tokio::task::JoinHandle<Result<()>>,
}

impl GameServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        match self.join_handle.await {
            Ok(res) => res,
            Err(e) => Err(anyhow!("Game server task join error: {}", e)),
        }
    }
}

/// Cleanroom Unreal Engine 3 UDP Game Server.
pub struct GameServer {
    socket: Arc<UdpSocket>,
    config: Arc<GameServerConfig>,
    sessions: Arc<RwLock<HashMap<SocketAddr, ClientSession>>>,
}

impl GameServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let config = GameServerConfig {
            bind_addr: addr,
            ..Default::default()
        };
        Self::bind_with_config(config).await
    }

    pub async fn bind_with_config(config: GameServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        info!("🎮 Game Server UDP bound to {}", socket.local_addr()?);
        Ok(Self {
            socket: Arc::new(socket),
            config: Arc::new(config),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(Into::into)
    }

    /// Spawns the server as a background Tokio task.
    pub fn start(config: GameServerConfig) -> Result<GameServerHandle> {
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let config_clone = config.clone();

        let std_socket = std::net::UdpSocket::bind(config.bind_addr)?;
        std_socket.set_nonblocking(true)?;
        let local_addr = std_socket.local_addr()?;

        let join_handle = tokio::spawn(async move {
            let socket = UdpSocket::from_std(std_socket)?;
            let server = GameServer {
                socket: Arc::new(socket),
                config: Arc::new(config_clone),
                sessions: Arc::new(RwLock::new(HashMap::new())),
            };

            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    recv_res = server.socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((size, src)) => {
                                let data = &buf[..size];
                                info!("📥 UDP datagram ({} bytes) from {}: {:02x?}", size, src, data);
                                match server.handle_datagram(data, src).await {
                                    Ok(replies) => {
                                        for reply in replies {
                                            if let Err(e) = server.socket.send_to(&reply, src).await {
                                                error!("Failed to send datagram reply to {}: {}", src, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Error processing datagram from {}: {}", src, e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("UDP socket recv_from error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🛑 Game Server shutting down");
                        break;
                    }
                }
            }
            Ok(())
        });

        Ok(GameServerHandle {
            shutdown_tx,
            local_addr,
            join_handle,
        })
    }

    /// Handles an incoming datagram and returns any outgoing response datagrams.
    pub async fn handle_datagram(&self, data: &[u8], src: SocketAddr) -> Result<Vec<Vec<u8>>> {
        // 1. Route UE3 / PComNetConn datagrams (`0x00` outer prefix + bit-packed UE3 payload)
        if data.len() >= PCOM_PREFIX_LEN + 2
            && data[0] == 0x00
            && data.len() <= DEFAULT_MAX_PACKET + PCOM_PREFIX_LEN
        {
            // Disambiguate overlapping 570..=582-byte legacy CPackUdp::HelloSend when
            // (connection_id & 0xFF) == 0: try UE3 decode first, falling through on failure.
            let overlaps_cpack_hello =
                data.len() >= HELLO_MIN_LEN && data[HELLO_PAYLOAD_OFFSET] == 0;
            if overlaps_cpack_hello {
                if let Ok(pkt) = Ue3Packet::decode(data) {
                    return self.process_ue3_pcom_packet(pkt, src).await;
                }
            } else {
                return self.handle_ue3_pcom_datagram(data, src).await;
            }
        }

        // 2. Legacy CPackUdp dispatch path (`HelloSend`, `PingSend`, `CPACK_OP_BUNCH`)
        let packet = parse_cpack_udp(data)?;
        let mut responses = Vec::new();

        let mut sessions = self.sessions.write().await;
        let session = get_or_insert_session(&mut sessions, src, &self.config);

        match packet {
            CPackUdpPacket::HelloSend(hello) => {
                debug!(
                    "Ingested HelloSend from {} (conn_id: {})",
                    src, hello.connection_id
                );
                if hello.raw.len() >= 650 && !hello.validate_hmac(&self.config.hmac_key) {
                    warn!("HelloSend from {} failed HMAC validation", src);
                    return Err(anyhow!("HMAC validation failed"));
                }

                session.phase = SessionPhase::HelloCompleted;
                let reply = HelloRecvReply::new(session.session_id, 0x1337C0DE);
                responses.push(reply.encode());
            }

            CPackUdpPacket::PingSend(ping) => {
                debug!("Ingested PingSend seq: {} from {}", ping.sequence, src);
                let now = current_time_millis();
                let reply = PingRecv::new(ping.sequence, ping.timestamp, now);
                responses.push(reply.encode());
            }

            CPackUdpPacket::HelloRecvReply(_) | CPackUdpPacket::PingRecv(_) => {}

            CPackUdpPacket::Bunch(bunch_raw) => match Bunch::decode(&bunch_raw) {
                Ok(bunch) => {
                    let bunch_responses = self.handle_bunch(bunch, session)?;
                    for b in bunch_responses {
                        responses.push(b.encode_cpack_udp()?);
                    }
                }
                Err(bunch_err) => match ControlMessage::decode(&bunch_raw) {
                    Ok(ctrl_msg) => {
                        warn!(
                            "Received raw unencapsulated ControlMessage from {} (bunch decode error: {})",
                            src, bunch_err
                        );
                        let replies = session.handshake.handle_control_message(&ctrl_msg)?;
                        for rep in replies {
                            let b = Bunch::control(session.next_ctrl_seq(), rep.encode());
                            responses.push(b.encode_cpack_udp()?);
                        }
                    }
                    Err(ctrl_err) => {
                        warn!(
                            "Failed to decode bunch payload from {}: bunch decode error ({}), control decode error ({})",
                            src, bunch_err, ctrl_err
                        );
                    }
                },
            },
        }

        Ok(responses)
    }

    /// Handles an authentic UE3 / `PComNetConn` bit-packed UDP 7777 datagram.
    async fn handle_ue3_pcom_datagram(&self, data: &[u8], src: SocketAddr) -> Result<Vec<Vec<u8>>> {
        let pkt = Ue3Packet::decode(data)?;
        self.process_ue3_pcom_packet(pkt, src).await
    }

    /// Processes a decoded `Ue3Packet` atomically across all bunches: stages handshake
    /// and reliable-sequence transitions and commits only after every bunch succeeds.
    async fn process_ue3_pcom_packet(
        &self,
        pkt: Ue3Packet,
        src: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let mut sessions = self.sessions.write().await;
        let session = get_or_insert_session(&mut sessions, src, &self.config);
        session.pcom_prefix = pkt.pcom_prefix;

        debug!(
            "🎮 Ingested UE3 PComNetConn pkt from {} (pkt_id={}, acks={:?}, bunches={})",
            src,
            pkt.packet_id,
            pkt.acks,
            pkt.bunches.len()
        );

        // Suppress ACK-of-ACK storms on pure ACK packets
        if pkt.bunches.is_empty() && !pkt.acks.is_empty() {
            return Ok(Vec::new());
        }

        // Bare keepalive (no bunches, no ACKs): return standalone ACK
        if pkt.bunches.is_empty() {
            let mut ack_pkt = Ue3Packet::new_with_prefix(session.pcom_prefix.clone(), session.next_packet_id());
            ack_pkt.acks.push(pkt.packet_id);
            return Ok(vec![ack_pkt.encode()?]);
        }

        let mut staged_handshake = session.handshake.clone();
        let mut staged_in_reliable = session.in_reliable_ctrl;
        let mut staged_reply_msgs: Vec<ControlMessage> = Vec::new();
        let mut suppress_ack = false;
        let mut closed_channel_seq: Option<u32> = None;

        for bunch in &pkt.bunches {
            match bunch.header.ch_index {
                CONTROL_CHANNEL_INDEX => {
                    if bunch.header.flags.b_close {
                        closed_channel_seq = Some(bunch.header.ch_sequence);
                        continue;
                    }

                    let incoming_seq = (bunch.header.ch_sequence % MAX_CHSEQUENCE) as u16;
                    if bunch.header.flags.b_reliable {
                        let delta = make_relative_seq(incoming_seq, staged_in_reliable);
                        if delta <= 0 {
                            debug!(
                                "Skipping duplicate/stale reliable Control bunch from {} (seq={}, last={})",
                                src, incoming_seq, staged_in_reliable
                            );
                            continue;
                        }
                        if delta > 1 {
                            debug!(
                                "Dropping out-of-order future reliable Control bunch from {} (seq={}, expected={}, delta={}); suppressing ACK",
                                src,
                                incoming_seq,
                                (u32::from(staged_in_reliable) + 1) % MAX_CHSEQUENCE,
                                delta
                            );
                            suppress_ack = true;
                            continue;
                        }
                    }

                    let messages = ControlMessage::decode_all(&bunch.data, bunch.num_bits)?;
                    for msg in &messages {
                        debug!("Ingested Channel 0 ControlMessage from {}: {:?}", src, msg);
                        if let ControlMessage::MapLoaded = msg {
                            session.map_loaded = true;
                            info!("🗺️ Client {} loaded map (NMT_MapLoaded 0x2A)", src);
                        }
                        let replies = staged_handshake.handle_control_message(msg)?;
                        staged_reply_msgs.extend(replies);
                    }

                    if bunch.header.flags.b_reliable {
                        staged_in_reliable = incoming_seq;
                    }
                }
                other_ch => {
                    debug!(
                        "Ignoring non-control bunch on channel {} from {} (Actor Channel deferred to UNK-UDP-004)",
                        other_ch, src
                    );
                }
            }
        }

        // Future out-of-order gap: drop packet without committing state or ACKing,
        // allowing UE3 reliable transport to retransmit bunches in order.
        if suppress_ack {
            return Ok(Vec::new());
        }

        if let Some(close_seq) = closed_channel_seq {
            info!(
                "🔌 Client {} closed Control Channel 0 (seq={})",
                src, close_seq
            );
        }

        let prev_phase = session.handshake.phase;
        session.handshake = staged_handshake;
        session.in_reliable_ctrl = staged_in_reliable;

        if session.handshake.phase != prev_phase {
            match session.handshake.phase {
                HandshakePhase::Welcomed => {
                    session.phase = SessionPhase::HandshakeCompleted;
                    info!(
                        "🎉 Welcomed client {} (Level: {}, Game: {})",
                        src, session.handshake.level_name, session.handshake.game_name
                    );
                }
                HandshakePhase::Joined => {
                    session.phase = SessionPhase::Replicating;
                    info!(
                        "🎉 Client {} sent NMT_Join — entering Replicating phase (Actor Channel deferred to UNK-UDP-004)",
                        src
                    );
                }
                _ => {}
            }
        }

        let mut reply_bunches = Vec::with_capacity(staged_reply_msgs.len());
        for reply_msg in staged_reply_msgs {
            reply_bunches.push(Bunch::control(session.next_ctrl_seq(), reply_msg.encode()));
        }

        pack_ue3_replies(session, pkt.packet_id, reply_bunches)
    }

    /// Handles a parsed bunch on the legacy `CPackUdp` dispatch path.
    fn handle_bunch(&self, bunch: Bunch, session: &mut ClientSession) -> Result<Vec<Bunch>> {
        let mut out = Vec::new();

        match bunch.header.ch_index {
            CONTROL_CHANNEL_INDEX => {
                let messages = ControlMessage::decode_all(&bunch.data, bunch.num_bits)?;
                for msg in &messages {
                    debug!("Ingested legacy CPackUdp ControlMessage: {:?}", msg);
                    if let ControlMessage::MapLoaded = msg {
                        session.map_loaded = true;
                        info!("🗺️ Client {} loaded map (NMT_MapLoaded 0x2A)", session.addr);
                    }
                    let replies = session.handshake.handle_control_message(msg)?;
                    for reply in replies {
                        out.push(Bunch::control(session.next_ctrl_seq(), reply.encode()));
                    }
                }

                if session.handshake.phase == HandshakePhase::Joined
                    && !session.replication.pawn_spawned
                {
                    info!(
                        "🎉 Legacy CPackUdp Handshake Joined for {}. Opening Actor Channel {} and Spawning Fernando!",
                        session.addr, ACTOR_CHANNEL_INDEX
                    );
                    session.phase = SessionPhase::Replicating;
                    out.push(session.replication.open_channel_2());
                    out.push(session.replication.spawn_fernando());
                    out.push(session.replication.stream_baseline_delta(0.016));
                }
            }
            ACTOR_CHANNEL_INDEX => {
                debug!(
                    "Ingested Actor Channel {} bunch (len: {}) from {}",
                    ACTOR_CHANNEL_INDEX,
                    bunch.data.len(),
                    session.addr
                );
                out.push(session.replication.stream_baseline_delta(0.016));
            }
            _ => {
                debug!(
                    "Ingested bunch on unknown channel: {}",
                    bunch.header.ch_index
                );
            }
        }

        Ok(out)
    }
}

/// Bounded session table lookup/insert with oldest-`last_seen` eviction (`MAX_SESSIONS = 1024`).
fn get_or_insert_session<'a>(
    sessions: &'a mut HashMap<SocketAddr, ClientSession>,
    src: SocketAddr,
    config: &GameServerConfig,
) -> &'a mut ClientSession {
    if !sessions.contains_key(&src) && sessions.len() >= MAX_SESSIONS {
        if let Some(oldest_addr) = sessions
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(addr, _)| *addr)
        {
            sessions.remove(&oldest_addr);
        }
    }
    let session = sessions.entry(src).or_insert_with(|| {
        let session_id = rand_session_id();
        ClientSession::new(
            src,
            session_id,
            &config.level_url,
            &config.game_class,
            config.net_speed,
        )
    });
    session.last_seen = Instant::now();
    session
}

/// Modular 10-bit UE3 `MakeRelative(seq, reference, MAX_CHSEQUENCE)`.
fn make_relative_seq(seq: u16, reference: u16) -> i32 {
    let max = MAX_CHSEQUENCE as i32;
    let half = max / 2;
    let mut delta = (i32::from(seq) - i32::from(reference)).rem_euclid(max);
    if delta >= half {
        delta -= max;
    }
    delta
}

/// Exact bit width of UE3 `SerializeInt(value, value_max)`.
fn serialize_int_width(value: u32, value_max: u32) -> usize {
    let max_u64 = u64::from(value_max);
    let val_u64 = u64::from(value);
    let mut written: u64 = 0;
    let mut mask: u64 = 1;
    let mut bits = 0usize;
    if max_u64 > 1 {
        while written.saturating_add(mask) < max_u64 {
            if mask >= (1u64 << 32) {
                break;
            }
            if (val_u64 & mask) != 0 {
                written |= mask;
            }
            bits += 1;
            mask <<= 1;
        }
    }
    bits
}

/// Computes exact wire bit length of a single `Bunch` entry (including leading `IsAck = 0` bit).
fn bunch_wire_bits(bunch: &Bunch, max_packet_bits: usize) -> usize {
    let b_control = bunch.header.flags.is_control();
    let mut bits = 1 + 1; // IsAck + bControl
    if b_control {
        bits += 2; // bOpen + bClose
    }
    bits += 1; // bReliable
    bits += 11; // ChIndex (MAX_CHANNELS = 0x800)
    if bunch.header.flags.b_reliable {
        bits += 10; // ChSequence (MAX_CHSEQUENCE = 0x400)
    }
    if bunch.header.flags.b_reliable || bunch.header.flags.b_open {
        bits += 3; // ChType (CHTYPE_MAX = 8)
    }
    bits += serialize_int_width(bunch.num_bits as u32, max_packet_bits as u32);
    bits += bunch.num_bits;
    bits
}

/// Packs `ack_packet_id` + `reply_bunches` into one or more `Ue3Packet` datagrams,
/// splitting cleanly only when total bit count would reach `DEFAULT_MAX_PACKET_BITS`.
fn pack_ue3_replies(
    session: &mut ClientSession,
    ack_packet_id: u16,
    reply_bunches: Vec<Bunch>,
) -> Result<Vec<Vec<u8>>> {
    let mut encoded_packets = Vec::new();
    let mut current = Ue3Packet::new_with_prefix(session.pcom_prefix.clone(), session.next_packet_id());
    current.acks.push(ack_packet_id);
    let mut current_bits = 14 + 15; // 14-bit PacketId + 15-bit ACK

    for bunch in reply_bunches {
        let b_bits = bunch_wire_bits(&bunch, DEFAULT_MAX_PACKET_BITS);
        if current_bits + b_bits >= DEFAULT_MAX_PACKET_BITS
            && (!current.bunches.is_empty() || !current.acks.is_empty())
        {
            encoded_packets.push(current.encode()?);
            current = Ue3Packet::new_with_prefix(session.pcom_prefix.clone(), session.next_packet_id());
            current_bits = 14;
        }
        current_bits += b_bits;
        current.bunches.push(bunch);
    }

    encoded_packets.push(current.encode()?);
    Ok(encoded_packets)
}

fn rand_session_id() -> u32 {
    let now = current_time_millis();
    (now & 0xFFFFFFFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_net::{
        ue3_handshake_crc, HelloSend, PingSend, Ue3ChannelType, DEFAULT_ENGINE_MIN_NET_VERSION,
        DEFAULT_ENGINE_NET_VERSION,
    };

    #[tokio::test]
    async fn test_flight034_full_staged_udp_handshake_to_welcome_and_join() {
        let config = GameServerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server = GameServer::bind_with_config(config).await.unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6];

        // Step 0 -> 1: Exact Flight 034 Packet 0 bytes (NMT_HandshakeStart 0x1A, platform=0x40)
        let pkt0_wire: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x00, 0x80, 0x05, 0x40, 0x00, 0x41, 0x01, 0x1A,
            0x40, 0x00, 0x00, 0x00, 0x01,
        ];
        let r0 = server
            .handle_datagram(pkt0_wire, client_addr)
            .await
            .unwrap();
        assert_eq!(r0.len(), 1);
        let s0 = Ue3Packet::decode(&r0[0]).unwrap();
        assert_eq!(s0.pcom_prefix, prefix);
        assert_eq!(s0.packet_id, 0);
        assert_eq!(s0.acks, vec![0]);
        assert_eq!(s0.bunches.len(), 1);
        assert!(!s0.bunches[0].header.flags.b_open);
        assert!(s0.bunches[0].header.flags.b_reliable);
        assert_eq!(s0.bunches[0].header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(s0.bunches[0].header.ch_type, Ue3ChannelType::Control);
        assert_eq!(s0.bunches[0].header.ch_sequence, 1);
        let challenge = match ControlMessage::decode(&s0.bunches[0].data).unwrap() {
            ControlMessage::HandshakeChallenge { challenge } => challenge,
            other => panic!("Expected HandshakeChallenge, got {:?}", other),
        };

        // Step 2 -> 3: NMT_HandshakeResponse (0x1C) with real signed %d CRC -> NMT_HandshakeComplete (0x1D)
        let mut c1 = Ue3Packet::new(prefix, 1);
        c1.acks.push(0);
        c1.bunches.push(Bunch::control(
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(challenge),
            }
            .encode(),
        ));
        let r1 = server
            .handle_datagram(&c1.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r1.len(), 1);
        let s1 = Ue3Packet::decode(&r1[0]).unwrap();
        assert_eq!(s1.pcom_prefix, prefix);
        assert_eq!(s1.packet_id, 1);
        assert_eq!(s1.acks, vec![1]);
        assert_eq!(s1.bunches[0].header.ch_sequence, 2);
        assert_eq!(
            ControlMessage::decode(&s1.bunches[0].data).unwrap(),
            ControlMessage::HandshakeComplete
        );

        // Step 4 -> 5: NMT_ServerAuthRequest (0x20) -> NMT_ClientAuthRequest (0x1F, ServerSteamId=0)
        let mut c2 = Ue3Packet::new(prefix, 2);
        c2.acks.push(1);
        c2.bunches.push(Bunch::control(
            3,
            ControlMessage::ServerAuthRequest.encode(),
        ));
        let r2 = server
            .handle_datagram(&c2.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r2.len(), 1);
        let s2 = Ue3Packet::decode(&r2[0]).unwrap();
        assert_eq!(s2.packet_id, 2);
        assert_eq!(s2.acks, vec![2]);
        assert_eq!(s2.bunches[0].header.ch_sequence, 3);
        assert_eq!(
            ControlMessage::decode(&s2.bunches[0].data).unwrap(),
            ControlMessage::client_auth_request_bypass()
        );

        // Step 6 -> 7: NMT_Hello (0x00) -> NMT_Challenge (0x03)
        let mut c3 = Ue3Packet::new(prefix, 3);
        c3.acks.push(2);
        c3.bunches.push(Bunch::control(
            4,
            ControlMessage::Hello {
                min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
                net_ver: DEFAULT_ENGINE_NET_VERSION,
                is_little_endian: 1,
            }
            .encode(),
        ));
        let r3 = server
            .handle_datagram(&c3.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r3.len(), 1);
        let s3 = Ue3Packet::decode(&r3[0]).unwrap();
        assert_eq!(s3.packet_id, 3);
        assert_eq!(s3.acks, vec![3]);
        assert_eq!(s3.bunches[0].header.ch_sequence, 4);
        assert_eq!(
            ControlMessage::decode(&s3.bunches[0].data).unwrap(),
            ControlMessage::Challenge {
                challenge_id: 0,
                challenge: "IMMORTAL".to_string(),
            }
        );

        // Step 8 + 9 -> 10: Packed NMT_Netspeed (0x04) + NMT_Login (0x05, 2x u64) in ONE datagram -> bare NMT_Welcome (0x01)
        let mut c4 = Ue3Packet::new(prefix, 4);
        c4.acks.push(3);
        c4.bunches.push(Bunch::control(
            5,
            ControlMessage::NetSpeed { rate: 24000 }.encode(),
        ));
        c4.bunches.push(Bunch::control(
            6,
            ControlMessage::Login {
                client_response: "0".to_string(),
                url: "Shootingrange_P?Name=Player?Team=0?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0".to_string(),
                unique_id: 8_302_401,
                portal_id: 0x0186_0000_8246_2A8F,
            }
            .encode(),
        ));
        let r4 = server
            .handle_datagram(&c4.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r4.len(), 1);
        let s4 = Ue3Packet::decode(&r4[0]).unwrap();
        assert_eq!(s4.pcom_prefix, prefix);
        assert_eq!(s4.packet_id, 4);
        assert_eq!(s4.acks, vec![4]);
        // Must contain ONLY NMT_Welcome (zero premature Actor bunches!)
        assert_eq!(s4.bunches.len(), 1);
        assert!(!s4.bunches[0].header.flags.b_open);
        assert_eq!(s4.bunches[0].header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(s4.bunches[0].header.ch_sequence, 5);
        assert_eq!(
            ControlMessage::decode(&s4.bunches[0].data).unwrap(),
            ControlMessage::Welcome {
                level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
                game_name: DEFAULT_GAME_CLASS.to_string(),
            }
        );

        // Step 11: NMT_Join (0x09) -> ACK only, transitions cleanly to SessionPhase::Replicating (holds Actor Ch!)
        let mut c5 = Ue3Packet::new(prefix, 5);
        c5.acks.push(4);
        c5.bunches
            .push(Bunch::control(7, ControlMessage::Join.encode()));
        let r5 = server
            .handle_datagram(&c5.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r5.len(), 1);
        let s5 = Ue3Packet::decode(&r5[0]).unwrap();
        assert_eq!(s5.packet_id, 5);
        assert_eq!(s5.acks, vec![5]);
        assert!(
            s5.bunches.is_empty(),
            "Actor Channel bunches must be deferred to UNK-UDP-004 after NMT_Join"
        );

        let sessions = server.sessions.read().await;
        let sess = sessions.get(&client_addr).unwrap();
        assert_eq!(sess.phase, SessionPhase::Replicating);
        assert_eq!(sess.handshake.phase, HandshakePhase::Joined);
    }

    #[tokio::test]
    async fn test_pcom_handshake_crc_mismatch_rejected() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54322".parse().unwrap();
        let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0x11, 0x22, 0x33, 0x44];

        let mut c0 = Ue3Packet::new(prefix, 0);
        c0.bunches.push(Bunch::control_open(
            1,
            ControlMessage::HandshakeStart {
                platform_flag: 0x40,
            }
            .encode(),
        ));
        let r0 = server
            .handle_datagram(&c0.encode().unwrap(), client_addr)
            .await
            .unwrap();
        let s0 = Ue3Packet::decode(&r0[0]).unwrap();
        let challenge = match ControlMessage::decode(&s0.bunches[0].data).unwrap() {
            ControlMessage::HandshakeChallenge { challenge } => challenge,
            other => panic!("Expected HandshakeChallenge, got {:?}", other),
        };

        // Send invalid CRC
        let mut c1_bad = Ue3Packet::new(prefix, 1);
        c1_bad.acks.push(0);
        c1_bad.bunches.push(Bunch::control(
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(challenge) ^ 0xFF,
            }
            .encode(),
        ));
        let res = server
            .handle_datagram(&c1_bad.encode().unwrap(), client_addr)
            .await;
        assert!(res.is_err());

        // Phase must remain ChallengeSent and in_reliable_ctrl must still be 1
        let sessions = server.sessions.read().await;
        let sess = sessions.get(&client_addr).unwrap();
        assert_eq!(sess.handshake.phase, HandshakePhase::ChallengeSent);
        assert_eq!(sess.in_reliable_ctrl, 1);
    }

    #[tokio::test]
    async fn test_pcom_duplicate_packet_idempotent_and_no_ack_storm() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54323".parse().unwrap();

        // Send Flight 034 Packet 0 twice (retransmit with same ChSequence = 1)
        let pkt0_wire: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x00, 0x80, 0x05, 0x40, 0x00, 0x41, 0x01, 0x1A,
            0x40, 0x00, 0x00, 0x00, 0x01,
        ];
        let r_first = server
            .handle_datagram(pkt0_wire, client_addr)
            .await
            .unwrap();
        assert_eq!(Ue3Packet::decode(&r_first[0]).unwrap().bunches.len(), 1);

        let r_dup = server
            .handle_datagram(pkt0_wire, client_addr)
            .await
            .unwrap();
        assert_eq!(r_dup.len(), 1);
        let s_dup = Ue3Packet::decode(&r_dup[0]).unwrap();
        assert_eq!(s_dup.acks, vec![0]);
        assert!(
            s_dup.bunches.is_empty(),
            "Duplicate reliable bunch must not re-advance handshake state"
        );

        // Pure ACK packet (exact Flight 034 Packet 2) must return 0 packets (no ACK storm)
        let pkt2_wire: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x02, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0x48,
            0x00, 0x2C, 0x00, 0x02,
        ];
        let r_ack = server
            .handle_datagram(pkt2_wire, client_addr)
            .await
            .unwrap();
        assert!(
            r_ack.is_empty(),
            "Pure ACK packet must not trigger an ACK-of-ACK storm"
        );
    }

    #[tokio::test]
    async fn test_pcom_client_close_bunch_handled_gracefully() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54324".parse().unwrap();

        // Exact Flight 034 Packet 1 (ACKs=[1,2,3], Ch0 bClose=1, 0 payload bits)
        let pkt1_wire: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x01, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0xD0,
            0x00, 0x10, 0x20, 0x00, 0x20,
        ];
        let replies = server
            .handle_datagram(pkt1_wire, client_addr)
            .await
            .unwrap();
        assert_eq!(replies.len(), 1);
        let s = Ue3Packet::decode(&replies[0]).unwrap();
        assert_eq!(s.acks, vec![1]);
        assert!(s.bunches.is_empty());
    }

    #[tokio::test]
    async fn test_game_server_session_table_bounded() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let pkt2_wire: &[u8] = &[
            0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x02, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0x48,
            0x00, 0x2C, 0x00, 0x02,
        ];

        for i in 0..(MAX_SESSIONS + 25) {
            let addr = SocketAddr::from(([127, 0, ((i >> 8) & 0xFF) as u8, 1], 10000 + (i as u16)));
            server.handle_datagram(pkt2_wire, addr).await.unwrap();
        }

        let sessions = server.sessions.read().await;
        assert_eq!(sessions.len(), MAX_SESSIONS);
    }

    #[tokio::test]
    async fn test_game_server_hello_handshake_flow() {
        let config = GameServerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server = GameServer::bind_with_config(config).await.unwrap();
        let client_addr: SocketAddr = "127.0.0.1:45678".parse().unwrap();

        // 1. Legacy CPackUdp HelloSend
        let hello_bytes = HelloSend::build(DEFAULT_HMAC_KEY, 1001, None, 650);
        let replies = server
            .handle_datagram(&hello_bytes, client_addr)
            .await
            .expect("Failed to handle HelloSend");
        assert_eq!(replies.len(), 1);
        let hello_reply = HelloRecvReply::decode(&replies[0]).unwrap();
        assert_eq!(hello_reply.negotiated_mtu, 1414);

        // 2. Legacy CPackUdp PingSend
        let ping_bytes = PingSend::new(1, 1000, true).encode();
        let ping_replies = server
            .handle_datagram(&ping_bytes, client_addr)
            .await
            .expect("Failed to handle PingSend");
        assert_eq!(ping_replies.len(), 1);
        let ping_reply = PingRecv::decode(&ping_replies[0]).unwrap();
        assert_eq!(ping_reply.sequence, 1);
        assert_eq!(ping_reply.negotiated_mtu, 1414);

        // 3. Channel 0 NMT_Hello (3x u32) -> NMT_Challenge (1-based ChSeq = 1)
        let nmt_hello = ControlMessage::Hello {
            min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
            net_ver: DEFAULT_ENGINE_NET_VERSION,
            is_little_endian: 1,
        };
        let hello_bunch = Bunch::control(1, nmt_hello.encode());
        let challenge_replies = server
            .handle_datagram(&hello_bunch.encode_cpack_udp().unwrap(), client_addr)
            .await
            .expect("Failed to handle NMT_Hello bunch");
        assert_eq!(challenge_replies.len(), 1);
        assert_eq!(challenge_replies[0][0], immortal_net::CPACK_OP_BUNCH);
        let ch_bunch = Bunch::decode_cpack_udp(&challenge_replies[0]).unwrap();
        assert_eq!(ch_bunch.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(ch_bunch.header.ch_sequence, 1);
        assert_eq!(
            ControlMessage::decode(&ch_bunch.data).unwrap(),
            ControlMessage::Challenge {
                challenge_id: 0,
                challenge: "IMMORTAL".to_string(),
            }
        );

        // 4. Channel 0 NMT_Login -> bare NMT_Welcome (ChSeq = 2)
        let login_bunch = Bunch::control(
            2,
            ControlMessage::Login {
                client_response: "0".to_string(),
                url: "Shootingrange_P".to_string(),
                unique_id: 10001,
                portal_id: 0,
            }
            .encode(),
        );
        let welcome_replies = server
            .handle_datagram(&login_bunch.encode_cpack_udp().unwrap(), client_addr)
            .await
            .expect("Failed to handle NMT_Login");
        assert_eq!(welcome_replies.len(), 1);
        let w_bunch = Bunch::decode_cpack_udp(&welcome_replies[0]).unwrap();
        assert_eq!(w_bunch.header.ch_sequence, 2);
        assert_eq!(
            ControlMessage::decode(&w_bunch.data).unwrap(),
            ControlMessage::Welcome {
                level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
                game_name: DEFAULT_GAME_CLASS.to_string(),
            }
        );

        // 5. Channel 0 NMT_Join -> Actor Channel 3 open (seq 1) + Spawn Fernando (seq 2)
        let join_bunch = Bunch::control(3, ControlMessage::Join.encode());
        let join_replies = server
            .handle_datagram(&join_bunch.encode_cpack_udp().unwrap(), client_addr)
            .await
            .expect("Failed to handle NMT_Join");
        assert!(join_replies.len() >= 2);
        let open_bunch = Bunch::decode_cpack_udp(&join_replies[0]).unwrap();
        let spawn_bunch = Bunch::decode_cpack_udp(&join_replies[1]).unwrap();
        assert_eq!(open_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(open_bunch.header.ch_sequence, 1);
        assert!(open_bunch.header.flags.b_open);
        assert_eq!(spawn_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(spawn_bunch.header.ch_sequence, 2);
        let payload = crate::replication::ReplicationPayload::decode(&spawn_bunch.data).unwrap();
        assert!(matches!(
            payload,
            crate::replication::ReplicationPayload::SpawnActor {
                champion_id: immortal_core::ChampionId::Fernando,
                weapon_device_id: 10774,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_pcom_out_of_order_future_reliable_bunch_rejected_and_wraparound() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54325".parse().unwrap();
        let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0x55, 0x66, 0x77, 0x88];

        // 1. Out-of-order seq=2 arriving before seq=1 (delta = 2 > 1):
        //    must NOT advance in_reliable_ctrl, must NOT mutate phase, and must suppress ACK!
        let mut future_pkt = Ue3Packet::new(prefix, 0);
        future_pkt.bunches.push(Bunch::control(
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(immortal_net::DEFAULT_HANDSHAKE_CHALLENGE),
            }
            .encode(),
        ));
        let r_future = server
            .handle_datagram(&future_pkt.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert!(
            r_future.is_empty(),
            "Future reliable bunch gap (delta > 1) must suppress ACK to allow UE3 retransmit"
        );
        {
            let sessions = server.sessions.read().await;
            let sess = sessions.get(&client_addr).unwrap();
            assert_eq!(sess.in_reliable_ctrl, 0);
            assert_eq!(sess.handshake.phase, HandshakePhase::AwaitingHandshakeStart);
            assert_eq!(sess.ctrl_sequence, 1);
            assert_eq!(sess.server_packet_id, 0);
        }

        // 2. Now seq=1 arrives -> advances cleanly to ChallengeSent
        let mut pkt1 = Ue3Packet::new(prefix, 1);
        pkt1.bunches.push(Bunch::control_open(
            1,
            ControlMessage::HandshakeStart {
                platform_flag: 0x40,
            }
            .encode(),
        ));
        let r1 = server
            .handle_datagram(&pkt1.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r1.len(), 1);
        let s1 = Ue3Packet::decode(&r1[0]).unwrap();
        let challenge = match ControlMessage::decode(&s1.bunches[0].data).unwrap() {
            ControlMessage::HandshakeChallenge { challenge } => challenge,
            other => panic!("Expected HandshakeChallenge, got {:?}", other),
        };

        // 3. Now seq=2 arrives in order -> succeeds cleanly
        let mut pkt2 = Ue3Packet::new(prefix, 2);
        pkt2.bunches.push(Bunch::control(
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(challenge),
            }
            .encode(),
        ));
        let r2 = server
            .handle_datagram(&pkt2.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r2.len(), 1);
        assert_eq!(
            ControlMessage::decode(&Ue3Packet::decode(&r2[0]).unwrap().bunches[0].data).unwrap(),
            ControlMessage::HandshakeComplete
        );

        // 4. Exercise 10-bit modular wraparound: 1023 -> 0 -> 1, and reject stale 1023 after 0
        {
            let mut sessions = server.sessions.write().await;
            let sess = sessions.get_mut(&client_addr).unwrap();
            sess.in_reliable_ctrl = (MAX_CHSEQUENCE - 1) as u16; // 1023
        }

        // seq=0 after 1023 -> delta == 1 -> accepted!
        let mut wrap0 = Ue3Packet::new(prefix, 3);
        wrap0.bunches.push(Bunch::control(
            0,
            ControlMessage::NetSpeed { rate: 30000 }.encode(),
        ));
        let rw0 = server
            .handle_datagram(&wrap0.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(rw0.len(), 1);
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .in_reliable_ctrl,
            0
        );
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .handshake
                .net_speed,
            30000
        );

        // Stale seq=1023 after advancing to 0 -> delta == -1 <= 0 -> skipped (does NOT overwrite net_speed)
        let mut stale = Ue3Packet::new(prefix, 4);
        stale.bunches.push(Bunch::control(
            MAX_CHSEQUENCE - 1,
            ControlMessage::NetSpeed { rate: 99999 }.encode(),
        ));
        let r_stale = server
            .handle_datagram(&stale.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(r_stale.len(), 1); // still ACKed
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .in_reliable_ctrl,
            0
        );
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .handshake
                .net_speed,
            30000
        );

        // seq=1 after 0 -> delta == 1 -> accepted!
        let mut wrap1 = Ue3Packet::new(prefix, 5);
        wrap1.bunches.push(Bunch::control(
            1,
            ControlMessage::NetSpeed { rate: 48000 }.encode(),
        ));
        let rw1 = server
            .handle_datagram(&wrap1.encode().unwrap(), client_addr)
            .await
            .unwrap();
        assert_eq!(rw1.len(), 1);
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .in_reliable_ctrl,
            1
        );
        assert_eq!(
            server
                .sessions
                .read()
                .await
                .get(&client_addr)
                .unwrap()
                .handshake
                .net_speed,
            48000
        );
    }

    #[tokio::test]
    async fn test_pcom_multi_bunch_mid_packet_error_is_atomic() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
        let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0xAA, 0xBB, 0xCC, 0xDD];

        // 2-bunch packet: Bunch 0 is valid NMT_HandshakeStart (seq=1),
        // Bunch 1 is invalid NMT_HandshakeResponse (seq=2) with wrong CRC.
        let mut pkt = Ue3Packet::new(prefix, 0);
        pkt.bunches.push(Bunch::control_open(
            1,
            ControlMessage::HandshakeStart {
                platform_flag: 0x40,
            }
            .encode(),
        ));
        pkt.bunches.push(Bunch::control(
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(immortal_net::DEFAULT_HANDSHAKE_CHALLENGE) ^ 0x1,
            }
            .encode(),
        ));

        let res = server
            .handle_datagram(&pkt.encode().unwrap(), client_addr)
            .await;
        assert!(res.is_err());

        // Entire packet must roll back cleanly: ctrl_sequence, in_reliable_ctrl, phase untouched!
        let sessions = server.sessions.read().await;
        let sess = sessions.get(&client_addr).unwrap();
        assert_eq!(sess.ctrl_sequence, 1);
        assert_eq!(sess.in_reliable_ctrl, 0);
        assert_eq!(sess.handshake.phase, HandshakePhase::AwaitingHandshakeStart);
        assert_eq!(sess.server_packet_id, 0);
    }

    #[tokio::test]
    async fn test_cpack_hello_send_570_bytes_zero_lo_conn_id_not_misrouted() {
        let server = GameServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client_addr: SocketAddr = "127.0.0.1:54327".parse().unwrap();

        // Build a 570-byte (HELLO_MIN_LEN) HelloSend with connection_id = 0x0100 (byte 0 == 0x00!)
        let mut raw = vec![0u8; HELLO_MIN_LEN];
        raw[0..4].copy_from_slice(&0x0100u32.to_le_bytes());
        raw[HELLO_PAYLOAD_OFFSET] = 0;

        let replies = server
            .handle_datagram(&raw, client_addr)
            .await
            .expect("570-byte HelloSend with connection_id=0x0100 must route to CPackUdp");
        assert_eq!(replies.len(), 1);
        let reply = HelloRecvReply::decode(&replies[0]).unwrap();
        assert_eq!(reply.negotiated_mtu, 1414);
    }

    #[test]
    fn test_pack_ue3_replies_splits_ack_from_near_max_bunch() {
        let addr: SocketAddr = "127.0.0.1:54328".parse().unwrap();
        let mut session = ClientSession::new(
            addr,
            1,
            DEFAULT_SHOOTING_RANGE_LEVEL,
            DEFAULT_GAME_CLASS,
            DEFAULT_NET_SPEED,
        );
        session.pcom_prefix = [0x00, 0x0C, 0x10, 0x20, 0x30, 0x40].into();

        // 568 bytes = 4544 payload bits; bunch header = 40 bits (13-bit len for 4544 >= 4096).
        // Total b_bits = 4584: fits alone (14 + 4584 = 4598 < 4608),
        // but does NOT fit alongside 15-bit ACK (29 + 4584 = 4613 >= 4608).
        let big_bunch = Bunch::control(1, vec![0xAB; 568]);
        let b_bits = bunch_wire_bits(&big_bunch, DEFAULT_MAX_PACKET_BITS);
        assert!(
            (4579..=4593).contains(&b_bits),
            "Expected b_bits in 4579..=4593, got {}",
            b_bits
        );

        let packets = pack_ue3_replies(&mut session, 7, vec![big_bunch.clone()])
            .expect("Near-max bunch must flush ACK first and split cleanly");
        assert_eq!(packets.len(), 2);

        let p0 = Ue3Packet::decode(&packets[0]).unwrap();
        assert_eq!(p0.packet_id, 0);
        assert_eq!(p0.acks, vec![7]);
        assert!(p0.bunches.is_empty());

        let p1 = Ue3Packet::decode(&packets[1]).unwrap();
        assert_eq!(p1.packet_id, 1);
        assert!(p1.acks.is_empty());
        assert_eq!(p1.bunches, vec![big_bunch]);
    }

    #[tokio::test]
    async fn test_pcom_map_loaded_flag_set() {
        let config = GameServerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server = GameServer::bind_with_config(config).await.unwrap();
        let src: SocketAddr = "127.0.0.1:54329".parse().unwrap();

        let mut pkt = Ue3Packet::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05], 0);
        pkt.bunches.push(Bunch::control(1, ControlMessage::MapLoaded.encode()));
        let encoded = pkt.encode().unwrap();

        let replies = server.handle_datagram(&encoded, src).await.unwrap();
        assert!(!replies.is_empty());

        let sessions = server.sessions.read().await;
        let session = sessions.get(&src).expect("Session should exist");
        assert!(session.map_loaded);
    }
}
