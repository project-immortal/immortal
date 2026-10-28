// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Cleanroom Game Server Daemon (Port 7777)
//! High-performance asynchronous UDP server handling `CPackUdp` wire framing,
//! Channel 0 Control Handshake (`ShootingRange?game=ChaosGame.ChaosGameInfo`),
//! and Actor Channel 2 Fernando pawn replication.

use crate::replication::ReplicationSession;
use anyhow::{anyhow, Result};
use immortal_net::{
    current_time_millis, parse_cpack_udp, Bunch, CPackUdpPacket, ControlChannelHandshake,
    ControlMessage, HelloRecvReply, PingRecv, ACTOR_CHANNEL_INDEX, CONTROL_CHANNEL_INDEX,
    DEFAULT_GAME_PORT, DEFAULT_HMAC_KEY, DEFAULT_NET_SPEED, DEFAULT_SHOOTING_RANGE_MAP,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

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
    pub ctrl_sequence: u32,
    pub server_sequence: u8,
    pub handshake: ControlChannelHandshake,
    pub replication: ReplicationSession,
    pub last_seen: Instant,
}

impl ClientSession {
    pub fn new(addr: SocketAddr, session_id: u32, level_url: &str, net_speed: u32) -> Self {
        Self {
            addr,
            session_id,
            phase: SessionPhase::Connected,
            ctrl_sequence: 0,
            server_sequence: 1,
            handshake: ControlChannelHandshake::new(Some(level_url), Some(net_speed)),
            replication: ReplicationSession::new(),
            last_seen: Instant::now(),
        }
    }
}

/// Game Server configuration parameters.
#[derive(Debug, Clone)]
pub struct GameServerConfig {
    pub bind_addr: SocketAddr,
    pub level_url: String,
    pub hmac_key: Vec<u8>,
    pub net_speed: u32,
}

impl Default for GameServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_GAME_PORT)),
            level_url: DEFAULT_SHOOTING_RANGE_MAP.to_string(),
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

        // Bind synchronously in start or initialize async task
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
        // 1. Check for UE3 PComNetConn wire format (6 zero bytes prefix)
        if data.len() >= 8 && data[0..6] == [0, 0, 0, 0, 0, 0] {
            let client_seq = data[6];
            let flags = data[7];

            let mut sessions = self.sessions.write().await;
            let session = sessions.entry(src).or_insert_with(|| {
                let session_id = rand_session_id();
                ClientSession::new(
                    src,
                    session_id,
                    &self.config.level_url,
                    self.config.net_speed,
                )
            });
            session.last_seen = Instant::now();

            let s_seq = session.server_sequence;
            session.server_sequence = session.server_sequence.wrapping_add(1);

            // Keepalive / Heartbeat ACK (flag 0x40)
            if flags == 0x40 {
                let ack = wrap_pcom_ack(client_seq, s_seq);
                return Ok(vec![ack]);
            }

            // Handshake / Payload packet (flag 0x80 or 0xc0)
            if (flags & 0x80) != 0 || (flags & 0x40) != 0 {
                info!(
                    "🎮 Ingested PComNetConn bunch from {} (client seq: 0x{:02x}, flags: 0x{:02x})",
                    src, client_seq, flags
                );
                let mut out = Vec::new();

                // 1. Reply with ACK
                out.push(wrap_pcom_ack(client_seq, s_seq));

                if client_seq == 0 && !session.replication.pawn_spawned {
                    // Send NMT_Welcome directing client to level URL
                    let welcome_msg = ControlMessage::Welcome {
                        level_url: self.config.level_url.clone(),
                        game_class: immortal_net::DEFAULT_GAME_CLASS.to_string(),
                    };
                    let welcome_bunch = Bunch::control(session.ctrl_sequence, welcome_msg.encode());
                    session.ctrl_sequence += 1;
                    let s_seq_welcome = session.server_sequence;
                    session.server_sequence = session.server_sequence.wrapping_add(1);
                    out.push(wrap_pcom_packet(
                        client_seq,
                        s_seq_welcome,
                        &welcome_bunch.encode(),
                    ));

                    // Send NMT_NetSpeed
                    let netspeed_msg = ControlMessage::NetSpeed {
                        rate: self.config.net_speed,
                    };
                    let netspeed_bunch =
                        Bunch::control(session.ctrl_sequence, netspeed_msg.encode());
                    session.ctrl_sequence += 1;
                    let s_seq_net = session.server_sequence;
                    session.server_sequence = session.server_sequence.wrapping_add(1);
                    out.push(wrap_pcom_packet(
                        client_seq,
                        s_seq_net,
                        &netspeed_bunch.encode(),
                    ));

                    // Open Actor Channel 2 & Spawn Fernando pawn
                    info!(
                        "🎉 Opening Actor Channel 2 and Spawning Fernando for {}!",
                        src
                    );
                    let open_ch2 = session.replication.open_channel_2();
                    let s_seq_ch2 = session.server_sequence;
                    session.server_sequence = session.server_sequence.wrapping_add(1);
                    out.push(wrap_pcom_packet(client_seq, s_seq_ch2, &open_ch2.encode()));

                    let spawn_fernando = session.replication.spawn_fernando();
                    let s_seq_spawn = session.server_sequence;
                    session.server_sequence = session.server_sequence.wrapping_add(1);
                    out.push(wrap_pcom_packet(
                        client_seq,
                        s_seq_spawn,
                        &spawn_fernando.encode(),
                    ));

                    session.replication.pawn_spawned = true;
                } else if session.replication.pawn_spawned {
                    // Client is sending input/acknowledgement; stream movement transform delta
                    let delta = session.replication.stream_baseline_delta(0.016);
                    let s_seq_delta = session.server_sequence;
                    session.server_sequence = session.server_sequence.wrapping_add(1);
                    out.push(wrap_pcom_packet(client_seq, s_seq_delta, &delta.encode()));
                }

                return Ok(out);
            }
        }

        let packet = parse_cpack_udp(data)?;
        let mut responses = Vec::new();

        let mut sessions = self.sessions.write().await;
        let session = sessions.entry(src).or_insert_with(|| {
            let session_id = rand_session_id();
            ClientSession::new(
                src,
                session_id,
                &self.config.level_url,
                self.config.net_speed,
            )
        });
        session.last_seen = Instant::now();

        match packet {
            CPackUdpPacket::HelloSend(hello) => {
                debug!(
                    "Ingested HelloSend from {} (conn_id: {})",
                    src, hello.connection_id
                );
                // Validate HMAC if present
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

            CPackUdpPacket::HelloRecvReply(_) | CPackUdpPacket::PingRecv(_) => {
                // Client usually doesn't send these to server
            }

            CPackUdpPacket::Bunch(bunch_raw) => match Bunch::decode(&bunch_raw) {
                Ok(bunch) => {
                    let bunch_responses = self.handle_bunch(bunch, session)?;
                    for b in bunch_responses {
                        responses.push(b.encode_cpack_udp());
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
                            let b = Bunch::control(session.ctrl_sequence, rep.encode());
                            session.ctrl_sequence += 1;
                            responses.push(b.encode_cpack_udp());
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

    /// Handles a parsed bunch and generates any response bunches.
    fn handle_bunch(&self, bunch: Bunch, session: &mut ClientSession) -> Result<Vec<Bunch>> {
        let mut out = Vec::new();

        match bunch.header.ch_index {
            CONTROL_CHANNEL_INDEX => {
                let msg = ControlMessage::decode(&bunch.data)?;
                debug!("Ingested Channel 0 ControlMessage: {:?}", msg);

                let replies = session.handshake.handle_control_message(&msg)?;
                for reply in replies {
                    out.push(Bunch::control(session.ctrl_sequence, reply.encode()));
                    session.ctrl_sequence += 1;
                }

                // If handshake completed, trigger Fernando pawn actor spawn & channel 2 opening!
                if session.handshake.phase == immortal_net::HandshakePhase::HandshakeCompleted
                    && !session.replication.pawn_spawned
                {
                    info!(
                        "🎉 Control Handshake Completed for {}. Opening Actor Channel 2 and Spawning Fernando!",
                        session.addr
                    );
                    session.phase = SessionPhase::Replicating;

                    // 1. Open Channel 2 for PlayerController
                    let open_ch2_bunch = session.replication.open_channel_2();
                    out.push(open_ch2_bunch);

                    // 2. Spawn and replicate Fernando pawn (TgPawn_Knight, 1026) at (0.0, 0.0, 100.0)
                    let spawn_bunch = session.replication.spawn_fernando();
                    out.push(spawn_bunch);

                    // 3. Baseline transform delta
                    let baseline_bunch = session.replication.stream_baseline_delta(0.016);
                    out.push(baseline_bunch);
                }
            }
            ACTOR_CHANNEL_INDEX => {
                // Client input / movement updates on Actor Channel 2
                debug!(
                    "Ingested Actor Channel 2 bunch (len: {}) from {}",
                    bunch.data.len(),
                    session.addr
                );
                // Stream baseline movement delta in response
                let delta = session.replication.stream_baseline_delta(0.016);
                out.push(delta);
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

fn rand_session_id() -> u32 {
    let now = current_time_millis();
    (now & 0xFFFFFFFF) as u32
}

/// Constructs a UE3 PComNetConn keepalive ACK datagram.
fn wrap_pcom_ack(client_seq: u8, server_seq: u8) -> Vec<u8> {
    vec![client_seq, 0x00, 0x00, 0x00, 0x00, 0x00, server_seq, 0x40]
}

/// Wraps payload into a UE3 PComNetConn datagram with trailing 1 bit.
fn wrap_pcom_packet(client_seq: u8, server_seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len() + 1);
    pkt.push(client_seq);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(server_seq);
    pkt.push(0x80);
    pkt.extend_from_slice(payload);
    pkt.push(0x01); // UE3 BitReader termination marker
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_net::{HelloSend, PingSend};

    #[tokio::test]
    async fn test_game_server_hello_handshake_flow() {
        let config = GameServerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server = GameServer::bind_with_config(config).await.unwrap();
        let client_addr: SocketAddr = "127.0.0.1:45678".parse().unwrap();

        // 1. Send HelloSend
        let hello_bytes = HelloSend::build(DEFAULT_HMAC_KEY, 1001, None, 650);
        let replies = server
            .handle_datagram(&hello_bytes, client_addr)
            .await
            .expect("Failed to handle HelloSend");

        assert_eq!(replies.len(), 1);
        let hello_reply = HelloRecvReply::decode(&replies[0]).unwrap();
        assert_eq!(hello_reply.negotiated_mtu, 1414);

        // 2. Send PingSend
        let ping_bytes = PingSend::new(1, 1000, true).encode();
        let ping_replies = server
            .handle_datagram(&ping_bytes, client_addr)
            .await
            .expect("Failed to handle PingSend");

        assert_eq!(ping_replies.len(), 1);
        let ping_reply = PingRecv::decode(&ping_replies[0]).unwrap();
        assert_eq!(ping_reply.sequence, 1);
        assert_eq!(ping_reply.negotiated_mtu, 1414);

        // 3. Send Channel 0 NMT_Hello bunch
        let nmt_hello = ControlMessage::Hello {
            engine_version: 10897,
            licensee_version: 0,
            map_url: "EntryMap".to_string(),
        };
        let hello_bunch = Bunch::control(0, nmt_hello.encode());
        let bunch_bytes = hello_bunch.encode_cpack_udp();

        let handshake_replies = server
            .handle_datagram(&bunch_bytes, client_addr)
            .await
            .expect("Failed to handle NMT_Hello bunch");

        // Should receive:
        // 1. NMT_NetSpeed (0x03) (ch 0 seq 0)
        // 2. NMT_Welcome (0x01) with ShootingRange map (ch 0 seq 1)
        // 3. Channel 2 Open (PlayerController) (ch 2 seq 0)
        // 4. Channel 2 Spawn Fernando (TgPawn_Knight, 1026) at (0.0, 0.0, 100.0) (ch 2 seq 1)
        // 5. Baseline transform delta (ch 2 seq 2)
        assert!(
            handshake_replies.len() >= 4,
            "Expected at least 4 bunches in response, got {}",
            handshake_replies.len()
        );

        // Verify each bunch datagram starts with CPACK_OP_BUNCH (0x04)
        for rep in &handshake_replies {
            assert_eq!(rep[0], immortal_net::CPACK_OP_BUNCH);
        }

        let bunch1 = Bunch::decode_cpack_udp(&handshake_replies[0]).unwrap();
        let bunch2 = Bunch::decode_cpack_udp(&handshake_replies[1]).unwrap();
        let bunch3 = Bunch::decode_cpack_udp(&handshake_replies[2]).unwrap();
        let bunch4 = Bunch::decode_cpack_udp(&handshake_replies[3]).unwrap();

        // Control Channel 0 sequence checks
        assert_eq!(bunch1.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(bunch1.header.ch_sequence, 0);
        assert_eq!(bunch2.header.ch_index, CONTROL_CHANNEL_INDEX);
        assert_eq!(bunch2.header.ch_sequence, 1);
        let welcome_msg = ControlMessage::decode(&bunch2.data).unwrap();
        match welcome_msg {
            ControlMessage::Welcome { level_url, .. } => {
                assert_eq!(level_url, DEFAULT_SHOOTING_RANGE_MAP);
            }
            other => panic!("Expected welcome message, found {:?}", other),
        }

        // Channel 2 opened with independent sequence counter starting at 0
        assert_eq!(bunch3.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(bunch3.header.ch_sequence, 0);
        assert!(bunch3.header.flags.b_open);

        // Fernando spawned on Channel 2 with sequence 1
        assert_eq!(bunch4.header.ch_index, ACTOR_CHANNEL_INDEX);
        assert_eq!(bunch4.header.ch_sequence, 1);
        let payload = crate::replication::ReplicationPayload::decode(&bunch4.data).unwrap();
        match payload {
            crate::replication::ReplicationPayload::SpawnActor {
                champion_id,
                class_name,
                location,
                ..
            } => {
                assert_eq!(champion_id, immortal_core::ChampionId::Fernando);
                assert_eq!(class_name, "TgPawn_Knight");
                assert_eq!(location.x, 0.0);
                assert_eq!(location.y, 0.0);
                assert_eq!(location.z, 100.0);
            }
            other => panic!("Expected SpawnActor payload, found {:?}", other),
        }
    }
}
