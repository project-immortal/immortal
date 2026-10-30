// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Tokio TCP Auth Gateway
//! Cleanroom MCTS TCP Auth Gateway server (default port 9000).
//! Accepts incoming client connections, decodes `CPackFrame` packets, parses `SendLogin` RPCs,
//! and responds with `OnLoginResponse` packages routing authenticated players to the game server.

use crate::error::NetError;
use crate::framing::{CPackFrame, MagicToken, HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::marshal::{LoginRequest, LoginResponse, MatchTicket};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Configuration options for the Tokio TCP Auth Gateway server.
#[derive(Debug, Clone)]
pub struct AuthGatewayConfig {
    pub bind_addr: SocketAddr,
    pub game_server_host: String,
    pub game_server_port: u16,
    pub account_id: i32,
    pub player_name: String,
    pub session_token: String,
    pub match_ticket_str: String,
    pub compress_response: bool,
}

impl Default for AuthGatewayConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], crate::DEFAULT_AUTH_PORT)),
            game_server_host: "127.0.0.1".to_string(),
            game_server_port: crate::DEFAULT_GAME_PORT,
            account_id: 8302401,
            player_name: "Fernando".to_string(),
            session_token: "IMMORTAL-DEV-SESSION-TICKET".to_string(),
            match_ticket_str: "IMMORTAL-MATCH-TICKET-7777".to_string(),
            compress_response: false,
        }
    }
}

/// Running handle for the Tokio TCP Auth Gateway server, exposing shutdown and address inspection.
pub struct AuthGatewayHandle {
    shutdown_tx: broadcast::Sender<()>,
    local_addr: SocketAddr,
    join_handle: tokio::task::JoinHandle<Result<(), NetError>>,
}

impl AuthGatewayHandle {
    /// Returns the local socket address this gateway is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sends a shutdown signal to the accept loop and awaits graceful termination.
    pub async fn shutdown(self) -> Result<(), NetError> {
        let _ = self.shutdown_tx.send(());
        match self.join_handle.await {
            Ok(res) => res,
            Err(e) => Err(NetError::Io(std::io::Error::other(e.to_string()))),
        }
    }
}

/// Tokio-based TCP Auth Gateway server that authenticates client connections and routes players to game servers.
pub struct AuthGateway {
    listener: TcpListener,
    config: Arc<AuthGatewayConfig>,
}

impl AuthGateway {
    /// Binds the AuthGateway TCP listener to the specified socket address using default configuration settings.
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let config = AuthGatewayConfig {
            bind_addr: addr,
            ..Default::default()
        };
        Self::bind_with_config(config).await
    }

    /// Binds the AuthGateway TCP listener using a custom [`AuthGatewayConfig`].
    pub async fn bind_with_config(config: AuthGatewayConfig) -> Result<Self, NetError> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// Returns the local socket address of the underlying TCP listener.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.listener.local_addr().map_err(NetError::Io)
    }

    /// Spawns the AuthGateway accept loop on a background Tokio task and returns an [`AuthGatewayHandle`].
    pub fn spawn(self) -> Result<AuthGatewayHandle, NetError> {
        let local_addr = self.local_addr()?;
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let join_handle = tokio::spawn(async move { self.run(shutdown_rx).await });
        Ok(AuthGatewayHandle {
            shutdown_tx,
            local_addr,
            join_handle,
        })
    }

    /// Runs the AuthGateway accept loop until a shutdown signal is received.
    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) -> Result<(), NetError> {
        let config = self.config;
        loop {
            tokio::select! {
                res = self.listener.accept() => {
                    match res {
                        Ok((stream, peer_addr)) => {
                            let cfg = Arc::clone(&config);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, peer_addr, cfg).await {
                                    warn!("Client connection {} finished or error: {:?}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("AuthGateway accept error: {:?}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("AuthGateway received shutdown signal, halting accept loop.");
                    break;
                }
            }
        }
        Ok(())
    }
}

pub use crate::mcts_handshake::{
    create_mcts_change_map_frame, create_mcts_champion_roster_frame,
    create_mcts_login_response_frame, create_mcts_match_status_frame,
    create_mcts_match_status_with_members_frame,
    create_mcts_player_svc_change_map_frame, BOT_ID_FERNANDO, CHUNK1_HANDSHAKE, CHUNK2_ACK, CHUNK3_SESSION,
    MAP_GAME_ID_SHOOTING_RANGE, MAP_INSTANCE_ID_SHOOTING_RANGE, MCTS_CHAMPION_SELECT_ACK_FRAME,
    MCTS_CLIENT_AUTH_REQUEST_FLAGS, MCTS_CLIENT_AUTH_REQUEST_LEN, MCTS_CLIENT_CRYPTO_TICKET_FLAGS,
    MCTS_CLIENT_CRYPTO_TICKET_LEN, MCTS_FUNCTION_ID_CHAMPION_ROSTER, MCTS_FUNCTION_ID_CHANGE_MAP,
    MCTS_FUNCTION_ID_MATCH_STATUS, MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE,
    MCTS_FUNCTION_ID_PLAYER_SVC_CHANGE_MAP, MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP,
    MCTS_HANDSHAKE_CHUNK1, MCTS_HANDSHAKE_CHUNK2_ACK, MCTS_HANDSHAKE_CHUNK3_SESSION,
    MCTS_HELLO_RESPONSE_FRAME, MCTS_HELLO_RESPONSE_PAYLOAD, MCTS_WIRE_FLAG_CHUNK,
};

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<AuthGatewayConfig>,
) -> Result<(), NetError> {
    debug!("Accepted incoming MCTS TCP connection from {}", peer_addr);
    let mut post_login_count: usize = 0;
    let mut login_completed = false;

    loop {
        let mut header = [0u8; HEADER_LEN];
        match stream.read_exact(&mut header).await {
            Ok(_) => {
                debug!("Received wire header from {}: {:02x?}", peer_addr, &header);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Peer {} closed connection (EOF)", peer_addr);
                break;
            }
            Err(e) => {
                error!("Peer {} read error: {:?}", peer_addr, e);
                return Err(NetError::Io(e));
            }
        }

        let field0 = u16::from_le_bytes([header[0], header[1]]);
        let field1 = u16::from_le_bytes([header[2], header[3]]);

        if login_completed {
            let payload_len = field0 as usize;
            let flags = field1;
            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                stream.read_exact(&mut payload).await?;
            }

            let has_fernando = payload.windows(2).any(|w| w == [0x9b, 0x08] || w == [0x08, 0x9b]) // agyis: no-mutant diagnostic logging
                || payload.windows(2).any(|w| w == 2203u16.to_le_bytes() || w == 2203u16.to_be_bytes()); // agyis: no-mutant diagnostic logging
            let has_shooting_range_req = payload.windows(2).any(|w| w == 434u16.to_le_bytes())
                || payload.windows(4).any(|w| w == MAP_GAME_ID_SHOOTING_RANGE.to_le_bytes());
            info!( // agyis: no-mutant logging
                "Received Live MCTS post-login/queue/champion select frame ({} bytes, flags 0x{:04x}, fernando={}, shooting_range={}) from {}",
                payload_len, flags, has_fernando, has_shooting_range_req, peer_addr
            );

            post_login_count += 1;
            if post_login_count == 1 || has_shooting_range_req {
                // Emit Shooting Range transition: MATCH_STATUS state 8 -> Champion Roster -> MATCH_STATUS state 10 with members table -> PlayerSvcChangeMap -> ChangeMap
                let match_status_8 = create_mcts_match_status_with_members_frame(
                    0,
                    878850364,
                    8,
                    0,
                    5,
                    4,
                    config.account_id as u64,
                    BOT_ID_FERNANDO,
                );
                stream.write_all(&match_status_8).await?;

                let champion_roster_frame =
                    create_mcts_champion_roster_frame(&[1026, 1024, 1025, 1027]);
                stream.write_all(&champion_roster_frame).await?;

                let match_status_10 = create_mcts_match_status_with_members_frame(
                    0,
                    878850364,
                    10,
                    0,
                    5,
                    7,
                    config.account_id as u64,
                    BOT_ID_FERNANDO,
                );
                stream.write_all(&match_status_10).await?;

                let player_svc_change_map_frame = create_mcts_player_svc_change_map_frame(
                    MAP_GAME_ID_SHOOTING_RANGE,
                    MAP_INSTANCE_ID_SHOOTING_RANGE,
                    false,
                );
                stream.write_all(&player_svc_change_map_frame).await?;

                let change_map_frame = create_mcts_change_map_frame(
                    MAP_GAME_ID_SHOOTING_RANGE,
                    MAP_INSTANCE_ID_SHOOTING_RANGE as u64,
                    true,
                );
                stream.write_all(&change_map_frame).await?;
                stream.flush().await?;
                info!(
                    "Sent Live MCTS Shooting Range transition (status 8 [lock:5, queue:4], champion roster, status 10 with members table [lock:5, queue:7, account_id={}, bot_id={}], player_svc_change_map, change_map mapGameId={}, instanceId={}) to {}",
                    config.account_id, BOT_ID_FERNANDO, MAP_GAME_ID_SHOOTING_RANGE, MAP_INSTANCE_ID_SHOOTING_RANGE, peer_addr
                );
            } else {
                // Reply with champion select acknowledgment frame (Frame 2554)
                stream.write_all(&MCTS_CHAMPION_SELECT_ACK_FRAME).await?;
                stream.flush().await?;
                info!("Sent Live MCTS champion select acknowledgment frame (19 bytes) to {}", peer_addr); // agyis: no-mutant logging
            }
        } else if field0 == MCTS_CLIENT_AUTH_REQUEST_LEN && field1 == MCTS_CLIENT_AUTH_REQUEST_FLAGS {
            // Live MCTS Step 1: Client Auth Request / Hello (405 bytes, flags 0x0000)
            let mut payload = vec![0u8; MCTS_CLIENT_AUTH_REQUEST_LEN as usize];
            stream.read_exact(&mut payload).await?;

            let hex_preview = payload
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            info!(
                "Received Live MCTS Step 1 Hello (405 bytes) from {}: {}...",
                peer_addr, hex_preview
            );

            // Respond with unencrypted CMarshal Hello response (wire flags 0x0000, 20-byte payload)
            // Client checks Field 2 (true) and Field 4 (1), setting CPackSession to authenticated.
            stream.write_all(&MCTS_HELLO_RESPONSE_FRAME).await?;
            stream.flush().await?;
            info!(
                "Sent unencrypted Live MCTS Hello Response (24 bytes, flags 0x0000) to {}. Awaiting SendLogin...",
                peer_addr
            );
        } else if (field0 == MCTS_CLIENT_CRYPTO_TICKET_LEN
            && field1 == MCTS_CLIENT_CRYPTO_TICKET_FLAGS)
            || (field0 > 0 && field1 == 0x0100)
        {
            // Live MCTS Step 2: Client SendLogin (1117 bytes or chunked wire transport)
            let mut payload = vec![0u8; field0 as usize];
            stream.read_exact(&mut payload).await?;

            info!(
                "Received Live MCTS Step 2 SendLogin ({} bytes, flags 0x{:04x}) from {}",
                field0, field1, peer_addr
            );

            // Send Chunk 2 ACK (21 bytes) with wire header [21 as u16, 0x0100]
            let mut ack_pkt = Vec::with_capacity(4 + MCTS_HANDSHAKE_CHUNK2_ACK.len());
            ack_pkt.extend_from_slice(&(MCTS_HANDSHAKE_CHUNK2_ACK.len() as u16).to_le_bytes());
            ack_pkt.extend_from_slice(&MCTS_WIRE_FLAG_CHUNK.to_le_bytes());
            ack_pkt.extend_from_slice(&MCTS_HANDSHAKE_CHUNK2_ACK);
            stream.write_all(&ack_pkt).await?;

            // Send Chunk 3 Session (75 bytes, which already contains the 3 framed subpackets)
            stream.write_all(&MCTS_HANDSHAKE_CHUNK3_SESSION).await?;

            // Send authentic Live MCTS OnLoginResponse wire frame (reverse engineered CMarshalRow::Store format)
            let login_frame = create_mcts_login_response_frame(
                config.account_id as u64,
                &config.player_name,
                &config.session_token,
            );
            stream.write_all(&login_frame).await?;
            stream.flush().await?;
            info!(
                "Sent Live MCTS Chunk 2 ACK, Chunk 3 Session, and OnLoginResponse (account_id={}, player_name={}) to {}",
                config.account_id, config.player_name, peer_addr
            );

            // Emit OnMatchStatus frame declaring initial lobby state (queue_id 0, match_id 0, match_lobby_state 0, launch_seconds 0, player_lobby_state 0, player_queue_state 0)
            let match_status_frame = create_mcts_match_status_frame(0, 0, 0, 0, 0, 0);
            stream.write_all(&match_status_frame).await?;
            stream.flush().await?;
            info!( // agyis: no-mutant logging
                "Sent Live MCTS OnMatchStatus initial lobby frame (0, 0, 0, 0, 0, 0) to {}",
                peer_addr
            );
            login_completed = true;
        } else {
            // Synthetic / standard CPackFrame flow
            let magic = MagicToken::from_u16(field0)?;
            let payload_len = field1 as usize;

            if payload_len > MAX_PAYLOAD_LEN {
                return Err(NetError::PayloadTooLarge {
                    length: payload_len,
                    max: MAX_PAYLOAD_LEN,
                });
            }

            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).await?;

            let req_frame = CPackFrame { magic, payload };
            let uncompressed_req = req_frame.uncompressed_payload()?;

            let login_req = LoginRequest::from_bytes(&uncompressed_req)?;
            debug!(
                "Validated SendLogin RPC from {}: version={}, platform_token={}",
                peer_addr, login_req.client_version, login_req.platform_token
            );

            // Construct OnLoginResponse
            let match_ticket = MatchTicket::new(
                &config.game_server_host,
                config.game_server_port,
                &config.match_ticket_str,
            );

            let response =
                LoginResponse::new(config.account_id, &config.session_token, match_ticket);

            let response_bytes = response.to_bytes()?;

            let should_compress = config.compress_response || magic == MagicToken::Compressed;
            let response_packet = if should_compress {
                CPackFrame::encode_compressed(&response_bytes)?
            } else {
                CPackFrame::encode_uncompressed(&response_bytes)?
            };

            stream.write_all(&response_packet).await?;
            stream.flush().await?;
            debug!("Sent OnLoginResponse to {}", peer_addr);
        }
    }

    Ok(())
}
