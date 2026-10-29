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
    CHUNK1_HANDSHAKE, CHUNK2_ACK, CHUNK3_SESSION, MCTS_CLIENT_AUTH_REQUEST_FLAGS,
    MCTS_CLIENT_AUTH_REQUEST_LEN, MCTS_CLIENT_CRYPTO_TICKET_FLAGS, MCTS_CLIENT_CRYPTO_TICKET_LEN,
    MCTS_HANDSHAKE_CHUNK1, MCTS_HANDSHAKE_CHUNK2_ACK, MCTS_HANDSHAKE_CHUNK3_SESSION,
    MCTS_WIRE_FLAG_CHUNK,
};

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<AuthGatewayConfig>,
) -> Result<(), NetError> {
    debug!("Accepted incoming MCTS TCP connection from {}", peer_addr);

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

        if field0 == MCTS_CLIENT_AUTH_REQUEST_LEN && field1 == MCTS_CLIENT_AUTH_REQUEST_FLAGS {
            // Live MCTS Step 1: Client Auth Request (405 bytes, flags 0x0000)
            let mut payload = vec![0u8; MCTS_CLIENT_AUTH_REQUEST_LEN as usize];
            stream.read_exact(&mut payload).await?;

            let hex_preview = payload.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            info!("Received Live MCTS Step 1 (405 bytes) from {}: {}", peer_addr, hex_preview);

            let mut pkt = Vec::with_capacity(4 + MCTS_HANDSHAKE_CHUNK1.len());
            pkt.extend_from_slice(&(MCTS_HANDSHAKE_CHUNK1.len() as u16).to_le_bytes());
            pkt.extend_from_slice(&MCTS_WIRE_FLAG_CHUNK.to_le_bytes());
            pkt.extend_from_slice(&MCTS_HANDSHAKE_CHUNK1);
            stream.write_all(&pkt).await?;
            stream.flush().await?;
            info!("Sent Live MCTS Handshake Chunk 1 to {}. Awaiting Step 2...", peer_addr);
        } else if field0 == MCTS_CLIENT_CRYPTO_TICKET_LEN && field1 == MCTS_CLIENT_CRYPTO_TICKET_FLAGS {
            // Live MCTS Step 2: Client Crypto Ticket (1117 bytes, flags 0x0100)
            let mut payload = vec![0u8; MCTS_CLIENT_CRYPTO_TICKET_LEN as usize];
            stream.read_exact(&mut payload).await?;

            // Send Chunk 2 ACK (21 bytes) with wire header [21 as u16, 0x0100]
            let mut ack_pkt = Vec::with_capacity(4 + MCTS_HANDSHAKE_CHUNK2_ACK.len());
            ack_pkt.extend_from_slice(&(MCTS_HANDSHAKE_CHUNK2_ACK.len() as u16).to_le_bytes());
            ack_pkt.extend_from_slice(&MCTS_WIRE_FLAG_CHUNK.to_le_bytes());
            ack_pkt.extend_from_slice(&MCTS_HANDSHAKE_CHUNK2_ACK);
            stream.write_all(&ack_pkt).await?;

            // Send Chunk 3 Session (75 bytes, which already contains the 3 framed subpackets)
            stream.write_all(&MCTS_HANDSHAKE_CHUNK3_SESSION).await?;

            // Also send the LoginResponse containing Fernando (1026), Cassie (1024), Viktor (1025), Flame Lance (10774), and Starter Deck (16379), along with MatchTicket routing to 127.0.0.1:7777
            let match_ticket = MatchTicket::new(
                &config.game_server_host,
                config.game_server_port,
                &config.match_ticket_str,
            );
            let response =
                LoginResponse::new(config.account_id, &config.session_token, match_ticket);
            let response_bytes = response.to_bytes()?;
            let should_compress = config.compress_response;
            let response_packet = if should_compress {
                CPackFrame::encode_compressed(&response_bytes)?
            } else {
                CPackFrame::encode_uncompressed(&response_bytes)?
            };
            stream.write_all(&response_packet).await?;
            stream.flush().await?;
            debug!(
                "Sent Live MCTS Chunk 2 ACK, Chunk 3 Session, and LoginResponse to {}",
                peer_addr
            );
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

