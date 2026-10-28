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
use tracing::{debug, error, info};

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
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9000)),
            game_server_host: "127.0.0.1".to_string(),
            game_server_port: 7777,
            account_id: 10001,
            session_token: "IMMORTAL-DEV-SESSION-TICKET".to_string(),
            match_ticket_str: "IMMORTAL-MATCH-TICKET-7777".to_string(),
            compress_response: false,
        }
    }
}

pub struct AuthGatewayHandle {
    shutdown_tx: broadcast::Sender<()>,
    local_addr: SocketAddr,
    join_handle: tokio::task::JoinHandle<Result<(), NetError>>,
}

impl AuthGatewayHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(self) -> Result<(), NetError> {
        let _ = self.shutdown_tx.send(());
        match self.join_handle.await {
            Ok(res) => res,
            Err(e) => Err(NetError::Io(std::io::Error::other(e.to_string()))),
        }
    }
}

pub struct AuthGateway {
    listener: TcpListener,
    config: Arc<AuthGatewayConfig>,
}

impl AuthGateway {
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let config = AuthGatewayConfig {
            bind_addr: addr,
            ..Default::default()
        };
        Self::bind_with_config(config).await
    }

    pub async fn bind_with_config(config: AuthGatewayConfig) -> Result<Self, NetError> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.listener.local_addr().map_err(NetError::Io)
    }

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
                                    debug!("Client connection {} finished or error: {:?}", peer_addr, e);
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

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<AuthGatewayConfig>,
) -> Result<(), NetError> {
    debug!("Accepted incoming MCTS TCP connection from {}", peer_addr);

    loop {
        let mut header = [0u8; HEADER_LEN];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(NetError::Io(e)),
        }

        let magic_raw = u16::from_le_bytes([header[0], header[1]]);
        let magic = MagicToken::from_u16(magic_raw)?;
        let payload_len = u16::from_le_bytes([header[2], header[3]]) as usize;

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

        // Attempt parsing login request if possible
        let _ = LoginRequest::from_bytes(&uncompressed_req);

        // Construct OnLoginResponse
        let match_ticket = MatchTicket::new(
            &config.game_server_host,
            config.game_server_port,
            &config.match_ticket_str,
        );

        let response = LoginResponse::new(config.account_id, &config.session_token, match_ticket);

        let response_bytes = response.to_bytes()?;

        let response_packet = if config.compress_response {
            CPackFrame::encode_compressed(&response_bytes)?
        } else {
            CPackFrame::encode_uncompressed(&response_bytes)?
        };

        stream.write_all(&response_packet).await?;
        stream.flush().await?;
        debug!("Sent OnLoginResponse to {}", peer_addr);
    }

    Ok(())
}
