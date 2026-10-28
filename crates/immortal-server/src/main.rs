// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Server Daemon
//! High-performance cleanroom game server and auth gateway emulator for Project Immortal.

use anyhow::Result;
use immortal_core::{PROJECT_MOTTO, PROJECT_NAME, TARGET_GAME_VERSION};
use immortal_net::{AuthGateway, AuthGatewayConfig, DEFAULT_AUTH_PORT, DEFAULT_GAME_PORT};
use immortal_server::{GameServer, GameServerConfig};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("🔥 Starting {} Daemon", PROJECT_NAME);
    info!("💬 Motto: \"{}\"", PROJECT_MOTTO);
    info!("🎯 Target Paladins Game Version: {}", TARGET_GAME_VERSION);

    // 1. Initialize MCTS TCP Auth Gateway (port 9000)
    let auth_config = AuthGatewayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], DEFAULT_AUTH_PORT)),
        ..Default::default()
    };
    let auth_gateway = AuthGateway::bind_with_config(auth_config).await?;
    let auth_handle = auth_gateway.spawn()?;
    info!(
        "🌐 Auth Gateway listening on {}",
        auth_handle.local_addr()
    );

    // 2. Initialize UDP Game Server (port 7777)
    let game_config = GameServerConfig {
        bind_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_GAME_PORT)),
        ..Default::default()
    };
    let game_handle = GameServer::start(game_config)?;
    info!("🎮 Game Server listening on UDP {}", game_handle.local_addr());

    info!("🚀 Cleanroom server services successfully started. Press Ctrl+C to terminate.");

    tokio::signal::ctrl_c().await?;
    info!("🛑 Shutdown signal received, terminating daemons...");

    if let Err(e) = game_handle.shutdown().await {
        tracing::error!("Error shutting down game server: {}", e);
    }
    if let Err(e) = auth_handle.shutdown().await {
        tracing::error!("Error shutting down auth gateway: {}", e);
    }
    info!("👋 Immortal Daemon exited cleanly.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_smoketest() {
        assert_eq!(DEFAULT_GAME_PORT, 7777);
    }
}
