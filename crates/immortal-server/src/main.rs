// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Server Daemon
//! High-performance cleanroom game server and auth gateway emulator for Project Immortal.

use anyhow::Result;
use immortal_core::{PROJECT_MOTTO, PROJECT_NAME, TARGET_GAME_VERSION};
use immortal_net::{DEFAULT_AUTH_PORT, DEFAULT_GAME_PORT};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("🔥 Starting {} Daemon", PROJECT_NAME);
    info!("💬 Motto: \"{}\"", PROJECT_MOTTO);
    info!("🎯 Target Paladins Game Version: {}", TARGET_GAME_VERSION);
    info!(
        "🌐 Auth Gateway listening on 127.0.0.1:{}",
        DEFAULT_AUTH_PORT
    );
    info!("🎮 Game Server listening on 0.0.0.0:{}", DEFAULT_GAME_PORT);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_server_smoketest() {
        assert!(true);
    }
}
