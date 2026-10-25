// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Core
//! Shared data structures, champion definitions, math primitives, and cleanroom game types
//! for Project Immortal (Paladins Cleanroom Game Preservation & Server Emulation).

use serde::{Deserialize, Serialize};

/// Core Project Immortal version and banner.
pub const PROJECT_NAME: &str = "Project Immortal";
pub const PROJECT_MOTTO: &str = "I will not die, not yet, amigo!";
pub const TARGET_GAME_VERSION: &str = "8.1.5839.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ChampionId {
    Unknown = 0,
    Viktor = 1024,
    Cassie = 1025,
    Fernando = 1026,
    Ying = 1027,
}

impl ChampionId {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fernando => "Fernando",
            Self::Viktor => "Viktor",
            Self::Cassie => "Cassie",
            Self::Ying => "Ying",
            Self::Unknown => "Unknown",
        }
    }

    pub fn from_id(id: u32) -> Self {
        match id {
            1024 => Self::Viktor,
            1025 => Self::Cassie,
            1026 => Self::Fernando,
            1027 => Self::Ying,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_constants() {
        assert_eq!(PROJECT_MOTTO, "I will not die, not yet, amigo!");
        assert_eq!(TARGET_GAME_VERSION, "8.1.5839.0");
    }

    #[test]
    fn test_fernando_champion() {
        let nando = ChampionId::Fernando;
        assert_eq!(nando.name(), "Fernando");
    }
}
