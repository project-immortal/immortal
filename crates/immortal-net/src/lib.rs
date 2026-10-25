// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net
//! Cleanroom Unreal Engine 3 bit-packed bunch protocol parser, control channel state
//! machine, and auth gateway protocol definitions.

pub const DEFAULT_GAME_PORT: u16 = 7777;
pub const DEFAULT_AUTH_PORT: u16 = 9000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelType {
    Control = 0,
    Actor = 1,
    File = 2,
    Voice = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports() {
        assert_eq!(DEFAULT_GAME_PORT, 7777);
        assert_eq!(DEFAULT_AUTH_PORT, 9000);
    }
}
