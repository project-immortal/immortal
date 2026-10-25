// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Extract
//! Cleanroom Unreal Engine 3 CookedPCConsole Package (`.upk`), Texture File Cache (`.tfc`),
//! and audio asset extractor adhering to the BYOD ("Bring Your Own Data") standard.

pub const UPK_MAGIC: u32 = 0x9E2A83C1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpkHeader {
    pub tag: u32,
    pub file_version: u16,
    pub license_mode: u16,
    pub package_flags: u32,
}

impl UpkHeader {
    pub fn is_valid_ue3_package(&self) -> bool {
        self.tag == UPK_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upk_magic() {
        let header = UpkHeader {
            tag: UPK_MAGIC,
            file_version: 860,
            license_mode: 0,
            package_flags: 0,
        };
        assert!(header.is_valid_ue3_package());
    }
}
