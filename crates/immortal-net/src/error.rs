// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Network Errors
//! Cleanroom network and protocol error types for Project Immortal.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid magic token: 0x{0:04X}")]
    InvalidMagic(u16),

    #[error("Payload length {length} exceeds maximum allowed {max}")]
    PayloadTooLarge { length: usize, max: usize },

    #[error("Zlib compression error: {0}")]
    Compression(String),

    #[error("Zlib decompression error: {0}")]
    Decompression(String),

    #[error("Incomplete data frame: needed {needed} bytes, available {available}")]
    IncompleteData { needed: usize, available: usize },

    #[error("Marshal serialization/deserialization error: {0}")]
    Marshal(String),

    #[error("Invalid field token: {0}")]
    InvalidToken(u16),

    #[error("Unexpected field type: expected 0x{expected:02X}, found 0x{found:02X}")]
    UnexpectedFieldType { expected: u8, found: u8 },

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("UTF-16 decoding error: {0}")]
    Utf16(#[from] std::string::FromUtf16Error),
}
