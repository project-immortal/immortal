// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Typed errors for UPK package reading, parsing, and chunk decompression.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid UPK magic tag: expected 0x{expected:08X}, found 0x{found:08X}")]
    InvalidMagic { expected: u32, found: u32 },

    #[error("Invalid package version: {version}")]
    InvalidPackageVersion { version: u16 },

    #[error("Invalid FString: {reason}")]
    InvalidString { reason: String },

    #[error("Unsupported compression flags: 0x{flags:08X}")]
    UnsupportedCompression { flags: u32 },

    #[error("Decompression failed: {reason}")]
    DecompressionFailed { reason: String },

    #[error("Corrupt compressed chunk: {reason}")]
    CorruptChunk { reason: String },

    #[error("Buffer overflow: required {required} bytes, available {available}")]
    BufferOverflow { required: usize, available: usize },

    #[error("Invalid bulk data: {reason}")]
    InvalidBulkData { reason: String },

    #[error("TFC file not found: {tfc_name} (path: {path})")]
    TfcNotFound { tfc_name: String, path: String },

    #[error("Invalid audio archive/format: {reason}")]
    InvalidAudio { reason: String },

    #[error("Invalid mesh/skeleton data: {reason}")]
    InvalidMesh { reason: String },

    #[error("glTF export error: {reason}")]
    GltfExport { reason: String },
}
