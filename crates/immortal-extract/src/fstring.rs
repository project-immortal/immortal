// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Unreal Engine 3 `FString` binary reader and writer.
//!
//! An `FString` is serialized as:
//! - 32-bit signed length prefix `L`:
//!   - If `L > 0`: ANSI / UTF-8 string with `L` bytes (including null terminator).
//!   - If `L < 0`: UTF-16LE string with `-L` 16-bit characters (including null terminator).
//!   - If `L == 0`: Empty string.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::error::ExtractError;

/// Reads an `FString` from a binary stream.
pub fn read_fstring<R: Read>(reader: &mut R) -> Result<String, ExtractError> {
    let length = reader.read_i32::<LittleEndian>()?;

    match length {
        0 => Ok(String::new()),
        l if l > 0 => {
            let byte_count = l as usize;
            let mut buf = vec![0u8; byte_count];
            reader.read_exact(&mut buf)?;

            // Strip trailing null terminator if present
            if let Some(&0) = buf.last() {
                buf.pop();
            }

            String::from_utf8(buf).map_err(|e| ExtractError::InvalidString {
                reason: format!("UTF-8 decoding failed: {e}"),
            })
        }
        l => {
            let char_count = (-l) as usize;
            let mut u16_buf = Vec::with_capacity(char_count);
            for _ in 0..char_count {
                u16_buf.push(reader.read_u16::<LittleEndian>()?);
            }

            // Strip trailing null terminator if present
            if let Some(&0) = u16_buf.last() {
                u16_buf.pop();
            }

            String::from_utf16(&u16_buf).map_err(|e| ExtractError::InvalidString {
                reason: format!("UTF-16 decoding failed: {e}"),
            })
        }
    }
}

/// Writes an `FString` to a binary stream.
pub fn write_fstring<W: Write>(writer: &mut W, s: &str, utf16: bool) -> std::io::Result<()> {
    if s.is_empty() {
        writer.write_i32::<LittleEndian>(0)?;
        return Ok(());
    }

    if utf16 {
        let utf16_chars: Vec<u16> = s.encode_utf16().collect();
        let length = -((utf16_chars.len() as i32) + 1);
        writer.write_i32::<LittleEndian>(length)?;
        for ch in utf16_chars {
            writer.write_u16::<LittleEndian>(ch)?;
        }
        writer.write_u16::<LittleEndian>(0)?; // null terminator
    } else {
        let bytes = s.as_bytes();
        let length = (bytes.len() as i32) + 1;
        writer.write_i32::<LittleEndian>(length)?;
        writer.write_all(bytes)?;
        writer.write_u8(0)?; // null terminator
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_fstring_ascii_roundtrip() {
        let mut buf = Vec::new();
        let original = "ChaosGame/CookedPCConsole";
        write_fstring(&mut buf, original, false).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = read_fstring(&mut cursor).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_fstring_utf16_roundtrip() {
        let mut buf = Vec::new();
        let original = "Fernando🛡️Champion";
        write_fstring(&mut buf, original, true).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = read_fstring(&mut cursor).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_fstring_empty() {
        let mut buf = Vec::new();
        write_fstring(&mut buf, "", false).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = read_fstring(&mut cursor).unwrap();
        assert_eq!(parsed, "");
    }
}
