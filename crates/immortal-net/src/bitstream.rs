// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Unreal Engine 3 LSB-First Bitstream Primitives & `appStrCrc`
//! Cleanroom implementation of Unreal Engine 3 bit-level reading/writing
//! (`FBitReader` / `FBitWriter` LSB-first bit packing, variable-width
//! `SerializeInt` / `WriteIntWrapped`, trailing stop-bit framing, `FString`
//! encoding, and UTF-16LE MSB-first CRC32 `appStrCrc`).

use crate::error::NetError;

/// Maximum permitted `FString` character/byte length for bounded decoding (`PSL-INV-011`).
pub const MAX_FSTRING_LEN: usize = 4096;

/// Unreal Engine 3 CRC32 polynomial (MSB-first, non-reflected).
pub const UE3_CRC32_POLY: u32 = 0x04C1_1DB7;

/// Paladins handshake CRC salt formatted as `"<salt> %d"` with signed `i32` challenge.
pub const HANDSHAKE_CRC_SALT: &str = "895fcf626f55798667e4e94cb7a636af";

const fn build_ue3_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            if (c & 0x8000_0000) != 0 {
                c = (c << 1) ^ UE3_CRC32_POLY;
            } else {
                c <<= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const UE3_CRC_TABLE: [u32; 256] = build_ue3_crc_table();

/// Computes UE3 `appStrCrc`: MSB-first CRC32 (`0x04C1_1DB7`, init `0xFFFF_FFFF`,
/// final bitwise NOT) over the UTF-16LE code units of `text` (low byte, then high byte).
pub fn ue3_str_crc(text: &str) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for unit in text.encode_utf16() {
        let lo = (unit & 0x00FF) as u8;
        let hi = ((unit >> 8) & 0x00FF) as u8;
        crc = UE3_CRC_TABLE[(((crc >> 24) as u8) ^ lo) as usize] ^ (crc << 8);
        crc = UE3_CRC_TABLE[(((crc >> 24) as u8) ^ hi) as usize] ^ (crc << 8);
    }
    !crc
}

/// Computes the expected `NMT_HandshakeResponse (0x1C)` CRC32 for a given `u32` challenge.
/// Formats the challenge as a signed 32-bit decimal (`%d`), matching client behavior.
pub fn ue3_handshake_crc(challenge: u32) -> u32 {
    let formatted = format!("{} {}", HANDSHAKE_CRC_SALT, challenge as i32);
    ue3_str_crc(&formatted)
}

/// Strips the UE3 trailing stop bit (`UNetConnection::ReceivedRawPacket` framing)
/// and returns the exact number of payload data bits preceding the highest set bit
/// in the final byte. Rejects empty slices and slices ending in `0x00`.
pub fn strip_stop_bit(ue3_bytes: &[u8]) -> Result<usize, NetError> {
    let Some(&last_byte) = ue3_bytes.last() else {
        return Err(NetError::InvalidUdpPacket(
            "Empty UE3 bitstream payload".to_string(),
        ));
    };
    if last_byte == 0 {
        return Err(NetError::InvalidUdpPacket(
            "Invalid trailing byte 0x00 (missing UE3 stop bit)".to_string(),
        ));
    }
    let total_raw_bits = ue3_bytes.len().checked_mul(8).ok_or_else(|| {
        NetError::BunchError("UE3 payload bit length arithmetic overflow".to_string())
    })?;
    Ok(total_raw_bits - 1 - last_byte.leading_zeros() as usize)
}

/// LSB-first bit reader matching UE3 `FBitReader`.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    num_bits: usize,
    pos: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a new `BitReader` over `data` spanning `num_bits` valid LSB-first bits.
    pub fn new(data: &'a [u8], num_bits: usize) -> Result<Self, NetError> {
        let capacity_bits = data.len().saturating_mul(8);
        if num_bits > capacity_bits {
            return Err(NetError::BunchError(format!(
                "BitReader num_bits ({}) exceeds buffer capacity ({} bits)",
                num_bits, capacity_bits
            )));
        }
        Ok(Self {
            data,
            num_bits,
            pos: 0,
        })
    }

    /// Returns `true` when all bits have been consumed.
    #[inline]
    pub fn at_end(&self) -> bool {
        self.pos >= self.num_bits
    }

    /// Returns the number of unread bits remaining.
    #[inline]
    pub fn bits_left(&self) -> usize {
        self.num_bits.saturating_sub(self.pos)
    }

    /// Returns the current bit cursor position.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Reads a single LSB-first bit.
    pub fn read_bit(&mut self) -> Result<bool, NetError> {
        if self.pos >= self.num_bits {
            return Err(NetError::BunchError(format!(
                "BitReader underflow at bit {} (total {} bits)",
                self.pos, self.num_bits
            )));
        }
        let byte = self.data[self.pos >> 3];
        let bit = ((byte >> (self.pos & 7)) & 1) != 0;
        self.pos += 1;
        Ok(bit)
    }

    /// Reads a variable-width unsigned integer in `[0, value_max)` using UE3
    /// `FBitReader::SerializeInt` (`while value + mask < value_max`) with `u64`
    /// arithmetic to prevent shift/addition overflow.
    pub fn read_int(&mut self, value_max: u32) -> Result<u32, NetError> {
        if value_max == 0 {
            return Err(NetError::BunchError(
                "BitReader::read_int called with value_max == 0".to_string(),
            ));
        }
        let max_u64 = u64::from(value_max);
        let mut value: u64 = 0;
        let mut mask: u64 = 1;
        if max_u64 > 1 {
            while value.saturating_add(mask) < max_u64 {
                if mask >= (1u64 << 32) {
                    break;
                }
                if self.read_bit()? {
                    value |= mask;
                }
                mask <<= 1;
            }
        }
        Ok(value as u32)
    }

    /// Reads `count` raw bits into a byte-aligned LSB-first buffer (`ceil(count / 8)` bytes).
    pub fn read_bits(&mut self, count: usize) -> Result<Vec<u8>, NetError> {
        if count > self.bits_left() {
            return Err(NetError::BunchError(format!(
                "BitReader payload underflow: requested {} bits at bit {}, only {} bits left",
                count,
                self.pos,
                self.bits_left()
            )));
        }
        let byte_len = count.div_ceil(8);
        let mut out = vec![0u8; byte_len];
        for i in 0..count {
            if self.read_bit()? {
                out[i >> 3] |= 1u8 << (i & 7);
            }
        }
        Ok(out)
    }

    /// Reads `count` raw bytes (`count * 8` bits) from the bitstream.
    pub fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>, NetError> {
        let bit_count = count.checked_mul(8).ok_or_else(|| {
            NetError::BunchError(format!("BitReader::read_bytes bit overflow for {}", count))
        })?;
        self.read_bits(bit_count)
    }

    /// Reads an 8-bit unsigned integer.
    pub fn read_u8(&mut self) -> Result<u8, NetError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    /// Reads a 16-bit little-endian unsigned integer.
    pub fn read_u16(&mut self) -> Result<u16, NetError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a 32-bit little-endian unsigned integer.
    pub fn read_u32(&mut self) -> Result<u32, NetError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a 32-bit little-endian signed integer.
    pub fn read_i32(&mut self) -> Result<i32, NetError> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a 64-bit little-endian unsigned integer.
    pub fn read_u64(&mut self) -> Result<u64, NetError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads a 32-bit little-endian IEEE-754 float.
    pub fn read_f32(&mut self) -> Result<f32, NetError> {
        let bytes = self.read_bytes(4)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a UE3 `SerializeCompressedVector`:
    /// `BitsMinus1 = read_int(20)`, `Bias = 1 << (BitsMinus1 + 1)`,
    /// `Max = 1 << (BitsMinus1 + 2)`, followed by X/Y/Z as `read_int(Max) - Bias`.
    pub fn read_compressed_vector(&mut self) -> Result<[f32; 3], NetError> {
        let bits_minus1 = self.read_int(20)?;
        let bias = 1i64 << (bits_minus1 + 1);
        let max_val = 1u32 << (bits_minus1 + 2);
        let x = (i64::from(self.read_int(max_val)?) - bias) as f32;
        let y = (i64::from(self.read_int(max_val)?) - bias) as f32;
        let z = (i64::from(self.read_int(max_val)?) - bias) as f32;
        Ok([x, y, z])
    }

    /// Reads a UE3 `SerializeCompressedRotator` in `(Pitch, Yaw, Roll)` order:
    /// per component, `1b bNonZero` + optional `u8` shifted left by `8`.
    pub fn read_compressed_rotator(&mut self) -> Result<[i32; 3], NetError> {
        let mut out = [0i32; 3];
        for slot in &mut out {
            if self.read_bit()? {
                *slot = i32::from(self.read_u8()?) << 8;
            }
        }
        Ok(out)
    }

    /// Reads a UE3 `FString` (`i32` length prefix):
    /// - `0` -> empty string (0 trailing bytes)
    /// - `> 0` -> ASCII/UTF-8 bytes including trailing NUL (`<= MAX_FSTRING_LEN`)
    /// - `< 0` -> `-len` UTF-16LE code units including trailing NUL (`<= MAX_FSTRING_LEN`, `checked_neg()`)
    pub fn read_fstring(&mut self) -> Result<String, NetError> {
        let raw_len = self.read_i32()?;
        if raw_len == 0 {
            return Ok(String::new());
        }
        if raw_len > 0 {
            let len = raw_len as usize;
            if len > MAX_FSTRING_LEN {
                return Err(NetError::PayloadTooLarge {
                    length: len,
                    max: MAX_FSTRING_LEN,
                });
            }
            let mut buf = self.read_bytes(len)?;
            if buf.last() == Some(&0) {
                buf.pop();
            }
            String::from_utf8(buf).map_err(NetError::Utf8)
        } else {
            let positive_len = raw_len.checked_neg().ok_or_else(|| {
                NetError::InvalidUdpPacket(format!(
                    "Integer negation overflow on FString length {}",
                    raw_len
                ))
            })?;
            let len = positive_len as usize;
            if len > MAX_FSTRING_LEN {
                return Err(NetError::PayloadTooLarge {
                    length: len,
                    max: MAX_FSTRING_LEN,
                });
            }
            let byte_len = len.checked_mul(2).ok_or(NetError::PayloadTooLarge {
                length: len,
                max: MAX_FSTRING_LEN,
            })?;
            let raw = self.read_bytes(byte_len)?;
            let mut units = Vec::with_capacity(len);
            let (chunks, _) = raw.as_chunks::<2>();
            for &[lo, hi] in chunks {
                units.push(u16::from_le_bytes([lo, hi]));
            }
            if units.last() == Some(&0) {
                units.pop();
            }
            String::from_utf16(&units).map_err(NetError::Utf16)
        }
    }
}

/// LSB-first bit writer matching UE3 `FBitWriter`.
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    data: Vec<u8>,
    num_bits: usize,
}

impl BitWriter {
    /// Creates an empty `BitWriter`.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            num_bits: 0,
        }
    }

    /// Creates a `BitWriter` pre-allocated for at least `bits` bits.
    pub fn with_capacity_bits(bits: usize) -> Self {
        Self {
            data: Vec::with_capacity(bits.div_ceil(8)),
            num_bits: 0,
        }
    }

    /// Returns the total number of written bits.
    #[inline]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Returns the written bytes (trailing unused bits in the final byte are zero).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the writer and returns the written byte vector.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Appends a single LSB-first bit.
    pub fn write_bit(&mut self, bit: bool) {
        let byte_idx = self.num_bits >> 3;
        if byte_idx >= self.data.len() {
            self.data.push(0);
        }
        if bit {
            self.data[byte_idx] |= 1u8 << (self.num_bits & 7);
        }
        self.num_bits += 1;
    }

    /// Writes a variable-width unsigned integer in `[0, value_max)` using UE3
    /// `FBitWriter::WriteIntWrapped` (`while written + mask < value_max`) with `u64`
    /// arithmetic. Rejects `value_max == 0` or `value >= value_max`.
    pub fn write_int(&mut self, value: u32, value_max: u32) -> Result<(), NetError> {
        if value_max == 0 || value >= value_max {
            return Err(NetError::BunchError(format!(
                "BitWriter::write_int value {} out of bounds for value_max {}",
                value, value_max
            )));
        }
        let max_u64 = u64::from(value_max);
        let val_u64 = u64::from(value);
        let mut written: u64 = 0;
        let mut mask: u64 = 1;
        if max_u64 > 1 {
            while written.saturating_add(mask) < max_u64 {
                if mask >= (1u64 << 32) {
                    break;
                }
                if (val_u64 & mask) != 0 {
                    self.write_bit(true);
                    written |= mask;
                } else {
                    self.write_bit(false);
                }
                mask <<= 1;
            }
        }
        Ok(())
    }

    /// Writes `count` raw LSB-first bits from `src`.
    pub fn write_bits(&mut self, src: &[u8], count: usize) -> Result<(), NetError> {
        let avail_bits = src.len().saturating_mul(8);
        if count > avail_bits {
            return Err(NetError::BunchError(format!(
                "BitWriter::write_bits requested {} bits from {}-bit source",
                count, avail_bits
            )));
        }
        for i in 0..count {
            let bit = ((src[i >> 3] >> (i & 7)) & 1) != 0;
            self.write_bit(bit);
        }
        Ok(())
    }

    /// Writes all bytes of `src` LSB-first.
    pub fn write_bytes(&mut self, src: &[u8]) {
        if (self.num_bits & 7) == 0 {
            self.data.extend_from_slice(src);
            self.num_bits += src.len() * 8;
        } else {
            for &byte in src {
                for bit_idx in 0..8 {
                    self.write_bit(((byte >> bit_idx) & 1) != 0);
                }
            }
        }
    }

    /// Writes an 8-bit unsigned integer.
    pub fn write_u8(&mut self, val: u8) {
        self.write_bytes(&[val]);
    }

    /// Writes a 16-bit little-endian unsigned integer.
    pub fn write_u16(&mut self, val: u16) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Writes a 32-bit little-endian unsigned integer.
    pub fn write_u32(&mut self, val: u32) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Writes a 32-bit little-endian signed integer.
    pub fn write_i32(&mut self, val: i32) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Writes a 64-bit little-endian unsigned integer.
    pub fn write_u64(&mut self, val: u64) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Writes a 32-bit little-endian IEEE-754 float (preserving exact bit representation).
    pub fn write_f32(&mut self, val: f32) {
        self.write_bytes(&val.to_bits().to_le_bytes());
    }

    /// Writes a UE3 `SerializeCompressedVector`:
    /// rounds finite components to `i64`, selects minimal `BitsMinus1` in `0..20`
    /// where `-(1 << (BitsMinus1 + 1)) <= c < (1 << (BitsMinus1 + 1))`, writes
    /// `BitsMinus1` via `write_int(bits_minus1, 20)`, and encodes X/Y/Z with `Bias` & `Max`.
    pub fn write_compressed_vector(&mut self, value: [f32; 3]) -> Result<(), NetError> {
        for &c in &value {
            if !c.is_finite() {
                return Err(NetError::BunchError(
                    "BitWriter::write_compressed_vector received non-finite component".to_string(),
                ));
            }
        }
        let ix = value[0].round() as i64;
        let iy = value[1].round() as i64;
        let iz = value[2].round() as i64;

        let mut bits_minus1: u32 = 0;
        while bits_minus1 < 20 {
            let bias = 1i64 << (bits_minus1 + 1);
            if ix >= -bias && ix < bias && iy >= -bias && iy < bias && iz >= -bias && iz < bias {
                break;
            }
            bits_minus1 += 1;
        }
        if bits_minus1 >= 20 {
            return Err(NetError::BunchError(format!(
                "BitWriter::write_compressed_vector ({}, {}, {}) exceeds 20-bit signed range",
                ix, iy, iz
            )));
        }

        self.write_int(bits_minus1, 20)?;
        let bias = 1i64 << (bits_minus1 + 1);
        let max_val = 1u32 << (bits_minus1 + 2);
        self.write_int((ix + bias) as u32, max_val)?;
        self.write_int((iy + bias) as u32, max_val)?;
        self.write_int((iz + bias) as u32, max_val)?;
        Ok(())
    }

    /// Writes a UE3 `SerializeCompressedRotator` in `(Pitch, Yaw, Roll)` order:
    /// per component, `1b bNonZero` + optional `u8` (`(c >> 8) & 0xFF`).
    pub fn write_compressed_rotator(&mut self, value: [i32; 3]) {
        for &c in &value {
            let byte = ((c >> 8) & 0xFF) as u8;
            if byte != 0 {
                self.write_bit(true);
                self.write_u8(byte);
            } else {
                self.write_bit(false);
            }
        }
    }

    /// Writes a UE3 `FString`:
    /// - Empty string writes `i32(0)` with 0 trailing bytes.
    /// - Pure ASCII writes positive `i32(len + 1)`, ASCII bytes, and `0x00`.
    /// - Non-ASCII Unicode writes negative `-(utf16_len + 1)`, UTF-16LE code units, and `0x0000`.
    pub fn write_fstring(&mut self, text: &str) {
        if text.is_empty() {
            self.write_i32(0);
            return;
        }
        if text.is_ascii() {
            let bytes = text.as_bytes();
            self.write_i32((bytes.len() + 1) as i32);
            self.write_bytes(bytes);
            self.write_u8(0);
        } else {
            let mut units: Vec<u16> = text.encode_utf16().collect();
            units.push(0);
            self.write_i32(-(units.len() as i32));
            for unit in units {
                self.write_u16(unit);
            }
        }
    }

    /// Appends the UE3 trailing `1` stop bit and zero-pads to the next byte boundary
    /// (`UNetConnection::FlushNet`).
    pub fn finish_with_stop_bit(mut self) -> Vec<u8> {
        self.write_bit(true);
        while (self.num_bits & 7) != 0 {
            self.write_bit(false);
        }
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_int_4608_boundaries() {
        // Non-power-of-two MaxPacketBits = 4608:
        // values with (v & 0xFFF) < 512 (0..=511 and 4096..=4607) encode in 13 bits;
        // values in 512..=4095 encode in 12 bits.
        let cases = [
            (0u32, 13usize),
            (40, 13),
            (511, 13),
            (512, 12),
            (1168, 12),
            (4095, 12),
            (4096, 13),
            (4607, 13),
        ];

        for (val, expected_bits) in cases {
            let mut w = BitWriter::new();
            w.write_int(val, 4608).unwrap();
            assert_eq!(
                w.num_bits(),
                expected_bits,
                "Unexpected SerializeInt(4608) width for value {}",
                val
            );
            let bytes = w.finish_with_stop_bit();
            let bit_len = strip_stop_bit(&bytes).unwrap();
            assert_eq!(bit_len, expected_bits);

            let mut r = BitReader::new(&bytes, bit_len).unwrap();
            let decoded = r.read_int(4608).unwrap();
            assert_eq!(decoded, val);
            assert!(r.at_end());
        }

        // Out-of-bounds value >= 4608 must be rejected
        let mut w = BitWriter::new();
        assert!(w.write_int(4608, 4608).is_err());
        assert!(w.write_int(0, 0).is_err());
    }

    #[test]
    fn test_serialize_int_power_of_two_limits() {
        let limits = [
            (0x4000u32, 14usize, 0x3FFF),
            (0x800, 11, 0x7FF),
            (0x400, 10, 0x3FF),
            (8, 3, 7),
        ];
        for (limit, expected_bits, sample_val) in limits {
            let mut w = BitWriter::new();
            w.write_int(sample_val, limit).unwrap();
            assert_eq!(w.num_bits(), expected_bits);
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, expected_bits).unwrap();
            assert_eq!(r.read_int(limit).unwrap(), sample_val);
            assert!(r.at_end());
        }
    }

    #[test]
    fn test_stop_bit_all_residues_and_zero_rejection() {
        for bit_count in 0..16 {
            let mut w = BitWriter::new();
            for i in 0..bit_count {
                w.write_bit((i & 1) == 1);
            }
            let wire = w.finish_with_stop_bit();
            let stripped = strip_stop_bit(&wire).unwrap();
            assert_eq!(stripped, bit_count);
            let mut r = BitReader::new(&wire, stripped).unwrap();
            for i in 0..bit_count {
                assert_eq!(r.read_bit().unwrap(), (i & 1) == 1);
            }
            assert!(r.at_end());
        }

        assert!(strip_stop_bit(&[]).is_err());
        assert!(strip_stop_bit(&[0x00]).is_err());
        assert!(strip_stop_bit(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn test_fstring_empty_ascii_utf16_and_error_bounds() {
        // Empty string -> i32(0) (4 bytes)
        let mut w = BitWriter::new();
        w.write_fstring("");
        assert_eq!(w.num_bits(), 32);
        let empty_bytes = w.into_bytes();
        assert_eq!(empty_bytes, vec![0, 0, 0, 0]);
        let mut r = BitReader::new(&empty_bytes, 32).unwrap();
        assert_eq!(r.read_fstring().unwrap(), "");

        // ASCII roundtrip
        let mut w = BitWriter::new();
        w.write_fstring("Shootingrange_P");
        let ascii_bits = w.num_bits();
        let ascii_bytes = w.into_bytes();
        let mut r = BitReader::new(&ascii_bytes, ascii_bits).unwrap();
        assert_eq!(r.read_fstring().unwrap(), "Shootingrange_P");

        // UTF-16 roundtrip (non-ASCII)
        let mut w = BitWriter::new();
        w.write_fstring("Paladins™");
        let u16_bits = w.num_bits();
        let u16_bytes = w.into_bytes();
        let mut r = BitReader::new(&u16_bytes, u16_bits).unwrap();
        assert_eq!(r.read_fstring().unwrap(), "Paladins™");

        // i32::MIN negation safety
        let min_bytes = i32::MIN.to_le_bytes();
        let mut r = BitReader::new(&min_bytes, 32).unwrap();
        assert!(matches!(
            r.read_fstring(),
            Err(NetError::InvalidUdpPacket(_))
        ));

        // Oversized positive length
        let over_pos = ((MAX_FSTRING_LEN as i32) + 1).to_le_bytes();
        let mut r = BitReader::new(&over_pos, 32).unwrap();
        assert!(matches!(
            r.read_fstring(),
            Err(NetError::PayloadTooLarge { .. })
        ));

        // Oversized negative length
        let over_neg = (-((MAX_FSTRING_LEN as i32) + 1)).to_le_bytes();
        let mut r = BitReader::new(&over_neg, 32).unwrap();
        assert!(matches!(
            r.read_fstring(),
            Err(NetError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_ue3_handshake_crc_signed_i32_positive_and_negative() {
        // Positive and negative signed i32 challenges must format using "%d"
        let cases: &[(u32, &str)] = &[
            (0x1234_5678, "895fcf626f55798667e4e94cb7a636af 305419896"),
            (0xDEAD_BEEF, "895fcf626f55798667e4e94cb7a636af -559038737"),
            (0xFFFF_FFFF, "895fcf626f55798667e4e94cb7a636af -1"),
            (0x8000_0000, "895fcf626f55798667e4e94cb7a636af -2147483648"),
        ];

        for &(challenge, expected_text) in cases {
            assert_eq!(
                ue3_handshake_crc(challenge),
                ue3_str_crc(expected_text),
                "CRC mismatch for challenge 0x{:08x}",
                challenge
            );
        }

        // Specifically assert unsigned formatting differs for negative challenges
        let unsigned_deadbeef = format!("{} {}", HANDSHAKE_CRC_SALT, 0xDEAD_BEEFu32);
        assert_ne!(
            ue3_handshake_crc(0xDEAD_BEEF),
            ue3_str_crc(&unsigned_deadbeef)
        );
    }

    #[test]
    fn test_serialize_int_20_boundaries() {
        // For Max = 20:
        // - 0..=3 have (val & 0xF) < 4 so written + 16 < 20 -> 5 bits
        // - 4..=15 have (val & 0xF) >= 4 so written + 16 >= 20 -> 4 bits
        // - 16..=19 have (val & 0xF) < 4 so written + 16 < 20 -> 5 bits
        for val in 0u32..20 {
            let expected_bits = if (val & 0xF) < 4 { 5 } else { 4 };
            let mut w = BitWriter::new();
            w.write_int(val, 20).unwrap();
            assert_eq!(
                w.num_bits(),
                expected_bits,
                "Unexpected SerializeInt(20) bit width for {}",
                val
            );
            let bytes = w.finish_with_stop_bit();
            let stripped = strip_stop_bit(&bytes).unwrap();
            assert_eq!(stripped, expected_bits);
            let mut r = BitReader::new(&bytes, stripped).unwrap();
            assert_eq!(r.read_int(20).unwrap(), val);
            assert!(r.at_end());
        }

        let mut w = BitWriter::new();
        assert!(w.write_int(20, 20).is_err());
    }

    #[test]
    fn test_compressed_vector_roundtrip_and_oracle_vectors() {
        let cases: &[([f32; 3], usize)] = &[
            ([0.0, 0.0, 0.0], 11),
            ([-2.0, 1.0, 0.0], 11),
            ([2.0, 0.0, 0.0], 14),
            ([-224.0, 0.0, 203.0], 31),
            ([1890.0, 239.0, 259.0], 40),
            ([-1_048_576.0, 1_048_575.0, 0.0], 68),
        ];

        for &(vec, expected_bits) in cases {
            let mut w = BitWriter::new();
            w.write_compressed_vector(vec).unwrap();
            assert_eq!(
                w.num_bits(),
                expected_bits,
                "Bit width mismatch for CompressedVector {:?}",
                vec
            );
            let bits = w.num_bits();
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, bits).unwrap();
            let decoded = r.read_compressed_vector().unwrap();
            assert_eq!(decoded, vec);
            assert!(r.at_end());
        }

        let mut w = BitWriter::new();
        assert!(w.write_compressed_vector([1_048_576.0, 0.0, 0.0]).is_err());
        assert!(w.write_compressed_vector([f32::NAN, 0.0, 0.0]).is_err());
    }

    #[test]
    fn test_compressed_rotator_roundtrip() {
        let cases: &[([i32; 3], usize)] = &[
            ([0, 0, 0], 3),
            ([0, 64512, 0], 11),
            ([256, 65280, 16384], 27),
        ];

        for &(rot, expected_bits) in cases {
            let mut w = BitWriter::new();
            w.write_compressed_rotator(rot);
            assert_eq!(w.num_bits(), expected_bits);
            let bits = w.num_bits();
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes, bits).unwrap();
            assert_eq!(r.read_compressed_rotator().unwrap(), rot);
            assert!(r.at_end());
        }

        // Low 8 bits are quantized away on wire (>> 8)
        let mut w = BitWriter::new();
        w.write_compressed_rotator([257, 64513, 127]);
        assert_eq!(w.num_bits(), 19);
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes, 19).unwrap();
        assert_eq!(r.read_compressed_rotator().unwrap(), [256, 64512, 0]);
        assert!(r.at_end());
    }
}
