// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # CPackCoder Wire Framing
//! Cleanroom framing layer for MCTS TCP protocol (port 9000).
//! Layout: `[magic_token: u16 LE, payload_len: u16 LE, payload: [u8]]`.

use crate::error::NetError;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

pub const HEADER_LEN: usize = 4;
pub const MAX_PAYLOAD_LEN: usize = 2046; // 0x07FE

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MagicToken {
    Compressed = 0xCBB0,
    Uncompressed = 0xCBBC,
}

impl MagicToken {
    pub fn from_u16(val: u16) -> Result<Self, NetError> {
        match val {
            0xCBB0 => Ok(Self::Compressed),
            0xCBBC => Ok(Self::Uncompressed),
            other => Err(NetError::InvalidMagic(other)),
        }
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CPackFrame {
    pub magic: MagicToken,
    pub payload: Vec<u8>,
}

impl CPackFrame {
    pub fn new(magic: MagicToken, payload: Vec<u8>) -> Result<Self, NetError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        Ok(Self { magic, payload })
    }

    pub fn encode_uncompressed(payload: &[u8]) -> Result<Vec<u8>, NetError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.write_u16::<LittleEndian>(MagicToken::Uncompressed.as_u16())?;
        out.write_u16::<LittleEndian>(payload.len() as u16)?;
        out.extend_from_slice(payload);
        Ok(out)
    }

    pub fn encode_compressed(payload: &[u8]) -> Result<Vec<u8>, NetError> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(payload)
            .map_err(|e| NetError::Compression(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| NetError::Compression(e.to_string()))?;

        if compressed.len() > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: compressed.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + compressed.len());
        out.write_u16::<LittleEndian>(MagicToken::Compressed.as_u16())?;
        out.write_u16::<LittleEndian>(compressed.len() as u16)?;
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, NetError> {
        let magic_raw = reader.read_u16::<LittleEndian>()?;
        let magic = MagicToken::from_u16(magic_raw)?;
        let payload_len = reader.read_u16::<LittleEndian>()? as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD_LEN,
            });
        }
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;
        Ok(Self { magic, payload })
    }

    pub fn decode_from_slice(data: &[u8]) -> Result<(Self, usize), NetError> {
        if data.len() < HEADER_LEN {
            return Err(NetError::IncompleteData {
                needed: HEADER_LEN,
                available: data.len(),
            });
        }
        let mut cursor = std::io::Cursor::new(data);
        let magic_raw = cursor.read_u16::<LittleEndian>()?;
        let magic = MagicToken::from_u16(magic_raw)?;
        let payload_len = cursor.read_u16::<LittleEndian>()? as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD_LEN,
            });
        }
        let total_len = HEADER_LEN + payload_len;
        if data.len() < total_len {
            return Err(NetError::IncompleteData {
                needed: total_len,
                available: data.len(),
            });
        }
        let payload = data[HEADER_LEN..total_len].to_vec();
        Ok((Self { magic, payload }, total_len))
    }

    pub fn uncompressed_payload(&self) -> Result<Vec<u8>, NetError> {
        match self.magic {
            MagicToken::Uncompressed => Ok(self.payload.clone()),
            MagicToken::Compressed => {
                let mut decoder = ZlibDecoder::new(&self.payload[..]);
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(|e| NetError::Decompression(e.to_string()))?;
                Ok(decompressed)
            }
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, NetError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(NetError::PayloadTooLarge {
                length: self.payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.write_u16::<LittleEndian>(self.magic.as_u16())?;
        out.write_u16::<LittleEndian>(self.payload.len() as u16)?;
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_tokens() {
        assert_eq!(MagicToken::Compressed.as_u16(), 0xCBB0);
        assert_eq!(MagicToken::Uncompressed.as_u16(), 0xCBBC);
        assert_eq!(
            MagicToken::from_u16(0xCBB0).unwrap(),
            MagicToken::Compressed
        );
        assert_eq!(
            MagicToken::from_u16(0xCBBC).unwrap(),
            MagicToken::Uncompressed
        );
        assert!(MagicToken::from_u16(0x1234).is_err());
    }

    #[test]
    fn test_roundtrip_uncompressed() {
        let sample_data = b"Hello, Project Immortal cleanroom framing!";
        let encoded = CPackFrame::encode_uncompressed(sample_data).unwrap();

        assert_eq!(encoded.len(), HEADER_LEN + sample_data.len());
        assert_eq!(&encoded[0..2], &0xCBBCu16.to_le_bytes());
        assert_eq!(&encoded[2..4], &(sample_data.len() as u16).to_le_bytes());

        // Decode via stream
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = CPackFrame::decode(&mut cursor).unwrap();
        assert_eq!(decoded.magic, MagicToken::Uncompressed);
        assert_eq!(decoded.payload, sample_data);
        assert_eq!(decoded.uncompressed_payload().unwrap(), sample_data);

        // Decode via slice
        let (decoded_slice, consumed) = CPackFrame::decode_from_slice(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded_slice.magic, MagicToken::Uncompressed);
        assert_eq!(decoded_slice.payload, sample_data);
    }

    #[test]
    fn test_roundtrip_compressed() {
        let sample_data = b"Repeat repeat repeat repeat repeat repeat data string for compression";
        let encoded = CPackFrame::encode_compressed(sample_data).unwrap();

        assert_eq!(&encoded[0..2], &0xCBB0u16.to_le_bytes());

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = CPackFrame::decode(&mut cursor).unwrap();
        assert_eq!(decoded.magic, MagicToken::Compressed);
        let payload = decoded.uncompressed_payload().unwrap();
        assert_eq!(payload, sample_data);
    }

    #[test]
    fn test_invalid_magic_error() {
        let bad_header = [0xAA, 0x55, 0x05, 0x00, 1, 2, 3, 4, 5];
        let mut cursor = std::io::Cursor::new(&bad_header);
        match CPackFrame::decode(&mut cursor) {
            Err(NetError::InvalidMagic(0x55AA)) => {}
            other => panic!("Expected InvalidMagic(0x55AA), got {:?}", other),
        }
    }

    #[test]
    fn test_max_payload_limit_enforcement() {
        let too_large = vec![0x42; MAX_PAYLOAD_LEN + 1];
        let err = CPackFrame::encode_uncompressed(&too_large);
        assert!(matches!(err, Err(NetError::PayloadTooLarge { .. })));

        let frame_err = CPackFrame::new(MagicToken::Uncompressed, too_large);
        assert!(matches!(frame_err, Err(NetError::PayloadTooLarge { .. })));

        // Wire header with length 2047
        let mut bad_len_data = Vec::new();
        bad_len_data
            .write_u16::<LittleEndian>(MagicToken::Uncompressed.as_u16())
            .unwrap();
        bad_len_data.write_u16::<LittleEndian>(2047).unwrap();
        bad_len_data.resize(4 + 2047, 0);

        let mut cursor = std::io::Cursor::new(&bad_len_data);
        assert!(matches!(
            CPackFrame::decode(&mut cursor),
            Err(NetError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_corrupted_payload_error() {
        let corrupted_frame = CPackFrame {
            magic: MagicToken::Compressed,
            payload: vec![0xFF, 0xFE, 0xFD, 0xFC], // Invalid zlib stream
        };
        assert!(matches!(
            corrupted_frame.uncompressed_payload(),
            Err(NetError::Decompression(_))
        ));
    }

    #[test]
    fn test_incomplete_slice_error() {
        let partial_header = [0xBC, 0xCB];
        assert!(matches!(
            CPackFrame::decode_from_slice(&partial_header),
            Err(NetError::IncompleteData { .. })
        ));

        let partial_data = [0xBC, 0xCB, 0x0A, 0x00, 1, 2, 3];
        assert!(matches!(
            CPackFrame::decode_from_slice(&partial_data),
            Err(NetError::IncompleteData { .. })
        ));
    }
}
