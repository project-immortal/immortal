// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # CPackUdp Wire Protocol & UDP Datagram Framing
//! Cleanroom UDP transport framing, session handshake validation, SHA-256 HMAC integrity,
//! and MTU discovery for Paladins game server on port 7777 (evidence `ev_017e402e...`).

use crate::error::NetError;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_GAME_PORT: u16 = 7777;
pub const NEGOTIATED_MTU: usize = 1414;
pub const HELLO_MIN_LEN: usize = 570; // 0x23a
pub const HELLO_PAYLOAD_OFFSET: usize = 0x5a; // 90
pub const HELLO_PAYLOAD_LEN: usize = 524; // 0x20c
pub const HELLO_HMAC_OFFSET: usize = 0x26a; // 618
pub const HELLO_FULL_LEN: usize = 0x28a; // 650 (0x26a + 32)
pub const DEFAULT_HMAC_KEY: &[u8] = b"ProjectImmortal_CPackUdp_Key\0";

pub const CPACK_OP_HELLO_SEND: u8 = 0x00;
pub const CPACK_OP_HELLO_REPLY: u8 = 0x01;
pub const CPACK_OP_PING_SEND: u8 = 0x02;
pub const CPACK_OP_PING_RECV: u8 = 0x03;
pub const CPACK_OP_BUNCH: u8 = 0x04;

// ============================================================================
// Pure-Rust Hermetic SHA-256 & HMAC-SHA256 (FIPS 180-4 / RFC 2104)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Computes standard FIPS 180-4 SHA-256 digest over arbitrary input bytes.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 64);
    padded.extend_from_slice(data);
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = BigEndian::read_u32(&chunk[i * 4..(i + 1) * 4]);
        }
        for i in 16..64 {
            w[i] = gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let t1 = h_val
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

/// Computes RFC 2104 HMAC-SHA256 over input bytes using the specified secret key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let key_hash = sha256(key);
        key_block[..32].copy_from_slice(&key_hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner_hash = sha256(&inner_input);

    let mut outer_input = Vec::with_capacity(64 + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}

// ============================================================================
// CPackUdp Packet Definitions & Serialization
// ============================================================================

/// HelloSend datagram sent by client to port 7777 during connection initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloSend {
    pub connection_id: u32,
    pub payload: Vec<u8>,
    pub hmac: [u8; 32],
    pub raw: Vec<u8>,
}

impl HelloSend {
    /// Validates minimum length 570 bytes (`0x23a`), asserts `+0x5a == 0`,
    /// and parses the 524-byte payload and 32-byte HMAC.
    pub fn parse(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < HELLO_MIN_LEN {
            return Err(NetError::PacketTooSmall {
                expected: HELLO_MIN_LEN,
                actual: data.len(),
            });
        }

        // Validate +0x5a == 0 (as specified in reverse engineering evidence ev_017e402e)
        if data[HELLO_PAYLOAD_OFFSET] != 0 {
            return Err(NetError::InvalidUdpPacket(format!(
                "HelloSend check failed: byte at offset +0x{:02x} must be 0, found {}",
                HELLO_PAYLOAD_OFFSET, data[HELLO_PAYLOAD_OFFSET]
            )));
        }

        let connection_id = LittleEndian::read_u32(&data[0..4]);

        let (payload, hmac) = if data.len() >= HELLO_FULL_LEN {
            let p = data[HELLO_PAYLOAD_OFFSET..HELLO_PAYLOAD_OFFSET + HELLO_PAYLOAD_LEN].to_vec();
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[HELLO_HMAC_OFFSET..HELLO_HMAC_OFFSET + 32]);
            (p, h)
        } else {
            // Partial minimum datagram (570 bytes)
            let p_len = (data.len() - HELLO_PAYLOAD_OFFSET).min(HELLO_PAYLOAD_LEN);
            let p = data[HELLO_PAYLOAD_OFFSET..HELLO_PAYLOAD_OFFSET + p_len].to_vec();
            (p, [0u8; 32])
        };

        Ok(Self {
            connection_id,
            payload,
            hmac,
            raw: data.to_vec(),
        })
    }

    /// Verifies the SHA-256 HMAC over the 524 bytes from +0x5a against the hash at +0x26a.
    pub fn validate_hmac(&self, key: &[u8]) -> bool {
        if self.raw.len() < HELLO_FULL_LEN {
            return false;
        }
        let data_slice = &self.raw[HELLO_PAYLOAD_OFFSET..HELLO_PAYLOAD_OFFSET + HELLO_PAYLOAD_LEN];
        let computed = hmac_sha256(key, data_slice);
        computed == self.hmac
    }

    /// Builds a valid HelloSend datagram with the specified key, payload, and optional padding.
    pub fn build(
        key: &[u8],
        connection_id: u32,
        payload_524: Option<&[u8]>,
        pad_to: usize,
    ) -> Vec<u8> {
        let target_len = pad_to.max(HELLO_FULL_LEN);
        let mut buf = vec![0u8; target_len];

        // Connection ID at offset 0
        LittleEndian::write_u32(&mut buf[0..4], connection_id);

        // +0x5a is set to 0
        buf[HELLO_PAYLOAD_OFFSET] = 0;

        // Populate 524 bytes payload
        if let Some(src) = payload_524 {
            let copy_len = src.len().min(HELLO_PAYLOAD_LEN);
            buf[HELLO_PAYLOAD_OFFSET..HELLO_PAYLOAD_OFFSET + copy_len]
                .copy_from_slice(&src[..copy_len]);
        }

        // Compute HMAC over 524 bytes from +0x5a
        let hmac = hmac_sha256(
            key,
            &buf[HELLO_PAYLOAD_OFFSET..HELLO_PAYLOAD_OFFSET + HELLO_PAYLOAD_LEN],
        );

        // Place 32-byte HMAC at +0x26a
        buf[HELLO_HMAC_OFFSET..HELLO_HMAC_OFFSET + 32].copy_from_slice(&hmac);

        buf
    }
}

/// Server reply acknowledging HelloSend and assigning a session ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloRecvReply {
    pub session_id: u32,
    pub negotiated_mtu: u16,
    pub server_nonce: u32,
}

impl HelloRecvReply {
    pub fn new(session_id: u32, server_nonce: u32) -> Self {
        Self {
            session_id,
            negotiated_mtu: NEGOTIATED_MTU as u16,
            server_nonce,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0] = CPACK_OP_HELLO_REPLY;
        LittleEndian::write_u32(&mut buf[1..5], self.session_id);
        LittleEndian::write_u16(&mut buf[5..7], self.negotiated_mtu);
        LittleEndian::write_u32(&mut buf[7..11], self.server_nonce);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 11 {
            return Err(NetError::PacketTooSmall {
                expected: 11,
                actual: data.len(),
            });
        }
        if data[0] != CPACK_OP_HELLO_REPLY {
            return Err(NetError::InvalidUdpPacket(format!(
                "Expected HelloRecvReply opcode 0x01, found 0x{:02x}",
                data[0]
            )));
        }
        let session_id = LittleEndian::read_u32(&data[1..5]);
        let negotiated_mtu = LittleEndian::read_u16(&data[5..7]);
        let server_nonce = LittleEndian::read_u32(&data[7..11]);

        Ok(Self {
            session_id,
            negotiated_mtu,
            server_nonce,
        })
    }
}

/// PingSend packet sent by client for MTU discovery and keepalive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingSend {
    pub sequence: u32,
    pub timestamp: u64,
    pub padding: Vec<u8>,
}

impl PingSend {
    pub fn new(sequence: u32, timestamp: u64, pad_to_mtu: bool) -> Self {
        let header_len = 1 + 4 + 8; // opcode + sequence + timestamp = 13 bytes
        let pad_len = if pad_to_mtu && NEGOTIATED_MTU > header_len {
            NEGOTIATED_MTU - header_len
        } else {
            0
        };
        Self {
            sequence,
            timestamp,
            padding: vec![0xAA; pad_len],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13 + self.padding.len());
        buf.push(CPACK_OP_PING_SEND);
        let mut num_buf = [0u8; 8];
        LittleEndian::write_u32(&mut num_buf[0..4], self.sequence);
        buf.extend_from_slice(&num_buf[0..4]);
        LittleEndian::write_u64(&mut num_buf, self.timestamp);
        buf.extend_from_slice(&num_buf);
        buf.extend_from_slice(&self.padding);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 13 {
            return Err(NetError::PacketTooSmall {
                expected: 13,
                actual: data.len(),
            });
        }
        if data[0] != CPACK_OP_PING_SEND {
            return Err(NetError::InvalidUdpPacket(format!(
                "Expected PingSend opcode 0x02, found 0x{:02x}",
                data[0]
            )));
        }
        let sequence = LittleEndian::read_u32(&data[1..5]);
        let timestamp = LittleEndian::read_u64(&data[5..13]);
        let padding = data[13..].to_vec();

        Ok(Self {
            sequence,
            timestamp,
            padding,
        })
    }
}

/// PingRecv packet sent by server in response to PingSend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingRecv {
    pub sequence: u32,
    pub client_timestamp: u64,
    pub server_timestamp: u64,
    pub negotiated_mtu: u16,
}

impl PingRecv {
    pub fn new(sequence: u32, client_timestamp: u64, server_timestamp: u64) -> Self {
        Self {
            sequence,
            client_timestamp,
            server_timestamp,
            negotiated_mtu: NEGOTIATED_MTU as u16,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 23];
        buf[0] = CPACK_OP_PING_RECV;
        LittleEndian::write_u32(&mut buf[1..5], self.sequence);
        LittleEndian::write_u64(&mut buf[5..13], self.client_timestamp);
        LittleEndian::write_u64(&mut buf[13..21], self.server_timestamp);
        LittleEndian::write_u16(&mut buf[21..23], self.negotiated_mtu);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 23 {
            return Err(NetError::PacketTooSmall {
                expected: 23,
                actual: data.len(),
            });
        }
        if data[0] != CPACK_OP_PING_RECV {
            return Err(NetError::InvalidUdpPacket(format!(
                "Expected PingRecv opcode 0x03, found 0x{:02x}",
                data[0]
            )));
        }
        let sequence = LittleEndian::read_u32(&data[1..5]);
        let client_timestamp = LittleEndian::read_u64(&data[5..13]);
        let server_timestamp = LittleEndian::read_u64(&data[13..21]);
        let negotiated_mtu = LittleEndian::read_u16(&data[21..23]);

        Ok(Self {
            sequence,
            client_timestamp,
            server_timestamp,
            negotiated_mtu,
        })
    }
}

/// High-level parsed CPackUdp transport packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CPackUdpPacket {
    HelloSend(HelloSend),
    HelloRecvReply(HelloRecvReply),
    PingSend(PingSend),
    PingRecv(PingRecv),
    Bunch(Vec<u8>),
}

/// Parses an arbitrary incoming UDP datagram from the game port (7777).
pub fn parse_cpack_udp(data: &[u8]) -> Result<CPackUdpPacket, NetError> {
    if data.is_empty() {
        return Err(NetError::PacketTooSmall {
            expected: 1,
            actual: 0,
        });
    }

    // Check standard transport opcodes first to prevent collision with HelloSend
    match data[0] {
        CPACK_OP_BUNCH => Ok(CPackUdpPacket::Bunch(data[1..].to_vec())),
        CPACK_OP_PING_SEND => PingSend::decode(data).map(CPackUdpPacket::PingSend),
        CPACK_OP_PING_RECV => PingRecv::decode(data).map(CPackUdpPacket::PingRecv),
        CPACK_OP_HELLO_REPLY => HelloRecvReply::decode(data).map(CPackUdpPacket::HelloRecvReply),
        _ => {
            // Only inspect HelloSend if it does not match known opcodes and satisfies
            // minimum datagram length (570 bytes) and byte +0x5a == 0.
            if data.len() >= HELLO_MIN_LEN && data[HELLO_PAYLOAD_OFFSET] == 0 {
                HelloSend::parse(data).map(CPackUdpPacket::HelloSend)
            } else {
                // Treat as raw bunch datagram if none of the explicit transport headers match
                Ok(CPackUdpPacket::Bunch(data.to_vec()))
            }
        }
    }
}

/// Helper returning current timestamp in milliseconds.
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_sha256_standard_vectors() {
        // Empty string
        let empty_hash = sha256(b"");
        assert_eq!(
            to_hex(&empty_hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // "abc"
        let abc_hash = sha256(b"abc");
        assert_eq!(
            to_hex(&abc_hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let data = b"Hi There";
        let hmac = hmac_sha256(&key, data);
        assert_eq!(
            to_hex(&hmac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_hello_send_minimum_length_rejection() {
        let short_data = vec![0u8; 569];
        assert!(matches!(
            HelloSend::parse(&short_data),
            Err(NetError::PacketTooSmall {
                expected: 570,
                actual: 569
            })
        ));
    }

    #[test]
    fn test_hello_send_offset_zero_check() {
        let mut data = vec![0u8; 570];
        data[HELLO_PAYLOAD_OFFSET] = 0xFF; // Violation of +0x5a == 0
        assert!(matches!(
            HelloSend::parse(&data),
            Err(NetError::InvalidUdpPacket(_))
        ));
    }

    #[test]
    fn test_hello_send_hmac_validation_success_and_failure() {
        let key = DEFAULT_HMAC_KEY;
        let mut custom_payload = vec![0x42; HELLO_PAYLOAD_LEN];
        custom_payload[0] = 0; // maintain +0x5a == 0

        let packet_bytes = HelloSend::build(key, 12345, Some(&custom_payload), NEGOTIATED_MTU);
        assert_eq!(packet_bytes.len(), NEGOTIATED_MTU);

        let parsed = HelloSend::parse(&packet_bytes).expect("Failed to parse valid HelloSend");
        assert_eq!(parsed.connection_id, 12345);
        assert!(
            parsed.validate_hmac(key),
            "HMAC verification must succeed with correct key"
        );

        // Verification must fail with wrong key
        assert!(!parsed.validate_hmac(b"wrong_secret_key"));
    }

    #[test]
    fn test_ping_send_and_recv_exchange() {
        let ping_send = PingSend::new(42, 10002000, true);
        assert_eq!(ping_send.padding.len(), NEGOTIATED_MTU - 13);
        let encoded_send = ping_send.encode();
        assert_eq!(encoded_send.len(), NEGOTIATED_MTU);

        let decoded_send = PingSend::decode(&encoded_send).expect("Failed to decode PingSend");
        assert_eq!(decoded_send.sequence, 42);
        assert_eq!(decoded_send.timestamp, 10002000);

        let ping_recv = PingRecv::new(decoded_send.sequence, decoded_send.timestamp, 10002050);
        let encoded_recv = ping_recv.encode();
        let decoded_recv = PingRecv::decode(&encoded_recv).expect("Failed to decode PingRecv");
        assert_eq!(decoded_recv.sequence, 42);
        assert_eq!(decoded_recv.client_timestamp, 10002000);
        assert_eq!(decoded_recv.server_timestamp, 10002050);
        assert_eq!(decoded_recv.negotiated_mtu, 1414);
    }

    #[test]
    fn test_parse_cpack_udp_dispatch() {
        let key = DEFAULT_HMAC_KEY;
        let hello_bytes = HelloSend::build(key, 999, None, 650);
        let parsed = parse_cpack_udp(&hello_bytes).expect("Failed to parse hello");
        assert!(matches!(parsed, CPackUdpPacket::HelloSend(_)));

        let ping_bytes = PingSend::new(1, 100, false).encode();
        let parsed_ping = parse_cpack_udp(&ping_bytes).expect("Failed to parse ping");
        assert!(matches!(parsed_ping, CPackUdpPacket::PingSend(_)));

        let mut bunch_packet = vec![CPACK_OP_BUNCH];
        bunch_packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        let parsed_bunch = parse_cpack_udp(&bunch_packet).expect("Failed to parse bunch");
        match parsed_bunch {
            CPackUdpPacket::Bunch(payload) => {
                assert_eq!(payload, &[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
            }
            other => panic!("Expected Bunch packet, got {:?}", other),
        }
    }
}
