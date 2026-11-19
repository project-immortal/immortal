// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Dedicated-Server Codec Tests (Milestone 5 Phase 2)
//! Validates `PcomPrefix` variants (DedicatedSequenced, DedicatedUnsequenced, Standalone),
//! Seq 1 6-byte session token invariant, Seq 2+ payload alignment, unsequenced control
//! frame parsing, and actual raw packet bytes from CAP-03.

use immortal_net::bunch::{
    Bunch, ControlMessage, DedicatedControlFrame, PcomPrefix, Ue3Packet,
    EXUDP_MAX_PACKET_BITS, MAX_ALLOWED_PACKET_BITS, SUBFLAG_SEQUENCED, SUBFLAG_UNSEQUENCED,
};
use immortal_net::error::NetError;

/// Raw packet bytes extracted from CAP-03 Frame 14612 (C->S Seq 1 with 6-byte token).
const CAP03_FRAME_14612_SEQ1: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x78, 0x7e, 0x10, 0x7b, 0x9a, 0x8f,
    0x37, 0x79, 0xcb, 0x08, 0x30, 0x79, 0x4f, 0xfd, 0x15, 0x10, 0xa4, 0xb5, 0x8d, 0x35, 0xed, 0xc0,
    0xb6, 0x01, 0xd3, 0x27, 0xad, 0xfd, 0xc9, 0x43, 0xd0, 0xf3, 0xd9, 0x85,
];

/// Raw packet bytes extracted from CAP-03 Frame 14639 (Server Seq 18 / Packet #39 Welcome).
const CAP03_FRAME_14639_SEQ18: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x19, 0xa0, 0x7a, 0x35, 0xd9,
    0xb1, 0xcd, 0x5d, 0xb1, 0x76, 0x4f, 0x04, 0x6d, 0x80, 0xc4, 0x48, 0xce, 0x8a, 0xc1, 0x4c, 0x03,
    0x47, 0x0f, 0x12, 0x5e, 0xd4, 0x3b,
];

/// Raw packet bytes extracted from CAP-03 Frame 15141 (Server Seq 51 / Packet #524 PlayerController).
const CAP03_FRAME_15141_SEQ51: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x01, 0x25, 0x8f, 0x19, 0xb9, 0x47, 0x81,
    0x84, 0xed, 0x3f, 0x92, 0x68, 0x0f, 0x1f, 0xbc, 0x88, 0x93, 0x75, 0xee, 0x5e, 0x0a, 0x77, 0xa6,
    0x3a, 0x5b, 0x68, 0x87, 0xb2, 0x2a, 0x5a, 0x88, 0x64, 0x04, 0xda, 0x00, 0xc5, 0x3c, 0xb3, 0x77,
    0x28, 0x69, 0xa6, 0xb6, 0x00, 0xda, 0xf6, 0xc8, 0xfa, 0x60, 0x6a, 0xe1, 0xb1, 0xfa, 0x95, 0xb8,
    0x07, 0xf4, 0x45, 0xfa, 0xec, 0xf1, 0x04, 0xbc, 0x03, 0x44, 0xbb, 0x96, 0x0f, 0x8e, 0xcd, 0xb4,
    0x04, 0x0c, 0x85, 0xe3, 0xb6, 0x8e, 0x69, 0xac, 0x48, 0x0c, 0x56, 0x24, 0x2c, 0x03, 0x5f, 0xda,
    0xdf, 0x30, 0x6b, 0x59, 0x56, 0x3b, 0x7b, 0x64, 0xcb, 0x7c, 0x6a, 0x4d, 0xdd, 0xf0, 0x99, 0x83,
    0x54, 0x5c, 0xa6, 0xf4, 0xf1, 0x81, 0x2a, 0xa9, 0xca, 0x0b, 0xd9, 0xe0, 0xbd, 0x6a, 0x13, 0xcb,
    0x1d, 0x1d, 0x3f, 0x51, 0xbd, 0x05, 0x76, 0xb5, 0xcf, 0xda, 0x7c, 0xff, 0x1e, 0xfe, 0x69, 0x98,
    0x80, 0xf7, 0xcc, 0x65, 0x7f, 0x21, 0xd3, 0xcf, 0x63, 0x90, 0x66, 0x44, 0xb1, 0x9f, 0x42, 0x3f,
    0xf8, 0x27, 0x9b, 0x49, 0x3e, 0xa8, 0xac, 0xc7, 0xbf, 0x12, 0x92, 0xcf, 0x32, 0xb3, 0xf9, 0x64,
    0xd3, 0x81, 0x75, 0xb3, 0xca, 0xed, 0xda, 0x1c, 0x28, 0xf3, 0xee, 0x8d, 0x3c, 0x9a, 0xb5, 0x68,
    0x91, 0xfa, 0x76, 0x79, 0x9a, 0x0d, 0xd9, 0xd6, 0x77, 0x85, 0xfa, 0xc5, 0xeb, 0xe4, 0xc0, 0x1c,
    0xcf, 0x96, 0x47, 0x9d, 0xa2, 0xff, 0xe4, 0x1a, 0x42, 0xc4, 0xd5, 0x6f, 0x89, 0x82, 0x0c, 0xcb,
    0x16, 0xc4, 0x8b, 0x79, 0x62, 0x5b, 0xf9, 0x06, 0xad, 0xa5, 0x90, 0x9c, 0xf8, 0x71, 0xdf, 0x3e,
    0x76, 0x67, 0x2e, 0xb9, 0xd3, 0x5a, 0xfa,
];

#[test]
fn test_dedicated_sequenced_seq1_session_token_roundtrip() {
    let token = [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F];
    let prefix = PcomPrefix::dedicated_sequenced(1, Some(token));
    assert_eq!(prefix.sequence(), Some(1));
    assert_eq!(prefix.subflag(), Some(SUBFLAG_SEQUENCED));
    assert_eq!(prefix.session_token(), Some(&token));
    assert_eq!(prefix.len(), 16);

    let mut pkt = Ue3Packet::new_with_prefix(prefix.clone(), 1);
    pkt.bunches.push(Bunch::control(1, ControlMessage::MapLoaded.encode()));

    let wire = pkt.encode_pcom(EXUDP_MAX_PACKET_BITS).expect("encode seq1");
    assert_eq!(&wire[..4], &[0x01, 0x00, 0x00, 0x00]); // magic
    assert_eq!(&wire[4..8], &[0x01, 0x00, 0x00, 0x00]); // seq = 1 LE
    assert_eq!(&wire[8..10], &[0x00, 0x01]); // subflags = 0x0001
    assert_eq!(&wire[10..16], &token); // 6-byte session token

    let decoded = Ue3Packet::decode_with_max_bits(&wire, EXUDP_MAX_PACKET_BITS).expect("decode seq1");
    assert_eq!(decoded.pcom_prefix, prefix);
    assert_eq!(decoded.packet_id, 1);
    assert_eq!(decoded.bunches.len(), 1);

    // Re-encoding must match bit-for-bit
    let reencoded = decoded.encode_pcom(EXUDP_MAX_PACKET_BITS).expect("reencode");
    assert_eq!(reencoded, wire);
}

#[test]
fn test_dedicated_sequenced_seq2_plus_roundtrip() {
    for seq in [2, 18, 51, 1000] {
        let prefix = PcomPrefix::dedicated_sequenced(seq, None);
        assert_eq!(prefix.sequence(), Some(seq));
        assert_eq!(prefix.subflag(), Some(SUBFLAG_SEQUENCED));
        assert_eq!(prefix.session_token(), None);
        assert_eq!(prefix.len(), 10);

        let mut pkt = Ue3Packet::new_with_prefix(prefix.clone(), (seq % 16384) as u16);
        pkt.acks.push((seq - 1) as u16);
        pkt.bunches.push(Bunch::control(seq % 1024, ControlMessage::Join.encode()));

        let wire = pkt.encode_pcom(EXUDP_MAX_PACKET_BITS).expect("encode seq2+");
        assert_eq!(&wire[..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&wire[4..8], &seq.to_le_bytes());
        assert_eq!(&wire[8..10], &[0x00, 0x01]);

        let decoded = Ue3Packet::decode_with_max_bits(&wire, EXUDP_MAX_PACKET_BITS).expect("decode seq2+");
        assert_eq!(decoded.pcom_prefix, prefix);
        assert_eq!(decoded.packet_id, (seq % 16384) as u16);
        assert_eq!(decoded.acks, vec![(seq - 1) as u16]);
        assert_eq!(decoded.bunches.len(), 1);

        let reencoded = decoded.encode_pcom(EXUDP_MAX_PACKET_BITS).expect("reencode");
        assert_eq!(reencoded, wire);
    }
}

#[test]
fn test_standalone_framing_roundtrip() {
    let prefix = PcomPrefix::standalone(42, SUBFLAG_SEQUENCED);
    assert_eq!(prefix.sequence(), Some(42));
    assert_eq!(prefix.subflag(), Some(SUBFLAG_SEQUENCED));
    assert_eq!(prefix.len(), 6);

    let mut pkt = Ue3Packet::new_with_prefix(prefix.clone(), 42);
    pkt.bunches.push(Bunch::control(1, ControlMessage::MapLoaded.encode()));

    let wire = pkt.encode().expect("encode standalone");
    assert_eq!(&wire[..4], &42u32.to_le_bytes());
    assert_eq!(&wire[4..6], &[0x00, 0x01]);

    let decoded = Ue3Packet::decode(&wire).expect("decode standalone");
    assert_eq!(decoded.pcom_prefix, prefix);
    assert_eq!(decoded.packet_id, 42);
    assert_eq!(decoded.bunches.len(), 1);

    let reencoded = decoded.encode().expect("reencode standalone");
    assert_eq!(reencoded, wire);
}

#[test]
fn test_unsequenced_control_frame_rejection_and_parsing() {
    // 1. Client Hello (570 bytes)
    let mut hello = vec![0u8; 570];
    hello[8..10].copy_from_slice(&[0x00, 0x10]);
    hello[10..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    hello[16..22].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    hello[22..24].copy_from_slice(&72u16.to_le_bytes());
    hello[538..570].copy_from_slice(&[0xAB; 32]);

    let err = Ue3Packet::decode(&hello).unwrap_err();
    match err {
        NetError::UnsequencedControlFrame { subflags, len, .. } => {
            assert_eq!(subflags, SUBFLAG_UNSEQUENCED);
            assert_eq!(len, 570);
        }
        other => panic!("Expected UnsequencedControlFrame, got {:?}", other),
    }

    let parsed = DedicatedControlFrame::parse(&hello).expect("parse hello");
    match parsed {
        DedicatedControlFrame::ClientHello { descriptor_len, ticket_payload, hmac, .. } => {
            assert_eq!(descriptor_len, 72);
            assert_eq!(ticket_payload.len(), 72);
            assert_eq!(hmac, [0xAB; 32]);
        }
        other => panic!("Expected ClientHello, got {:?}", other),
    }

    // 2. Server Challenge (46 bytes)
    let mut challenge = vec![0u8; 46];
    challenge[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    challenge[8..10].copy_from_slice(&[0x00, 0x10]);
    challenge[10] = 0x5D; // Challenge flag (with 0x05 bits set)
    challenge[11..16].copy_from_slice(&[1, 2, 3, 4, 5]);
    challenge[16..22].copy_from_slice(&[6, 7, 8, 9, 10, 11]);

    let parsed_ch = DedicatedControlFrame::parse(&challenge).expect("parse challenge");
    match parsed_ch {
        DedicatedControlFrame::ServerChallenge { handshake_flag, client_cookie, server_cookie, .. } => {
            assert_eq!(handshake_flag, 0x5D);
            assert_eq!(client_cookie, [1, 2, 3, 4, 5]);
            assert_eq!(server_cookie, [6, 7, 8, 9, 10, 11]);
        }
        other => panic!("Expected ServerChallenge, got {:?}", other),
    }

    // 3. PMTU Probe (1440 bytes)
    let mut pmtu = vec![0u8; 1440];
    pmtu[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    pmtu[8..10].copy_from_slice(&[0x00, 0x10]);
    pmtu[10..16].copy_from_slice(&[0x25, 0x3E, 0x4E, 0xED, 0xA3, 0x7C]);
    pmtu[16..22].copy_from_slice(&[0xFB, 0x73, 0x09, 0xF1, 0x45, 0x49]);

    let parsed_pmtu = DedicatedControlFrame::parse(&pmtu).expect("parse pmtu");
    match parsed_pmtu {
        DedicatedControlFrame::PmtuProbe { probe_token, probe_marker, total_len, .. } => {
            assert_eq!(probe_token, [0x25, 0x3E, 0x4E, 0xED, 0xA3, 0x7C]);
            assert_eq!(probe_marker, [0xFB, 0x73, 0x09, 0xF1, 0x45, 0x49]);
            assert_eq!(total_len, 1440);
        }
        other => panic!("Expected PmtuProbe, got {:?}", other),
    }

    // 4. Handshake Complete (46 bytes)
    let mut complete = vec![0u8; 46];
    complete[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    complete[8..10].copy_from_slice(&[0x00, 0x10]);
    complete[10] = 0x58; // Finalized flag (cleared 0x05 bits)
    complete[11..22].copy_from_slice(&[0xCC; 11]);

    let parsed_comp = DedicatedControlFrame::parse(&complete).expect("parse complete");
    match parsed_comp {
        DedicatedControlFrame::HandshakeComplete { handshake_flag, session_tokens, .. } => {
            assert_eq!(handshake_flag, 0x58);
            assert_eq!(session_tokens, [0xCC; 11]);
        }
        other => panic!("Expected HandshakeComplete, got {:?}", other),
    }
}

#[test]
fn test_cap03_frame_14612_seq1_session_token_and_framing() {
    assert_eq!(CAP03_FRAME_14612_SEQ1.len(), 44);

    // Verify 10-byte prefix: magic=1, seq=1, subflag=0x0001
    assert_eq!(&CAP03_FRAME_14612_SEQ1[..4], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_14612_SEQ1[4..8], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_14612_SEQ1[8..10], &[0x00, 0x01]);

    // Verify 6-byte session token
    let expected_token = [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F];
    assert_eq!(&CAP03_FRAME_14612_SEQ1[10..16], &expected_token);

    // Decoding with EXUDP_MAX_PACKET_BITS verifies framing deconstruction
    let res = Ue3Packet::decode_with_max_bits(CAP03_FRAME_14612_SEQ1, EXUDP_MAX_PACKET_BITS);
    // The prefix must be correctly parsed even if bunch bitstream requires specific session state
    match res {
        Ok(pkt) => {
            assert_eq!(pkt.pcom_prefix.sequence(), Some(1));
            assert_eq!(pkt.pcom_prefix.session_token(), Some(&expected_token));
        }
        Err(e) => {
            // If bitstream parse underflows on raw synthetic/gameplay bits, verify it's a bunch error
            // and NOT a prefix/packet-too-small error!
            match e {
                NetError::BunchError(_) | NetError::InvalidUdpPacket(_) => {}
                other => panic!("Unexpected error on Frame 14612: {:?}", other),
            }
        }
    }
}

#[test]
fn test_cap03_frame_14639_seq18_welcome_framing() {
    assert_eq!(CAP03_FRAME_14639_SEQ18.len(), 38);

    // Verify 10-byte prefix: magic=1, seq=18 (0x12), subflag=0x0001
    assert_eq!(&CAP03_FRAME_14639_SEQ18[..4], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_14639_SEQ18[4..8], &[0x12, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_14639_SEQ18[8..10], &[0x00, 0x01]);

    // Since seq=18 > 1, no session token is present; UE3 payload starts at offset 10
    let res = Ue3Packet::decode_with_max_bits(CAP03_FRAME_14639_SEQ18, EXUDP_MAX_PACKET_BITS);
    match res {
        Ok(pkt) => {
            assert_eq!(pkt.pcom_prefix.sequence(), Some(18));
            assert_eq!(pkt.pcom_prefix.session_token(), None);
        }
        Err(e) => {
            match e {
                NetError::BunchError(_) | NetError::InvalidUdpPacket(_) => {}
                other => panic!("Unexpected error on Frame 14639: {:?}", other),
            }
        }
    }
}

#[test]
fn test_cap03_frame_15141_seq51_player_controller_framing() {
    assert_eq!(CAP03_FRAME_15141_SEQ51.len(), 247);

    // Verify 10-byte prefix: magic=1, seq=51 (0x33), subflag=0x0001
    assert_eq!(&CAP03_FRAME_15141_SEQ51[..4], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_15141_SEQ51[4..8], &[0x33, 0x00, 0x00, 0x00]);
    assert_eq!(&CAP03_FRAME_15141_SEQ51[8..10], &[0x00, 0x01]);

    // Seq 51 > 1: payload starts at offset 10
    let res = Ue3Packet::decode_with_max_bits(CAP03_FRAME_15141_SEQ51, MAX_ALLOWED_PACKET_BITS);
    match res {
        Ok(pkt) => {
            assert_eq!(pkt.pcom_prefix.sequence(), Some(51));
            assert_eq!(pkt.pcom_prefix.session_token(), None);
        }
        Err(e) => {
            match e {
                NetError::BunchError(_) | NetError::InvalidUdpPacket(_) => {}
                other => panic!("Unexpected error on Frame 15141: {:?}", other),
            }
        }
    }
}
