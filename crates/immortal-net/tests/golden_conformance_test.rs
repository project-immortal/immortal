// SPDX-License-Identifier: Apache-2.0
//! Hermetic Golden Pcap Conformance Test Suite (Vector 2).
//! Replays and validates authentic server/client MCTS traffic frames
//! extracted from `paladins_live_session.pcap` / `mcts_only.pcap`.

// Hermetic Golden Pcap Conformance Test Suite (Vector 2).

#[derive(Debug)]
struct GoldenPacket {
    frame_idx: u32,
    is_client: bool,
    payload: Vec<u8>,
}

fn load_golden_packets() -> Vec<GoldenPacket> {
    let bytes = include_bytes!("fixtures/golden_mcts_stream.bin");
    assert!(bytes.len() >= 4, "golden_mcts_stream.bin fixture must be valid");

    let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut packets = Vec::with_capacity(count);
    let mut offset = 4;

    while offset + 9 <= bytes.len() {
        let frame_idx = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]);
        let is_client = bytes[offset+4] == 1;
        let p_len = u32::from_le_bytes([bytes[offset+5], bytes[offset+6], bytes[offset+7], bytes[offset+8]]) as usize;
        offset += 9;
        assert!(offset + p_len <= bytes.len(), "corrupted packet payload at frame {}", frame_idx);
        let payload = bytes[offset..offset+p_len].to_vec();
        offset += p_len;
        packets.push(GoldenPacket {
            frame_idx,
            is_client,
            payload,
        });
    }

    assert_eq!(packets.len(), count, "Parsed packet count must match header");
    packets
}

#[test]
fn test_golden_stream_fixture_integrity() {
    let packets = load_golden_packets();
    assert_eq!(packets.len(), 1617, "Golden stream fixture must contain exactly 1617 packets");

    // Frame 4: Client Step 1 Handshake
    let f4 = &packets[0];
    assert_eq!(f4.frame_idx, 4);
    assert!(f4.is_client);
    assert_eq!(f4.payload.len(), 409);
    assert_eq!(u16::from_le_bytes([f4.payload[0], f4.payload[1]]), 405);
    assert_eq!(u16::from_le_bytes([f4.payload[2], f4.payload[3]]), 0x0000);

    // Frame 6: Server Step 1 Handshake Response Challenge (Chunk 1)
    let f6 = &packets[1];
    assert_eq!(f6.frame_idx, 6);
    assert!(!f6.is_client);
    assert_eq!(f6.payload.len(), 437);
    assert_eq!(u16::from_le_bytes([f6.payload[0], f6.payload[1]]), 433);
    assert_eq!(u16::from_le_bytes([f6.payload[2], f6.payload[3]]), 0x0100); // MCTS_WIRE_FLAG_CHUNK

    // Frame 8: Client Step 2 Crypto Ticket
    let f8 = &packets[2];
    assert_eq!(f8.frame_idx, 8);
    assert!(f8.is_client);
    assert_eq!(f8.payload.len(), 1121);
    assert_eq!(u16::from_le_bytes([f8.payload[0], f8.payload[1]]), 1117);
    assert_eq!(u16::from_le_bytes([f8.payload[2], f8.payload[3]]), 0x0100);

    // Frame 10: Server Step 2 Chunk 2 ACK
    let f10 = &packets[3];
    assert_eq!(f10.frame_idx, 10);
    assert!(!f10.is_client);
    assert_eq!(f10.payload.len(), 25);
    assert_eq!(u16::from_le_bytes([f10.payload[0], f10.payload[1]]), 21);
    assert_eq!(u16::from_le_bytes([f10.payload[2], f10.payload[3]]), 0x0100);
}

#[test]
fn test_golden_stream_framing_and_flags_distribution() {
    let packets = load_golden_packets();

    let mut client_count = 0;
    let mut server_count = 0;
    let mut total_bytes = 0;
    let mut uncompressed_frames = 0;
    let mut chunk_flag_frames = 0;

    for p in &packets {
        if p.is_client {
            client_count += 1;
        } else {
            server_count += 1;
        }
        total_bytes += p.payload.len();

        if p.payload.len() >= 4 {
            let flags = u16::from_le_bytes([p.payload[2], p.payload[3]]);
            if flags == 0x0000 {
                uncompressed_frames += 1;
            } else if (flags & 0x0100) != 0 {
                chunk_flag_frames += 1;
            }
        }
    }

    assert!(client_count >= 90, "Must have >=90 client packets (got {})", client_count);
    assert!(server_count >= 1500, "Must have >=1500 server packets (got {})", server_count);
    assert!(total_bytes > 1_000_000, "Must have >1MB total payload data");
    assert!(uncompressed_frames > 0, "Must have uncompressed handshake frames");
    assert!(chunk_flag_frames > 0, "Must have chunk-flagged payload frames");
}
