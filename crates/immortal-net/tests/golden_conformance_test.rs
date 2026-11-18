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
    assert!(
        bytes.len() >= 4,
        "golden_mcts_stream.bin fixture must be valid"
    );

    let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut packets = Vec::with_capacity(count);
    let mut offset = 4;

    while offset + 9 <= bytes.len() {
        let frame_idx = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let is_client = bytes[offset + 4] == 1;
        let p_len = u32::from_le_bytes([
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
        ]) as usize;
        offset += 9;
        assert!(
            offset + p_len <= bytes.len(),
            "corrupted packet payload at frame {}",
            frame_idx
        );
        let payload = bytes[offset..offset + p_len].to_vec();
        offset += p_len;
        packets.push(GoldenPacket {
            frame_idx,
            is_client,
            payload,
        });
    }

    assert_eq!(
        packets.len(),
        count,
        "Parsed packet count must match header"
    );
    packets
}

#[test]
fn test_golden_stream_fixture_integrity() {
    let packets = load_golden_packets();
    assert_eq!(
        packets.len(),
        1617,
        "Golden stream fixture must contain exactly 1617 packets"
    );

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

    assert!(
        client_count >= 90,
        "Must have >=90 client packets (got {})",
        client_count
    );
    assert!(
        server_count >= 1500,
        "Must have >=1500 server packets (got {})",
        server_count
    );
    assert!(total_bytes > 1_000_000, "Must have >1MB total payload data");
    assert!(
        uncompressed_frames > 0,
        "Must have uncompressed handshake frames"
    );
    assert!(
        chunk_flag_frames > 0,
        "Must have chunk-flagged payload frames"
    );
}

#[test]
fn test_golden_flight034_udp_bitstream_roundtrip() {
    use immortal_net::{
        ControlMessage, Ue3ChannelType, Ue3Packet, CONTROL_CHANNEL_INDEX, PCOM_PREFIX_LEN,
    };

    // Sanitized 6-byte PComNetConn outer prefix + exact Flight 034 UE3 payload bits (EV-LOG-002)
    let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0xAA, 0xBB, 0xCC, 0xDD];
    let ue3_payloads: [&[u8]; 3] = [
        // Packet 0: PktId=0, Ch0(Open, Rel, Seq=1, 40b) NMT_HandshakeStart(0x40)
        &[
            0x00, 0x80, 0x05, 0x40, 0x00, 0x41, 0x01, 0x1A, 0x40, 0x00, 0x00, 0x00, 0x01,
        ],
        // Packet 1: PktId=1, ACKs=[1,2,3], Ch0(Close, Rel, Seq=2, 0b)
        &[
            0x01, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0xD0, 0x00, 0x10, 0x20, 0x00, 0x20,
        ],
        // Packet 2: PktId=2, ACKs=[1,2,3,4,5], Bunches=[]
        &[
            0x02, 0xC0, 0x00, 0xA0, 0x00, 0x70, 0x00, 0x48, 0x00, 0x2C, 0x00, 0x02,
        ],
    ];

    for (idx, ue3) in ue3_payloads.iter().enumerate() {
        let mut wire = Vec::with_capacity(PCOM_PREFIX_LEN + ue3.len());
        wire.extend_from_slice(&prefix);
        wire.extend_from_slice(ue3);

        let decoded = Ue3Packet::decode(&wire)
            .unwrap_or_else(|e| panic!("Flight 034 packet {} decode failed: {}", idx, e));
        assert_eq!(decoded.pcom_prefix, prefix);
        assert_eq!(decoded.packet_id, idx as u16);

        let reencoded = decoded
            .encode()
            .unwrap_or_else(|e| panic!("Flight 034 packet {} re-encode failed: {}", idx, e));
        assert_eq!(
            reencoded, wire,
            "Bit-exact roundtrip mismatch on Flight 034 packet {}",
            idx
        );

        match idx {
            0 => {
                assert!(decoded.acks.is_empty());
                assert_eq!(decoded.bunches.len(), 1);
                let b = &decoded.bunches[0];
                assert_eq!(b.header.ch_index, CONTROL_CHANNEL_INDEX);
                assert_eq!(b.header.ch_type, Ue3ChannelType::Control);
                assert!(
                    b.header.flags.b_open && !b.header.flags.b_close && b.header.flags.b_reliable
                );
                assert_eq!(b.header.ch_sequence, 1);
                assert_eq!(b.num_bits, 40);
                let msgs = ControlMessage::decode_all(&b.data, b.num_bits).unwrap();
                assert_eq!(
                    msgs,
                    vec![ControlMessage::HandshakeStart {
                        platform_flag: 0x40
                    }]
                );
            }
            1 => {
                assert_eq!(decoded.acks, vec![1, 2, 3]);
                assert_eq!(decoded.bunches.len(), 1);
                let b = &decoded.bunches[0];
                assert_eq!(b.header.ch_index, CONTROL_CHANNEL_INDEX);
                assert_eq!(b.header.ch_type, Ue3ChannelType::Control);
                assert!(
                    !b.header.flags.b_open && b.header.flags.b_close && b.header.flags.b_reliable
                );
                assert_eq!(b.header.ch_sequence, 2);
                assert_eq!(b.num_bits, 0);
            }
            2 => {
                assert_eq!(decoded.acks, vec![1, 2, 3, 4, 5]);
                assert!(decoded.bunches.is_empty());
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_golden_server_handshake_packets_bit_parity() {
    use immortal_net::{
        strip_stop_bit, ue3_handshake_crc, Bunch, ControlMessage, Ue3Packet,
        DEFAULT_ENGINE_MIN_NET_VERSION, DEFAULT_ENGINE_NET_VERSION, DEFAULT_GAME_CLASS,
        DEFAULT_SHOOTING_RANGE_LEVEL, PCOM_PREFIX_LEN,
    };

    let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0xAA, 0xBB, 0xCC, 0xDD];
    let challenge = 0xDEAD_BEEFu32; // exercises signed negative i32 (-559038737)
    let login_url = "Shootingrange_P?Name=Player?Team=0?game=TgGame.TgGame_Paladins_ShootingRange?GameState=OGS_NoSession?GameMode=0";

    // Full server + client control handshake cadence exercising both <512b (13-bit len)
    // and >=512b (12-bit len) SerializeInt(4608) paths.
    let stages: Vec<(u16, Vec<u16>, bool, u32, ControlMessage)> = vec![
        (
            0,
            vec![],
            true,
            1,
            ControlMessage::HandshakeStart {
                platform_flag: 0x40,
            },
        ),
        (
            0,
            vec![0],
            false,
            1,
            ControlMessage::HandshakeChallenge { challenge },
        ),
        (
            1,
            vec![0],
            false,
            2,
            ControlMessage::HandshakeResponse {
                crc_response: ue3_handshake_crc(challenge),
            },
        ),
        (1, vec![1], false, 2, ControlMessage::HandshakeComplete),
        (2, vec![1], false, 3, ControlMessage::ServerAuthRequest),
        (
            2,
            vec![2],
            false,
            3,
            ControlMessage::client_auth_request_bypass(),
        ),
        (
            3,
            vec![2],
            false,
            4,
            ControlMessage::Hello {
                min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
                net_ver: DEFAULT_ENGINE_NET_VERSION,
                is_little_endian: 1,
            },
        ),
        (
            3,
            vec![3],
            false,
            4,
            ControlMessage::Challenge {
                challenge_id: 0,
                challenge: "IMMORTAL".to_string(),
            },
        ),
        (
            4,
            vec![3],
            false,
            5,
            ControlMessage::NetSpeed { rate: 24000 },
        ),
        (
            5,
            vec![],
            false,
            6,
            ControlMessage::Login {
                client_response: "0".to_string(),
                url: login_url.to_string(),
                unique_id: 8_302_401,
                portal_id: 0,
            },
        ),
        (
            4,
            vec![4, 5],
            false,
            5,
            ControlMessage::Welcome {
                level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
                game_name: DEFAULT_GAME_CLASS.to_string(),
            },
        ),
        (6, vec![4], false, 7, ControlMessage::Join),
    ];

    let mut saw_lt_512 = false;
    let mut saw_ge_512 = false;

    for (pkt_id, acks, b_open, ch_seq, msg) in stages {
        let payload = msg.encode();
        let payload_bits = payload.len() * 8;
        let bunch = if b_open {
            Bunch::control_open(ch_seq, payload)
        } else {
            Bunch::control(ch_seq, payload)
        };
        let mut pkt = Ue3Packet::new(prefix, pkt_id);
        pkt.acks = acks.clone();
        pkt.bunches.push(bunch);

        let wire = pkt.encode().unwrap();
        let data_bits = strip_stop_bit(&wire[PCOM_PREFIX_LEN..]).unwrap();
        let len_width = if payload_bits >= 512 { 12 } else { 13 };
        let hdr_bits = 1 + 1 + if b_open { 2 } else { 0 } + 1 + 11 + 10 + 3 + len_width;
        assert_eq!(data_bits, 14 + acks.len() * 15 + hdr_bits + payload_bits);

        if payload_bits < 512 {
            saw_lt_512 = true;
        } else {
            saw_ge_512 = true;
        }

        let decoded = Ue3Packet::decode(&wire).unwrap();
        assert_eq!(decoded, pkt);
        let decoded_msgs =
            ControlMessage::decode_all(&decoded.bunches[0].data, decoded.bunches[0].num_bits)
                .unwrap();
        assert_eq!(decoded_msgs, vec![msg]);
    }

    assert!(saw_lt_512 && saw_ge_512);
}
