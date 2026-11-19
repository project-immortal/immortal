// SPDX-License-Identifier: AGPL-3.0
// Project Immortal — Scratch Dedicated-Server Pcap Decoder
// Reads raw hex packets from stdin or tshark output and decodes Ue3Packet/Bunches.

use immortal_net::bunch::{
    DedicatedControlFrame, PcomPrefix, Ue3Packet, DEFAULT_MAX_PACKET_BITS, EXUDP_MAX_PACKET_BITS,
    MAX_ALLOWED_PACKET_BITS, NMT_HELLO, NMT_WELCOME,
    NMT_UPGRADE, NMT_CHALLENGE, NMT_NETSPEED, NMT_LOGIN, NMT_FAILURE, NMT_USES, NMT_HAVE,
    NMT_JOIN, NMT_JOIN_SPLIT, NMT_HANDSHAKE_START, NMT_HANDSHAKE_CHALLENGE,
    NMT_HANDSHAKE_RESPONSE, NMT_HANDSHAKE_COMPLETE, NMT_MAP_LOADED, NMT_REDIRECT,
    NMT_CLIENT_AUTH_REQUEST, NMT_SERVER_AUTH_REQUEST,
};
use immortal_net::udp_framing::{parse_cpack_udp, CPackUdpPacket, HELLO_FULL_LEN, HELLO_MIN_LEN};
use immortal_net::NetError;
use std::io::{self, BufRead};

fn control_opcode_name(op: u8) -> &'static str {
    match op {
        NMT_HELLO => "NMT_Hello (0x00)",
        NMT_WELCOME => "NMT_Welcome (0x01)",
        NMT_UPGRADE => "NMT_Upgrade (0x02)",
        NMT_CHALLENGE => "NMT_Challenge (0x03)",
        NMT_NETSPEED => "NMT_NetSpeed (0x04)",
        NMT_LOGIN => "NMT_Login (0x05)",
        NMT_FAILURE => "NMT_Failure (0x06)",
        NMT_USES => "NMT_Uses (0x07)",
        NMT_HAVE => "NMT_Have (0x08)",
        NMT_JOIN => "NMT_Join (0x09)",
        NMT_JOIN_SPLIT => "NMT_JoinSplit (0x0A)",
        NMT_HANDSHAKE_START => "NMT_HandshakeStart (0x1A)",
        NMT_HANDSHAKE_CHALLENGE => "NMT_HandshakeChallenge (0x1B)",
        NMT_HANDSHAKE_RESPONSE => "NMT_HandshakeResponse (0x1C)",
        NMT_HANDSHAKE_COMPLETE => "NMT_HandshakeComplete (0x1D)",
        NMT_REDIRECT => "NMT_Redirect (0x1E)",
        NMT_CLIENT_AUTH_REQUEST => "NMT_ClientAuthRequest (0x1F)",
        NMT_SERVER_AUTH_REQUEST => "NMT_ServerAuthRequest (0x20)",
        0x27 => "NMT_MarshalPackage (0x27)",
        0x29 => "NMT_PlayTime (0x29)",
        NMT_MAP_LOADED => "NMT_MapLoaded (0x2A)",
        0x2B => "NMT_TimeLapse (0x2B)",
        0x2C => "NMT_UsesOpt (0x2C)",
        0x2D => "NMT_UsesOptEx (0x2D)",
        _ => "NMT_UNKNOWN",
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(b);
    }
    Some(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli_max_bits: Option<usize> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut arg_idx = 1;
    while arg_idx < args.len() {
        if args[arg_idx] == "--max-packet-bits" && arg_idx + 1 < args.len() {
            if let Ok(val) = args[arg_idx + 1].parse::<usize>() {
                cli_max_bits = Some(val);
            }
            arg_idx += 2;
            continue;
        }
        arg_idx += 1;
    }

    let stdin = io::stdin();
    let lines = stdin.lock().lines();

    let mut total_packets = 0usize;
    let mut decoded_packets = 0usize;
    let mut total_bunches = 0usize;
    let mut ch0_count = 0usize;
    let mut ch1_count = 0usize;
    let mut ch2_count = 0usize;
    let mut ch3_plus_count = 0usize;

    for line_res in lines {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let (meta, hex_str) = if parts.len() >= 2 {
            let meta = parts[..parts.len() - 1].join(" ");
            (meta, parts[parts.len() - 1])
        } else {
            ("".to_string(), parts[0])
        };

        let Some(raw_bytes) = hex_decode(hex_str) else {
            continue;
        };

        total_packets += 1;

        // 1. Check for dedicated server unsequenced control / handshake / PMTU frames (subflags 0x0010)
        let is_dedicated_unsequenced = raw_bytes.len() >= 10
            && (raw_bytes.starts_with(&[0x01, 0x00, 0x00, 0x00]) || raw_bytes.starts_with(&[0x00, 0x00, 0x00, 0x00]))
            && raw_bytes[8..10] == [0x00, 0x10];

        if is_dedicated_unsequenced {
            if let Some(ctrl) = DedicatedControlFrame::parse(&raw_bytes) {
                match ctrl {
                    DedicatedControlFrame::ClientHello { descriptor_len, ticket_payload, .. } => {
                        println!(
                            "[+] Packet #{:<5} {} | [Dedicated::ClientHello] DescriptorLen: {} B, TicketLen: {} B (Len: {} B)",
                            total_packets, meta, descriptor_len, ticket_payload.len(), raw_bytes.len()
                        );
                    }
                    DedicatedControlFrame::ServerChallenge { handshake_flag, client_cookie, server_cookie, .. } => {
                        println!(
                            "[+] Packet #{:<5} {} | [Dedicated::ServerChallenge] Flag: 0x{:02x}, ClientCookie: {:02x?}, ServerCookie: {:02x?} (Len: {} B)",
                            total_packets, meta, handshake_flag, client_cookie, server_cookie, raw_bytes.len()
                        );
                    }
                    DedicatedControlFrame::PmtuProbe { probe_token, probe_marker, total_len, .. } => {
                        println!(
                            "[+] Packet #{:<5} {} | [Dedicated::PmtuProbe] Token: {:02x?}, Marker: {:02x?} (Len: {} B)",
                            total_packets, meta, probe_token, probe_marker, total_len
                        );
                    }
                    DedicatedControlFrame::HandshakeComplete { handshake_flag, session_tokens, .. } => {
                        println!(
                            "[+] Packet #{:<5} {} | [Dedicated::HandshakeComplete] Flag: 0x{:02x}, Tokens: {:02x?} (Len: {} B)",
                            total_packets, meta, handshake_flag, session_tokens, raw_bytes.len()
                        );
                    }
                    DedicatedControlFrame::Other { magic, subflags, .. } => {
                        println!(
                            "[+] Packet #{:<5} {} | [Dedicated::UnsequencedOther] Magic: {:02x?}, Subflags: 0x{:04x} (Len: {} B)",
                            total_packets, meta, magic, subflags, raw_bytes.len()
                        );
                    }
                }
                decoded_packets += 1;
                continue;
            }
        }

        let is_dedicated_ue3 = raw_bytes.len() >= 11
            && raw_bytes.starts_with(&[0x01, 0x00, 0x00, 0x00])
            && raw_bytes[8..10] == [0x00, 0x01];

        let mut handled_cpack = false;
        if !is_dedicated_ue3 {
            // Disambiguate CPackUdp transport datagrams (e.g. HelloSend 570B/650B, PingSend, PingRecv, HelloRecvReply)
            let is_cpack_hello = raw_bytes.len() == HELLO_MIN_LEN || raw_bytes.len() == HELLO_FULL_LEN;
            if is_cpack_hello {
                let conn_id = if raw_bytes.len() >= 4 {
                    u32::from_le_bytes(raw_bytes[0..4].try_into().unwrap_or([0; 4]))
                } else {
                    0
                };
                println!(
                    "[+] Packet #{:<5} {} | [CPackUdp::HelloSend] ConnID: 0x{:08x} (Len: {} B)",
                    total_packets, meta, conn_id, raw_bytes.len()
                );
                decoded_packets += 1;
                handled_cpack = true;
            } else if let Ok(ref cpack) = parse_cpack_udp(&raw_bytes) {
                match cpack {
                    CPackUdpPacket::HelloSend(hello) => {
                        println!(
                            "[+] Packet #{:<5} {} | [CPackUdp::HelloSend] ConnID: 0x{:08x} (Len: {} B)",
                            total_packets, meta, hello.connection_id, raw_bytes.len()
                        );
                        decoded_packets += 1;
                        handled_cpack = true;
                    }
                    CPackUdpPacket::HelloRecvReply(reply) if raw_bytes.len() == 16 => {
                        println!(
                            "[+] Packet #{:<5} {} | [CPackUdp::HelloRecvReply] SessionID: 0x{:08x}, MTU: {}",
                            total_packets, meta, reply.session_id, reply.negotiated_mtu
                        );
                        decoded_packets += 1;
                        handled_cpack = true;
                    }
                    CPackUdpPacket::PingSend(ping) => {
                        println!(
                            "[+] Packet #{:<5} {} | [CPackUdp::PingSend] Seq: {}, Timestamp: {}",
                            total_packets, meta, ping.sequence, ping.timestamp
                        );
                        decoded_packets += 1;
                        handled_cpack = true;
                    }
                    CPackUdpPacket::PingRecv(ping) => {
                        println!(
                            "[+] Packet #{:<5} {} | [CPackUdp::PingRecv] Seq: {}, ClientTS: {}, ServerTS: {}",
                            total_packets, meta, ping.sequence, ping.client_timestamp, ping.server_timestamp
                        );
                        decoded_packets += 1;
                        handled_cpack = true;
                    }
                    _ => {}
                }
            }
        }

        if handled_cpack {
            continue;
        }

        // 2. Ladder: prioritize CLI override if supplied.
        // For large packets (> 576 B), do not fall back to smaller MTUs (576B/496B) that would synthetically fail with PayloadTooLarge.
        let max_bits_ladder: Vec<usize> = if let Some(mb) = cli_max_bits {
            vec![mb]
        } else if raw_bytes.len() > 576 {
            vec![MAX_ALLOWED_PACKET_BITS]
        } else {
            vec![EXUDP_MAX_PACKET_BITS, DEFAULT_MAX_PACKET_BITS, MAX_ALLOWED_PACKET_BITS]
        };

        let mut decoded = Err(NetError::InvalidUdpPacket("Empty ladder".to_string()));
        let mut first_authentic_err: Option<NetError> = None;

        for &bits in &max_bits_ladder {
            let max_bytes = bits.div_ceil(8);
            if raw_bytes.len() > max_bytes + 10 {
                continue;
            }
            let res = Ue3Packet::decode_with_max_bits(&raw_bytes, bits);
            match res {
                Ok(pkt) => {
                    decoded = Ok(pkt);
                    break;
                }
                Err(e) => {
                    if first_authentic_err.is_none() {
                        first_authentic_err = Some(e);
                    }
                }
            }
        }

        if decoded.is_err() {
            if let Some(err) = first_authentic_err {
                decoded = Err(err);
            }
        }

        match decoded {
            Ok(pkt) => {
                decoded_packets += 1;
                let prefix_type = match &pkt.pcom_prefix {
                    PcomPrefix::DedicatedSequenced { sequence, session_token, .. } => {
                        if let Some(token) = session_token {
                            let hex_token = token.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                            format!("Dedicated-Seq#{} [Token: {}]", sequence, hex_token)
                        } else {
                            format!("Dedicated-Seq#{}", sequence)
                        }
                    }
                    PcomPrefix::DedicatedUnsequenced { .. } => "Dedicated-Unseq".to_string(),
                    PcomPrefix::Standalone { sequence, .. } => format!("Standalone-Seq#{}", sequence),
                    PcomPrefix::Raw(_) => "Raw".to_string(),
                };
                println!(
                    "[+] Packet #{:<5} {} | [{}] ID: {:<5} | Acks: {:?} | Bunches: {}",
                    total_packets, meta, prefix_type, pkt.packet_id, pkt.acks, pkt.bunches.len()
                );

                for (idx, b) in pkt.bunches.iter().enumerate() {
                    total_bunches += 1;
                    let ch = b.header.ch_index;
                    let ch_type = b.header.ch_type;
                    let open_str = if b.header.flags.b_open { " OPEN" } else { "" };
                    let close_str = if b.header.flags.b_close { " CLOSE" } else { "" };
                    let rel_str = if b.header.flags.b_reliable { " RELIABLE" } else { "" };

                    match ch {
                        0 => ch0_count += 1,
                        1 => ch1_count += 1,
                        2 => ch2_count += 1,
                        _ => ch3_plus_count += 1,
                    }

                    print!(
                        "    Bunch #{:<2}: Ch {:<3} ({:?}) | Seq: {:<4} | Bits: {:<4} | Flags:{}{}{}",
                        idx, ch, ch_type, b.header.ch_sequence, b.num_bits, open_str, close_str, rel_str
                    );

                    if ch == 0 && !b.data.is_empty() {
                        let op = b.data[0];
                        let op_name = control_opcode_name(op);
                        let hex_preview = b.data.iter().take(24).map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ");
                        println!(" -> {} | Data: [{}]", op_name, hex_preview);
                    } else if ch == 1 {
                        let hex_preview = b.data.iter().take(24).map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ");
                        println!(" -> UMarshalChannel | Data: [{}]", hex_preview);
                    } else if ch >= 3 {
                        let hex_preview = b.data.iter().take(24).map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ");
                        println!(" -> UActorChannel | Data: [{}]", hex_preview);
                    } else {
                        println!();
                    }
                }
            }
            Err(e) => {
                // If it fails standard decode, inspect raw prefix / first bytes
                let hex_prefix = raw_bytes.iter().take(12).map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ");
                println!("[-] Packet #{:<5} {} | (Len: {} B) [Hex: {}] -> Decode error: {}", total_packets, meta, raw_bytes.len(), hex_prefix, e);
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total Packets Decoded: {} / {}", decoded_packets, total_packets);
    println!("Total Bunches: {}", total_bunches);
    println!("  Channel 0 (Control): {}", ch0_count);
    println!("  Channel 1 (Marshal): {}", ch1_count);
    println!("  Channel 2 (Voice):   {}", ch2_count);
    println!("  Channel 3+ (Actor):  {}", ch3_plus_count);

    Ok(())
}
