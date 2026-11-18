// SPDX-License-Identifier: AGPL-3.0
// Project Immortal — Scratch Dedicated-Server Pcap Decoder
// Reads raw hex packets from stdin or tshark output and decodes Ue3Packet/Bunches.

use immortal_net::bunch::{
    PcomPrefix, Ue3Packet, DEFAULT_MAX_PACKET_BITS, EXUDP_MAX_PACKET_BITS, MAX_ALLOWED_PACKET_BITS,
    NMT_HELLO, NMT_WELCOME, NMT_UPGRADE, NMT_CHALLENGE, NMT_NETSPEED, NMT_LOGIN,
    NMT_FAILURE, NMT_USES, NMT_HAVE, NMT_JOIN, NMT_JOIN_SPLIT, NMT_HANDSHAKE_START,
    NMT_HANDSHAKE_CHALLENGE, NMT_HANDSHAKE_RESPONSE, NMT_HANDSHAKE_COMPLETE,
    NMT_MAP_LOADED, NMT_REDIRECT, NMT_CLIENT_AUTH_REQUEST, NMT_SERVER_AUTH_REQUEST,
};
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
    if s.len() % 2 != 0 {
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

        // Ladder: if CLI specified, prioritize it. If packet > 576 bytes, prioritize 1440B MTU (11520 bits).
        let max_bits_ladder: Vec<usize> = if let Some(mb) = cli_max_bits {
            vec![mb, EXUDP_MAX_PACKET_BITS, DEFAULT_MAX_PACKET_BITS]
        } else if raw_bytes.len() > 576 {
            vec![MAX_ALLOWED_PACKET_BITS, EXUDP_MAX_PACKET_BITS, DEFAULT_MAX_PACKET_BITS]
        } else {
            vec![EXUDP_MAX_PACKET_BITS, DEFAULT_MAX_PACKET_BITS, MAX_ALLOWED_PACKET_BITS]
        };

        let mut decoded = Err(NetError::InvalidUdpPacket("Empty ladder".to_string()));
        for &bits in &max_bits_ladder {
            let res = Ue3Packet::decode_with_max_bits(&raw_bytes, bits);
            if res.is_ok() {
                decoded = res;
                break;
            } else {
                decoded = res;
            }
        }

        match decoded {
            Ok(pkt) => {
                decoded_packets += 1;
                let prefix_type = match &pkt.pcom_prefix {
                    PcomPrefix::Dedicated(_) => "Dedicated-10B",
                    PcomPrefix::Standalone(_) => "Standalone-6B",
                    PcomPrefix::Raw(_) => "Raw",
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
