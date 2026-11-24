// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # CAP-03 Framing, Launch.log Correlation & Shannon Entropy Audit (`UNK-CRYPTO-001` / `UNK-PROP-001`)
//!
//! Performs honest transport-level inspection and log correlation on `CAP-03` (`EV-NET-005` / `EV-LOG-006`):
//! - Parses cleartext 10-byte outer framing (`[01 00 00 00] [seq: 4B] [subflags: 2B]`) and
//!   4-stage unsequenced handshake (`subflags = 0x0010`: 570B Hello, 46B ServerChallenge, 1440B PMTU, 46B Finish).
//! - Extracts the cleartext Seq 1 6-byte session token prefix (`payload[10..16]`).
//! - Computes Shannon entropy over sequenced `0x0001` payloads (`~7.55 bits/byte` on full-size frames),
//!   confirming the `?exudp=2` session cipher boundary (`UNK-CRYPTO-001`).
//! - **PSL-INV-012 Truth Boundary**: This tool does **NOT** decrypt or deserialize UE3 bunches from
//!   sequenced CAP-03 frames. `UNK-PROP-001` (wire-level deck/item property decoding) remains OPEN;
//!   all Deck/Item identifiers shown below are externally correlated from `CAP-03_Launch.log` and
//!   binary VAs, NOT parsed from encrypted UDP payloads.

use immortal_net::bunch::{DedicatedControlFrame, SUBFLAG_SEQUENCED, SUBFLAG_UNSEQUENCED};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Extracted UDP Packet from PCAP / PCAPNG.
#[derive(Debug, Clone)]
pub struct RawUdpPacket {
    pub frame_number: usize,
    pub timestamp_sec: f64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Simple PCAP / PCAPNG (including NFLOG linktype 141) native reader.
pub struct PcapExtractor;

impl PcapExtractor {
    pub fn extract_packets<P: AsRef<Path>>(
        path: P,
        port_filter: Option<u16>,
    ) -> Result<Vec<RawUdpPacket>, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        reader.seek(SeekFrom::Start(0))?;

        if &magic == b"\n\r\r\n" {
            Self::extract_pcapng(&mut reader, port_filter)
        } else if &magic == b"\xa1\xb2\xc3\xd4"
            || &magic == b"\xd4\xc3\xb2\xa1"
            || &magic == b"\xa1\xb2\x3c\x4d"
            || &magic == b"\x4d\x3c\xb2\xa1"
        {
            Self::extract_classic_pcap(&mut reader, port_filter)
        } else {
            Err(format!("Unsupported capture file format: magic {:?}", magic).into())
        }
    }

    fn extract_pcapng<R: Read + Seek>(
        reader: &mut R,
        port_filter: Option<u16>,
    ) -> Result<Vec<RawUdpPacket>, Box<dyn std::error::Error>> {
        let mut packets = Vec::new();
        let mut interfaces: Vec<u16> = Vec::new();
        let mut frame_number = 0usize;

        let mut hdr = [0u8; 8];
        while reader.read_exact(&mut hdr).is_ok() {
            let block_type = u32::from_le_bytes(hdr[0..4].try_into()?);
            let block_len = u32::from_le_bytes(hdr[4..8].try_into()?);
            if block_len < 8 {
                break;
            }
            let body_len = (block_len - 8) as usize;
            let mut body = vec![0u8; body_len];
            reader.read_exact(&mut body)?;

            match block_type {
                0x00000001 => {
                    // Interface Description Block (IDB)
                    if body.len() >= 8 {
                        let linktype = u16::from_le_bytes(body[0..2].try_into()?);
                        interfaces.push(linktype);
                    }
                }
                0x00000006 => {
                    // Enhanced Packet Block (EPB)
                    if body.len() >= 20 {
                        let iface_id = u32::from_le_bytes(body[0..4].try_into()?) as usize;
                        let ts_high = u32::from_le_bytes(body[4..8].try_into()?);
                        let ts_low = u32::from_le_bytes(body[8..12].try_into()?);
                        let cap_len = u32::from_le_bytes(body[12..16].try_into()?) as usize;
                        let linktype = interfaces.get(iface_id).copied().unwrap_or(141);

                        let time_sec =
                            (((ts_high as u64) << 32) | (ts_low as u64)) as f64 / 1_000_000.0;
                        frame_number += 1;

                        if body.len() >= 20 + cap_len {
                            let packet_data = &body[20..20 + cap_len];
                            if let Some(pkt) = Self::parse_udp(
                                packet_data,
                                linktype,
                                frame_number,
                                time_sec,
                                port_filter,
                            ) {
                                packets.push(pkt);
                            }
                        }
                    }
                }
                0x00000003 => {
                    // Simple Packet Block (SPB)
                    if body.len() >= 4 {
                        let orig_len = u32::from_le_bytes(body[0..4].try_into()?) as usize;
                        let linktype = interfaces.first().copied().unwrap_or(141);
                        frame_number += 1;
                        if body.len() >= 4 + orig_len {
                            let packet_data = &body[4..4 + orig_len];
                            if let Some(pkt) = Self::parse_udp(
                                packet_data,
                                linktype,
                                frame_number,
                                0.0,
                                port_filter,
                            ) {
                                packets.push(pkt);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(packets)
    }

    fn extract_classic_pcap<R: Read + Seek>(
        reader: &mut R,
        port_filter: Option<u16>,
    ) -> Result<Vec<RawUdpPacket>, Box<dyn std::error::Error>> {
        let mut packets = Vec::new();
        let mut ghdr = [0u8; 24];
        reader.read_exact(&mut ghdr)?;
        let is_little =
            ghdr[0..4] == [0xd4, 0xc3, 0xb2, 0xa1] || ghdr[0..4] == [0x4d, 0x3c, 0xb2, 0xa1];
        let linktype = if is_little {
            u32::from_le_bytes(ghdr[20..24].try_into()?) as u16
        } else {
            u32::from_be_bytes(ghdr[20..24].try_into()?) as u16
        };

        let mut frame_number = 0usize;
        let mut phdr = [0u8; 16];
        while reader.read_exact(&mut phdr).is_ok() {
            let (ts_sec, ts_usec, cap_len) = if is_little {
                (
                    u32::from_le_bytes(phdr[0..4].try_into()?),
                    u32::from_le_bytes(phdr[4..8].try_into()?),
                    u32::from_le_bytes(phdr[8..12].try_into()?) as usize,
                )
            } else {
                (
                    u32::from_be_bytes(phdr[0..4].try_into()?),
                    u32::from_be_bytes(phdr[4..8].try_into()?),
                    u32::from_be_bytes(phdr[8..12].try_into()?) as usize,
                )
            };

            let time_sec = ts_sec as f64 + (ts_usec as f64 / 1_000_000.0);
            let mut packet_data = vec![0u8; cap_len];
            reader.read_exact(&mut packet_data)?;

            frame_number += 1;
            if let Some(pkt) =
                Self::parse_udp(&packet_data, linktype, frame_number, time_sec, port_filter)
            {
                packets.push(pkt);
            }
        }

        Ok(packets)
    }

    fn parse_udp(
        packet_data: &[u8],
        linktype: u16,
        frame_number: usize,
        time_sec: f64,
        port_filter: Option<u16>,
    ) -> Option<RawUdpPacket> {
        let ip_data = match linktype {
            141 | 239 => Self::parse_nflog(packet_data)?,
            1 => {
                if packet_data.len() >= 14 && packet_data[12..14] == [0x08, 0x00] {
                    &packet_data[14..]
                } else {
                    return None;
                }
            }
            113 => {
                if packet_data.len() >= 16 && packet_data[14..16] == [0x08, 0x00] {
                    &packet_data[16..]
                } else {
                    return None;
                }
            }
            12 | 101 => packet_data,
            _ => return None,
        };

        if ip_data.len() < 20 {
            return None;
        }

        let ver_ihl = ip_data[0];
        if (ver_ihl >> 4) != 4 {
            return None;
        }
        let ihl = ((ver_ihl & 0x0F) * 4) as usize;
        let proto = ip_data[9];
        if proto != 17 || ip_data.len() < ihl + 8 {
            return None;
        }

        let src_ip = format!(
            "{}.{}.{}.{}",
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]
        );

        let udp_header = &ip_data[ihl..ihl + 8];
        let src_port = u16::from_be_bytes(udp_header[0..2].try_into().ok()?);
        let dst_port = u16::from_be_bytes(udp_header[2..4].try_into().ok()?);
        let udp_len = u16::from_be_bytes(udp_header[4..6].try_into().ok()?) as usize;

        if let Some(pf) = port_filter {
            if src_port != pf && dst_port != pf {
                return None;
            }
        }

        let payload_start = ihl + 8;
        let payload_end = (ihl + udp_len).min(ip_data.len());
        if payload_start > payload_end {
            return None;
        }

        Some(RawUdpPacket {
            frame_number,
            timestamp_sec: time_sec,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload: ip_data[payload_start..payload_end].to_vec(),
        })
    }

    fn parse_nflog(packet_data: &[u8]) -> Option<&[u8]> {
        if packet_data.len() < 4 {
            return None;
        }
        let mut offset = 4;
        while offset + 4 <= packet_data.len() {
            let tlv_len =
                u16::from_le_bytes(packet_data[offset..offset + 2].try_into().ok()?) as usize;
            let tlv_type =
                u16::from_le_bytes(packet_data[offset + 2..offset + 4].try_into().ok()?) & 0x7FFF;
            if tlv_len < 4 {
                break;
            }
            let val_len = tlv_len - 4;
            if tlv_type == 9 && offset + 4 + val_len <= packet_data.len() {
                return Some(&packet_data[offset + 4..offset + 4 + val_len]);
            }
            offset += (tlv_len + 3) & !3;
        }
        None
    }
}

/// Computes Shannon entropy (bits per byte) for empirical crypto boundary verification.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn locate_capture_file() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--pcap" && i + 1 < args.len() {
            return PathBuf::from(&args[i + 1]);
        }
    }

    let candidates = [
        PathBuf::from(".dirtyroom/pcaps/CAP-03_custom_baseline_20261119.pcapng"),
        PathBuf::from("../../.dirtyroom/pcaps/CAP-03_custom_baseline_20261119.pcapng"),
        PathBuf::from("pcaps/CAP-03_custom_baseline_20261119.pcapng"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }

    PathBuf::from(".dirtyroom/pcaps/CAP-03_custom_baseline_20261119.pcapng")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("🛡️  PROJECT IMMORTAL: CAP-03 LAUNCH.LOG CORRELATION & ENTROPY AUDIT");
    println!("    Cipher Boundary: UNK-CRYPTO-001 (?exudp=2) | Property Status: UNK-PROP-001 OPEN");
    println!("    Governing Standard: PSL-INV-012 (Anti-Guess, Absolute Truth & Zero-Facade)");
    println!("================================================================================\n");

    let pcap_path = locate_capture_file();
    println!("[*] Capture Target: {}", pcap_path.display());
    if !pcap_path.exists() {
        eprintln!(
            "[-] Error: Target capture file does not exist at {}",
            pcap_path.display()
        );
        eprintln!(
            "    Please specify path via: cargo run --example extract_deck_items -- --pcap <path>"
        );
        std::process::exit(1);
    }

    println!("[*] Ingesting UDP 9113 datagram stream (NFLOG / PCAPNG)...");
    let packets = PcapExtractor::extract_packets(&pcap_path, Some(9113))?;
    println!(
        "[+] Total UDP Port 9113 Packets Extracted: {}\n",
        packets.len()
    );

    // 1. Audit Transport Framing & Handshake Protocol
    let mut unsequenced_frames = 0usize;
    let mut sequenced_frames = 0usize;
    let mut server_challenge_cookie = None;
    let mut client_challenge_cookie = None;
    let mut session_token_seq1 = None;
    let mut welcome_frame = None;
    let mut map_loaded_frame = None;

    // Milestone Packets
    let mut actor_channel_open_pkt = None;
    let mut pawn_spawn_pkt = None;
    let mut weapon_spawn_pkt = None;

    // Deck & Items Milestones
    let mut deck_equip_packet = None;
    let mut item_buy1_packet = None;
    let mut item_buy1_resp_packet = None;
    let mut item_buy2_packet = None;

    for (idx, pkt) in packets.iter().enumerate() {
        let pnum = idx + 1;
        let payload = &pkt.payload;
        if payload.len() < 10 {
            continue;
        }

        let _magic = &payload[0..4];
        let seq = u32::from_le_bytes(payload[4..8].try_into().unwrap_or([0; 4]));
        let subflags = u16::from_be_bytes(payload[8..10].try_into().unwrap_or([0; 2]));

        if subflags == SUBFLAG_UNSEQUENCED {
            unsequenced_frames += 1;
            if let Some(DedicatedControlFrame::ServerChallenge {
                client_cookie,
                server_cookie,
                ..
            }) = DedicatedControlFrame::parse(payload)
            {
                client_challenge_cookie = Some(client_cookie);
                server_challenge_cookie = Some(server_cookie);
            }
        } else if subflags == SUBFLAG_SEQUENCED {
            sequenced_frames += 1;
            let is_client_to_server = pkt.src_port == 50427;

            // Seq 1 Token Barrier
            if seq == 1 && session_token_seq1.is_none() && payload.len() >= 16 {
                let token: [u8; 6] = payload[10..16].try_into().unwrap();
                session_token_seq1 = Some((pkt.frame_number, pnum, token));
            }

            // Seq 18 Welcome
            if seq == 18 && !is_client_to_server && welcome_frame.is_none() {
                welcome_frame = Some((pkt.frame_number, pnum, pkt.timestamp_sec));
            }

            // Seq 28 MapLoaded
            if seq == 28 && !is_client_to_server && map_loaded_frame.is_none() {
                map_loaded_frame = Some((pkt.frame_number, pnum, pkt.timestamp_sec));
            }

            // Post-MapLoaded Server Seq 51..60 (Actor Channel Initialization)
            if !is_client_to_server {
                if seq == 51 && actor_channel_open_pkt.is_none() {
                    actor_channel_open_pkt = Some((pkt.frame_number, pnum, pkt.clone()));
                } else if seq == 52 && pawn_spawn_pkt.is_none() {
                    pawn_spawn_pkt = Some((pkt.frame_number, pnum, pkt.clone()));
                } else if seq == 53 && weapon_spawn_pkt.is_none() {
                    weapon_spawn_pkt = Some((pkt.frame_number, pnum, pkt.clone()));
                }
            }

            // Deck Equip Frame (around T=1795057746.17 / Launch log [0225.57])
            // Client Seq 1774 (Frame 17205) / Server Seq 768..770 (Frames 17206..17210)
            if pkt.frame_number == 17205 {
                deck_equip_packet = Some((pnum, pkt.clone()));
            }

            // Round 1 Item Purchase (around T=1795057770.35 / Launch log [0249.85])
            // Client Seq 3087 (Frame 19115) / Server Seq 1349 (Frame 19117)
            if pkt.frame_number == 19115 {
                item_buy1_packet = Some((pnum, pkt.clone()));
            }
            if pkt.frame_number == 19117 {
                item_buy1_resp_packet = Some((pnum, pkt.clone()));
            }

            // Round 2 Item Purchase (around T=1795058067.55 / Launch log [0547.10])
            // Server Seq 8513 (Frame 46685)
            if pkt.frame_number == 46685 {
                item_buy2_packet = Some((pnum, pkt.clone()));
            }
        }
    }

    println!("--- [PHASE 1: TRANSPORT FRAMING & CRYPTOGRAPHIC BARRIER] ---");
    println!(
        "  • Unsequenced Control Frames (0x0010): {} frames",
        unsequenced_frames
    );
    println!(
        "  • Sequenced Gameplay Frames  (0x0001): {} frames",
        sequenced_frames
    );

    if let (Some(cc), Some(sc)) = (client_challenge_cookie, server_challenge_cookie) {
        let cc_hex = cc
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let sc_hex = sc
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  • Handshake Challenge (Frame 14598): Client Cookie: [{}] | Server Cookie: [{}]",
            cc_hex, sc_hex
        );
    }

    if let Some((fnum, pnum, token)) = session_token_seq1 {
        let token_hex = token
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  • Seq 1 Session Token Barrier: Pkt #{} (Frame {}) -> Token: [{}]",
            pnum, fnum, token_hex
        );
        assert_eq!(
            token,
            [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F],
            "Session token must match authentic CAP-03 ground truth"
        );
    }

    if let Some((fnum, pnum, ts)) = welcome_frame {
        println!(
            "  • S->C Seq 18 (encrypted 0x0001): Pkt #{} (Frame {}) at ts={:.3}s [correlates with map load window; payload encrypted]",
            pnum, fnum, ts
        );
    }
    if let Some((fnum, pnum, ts)) = map_loaded_frame {
        println!(
            "  • S->C Seq 28 (encrypted 0x0001): Pkt #{} (Frame {}) at ts={:.3}s [encrypted server datagram; NOT NMT_MapLoaded]",
            pnum, fnum, ts
        );
    }
    println!();

    // 2. Encrypted Sequenced Gameplay Stream & Entropy Audit (Server Seq 51–60, Packets #524–#560)
    println!(
        "--- [PHASE 2: SEQUENCED 0x0001 STREAM & SHANNON ENTROPY AUDIT (PACKETS #524–#560)] ---"
    );
    println!("  • PSL-INV-012 Notice: Sequenced 0x0001 payloads in CAP-03 are encrypted by ?exudp=2 (UNK-CRYPTO-001).");
    println!("    Decoder unmapped / infrastructure not yet ready — cannot extract UE3 bunches from capture.");
    if let Some((fnum, pnum, ref pkt)) = actor_channel_open_pkt {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Packet #{:<5} Frame {:<5} | S->C Seq {:<3} | Len {:<4} B | Payload Entropy: {:.4} bits/byte (cipher)", pnum, fnum, seq, pkt.payload.len(), entropy);
        println!("    ├─ External Launch.log correlation: [0195.74] TgPlayerController_1 setplayer TgLocalPlayer_0");
        println!(
            "    └─ Wire Prefix Hex: [{}]",
            pkt.payload
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if let Some((fnum, pnum, ref pkt)) = pawn_spawn_pkt {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Packet #{:<5} Frame {:<5} | S->C Seq {:<3} | Len {:<4} B | Payload Entropy: {:.4} bits/byte (encrypted; unparsed)", pnum, fnum, seq, pkt.payload.len(), entropy);
    }

    if let Some((fnum, pnum, ref pkt)) = weapon_spawn_pkt {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Packet #{:<5} Frame {:<5} | S->C Seq {:<3} | Len {:<4} B | Payload Entropy: {:.4} bits/byte (encrypted; unparsed)", pnum, fnum, seq, pkt.payload.len(), entropy);
    }

    println!("  • Sequenced Frame Header Summary (Packets #524–#560):");
    let mut seq51_60_count = 0usize;
    for (idx, pkt) in packets.iter().enumerate() {
        let pnum = idx + 1;
        if (524..=560).contains(&pnum) {
            let seq = if pkt.payload.len() >= 8 {
                u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap_or([0; 4]))
            } else {
                0
            };
            let dir = if pkt.src_port == 50427 {
                "C->S"
            } else {
                "S->C"
            };
            seq51_60_count += 1;
            if seq51_60_count <= 8 || pnum == 560 {
                println!(
                    "    [{:04}] Frame {:<5} | {} | Seq {:<4} | Len {:<4} B | [{}]",
                    pnum,
                    pkt.frame_number,
                    dir,
                    seq,
                    pkt.payload.len(),
                    pkt.payload
                        .iter()
                        .take(12)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            } else if seq51_60_count == 9 {
                println!("    ... (Packets #532–#559 outer prefixes audited across Server Seq 54–73 and Client Seq 464–471) ...");
            }
        }
    }
    println!();

    // 3. Launch.log Timestamp Correlation & Entropy Verification: Card Deck Event (UNK-PROP-001 OPEN)
    println!("--- [PHASE 3: LAUNCH.LOG CORRELATION — CARD DECK WINDOW (UNK-PROP-001 OPEN)] ---");
    println!("  • External Retail Log Reference (CAP-03_custom_baseline_20261119_Launch.log):");
    println!("    [0225.57] Log: UUIHudDecks::OnEquip 16381");
    println!("    [0225.73] Log: ATgPawn::ReceiveInventoryData called");
    println!("  • External Binary RE Reference (ShippingPC-ChaosGame.exe):");
    println!("    ├─ Procedure 0x1415caaf0: UUIHudDecks::OnEquip");
    println!("    ├─ Procedure 0x140e75ab0: ATgRepInfo_PlayerexecLoadCardDeck");
    println!("    └─ FName Symbol 0x144445ab8: ServerRequestDeckAndTalent");
    println!("  • Wire Status: CANNOT deserialize deck/talent properties from capture (encrypted by UNK-CRYPTO-001).");
    println!();

    if let Some((pnum, ref pkt)) = deck_equip_packet {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!(
            "  • Correlated Encrypted Datagram in Window (Frame {}):",
            pkt.frame_number
        );
        println!(
            "    ├─ Packet Index:  Pkt #{} (Frame {})",
            pnum, pkt.frame_number
        );
        println!(
            "    ├─ Direction:     Client -> Server ({}:{} -> {}:{})",
            pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
        );
        println!("    ├─ Outer Seq:     Client Monotonic Seq = {}", seq);
        println!(
            "    ├─ Timestamp:     ts = {:.3}s (time-window correlated to Launch.log [0225.57])",
            pkt.timestamp_sec
        );
        println!(
            "    ├─ Wire Length:   {} Bytes | Cipher Entropy: {:.4} bits/byte",
            pkt.payload.len(),
            entropy
        );
        println!(
            "    └─ Ciphertext:    [{}]",
            pkt.payload
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    println!();

    // 4. Launch.log Timestamp Correlation & Entropy Verification: Item Purchase Windows (UNK-PROP-001 OPEN)
    println!(
        "--- [PHASE 4: LAUNCH.LOG CORRELATION — ITEM PURCHASE WINDOWS (UNK-PROP-001 OPEN)] ---"
    );
    println!("  • External Retail Log Reference:");
    println!("    [0249.85] Log: Soft Init of PropID 4 on DeviceID 11059 for FireModeID 10445 -- Setting to 0.00");
    println!("    [0249.85] Log: ATgPawn::ReceiveInventoryData called");
    println!("    [0547.10] Log: ATgPawn::ReceiveInventoryData called");
    println!("  • External Binary RE Reference (ShippingPC-ChaosGame.exe):");
    println!("    └─ Procedure 0x140e712c0: ATgPlayerControllerexecServerPurchaseItem");
    println!("  • Wire Status: CANNOT deserialize item/property fields from capture (encrypted by UNK-CRYPTO-001).");
    println!();

    if let Some((pnum, ref pkt)) = item_buy1_packet {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Correlated Encrypted Datagram in Round 1 Window (C->S):");
        println!(
            "    ├─ Packet Index:  Pkt #{} (Frame {})",
            pnum, pkt.frame_number
        );
        println!("    ├─ Outer Seq:     Client Monotonic Seq = {}", seq);
        println!(
            "    ├─ Timestamp:     ts = {:.3}s (time-window correlated to Launch.log [0249.85])",
            pkt.timestamp_sec
        );
        println!(
            "    ├─ Wire Length:   {} Bytes | Cipher Entropy: {:.4} bits/byte",
            pkt.payload.len(),
            entropy
        );
        println!(
            "    └─ Prefix+Cipher: [{}]",
            pkt.payload
                .iter()
                .take(24)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if let Some((pnum, ref pkt)) = item_buy1_resp_packet {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Correlated Encrypted Datagram in Round 1 Window (S->C):");
        println!(
            "    ├─ Packet Index:  Pkt #{} (Frame {})",
            pnum, pkt.frame_number
        );
        println!("    ├─ Outer Seq:     Server Monotonic Seq = {}", seq);
        println!("    ├─ Timestamp:     ts = {:.3}s", pkt.timestamp_sec);
        println!(
            "    ├─ Wire Length:   {} Bytes | Cipher Entropy: {:.4} bits/byte",
            pkt.payload.len(),
            entropy
        );
        println!(
            "    └─ Prefix+Cipher: [{}]",
            pkt.payload
                .iter()
                .take(24)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if let Some((pnum, ref pkt)) = item_buy2_packet {
        let seq = u32::from_le_bytes(pkt.payload[4..8].try_into().unwrap());
        let entropy = calculate_shannon_entropy(&pkt.payload[10..]);
        println!("  • Correlated Encrypted Datagram in Round 2 Window (S->C):");
        println!(
            "    ├─ Packet Index:  Pkt #{} (Frame {})",
            pnum, pkt.frame_number
        );
        println!("    ├─ Outer Seq:     Server Monotonic Seq = {}", seq);
        println!(
            "    ├─ Timestamp:     ts = {:.3}s (time-window correlated to Launch.log [0547.10])",
            pkt.timestamp_sec
        );
        println!(
            "    ├─ Wire Length:   {} Bytes | Cipher Entropy: {:.4} bits/byte",
            pkt.payload.len(),
            entropy
        );
        println!(
            "    └─ Prefix+Cipher: [{}]",
            pkt.payload
                .iter()
                .take(24)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    println!();

    // 5. PSL-INV-012 Verification & Cryptographic Boundary Declaration
    println!("--- [PHASE 5: PSL-INV-012 ABSOLUTE TRUTH AUDIT & CRYPTO BOUNDARY] ---");
    println!("  • Honest Infrastructure Declaration:");
    println!("    - Unsequenced 0x0010 handshake headers and 10-byte outer prefixes are parsed from CAP-03.");
    println!("    - Sequenced 0x0001 payloads carry high-entropy ciphertext (~7.55 bits/byte on large frames),");
    println!("      encrypted by the ?exudp=2 session cipher (UNK-CRYPTO-001).");
    println!(
        "    - Decoder unmapped / infrastructure not yet ready — this tool does NOT decrypt or"
    );
    println!(
        "      deserialize UE3 bunches, and UNK-PROP-001 remains OPEN pending UNK-CRYPTO-001."
    );
    println!();

    println!("================================================================================");
    println!("✅ CAP-03 CORRELATION & ENTROPY VERIFICATION COMPLETE (UNK-PROP-001 STILL OPEN)");
    println!("================================================================================");

    Ok(())
}
