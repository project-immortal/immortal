// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net Integration Tests
//! End-to-end integration tests for MCTS TCP Auth Gateway and CPackCoder wire framing.

use immortal_net::{
    AuthGateway, AuthGatewayConfig, CPackFrame, LoginRequest, LoginResponse, MagicToken,
    CHAMPION_CASSIE, CHAMPION_FERNANDO, CHAMPION_VIKTOR, CHUNK1_HANDSHAKE, CHUNK2_ACK,
    CHUNK3_SESSION, DECK_FERNANDO_STARTER, DEVICE_FERNANDO_FLAME_LANCE, HEADER_LEN,
};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_auth_gateway_login_uncompressed() {
    let start = Instant::now();

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let gateway = AuthGateway::bind(bind_addr)
        .await
        .expect("Failed to bind AuthGateway");
    let handle = gateway.spawn().expect("Failed to spawn AuthGateway");
    let server_addr = handle.local_addr();

    // Connect client
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Client failed to connect to AuthGateway");

    // Formulate SendLogin RPC request
    let login_req = LoginRequest::new("8.1.5839.0", "IMMORTAL_CLIENT_DEV_TOKEN", "INT");
    let req_bytes = login_req.to_bytes().expect("Failed to encode LoginRequest");
    let wire_frame = CPackFrame::encode_uncompressed(&req_bytes).expect("Failed to encode frame");

    stream
        .write_all(&wire_frame)
        .await
        .expect("Failed to send wire frame");
    stream.flush().await.expect("Failed to flush wire frame");

    // Read response header
    let mut header = [0u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .expect("Failed to read response header");

    let magic_raw = u16::from_le_bytes([header[0], header[1]]);
    let magic = MagicToken::from_u16(magic_raw).expect("Invalid magic token received");
    assert_eq!(magic, MagicToken::Uncompressed);

    let payload_len = u16::from_le_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .expect("Failed to read response payload");

    let response_frame = CPackFrame { magic, payload };
    let uncompressed_bytes = response_frame
        .uncompressed_payload()
        .expect("Failed to get uncompressed payload");

    let login_resp =
        LoginResponse::from_bytes(&uncompressed_bytes).expect("Failed to parse LoginResponse");

    assert_eq!(login_resp.status, 0);
    assert_eq!(login_resp.account_id, 8302401);
    assert_eq!(login_resp.session_token, "IMMORTAL-DEV-SESSION-TICKET");
    assert_eq!(login_resp.match_ticket.server_host, "127.0.0.1");
    assert_eq!(login_resp.match_ticket.server_port, 7777);

    // Verify inventory rowsets (tokens 100, 102, 105)
    let roster = &login_resp.champion_roster;
    assert_eq!(roster.len(), 3);
    assert_eq!(roster[0].champion_id, CHAMPION_FERNANDO);
    assert!(roster[0].owned);
    assert_eq!(roster[1].champion_id, CHAMPION_CASSIE);
    assert!(roster[1].owned);
    assert_eq!(roster[2].champion_id, CHAMPION_VIKTOR);
    assert!(roster[2].owned);

    let weapons = &login_resp.weapon_devices;
    assert_eq!(weapons.len(), 1);
    assert_eq!(weapons[0].device_id, DEVICE_FERNANDO_FLAME_LANCE);
    assert_eq!(weapons[0].champion_id, CHAMPION_FERNANDO);

    let decks = &login_resp.deck_loadouts;
    assert_eq!(decks.len(), 1);
    assert_eq!(decks[0].deck_id, DECK_FERNANDO_STARTER);
    assert_eq!(decks[0].champion_id, CHAMPION_FERNANDO);
    handle
        .shutdown()
        .await
        .expect("Failed to shutdown AuthGateway");

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 200,
        "Auth Gateway integration test must finish in < 200ms, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_auth_gateway_login_compressed() {
    let start = Instant::now();

    let config = AuthGatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        compress_response: true,
        ..Default::default()
    };
    let gateway = AuthGateway::bind_with_config(config)
        .await
        .expect("Failed to bind AuthGateway");
    let handle = gateway.spawn().expect("Failed to spawn AuthGateway");
    let server_addr = handle.local_addr();

    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Client failed to connect");

    // Send compressed frame from client
    let login_req = LoginRequest::new("8.1.5839.0", "IMMORTAL_CLIENT_DEV_TOKEN", "INT");
    let req_bytes = login_req.to_bytes().expect("Failed to encode LoginRequest");
    let wire_frame =
        CPackFrame::encode_compressed(&req_bytes).expect("Failed to encode compressed frame");

    stream
        .write_all(&wire_frame)
        .await
        .expect("Failed to send wire frame");
    stream.flush().await.expect("Failed to flush");

    let mut header = [0u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .expect("Failed to read header");

    let magic_raw = u16::from_le_bytes([header[0], header[1]]);
    let magic = MagicToken::from_u16(magic_raw).expect("Invalid magic");
    assert_eq!(magic, MagicToken::Compressed);

    let payload_len = u16::from_le_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .expect("Failed to read payload");

    let response_frame = CPackFrame { magic, payload };
    let uncompressed_bytes = response_frame
        .uncompressed_payload()
        .expect("Failed to decompress payload");

    let login_resp =
        LoginResponse::from_bytes(&uncompressed_bytes).expect("Failed to parse LoginResponse");

    assert_eq!(login_resp.status, 0);
    assert_eq!(login_resp.account_id, 8302401);
    assert_eq!(login_resp.session_token, "IMMORTAL-DEV-SESSION-TICKET");
    assert_eq!(login_resp.match_ticket.server_host, "127.0.0.1");
    assert_eq!(login_resp.match_ticket.server_port, 7777);

    // Verify inventory rowsets (tokens 100, 102, 105)
    let roster = &login_resp.champion_roster;
    assert_eq!(roster.len(), 3);
    assert_eq!(roster[0].champion_id, CHAMPION_FERNANDO);
    assert!(roster[0].owned);
    assert_eq!(roster[1].champion_id, CHAMPION_CASSIE);
    assert!(roster[1].owned);
    assert_eq!(roster[2].champion_id, CHAMPION_VIKTOR);
    assert!(roster[2].owned);

    let weapons = &login_resp.weapon_devices;
    assert_eq!(weapons.len(), 1);
    assert_eq!(weapons[0].device_id, DEVICE_FERNANDO_FLAME_LANCE);
    assert_eq!(weapons[0].champion_id, CHAMPION_FERNANDO);

    let decks = &login_resp.deck_loadouts;
    assert_eq!(decks.len(), 1);
    assert_eq!(decks[0].deck_id, DECK_FERNANDO_STARTER);
    assert_eq!(decks[0].champion_id, CHAMPION_FERNANDO);
    handle
        .shutdown()
        .await
        .expect("Failed to shutdown AuthGateway");

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 200,
        "Compressed Auth Gateway integration test must finish in < 200ms, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_auth_gateway_live_mcts_two_step_exchange() {
    let start = Instant::now();

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let gateway = AuthGateway::bind(bind_addr)
        .await
        .expect("Failed to bind AuthGateway");
    let handle = gateway.spawn().expect("Failed to spawn AuthGateway");
    let server_addr = handle.local_addr();

    // Connect client
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Client failed to connect to AuthGateway");

    // 1. Step 1: Send client Frame 4 (405 bytes payload, flags 0x0000)
    let mut client_frame_4 = Vec::with_capacity(409);
    client_frame_4.extend_from_slice(&405u16.to_le_bytes());
    client_frame_4.extend_from_slice(&0x0000u16.to_le_bytes());
    client_frame_4.extend_from_slice(&vec![0xAAu8; 405]);
    stream.write_all(&client_frame_4).await.unwrap();
    stream.flush().await.unwrap();

    // Expect server Frame 6 (Chunk 1: 433 bytes payload, flags 0x0100)
    let mut header_buf = [0u8; 4];
    stream.read_exact(&mut header_buf).await.unwrap();
    let len = u16::from_le_bytes([header_buf[0], header_buf[1]]);
    let flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(len, 433);
    assert_eq!(flags, 0x0100);

    let mut chunk1_buf = vec![0u8; 433];
    stream.read_exact(&mut chunk1_buf).await.unwrap();
    assert_eq!(&chunk1_buf[..], CHUNK1_HANDSHAKE);

    // 2. Step 2: Send client Frame 8 (1117 bytes payload, flags 0x0100)
    let mut client_frame_8 = Vec::with_capacity(1121);
    client_frame_8.extend_from_slice(&1117u16.to_le_bytes());
    client_frame_8.extend_from_slice(&0x0100u16.to_le_bytes());
    client_frame_8.extend_from_slice(&vec![0xBBu8; 1117]);
    stream.write_all(&client_frame_8).await.unwrap();
    stream.flush().await.unwrap();

    // Expect Chunk 2 ACK (21 bytes payload, flags 0x0100)
    stream.read_exact(&mut header_buf).await.unwrap();
    let len = u16::from_le_bytes([header_buf[0], header_buf[1]]);
    let flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(len, 21);
    assert_eq!(flags, 0x0100);

    let mut chunk2_buf = vec![0u8; 21];
    stream.read_exact(&mut chunk2_buf).await.unwrap();
    assert_eq!(&chunk2_buf[..], CHUNK2_ACK);

    // Expect Chunk 3 Session (75 bytes)
    let mut chunk3_buf = vec![0u8; 75];
    stream.read_exact(&mut chunk3_buf).await.unwrap();
    assert_eq!(&chunk3_buf[..], CHUNK3_SESSION);

    // Expect LoginResponse
    stream.read_exact(&mut header_buf).await.unwrap();
    let magic_raw = u16::from_le_bytes([header_buf[0], header_buf[1]]);
    let magic = MagicToken::from_u16(magic_raw).expect("Invalid magic");
    let payload_len = u16::from_le_bytes([header_buf[2], header_buf[3]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.unwrap();

    let resp_frame = CPackFrame { magic, payload };
    let uncompressed_bytes = resp_frame.uncompressed_payload().unwrap();
    let login_resp = LoginResponse::from_bytes(&uncompressed_bytes).unwrap();

    assert_eq!(login_resp.status, 0);
    assert_eq!(login_resp.match_ticket.server_host, "127.0.0.1");
    assert_eq!(login_resp.match_ticket.server_port, 7777);

    let roster = &login_resp.champion_roster;
    assert_eq!(roster.len(), 3);
    assert_eq!(roster[0].champion_id, CHAMPION_FERNANDO);
    assert_eq!(roster[1].champion_id, CHAMPION_CASSIE);
    assert_eq!(roster[2].champion_id, CHAMPION_VIKTOR);

    let weapons = &login_resp.weapon_devices;
    assert_eq!(weapons.len(), 1);
    assert_eq!(weapons[0].device_id, DEVICE_FERNANDO_FLAME_LANCE);

    let decks = &login_resp.deck_loadouts;
    assert_eq!(decks.len(), 1);
    assert_eq!(decks[0].deck_id, DECK_FERNANDO_STARTER);

    handle.shutdown().await.unwrap();

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 200,
        "Live MCTS Auth Gateway exchange test must finish in < 200ms, took {:?}",
        elapsed
    );
}

