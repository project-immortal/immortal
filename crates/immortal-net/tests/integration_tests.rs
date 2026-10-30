// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net Integration Tests
//! End-to-end integration tests for MCTS TCP Auth Gateway and CPackCoder wire framing.

use immortal_net::{
    AuthGateway, AuthGatewayConfig, CPackFrame, LoginRequest, LoginResponse, MagicToken,
    BOT_ID_FERNANDO, CHAMPION_CASSIE, CHAMPION_FERNANDO, CHAMPION_VIKTOR, CHUNK2_ACK, CHUNK3_SESSION, DECK_FERNANDO_STARTER, DEVICE_FERNANDO_FLAME_LANCE, HEADER_LEN,
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
    let config = AuthGatewayConfig {
        bind_addr,
        post_login_settle_delay_ms: 0,
        post_login_invite_delay_ms: 0,
        post_login_accept_delay_ms: 0,
        post_login_launch_delay_ms: 0,
        ..Default::default()
    };
    let gateway = AuthGateway::bind_with_config(config)
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

    // Expect server unencrypted CMarshal Hello response (20 bytes payload, flags 0x0000)
    let mut header_buf = [0u8; 4];
    stream.read_exact(&mut header_buf).await.unwrap();
    let len = u16::from_le_bytes([header_buf[0], header_buf[1]]);
    let flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(len, 20);
    assert_eq!(flags, 0x0000);

    let mut hello_resp_buf = vec![0u8; 20];
    stream.read_exact(&mut hello_resp_buf).await.unwrap();
    assert_eq!(&hello_resp_buf[..], &immortal_net::MCTS_HELLO_RESPONSE_PAYLOAD[..]);

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

    // Expect authentic Live MCTS OnLoginResponse wire frame
    stream.read_exact(&mut header_buf).await.unwrap();
    let frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let wire_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(wire_flags, 0x0000);

    let mut payload = vec![0u8; frame_len];
    stream.read_exact(&mut payload).await.unwrap();

    assert_eq!(payload[0], 0x00); // this[0x30]
    let func_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    assert_eq!(func_id, immortal_net::MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE);
    assert_eq!(func_id, 0x7a4036ab);

    let field_count = u16::from_le_bytes([payload[5], payload[6]]);
    assert_eq!(field_count, 7);

    // Group 0x1000: Field 2 (bool true)
    let grp1 = u16::from_le_bytes([payload[7], payload[8]]);
    assert_eq!(grp1, 0x1001);
    assert_eq!(u16::from_le_bytes([payload[9], payload[10]]), 2);
    assert_eq!(payload[11], 1);

    // Group 0x3000: Field 3 (0), Field 739 (60)
    let grp4 = u16::from_le_bytes([payload[12], payload[13]]);
    assert_eq!(grp4, 0x3002);
    assert_eq!(u16::from_le_bytes([payload[14], payload[15]]), 3);
    assert_eq!(u16::from_le_bytes([payload[16], payload[17]]), 739);
    assert_eq!(u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]), 0); // Token 3 = 0
    assert_eq!(u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]), 60); // Token 739 = 60

    // Group 0x4000: Field 11 (MCTS_TOKEN_PLAYER_ID) and Field 26 (ACCOUNT_ID)
    let grp8 = u16::from_le_bytes([payload[26], payload[27]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(u16::from_le_bytes([payload[28], payload[29]]), 11);
    assert_eq!(u16::from_le_bytes([payload[30], payload[31]]), 26);
    let v11 = u64::from_le_bytes([
        payload[32], payload[33], payload[34], payload[35],
        payload[36], payload[37], payload[38], payload[39],
    ]);
    let v26 = u64::from_le_bytes([
        payload[40], payload[41], payload[42], payload[43],
        payload[44], payload[45], payload[46], payload[47],
    ]);
    assert_eq!(v11, 8302401);
    assert_eq!(v26, 8302401);

    // String 1: Token 7 (session_token)
    assert_eq!(u16::from_le_bytes([payload[48], payload[49]]), 0xa001);
    assert_eq!(u16::from_le_bytes([payload[50], payload[51]]), 7);
    let s1_len = u16::from_le_bytes([payload[52], payload[53]]) as usize;
    let s1_str = std::str::from_utf8(&payload[54..54 + s1_len]).unwrap();
    assert_eq!(s1_str, "IMMORTAL-DEV-SESSION-TICKET");

    // String 2: Token 758 (player_name)
    let p2 = 54 + s1_len;
    assert_eq!(u16::from_le_bytes([payload[p2], payload[p2 + 1]]), 0xa001);
    assert_eq!(u16::from_le_bytes([payload[p2 + 2], payload[p2 + 3]]), 758);
    let s2_len = u16::from_le_bytes([payload[p2 + 4], payload[p2 + 5]]) as usize;
    let s2_str = std::str::from_utf8(&payload[p2 + 6..p2 + 6 + s2_len]).unwrap();
    assert_eq!(s2_str, "Fernando");

    // 3. Step 3: Expect authentic Live MCTS MATCH_STATUS wire frame (0x392dcda5, queue_id 0, match_id 0, match_lobby_state 0, launch_seconds 0, player_lobby_state 0, player_queue_state 0)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status_frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status_wire_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status_wire_flags, 0x0000);

    let mut status_payload = vec![0u8; status_frame_len];
    stream.read_exact(&mut status_payload).await.unwrap();
    assert_eq!(status_payload[0], 0x00);
    let status_func_id = u32::from_le_bytes([status_payload[1], status_payload[2], status_payload[3], status_payload[4]]);
    assert_eq!(status_func_id, immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS);
    assert_eq!(status_func_id, 0x392dcda5);
    let field_count = u16::from_le_bytes([status_payload[5], status_payload[6]]);
    assert_eq!(field_count, 6);

    // Group 0x3000: Token 1342 (match_lobby_state = 0), Token 1690 (launch_seconds = 0), Token 1344 (player_lobby_state = 0), Token 2191 (player_queue_state = 0)
    let grp4 = u16::from_le_bytes([status_payload[7], status_payload[8]]);
    assert_eq!(grp4, 0x3004);
    assert_eq!(u16::from_le_bytes([status_payload[9], status_payload[10]]), 1342);
    assert_eq!(u16::from_le_bytes([status_payload[11], status_payload[12]]), 1690);
    assert_eq!(u16::from_le_bytes([status_payload[13], status_payload[14]]), 1344);
    assert_eq!(u16::from_le_bytes([status_payload[15], status_payload[16]]), 2191);
    let v1342 = u32::from_le_bytes([status_payload[17], status_payload[18], status_payload[19], status_payload[20]]);
    let v1690 = u32::from_le_bytes([status_payload[21], status_payload[22], status_payload[23], status_payload[24]]);
    let v1344 = u32::from_le_bytes([status_payload[25], status_payload[26], status_payload[27], status_payload[28]]);
    let v2191 = u32::from_le_bytes([status_payload[29], status_payload[30], status_payload[31], status_payload[32]]);
    assert_eq!(v1342, 0); // match_lobby_state = 0
    assert_eq!(v1690, 0); // launch_seconds = 0
    assert_eq!(v1344, 0); // player_lobby_state = 0
    assert_eq!(v2191, 0); // player_queue_state = 0

    // Group 0x4000: Token 700 (match_id = 0), Token 703 (queue_id = 0)
    let grp8 = u16::from_le_bytes([status_payload[33], status_payload[34]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(u16::from_le_bytes([status_payload[35], status_payload[36]]), 700);
    assert_eq!(u16::from_le_bytes([status_payload[37], status_payload[38]]), 703);
    let v700 = u64::from_le_bytes([
        status_payload[39], status_payload[40], status_payload[41], status_payload[42],
        status_payload[43], status_payload[44], status_payload[45], status_payload[46],
    ]);
    let v703 = u64::from_le_bytes([
        status_payload[47], status_payload[48], status_payload[49], status_payload[50],
        status_payload[51], status_payload[52], status_payload[53], status_payload[54],
    ]);
    assert_eq!(v700, 0); // match_id = 0
    assert_eq!(v703, 0); // queue_id = 0

    // Step 3b: Expect authentic Live MCTS CHAMPION_ROSTER wire frame (Table 249, 5 champions: [1026, 1024, 1025, 1027, BOT_ID_FERNANDO])
    stream.read_exact(&mut header_buf).await.unwrap();
    let roster_frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let roster_wire_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(roster_wire_flags, 0x0000);

    let mut roster_payload = vec![0u8; roster_frame_len];
    stream.read_exact(&mut roster_payload).await.unwrap();
    assert_eq!(roster_payload[0], 0x00);
    let roster_func_id = u32::from_le_bytes([roster_payload[1], roster_payload[2], roster_payload[3], roster_payload[4]]);
    assert_eq!(roster_func_id, immortal_net::MCTS_FUNCTION_ID_CHAMPION_ROSTER);
    assert_eq!(roster_func_id, 0xdb15d3d7);
    assert_eq!(u16::from_le_bytes([roster_payload[5], roster_payload[6]]), 1); // 1 table field
    assert_eq!(u16::from_le_bytes([roster_payload[7], roster_payload[8]]), 0x6001); // Group 0x6000 | 1
    assert_eq!(u16::from_le_bytes([roster_payload[9], roster_payload[10]]), 249); // Table 249
    assert_eq!(u16::from_le_bytes([roster_payload[11], roster_payload[12]]), 5); // 5 rows

    // 4. Step 4: Client sends first post-login frame (e.g. champion select or queue request)
    let mut champ_frame = Vec::new();
    champ_frame.extend_from_slice(&15u16.to_le_bytes());
    champ_frame.extend_from_slice(&0x0000u16.to_le_bytes());
    let mut champ_payload = vec![0u8; 15];
    champ_payload[6] = 0x9b;
    champ_payload[7] = 0x08; // 2203 (Fernando)
    champ_frame.extend_from_slice(&champ_payload);
    stream.write_all(&champ_frame).await.unwrap();
    stream.flush().await.unwrap();

    // Expect automatic Shooting Range transition sequence:
    // (a0) MATCH_STATUS queued (queue 434, match 0, lobby_state 0, launch_seconds 0, player_lobby_state 0, player_queue_state 2 MQ_QUEUED)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status_queued_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status_queued_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status_queued_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status_queued_len, 55); // agyis: no-mutant
    let mut status_queued_payload = vec![0u8; status_queued_len];
    stream.read_exact(&mut status_queued_payload).await.unwrap();
    assert_eq!(status_queued_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([status_queued_payload[1], status_queued_payload[2], status_queued_payload[3], status_queued_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[5], status_queued_payload[6]]), 6); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[7], status_queued_payload[8]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[9], status_queued_payload[10]]), 1342); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[11], status_queued_payload[12]]), 1690); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[13], status_queued_payload[14]]), 1344); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[15], status_queued_payload[16]]), 2191); // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_queued_payload[17], status_queued_payload[18], status_queued_payload[19], status_queued_payload[20]]), 0); // match_lobby_state = 0 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_queued_payload[21], status_queued_payload[22], status_queued_payload[23], status_queued_payload[24]]), 0); // launch_seconds = 0 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_queued_payload[25], status_queued_payload[26], status_queued_payload[27], status_queued_payload[28]]), 0); // player_lobby_state = 0 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_queued_payload[29], status_queued_payload[30], status_queued_payload[31], status_queued_payload[32]]), 2); // player_queue_state = 2 (MQ_QUEUED) // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[33], status_queued_payload[34]]), 0x4002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[35], status_queued_payload[36]]), 700); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_queued_payload[37], status_queued_payload[38]]), 703); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_queued_payload[39], status_queued_payload[40], status_queued_payload[41], status_queued_payload[42],
            status_queued_payload[43], status_queued_payload[44], status_queued_payload[45], status_queued_payload[46],
        ]),
        0
    ); // match_id = 0 // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_queued_payload[47], status_queued_payload[48], status_queued_payload[49], status_queued_payload[50],
            status_queued_payload[51], status_queued_payload[52], status_queued_payload[53], status_queued_payload[54],
        ]),
        434
    ); // queue_id = 434 // agyis: no-mutant

    // (a1) MATCH_STATUS invited (queue 0, match 878850364, lobby_state 0, launch_seconds 30, player_lobby_state 0, player_queue_state 3 MQ_INVITED)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status_inv_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status_inv_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status_inv_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status_inv_len, 55); // agyis: no-mutant
    let mut status_inv_payload = vec![0u8; status_inv_len];
    stream.read_exact(&mut status_inv_payload).await.unwrap();
    assert_eq!(status_inv_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([status_inv_payload[1], status_inv_payload[2], status_inv_payload[3], status_inv_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[5], status_inv_payload[6]]), 6); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[7], status_inv_payload[8]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[9], status_inv_payload[10]]), 1342); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[11], status_inv_payload[12]]), 1690); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[13], status_inv_payload[14]]), 1344); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[15], status_inv_payload[16]]), 2191); // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_inv_payload[17], status_inv_payload[18], status_inv_payload[19], status_inv_payload[20]]), 0); // match_lobby_state = 0 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_inv_payload[21], status_inv_payload[22], status_inv_payload[23], status_inv_payload[24]]), 30); // launch_seconds = 30 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_inv_payload[25], status_inv_payload[26], status_inv_payload[27], status_inv_payload[28]]), 0); // player_lobby_state = 0 // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([status_inv_payload[29], status_inv_payload[30], status_inv_payload[31], status_inv_payload[32]]), 3); // player_queue_state = 3 (MQ_INVITED) // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[33], status_inv_payload[34]]), 0x4002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[35], status_inv_payload[36]]), 700); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status_inv_payload[37], status_inv_payload[38]]), 703); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_inv_payload[39], status_inv_payload[40], status_inv_payload[41], status_inv_payload[42],
            status_inv_payload[43], status_inv_payload[44], status_inv_payload[45], status_inv_payload[46],
        ]),
        878850364
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_inv_payload[47], status_inv_payload[48], status_inv_payload[49], status_inv_payload[50],
            status_inv_payload[51], status_inv_payload[52], status_inv_payload[53], status_inv_payload[54],
        ]),
        0
    ); // agyis: no-mutant

    // (a1) MATCH_INVITATION (Function ID 0x423b389a, queue 434, match 878850364, timeout 30s, Table 1619 account 8302401)
    stream.read_exact(&mut header_buf).await.unwrap();
    let invite_frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let invite_frame_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(invite_frame_flags, 0x0000); // agyis: no-mutant
    assert_eq!(invite_frame_len, 65); // agyis: no-mutant
    let mut invite_frame_payload = vec![0u8; invite_frame_len];
    stream.read_exact(&mut invite_frame_payload).await.unwrap();
    assert_eq!(invite_frame_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([invite_frame_payload[1], invite_frame_payload[2], invite_frame_payload[3], invite_frame_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_INVITATION
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[5], invite_frame_payload[6]]), 5); // agyis: no-mutant

    // Group 0x3000: Token 1342 (state = 0), Token 1690 (timeout = 30)
    assert_eq!(u16::from_le_bytes([invite_frame_payload[7], invite_frame_payload[8]]), 0x3002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[9], invite_frame_payload[10]]), 1342); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[11], invite_frame_payload[12]]), 1690); // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([invite_frame_payload[13], invite_frame_payload[14], invite_frame_payload[15], invite_frame_payload[16]]), 0); // agyis: no-mutant
    assert_eq!(u32::from_le_bytes([invite_frame_payload[17], invite_frame_payload[18], invite_frame_payload[19], invite_frame_payload[20]]), 30); // agyis: no-mutant

    // Group 0x4000: Token 700 (match_id), Token 703 (queue_id)
    assert_eq!(u16::from_le_bytes([invite_frame_payload[21], invite_frame_payload[22]]), 0x4002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[23], invite_frame_payload[24]]), 700); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[25], invite_frame_payload[26]]), 703); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            invite_frame_payload[27], invite_frame_payload[28], invite_frame_payload[29], invite_frame_payload[30],
            invite_frame_payload[31], invite_frame_payload[32], invite_frame_payload[33], invite_frame_payload[34],
        ]),
        878850364
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            invite_frame_payload[35], invite_frame_payload[36], invite_frame_payload[37], invite_frame_payload[38],
            invite_frame_payload[39], invite_frame_payload[40], invite_frame_payload[41], invite_frame_payload[42],
        ]),
        434
    ); // agyis: no-mutant

    // Group 0x6000: Table 1619 (MCTS_TOKEN_INVITED_MEMBERS)
    assert_eq!(u16::from_le_bytes([invite_frame_payload[43], invite_frame_payload[44]]), 0x6001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[45], invite_frame_payload[46]]), immortal_net::MCTS_TOKEN_INVITED_MEMBERS); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[45], invite_frame_payload[46]]), 1619); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[47], invite_frame_payload[48]]), 1); // agyis: no-mutant (1 row)

    // Row 0: 2 fields (Tokens 11 and 682)
    assert_eq!(u16::from_le_bytes([invite_frame_payload[49], invite_frame_payload[50]]), 2); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[51], invite_frame_payload[52]]), 0x3002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[53], invite_frame_payload[54]]), immortal_net::MCTS_TOKEN_PLAYER_ID); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[53], invite_frame_payload[54]]), 11); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[55], invite_frame_payload[56]]), immortal_net::MCTS_TOKEN_ACCOUNT_ID); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([invite_frame_payload[55], invite_frame_payload[56]]), 682); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[57], invite_frame_payload[58], invite_frame_payload[59], invite_frame_payload[60]
        ]),
        8302401
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[61], invite_frame_payload[62], invite_frame_payload[63], invite_frame_payload[64]
        ]),
        8302401
    ); // agyis: no-mutant

    // (a) MATCH_STATUS state 8 with QUEUE_STATUS table (Token 242) and DATA_SET_MEMBERS table (Token 312)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status8_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status8_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status8_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status8_len, 119); // agyis: no-mutant
    let mut status8_payload = vec![0u8; status8_len];
    stream.read_exact(&mut status8_payload).await.unwrap();
    assert_eq!(status8_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([status8_payload[1], status8_payload[2], status8_payload[3], status8_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[5], status8_payload[6]]), 8); // agyis: no-mutant (8 total fields)

    // Group 0x3000 (4 fields)
    assert_eq!(u16::from_le_bytes([status8_payload[7], status8_payload[8]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[9], status8_payload[10]]), 1342); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[11], status8_payload[12]]), 1690); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[13], status8_payload[14]]), 1344); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[15], status8_payload[16]]), 2191); // agyis: no-mutant
    let s8_state = u32::from_le_bytes([status8_payload[17], status8_payload[18], status8_payload[19], status8_payload[20]]); // agyis: no-mutant
    let s8_launch = u32::from_le_bytes([status8_payload[21], status8_payload[22], status8_payload[23], status8_payload[24]]); // agyis: no-mutant
    let s8_player_lobby = u32::from_le_bytes([status8_payload[25], status8_payload[26], status8_payload[27], status8_payload[28]]); // agyis: no-mutant
    let s8_player_queue = u32::from_le_bytes([status8_payload[29], status8_payload[30], status8_payload[31], status8_payload[32]]); // agyis: no-mutant
    assert_eq!(s8_state, 8); // agyis: no-mutant
    assert_eq!(s8_launch, 0); // agyis: no-mutant
    assert_eq!(s8_player_lobby, 5); // agyis: no-mutant
    assert_eq!(s8_player_queue, 4); // agyis: no-mutant

    // Group 0x4000 (2 fields)
    assert_eq!(u16::from_le_bytes([status8_payload[33], status8_payload[34]]), 0x4002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[35], status8_payload[36]]), 700); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[37], status8_payload[38]]), 703); // agyis: no-mutant
    let s8_match_id = u64::from_le_bytes([
        status8_payload[39], status8_payload[40], status8_payload[41], status8_payload[42],
        status8_payload[43], status8_payload[44], status8_payload[45], status8_payload[46],
    ]); // agyis: no-mutant
    let s8_queue_id = u64::from_le_bytes([
        status8_payload[47], status8_payload[48], status8_payload[49], status8_payload[50],
        status8_payload[51], status8_payload[52], status8_payload[53], status8_payload[54],
    ]); // agyis: no-mutant
    assert_eq!(s8_match_id, 878850364); // agyis: no-mutant
    assert_eq!(s8_queue_id, 434); // agyis: no-mutant

    // Group 0x6000 (2 tables: Table 242 QUEUE_STATUS and Table 312 DATA_SET_MEMBERS)
    assert_eq!(u16::from_le_bytes([status8_payload[55], status8_payload[56]]), 0x6002); // agyis: no-mutant

    // Table 242 / QUEUE_STATUS
    assert_eq!(u16::from_le_bytes([status8_payload[57], status8_payload[58]]), immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[57], status8_payload[58]]), 242); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[59], status8_payload[60]]), 1); // agyis: no-mutant (1 row)

    // Table 242 Row 0: 3 fields
    assert_eq!(u16::from_le_bytes([status8_payload[61], status8_payload[62]]), 3); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[63], status8_payload[64]]), 0x1001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[65], status8_payload[66]]), immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[65], status8_payload[66]]), 36); // agyis: no-mutant
    assert_eq!(status8_payload[67], 0x01); // agyis: no-mutant (active = true)

    assert_eq!(u16::from_le_bytes([status8_payload[68], status8_payload[69]]), 0x3002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[70], status8_payload[71]]), 703); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[72], status8_payload[73]]), immortal_net::MCTS_TOKEN_TIMESTAMP); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[72], status8_payload[73]]), 912); // agyis: no-mutant

    let s8_q_queue_id = u32::from_le_bytes([status8_payload[74], status8_payload[75], status8_payload[76], status8_payload[77]]); // agyis: no-mutant
    let s8_q_timestamp = u32::from_le_bytes([status8_payload[78], status8_payload[79], status8_payload[80], status8_payload[81]]); // agyis: no-mutant
    assert_eq!(s8_q_queue_id, 434); // agyis: no-mutant
    assert_eq!(s8_q_timestamp, 0); // agyis: no-mutant

    // Table 312 / DATA_SET_MEMBERS
    assert_eq!(u16::from_le_bytes([status8_payload[82], status8_payload[83]]), immortal_net::MCTS_TOKEN_MEMBERS); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[82], status8_payload[83]]), 312); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[84], status8_payload[85]]), 1); // agyis: no-mutant (1 row)

    // Table 312 Row 0: 5 fields
    assert_eq!(u16::from_le_bytes([status8_payload[86], status8_payload[87]]), 5); // agyis: no-mutant

    // Row Group 0x1000: Token 2143 (bool false = 0)
    assert_eq!(u16::from_le_bytes([status8_payload[88], status8_payload[89]]), 0x1001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[90], status8_payload[91]]), 2143); // agyis: no-mutant
    assert_eq!(status8_payload[92], 0); // agyis: no-mutant

    // Row Group 0x3000: Tokens 11 (PLAYER_ID), 122 (BOT_ID), 855 (PROFILE_ID), 1344 (PLAYER_LOBBY_STATE)
    assert_eq!(u16::from_le_bytes([status8_payload[93], status8_payload[94]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[95], status8_payload[96]]), 11); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[97], status8_payload[98]]), 122); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[99], status8_payload[100]]), 855); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status8_payload[101], status8_payload[102]]), 1344); // agyis: no-mutant
    let s8_player_id = u32::from_le_bytes([status8_payload[103], status8_payload[104], status8_payload[105], status8_payload[106]]); // agyis: no-mutant
    let s8_bot_id = u32::from_le_bytes([status8_payload[107], status8_payload[108], status8_payload[109], status8_payload[110]]); // agyis: no-mutant
    let s8_profile_id = u32::from_le_bytes([status8_payload[111], status8_payload[112], status8_payload[113], status8_payload[114]]); // agyis: no-mutant
    let s8_lobby_state = u32::from_le_bytes([status8_payload[115], status8_payload[116], status8_payload[117], status8_payload[118]]); // agyis: no-mutant
    assert_eq!(s8_player_id, 8302401); // agyis: no-mutant
    assert_eq!(s8_bot_id, BOT_ID_FERNANDO); // agyis: no-mutant
    assert_eq!(s8_bot_id, 2285); // agyis: no-mutant
    assert_eq!(s8_profile_id, 8302401); // agyis: no-mutant
    assert_eq!(s8_lobby_state, 5); // agyis: no-mutant


    // (b) Champion Roster (Function ID 0xdb15d3d7, Table 249, Token 122)
    stream.read_exact(&mut header_buf).await.unwrap();
    let roster_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let roster_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(roster_flags, 0x0000); // agyis: no-mutant
    let mut roster_payload = vec![0u8; roster_len];
    stream.read_exact(&mut roster_payload).await.unwrap();
    assert_eq!(roster_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([roster_payload[1], roster_payload[2], roster_payload[3], roster_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_CHAMPION_ROSTER
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([roster_payload[5], roster_payload[6]]), 1); // agyis: no-mutant (1 table field)
    assert_eq!(u16::from_le_bytes([roster_payload[7], roster_payload[8]]), 0x6001); // agyis: no-mutant (Group 0x6001)
    assert_eq!(u16::from_le_bytes([roster_payload[9], roster_payload[10]]), 249); // agyis: no-mutant (Table 249)
    assert_eq!(u16::from_le_bytes([roster_payload[11], roster_payload[12]]), 4); // agyis: no-mutant (4 champions)
    let expected_champs = [1026, 1024, 1025, 1027];
    for (i, &expected_champ) in expected_champs.iter().enumerate() {
        let offset = 13 + i * 10;
        assert_eq!(u16::from_le_bytes([roster_payload[offset], roster_payload[offset + 1]]), 1); // agyis: no-mutant
        assert_eq!(u16::from_le_bytes([roster_payload[offset + 2], roster_payload[offset + 3]]), 0x3001); // agyis: no-mutant
        assert_eq!(u16::from_le_bytes([roster_payload[offset + 4], roster_payload[offset + 5]]), 122); // agyis: no-mutant
        let champ_id = u32::from_le_bytes([
            roster_payload[offset + 6],
            roster_payload[offset + 7],
            roster_payload[offset + 8],
            roster_payload[offset + 9],
        ]); // agyis: no-mutant
        assert_eq!(champ_id, expected_champ); // agyis: no-mutant
    }

    // (c) MATCH_STATUS state 10 with QUEUE_STATUS table (Token 242) and DATA_SET_MEMBERS table (Token 312)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status10_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status10_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status10_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status10_len, 119); // agyis: no-mutant
    let mut status10_payload = vec![0u8; status10_len];
    stream.read_exact(&mut status10_payload).await.unwrap();
    assert_eq!(status10_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([status10_payload[1], status10_payload[2], status10_payload[3], status10_payload[4]]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[5], status10_payload[6]]), 8); // agyis: no-mutant (8 total fields)

    // Group 0x3000 (4 fields)
    assert_eq!(u16::from_le_bytes([status10_payload[7], status10_payload[8]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[9], status10_payload[10]]), 1342); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[11], status10_payload[12]]), 1690); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[13], status10_payload[14]]), 1344); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[15], status10_payload[16]]), 2191); // agyis: no-mutant
    let s10_state = u32::from_le_bytes([status10_payload[17], status10_payload[18], status10_payload[19], status10_payload[20]]); // agyis: no-mutant
    let s10_launch = u32::from_le_bytes([status10_payload[21], status10_payload[22], status10_payload[23], status10_payload[24]]); // agyis: no-mutant
    let s10_player_lobby = u32::from_le_bytes([status10_payload[25], status10_payload[26], status10_payload[27], status10_payload[28]]); // agyis: no-mutant
    let s10_player_queue = u32::from_le_bytes([status10_payload[29], status10_payload[30], status10_payload[31], status10_payload[32]]); // agyis: no-mutant
    assert_eq!(s10_state, 10); // agyis: no-mutant
    assert_eq!(s10_launch, 0); // agyis: no-mutant
    assert_eq!(s10_player_lobby, 5); // agyis: no-mutant
    assert_eq!(s10_player_queue, 7); // agyis: no-mutant

    // Group 0x4000 (2 fields)
    assert_eq!(u16::from_le_bytes([status10_payload[33], status10_payload[34]]), 0x4002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[35], status10_payload[36]]), 700); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[37], status10_payload[38]]), 703); // agyis: no-mutant
    let s10_match_id = u64::from_le_bytes([
        status10_payload[39], status10_payload[40], status10_payload[41], status10_payload[42],
        status10_payload[43], status10_payload[44], status10_payload[45], status10_payload[46],
    ]); // agyis: no-mutant
    let s10_queue_id = u64::from_le_bytes([
        status10_payload[47], status10_payload[48], status10_payload[49], status10_payload[50],
        status10_payload[51], status10_payload[52], status10_payload[53], status10_payload[54],
    ]); // agyis: no-mutant
    assert_eq!(s10_match_id, 878850364); // agyis: no-mutant
    assert_eq!(s10_queue_id, 434); // agyis: no-mutant

    // Group 0x6000 (2 tables: Table 242 QUEUE_STATUS and Table 312 DATA_SET_MEMBERS)
    assert_eq!(u16::from_le_bytes([status10_payload[55], status10_payload[56]]), 0x6002); // agyis: no-mutant

    // Table 242 / QUEUE_STATUS
    assert_eq!(u16::from_le_bytes([status10_payload[57], status10_payload[58]]), immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[57], status10_payload[58]]), 242); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[59], status10_payload[60]]), 1); // agyis: no-mutant (1 row)

    // Table 242 Row 0: 3 fields
    assert_eq!(u16::from_le_bytes([status10_payload[61], status10_payload[62]]), 3); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[63], status10_payload[64]]), 0x1001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[65], status10_payload[66]]), immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[65], status10_payload[66]]), 36); // agyis: no-mutant
    assert_eq!(status10_payload[67], 0x01); // agyis: no-mutant (active = true)

    assert_eq!(u16::from_le_bytes([status10_payload[68], status10_payload[69]]), 0x3002); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[70], status10_payload[71]]), 703); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[72], status10_payload[73]]), immortal_net::MCTS_TOKEN_TIMESTAMP); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[72], status10_payload[73]]), 912); // agyis: no-mutant

    let s10_q_queue_id = u32::from_le_bytes([status10_payload[74], status10_payload[75], status10_payload[76], status10_payload[77]]); // agyis: no-mutant
    let s10_q_timestamp = u32::from_le_bytes([status10_payload[78], status10_payload[79], status10_payload[80], status10_payload[81]]); // agyis: no-mutant
    assert_eq!(s10_q_queue_id, 434); // agyis: no-mutant
    assert_eq!(s10_q_timestamp, 0); // agyis: no-mutant

    // Table 312 / DATA_SET_MEMBERS
    assert_eq!(u16::from_le_bytes([status10_payload[82], status10_payload[83]]), immortal_net::MCTS_TOKEN_MEMBERS); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[82], status10_payload[83]]), 312); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[84], status10_payload[85]]), 1); // agyis: no-mutant (1 row)

    // Table 312 Row 0: 5 fields
    assert_eq!(u16::from_le_bytes([status10_payload[86], status10_payload[87]]), 5); // agyis: no-mutant

    // Row Group 0x1000: Token 2143 (bool false = 0)
    assert_eq!(u16::from_le_bytes([status10_payload[88], status10_payload[89]]), 0x1001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[90], status10_payload[91]]), 2143); // agyis: no-mutant
    assert_eq!(status10_payload[92], 0); // agyis: no-mutant

    // Row Group 0x3000: Tokens 11 (PLAYER_ID), 122 (BOT_ID), 855 (PROFILE_ID), 1344 (PLAYER_LOBBY_STATE)
    assert_eq!(u16::from_le_bytes([status10_payload[93], status10_payload[94]]), 0x3004); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[95], status10_payload[96]]), 11); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[97], status10_payload[98]]), 122); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[99], status10_payload[100]]), 855); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([status10_payload[101], status10_payload[102]]), 1344); // agyis: no-mutant
    let s10_player_id = u32::from_le_bytes([status10_payload[103], status10_payload[104], status10_payload[105], status10_payload[106]]); // agyis: no-mutant
    let s10_bot_id = u32::from_le_bytes([status10_payload[107], status10_payload[108], status10_payload[109], status10_payload[110]]); // agyis: no-mutant
    let s10_profile_id = u32::from_le_bytes([status10_payload[111], status10_payload[112], status10_payload[113], status10_payload[114]]); // agyis: no-mutant
    let s10_lobby_state = u32::from_le_bytes([status10_payload[115], status10_payload[116], status10_payload[117], status10_payload[118]]); // agyis: no-mutant
    assert_eq!(s10_player_id, 8302401); // agyis: no-mutant
    assert_eq!(s10_bot_id, BOT_ID_FERNANDO); // agyis: no-mutant
    assert_eq!(s10_bot_id, 2285); // agyis: no-mutant
    assert_eq!(s10_profile_id, 8302401); // agyis: no-mutant
    assert_eq!(s10_lobby_state, 5); // agyis: no-mutant


    // (e) MAP_TRANSITION (mapGameId=1615, instanceId=1282927737, is_standalone=false)
    stream.read_exact(&mut header_buf).await.unwrap();
    let map_trans_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let map_trans_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(map_trans_flags, 0x0000); // agyis: no-mutant
    let mut map_trans_payload = vec![0u8; map_trans_len];
    stream.read_exact(&mut map_trans_payload).await.unwrap();
    assert_eq!(map_trans_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(&map_trans_payload[1..5], &[0x4e, 0x82, 0x21, 0xe6]); // agyis: no-mutant
    let map_trans_func_id = u32::from_le_bytes([
        map_trans_payload[1], map_trans_payload[2], map_trans_payload[3], map_trans_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(map_trans_func_id, immortal_net::MCTS_FUNCTION_ID_MAP_TRANSITION); // agyis: no-mutant
    assert_eq!(map_trans_func_id, 0xe621824e); // agyis: no-mutant
    let total_fields = u16::from_le_bytes([map_trans_payload[5], map_trans_payload[6]]); // agyis: no-mutant
    assert_eq!(total_fields, 3); // agyis: no-mutant

    // Group 0x1000: Token 1116 (is_standalone = false)
    let grp1 = u16::from_le_bytes([map_trans_payload[7], map_trans_payload[8]]); // agyis: no-mutant
    assert_eq!(grp1, 0x1001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([map_trans_payload[9], map_trans_payload[10]]), 1116); // agyis: no-mutant
    assert_eq!(map_trans_payload[11], 0); // Token 1116 = 0x00 (is_standalone = false) // agyis: no-mutant

    // Group 0x3000: Token 682 (mapGameId = 1615)
    let grp4 = u16::from_le_bytes([map_trans_payload[12], map_trans_payload[13]]); // agyis: no-mutant
    assert_eq!(grp4, 0x3001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([map_trans_payload[14], map_trans_payload[15]]), 682); // Token 682 // agyis: no-mutant
    let map_game_id = u32::from_le_bytes([
        map_trans_payload[16], map_trans_payload[17], map_trans_payload[18], map_trans_payload[19],
    ]); // agyis: no-mutant
    assert_eq!(map_game_id, immortal_net::MAP_GAME_ID_SHOOTING_RANGE); // agyis: no-mutant

    // Group 0x4000: Token 685 (mapInstanceId = 1282927737)
    let grp8 = u16::from_le_bytes([map_trans_payload[20], map_trans_payload[21]]); // agyis: no-mutant
    assert_eq!(grp8, 0x4001); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([map_trans_payload[22], map_trans_payload[23]]), 685); // Token 685 // agyis: no-mutant
    let map_instance_id = u64::from_le_bytes([
        map_trans_payload[24], map_trans_payload[25], map_trans_payload[26], map_trans_payload[27],
        map_trans_payload[28], map_trans_payload[29], map_trans_payload[30], map_trans_payload[31],
    ]); // agyis: no-mutant
    assert_eq!(map_instance_id, immortal_net::MAP_INSTANCE_ID_SHOOTING_RANGE as u64); // agyis: no-mutant

    // 5. Step 5: Subsequent post-login frame responds with MCTS_CHAMPION_SELECT_ACK_FRAME
    stream.write_all(&champ_frame).await.unwrap();
    stream.flush().await.unwrap();

    let mut ack_buf = [0u8; 19];
    stream.read_exact(&mut ack_buf).await.unwrap();
    assert_eq!(&ack_buf[..], &immortal_net::MCTS_CHAMPION_SELECT_ACK_FRAME[..]);

    // 6. Step 6: Verify arbitrary post-login frame length does not drop connection with InvalidMagic
    // and telemetry frame does not emit spurious ACK.
    let mut arb_frame = Vec::new();
    arb_frame.extend_from_slice(&25u16.to_le_bytes()); // Length 25 (not in legacy [37, 19, 33, 15])
    arb_frame.extend_from_slice(&0x0000u16.to_le_bytes()); // Flags 0x0000 (not 0x0108)
    arb_frame.extend_from_slice(&vec![0x77u8; 25]);
    stream.write_all(&arb_frame).await.unwrap();
    stream.flush().await.unwrap();

    // Verify connection remains active and subsequent champion select frame responds with ACK
    stream.write_all(&champ_frame).await.unwrap();
    stream.flush().await.unwrap();

    let mut ack_buf2 = [0u8; 19];
    stream.read_exact(&mut ack_buf2).await.unwrap();
    assert_eq!(&ack_buf2[..], &immortal_net::MCTS_CHAMPION_SELECT_ACK_FRAME[..]);

    // 7. Step 7: Verify payload_len == 19 and payload_len == 37 (vendor query) do NOT trigger bogus MCTS_CHAMPION_SELECT_ACK_FRAME without fernando
    let mut frame_19 = Vec::new();
    frame_19.extend_from_slice(&19u16.to_le_bytes());
    frame_19.extend_from_slice(&0x0000u16.to_le_bytes());
    frame_19.extend_from_slice(&vec![0x11u8; 19]);
    stream.write_all(&frame_19).await.unwrap();
    stream.flush().await.unwrap();

    let mut frame_37 = Vec::new();
    frame_37.extend_from_slice(&37u16.to_le_bytes());
    frame_37.extend_from_slice(&0x0000u16.to_le_bytes());
    frame_37.extend_from_slice(&vec![0x22u8; 37]);
    stream.write_all(&frame_37).await.unwrap();
    stream.flush().await.unwrap();

    // Verify neither frame triggered a bogus ACK by asserting no bytes are pending on stream
    let mut probe_buf = [0u8; 1];
    let probe_res = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut probe_buf),
    )
    .await;
    assert!(
        probe_res.is_err(),
        "Server must not respond to 19-byte or 37-byte vendor query frames with bogus ACK"
    );

    // Verify subsequent champion select frame with Fernando DOES trigger ACK
    stream.write_all(&champ_frame).await.unwrap();
    stream.flush().await.unwrap();

    let mut ack_buf3 = [0u8; 19];
    stream.read_exact(&mut ack_buf3).await.unwrap();
    assert_eq!(&ack_buf3[..], &immortal_net::MCTS_CHAMPION_SELECT_ACK_FRAME[..]);

    handle.shutdown().await.unwrap();

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 800,
        "Live MCTS Auth Gateway exchange test must finish in < 800ms, took {:?}",
        elapsed
    );
}
