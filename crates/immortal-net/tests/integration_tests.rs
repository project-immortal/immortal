// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Governed by: Cleanroom Preservation Standard & ICARO-42/b Ordinance
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Immortal Net Integration Tests
//! End-to-end integration tests for MCTS TCP Auth Gateway and CPackCoder wire framing.

use immortal_net::{
    AuthGateway, AuthGatewayConfig, CPackFrame, LoginRequest, LoginResponse, MagicToken,
    BOT_ID_FERNANDO, BOT_ID_VIKTOR, CHAMPION_CASSIE, CHAMPION_FERNANDO, CHAMPION_VIKTOR,
    CHUNK2_ACK, CHUNK3_SESSION, DECK_FERNANDO_STARTER, DEVICE_FERNANDO_FLAME_LANCE, HEADER_LEN,
    MCTS_TOKEN_POSITION,
};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_auth_gateway_login_uncompressed() {
    let start = Instant::now();

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = AuthGatewayConfig {
        bind_addr,
        account_id: 8302401,
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
        account_id: 8302401,
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
        account_id: 8302401,
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
    assert_eq!(
        &hello_resp_buf[..],
        &immortal_net::MCTS_HELLO_RESPONSE_PAYLOAD[..]
    );

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
    assert_eq!(
        u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]),
        0
    ); // Token 3 = 0
    assert_eq!(
        u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]),
        60
    ); // Token 739 = 60

    // Group 0x4000: Field 11 (MCTS_TOKEN_PLAYER_ID) and Field 26 (ACCOUNT_ID)
    let grp8 = u16::from_le_bytes([payload[26], payload[27]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(u16::from_le_bytes([payload[28], payload[29]]), 11);
    assert_eq!(u16::from_le_bytes([payload[30], payload[31]]), 26);
    let v11 = u64::from_le_bytes([
        payload[32],
        payload[33],
        payload[34],
        payload[35],
        payload[36],
        payload[37],
        payload[38],
        payload[39],
    ]);
    let v26 = u64::from_le_bytes([
        payload[40],
        payload[41],
        payload[42],
        payload[43],
        payload[44],
        payload[45],
        payload[46],
        payload[47],
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

    // Expect authentic Live MCTS Queue Definition wire frame (Function ID 0xaf434825, Table 1619 + Table 242)
    stream.read_exact(&mut header_buf).await.unwrap();
    let qdef_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let qdef_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(qdef_flags, 0x0000); // agyis: no-mutant
    assert_eq!(qdef_len, 63); // agyis: no-mutant

    let mut qdef_payload = vec![0u8; qdef_len];
    stream.read_exact(&mut qdef_payload).await.unwrap();
    assert_eq!(qdef_payload[0], 0x00); // agyis: no-mutant
    let qdef_func_id = u32::from_le_bytes([
        qdef_payload[1],
        qdef_payload[2],
        qdef_payload[3],
        qdef_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(qdef_func_id, immortal_net::MCTS_FUNCTION_ID_QUERY_SERVERS); // agyis: no-mutant
    assert_eq!(qdef_func_id, 0xaf434825); // agyis: no-mutant

    // Total fields: 3
    let qdef_fields = u16::from_le_bytes([qdef_payload[5], qdef_payload[6]]); // agyis: no-mutant
    assert_eq!(qdef_fields, 3); // agyis: no-mutant

    // Group 0x3001: Token 550 (QUEUE_CATEGORY = 1)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[7], qdef_payload[8]]),
        0x3001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[9], qdef_payload[10]]),
        immortal_net::MCTS_TOKEN_QUEUE_CATEGORY
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            qdef_payload[11],
            qdef_payload[12],
            qdef_payload[13],
            qdef_payload[14]
        ]),
        1
    ); // agyis: no-mutant

    // Group 0x6002: Table Header (2 tables: Table 1619 + Table 242)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[15], qdef_payload[16]]),
        0x6002
    ); // agyis: no-mutant

    // Table 1: Token 1619 (INVITED_MEMBERS)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[17], qdef_payload[18]]),
        immortal_net::MCTS_TOKEN_INVITED_MEMBERS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[17], qdef_payload[18]]),
        1619
    ); // agyis: no-mutant

    // Row count 1, field count 1
    assert_eq!(u16::from_le_bytes([qdef_payload[19], qdef_payload[20]]), 1); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([qdef_payload[21], qdef_payload[22]]), 1); // agyis: no-mutant

    // Row Group 0x3001: Token 682 (MAP_GAME_ID = 1615)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[23], qdef_payload[24]]),
        0x3001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[25], qdef_payload[26]]),
        immortal_net::MCTS_TOKEN_MAP_GAME_ID
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            qdef_payload[27],
            qdef_payload[28],
            qdef_payload[29],
            qdef_payload[30]
        ]),
        1615
    ); // agyis: no-mutant

    // Table 2: Token 242 (QUEUE_STATUS)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[31], qdef_payload[32]]),
        immortal_net::MCTS_TOKEN_QUEUE_STATUS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[31], qdef_payload[32]]),
        242
    ); // agyis: no-mutant

    // Row count 1, field count 3
    assert_eq!(u16::from_le_bytes([qdef_payload[33], qdef_payload[34]]), 1); // agyis: no-mutant
    assert_eq!(u16::from_le_bytes([qdef_payload[35], qdef_payload[36]]), 3); // agyis: no-mutant

    // Row Group 0x3002: Token 36 (1), Token 1646 (0)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[37], qdef_payload[38]]),
        0x3002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[39], qdef_payload[40]]),
        immortal_net::MCTS_TOKEN_QUEUE_ACTIVE
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[41], qdef_payload[42]]),
        immortal_net::MCTS_TOKEN_QUEUE_STATE
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            qdef_payload[43],
            qdef_payload[44],
            qdef_payload[45],
            qdef_payload[46]
        ]),
        1
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            qdef_payload[47],
            qdef_payload[48],
            qdef_payload[49],
            qdef_payload[50]
        ]),
        0
    ); // agyis: no-mutant

    // Row Group 0x4001: Token 703 (434)
    assert_eq!(
        u16::from_le_bytes([qdef_payload[51], qdef_payload[52]]),
        0x4001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([qdef_payload[53], qdef_payload[54]]),
        immortal_net::MCTS_TOKEN_MATCH_QUEUE_ID
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            qdef_payload[55],
            qdef_payload[56],
            qdef_payload[57],
            qdef_payload[58],
            qdef_payload[59],
            qdef_payload[60],
            qdef_payload[61],
            qdef_payload[62]
        ]),
        434
    ); // agyis: no-mutant

    // 3. Step 3: Expect authentic Live MCTS MATCH_STATUS wire frame (0x392dcda5, queue_id 0, match_id 0, match_lobby_state 0, launch_seconds 0, player_lobby_state 0, player_queue_state 0)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status_frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status_wire_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status_wire_flags, 0x0000);
    assert_eq!(status_frame_len, 55);

    let mut status_payload = vec![0u8; status_frame_len];
    stream.read_exact(&mut status_payload).await.unwrap();
    assert_eq!(status_payload[0], 0x00);
    let status_func_id = u32::from_le_bytes([
        status_payload[1],
        status_payload[2],
        status_payload[3],
        status_payload[4],
    ]);
    assert_eq!(status_func_id, immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS);
    assert_eq!(status_func_id, 0x392dcda5);
    let field_count = u16::from_le_bytes([status_payload[5], status_payload[6]]);
    assert_eq!(field_count, 6);

    // Group 0x3000: Token 1342 (match_lobby_state = 0), Token 1690 (launch_seconds = 0), Token 1344 (player_lobby_state = 0), Token 2191 (player_queue_state = 0)
    let grp4 = u16::from_le_bytes([status_payload[7], status_payload[8]]);
    assert_eq!(grp4, 0x3004);
    assert_eq!(
        u16::from_le_bytes([status_payload[9], status_payload[10]]),
        1342
    );
    assert_eq!(
        u16::from_le_bytes([status_payload[11], status_payload[12]]),
        1690
    );
    assert_eq!(
        u16::from_le_bytes([status_payload[13], status_payload[14]]),
        1344
    );
    assert_eq!(
        u16::from_le_bytes([status_payload[15], status_payload[16]]),
        2191
    );
    let v1342 = u32::from_le_bytes([
        status_payload[17],
        status_payload[18],
        status_payload[19],
        status_payload[20],
    ]);
    let v1690 = u32::from_le_bytes([
        status_payload[21],
        status_payload[22],
        status_payload[23],
        status_payload[24],
    ]);
    let v1344 = u32::from_le_bytes([
        status_payload[25],
        status_payload[26],
        status_payload[27],
        status_payload[28],
    ]);
    let v2191 = u32::from_le_bytes([
        status_payload[29],
        status_payload[30],
        status_payload[31],
        status_payload[32],
    ]);
    assert_eq!(v1342, 0); // match_lobby_state = 0
    assert_eq!(v1690, 0); // launch_seconds = 0
    assert_eq!(v1344, 0); // player_lobby_state = 0
    assert_eq!(v2191, 0); // player_queue_state = 0

    // Group 0x4000: Token 700 (match_id = 0), Token 703 (queue_id = 0)
    let grp8 = u16::from_le_bytes([status_payload[33], status_payload[34]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(
        u16::from_le_bytes([status_payload[35], status_payload[36]]),
        700
    );
    assert_eq!(
        u16::from_le_bytes([status_payload[37], status_payload[38]]),
        703
    );
    let v700 = u64::from_le_bytes([
        status_payload[39],
        status_payload[40],
        status_payload[41],
        status_payload[42],
        status_payload[43],
        status_payload[44],
        status_payload[45],
        status_payload[46],
    ]);
    let v703 = u64::from_le_bytes([
        status_payload[47],
        status_payload[48],
        status_payload[49],
        status_payload[50],
        status_payload[51],
        status_payload[52],
        status_payload[53],
        status_payload[54],
    ]);
    assert_eq!(v700, 0); // match_id = 0
    assert_eq!(v703, 0); // queue_id = 0
    assert_eq!(status_payload.len(), 55);

    // Step 3b: Expect authentic Live MCTS CHAMPION_ROSTER wire frame (Table 249, 9 champions: [1026, 1024, 1025, 1027, BOT_ID_FERNANDO, BOT_ID_VIKTOR, 2205, 2404, 2512])
    stream.read_exact(&mut header_buf).await.unwrap();
    let roster_frame_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let roster_wire_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(roster_wire_flags, 0x0000);

    let mut roster_payload = vec![0u8; roster_frame_len];
    stream.read_exact(&mut roster_payload).await.unwrap();
    assert_eq!(roster_payload[0], 0x00);
    let roster_func_id = u32::from_le_bytes([
        roster_payload[1],
        roster_payload[2],
        roster_payload[3],
        roster_payload[4],
    ]);
    assert_eq!(
        roster_func_id,
        immortal_net::MCTS_FUNCTION_ID_CHAMPION_ROSTER
    );
    assert_eq!(roster_func_id, 0xdb15d3d7);
    assert_eq!(
        u16::from_le_bytes([roster_payload[5], roster_payload[6]]),
        1
    ); // 1 table field
    assert_eq!(
        u16::from_le_bytes([roster_payload[7], roster_payload[8]]),
        0x6001
    ); // Group 0x6000 | 1
    assert_eq!(
        u16::from_le_bytes([roster_payload[9], roster_payload[10]]),
        249
    ); // Table 249
    assert_eq!(
        u16::from_le_bytes([roster_payload[11], roster_payload[12]]),
        9
    ); // 9 rows

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
    // (a0-queue-definition) Proactive Queue Definition (Function ID 0xaf434825, Table 1619 + Table 242)
    stream.read_exact(&mut header_buf).await.unwrap();
    let qdef_start_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let qdef_start_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(qdef_start_flags, 0x0000); // agyis: no-mutant
    assert_eq!(qdef_start_len, 63); // agyis: no-mutant
    let mut qdef_start_payload = vec![0u8; qdef_start_len];
    stream.read_exact(&mut qdef_start_payload).await.unwrap();
    assert_eq!(qdef_start_payload[0], 0x00); // agyis: no-mutant
    let qdef_start_func_id = u32::from_le_bytes([
        qdef_start_payload[1],
        qdef_start_payload[2],
        qdef_start_payload[3],
        qdef_start_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        qdef_start_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUERY_SERVERS
    ); // agyis: no-mutant
    assert_eq!(qdef_start_func_id, 0xaf434825); // agyis: no-mutant

    // (a0-queue-status) QUEUE_STATUS (Function ID 0x2cdbafe1, Table 242, queue 434, state 2)
    stream.read_exact(&mut header_buf).await.unwrap();
    let q_status_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let q_status_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(q_status_flags, 0x0000); // agyis: no-mutant
    assert_eq!(q_status_len, 41); // agyis: no-mutant
    let mut q_status_payload = vec![0u8; q_status_len];
    stream.read_exact(&mut q_status_payload).await.unwrap();
    assert_eq!(q_status_payload[0], 0x00); // agyis: no-mutant
    let q_status_func_id = u32::from_le_bytes([
        q_status_payload[1],
        q_status_payload[2],
        q_status_payload[3],
        q_status_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        q_status_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUEUE_STATUS
    ); // agyis: no-mutant
    assert_eq!(q_status_func_id, 0x2cdbafe1); // agyis: no-mutant
    let q_fields = u16::from_le_bytes([q_status_payload[5], q_status_payload[6]]); // agyis: no-mutant
    assert_eq!(q_fields, 1); // agyis: no-mutant
    let q_tbl_grp = u16::from_le_bytes([q_status_payload[7], q_status_payload[8]]); // agyis: no-mutant
    assert_eq!(q_tbl_grp, 0x6001); // agyis: no-mutant
    let q_tbl_tok = u16::from_le_bytes([q_status_payload[9], q_status_payload[10]]); // agyis: no-mutant
    assert_eq!(q_tbl_tok, immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(q_tbl_tok, 242); // agyis: no-mutant
    let q_row_cnt = u16::from_le_bytes([q_status_payload[11], q_status_payload[12]]); // agyis: no-mutant
    assert_eq!(q_row_cnt, 1); // agyis: no-mutant
    let q_row_fields = u16::from_le_bytes([q_status_payload[13], q_status_payload[14]]); // agyis: no-mutant
    assert_eq!(q_row_fields, 3); // agyis: no-mutant
    let q_grp4 = u16::from_le_bytes([q_status_payload[15], q_status_payload[16]]); // agyis: no-mutant
    assert_eq!(q_grp4, 0x3002); // agyis: no-mutant
    let q_tok36 = u16::from_le_bytes([q_status_payload[17], q_status_payload[18]]); // agyis: no-mutant
    assert_eq!(q_tok36, immortal_net::MCTS_TOKEN_QUEUE_ACTIVE); // agyis: no-mutant
    assert_eq!(q_tok36, 36); // agyis: no-mutant
    let q_tok1646 = u16::from_le_bytes([q_status_payload[19], q_status_payload[20]]); // agyis: no-mutant
    assert_eq!(q_tok1646, immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(q_tok1646, 1646); // agyis: no-mutant
    let q_v36 = u32::from_le_bytes([
        q_status_payload[21],
        q_status_payload[22],
        q_status_payload[23],
        q_status_payload[24],
    ]); // agyis: no-mutant
    assert_eq!(q_v36, 1); // agyis: no-mutant
    let q_v1646 = u32::from_le_bytes([
        q_status_payload[25],
        q_status_payload[26],
        q_status_payload[27],
        q_status_payload[28],
    ]); // agyis: no-mutant
    assert_eq!(q_v1646, 2); // agyis: no-mutant
    let q_grp8 = u16::from_le_bytes([q_status_payload[29], q_status_payload[30]]); // agyis: no-mutant
    assert_eq!(q_grp8, 0x4001); // agyis: no-mutant
    let q_tok703 = u16::from_le_bytes([q_status_payload[31], q_status_payload[32]]); // agyis: no-mutant
    assert_eq!(q_tok703, immortal_net::MCTS_TOKEN_MATCH_QUEUE_ID); // agyis: no-mutant
    assert_eq!(q_tok703, 703); // agyis: no-mutant
    let q_v703 = u64::from_le_bytes([
        q_status_payload[33],
        q_status_payload[34],
        q_status_payload[35],
        q_status_payload[36],
        q_status_payload[37],
        q_status_payload[38],
        q_status_payload[39],
        q_status_payload[40],
    ]); // agyis: no-mutant
    assert_eq!(q_v703, 434); // agyis: no-mutant

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
        u32::from_le_bytes([
            status_queued_payload[1],
            status_queued_payload[2],
            status_queued_payload[3],
            status_queued_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[5], status_queued_payload[6]]),
        6
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[7], status_queued_payload[8]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[9], status_queued_payload[10]]),
        1342
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[11], status_queued_payload[12]]),
        1690
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[13], status_queued_payload[14]]),
        1344
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[15], status_queued_payload[16]]),
        2191
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_queued_payload[17],
            status_queued_payload[18],
            status_queued_payload[19],
            status_queued_payload[20]
        ]),
        0
    ); // match_lobby_state = 0 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_queued_payload[21],
            status_queued_payload[22],
            status_queued_payload[23],
            status_queued_payload[24]
        ]),
        0
    ); // launch_seconds = 0 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_queued_payload[25],
            status_queued_payload[26],
            status_queued_payload[27],
            status_queued_payload[28]
        ]),
        0
    ); // player_lobby_state = 0 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_queued_payload[29],
            status_queued_payload[30],
            status_queued_payload[31],
            status_queued_payload[32]
        ]),
        2
    ); // player_queue_state = 2 (MQ_QUEUED) // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[33], status_queued_payload[34]]),
        0x4002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[35], status_queued_payload[36]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_queued_payload[37], status_queued_payload[38]]),
        703
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_queued_payload[39],
            status_queued_payload[40],
            status_queued_payload[41],
            status_queued_payload[42],
            status_queued_payload[43],
            status_queued_payload[44],
            status_queued_payload[45],
            status_queued_payload[46],
        ]),
        0
    ); // match_id = 0 // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_queued_payload[47],
            status_queued_payload[48],
            status_queued_payload[49],
            status_queued_payload[50],
            status_queued_payload[51],
            status_queued_payload[52],
            status_queued_payload[53],
            status_queued_payload[54],
        ]),
        434
    ); // queue_id = 434 // agyis: no-mutant
    assert_eq!(status_queued_payload.len(), 55); // agyis: no-mutant

    // (a0-queue-status-invited) QUEUE_STATUS (Function ID 0x2cdbafe1, Table 242, queue 434, state 3 MQ_INVITED)
    stream.read_exact(&mut header_buf).await.unwrap();
    let q_status3_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let q_status3_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(q_status3_flags, 0x0000); // agyis: no-mutant
    assert_eq!(q_status3_len, 41); // agyis: no-mutant
    let mut q_status3_payload = vec![0u8; q_status3_len];
    stream.read_exact(&mut q_status3_payload).await.unwrap();
    assert_eq!(q_status3_payload[0], 0x00); // agyis: no-mutant
    let q_status3_func_id = u32::from_le_bytes([
        q_status3_payload[1],
        q_status3_payload[2],
        q_status3_payload[3],
        q_status3_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        q_status3_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUEUE_STATUS
    ); // agyis: no-mutant
    assert_eq!(q_status3_func_id, 0x2cdbafe1); // agyis: no-mutant
    let q3_fields = u16::from_le_bytes([q_status3_payload[5], q_status3_payload[6]]); // agyis: no-mutant
    assert_eq!(q3_fields, 1); // agyis: no-mutant
    let q3_tbl_grp = u16::from_le_bytes([q_status3_payload[7], q_status3_payload[8]]); // agyis: no-mutant
    assert_eq!(q3_tbl_grp, 0x6001); // agyis: no-mutant
    let q3_tbl_tok = u16::from_le_bytes([q_status3_payload[9], q_status3_payload[10]]); // agyis: no-mutant
    assert_eq!(q3_tbl_tok, immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(q3_tbl_tok, 242); // agyis: no-mutant
    let q3_row_cnt = u16::from_le_bytes([q_status3_payload[11], q_status3_payload[12]]); // agyis: no-mutant
    assert_eq!(q3_row_cnt, 1); // agyis: no-mutant
    let q3_row_fields = u16::from_le_bytes([q_status3_payload[13], q_status3_payload[14]]); // agyis: no-mutant
    assert_eq!(q3_row_fields, 3); // agyis: no-mutant
    let q3_grp4 = u16::from_le_bytes([q_status3_payload[15], q_status3_payload[16]]); // agyis: no-mutant
    assert_eq!(q3_grp4, 0x3002); // agyis: no-mutant
    let q3_tok36 = u16::from_le_bytes([q_status3_payload[17], q_status3_payload[18]]); // agyis: no-mutant
    assert_eq!(q3_tok36, immortal_net::MCTS_TOKEN_QUEUE_ACTIVE); // agyis: no-mutant
    assert_eq!(q3_tok36, 36); // agyis: no-mutant
    let q3_tok1646 = u16::from_le_bytes([q_status3_payload[19], q_status3_payload[20]]); // agyis: no-mutant
    assert_eq!(q3_tok1646, immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(q3_tok1646, 1646); // agyis: no-mutant
    let q3_v36 = u32::from_le_bytes([
        q_status3_payload[21],
        q_status3_payload[22],
        q_status3_payload[23],
        q_status3_payload[24],
    ]); // agyis: no-mutant
    assert_eq!(q3_v36, 1); // agyis: no-mutant
    let q3_v1646 = u32::from_le_bytes([
        q_status3_payload[25],
        q_status3_payload[26],
        q_status3_payload[27],
        q_status3_payload[28],
    ]); // agyis: no-mutant
    assert_eq!(q3_v1646, 3); // agyis: no-mutant
    let q3_grp8 = u16::from_le_bytes([q_status3_payload[29], q_status3_payload[30]]); // agyis: no-mutant
    assert_eq!(q3_grp8, 0x4001); // agyis: no-mutant
    let q3_tok703 = u16::from_le_bytes([q_status3_payload[31], q_status3_payload[32]]); // agyis: no-mutant
    assert_eq!(q3_tok703, immortal_net::MCTS_TOKEN_MATCH_QUEUE_ID); // agyis: no-mutant
    assert_eq!(q3_tok703, 703); // agyis: no-mutant
    let q3_v703 = u64::from_le_bytes([
        q_status3_payload[33],
        q_status3_payload[34],
        q_status3_payload[35],
        q_status3_payload[36],
        q_status3_payload[37],
        q_status3_payload[38],
        q_status3_payload[39],
        q_status3_payload[40],
    ]); // agyis: no-mutant
    assert_eq!(q3_v703, 434); // agyis: no-mutant

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
        u32::from_le_bytes([
            status_inv_payload[1],
            status_inv_payload[2],
            status_inv_payload[3],
            status_inv_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[5], status_inv_payload[6]]),
        6
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[7], status_inv_payload[8]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[9], status_inv_payload[10]]),
        1342
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[11], status_inv_payload[12]]),
        1690
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[13], status_inv_payload[14]]),
        1344
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[15], status_inv_payload[16]]),
        2191
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_inv_payload[17],
            status_inv_payload[18],
            status_inv_payload[19],
            status_inv_payload[20]
        ]),
        0
    ); // match_lobby_state = 0 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_inv_payload[21],
            status_inv_payload[22],
            status_inv_payload[23],
            status_inv_payload[24]
        ]),
        30
    ); // launch_seconds = 30 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_inv_payload[25],
            status_inv_payload[26],
            status_inv_payload[27],
            status_inv_payload[28]
        ]),
        0
    ); // player_lobby_state = 0 // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status_inv_payload[29],
            status_inv_payload[30],
            status_inv_payload[31],
            status_inv_payload[32]
        ]),
        3
    ); // player_queue_state = 3 (MQ_INVITED) // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[33], status_inv_payload[34]]),
        0x4002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[35], status_inv_payload[36]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status_inv_payload[37], status_inv_payload[38]]),
        703
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_inv_payload[39],
            status_inv_payload[40],
            status_inv_payload[41],
            status_inv_payload[42],
            status_inv_payload[43],
            status_inv_payload[44],
            status_inv_payload[45],
            status_inv_payload[46],
        ]),
        878850364
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            status_inv_payload[47],
            status_inv_payload[48],
            status_inv_payload[49],
            status_inv_payload[50],
            status_inv_payload[51],
            status_inv_payload[52],
            status_inv_payload[53],
            status_inv_payload[54],
        ]),
        0
    ); // agyis: no-mutant
    assert_eq!(status_inv_payload.len(), 55); // agyis: no-mutant

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
        u32::from_le_bytes([
            invite_frame_payload[1],
            invite_frame_payload[2],
            invite_frame_payload[3],
            invite_frame_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_INVITATION
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[5], invite_frame_payload[6]]),
        5
    ); // agyis: no-mutant

    // Group 0x3000: Token 1342 (state = 0), Token 1690 (timeout = 30)
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[7], invite_frame_payload[8]]),
        0x3002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[9], invite_frame_payload[10]]),
        1342
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[11], invite_frame_payload[12]]),
        1690
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[13],
            invite_frame_payload[14],
            invite_frame_payload[15],
            invite_frame_payload[16]
        ]),
        0
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[17],
            invite_frame_payload[18],
            invite_frame_payload[19],
            invite_frame_payload[20]
        ]),
        30
    ); // agyis: no-mutant

    // Group 0x4000: Token 700 (match_id), Token 703 (queue_id)
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[21], invite_frame_payload[22]]),
        0x4002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[23], invite_frame_payload[24]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[25], invite_frame_payload[26]]),
        703
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            invite_frame_payload[27],
            invite_frame_payload[28],
            invite_frame_payload[29],
            invite_frame_payload[30],
            invite_frame_payload[31],
            invite_frame_payload[32],
            invite_frame_payload[33],
            invite_frame_payload[34],
        ]),
        878850364
    ); // agyis: no-mutant
    assert_eq!(
        u64::from_le_bytes([
            invite_frame_payload[35],
            invite_frame_payload[36],
            invite_frame_payload[37],
            invite_frame_payload[38],
            invite_frame_payload[39],
            invite_frame_payload[40],
            invite_frame_payload[41],
            invite_frame_payload[42],
        ]),
        434
    ); // agyis: no-mutant

    // Group 0x6000: Table 1619 (MCTS_TOKEN_INVITED_MEMBERS)
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[43], invite_frame_payload[44]]),
        0x6001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[45], invite_frame_payload[46]]),
        immortal_net::MCTS_TOKEN_INVITED_MEMBERS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[45], invite_frame_payload[46]]),
        1619
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[47], invite_frame_payload[48]]),
        1
    ); // agyis: no-mutant (1 row)

    // Row 0: 2 fields (Tokens 11 and 682)
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[49], invite_frame_payload[50]]),
        2
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[51], invite_frame_payload[52]]),
        0x3002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[53], invite_frame_payload[54]]),
        immortal_net::MCTS_TOKEN_PLAYER_ID
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[53], invite_frame_payload[54]]),
        11
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[55], invite_frame_payload[56]]),
        immortal_net::MCTS_TOKEN_ACCOUNT_ID
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([invite_frame_payload[55], invite_frame_payload[56]]),
        682
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[57],
            invite_frame_payload[58],
            invite_frame_payload[59],
            invite_frame_payload[60]
        ]),
        8302401
    ); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            invite_frame_payload[61],
            invite_frame_payload[62],
            invite_frame_payload[63],
            invite_frame_payload[64]
        ]),
        8302401
    ); // agyis: no-mutant

    // (a-queue-status-accepted) QUEUE_STATUS (Function ID 0x2cdbafe1, Table 242, queue 434, state 4 MQ_ACCEPTED)
    stream.read_exact(&mut header_buf).await.unwrap();
    let q_status4_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let q_status4_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(q_status4_flags, 0x0000); // agyis: no-mutant
    assert_eq!(q_status4_len, 41); // agyis: no-mutant
    let mut q_status4_payload = vec![0u8; q_status4_len];
    stream.read_exact(&mut q_status4_payload).await.unwrap();
    assert_eq!(q_status4_payload[0], 0x00); // agyis: no-mutant
    let q_status4_func_id = u32::from_le_bytes([
        q_status4_payload[1],
        q_status4_payload[2],
        q_status4_payload[3],
        q_status4_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        q_status4_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUEUE_STATUS
    ); // agyis: no-mutant
    assert_eq!(q_status4_func_id, 0x2cdbafe1); // agyis: no-mutant
    let q4_fields = u16::from_le_bytes([q_status4_payload[5], q_status4_payload[6]]); // agyis: no-mutant
    assert_eq!(q4_fields, 1); // agyis: no-mutant
    let q4_tbl_grp = u16::from_le_bytes([q_status4_payload[7], q_status4_payload[8]]); // agyis: no-mutant
    assert_eq!(q4_tbl_grp, 0x6001); // agyis: no-mutant
    let q4_tbl_tok = u16::from_le_bytes([q_status4_payload[9], q_status4_payload[10]]); // agyis: no-mutant
    assert_eq!(q4_tbl_tok, immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(q4_tbl_tok, 242); // agyis: no-mutant
    let q4_row_cnt = u16::from_le_bytes([q_status4_payload[11], q_status4_payload[12]]); // agyis: no-mutant
    assert_eq!(q4_row_cnt, 1); // agyis: no-mutant
    let q4_row_fields = u16::from_le_bytes([q_status4_payload[13], q_status4_payload[14]]); // agyis: no-mutant
    assert_eq!(q4_row_fields, 3); // agyis: no-mutant
    let q4_grp4 = u16::from_le_bytes([q_status4_payload[15], q_status4_payload[16]]); // agyis: no-mutant
    assert_eq!(q4_grp4, 0x3002); // agyis: no-mutant
    let q4_tok36 = u16::from_le_bytes([q_status4_payload[17], q_status4_payload[18]]); // agyis: no-mutant
    assert_eq!(q4_tok36, immortal_net::MCTS_TOKEN_QUEUE_ACTIVE); // agyis: no-mutant
    assert_eq!(q4_tok36, 36); // agyis: no-mutant
    let q4_tok1646 = u16::from_le_bytes([q_status4_payload[19], q_status4_payload[20]]); // agyis: no-mutant
    assert_eq!(q4_tok1646, immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(q4_tok1646, 1646); // agyis: no-mutant
    let q4_v36 = u32::from_le_bytes([
        q_status4_payload[21],
        q_status4_payload[22],
        q_status4_payload[23],
        q_status4_payload[24],
    ]); // agyis: no-mutant
    assert_eq!(q4_v36, 1); // agyis: no-mutant
    let q4_v1646 = u32::from_le_bytes([
        q_status4_payload[25],
        q_status4_payload[26],
        q_status4_payload[27],
        q_status4_payload[28],
    ]); // agyis: no-mutant
    assert_eq!(q4_v1646, 4); // agyis: no-mutant
    let q4_grp8 = u16::from_le_bytes([q_status4_payload[29], q_status4_payload[30]]); // agyis: no-mutant
    assert_eq!(q4_grp8, 0x4001); // agyis: no-mutant
    let q4_tok703 = u16::from_le_bytes([q_status4_payload[31], q_status4_payload[32]]); // agyis: no-mutant
    assert_eq!(q4_tok703, immortal_net::MCTS_TOKEN_MATCH_QUEUE_ID); // agyis: no-mutant
    assert_eq!(q4_tok703, 703); // agyis: no-mutant
    let q4_v703 = u64::from_le_bytes([
        q_status4_payload[33],
        q_status4_payload[34],
        q_status4_payload[35],
        q_status4_payload[36],
        q_status4_payload[37],
        q_status4_payload[38],
        q_status4_payload[39],
        q_status4_payload[40],
    ]); // agyis: no-mutant
    assert_eq!(q4_v703, 434); // agyis: no-mutant

    // (a) MATCH_STATUS state 8 with DATA_SET_MEMBERS table (Token 312)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status8_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status8_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status8_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status8_len, 106); // agyis: no-mutant
    let mut status8_payload = vec![0u8; status8_len];
    stream.read_exact(&mut status8_payload).await.unwrap();
    assert_eq!(status8_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status8_payload[1],
            status8_payload[2],
            status8_payload[3],
            status8_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[5], status8_payload[6]]),
        7
    ); // agyis: no-mutant (7 total fields)

    // Group 0x3000 (4 fields)
    assert_eq!(
        u16::from_le_bytes([status8_payload[7], status8_payload[8]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[9], status8_payload[10]]),
        1342
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[11], status8_payload[12]]),
        1690
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[13], status8_payload[14]]),
        1344
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[15], status8_payload[16]]),
        2191
    ); // agyis: no-mutant
    let s8_state = u32::from_le_bytes([
        status8_payload[17],
        status8_payload[18],
        status8_payload[19],
        status8_payload[20],
    ]); // agyis: no-mutant
    let s8_launch = u32::from_le_bytes([
        status8_payload[21],
        status8_payload[22],
        status8_payload[23],
        status8_payload[24],
    ]); // agyis: no-mutant
    let s8_player_lobby = u32::from_le_bytes([
        status8_payload[25],
        status8_payload[26],
        status8_payload[27],
        status8_payload[28],
    ]); // agyis: no-mutant
    let s8_player_queue = u32::from_le_bytes([
        status8_payload[29],
        status8_payload[30],
        status8_payload[31],
        status8_payload[32],
    ]); // agyis: no-mutant
    assert_eq!(s8_state, 8); // agyis: no-mutant
    assert_eq!(s8_launch, 30); // agyis: no-mutant
    assert_eq!(s8_player_lobby, 0); // agyis: no-mutant
    assert_eq!(s8_player_queue, 4); // agyis: no-mutant

    // Group 0x4000 (2 fields)
    assert_eq!(
        u16::from_le_bytes([status8_payload[33], status8_payload[34]]),
        0x4002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[35], status8_payload[36]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[37], status8_payload[38]]),
        703
    ); // agyis: no-mutant
    let s8_match_id = u64::from_le_bytes([
        status8_payload[39],
        status8_payload[40],
        status8_payload[41],
        status8_payload[42],
        status8_payload[43],
        status8_payload[44],
        status8_payload[45],
        status8_payload[46],
    ]); // agyis: no-mutant
    let s8_queue_id = u64::from_le_bytes([
        status8_payload[47],
        status8_payload[48],
        status8_payload[49],
        status8_payload[50],
        status8_payload[51],
        status8_payload[52],
        status8_payload[53],
        status8_payload[54],
    ]); // agyis: no-mutant
    assert_eq!(s8_match_id, 878850364); // agyis: no-mutant
    assert_eq!(s8_queue_id, 0); // agyis: no-mutant

    // Group 0x6000 (1 table: Table 312 DATA_SET_MEMBERS)
    assert_eq!(
        u16::from_le_bytes([status8_payload[55], status8_payload[56]]),
        0x6001
    ); // agyis: no-mutant

    // Table 312 / DATA_SET_MEMBERS
    assert_eq!(
        u16::from_le_bytes([status8_payload[57], status8_payload[58]]),
        immortal_net::MCTS_TOKEN_MEMBERS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[57], status8_payload[58]]),
        312
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[59], status8_payload[60]]),
        1
    ); // agyis: no-mutant (1 row)

    // Table 312 Row 0: 6 fields
    assert_eq!(
        u16::from_le_bytes([status8_payload[61], status8_payload[62]]),
        6
    ); // agyis: no-mutant

    // Row Group 0x1000: Token 2143 (bool false = 0)
    assert_eq!(
        u16::from_le_bytes([status8_payload[63], status8_payload[64]]),
        0x1001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[65], status8_payload[66]]),
        2143
    ); // agyis: no-mutant
    assert_eq!(status8_payload[67], 0); // agyis: no-mutant

    // Row Group 0x3000: Tokens 122 (BOT_ID), 838 (POSITION), 855 (PROFILE_ID), 1344 (PLAYER_LOBBY_STATE)
    assert_eq!(
        u16::from_le_bytes([status8_payload[68], status8_payload[69]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[70], status8_payload[71]]),
        122
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[72], status8_payload[73]]),
        MCTS_TOKEN_POSITION
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[74], status8_payload[75]]),
        855
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[76], status8_payload[77]]),
        1344
    ); // agyis: no-mutant
    let s8_bot_id = u32::from_le_bytes([
        status8_payload[78],
        status8_payload[79],
        status8_payload[80],
        status8_payload[81],
    ]); // agyis: no-mutant
    let s8_position = u32::from_le_bytes([
        status8_payload[82],
        status8_payload[83],
        status8_payload[84],
        status8_payload[85],
    ]); // agyis: no-mutant
    let s8_profile_id = u32::from_le_bytes([
        status8_payload[86],
        status8_payload[87],
        status8_payload[88],
        status8_payload[89],
    ]); // agyis: no-mutant
    let s8_lobby_state = u32::from_le_bytes([
        status8_payload[90],
        status8_payload[91],
        status8_payload[92],
        status8_payload[93],
    ]); // agyis: no-mutant
    assert_eq!(s8_bot_id, BOT_ID_VIKTOR); // agyis: no-mutant
    assert_eq!(s8_bot_id, 2285); // agyis: no-mutant
    assert_eq!(s8_position, 0); // agyis: no-mutant
    assert_eq!(s8_profile_id, 8302401); // agyis: no-mutant
    assert_eq!(s8_lobby_state, 0); // agyis: no-mutant

    // Row Group 0x4000: Token 11 (PLAYER_ID, 8 bytes)
    assert_eq!(
        u16::from_le_bytes([status8_payload[94], status8_payload[95]]),
        0x4001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status8_payload[96], status8_payload[97]]),
        11
    ); // agyis: no-mutant
    let s8_player_id = u64::from_le_bytes([
        status8_payload[98],
        status8_payload[99],
        status8_payload[100],
        status8_payload[101],
        status8_payload[102],
        status8_payload[103],
        status8_payload[104],
        status8_payload[105],
    ]); // agyis: no-mutant
    assert_eq!(s8_player_id, 8302401); // agyis: no-mutant

    // (b) Champion Roster (Function ID 0xdb15d3d7, Table 249, Token 122)
    stream.read_exact(&mut header_buf).await.unwrap();
    let roster_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let roster_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(roster_flags, 0x0000); // agyis: no-mutant
    let mut roster_payload = vec![0u8; roster_len];
    stream.read_exact(&mut roster_payload).await.unwrap();
    assert_eq!(roster_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            roster_payload[1],
            roster_payload[2],
            roster_payload[3],
            roster_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_CHAMPION_ROSTER
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([roster_payload[5], roster_payload[6]]),
        1
    ); // agyis: no-mutant (1 table field)
    assert_eq!(
        u16::from_le_bytes([roster_payload[7], roster_payload[8]]),
        0x6001
    ); // agyis: no-mutant (Group 0x6001)
    assert_eq!(
        u16::from_le_bytes([roster_payload[9], roster_payload[10]]),
        249
    ); // agyis: no-mutant (Table 249)
    assert_eq!(
        u16::from_le_bytes([roster_payload[11], roster_payload[12]]),
        9
    ); // agyis: no-mutant (9 champions)
    let expected_champs = [
        1026,
        1024,
        1025,
        1027,
        BOT_ID_FERNANDO,
        BOT_ID_VIKTOR,
        2205,
        2404,
        2512,
    ];
    for (i, &expected_champ) in expected_champs.iter().enumerate() {
        let offset = 13 + i * 10;
        assert_eq!(
            u16::from_le_bytes([roster_payload[offset], roster_payload[offset + 1]]),
            1
        ); // agyis: no-mutant
        assert_eq!(
            u16::from_le_bytes([roster_payload[offset + 2], roster_payload[offset + 3]]),
            0x3001
        ); // agyis: no-mutant
        assert_eq!(
            u16::from_le_bytes([roster_payload[offset + 4], roster_payload[offset + 5]]),
            122
        ); // agyis: no-mutant
        let champ_id = u32::from_le_bytes([
            roster_payload[offset + 6],
            roster_payload[offset + 7],
            roster_payload[offset + 8],
            roster_payload[offset + 9],
        ]); // agyis: no-mutant
        assert_eq!(champ_id, expected_champ); // agyis: no-mutant
    }

    // (b-queue-def-launching) QUEUE_DEFINITION (Function ID 0xaf434825, Table 242, queue 434, state 7 MQ_LAUNCHING)
    stream.read_exact(&mut header_buf).await.unwrap();
    let q_def7_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let q_def7_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(q_def7_flags, 0x0000); // agyis: no-mutant
    assert_eq!(q_def7_len, 63); // agyis: no-mutant
    let mut q_def7_payload = vec![0u8; q_def7_len];
    stream.read_exact(&mut q_def7_payload).await.unwrap();
    assert_eq!(q_def7_payload[0], 0x00); // agyis: no-mutant
    let q_def7_func_id = u32::from_le_bytes([
        q_def7_payload[1],
        q_def7_payload[2],
        q_def7_payload[3],
        q_def7_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(q_def7_func_id, immortal_net::MCTS_FUNCTION_ID_QUERY_SERVERS); // agyis: no-mutant
    assert_eq!(q_def7_func_id, 0xaf434825); // agyis: no-mutant
    let q_def7_v1646 = u32::from_le_bytes([
        q_def7_payload[47],
        q_def7_payload[48],
        q_def7_payload[49],
        q_def7_payload[50],
    ]); // agyis: no-mutant
    assert_eq!(q_def7_v1646, 7); // agyis: no-mutant

    // (b-queue-status-launching) QUEUE_STATUS (Function ID 0x2cdbafe1, Table 242, queue 434, state 7 MQ_LAUNCHING)
    stream.read_exact(&mut header_buf).await.unwrap();
    let q_status7_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let q_status7_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(q_status7_flags, 0x0000); // agyis: no-mutant
    assert_eq!(q_status7_len, 41); // agyis: no-mutant
    let mut q_status7_payload = vec![0u8; q_status7_len];
    stream.read_exact(&mut q_status7_payload).await.unwrap();
    assert_eq!(q_status7_payload[0], 0x00); // agyis: no-mutant
    let q_status7_func_id = u32::from_le_bytes([
        q_status7_payload[1],
        q_status7_payload[2],
        q_status7_payload[3],
        q_status7_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        q_status7_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUEUE_STATUS
    ); // agyis: no-mutant
    assert_eq!(q_status7_func_id, 0x2cdbafe1); // agyis: no-mutant
    let q7_fields = u16::from_le_bytes([q_status7_payload[5], q_status7_payload[6]]); // agyis: no-mutant
    assert_eq!(q7_fields, 1); // agyis: no-mutant
    let q7_tbl_grp = u16::from_le_bytes([q_status7_payload[7], q_status7_payload[8]]); // agyis: no-mutant
    assert_eq!(q7_tbl_grp, 0x6001); // agyis: no-mutant
    let q7_tbl_tok = u16::from_le_bytes([q_status7_payload[9], q_status7_payload[10]]); // agyis: no-mutant
    assert_eq!(q7_tbl_tok, immortal_net::MCTS_TOKEN_QUEUE_STATUS); // agyis: no-mutant
    assert_eq!(q7_tbl_tok, 242); // agyis: no-mutant
    let q7_row_cnt = u16::from_le_bytes([q_status7_payload[11], q_status7_payload[12]]); // agyis: no-mutant
    assert_eq!(q7_row_cnt, 1); // agyis: no-mutant
    let q7_row_fields = u16::from_le_bytes([q_status7_payload[13], q_status7_payload[14]]); // agyis: no-mutant
    assert_eq!(q7_row_fields, 3); // agyis: no-mutant
    let q7_grp4 = u16::from_le_bytes([q_status7_payload[15], q_status7_payload[16]]); // agyis: no-mutant
    assert_eq!(q7_grp4, 0x3002); // agyis: no-mutant
    let q7_tok36 = u16::from_le_bytes([q_status7_payload[17], q_status7_payload[18]]); // agyis: no-mutant
    assert_eq!(q7_tok36, immortal_net::MCTS_TOKEN_QUEUE_ACTIVE); // agyis: no-mutant
    assert_eq!(q7_tok36, 36); // agyis: no-mutant
    let q7_tok1646 = u16::from_le_bytes([q_status7_payload[19], q_status7_payload[20]]); // agyis: no-mutant
    assert_eq!(q7_tok1646, immortal_net::MCTS_TOKEN_QUEUE_STATE); // agyis: no-mutant
    assert_eq!(q7_tok1646, 1646); // agyis: no-mutant
    let q7_v36 = u32::from_le_bytes([
        q_status7_payload[21],
        q_status7_payload[22],
        q_status7_payload[23],
        q_status7_payload[24],
    ]); // agyis: no-mutant
    assert_eq!(q7_v36, 1); // agyis: no-mutant
    let q7_v1646 = u32::from_le_bytes([
        q_status7_payload[25],
        q_status7_payload[26],
        q_status7_payload[27],
        q_status7_payload[28],
    ]); // agyis: no-mutant
    assert_eq!(q7_v1646, 7); // agyis: no-mutant
    let q7_grp8 = u16::from_le_bytes([q_status7_payload[29], q_status7_payload[30]]); // agyis: no-mutant
    assert_eq!(q7_grp8, 0x4001); // agyis: no-mutant
    let q7_tok703 = u16::from_le_bytes([q_status7_payload[31], q_status7_payload[32]]); // agyis: no-mutant
    assert_eq!(q7_tok703, immortal_net::MCTS_TOKEN_MATCH_QUEUE_ID); // agyis: no-mutant
    assert_eq!(q7_tok703, 703); // agyis: no-mutant
    let q7_v703 = u64::from_le_bytes([
        q_status7_payload[33],
        q_status7_payload[34],
        q_status7_payload[35],
        q_status7_payload[36],
        q_status7_payload[37],
        q_status7_payload[38],
        q_status7_payload[39],
        q_status7_payload[40],
    ]); // agyis: no-mutant
    assert_eq!(q7_v703, 434); // agyis: no-mutant

    // (c) MATCH_STATUS state 10 with DATA_SET_MEMBERS table (Token 312)
    stream.read_exact(&mut header_buf).await.unwrap();
    let status10_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let status10_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(status10_flags, 0x0000); // agyis: no-mutant
    assert_eq!(status10_len, 106); // agyis: no-mutant
    let mut status10_payload = vec![0u8; status10_len];
    stream.read_exact(&mut status10_payload).await.unwrap();
    assert_eq!(status10_payload[0], 0x00); // agyis: no-mutant
    assert_eq!(
        u32::from_le_bytes([
            status10_payload[1],
            status10_payload[2],
            status10_payload[3],
            status10_payload[4]
        ]),
        immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[5], status10_payload[6]]),
        7
    ); // agyis: no-mutant (7 total fields)

    // Group 0x3000 (4 fields)
    assert_eq!(
        u16::from_le_bytes([status10_payload[7], status10_payload[8]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[9], status10_payload[10]]),
        1342
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[11], status10_payload[12]]),
        1690
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[13], status10_payload[14]]),
        1344
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[15], status10_payload[16]]),
        2191
    ); // agyis: no-mutant
    let s10_state = u32::from_le_bytes([
        status10_payload[17],
        status10_payload[18],
        status10_payload[19],
        status10_payload[20],
    ]); // agyis: no-mutant
    let s10_launch = u32::from_le_bytes([
        status10_payload[21],
        status10_payload[22],
        status10_payload[23],
        status10_payload[24],
    ]); // agyis: no-mutant
    let s10_player_lobby = u32::from_le_bytes([
        status10_payload[25],
        status10_payload[26],
        status10_payload[27],
        status10_payload[28],
    ]); // agyis: no-mutant
    let s10_player_queue = u32::from_le_bytes([
        status10_payload[29],
        status10_payload[30],
        status10_payload[31],
        status10_payload[32],
    ]); // agyis: no-mutant
    assert_eq!(s10_state, 10); // agyis: no-mutant
    assert_eq!(s10_launch, 0); // agyis: no-mutant
    assert_eq!(s10_player_lobby, 5); // agyis: no-mutant
    assert_eq!(s10_player_queue, 7); // agyis: no-mutant

    // Group 0x4000 (2 fields)
    assert_eq!(
        u16::from_le_bytes([status10_payload[33], status10_payload[34]]),
        0x4002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[35], status10_payload[36]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[37], status10_payload[38]]),
        703
    ); // agyis: no-mutant
    let s10_match_id = u64::from_le_bytes([
        status10_payload[39],
        status10_payload[40],
        status10_payload[41],
        status10_payload[42],
        status10_payload[43],
        status10_payload[44],
        status10_payload[45],
        status10_payload[46],
    ]); // agyis: no-mutant
    let s10_queue_id = u64::from_le_bytes([
        status10_payload[47],
        status10_payload[48],
        status10_payload[49],
        status10_payload[50],
        status10_payload[51],
        status10_payload[52],
        status10_payload[53],
        status10_payload[54],
    ]); // agyis: no-mutant
    assert_eq!(s10_match_id, 878850364); // agyis: no-mutant
    assert_eq!(s10_queue_id, 434); // agyis: no-mutant

    // Group 0x6000 (1 table: Table 312 DATA_SET_MEMBERS)
    assert_eq!(
        u16::from_le_bytes([status10_payload[55], status10_payload[56]]),
        0x6001
    ); // agyis: no-mutant

    // Table 312 / DATA_SET_MEMBERS
    assert_eq!(
        u16::from_le_bytes([status10_payload[57], status10_payload[58]]),
        immortal_net::MCTS_TOKEN_MEMBERS
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[57], status10_payload[58]]),
        312
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[59], status10_payload[60]]),
        1
    ); // agyis: no-mutant (1 row)

    // Table 312 Row 0: 6 fields
    assert_eq!(
        u16::from_le_bytes([status10_payload[61], status10_payload[62]]),
        6
    ); // agyis: no-mutant

    // Row Group 0x1000: Token 2143 (bool false = 0)
    assert_eq!(
        u16::from_le_bytes([status10_payload[63], status10_payload[64]]),
        0x1001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[65], status10_payload[66]]),
        2143
    ); // agyis: no-mutant
    assert_eq!(status10_payload[67], 0); // agyis: no-mutant

    // Row Group 0x3000: Tokens 122 (BOT_ID), 838 (POSITION), 855 (PROFILE_ID), 1344 (PLAYER_LOBBY_STATE)
    assert_eq!(
        u16::from_le_bytes([status10_payload[68], status10_payload[69]]),
        0x3004
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[70], status10_payload[71]]),
        122
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[72], status10_payload[73]]),
        MCTS_TOKEN_POSITION
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[74], status10_payload[75]]),
        855
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[76], status10_payload[77]]),
        1344
    ); // agyis: no-mutant
    let s10_bot_id = u32::from_le_bytes([
        status10_payload[78],
        status10_payload[79],
        status10_payload[80],
        status10_payload[81],
    ]); // agyis: no-mutant
    let s10_position = u32::from_le_bytes([
        status10_payload[82],
        status10_payload[83],
        status10_payload[84],
        status10_payload[85],
    ]); // agyis: no-mutant
    let s10_profile_id = u32::from_le_bytes([
        status10_payload[86],
        status10_payload[87],
        status10_payload[88],
        status10_payload[89],
    ]); // agyis: no-mutant
    let s10_lobby_state = u32::from_le_bytes([
        status10_payload[90],
        status10_payload[91],
        status10_payload[92],
        status10_payload[93],
    ]); // agyis: no-mutant
    assert_eq!(s10_bot_id, BOT_ID_VIKTOR); // agyis: no-mutant
    assert_eq!(s10_bot_id, 2285); // agyis: no-mutant
    assert_eq!(s10_position, 0); // agyis: no-mutant
    assert_eq!(s10_profile_id, 8302401); // agyis: no-mutant
    assert_eq!(s10_lobby_state, 5); // agyis: no-mutant

    // Row Group 0x4000: Token 11 (PLAYER_ID, 8 bytes)
    assert_eq!(
        u16::from_le_bytes([status10_payload[94], status10_payload[95]]),
        0x4001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([status10_payload[96], status10_payload[97]]),
        11
    ); // agyis: no-mutant
    let s10_player_id = u64::from_le_bytes([
        status10_payload[98],
        status10_payload[99],
        status10_payload[100],
        status10_payload[101],
        status10_payload[102],
        status10_payload[103],
        status10_payload[104],
        status10_payload[105],
    ]); // agyis: no-mutant
    assert_eq!(s10_player_id, 8302401); // agyis: no-mutant

    // (d) PLAYER_SVC_LAUNCH_MAP_INSTANCE wire frame (Function ID 0x4bee2ed8, len 53, queue_id 434, match_id 878850364, timeout 60, sockaddr 127.0.0.1:7777)
    stream.read_exact(&mut header_buf).await.unwrap();
    let launch_map_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let launch_map_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(launch_map_flags, 0x0000); // agyis: no-mutant
    assert_eq!(launch_map_len, 53); // agyis: no-mutant
    let mut launch_map_payload = vec![0u8; launch_map_len];
    stream.read_exact(&mut launch_map_payload).await.unwrap();
    assert_eq!(launch_map_payload[0], 0x00); // agyis: no-mutant
    let launch_map_func_id = u32::from_le_bytes([
        launch_map_payload[1],
        launch_map_payload[2],
        launch_map_payload[3],
        launch_map_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        launch_map_func_id,
        immortal_net::MCTS_FUNCTION_ID_PLAYER_SVC_LAUNCH_MAP_INSTANCE
    ); // agyis: no-mutant
    assert_eq!(launch_map_func_id, 0x4bee2ed8); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[5], launch_map_payload[6]]),
        5
    ); // agyis: no-mutant (5 total fields)

    // Group 0x3000 (2 fields): Token 721 (queue_id = 434), Token 1839 (timeout_secs = 60)
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[7], launch_map_payload[8]]),
        0x3002
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[9], launch_map_payload[10]]),
        721
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[11], launch_map_payload[12]]),
        1839
    ); // agyis: no-mutant
    let lm_queue_id = u32::from_le_bytes([
        launch_map_payload[13],
        launch_map_payload[14],
        launch_map_payload[15],
        launch_map_payload[16],
    ]); // agyis: no-mutant
    let lm_timeout = u32::from_le_bytes([
        launch_map_payload[17],
        launch_map_payload[18],
        launch_map_payload[19],
        launch_map_payload[20],
    ]); // agyis: no-mutant
    assert_eq!(lm_queue_id, 434); // agyis: no-mutant
    assert_eq!(lm_timeout, 60); // agyis: no-mutant

    // Group 0x4000 (3 fields): Token 25 (0u64), Token 700 (match_id), Token 877 (sockaddr_in)
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[21], launch_map_payload[22]]),
        0x4003
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[23], launch_map_payload[24]]),
        25
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[25], launch_map_payload[26]]),
        700
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([launch_map_payload[27], launch_map_payload[28]]),
        877
    ); // agyis: no-mutant
    let lm_instance_id = u64::from_le_bytes([
        launch_map_payload[29],
        launch_map_payload[30],
        launch_map_payload[31],
        launch_map_payload[32],
        launch_map_payload[33],
        launch_map_payload[34],
        launch_map_payload[35],
        launch_map_payload[36],
    ]); // agyis: no-mutant
    let lm_match_id = u64::from_le_bytes([
        launch_map_payload[37],
        launch_map_payload[38],
        launch_map_payload[39],
        launch_map_payload[40],
        launch_map_payload[41],
        launch_map_payload[42],
        launch_map_payload[43],
        launch_map_payload[44],
    ]); // agyis: no-mutant
    assert_eq!(lm_instance_id, 0); // agyis: no-mutant
    assert_eq!(lm_match_id, 878850364); // agyis: no-mutant
    assert_eq!(
        &launch_map_payload[45..53],
        &[0x02, 0x00, 0x1e, 0x61, 127, 0, 0, 1]
    ); // agyis: no-mutant

    // (e) CHANGE_MAP wire frame (Function ID 0x847de68b, len 32, compel true, mapGameId 1615, mapInstanceId 1282927737)
    stream.read_exact(&mut header_buf).await.unwrap();
    let change_map_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let change_map_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(change_map_flags, 0x0000); // agyis: no-mutant
    assert_eq!(change_map_len, 32); // agyis: no-mutant
    let mut change_map_payload = vec![0u8; change_map_len];
    stream.read_exact(&mut change_map_payload).await.unwrap();
    assert_eq!(change_map_payload[0], 0x00); // agyis: no-mutant
    let change_map_func_id = u32::from_le_bytes([
        change_map_payload[1],
        change_map_payload[2],
        change_map_payload[3],
        change_map_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        change_map_func_id,
        immortal_net::MCTS_FUNCTION_ID_CHANGE_MAP
    ); // agyis: no-mutant
    assert_eq!(change_map_func_id, 0x847de68b); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([change_map_payload[5], change_map_payload[6]]),
        3
    ); // agyis: no-mutant (3 total fields)

    // Group 0x1000 (1 field): Token 1536 (compel = true / 0x01)
    assert_eq!(
        u16::from_le_bytes([change_map_payload[7], change_map_payload[8]]),
        0x1001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([change_map_payload[9], change_map_payload[10]]),
        1536
    ); // agyis: no-mutant
    assert_eq!(change_map_payload[11], 1); // agyis: no-mutant

    // Group 0x3000 (1 field): Token 682 (mapGameId = 1615)
    assert_eq!(
        u16::from_le_bytes([change_map_payload[12], change_map_payload[13]]),
        0x3001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([change_map_payload[14], change_map_payload[15]]),
        682
    ); // agyis: no-mutant
    let trans_map_game_id = u32::from_le_bytes([
        change_map_payload[16],
        change_map_payload[17],
        change_map_payload[18],
        change_map_payload[19],
    ]); // agyis: no-mutant
    assert_eq!(trans_map_game_id, 1615); // agyis: no-mutant

    // Group 0x4000 (1 field): Token 685 (mapInstanceId = 1282927737)
    assert_eq!(
        u16::from_le_bytes([change_map_payload[20], change_map_payload[21]]),
        0x4001
    ); // agyis: no-mutant
    assert_eq!(
        u16::from_le_bytes([change_map_payload[22], change_map_payload[23]]),
        685
    ); // agyis: no-mutant
    let trans_map_instance_id = u64::from_le_bytes([
        change_map_payload[24],
        change_map_payload[25],
        change_map_payload[26],
        change_map_payload[27],
        change_map_payload[28],
        change_map_payload[29],
        change_map_payload[30],
        change_map_payload[31],
    ]); // agyis: no-mutant
    assert_eq!(trans_map_instance_id, 1282927737); // agyis: no-mutant

    // 5. Step 5: Live sequence completes at MATCH_STATUS 10 and change_map frame (0x847de68b with compel=true).
    // Subsequent post-login frame (champion select with Fernando) is drained by decoupled reader
    // without emitting bogus encrypted ciphertext ACK and stream remains connected.
    stream.write_all(&champ_frame).await.unwrap();
    stream.flush().await.unwrap();

    let mut probe_buf = [0u8; 1];
    let probe_res = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut probe_buf),
    )
    .await;
    assert!(
        probe_res.is_err(),
        "Server must not respond to champion select with bogus encrypted ciphertext ACK in unencrypted MCTS"
    );

    // 6. Step 6: Verify arbitrary post-login frame length does not drop connection with InvalidMagic
    // and decoupled reader continuously drains client frames.
    let mut arb_frame = Vec::new();
    arb_frame.extend_from_slice(&25u16.to_le_bytes()); // Length 25 (not in legacy [37, 19, 33, 15])
    arb_frame.extend_from_slice(&0x0000u16.to_le_bytes()); // Flags 0x0000 (not 0x0108)
    arb_frame.extend_from_slice(&[0x77u8; 25]);
    stream.write_all(&arb_frame).await.unwrap();
    stream.flush().await.unwrap();

    // 7. Step 7: Verify vendor query frames (19 and 37 bytes) are continuously drained without error
    let mut frame_19 = Vec::new();
    frame_19.extend_from_slice(&19u16.to_le_bytes());
    frame_19.extend_from_slice(&0x0000u16.to_le_bytes());
    frame_19.extend_from_slice(&[0x11u8; 19]);
    stream.write_all(&frame_19).await.unwrap();
    stream.flush().await.unwrap();

    let mut frame_37 = Vec::new();
    frame_37.extend_from_slice(&37u16.to_le_bytes());
    frame_37.extend_from_slice(&0x0000u16.to_le_bytes());
    frame_37.extend_from_slice(&[0x22u8; 37]);
    stream.write_all(&frame_37).await.unwrap();
    stream.flush().await.unwrap();

    // Verify neither frame triggered a bogus ACK by asserting no bytes are pending on stream
    let probe_res2 = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut probe_buf),
    )
    .await;
    assert!(
        probe_res2.is_err(),
        "Server must continuously drain client frames without sending bogus ACKs"
    );

    // 8. Step 8: Assert that a raw 15-byte protocol sequence ACK packet does NOT trigger a queue definition frame
    let mut seq_ack_frame = Vec::new();
    seq_ack_frame.extend_from_slice(&15u16.to_le_bytes());
    seq_ack_frame.extend_from_slice(&0x0100u16.to_le_bytes());
    let mut seq_ack_payload = [0u8; 15];
    seq_ack_payload[..9].copy_from_slice(&[0xf8, 0x85, 0x8d, 0x96, 0xbe, 0x4c, 0xc3, 0x01, 0x00]);
    seq_ack_frame.extend_from_slice(&seq_ack_payload);
    stream.write_all(&seq_ack_frame).await.unwrap();
    stream.flush().await.unwrap();

    let probe_res_ack = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut probe_buf),
    )
    .await;
    assert!(
        probe_res_ack.is_err(),
        "Raw 15-byte sequence ACK packet must not trigger unsolicited queue definition frames"
    );

    // Client sends query servers request carrying MCTS_FUNCTION_ID_QUERY_SERVERS (content-based matching)
    let mut req_list_frame = Vec::new();
    let mut req_payload = vec![0x00u8; 15];
    req_payload[1..5].copy_from_slice(&immortal_net::MCTS_FUNCTION_ID_QUERY_SERVERS.to_le_bytes());
    req_list_frame.extend_from_slice(&(req_payload.len() as u16).to_le_bytes());
    req_list_frame.extend_from_slice(&0x0108u16.to_le_bytes());
    req_list_frame.extend_from_slice(&req_payload);
    stream.write_all(&req_list_frame).await.unwrap();
    stream.flush().await.unwrap();

    // Expect server to respond with MCTS Queue Definition wire frame (Function ID 0xaf434825)
    stream.read_exact(&mut header_buf).await.unwrap();
    let qdef_req_len = u16::from_le_bytes([header_buf[0], header_buf[1]]) as usize;
    let qdef_req_flags = u16::from_le_bytes([header_buf[2], header_buf[3]]);
    assert_eq!(qdef_req_flags, 0x0000); // agyis: no-mutant
    assert_eq!(qdef_req_len, 63); // agyis: no-mutant

    let mut qdef_req_payload = vec![0u8; qdef_req_len];
    stream.read_exact(&mut qdef_req_payload).await.unwrap();
    assert_eq!(qdef_req_payload[0], 0x00); // agyis: no-mutant
    let qdef_req_func_id = u32::from_le_bytes([
        qdef_req_payload[1],
        qdef_req_payload[2],
        qdef_req_payload[3],
        qdef_req_payload[4],
    ]); // agyis: no-mutant
    assert_eq!(
        qdef_req_func_id,
        immortal_net::MCTS_FUNCTION_ID_QUERY_SERVERS
    ); // agyis: no-mutant
    assert_eq!(qdef_req_func_id, 0xaf434825); // agyis: no-mutant

    // Verify stream has no extra pending bytes
    let probe_res3 = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut probe_buf),
    )
    .await;
    assert!(
        probe_res3.is_err(),
        "Server must not send additional unsolicited frames after queue definition response"
    );

    handle.shutdown().await.unwrap();

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 2500, // agyis: no-mutant
        "Live MCTS Auth Gateway exchange test must finish in < 2500ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_gazebo_lifecycle_state8_to_state10_transition_invariants() {
    // Verifies the Gazebo lifecycle state machine transition sequence documented in
    // docs/protocol/mcts_gazebo_lifecycle.md:
    // - State 8: PlayerLobbyState = 0, QueueId = 0, LaunchTime = 30.
    // - State 10: PlayerLobbyState = 5, QueueId = 434, LaunchTime = 0, QueueState = 7.
    // - ChangeMap RPC: Function ID = 0x847de68b, compel = true, mapGameId = 1615, mapInstanceId = 1282927737.

    let account_id = 8302401u64;
    let match_id = 878850364u64;

    // 1. Construct State 8: Champion Selection / Gazebo Staging
    let frame_8 = immortal_net::create_mcts_match_status_with_members_frame(
        0,
        match_id,
        8,
        30,
        0,
        4,
        account_id,
        BOT_ID_VIKTOR,
    );
    let payload_8 = &frame_8[4..];
    assert_eq!(payload_8[0], 0x00);
    let func_id_8 = u32::from_le_bytes([payload_8[1], payload_8[2], payload_8[3], payload_8[4]]);
    assert_eq!(func_id_8, immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS);

    // Extract State 8 Group 0x3000 fields
    // Token 1342 (MATCH_LOBBY_STATE) = 8
    let s8_match_lobby_state =
        u32::from_le_bytes([payload_8[17], payload_8[18], payload_8[19], payload_8[20]]);
    assert_eq!(s8_match_lobby_state, 8);
    // Token 1690 (LAUNCH_SECONDS) = 30
    let s8_launch_time =
        u32::from_le_bytes([payload_8[21], payload_8[22], payload_8[23], payload_8[24]]);
    assert_eq!(s8_launch_time, 30);
    // Token 1344 (PLAYER_LOBBY_STATE) = 0
    let s8_player_lobby_state =
        u32::from_le_bytes([payload_8[25], payload_8[26], payload_8[27], payload_8[28]]);
    assert_eq!(s8_player_lobby_state, 0);
    // Token 2191 (PLAYER_QUEUE_STATE) = 4 (MQ_ACCEPTED)
    let s8_player_queue_state =
        u32::from_le_bytes([payload_8[29], payload_8[30], payload_8[31], payload_8[32]]);
    assert_eq!(s8_player_queue_state, 4);

    // Extract State 8 Group 0x4000 fields
    // Token 700 (MATCH_ID) = 878850364
    let s8_match_id = u64::from_le_bytes([
        payload_8[39],
        payload_8[40],
        payload_8[41],
        payload_8[42],
        payload_8[43],
        payload_8[44],
        payload_8[45],
        payload_8[46],
    ]);
    assert_eq!(s8_match_id, match_id);
    // Token 703 (MATCH_QUEUE_ID) = 0
    let s8_queue_id = u64::from_le_bytes([
        payload_8[47],
        payload_8[48],
        payload_8[49],
        payload_8[50],
        payload_8[51],
        payload_8[52],
        payload_8[53],
        payload_8[54],
    ]);
    assert_eq!(s8_queue_id, 0);

    // 2. Construct State 10: Match Finalized / Launching
    let frame_10 = immortal_net::create_mcts_match_status_with_members_frame(
        434,
        match_id,
        10,
        0,
        5,
        7,
        account_id,
        BOT_ID_VIKTOR,
    );
    let payload_10 = &frame_10[4..];
    assert_eq!(payload_10[0], 0x00);
    let func_id_10 =
        u32::from_le_bytes([payload_10[1], payload_10[2], payload_10[3], payload_10[4]]);
    assert_eq!(func_id_10, immortal_net::MCTS_FUNCTION_ID_MATCH_STATUS);

    // Extract State 10 Group 0x3000 fields
    let s10_match_lobby_state = u32::from_le_bytes([
        payload_10[17],
        payload_10[18],
        payload_10[19],
        payload_10[20],
    ]);
    assert_eq!(s10_match_lobby_state, 10);
    let s10_launch_time = u32::from_le_bytes([
        payload_10[21],
        payload_10[22],
        payload_10[23],
        payload_10[24],
    ]);
    assert_eq!(s10_launch_time, 0);
    let s10_player_lobby_state = u32::from_le_bytes([
        payload_10[25],
        payload_10[26],
        payload_10[27],
        payload_10[28],
    ]);
    assert_eq!(s10_player_lobby_state, 5);
    let s10_player_queue_state = u32::from_le_bytes([
        payload_10[29],
        payload_10[30],
        payload_10[31],
        payload_10[32],
    ]);
    assert_eq!(s10_player_queue_state, 7);

    // Extract State 10 Group 0x4000 fields
    let s10_queue_id = u64::from_le_bytes([
        payload_10[47],
        payload_10[48],
        payload_10[49],
        payload_10[50],
        payload_10[51],
        payload_10[52],
        payload_10[53],
        payload_10[54],
    ]);
    assert_eq!(s10_queue_id, 434);

    // 3. Assert State Invariant Deltas (Gate Conditions)
    // Invariant A: PlayerLobbyState 0 -> 5 (Satisfies client launch gate condition: OLD < 1 && NEW > 0)
    assert!(
        s8_player_lobby_state < 1,
        "State 8 PlayerLobbyState must be < 1"
    );
    assert!(
        s10_player_lobby_state > 0,
        "State 10 PlayerLobbyState must be > 0"
    );

    // Invariant B: QueueId transitions 0 -> 434 in state 10 (Breaks UTgMatchLobby cache so FindQueueById(434) copies QueueState 7 into [UTgMatchLobby + 0x1d8])
    assert_eq!(s8_queue_id, 0);
    assert_eq!(s10_queue_id, 434);

    // Invariant C: LaunchTime 30 -> 0 (Timer expires, triggers match launch)
    assert_eq!(s8_launch_time, 30);
    assert_eq!(s10_launch_time, 0);

    // Invariant D: MatchLobbyState 8 -> 10 (Selecting -> Launching)
    assert_eq!(s8_match_lobby_state, 8);
    assert_eq!(s10_match_lobby_state, 10);

    // Invariant E: PlayerQueueState 4 -> 7 (MQ_ACCEPTED -> MQ_LAUNCHING)
    assert_eq!(s8_player_queue_state, 4);
    assert_eq!(s10_player_queue_state, 7);

    // 4. Verify authentic ChangeMap RPC frame (0x847de68b)
    let change_map_frame = immortal_net::create_mcts_change_map_frame(
        immortal_net::MAP_GAME_ID_SHOOTING_RANGE,
        immortal_net::MAP_INSTANCE_ID_SHOOTING_RANGE as u64,
        true,
    );
    assert_eq!(change_map_frame.len(), 36);
    let cm_payload = &change_map_frame[4..];
    let cm_func_id =
        u32::from_le_bytes([cm_payload[1], cm_payload[2], cm_payload[3], cm_payload[4]]);
    assert_eq!(cm_func_id, immortal_net::MCTS_FUNCTION_ID_CHANGE_MAP);
    assert_eq!(cm_func_id, 0x847de68b);
    assert_eq!(cm_payload[11], 1); // compel = true
    let cm_game_id = u32::from_le_bytes([
        cm_payload[16],
        cm_payload[17],
        cm_payload[18],
        cm_payload[19],
    ]);
    assert_eq!(cm_game_id, 1615);
    let cm_instance_id = u64::from_le_bytes([
        cm_payload[24],
        cm_payload[25],
        cm_payload[26],
        cm_payload[27],
        cm_payload[28],
        cm_payload[29],
        cm_payload[30],
        cm_payload[31],
    ]);
    assert_eq!(cm_instance_id, 1282927737);
}
