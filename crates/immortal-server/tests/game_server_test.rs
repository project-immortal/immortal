// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Loopback Integration Tests for GameServer
//! Validates Tokio UdpSocket exchange, legacy CPackUdp framing, authentic UE3 / PComNetConn
//! 7-stage bit-packed UDP handshake, bounded Actor Channel deferral (`UNK-UDP-004`), and
//! graceful daemon shutdown.

use immortal_core::ChampionId;
use immortal_net::{
    ue3_handshake_crc, Bunch, ControlMessage, HelloRecvReply, HelloSend, PingRecv, PingSend,
    Ue3ChannelType, Ue3Packet, ACTOR_CHANNEL_INDEX, CONTROL_CHANNEL_INDEX, CPACK_OP_BUNCH,
    DEFAULT_ENGINE_MIN_NET_VERSION, DEFAULT_ENGINE_NET_VERSION, DEFAULT_GAME_CLASS,
    DEFAULT_HMAC_KEY, DEFAULT_SHOOTING_RANGE_LEVEL, PCOM_PREFIX_LEN,
};
use immortal_server::{
    GameServer, GameServerConfig, ReplicationPayload, DEVICE_FERNANDO_FLAME_LANCE,
    FERNANDO_DEFAULT_TEAM,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test]
async fn test_game_server_loopback_integration() {
    let config = GameServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    };
    let server_handle = GameServer::start(config).expect("Failed to start GameServer");
    let server_addr = server_handle.local_addr();

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client UdpSocket");
    client_socket
        .connect(server_addr)
        .await
        .expect("Failed to connect client to GameServer");

    let mut buf = [0u8; 2048];

    // 1. Legacy CPackUdp HelloSend -> HelloRecvReply
    let hello_bytes = HelloSend::build(DEFAULT_HMAC_KEY, 1337, None, 650);
    client_socket
        .send(&hello_bytes)
        .await
        .expect("Failed to send HelloSend");

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for HelloRecvReply")
        .expect("Recv error");
    let hello_reply = HelloRecvReply::decode(&buf[..n]).expect("Failed to decode HelloRecvReply");
    assert_eq!(hello_reply.negotiated_mtu, 1414);

    // 2. Legacy CPackUdp PingSend -> PingRecv
    let ping = PingSend::new(101, 55555, true);
    client_socket
        .send(&ping.encode())
        .await
        .expect("Failed to send PingSend");

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for PingRecv")
        .expect("Recv error");
    let ping_reply = PingRecv::decode(&buf[..n]).expect("Failed to decode PingRecv");
    assert_eq!(ping_reply.sequence, 101);
    assert_eq!(ping_reply.client_timestamp, 55555);

    // 3. Channel 0 NMT_Hello (3x u32) -> NMT_Challenge (1-based ChSeq = 1)
    let nmt_hello = ControlMessage::Hello {
        min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
        net_ver: DEFAULT_ENGINE_NET_VERSION,
        is_little_endian: 1,
    };
    let hello_bunch = Bunch::control(1, nmt_hello.encode());
    client_socket
        .send(&hello_bunch.encode_cpack_udp().unwrap())
        .await
        .expect("Failed to send NMT_Hello bunch");

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for NMT_Challenge")
        .expect("Recv error");
    assert_eq!(buf[0], CPACK_OP_BUNCH);
    let challenge_bunch = Bunch::decode_cpack_udp(&buf[..n]).expect("Decode challenge bunch");
    assert_eq!(challenge_bunch.header.ch_index, CONTROL_CHANNEL_INDEX);
    assert_eq!(challenge_bunch.header.ch_sequence, 1);
    assert_eq!(
        ControlMessage::decode(&challenge_bunch.data).unwrap(),
        ControlMessage::Challenge {
            challenge_id: 0,
            challenge: "IMMORTAL".to_string(),
        }
    );

    // 4. Channel 0 NMT_Login -> bare NMT_Welcome (ChSeq = 2)
    let login_bunch = Bunch::control(
        2,
        ControlMessage::Login {
            client_response: "0".to_string(),
            url: "Shootingrange_P?Name=Player".to_string(),
            unique_id: 10001,
            portal_id: 0,
        }
        .encode(),
    );
    client_socket
        .send(&login_bunch.encode_cpack_udp().unwrap())
        .await
        .expect("Failed to send NMT_Login");

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for NMT_Welcome")
        .expect("Recv error");
    assert_eq!(buf[0], CPACK_OP_BUNCH);
    let welcome_bunch = Bunch::decode_cpack_udp(&buf[..n]).expect("Decode welcome bunch");
    assert_eq!(welcome_bunch.header.ch_sequence, 2);
    assert_eq!(
        ControlMessage::decode(&welcome_bunch.data).unwrap(),
        ControlMessage::Welcome {
            level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
            game_name: DEFAULT_GAME_CLASS.to_string(),
        }
    );

    // 5. Channel 0 NMT_Join -> Actor Channel 3 Open (seq 1) + Spawn Fernando (seq 2) + Delta (seq 3)
    let join_bunch = Bunch::control(3, ControlMessage::Join.encode());
    client_socket
        .send(&join_bunch.encode_cpack_udp().unwrap())
        .await
        .expect("Failed to send NMT_Join");

    let mut received_bunches = Vec::new();
    for _ in 0..3 {
        let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
            .await
            .expect("Timeout waiting for replication bunch")
            .expect("Recv error");
        assert_eq!(buf[0], CPACK_OP_BUNCH);
        received_bunches.push(Bunch::decode_cpack_udp(&buf[..n]).expect("Decode bunch"));
    }

    assert_eq!(received_bunches[0].header.ch_index, ACTOR_CHANNEL_INDEX);
    assert_eq!(received_bunches[0].header.ch_sequence, 1);
    assert!(received_bunches[0].header.flags.b_open);

    assert_eq!(received_bunches[1].header.ch_index, ACTOR_CHANNEL_INDEX);
    assert_eq!(received_bunches[1].header.ch_sequence, 2);
    let spawn_payload =
        ReplicationPayload::decode(&received_bunches[1].data).expect("Decode spawn");
    match spawn_payload {
        ReplicationPayload::SpawnActor {
            champion_id,
            weapon_device_id,
            team,
            class_name,
            location,
            health,
            ..
        } => {
            assert_eq!(champion_id, ChampionId::Fernando);
            assert_eq!(weapon_device_id, DEVICE_FERNANDO_FLAME_LANCE);
            assert_eq!(team, FERNANDO_DEFAULT_TEAM);
            assert_eq!(class_name, "TgPawn_Fernando");
            assert_eq!(location.x, 0.0);
            assert_eq!(location.y, 0.0);
            assert_eq!(location.z, 100.0);
            assert_eq!(health, 4600.0);
        }
        other => panic!("Expected SpawnActor, found {:?}", other),
    }

    // 6. Actor Channel 3 roundtrip
    let actor_input = Bunch::actor(4, false, vec![0x03, 0x0A, 0x00, 0x00, 0x00]);
    client_socket
        .send(&actor_input.encode_cpack_udp().unwrap())
        .await
        .expect("Failed to send actor input bunch");

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for actor transform delta response")
        .expect("Recv error");
    assert_eq!(buf[0], CPACK_OP_BUNCH);
    let delta_bunch = Bunch::decode_cpack_udp(&buf[..n]).expect("Failed to decode delta bunch");
    assert_eq!(delta_bunch.header.ch_index, ACTOR_CHANNEL_INDEX);

    server_handle
        .shutdown()
        .await
        .expect("Graceful shutdown must complete successfully");
}

#[tokio::test]
async fn test_game_server_pcom_driver_loopback_integration() {
    let config = GameServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    };
    let server_handle = GameServer::start(config).expect("Failed to start GameServer");
    let server_addr = server_handle.local_addr();

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client UdpSocket");
    client_socket
        .connect(server_addr)
        .await
        .expect("Failed to connect client to GameServer");

    let mut buf = [0u8; 2048];
    let prefix: [u8; PCOM_PREFIX_LEN] = [0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6];

    // 1. Send exact Flight 034 Packet 0 (NMT_HandshakeStart 0x1A, platform=0x40)
    let pkt0_wire: &[u8] = &[
        0x00, 0x0C, 0xCE, 0x31, 0xC6, 0xF6, 0x00, 0x80, 0x05, 0x40, 0x00, 0x41, 0x01, 0x1A, 0x40,
        0x00, 0x00, 0x00, 0x01,
    ];
    client_socket.send(pkt0_wire).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for NMT_HandshakeChallenge")
        .unwrap();
    let s0 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s0.pcom_prefix, prefix);
    assert_eq!(s0.packet_id, 0);
    assert_eq!(s0.acks, vec![0]);
    assert_eq!(s0.bunches.len(), 1);
    assert_eq!(s0.bunches[0].header.ch_type, Ue3ChannelType::Control);
    assert_eq!(s0.bunches[0].header.ch_sequence, 1);
    let challenge = match ControlMessage::decode(&s0.bunches[0].data).unwrap() {
        ControlMessage::HandshakeChallenge { challenge } => challenge,
        other => panic!("Expected HandshakeChallenge, got {:?}", other),
    };

    // 2. NMT_HandshakeResponse (0x1C) -> NMT_HandshakeComplete (0x1D)
    let mut c1 = Ue3Packet::new(prefix, 1);
    c1.acks.push(0);
    c1.bunches.push(Bunch::control(
        2,
        ControlMessage::HandshakeResponse {
            crc_response: ue3_handshake_crc(challenge),
        }
        .encode(),
    ));
    client_socket.send(&c1.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s1 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s1.packet_id, 1);
    assert_eq!(s1.acks, vec![1]);
    assert_eq!(
        ControlMessage::decode(&s1.bunches[0].data).unwrap(),
        ControlMessage::HandshakeComplete
    );

    // 3. NMT_ServerAuthRequest (0x20) -> NMT_ClientAuthRequest(0) (0x1F)
    let mut c2 = Ue3Packet::new(prefix, 2);
    c2.acks.push(1);
    c2.bunches.push(Bunch::control(
        3,
        ControlMessage::ServerAuthRequest.encode(),
    ));
    client_socket.send(&c2.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s2 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s2.packet_id, 2);
    assert_eq!(s2.acks, vec![2]);
    assert_eq!(
        ControlMessage::decode(&s2.bunches[0].data).unwrap(),
        ControlMessage::client_auth_request_bypass()
    );

    // 4. NMT_Hello (0x00) -> NMT_Challenge (0x03)
    let mut c3 = Ue3Packet::new(prefix, 3);
    c3.acks.push(2);
    c3.bunches.push(Bunch::control(
        4,
        ControlMessage::Hello {
            min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
            net_ver: DEFAULT_ENGINE_NET_VERSION,
            is_little_endian: 1,
        }
        .encode(),
    ));
    client_socket.send(&c3.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s3 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s3.packet_id, 3);
    assert_eq!(s3.acks, vec![3]);
    assert_eq!(
        ControlMessage::decode(&s3.bunches[0].data).unwrap(),
        ControlMessage::Challenge {
            challenge_id: 0,
            challenge: "IMMORTAL".to_string(),
        }
    );

    // 5. Packed NMT_Netspeed (0x04) + NMT_Login (0x05) -> bare NMT_Welcome (0x01)
    let mut c4 = Ue3Packet::new(prefix, 4);
    c4.acks.push(3);
    c4.bunches.push(Bunch::control(
        5,
        ControlMessage::NetSpeed { rate: 24000 }.encode(),
    ));
    c4.bunches.push(Bunch::control(
        6,
        ControlMessage::Login {
            client_response: "0".to_string(),
            url: "Shootingrange_P?Name=Player?Team=0".to_string(),
            unique_id: 8_302_401,
            portal_id: 0,
        }
        .encode(),
    ));
    client_socket.send(&c4.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s4 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s4.packet_id, 4);
    assert_eq!(s4.acks, vec![4]);
    assert_eq!(s4.bunches.len(), 1);
    assert_eq!(
        ControlMessage::decode(&s4.bunches[0].data).unwrap(),
        ControlMessage::Welcome {
            level_name: DEFAULT_SHOOTING_RANGE_LEVEL.to_string(),
            game_name: DEFAULT_GAME_CLASS.to_string(),
        }
    );

    // 6. NMT_Join (0x09) -> ACK only, zero premature Actor Channel bunches
    let mut c5 = Ue3Packet::new(prefix, 5);
    c5.acks.push(4);
    c5.bunches
        .push(Bunch::control(7, ControlMessage::Join.encode()));
    client_socket.send(&c5.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s5 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s5.packet_id, 5);
    assert_eq!(s5.acks, vec![5]);
    assert!(s5.bunches.is_empty());

    // 7. Client sends NMT_MapLoaded (0x2A) -> triggers initial Actor Channel replication
    let mut c7 = Ue3Packet::new(prefix, 7);
    c7.acks.push(5);
    c7.bunches.push(Bunch::control(8, ControlMessage::MapLoaded.encode()));
    client_socket.send(&c7.encode().unwrap()).await.unwrap();

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for Actor Channel replication bunches")
        .unwrap();
    let s7 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s7.packet_id, 6);
    assert_eq!(s7.acks, vec![7]);
    assert!(!s7.bunches.is_empty(), "MapLoaded must trigger replication bunches");

    // Verify Channel 3 Open bunch
    assert_eq!(s7.bunches[0].header.ch_index, ACTOR_CHANNEL_INDEX);
    assert!(s7.bunches[0].header.flags.b_open);
    assert_eq!(s7.bunches[0].header.ch_sequence, 1);

    // Verify TgPlayerController possession bunch
    assert_eq!(s7.bunches[1].header.ch_index, ACTOR_CHANNEL_INDEX);
    let p_possess = ReplicationPayload::decode(&s7.bunches[1].data).unwrap();
    match p_possess {
        ReplicationPayload::PossessPlayer { controller_name, local_player_name, .. } => {
            assert_eq!(controller_name, "TgPlayerController_1");
            assert_eq!(local_player_name, "TgLocalPlayer_0");
        }
        other => panic!("Expected PossessPlayer, got {:?}", other),
    }

    // Verify TgPawn_Fernando replication bunch
    assert_eq!(s7.bunches[2].header.ch_index, ACTOR_CHANNEL_INDEX);
    let p_pawn = ReplicationPayload::decode(&s7.bunches[2].data).unwrap();
    match p_pawn {
        ReplicationPayload::SpawnActor { champion_id, health, weapon_device_id, .. } => {
            assert_eq!(champion_id, ChampionId::Fernando);
            assert_eq!(health, 4600.0);
            assert_eq!(weapon_device_id, 10774);
        }
        other => panic!("Expected SpawnActor, got {:?}", other),
    }

    // Verify TgDevice_FernandoInhand_0 weapon replication bunch
    assert_eq!(s7.bunches[3].header.ch_index, ACTOR_CHANNEL_INDEX);
    let p_device = ReplicationPayload::decode(&s7.bunches[3].data).unwrap();
    match p_device {
        ReplicationPayload::SpawnDevice { device_id, device_name, .. } => {
            assert_eq!(device_id, 10774);
            assert_eq!(device_name, "TgDevice_FernandoInhand_0");
        }
        other => panic!("Expected SpawnDevice, got {:?}", other),
    }

    // Verify bot opponent replication (Channel 4)
    assert_eq!(s7.bunches[4].header.ch_index, 4);
    assert!(s7.bunches[4].header.flags.b_open);

    // 8. Pure ACK packet -> zero reply (no ACK storm)
    let mut c8 = Ue3Packet::new(prefix, 8);
    c8.acks.push(6);
    client_socket.send(&c8.encode().unwrap()).await.unwrap();
    let storm_res = timeout(Duration::from_millis(100), client_socket.recv(&mut buf)).await;
    assert!(
        storm_res.is_err(),
        "Pure ACK packet must not elicit a reply packet"
    );

    server_handle
        .shutdown()
        .await
        .expect("Graceful shutdown must complete successfully");
}

#[tokio::test]
async fn test_dedicated_server_handshake_and_actor_replication() {
    use immortal_net::{DedicatedControlFrame, EXUDP_MAX_PACKET_BITS, PcomPrefix};

    let config = GameServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    };
    let server_handle = GameServer::start(config).expect("Failed to start GameServer");
    let server_addr = server_handle.local_addr();

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client UdpSocket");
    client_socket
        .connect(server_addr)
        .await
        .expect("Failed to connect client to GameServer");

    let mut buf = [0u8; 2048];

    // 1. Client Hello (570B unsequenced) -> 46B Server Challenge
    let mut client_hello = vec![0u8; 570];
    client_hello[8..10].copy_from_slice(&[0x00, 0x10]);
    client_hello[10..16].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    client_hello[22..24].copy_from_slice(&72u16.to_le_bytes());
    client_hello[538..570].copy_from_slice(&[0xCC; 32]);

    client_socket.send(&client_hello).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for ServerChallenge")
        .unwrap();
    assert_eq!(n, 46);
    let challenge_frame = DedicatedControlFrame::parse(&buf[..n]).expect("Parse ServerChallenge");
    let (server_token, challenge_flag) = match challenge_frame {
        DedicatedControlFrame::ServerChallenge { handshake_flag, server_cookie, .. } => {
            (server_cookie, handshake_flag)
        }
        other => panic!("Expected ServerChallenge, got {:?}", other),
    };
    assert_eq!(challenge_flag, 0x5D);
    assert_eq!(server_token, [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F]);

    // 2. PMTU Probe (1440B unsequenced) -> 1440B reply
    let mut pmtu = vec![0u8; 1440];
    pmtu[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    pmtu[8..10].copy_from_slice(&[0x00, 0x10]);
    pmtu[10..16].copy_from_slice(&[0x25, 0x3E, 0x4E, 0xED, 0xA3, 0x7C]);
    pmtu[16..22].copy_from_slice(&[0xFB, 0x73, 0x09, 0xF1, 0x45, 0x49]);

    client_socket.send(&pmtu).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for PMTU probe reply")
        .unwrap();
    assert_eq!(n, 1440);

    // 3. Sequenced Seq 1 with 6-byte session token barrier: NMT_MapLoaded (0x2A)
    let prefix = PcomPrefix::dedicated_sequenced(1, Some(server_token));
    let mut c1 = Ue3Packet::new_with_prefix(prefix, 1);
    c1.bunches.push(Bunch::control(1, ControlMessage::MapLoaded.encode()));

    let wire1 = c1.encode_pcom(EXUDP_MAX_PACKET_BITS).unwrap();
    client_socket.send(&wire1).await.unwrap();

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for replication reply")
        .unwrap();

    let s1 = Ue3Packet::decode_with_max_bits(&buf[..n], EXUDP_MAX_PACKET_BITS).expect("Decode dedicated server reply");
    assert_eq!(s1.pcom_prefix.sequence(), Some(1));
    assert_eq!(s1.pcom_prefix.session_token(), Some(&server_token));
    assert_eq!(s1.acks, vec![1]);
    assert!(!s1.bunches.is_empty(), "MapLoaded must trigger replication bunches");

    // Verify Fernando and Channel 3 bunches
    assert_eq!(s1.bunches[0].header.ch_index, ACTOR_CHANNEL_INDEX);
    assert!(s1.bunches[0].header.flags.b_open);

    server_handle.shutdown().await.unwrap();
}
