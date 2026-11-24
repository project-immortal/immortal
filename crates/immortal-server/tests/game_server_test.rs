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
    ue3_handshake_crc, ActorBunch, ActorBunchCodec, BitWriter, Bunch, ControlMessage,
    HelloRecvReply, HelloSend, NetName, NetValue, ObjectRef, PingRecv, PingSend, ReplicatedItem,
    RpcParamValue, Ue3ChannelType, Ue3Packet, ACTOR_CHANNEL_INDEX, CONTROL_CHANNEL_INDEX,
    CPACK_OP_BUNCH, DEFAULT_ENGINE_MIN_NET_VERSION, DEFAULT_ENGINE_NET_VERSION, DEFAULT_HMAC_KEY,
    PCOM_PREFIX_LEN,
};
use immortal_server::{
    game_server::{DEFAULT_WELCOME_GAME_CLASS, DEFAULT_WELCOME_LEVEL},
    ActorReplicationSchemas, GameServer, GameServerConfig, ReplicationPayload,
    ARCHWAY_FERNANDO_SPAWN_X, ARCHWAY_FERNANDO_SPAWN_Y, ARCHWAY_FERNANDO_SPAWN_Z,
    ARCHWAY_FERNANDO_YAW, BOT_PRI_CHANNEL_INDEX, DEVICE_FERNANDO_FLAME_LANCE,
    FERNANDO_DEFAULT_TEAM, GRI_CHANNEL_INDEX, PHYS_WALKING, PLAYER_CONTROLLER_CHANNEL_INDEX,
    PLAYER_PAWN_CHANNEL_INDEX, PRI_CHANNEL_INDEX, ROLE_AUTONOMOUS_PROXY, STATE_NAME_SPECTATING,
    TASK_FORCE_CHANNEL_INDEX, TG_GAME_TYPE_SHOOTING_RANGE,
};
use std::collections::BTreeMap;
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
            level_name: DEFAULT_WELCOME_LEVEL.to_string(),
            game_name: DEFAULT_WELCOME_GAME_CLASS.to_string(),
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

    // 5. Packed NMT_Netspeed (0x04) + NMT_Login (0x05) -> NMT_UsesOpt + NMT_DownloadMgr + NMT_Welcome
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
    let mut welcome_msgs = Vec::new();
    let mut last_srv_pkt_id = 3u16;
    while !welcome_msgs
        .iter()
        .any(|m| matches!(m, ControlMessage::Welcome { .. }))
    {
        let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
            .await
            .expect("Timeout waiting for NMT_UsesOpt/Welcome")
            .unwrap();
        let pkt = Ue3Packet::decode(&buf[..n]).unwrap();
        last_srv_pkt_id = pkt.packet_id;
        for b in &pkt.bunches {
            welcome_msgs.extend(ControlMessage::decode_all(&b.data, b.num_bits).unwrap());
        }
    }
    assert!(welcome_msgs
        .iter()
        .any(|m| matches!(m, ControlMessage::UsesOpt { .. })));
    assert!(welcome_msgs.contains(&ControlMessage::DownloadMgr {
        class_name: "Engine.ChannelDownload".to_string(),
        params: "Enabled".to_string(),
        compression: 0,
    }));
    assert_eq!(
        welcome_msgs.last().unwrap(),
        &ControlMessage::Welcome {
            level_name: DEFAULT_WELCOME_LEVEL.to_string(),
            game_name: DEFAULT_WELCOME_GAME_CLASS.to_string(),
        }
    );

    // 6. NMT_Join (0x09) without NMT_Have -> ACK only, zero premature Actor Channel bunches
    let mut c5 = Ue3Packet::new(prefix, 5);
    c5.acks.push(last_srv_pkt_id);
    c5.bunches
        .push(Bunch::control(7, ControlMessage::Join.encode()));
    client_socket.send(&c5.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s5 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s5.acks, vec![5]);
    assert!(s5.bunches.is_empty());

    // 7. Client sends NMT_MapLoaded (0x2A) without NMT_Have -> ACK only (holds Actor opens until NMT_Have)
    let mut c7 = Ue3Packet::new(prefix, 7);
    c7.acks.push(s5.packet_id);
    c7.bunches
        .push(Bunch::control(8, ControlMessage::MapLoaded.encode()));
    client_socket.send(&c7.encode().unwrap()).await.unwrap();

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for NMT_MapLoaded ACK")
        .unwrap();
    let s7 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s7.acks, vec![7]);
    assert!(
        s7.bunches.is_empty(),
        "Actor Channel opens must wait for required NMT_Have acknowledgments"
    );

    // 8. Pure ACK packet -> zero reply (no ACK storm)
    let mut c8 = Ue3Packet::new(prefix, 8);
    c8.acks.push(s7.packet_id);
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
async fn test_dedicated_server_handshake_and_map_loaded_hold() {
    use immortal_net::{DedicatedControlFrame, PcomPrefix, EXUDP_MAX_PACKET_BITS};

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

    // 1. Client Hello (570B unsequenced) -> 46B Server Challenge with dynamic session cookie
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
        DedicatedControlFrame::ServerChallenge {
            handshake_flag,
            server_cookie,
            ..
        } => (server_cookie, handshake_flag),
        other => panic!("Expected ServerChallenge, got {:?}", other),
    };
    assert_eq!(challenge_flag, 0x5D);
    // Must NOT fall back to hardcoded CAP-03 capture token
    assert_ne!(server_token, [0x78, 0x7E, 0x10, 0x7B, 0x9A, 0x8F]);

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

    // 3. Sequenced Seq 1 with dynamic 6-byte session token: NMT_MapLoaded (0x2A) -> ACK only
    let prefix = PcomPrefix::dedicated_sequenced(1, Some(server_token));
    let mut c1 = Ue3Packet::new_with_prefix(prefix, 1);
    c1.bunches
        .push(Bunch::control(1, ControlMessage::MapLoaded.encode()));

    let wire1 = c1.encode_pcom(EXUDP_MAX_PACKET_BITS).unwrap();
    client_socket.send(&wire1).await.unwrap();

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for dedicated ACK reply")
        .unwrap();

    let s1 = Ue3Packet::decode_with_max_bits(&buf[..n], EXUDP_MAX_PACKET_BITS)
        .expect("Decode dedicated server reply");
    assert_eq!(s1.pcom_prefix.sequence(), Some(1));
    assert_eq!(s1.pcom_prefix.session_token(), Some(&server_token));
    assert_eq!(s1.acks, vec![1]);
    assert!(
        s1.bunches.is_empty(),
        "Claim 16 hold invariant: MapLoaded must NOT emit invented ReplicationPayload bunches"
    );

    server_handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_exudp0_full_handshake_and_uactor_channel_opens_loopback() {
    run_exudp0_full_handshake_case(GameServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        upk_dir: None, // Hermetic path
        ..Default::default()
    })
    .await;

    // Also verify auto-detected default config (uses real UPKs when present on disk)
    run_exudp0_full_handshake_case(GameServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    })
    .await;
}

async fn run_exudp0_full_handshake_case(config: GameServerConfig) {
    let expected_schemas = match config.upk_dir.as_deref() {
        Some(dir) => ActorReplicationSchemas::from_upk_dir(dir)
            .expect("Load ActorReplicationSchemas from upk_dir"),
        None => ActorReplicationSchemas::hermetic(),
    };
    let expected_pkg_count = expected_schemas.manifest.entries.len();

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
    let mut client_pkt_id: u16 = 0;
    let mut ctrl_seq: u32 = 1;

    // 1. 0x1A NMT_HandshakeStart -> 0x1B NMT_HandshakeChallenge
    let mut c0 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c0.bunches.push(Bunch::control_open(
        ctrl_seq,
        ControlMessage::HandshakeStart {
            platform_flag: 0x40,
        }
        .encode(),
    ));
    ctrl_seq += 1;
    client_socket.send(&c0.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s0 = Ue3Packet::decode(&buf[..n]).unwrap();
    let challenge = match ControlMessage::decode(&s0.bunches[0].data).unwrap() {
        ControlMessage::HandshakeChallenge { challenge } => challenge,
        other => panic!("Expected 0x1B HandshakeChallenge, got {:?}", other),
    };

    // 2. 0x1C NMT_HandshakeResponse -> 0x1D NMT_HandshakeComplete
    let mut c1 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c1.acks.push(s0.packet_id);
    c1.bunches.push(Bunch::control(
        ctrl_seq,
        ControlMessage::HandshakeResponse {
            crc_response: ue3_handshake_crc(challenge),
        }
        .encode(),
    ));
    ctrl_seq += 1;
    client_socket.send(&c1.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s1 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(
        ControlMessage::decode(&s1.bunches[0].data).unwrap(),
        ControlMessage::HandshakeComplete
    );

    // 3. 0x20 NMT_ServerAuthRequest -> 0x1F NMT_ClientAuthRequest(0)
    let mut c2 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c2.acks.push(s1.packet_id);
    c2.bunches.push(Bunch::control(
        ctrl_seq,
        ControlMessage::ServerAuthRequest.encode(),
    ));
    ctrl_seq += 1;
    client_socket.send(&c2.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s2 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(
        ControlMessage::decode(&s2.bunches[0].data).unwrap(),
        ControlMessage::client_auth_request_bypass()
    );

    // 4. 0x00 NMT_Hello -> 0x03 NMT_Challenge
    let mut c3 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c3.acks.push(s2.packet_id);
    c3.bunches.push(Bunch::control(
        ctrl_seq,
        ControlMessage::Hello {
            min_net_ver: DEFAULT_ENGINE_MIN_NET_VERSION,
            net_ver: DEFAULT_ENGINE_NET_VERSION,
            is_little_endian: 1,
        }
        .encode(),
    ));
    ctrl_seq += 1;
    client_socket.send(&c3.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s3 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert!(matches!(
        ControlMessage::decode(&s3.bunches[0].data).unwrap(),
        ControlMessage::Challenge { .. }
    ));

    // 5. 0x04 NMT_Netspeed + 0x05 NMT_Login(UniqueId=0) ->
    //    NMT_UsesOpt (manifest) + NMT_DownloadMgr + NMT_Welcome
    let mut c4 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c4.acks.push(s3.packet_id);
    c4.bunches.push(Bunch::control(
        ctrl_seq,
        ControlMessage::NetSpeed { rate: 24000 }.encode(),
    ));
    ctrl_seq += 1;
    c4.bunches.push(Bunch::control(
        ctrl_seq,
        ControlMessage::Login {
            client_response: "0".to_string(),
            url: "Shootingrange_P?Name=Player?Team=0?game=TgGame.TgGame_Paladins".to_string(),
            unique_id: 0,
            portal_id: 0,
        }
        .encode(),
    ));
    ctrl_seq += 1;
    client_socket.send(&c4.encode().unwrap()).await.unwrap();

    let mut received_guids: Vec<[u32; 4]> = Vec::new();
    let mut saw_download_mgr = false;
    let mut saw_welcome = false;
    let mut acks_to_send = Vec::new();

    while !saw_welcome {
        let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
            .await
            .expect("Timeout waiting for NMT_UsesOpt / NMT_DownloadMgr / NMT_Welcome")
            .unwrap();
        let pkt = Ue3Packet::decode(&buf[..n]).unwrap();
        acks_to_send.push(pkt.packet_id);
        for b in &pkt.bunches {
            for msg in ControlMessage::decode_all(&b.data, b.num_bits).unwrap() {
                match msg {
                    ControlMessage::UsesOpt { guid, .. } => received_guids.push(guid),
                    ControlMessage::DownloadMgr {
                        class_name,
                        params,
                        compression,
                    } => {
                        assert_eq!(class_name, "Engine.ChannelDownload");
                        assert_eq!(params, "Enabled");
                        assert_eq!(compression, 0);
                        saw_download_mgr = true;
                    }
                    ControlMessage::Welcome {
                        level_name,
                        game_name,
                    } => {
                        assert_eq!(level_name, "shootingrange_p");
                        assert_eq!(game_name, "TgGame.TgGame_Paladins");
                        saw_welcome = true;
                    }
                    other => panic!("Unexpected post-login control msg: {:?}", other),
                }
            }
        }
    }
    assert_eq!(received_guids.len(), expected_pkg_count);
    assert!(saw_download_mgr);
    assert!(saw_welcome);

    // 6. Send 0x08 NMT_Have for every package GUID (packed in one bunch)
    let mut have_writer = BitWriter::new();
    for guid in &received_guids {
        ControlMessage::Have {
            guid: *guid,
            generation: 1,
        }
        .encode_into(&mut have_writer)
        .unwrap();
    }
    let have_bits = have_writer.num_bits();
    let have_bunch = Bunch::with_bits(
        immortal_net::BunchHeader {
            ch_index: CONTROL_CHANNEL_INDEX,
            ch_type: Ue3ChannelType::Control,
            flags: immortal_net::BunchFlags {
                b_open: false,
                b_close: false,
                b_reliable: true,
                b_partial: false,
            },
            ch_sequence: ctrl_seq,
        },
        have_bits,
        have_writer.into_bytes(),
    );
    ctrl_seq += 1;

    let mut c5 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c5.acks.append(&mut acks_to_send);
    c5.bunches.push(have_bunch);
    client_socket.send(&c5.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s5 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert!(s5.bunches.is_empty());

    // 7. Send 0x2A NMT_MapLoaded
    let mut c6 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c6.acks.push(s5.packet_id);
    c6.bunches
        .push(Bunch::control(ctrl_seq, ControlMessage::MapLoaded.encode()));
    ctrl_seq += 1;
    client_socket.send(&c6.encode().unwrap()).await.unwrap();
    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let s6 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert!(s6.bunches.is_empty());

    // 8. Send 0x09 NMT_Join -> receive authentic UActorChannel opens (ch=3, 57, 4, 61, 80, 81) + 2 follow-ups
    let mut c7 = Ue3Packet::new(prefix, client_pkt_id);
    client_pkt_id += 1;
    c7.acks.push(s6.packet_id);
    c7.bunches
        .push(Bunch::control(ctrl_seq, ControlMessage::Join.encode()));
    client_socket.send(&c7.encode().unwrap()).await.unwrap();

    let mut actor_open_bunches = BTreeMap::new();
    let mut actor_followup_bunches = BTreeMap::new();
    let mut last_server_pkt_id = s6.packet_id;
    while actor_open_bunches.len() < 6 || actor_followup_bunches.len() < 2 {
        let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
            .await
            .expect("Timeout waiting for UActorChannel opens (ch=3, 4, 57, 61, 80, 81)")
            .unwrap();
        let pkt = Ue3Packet::decode(&buf[..n]).unwrap();
        last_server_pkt_id = pkt.packet_id;
        for b in pkt.bunches {
            assert_eq!(b.header.ch_type, Ue3ChannelType::Actor);
            assert!(b.header.flags.b_reliable);
            if b.header.flags.b_open {
                actor_open_bunches.insert(b.header.ch_index, b);
            } else {
                actor_followup_bunches.insert(b.header.ch_index, b);
            }
        }
    }

    for ch in [
        PLAYER_CONTROLLER_CHANNEL_INDEX,
        PLAYER_PAWN_CHANNEL_INDEX,
        TASK_FORCE_CHANNEL_INDEX,
        BOT_PRI_CHANNEL_INDEX,
        PRI_CHANNEL_INDEX,
        GRI_CHANNEL_INDEX,
    ] {
        assert!(
            actor_open_bunches.contains_key(&ch),
            "Missing open bunch for ch={ch}"
        );
    }

    // Decode all 6 opens + 2 follow-ups via ActorBunchCodec (asserting 0 leftover bits)
    let (pc_cache, pc_layout) = expected_schemas
        .for_channel(PLAYER_CONTROLLER_CHANNEL_INDEX)
        .unwrap();
    let pc_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches
            .get(&PLAYER_CONTROLLER_CHANNEL_INDEX)
            .unwrap(),
        pc_cache,
        Some(pc_layout),
    )
    .expect("ch=3 TgPlayerController must decode with 0 leftover bits");
    let pc_hdr = pc_decoded.open_header.as_ref().unwrap();
    assert_eq!(pc_hdr.net_player_index, Some(0));
    assert_eq!(
        pc_hdr.object_ref,
        ObjectRef::Static(expected_schemas.archetypes.tg_player_controller)
    );
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Bool(true), .. } if name == "bCollideWorld"
    )));
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Enum(v), .. }
            if name == "Role" && *v == ROLE_AUTONOMOUS_PROXY
    )));
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Bool(true), .. } if name == "bNetOwner"
    )));
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(1), .. } if name == "r_bInputEnabled"
    )));
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Rpc { name, params, .. }
            if name == "ClientSetHUD"
                && matches!(
                    params.first().and_then(|p| p.values.as_ref()).and_then(|v| v.first()),
                    Some(NetValue::Object(ObjectRef::Static(id)))
                        if *id == expected_schemas.archetypes.tg_hud
                )
    )));
    assert!(pc_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Rpc { name, params, .. }
            if name == "ClientGotoState"
                && matches!(
                    params.first().and_then(|p| p.values.as_ref()).and_then(|v| v.first()),
                    Some(NetValue::Name(NetName::Hardcoded(state_id)))
                        if *state_id == STATE_NAME_SPECTATING
                )
    )));

    let pc_followup = ActorBunchCodec::decode_bunch(
        actor_followup_bunches
            .get(&PLAYER_CONTROLLER_CHANNEL_INDEX)
            .unwrap(),
        pc_cache,
        None,
    )
    .expect("ch=3 follow-up must decode with 0 leftover bits");
    assert!(pc_followup.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property {
            name,
            value: NetValue::Object(ObjectRef::DynamicChannel(80)),
            ..
        } if name == "PlayerReplicationInfo"
    )));
    assert!(pc_followup.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Float(_), .. } if name == "r_fServerTimeStamp"
    )));

    let (tf_cache, tf_layout) = expected_schemas
        .for_channel(TASK_FORCE_CHANNEL_INDEX)
        .unwrap();
    let tf_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches.get(&TASK_FORCE_CHANNEL_INDEX).unwrap(),
        tf_cache,
        Some(tf_layout),
    )
    .expect("ch=57 TgRepInfo_TaskForce must decode with 0 leftover bits");
    assert_eq!(
        tf_decoded.open_header.as_ref().unwrap().object_ref,
        ObjectRef::Static(expected_schemas.archetypes.tg_rep_info_task_force)
    );
    assert!(tf_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(1), .. } if name == "TeamIndex"
    )));
    assert!(tf_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Byte(1), .. } if name == "r_nTaskForce"
    )));

    let (pawn_cache, pawn_layout) = expected_schemas
        .for_channel(PLAYER_PAWN_CHANNEL_INDEX)
        .unwrap();
    let pawn_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches.get(&PLAYER_PAWN_CHANNEL_INDEX).unwrap(),
        pawn_cache,
        Some(pawn_layout),
    )
    .expect("ch=4 TgPawn_Fernando must decode with 0 leftover bits");
    let pawn_hdr = pawn_decoded.open_header.as_ref().unwrap();
    assert_eq!(
        pawn_hdr.object_ref,
        ObjectRef::Static(expected_schemas.archetypes.tg_pawn_fernando)
    );
    assert_eq!(
        pawn_hdr.location,
        Some([
            ARCHWAY_FERNANDO_SPAWN_X,
            ARCHWAY_FERNANDO_SPAWN_Y,
            ARCHWAY_FERNANDO_SPAWN_Z,
        ])
    );
    assert!(pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(4600), .. } if name == "Health"
    )));
    assert!(pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Float(v), .. }
            if name == "r_fCachedMaxHealth" && (*v - 4600.0).abs() < f32::EPSILON
    )));
    assert!(pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Enum(v), .. }
            if name == "Physics" && *v == PHYS_WALKING
    )));
    assert!(pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Rotator([0, yaw, 0]), .. }
            if name == "Rotation" && *yaw == ARCHWAY_FERNANDO_YAW
    )));
    assert!(pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(12203), .. } if name == "r_nSkinId"
    )));
    assert!(!pawn_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, .. } if name == "Controller"
    )));

    let pawn_followup = ActorBunchCodec::decode_bunch(
        actor_followup_bunches
            .get(&PLAYER_PAWN_CHANNEL_INDEX)
            .unwrap(),
        pawn_cache,
        None,
    )
    .expect("ch=4 follow-up must decode with 0 leftover bits");
    assert!(pawn_followup.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property {
            name,
            value: NetValue::Object(ObjectRef::DynamicChannel(61)),
            ..
        } if name == "PlayerReplicationInfo"
    )));

    let (bot_pri_cache, bot_pri_layout) =
        expected_schemas.for_channel(BOT_PRI_CHANNEL_INDEX).unwrap();
    let bot_pri_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches.get(&BOT_PRI_CHANNEL_INDEX).unwrap(),
        bot_pri_cache,
        Some(bot_pri_layout),
    )
    .expect("ch=61 bot TgRepInfo_Player must decode with 0 leftover bits");
    assert!(bot_pri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Str(s), .. }
            if name == "PlayerName" && s == "Fernando"
    )));
    assert!(bot_pri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Bool(true), .. } if name == "bBot"
    )));

    let (pri_cache, pri_layout) = expected_schemas.for_channel(PRI_CHANNEL_INDEX).unwrap();
    let pri_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches.get(&PRI_CHANNEL_INDEX).unwrap(),
        pri_cache,
        Some(pri_layout),
    )
    .expect("ch=80 TgRepInfo_Player must decode with 0 leftover bits");
    assert!(pri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Str(s), .. }
            if name == "PlayerName" && s == "Player"
    )));
    assert!(pri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(500), .. } if name == "r_nCredits"
    )));
    assert!(pri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Int(500), .. }
            if name == "r_nEarnedCredits"
    )));

    let (gri_cache, gri_layout) = expected_schemas.for_channel(GRI_CHANNEL_INDEX).unwrap();
    let gri_decoded = ActorBunchCodec::decode_bunch(
        actor_open_bunches.get(&GRI_CHANNEL_INDEX).unwrap(),
        gri_cache,
        Some(gri_layout),
    )
    .expect("ch=81 TgRepInfo_Game must decode with 0 leftover bits");
    assert!(gri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Bool(true), .. } if name == "bMatchHasBegun"
    )));
    assert!(gri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property {
            name,
            value: NetValue::Object(ObjectRef::Static(id)),
            ..
        } if name == "GameClass" && *id == expected_schemas.archetypes.tg_game_paladins
    )));
    assert!(gri_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Enum(v), .. }
            if name == "r_GameType" && *v == TG_GAME_TYPE_SHOOTING_RANGE
    )));

    // 9. Send C->S ch=3 ServerSetSpectatorLocation + ServerUpdateCamera after >45ms
    //    and verify server ACKs and emits r_fServerTimeStamp heartbeat cleanly!
    tokio::time::sleep(Duration::from_millis(55)).await;
    let spec_rep = pc_cache
        .fields()
        .find(|f| f.name == "ServerSetSpectatorLocation")
        .unwrap()
        .rep_index;
    let cam_rep = pc_cache
        .fields()
        .find(|f| f.name == "ServerUpdateCamera")
        .unwrap()
        .rep_index;
    let c2s_actor_bunch = ActorBunchCodec::encode_to_bunch(
        PLAYER_CONTROLLER_CHANNEL_INDEX,
        0,
        false,
        pc_cache,
        &ActorBunch {
            open_header: None,
            items: vec![
                ReplicatedItem::Rpc {
                    rep_index: spec_rep,
                    name: "ServerSetSpectatorLocation".to_string(),
                    params: vec![RpcParamValue {
                        name: "NewLoc".to_string(),
                        values: Some(vec![NetValue::Vector([-224.0, 0.0, 203.0])]),
                    }],
                },
                ReplicatedItem::Rpc {
                    rep_index: cam_rep,
                    name: "ServerUpdateCamera".to_string(),
                    params: vec![
                        RpcParamValue {
                            name: "CamLoc".to_string(),
                            values: Some(vec![NetValue::Vector([-474.0, 0.0, 233.0])]),
                        },
                        RpcParamValue {
                            name: "CamPitchAndYaw".to_string(),
                            values: None,
                        },
                    ],
                },
            ],
        },
    )
    .unwrap();

    let mut c8 = Ue3Packet::new(prefix, client_pkt_id);
    c8.acks.push(last_server_pkt_id);
    c8.bunches.push(c2s_actor_bunch);
    client_socket.send(&c8.encode().unwrap()).await.unwrap();

    let n = timeout(Duration::from_millis(500), client_socket.recv(&mut buf))
        .await
        .expect("Timeout waiting for ch=3 ACK + r_fServerTimeStamp heartbeat")
        .unwrap();
    let s8 = Ue3Packet::decode(&buf[..n]).unwrap();
    assert_eq!(s8.acks, vec![client_pkt_id]);
    assert_eq!(s8.bunches.len(), 1);
    assert_eq!(
        s8.bunches[0].header.ch_index,
        PLAYER_CONTROLLER_CHANNEL_INDEX
    );
    assert!(!s8.bunches[0].header.flags.b_reliable);
    let ts_decoded = ActorBunchCodec::decode_bunch(&s8.bunches[0], pc_cache, None)
        .expect("r_fServerTimeStamp heartbeat must decode with 0 leftover bits");
    assert!(ts_decoded.items.iter().any(|it| matches!(
        it,
        ReplicatedItem::Property { name, value: NetValue::Float(v), .. }
            if name == "r_fServerTimeStamp" && *v >= 96.0
    )));

    server_handle.shutdown().await.unwrap();
}
