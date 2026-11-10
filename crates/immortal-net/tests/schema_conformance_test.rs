// SPDX-License-Identifier: Apache-2.0
//! Hermetic Schema Conformance Test Suite (Vector 1).
//! Validates that every MCTS token serialized by `immortal-net` strictly matches
//! the authentic 3,731-entry engine schema extracted from `MctsInterface.dll`.

use immortal_net::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SchemaEntry {
    id: u16,
    name: String,
    type_id: u8,
    type_name: String,
    expected_group: String,
}

fn load_schema() -> Vec<SchemaEntry> {
    let schema_json = include_str!("fixtures/mcts_field_schema.json");
    serde_json::from_str(schema_json).expect("valid mcts_field_schema.json fixture")
}

#[test]
fn test_all_mcts_token_constants_match_engine_schema() {
    let schema = load_schema();
    assert_eq!(
        schema.len(),
        3731,
        "Schema must contain exactly 3731 engine fields"
    );

    // Token ID -> (Expected Name, Expected Type ID, Expected Group Header Mask)
    let expectations: &[(u16, &str, u8, u16)] = &[
        (MCTS_TOKEN_PLAYER_ID, "PLAYER_ID", 9, 0x4000), // Type 9 (INT64)
        (MCTS_TOKEN_BOT_ID, "BOT_ID", 5, 0x3000),       // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_STATUS, "DATA_SET", 13, 0x6000), // Type 13 (ROWSET)
        (MCTS_TOKEN_CHAMPION_ROSTER, "DATA_SET_BOTS", 13, 0x6000), // Type 13 (ROWSET)
        (MCTS_TOKEN_MEMBERS, "DATA_SET_MEMBERS", 13, 0x6000), // Type 13 (ROWSET)
        (MCTS_TOKEN_MAP_GAME_ID, "MAP_GAME_ID", 5, 0x3000), // Type 5 (INT32)
        (MCTS_TOKEN_MAP_INSTANCE_ID, "MAP_INSTANCE_ID", 9, 0x4000), // Type 9 (INT64)
        (MCTS_TOKEN_MATCH_ID, "MATCH_ID", 9, 0x4000),   // Type 9 (INT64)
        (MCTS_TOKEN_MATCH_QUEUE_ID, "MATCH_QUEUE_ID", 9, 0x4000), // Type 9 (INT64)
        (MCTS_TOKEN_PROFILE_ID, "PROFILE_ID", 5, 0x3000), // Type 5 (INT32)
        (MCTS_TOKEN_TIMESTAMP, "REMAINING_SECONDS", 5, 0x3000), // Type 5 (INT32)
        (MCTS_TOKEN_MATCH_LOBBY_STATE, "MATCH_LOBBY_STATE", 5, 0x3000), // Type 5 (INT32)
        (
            MCTS_TOKEN_PLAYER_LOBBY_STATE,
            "PLAYER_LOBBY_STATE",
            5,
            0x3000,
        ), // Type 5 (INT32)
        (MCTS_TOKEN_COMPEL_FLAG, "COMPEL_FLAG", 2, 0x1000), // Type 2 (INT8)
        (MCTS_TOKEN_INVITED_MEMBERS, "DATA_SET_MAP_GAMES", 13, 0x6000), // Type 13 (ROWSET)
        (MCTS_TOKEN_LAUNCH_SECONDS, "LAUNCH_SECONDS", 5, 0x3000), // Type 5 (INT32)
        (MCTS_TOKEN_INVITE_PRIVILEGES, "INVITE_PRIVILEGES", 2, 0x1000), // Type 2 (INT8 / bool bIsBot)
        (
            MCTS_TOKEN_PLAYER_QUEUE_STATE,
            "PLAYER_QUEUE_STATE",
            5,
            0x3000,
        ), // Type 5 (INT32)
        (MCTS_TOKEN_STATUS_CODE, "STATUS_CODE", 5, 0x3000),             // Type 5 (INT32)
        (MCTS_TOKEN_POSITION, "POSITION", 5, 0x3000),                   // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_CATEGORY, "GROUP_TYPE", 5, 0x3000),           // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_STATE, "UI_HINT_VALUE_ID", 5, 0x3000),        // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_ACTIVE, "ACTIVE_FLAG", 12, 0xa000),           // Type 12 (STRING)
        (
            MCTS_TOKEN_MATCH_COMPOSITION,
            "DATA_SET_MATCH_COMPOSITION",
            13,
            0x6000,
        ), // Type 13 (ROWSET)
        (
            MCTS_TOKEN_PORTAL_SESSION_ID,
            "PORTAL_SESSION_ID",
            12,
            0xa000,
        ), // Type 12 (STRING)
        (MCTS_TOKEN_TASK_FORCE, "TASK_FORCE", 5, 0x3000),               // Type 5 (INT32)
    ];

    for &(token, name, type_id, group_mask) in expectations {
        let entry = schema.iter().find(|e| e.id == token).unwrap_or_else(|| {
            panic!("Token {} not found in engine schema", token);
        });
        assert_eq!(entry.name, name, "Token {} name mismatch", token);
        assert_eq!(
            entry.type_id, type_id,
            "Token {} type mismatch (name: {})",
            token, name
        );
        let expected_grp =
            u16::from_str_radix(entry.expected_group.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(
            expected_grp, group_mask,
            "Token {} group mask mismatch",
            token
        );
    }
}

#[test]
fn test_match_status_with_members_frame_schema_conformance() {
    let frame =
        create_mcts_match_status_with_members_frame(434, 878850364, 8, 0, 5, 4, 8302401, 2285);

    // Frame must have valid header [len, 0x0000]
    let payload_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
    assert_eq!(frame.len(), 4 + payload_len);
    assert_eq!(payload_len, 112);

    let payload = &frame[4..];
    assert_eq!(payload[0], 0x00);
    assert_eq!(
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
        MCTS_FUNCTION_ID_MATCH_STATUS
    );

    // Root row fields: 8
    let total_fields = u16::from_le_bytes([payload[5], payload[6]]);
    assert_eq!(total_fields, 8);

    // Group 0x3000: 5 fields (Token 1342, 1690, 1344, 2191, 1053) - all Type 5 (4 bytes)
    let grp4 = u16::from_le_bytes([payload[7], payload[8]]);
    assert_eq!(grp4, 0x3005);
    assert_eq!(
        u16::from_le_bytes([payload[17], payload[18]]),
        MCTS_TOKEN_STATUS_CODE
    );

    // Group 0x4000: 2 fields (Token 700 MATCH_ID, Token 703 MATCH_QUEUE_ID) - all Type 9 (8 bytes)
    let grp8 = u16::from_le_bytes([payload[39], payload[40]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(
        u16::from_le_bytes([payload[41], payload[42]]),
        MCTS_TOKEN_MATCH_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[43], payload[44]]),
        MCTS_TOKEN_MATCH_QUEUE_ID
    );

    // Group 0x6000: 1 table (Table 312 DATA_SET_MEMBERS)
    let grp_tbl = u16::from_le_bytes([payload[61], payload[62]]);
    assert_eq!(grp_tbl, 0x6001);

    // Table 312 Row 0:
    // - Group 0x1000: Token 2143 (Type 2 int8 / bool, 1 byte)
    // - Group 0x3000: Tokens 122, 838, 855, 1344 (all Type 5 int32, 4 bytes)
    // - Group 0x4000: Token 11 (Type 9 int64, 8 bytes!)
    assert_eq!(
        u16::from_le_bytes([payload[63], payload[64]]),
        MCTS_TOKEN_MEMBERS
    );
    assert_eq!(u16::from_le_bytes([payload[65], payload[66]]), 1); // 1 row
    assert_eq!(u16::from_le_bytes([payload[67], payload[68]]), 6); // 6 fields
    assert_eq!(u16::from_le_bytes([payload[69], payload[70]]), 0x1001); // Group 0x1000
    assert_eq!(
        u16::from_le_bytes([payload[71], payload[72]]),
        MCTS_TOKEN_INVITE_PRIVILEGES
    );
    assert_eq!(payload[73], 0x00);
    assert_eq!(u16::from_le_bytes([payload[74], payload[75]]), 0x3004); // Group 0x3000 (4 fields)
    assert_eq!(
        u16::from_le_bytes([payload[76], payload[77]]),
        MCTS_TOKEN_BOT_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[78], payload[79]]),
        MCTS_TOKEN_POSITION
    );
    assert_eq!(
        u16::from_le_bytes([payload[80], payload[81]]),
        MCTS_TOKEN_PROFILE_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[82], payload[83]]),
        MCTS_TOKEN_PLAYER_LOBBY_STATE
    );
    assert_eq!(u16::from_le_bytes([payload[100], payload[101]]), 0x4001); // Group 0x4000 (1 field, Type 9!)
    assert_eq!(
        u16::from_le_bytes([payload[102], payload[103]]),
        MCTS_TOKEN_PLAYER_ID
    );
    assert_eq!(
        u64::from_le_bytes([
            payload[104],
            payload[105],
            payload[106],
            payload[107],
            payload[108],
            payload[109],
            payload[110],
            payload[111]
        ]),
        8302401u64
    );
}

#[test]
fn test_match_composition_frame_schema_conformance() {
    let frame = create_mcts_match_composition_frame(
        878850364,
        434,
        "IMMORTAL_SHOOTING_RANGE_PORTAL_SESSION",
        8302401,
        2285,
    );

    let payload_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
    assert_eq!(frame.len(), 4 + payload_len);

    let payload = &frame[4..];
    assert_eq!(payload[0], 0x00);
    assert_eq!(
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
        MCTS_FUNCTION_ID_MATCH_STATUS
    );

    // Root row fields: 2 (1 Table in 0x6000 + 1 String in 0xa000)
    let total_fields = u16::from_le_bytes([payload[5], payload[6]]);
    assert_eq!(total_fields, 2);

    // Group 0x6000: 1 table (Table 1583 DATA_SET_MATCH_COMPOSITION)
    let grp_tbl = u16::from_le_bytes([payload[7], payload[8]]);
    assert_eq!(grp_tbl, 0x6001);
    assert_eq!(
        u16::from_le_bytes([payload[9], payload[10]]),
        MCTS_TOKEN_MATCH_COMPOSITION
    );
    assert_eq!(u16::from_le_bytes([payload[11], payload[12]]), 1); // 1 row
    assert_eq!(u16::from_le_bytes([payload[13], payload[14]]), 5); // 5 row fields

    // Table 1583 Row 0:
    // - Group 0x3000: Tokens 122 (BOT_ID), 1092 (TASK_FORCE) - Type 5 (int32, 4 bytes)
    // - Group 0x4000: Tokens 11 (PLAYER_ID), 700 (MATCH_ID), 703 (MATCH_QUEUE_ID) - Type 9 (int64, 8 bytes)
    assert_eq!(u16::from_le_bytes([payload[15], payload[16]]), 0x3002);
    assert_eq!(
        u16::from_le_bytes([payload[17], payload[18]]),
        MCTS_TOKEN_BOT_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[19], payload[20]]),
        MCTS_TOKEN_TASK_FORCE
    );

    assert_eq!(u16::from_le_bytes([payload[29], payload[30]]), 0x4003);
    assert_eq!(
        u16::from_le_bytes([payload[31], payload[32]]),
        MCTS_TOKEN_PLAYER_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[33], payload[34]]),
        MCTS_TOKEN_MATCH_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[35], payload[36]]),
        MCTS_TOKEN_MATCH_QUEUE_ID
    );

    // Group 0xa000: 1 string (Token 2287 PORTAL_SESSION_ID)
    assert_eq!(u16::from_le_bytes([payload[61], payload[62]]), 0xa001);
    assert_eq!(
        u16::from_le_bytes([payload[63], payload[64]]),
        MCTS_TOKEN_PORTAL_SESSION_ID
    );
}
