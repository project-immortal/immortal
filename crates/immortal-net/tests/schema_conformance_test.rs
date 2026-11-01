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
        (MCTS_TOKEN_POSITION, "POSITION", 5, 0x3000),                   // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_CATEGORY, "GROUP_TYPE", 5, 0x3000),           // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_STATE, "UI_HINT_VALUE_ID", 5, 0x3000),        // Type 5 (INT32)
        (MCTS_TOKEN_QUEUE_ACTIVE, "ACTIVE_FLAG", 12, 0xa000),           // Type 12 (STRING)
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
    assert_eq!(payload_len, 106);

    let payload = &frame[4..];
    assert_eq!(payload[0], 0x00);
    assert_eq!(
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
        MCTS_FUNCTION_ID_MATCH_STATUS
    );

    // Root row fields: 7
    let total_fields = u16::from_le_bytes([payload[5], payload[6]]);
    assert_eq!(total_fields, 7);

    // Group 0x3000: 4 fields (Token 1342, 1690, 1344, 2191) - all Type 5 (4 bytes)
    let grp4 = u16::from_le_bytes([payload[7], payload[8]]);
    assert_eq!(grp4, 0x3004);

    // Group 0x4000: 2 fields (Token 700 MATCH_ID, Token 703 MATCH_QUEUE_ID) - all Type 9 (8 bytes)
    let grp8 = u16::from_le_bytes([payload[33], payload[34]]);
    assert_eq!(grp8, 0x4002);
    assert_eq!(
        u16::from_le_bytes([payload[35], payload[36]]),
        MCTS_TOKEN_MATCH_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[37], payload[38]]),
        MCTS_TOKEN_MATCH_QUEUE_ID
    );

    // Group 0x6000: 1 table (Table 312 DATA_SET_MEMBERS)
    let grp_tbl = u16::from_le_bytes([payload[55], payload[56]]);
    assert_eq!(grp_tbl, 0x6001);

    // Table 312 Row 0:
    // - Group 0x1000: Token 2143 (Type 2 int8 / bool, 1 byte)
    // - Group 0x3000: Tokens 122, 838, 855, 1344 (all Type 5 int32, 4 bytes)
    // - Group 0x4000: Token 11 (Type 9 int64, 8 bytes!)
    assert_eq!(
        u16::from_le_bytes([payload[57], payload[58]]),
        MCTS_TOKEN_MEMBERS
    );
    assert_eq!(u16::from_le_bytes([payload[59], payload[60]]), 1); // 1 row
    assert_eq!(u16::from_le_bytes([payload[61], payload[62]]), 6); // 6 fields
    assert_eq!(u16::from_le_bytes([payload[63], payload[64]]), 0x1001); // Group 0x1000
    assert_eq!(
        u16::from_le_bytes([payload[65], payload[66]]),
        MCTS_TOKEN_INVITE_PRIVILEGES
    );
    assert_eq!(payload[67], 0x00);
    assert_eq!(u16::from_le_bytes([payload[68], payload[69]]), 0x3004); // Group 0x3000 (4 fields)
    assert_eq!(
        u16::from_le_bytes([payload[70], payload[71]]),
        MCTS_TOKEN_BOT_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[72], payload[73]]),
        MCTS_TOKEN_POSITION
    );
    assert_eq!(
        u16::from_le_bytes([payload[74], payload[75]]),
        MCTS_TOKEN_PROFILE_ID
    );
    assert_eq!(
        u16::from_le_bytes([payload[76], payload[77]]),
        MCTS_TOKEN_PLAYER_LOBBY_STATE
    );
    assert_eq!(u16::from_le_bytes([payload[94], payload[95]]), 0x4001); // Group 0x4000 (1 field, Type 9!)
    assert_eq!(
        u16::from_le_bytes([payload[96], payload[97]]),
        MCTS_TOKEN_PLAYER_ID
    );
    assert_eq!(
        u64::from_le_bytes([
            payload[98],
            payload[99],
            payload[100],
            payload[101],
            payload[102],
            payload[103],
            payload[104],
            payload[105]
        ]),
        8302401u64
    );
}
