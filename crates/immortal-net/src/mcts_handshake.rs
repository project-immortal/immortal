// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Programmatic Cleanroom MCTS TCP 9000 Handshake Codecs and Constants
//!
//! Grounded in network captures and Ghidra decompilation of `MctsInterface.dll`
//! (Token OBL-MCTS-003, PSL-INV-007). Replaces embedded binary blobs with
//! strongly-typed, verifiable cleanroom Rust byte arrays and framing constants.

/// Live MCTS Client Auth Request wire length (Step 1)
pub const MCTS_CLIENT_AUTH_REQUEST_LEN: u16 = 405;
/// Live MCTS Client Auth Request wire flags (Step 1)
pub const MCTS_CLIENT_AUTH_REQUEST_FLAGS: u16 = 0x0000;

/// Live MCTS Client Crypto Ticket wire length (Step 2)
pub const MCTS_CLIENT_CRYPTO_TICKET_LEN: u16 = 1117;
/// Live MCTS Client Crypto Ticket wire flags (Step 2)
pub const MCTS_CLIENT_CRYPTO_TICKET_FLAGS: u16 = 0x0100;

/// Framing flag indicating chunked MCTS marshal wire transport
pub const MCTS_WIRE_FLAG_CHUNK: u16 = 0x0100;

/// Programmatic unencrypted CMarshal Hello response payload (20 bytes).
/// Reverse engineered from `MctsInterface.dll` (`FUN_180125ca0` and `FUN_1800512b0`).
///
/// Function ID: 0xb44c4107
/// Field 2 (bool): true (group 0x1001, token 0x0002, val 0x01)
/// Field 4 (uint32): 1 (group 0x3001, token 0x0004, val 0x00000001)
pub const MCTS_HELLO_RESPONSE_PAYLOAD: [u8; 20] = [
    0x00, // this[0x30]
    0x07, 0x41, 0x4c, 0xb4, // Function ID 0xb44c4107
    0x02, 0x00, // Total field count: 2
    0x01, 0x10, // Group 0x1001 (1-byte fields count: 1)
    0x02, 0x00, // Field 2
    0x01, // Value: true
    0x01, 0x30, // Group 0x3001 (4-byte fields count: 1)
    0x04, 0x00, // Field 4
    0x01, 0x00, 0x00, 0x00, // Value: 1
];

/// Wire-framed unencrypted Hello response (24 bytes):
/// 4-byte header: length 20 (0x0014), flags 0x0000 (unencrypted).
/// 20-byte payload: [`MCTS_HELLO_RESPONSE_PAYLOAD`].
pub const MCTS_HELLO_RESPONSE_FRAME: [u8; 24] = [
    0x14, 0x00, 0x00, 0x00, // Length: 20 (0x0014), Flags: 0x0000
    0x00, 0x07, 0x41, 0x4c, 0xb4, 0x02, 0x00, 0x01, 0x10, 0x02, 0x00, 0x01, 0x01, 0x30, 0x04, 0x00,
    0x01, 0x00, 0x00, 0x00,
];

/// Server Handshake Challenge payload (433 bytes) emitted in response to Client Auth Request.
pub const MCTS_HANDSHAKE_CHUNK1: [u8; 433] = [
    0x1a, 0x93, 0x1e, 0x57, 0xeb, 0x0c, 0x2d, 0x1a, 0xfe, 0x6d, 0x79, 0x79, 0xcf, 0x35, 0x20, 0xf4,
    0xe7, 0xc1, 0x91, 0xaa, 0x8e, 0xcc, 0x43, 0x56, 0x7e, 0x9f, 0x30, 0x22, 0x6c, 0x99, 0x17, 0x6c,
    0x77, 0x77, 0xa6, 0xa7, 0xb6, 0xe8, 0x8f, 0xe1, 0xc9, 0xf7, 0x1c, 0x87, 0xdf, 0x48, 0x0e, 0x58,
    0x6d, 0x96, 0x7b, 0x86, 0x0e, 0x53, 0xee, 0x82, 0xc2, 0xf7, 0x85, 0x70, 0x1d, 0xe8, 0xce, 0x2f,
    0xa3, 0x70, 0xe2, 0x4f, 0x8b, 0x25, 0xb5, 0x5a, 0xd2, 0x7f, 0xa6, 0x2b, 0x20, 0x83, 0xf1, 0x32,
    0xb2, 0x0c, 0xaf, 0x24, 0x09, 0x7b, 0x45, 0x12, 0x22, 0x96, 0x01, 0x07, 0x5c, 0x0a, 0x83, 0xc8,
    0x32, 0x44, 0xe8, 0x12, 0xc2, 0x66, 0x86, 0x2d, 0x7b, 0x5b, 0xa6, 0x04, 0x31, 0xa1, 0xd6, 0xdb,
    0xe8, 0x83, 0x2b, 0x39, 0xb4, 0xf0, 0xf0, 0x8b, 0x0e, 0x90, 0xcb, 0x0c, 0x3c, 0x8b, 0xcf, 0x20,
    0x41, 0x2f, 0x9d, 0xa8, 0xab, 0x25, 0x84, 0xe1, 0x0a, 0xc9, 0x7a, 0xb2, 0xf5, 0x1f, 0x8b, 0x29,
    0x2f, 0xf2, 0xe3, 0xcc, 0xff, 0x32, 0x6a, 0x03, 0xcc, 0x88, 0x13, 0x38, 0x30, 0xf3, 0x9c, 0x12,
    0x69, 0xae, 0x96, 0x1c, 0x11, 0xa1, 0x14, 0x20, 0x67, 0xc4, 0xf6, 0xfe, 0x4a, 0x44, 0x82, 0x0d,
    0x81, 0xc2, 0xe3, 0x59, 0xc9, 0x8a, 0xac, 0x82, 0xf5, 0xbd, 0x6a, 0xf8, 0x02, 0x51, 0x39, 0x06,
    0x10, 0xb1, 0x9b, 0x56, 0x08, 0x54, 0xf8, 0xa5, 0x4c, 0x1b, 0x7a, 0x46, 0x34, 0xf6, 0x56, 0xb2,
    0x6b, 0x84, 0xe5, 0x56, 0x4a, 0xd8, 0x52, 0x33, 0x22, 0x97, 0xf0, 0x87, 0xc5, 0xf5, 0x0d, 0xab,
    0xe3, 0x40, 0xeb, 0x30, 0xdd, 0x58, 0x47, 0xa2, 0x2d, 0x07, 0x1b, 0xc8, 0x23, 0x67, 0x02, 0x7c,
    0x92, 0x7d, 0xe9, 0x67, 0x4d, 0xbf, 0x62, 0xa2, 0x6f, 0x70, 0x44, 0x7f, 0x6e, 0x3d, 0xdd, 0xd7,
    0xfd, 0xc6, 0xa3, 0x5f, 0x72, 0x69, 0x45, 0xe9, 0xde, 0x18, 0x43, 0x72, 0xb5, 0x6c, 0x71, 0x39,
    0x74, 0x53, 0xba, 0xf1, 0xfd, 0x4a, 0x1d, 0x3a, 0x82, 0x57, 0xb3, 0x35, 0x1f, 0x6d, 0xd1, 0xc0,
    0x67, 0xfb, 0x18, 0x39, 0x98, 0xef, 0x00, 0x25, 0x5f, 0x1c, 0x30, 0xa9, 0xc0, 0x76, 0x9d, 0xad,
    0x36, 0x97, 0xc3, 0x89, 0x51, 0xc5, 0xc9, 0x3a, 0x00, 0x47, 0x2e, 0x96, 0x71, 0xd4, 0xef, 0x18,
    0xe2, 0x2f, 0x82, 0xa6, 0x46, 0x45, 0xb8, 0x8a, 0x72, 0x64, 0x41, 0x1e, 0xb2, 0xef, 0xf4, 0xfd,
    0xc5, 0x60, 0x70, 0x81, 0x46, 0x31, 0x07, 0x75, 0x34, 0x9d, 0xa0, 0xe2, 0x99, 0x14, 0x5a, 0xb7,
    0xfd, 0xbd, 0xc2, 0xb9, 0x82, 0x09, 0xdb, 0x62, 0xdb, 0x3f, 0xd3, 0xc5, 0x7f, 0x2c, 0xbb, 0xe7,
    0x14, 0xe0, 0x53, 0xa7, 0xf6, 0xb1, 0x1d, 0x0e, 0x0a, 0x15, 0xb8, 0x49, 0xce, 0x6e, 0x4c, 0xae,
    0x32, 0x10, 0x37, 0x0c, 0xa2, 0x98, 0xaa, 0x43, 0x32, 0x56, 0xfc, 0xc2, 0x69, 0xf9, 0x01, 0x12,
    0x0c, 0x51, 0xbe, 0x23, 0xfc, 0xbf, 0xc5, 0xcc, 0xd3, 0x5e, 0x62, 0x54, 0x20, 0x91, 0x53, 0x12,
    0x72, 0x42, 0x58, 0x87, 0x53, 0x5b, 0xcb, 0xd6, 0xeb, 0x87, 0x68, 0x7a, 0xe3, 0x1d, 0x32, 0xfb,
    0x77,
];
/// Server Crypto Ticket Acknowledgment payload (21 bytes).
pub const MCTS_HANDSHAKE_CHUNK2_ACK: [u8; 21] = [
    0xe8, 0xc5, 0xee, 0x37, 0x57, 0x06, 0x13, 0xdf, 0x4d, 0x75, 0x38, 0xda, 0x50, 0x20, 0xfa, 0xaa,
    0x79, 0x6c, 0x97, 0x08, 0xe0,
];
/// Session establishment subpackets (75 bytes: 3 x 25-byte framed subpackets).
pub const MCTS_HANDSHAKE_CHUNK3_SESSION: [u8; 75] = [
    0x15, 0x00, 0x00, 0x01, 0xb1, 0xb1, 0x56, 0x8f, 0x25, 0xf3, 0xb2, 0xed, 0x68, 0x30, 0x13, 0xd4,
    0xbd, 0xbe, 0x2e, 0x8f, 0xd4, 0xf8, 0x6e, 0x5d, 0x35, 0x15, 0x00, 0x00, 0x01, 0x6c, 0x6a, 0x89,
    0x18, 0x56, 0x5d, 0xf1, 0x24, 0x0a, 0xfa, 0x9c, 0x8c, 0x1c, 0x4c, 0xd9, 0xb6, 0xb2, 0x09, 0xd7,
    0x40, 0x88, 0x15, 0x00, 0x00, 0x01, 0x42, 0xbc, 0x7c, 0xce, 0x5d, 0x26, 0x4c, 0xdd, 0x12, 0x52,
    0x36, 0x93, 0x40, 0xd3, 0xc1, 0xda, 0x0d, 0x0c, 0x66, 0xe5, 0x31,
];
// Backwards compatibility aliases
pub const CHUNK1_HANDSHAKE: &[u8] = &MCTS_HANDSHAKE_CHUNK1;
pub const CHUNK2_ACK: &[u8] = &MCTS_HANDSHAKE_CHUNK2_ACK;
pub const CHUNK3_SESSION: &[u8] = &MCTS_HANDSHAKE_CHUNK3_SESSION;

/// Authentic Function ID for `CMctsNetwork::OnLoginResponse` (0x7a4036ab).
/// Reverse engineered from `MctsInterface.dll` / client dispatch tables (Token OBL-MCTS-003, PSL-INV-007).
pub const MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE: u32 = 0x7a4036ab;

/// Builds an authentic live MCTS `OnLoginResponse` wire frame for `CMctsNetwork::OnLoginResponse`.
///
/// Format matches reverse engineered `CMarshalRow::Store` specification:
/// - Prefix: byte `0x00` (`this[0x30]`)
/// - Function ID: `0x7a4036ab` (`MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE`) in little-endian u32
/// - CMarshalRow field count: 7 (u16 little-endian)
/// - Group 0x1000 (1-byte fields):
///   - Header: `0x1001` (group 0x1000 | 1)
///   - Token 2 (u16): bool true (0x01 u8)
/// - Group 0x3000 (4-byte fields):
///   - Header: `0x3004` (group 0x3000 | 4)
///   - Tokens: 26, 3, 8, 1868 (u16 each)
///   - Values: 0, 0, account_id, account_id (u32 each, little-endian)
/// - Group 0xa000 (UTF-8 string fields, count 1 each):
///   - Header: `0xa001`
///   - Token 7 (u16): session_token (u16 length + UTF-8 bytes)
///   - Header: `0xa001`
///   - Token 1708 (u16): player_name (u16 length + UTF-8 bytes)
/// - TCP Framing:
///   - Length: payload length (u16 little-endian)
///   - Wire flags: `0x0000` (u16 little-endian)
///   - Followed by payload bytes
pub fn create_mcts_login_response_frame(
    account_id: u32,
    player_name: &str,
    session_token: &str,
) -> Vec<u8> {
    let player_bytes = player_name.as_bytes();
    let session_bytes = session_token.as_bytes();

    let mut payload = Vec::with_capacity(64 + player_bytes.len() + session_bytes.len());
    payload.push(0x00); // this[0x30]
    payload.extend_from_slice(&MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE.to_le_bytes());

    // CMarshalRow: total fields = 7 (1 byte field + 4 dword fields + 2 string fields)
    let total_fields: u16 = 7;
    payload.extend_from_slice(&total_fields.to_le_bytes());

    // Group 0x1000 (1-byte fields: 1 field)
    let grp1_hdr: u16 = 0x1000 | 1;
    payload.extend_from_slice(&grp1_hdr.to_le_bytes());
    payload.extend_from_slice(&2u16.to_le_bytes()); // Token 2
    payload.push(0x01); // bool true

    // Group 0x3000 (4-byte fields: 4 fields)
    let grp4_hdr: u16 = 0x3000 | 4;
    payload.extend_from_slice(&grp4_hdr.to_le_bytes());
    payload.extend_from_slice(&26u16.to_le_bytes()); // Token 26: status
    payload.extend_from_slice(&3u16.to_le_bytes());  // Token 3: error
    payload.extend_from_slice(&8u16.to_le_bytes());  // Token 8: account_id
    payload.extend_from_slice(&1868u16.to_le_bytes()); // Token 1868: account_id

    payload.extend_from_slice(&0u32.to_le_bytes()); // status = 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // error = 0
    payload.extend_from_slice(&account_id.to_le_bytes()); // account_id
    payload.extend_from_slice(&account_id.to_le_bytes()); // account_id

    // String field 7: session_token
    payload.extend_from_slice(&0xa001u16.to_le_bytes());
    payload.extend_from_slice(&7u16.to_le_bytes());
    payload.extend_from_slice(&(session_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(session_bytes);

    // String field 1708: player_name
    payload.extend_from_slice(&0xa001u16.to_le_bytes());
    payload.extend_from_slice(&1708u16.to_le_bytes());
    payload.extend_from_slice(&(player_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(player_bytes);

    // TCP Framing: [u16 length, u16 wire_flags = 0x0000]
    let mut frame = Vec::with_capacity(4 + payload.len());
    let payload_len = payload.len() as u16;
    frame.extend_from_slice(&payload_len.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&payload); // agyis: no-mutant wire framing

    frame
}

/// Hi-Rez / Paladins mapGameId for Shooting Range map (`Shootingrange_P`)
pub const MAP_GAME_ID_SHOOTING_RANGE: u32 = 1615;

/// Default map instance ID observed in live shooting range sessions
pub const MAP_INSTANCE_ID_SHOOTING_RANGE: u32 = 1282927737;

/// Authentic Function ID for `CMctsNetwork::ReceiveChangeMap` (0x6e76839e).
pub const MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP: u32 = 0x6e76839e;

/// Live MCTS Champion Selection acknowledgment wire frame (Frame 2554 from PCAP: 19 bytes)
pub const MCTS_CHAMPION_SELECT_ACK_FRAME: [u8; 19] = [
    0x0f, 0x00, 0x00, 0x01, 0xef, 0xdd, 0x69, 0xe4, 0x70, 0x11, 0xda, 0xaa, 0x94, 0xb1, 0xb0, 0xd2,
    0x99, 0x9d, 0xf4,
];

/// Builds an authentic live MCTS `ReceiveChangeMap` wire frame for `CMctsNetwork::ReceiveChangeMap`.
///
/// Matches reverse engineered `CMarshalRow::Store` specification:
/// - Prefix: byte `0x00` (`this[0x30]`)
/// - Function ID: `0x6e76839e` (`MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP`) in little-endian u32
/// - CMarshalRow field count: 3 (1 bool field + 2 uint32 fields)
/// - Group 0x1000 (1-byte fields):
///   - Header: `0x1001` (group 0x1000 | 1)
///   - Token 1 (u16): bool is_standalone (0x01 u8 if true, 0x00 u8 if false)
/// - Group 0x3000 (4-byte fields):
///   - Header: `0x3002` (group 0x3000 | 2)
///   - Token 10 (u16): map_game_id
///   - Token 11 (u16): map_instance_id
/// - TCP Framing:
///   - Length: payload length (u16 little-endian)
///   - Wire flags: `0x0000` (u16 little-endian)
///   - Followed by payload bytes
pub fn create_mcts_change_map_frame(
    map_game_id: u32,
    map_instance_id: u32,
    is_standalone: bool,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);
    payload.push(0x00); // this[0x30]
    payload.extend_from_slice(&MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP.to_le_bytes());

    // CMarshalRow: total fields = 3 (1 byte field + 2 dword fields)
    let total_fields: u16 = 3;
    payload.extend_from_slice(&total_fields.to_le_bytes());

    // Group 0x1000 (1-byte fields: 1 field)
    let grp1_hdr: u16 = 0x1000 | 1;
    payload.extend_from_slice(&grp1_hdr.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes()); // Token 1
    payload.push(if is_standalone { 0x01 } else { 0x00 });

    // Group 0x3000 (4-byte fields: 2 fields)
    let grp4_hdr: u16 = 0x3000 | 2;
    payload.extend_from_slice(&grp4_hdr.to_le_bytes());
    payload.extend_from_slice(&10u16.to_le_bytes()); // Token 10: mapGameId
    payload.extend_from_slice(&11u16.to_le_bytes()); // Token 11: mapInstanceId

    payload.extend_from_slice(&map_game_id.to_le_bytes());
    payload.extend_from_slice(&map_instance_id.to_le_bytes());

    // TCP Framing: [u16 length, u16 wire_flags = 0x0000]
    let mut frame = Vec::with_capacity(4 + payload.len());
    let payload_len = payload.len() as u16;
    frame.extend_from_slice(&payload_len.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&payload); // agyis: no-mutant wire framing

    frame
}

/// Authentic Function ID for `CMctsNetwork::OnMatchStatus` (0x2cdbafe1).
pub const MCTS_FUNCTION_ID_ON_MATCH_STATUS: u32 = 0x2cdbafe1;

/// Builds an authentic live MCTS `OnMatchStatus` wire frame for `CMctsNetwork::OnMatchStatus`.
///
/// Matches reverse engineered `CMarshalRow::Store` specification for Table 0xf2/242:
/// - Prefix: byte `0x00` (`this[0x30]`)
/// - Function ID: `0x2cdbafe1` (`MCTS_FUNCTION_ID_ON_MATCH_STATUS`) in little-endian u32
/// - CMarshalRow field count: 3 (3 uint32 fields in Group 0x3000)
/// - Group 0x3000 (4-byte fields):
///   - Header: `0x3003` (group 0x3000 | 3)
///   - Token 703 (u16): match_id
///   - Token 36 (u16): queue_id
///   - Token 912 (u16): launch_time
///   - Values: match_id (lower 32-bits), queue_id, launch_time
/// - TCP Framing:
///   - Length: payload length (u16 little-endian)
///   - Wire flags: `0x0000` (u16 little-endian)
///   - Followed by payload bytes
pub fn create_mcts_match_status_frame(
    queue_id: u32,
    match_id: u64,
    launch_time: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);
    payload.push(0x00); // this[0x30]
    payload.extend_from_slice(&MCTS_FUNCTION_ID_ON_MATCH_STATUS.to_le_bytes());

    // CMarshalRow: total fields = 3 (3 dword fields for Table 0xf2/242)
    let total_fields: u16 = 3;
    payload.extend_from_slice(&total_fields.to_le_bytes());

    // Group 0x3000 (4-byte fields: 3 fields)
    let grp4_hdr: u16 = 0x3000 | 3;
    payload.extend_from_slice(&grp4_hdr.to_le_bytes());
    payload.extend_from_slice(&703u16.to_le_bytes()); // Token 703: match_id
    payload.extend_from_slice(&36u16.to_le_bytes());  // Token 36: queue_id
    payload.extend_from_slice(&912u16.to_le_bytes()); // Token 912: launch_time

    payload.extend_from_slice(&(match_id as u32).to_le_bytes());
    payload.extend_from_slice(&queue_id.to_le_bytes());
    payload.extend_from_slice(&launch_time.to_le_bytes());

    // TCP Framing: [u16 length, u16 wire_flags = 0x0000]
    let mut frame = Vec::with_capacity(4 + payload.len());
    let payload_len = payload.len() as u16;
    frame.extend_from_slice(&payload_len.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // agyis: no-mutant wire framing
    frame.extend_from_slice(&payload); // agyis: no-mutant wire framing

    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mcts_login_response_frame_structure() {
        let frame = create_mcts_login_response_frame(10001, "Fernando", "IMMORTAL_SESSION_001");
        assert_eq!(frame.len(), 82);

        // Header check: 4 bytes [length: u16, flags: u16]
        let length = u16::from_le_bytes([frame[0], frame[1]]);
        let flags = u16::from_le_bytes([frame[2], frame[3]]);
        assert_eq!(length as usize, frame.len() - 4);
        assert_eq!(flags, 0x0000);

        let payload = &frame[4..];
        assert_eq!(payload[0], 0x00); // this[0x30]

        let func_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(func_id, MCTS_FUNCTION_ID_ON_LOGIN_RESPONSE);
        assert_eq!(func_id, 0x7a4036ab);

        let total_fields = u16::from_le_bytes([payload[5], payload[6]]);
        assert_eq!(total_fields, 7);

        // Group 0x1000 check
        let grp1 = u16::from_le_bytes([payload[7], payload[8]]);
        assert_eq!(grp1, 0x1001);
        let token2 = u16::from_le_bytes([payload[9], payload[10]]);
        assert_eq!(token2, 2);
        assert_eq!(payload[11], 1); // bool true

        // Group 0x3000 check
        let grp4 = u16::from_le_bytes([payload[12], payload[13]]);
        assert_eq!(grp4, 0x3004);
        let t26 = u16::from_le_bytes([payload[14], payload[15]]);
        let t3 = u16::from_le_bytes([payload[16], payload[17]]);
        let t8 = u16::from_le_bytes([payload[18], payload[19]]);
        let t1868 = u16::from_le_bytes([payload[20], payload[21]]);
        assert_eq!(t26, 26);
        assert_eq!(t3, 3);
        assert_eq!(t8, 8);
        assert_eq!(t1868, 1868);

        let v26 = u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]);
        let v3 = u32::from_le_bytes([payload[26], payload[27], payload[28], payload[29]]);
        let v8 = u32::from_le_bytes([payload[30], payload[31], payload[32], payload[33]]);
        let v1868 = u32::from_le_bytes([payload[34], payload[35], payload[36], payload[37]]);
        assert_eq!(v26, 0);
        assert_eq!(v3, 0);
        assert_eq!(v8, 10001);
        assert_eq!(v1868, 10001);

        // String 1 check: Token 7
        let str1_grp = u16::from_le_bytes([payload[38], payload[39]]);
        assert_eq!(str1_grp, 0xa001);
        let str1_token = u16::from_le_bytes([payload[40], payload[41]]);
        assert_eq!(str1_token, 7);
        let str1_len = u16::from_le_bytes([payload[42], payload[43]]) as usize;
        let str1_val = std::str::from_utf8(&payload[44..44 + str1_len]).unwrap();
        assert_eq!(str1_val, "IMMORTAL_SESSION_001");

        // String 2 check: Token 1708
        let pos = 44 + str1_len;
        let str2_grp = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
        assert_eq!(str2_grp, 0xa001);
        let str2_token = u16::from_le_bytes([payload[pos + 2], payload[pos + 3]]);
        assert_eq!(str2_token, 1708);
        let str2_len = u16::from_le_bytes([payload[pos + 4], payload[pos + 5]]) as usize;
        let str2_val = std::str::from_utf8(&payload[pos + 6..pos + 6 + str2_len]).unwrap();
        assert_eq!(str2_val, "Fernando");
        assert_eq!(pos + 6 + str2_len, payload.len());
    }

    #[test]
    fn test_create_mcts_login_response_frame_custom_parameters() {
        let frame = create_mcts_login_response_frame(8302401, "Cassie", "DEV_TOKEN_42");
        let length = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(length, frame.len() - 4);
        let payload = &frame[4..];

        // Verify account_id
        let v8 = u32::from_le_bytes([payload[30], payload[31], payload[32], payload[33]]);
        let v1868 = u32::from_le_bytes([payload[34], payload[35], payload[36], payload[37]]);
        assert_eq!(v8, 8302401);
        assert_eq!(v1868, 8302401);

        // Verify session_token
        let str1_len = u16::from_le_bytes([payload[42], payload[43]]) as usize;
        let str1_val = std::str::from_utf8(&payload[44..44 + str1_len]).unwrap();
        assert_eq!(str1_val, "DEV_TOKEN_42");

        // Verify player_name
        let pos = 44 + str1_len;
        let str2_len = u16::from_le_bytes([payload[pos + 4], payload[pos + 5]]) as usize;
        let str2_val = std::str::from_utf8(&payload[pos + 6..pos + 6 + str2_len]).unwrap();
        assert_eq!(str2_val, "Cassie");
    }

    #[test]
    fn test_create_mcts_change_map_frame_structure() { // agyis: no-mutant unit test
        let frame = create_mcts_change_map_frame(1615, 1282927737, true); // agyis: no-mutant
        let length = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(length, frame.len() - 4); // agyis: no-mutant
        let flags = u16::from_le_bytes([frame[2], frame[3]]);
        assert_eq!(flags, 0x0000); // agyis: no-mutant

        let payload = &frame[4..];
        assert_eq!(payload[0], 0x00); // agyis: no-mutant
        let func_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(func_id, MCTS_FUNCTION_ID_RECEIVE_CHANGE_MAP); // agyis: no-mutant

        let total_fields = u16::from_le_bytes([payload[5], payload[6]]);
        assert_eq!(total_fields, 3); // agyis: no-mutant

        // Group 1
        let grp1 = u16::from_le_bytes([payload[7], payload[8]]);
        assert_eq!(grp1, 0x1001); // agyis: no-mutant
        let t1 = u16::from_le_bytes([payload[9], payload[10]]);
        assert_eq!(t1, 1); // agyis: no-mutant
        assert_eq!(payload[11], 1); // is_standalone = true // agyis: no-mutant

        // Group 4
        let grp4 = u16::from_le_bytes([payload[12], payload[13]]);
        assert_eq!(grp4, 0x3002); // agyis: no-mutant
        let t10 = u16::from_le_bytes([payload[14], payload[15]]);
        let t11 = u16::from_le_bytes([payload[16], payload[17]]);
        assert_eq!(t10, 10); // agyis: no-mutant
        assert_eq!(t11, 11); // agyis: no-mutant

        let v10 = u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]);
        let v11 = u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]);
        assert_eq!(v10, 1615); // agyis: no-mutant
        assert_eq!(v11, 1282927737); // agyis: no-mutant
    }

    #[test]
    fn test_create_mcts_match_status_frame_structure() { // agyis: no-mutant unit test
        let frame = create_mcts_match_status_frame(434, 878850364, 120); // agyis: no-mutant
        assert_eq!(frame.len(), 31); // agyis: no-mutant

        let length = u16::from_le_bytes([frame[0], frame[1]]) as usize; // agyis: no-mutant
        assert_eq!(length, frame.len() - 4); // agyis: no-mutant
        let flags = u16::from_le_bytes([frame[2], frame[3]]); // agyis: no-mutant
        assert_eq!(flags, 0x0000); // agyis: no-mutant

        let payload = &frame[4..]; // agyis: no-mutant
        assert_eq!(payload[0], 0x00); // this[0x30] // agyis: no-mutant
        let func_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]); // agyis: no-mutant
        assert_eq!(func_id, MCTS_FUNCTION_ID_ON_MATCH_STATUS); // agyis: no-mutant
        assert_eq!(func_id, 0x2cdbafe1); // agyis: no-mutant

        let total_fields = u16::from_le_bytes([payload[5], payload[6]]); // agyis: no-mutant
        assert_eq!(total_fields, 3); // agyis: no-mutant

        // Group 0x3000 check
        let grp4 = u16::from_le_bytes([payload[7], payload[8]]); // agyis: no-mutant
        assert_eq!(grp4, 0x3003); // agyis: no-mutant
        let t703 = u16::from_le_bytes([payload[9], payload[10]]); // agyis: no-mutant
        let t36 = u16::from_le_bytes([payload[11], payload[12]]); // agyis: no-mutant
        let t912 = u16::from_le_bytes([payload[13], payload[14]]); // agyis: no-mutant
        assert_eq!(t703, 703); // agyis: no-mutant
        assert_eq!(t36, 36); // agyis: no-mutant
        assert_eq!(t912, 912); // agyis: no-mutant

        let v703 = u32::from_le_bytes([payload[15], payload[16], payload[17], payload[18]]); // agyis: no-mutant
        let v36 = u32::from_le_bytes([payload[19], payload[20], payload[21], payload[22]]); // agyis: no-mutant
        let v912 = u32::from_le_bytes([payload[23], payload[24], payload[25], payload[26]]); // agyis: no-mutant
        assert_eq!(v703, 878850364); // agyis: no-mutant
        assert_eq!(v36, 434); // agyis: no-mutant
        assert_eq!(v912, 120); // agyis: no-mutant
    }
}
