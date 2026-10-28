// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # CMarshal RPC Serialization
//! Cleanroom serialization and deserialization for high-level MCTS game operations.
//! Header: 52-byte prefix, `FunctionId` at `+0x34`, `RowCount` at `+0x38`, followed by `MFIELD_ENTRY` records.

use crate::error::NetError;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

pub const HEADER_PREFIX_LEN: usize = 0x34; // 52 bytes
pub const FUNCTION_ID_OFFSET: usize = 0x34;
pub const ROW_COUNT_OFFSET: usize = 0x38;
pub const MIN_MARSHAL_LEN: usize = 0x3C; // 60 bytes

// Standard Token Definitions per G2 Specification
pub const TOKEN_STATUS: u16 = 0x1A; // 26
pub const TOKEN_SESSION_TOKEN: u16 = 7;
pub const TOKEN_ACCOUNT_ID: u16 = 10;
pub const TOKEN_CHAMPION_ROSTER: u16 = 100;
pub const TOKEN_WEAPON_DEVICES: u16 = 102;
pub const TOKEN_DECK_LOADOUTS: u16 = 105;
pub const TOKEN_MATCH_TICKET: u16 = 500;

// Champion & Device Constants per MCTS Inventory Specification
pub const CHAMPION_FERNANDO: u32 = 1026;
pub const CHAMPION_CASSIE: u32 = 1024;
pub const CHAMPION_VIKTOR: u32 = 1025;
pub const DEVICE_FERNANDO_FLAME_LANCE: u32 = 10774;
pub const DECK_FERNANDO_STARTER: u32 = 16379;

// Type Identifiers
pub const TYPE_INTEGER: u8 = 0x05;
pub const TYPE_ROWSET_BLOB: u8 = 0x0A;
pub const TYPE_WCHAR_STRING: u8 = 0x0C;

// Function IDs
pub const FUNCTION_ID_SEND_LOGIN: u32 = 1001;
pub const FUNCTION_ID_ON_LOGIN_RESPONSE: u32 = 1002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Integer(i32),
    WCharString(String),
    Blob(Vec<u8>),
}

impl FieldValue {
    pub fn type_id(&self) -> u8 {
        match self {
            Self::Integer(_) => TYPE_INTEGER,
            Self::Blob(_) => TYPE_ROWSET_BLOB,
            Self::WCharString(_) => TYPE_WCHAR_STRING,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarshalField {
    pub token_id: u16,
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CMarshalMessage {
    pub header_prefix: [u8; HEADER_PREFIX_LEN],
    pub function_id: u32,
    pub fields: Vec<MarshalField>,
}

impl Default for CMarshalMessage {
    fn default() -> Self {
        Self {
            header_prefix: [0u8; HEADER_PREFIX_LEN],
            function_id: 0,
            fields: Vec::new(),
        }
    }
}

impl CMarshalMessage {
    pub fn new(function_id: u32) -> Self {
        Self {
            header_prefix: [0u8; HEADER_PREFIX_LEN],
            function_id,
            fields: Vec::new(),
        }
    }

    pub fn with_prefix(function_id: u32, header_prefix: [u8; HEADER_PREFIX_LEN]) -> Self {
        Self {
            header_prefix,
            function_id,
            fields: Vec::new(),
        }
    }

    pub fn add_field(&mut self, token_id: u16, value: FieldValue) {
        self.fields.push(MarshalField { token_id, value });
    }

    pub fn add_integer(&mut self, token_id: u16, value: i32) {
        self.add_field(token_id, FieldValue::Integer(value));
    }

    pub fn add_string(&mut self, token_id: u16, value: impl Into<String>) {
        self.add_field(token_id, FieldValue::WCharString(value.into()));
    }

    pub fn add_blob(&mut self, token_id: u16, value: Vec<u8>) {
        self.add_field(token_id, FieldValue::Blob(value));
    }

    pub fn get_field(&self, token_id: u16) -> Option<&MarshalField> {
        self.fields.iter().find(|f| f.token_id == token_id)
    }

    pub fn get_integer(&self, token_id: u16) -> Option<i32> {
        match self.get_field(token_id)?.value {
            FieldValue::Integer(val) => Some(val),
            _ => None,
        }
    }

    pub fn get_string(&self, token_id: u16) -> Option<&str> {
        match &self.get_field(token_id)?.value {
            FieldValue::WCharString(ref s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_blob(&self, token_id: u16) -> Option<&[u8]> {
        match &self.get_field(token_id)?.value {
            FieldValue::Blob(ref b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, NetError> {
        let mut out = Vec::with_capacity(MIN_MARSHAL_LEN + self.fields.len() * 16);
        out.extend_from_slice(&self.header_prefix);
        out.write_u32::<LittleEndian>(self.function_id)?;
        out.write_u32::<LittleEndian>(self.fields.len() as u32)?;

        for field in &self.fields {
            out.write_u16::<LittleEndian>(field.token_id)?;
            out.write_u8(field.value.type_id())?;
            match &field.value {
                FieldValue::Integer(val) => {
                    out.write_i32::<LittleEndian>(*val)?;
                }
                FieldValue::WCharString(s) => {
                    let utf16_units: Vec<u16> = s.encode_utf16().collect();
                    out.write_u32::<LittleEndian>(utf16_units.len() as u32)?;
                    for unit in utf16_units {
                        out.write_u16::<LittleEndian>(unit)?;
                    }
                }
                FieldValue::Blob(blob) => {
                    out.write_u32::<LittleEndian>(blob.len() as u32)?;
                    out.extend_from_slice(blob);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < MIN_MARSHAL_LEN {
            return Err(NetError::Marshal(format!(
                "Data length {} is less than minimum marshal header size {}",
                data.len(),
                MIN_MARSHAL_LEN
            )));
        }

        let mut header_prefix = [0u8; HEADER_PREFIX_LEN];
        header_prefix.copy_from_slice(&data[..HEADER_PREFIX_LEN]);

        let mut cursor = Cursor::new(&data[HEADER_PREFIX_LEN..]);
        let function_id = cursor.read_u32::<LittleEndian>()?;
        let row_count = cursor.read_u32::<LittleEndian>()? as usize;

        let mut fields = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let token_id = cursor.read_u16::<LittleEndian>()?;
            let type_id = cursor.read_u8()?;
            let value = match type_id {
                TYPE_INTEGER => {
                    let val = cursor.read_i32::<LittleEndian>()?;
                    FieldValue::Integer(val)
                }
                TYPE_WCHAR_STRING => {
                    let char_count = cursor.read_u32::<LittleEndian>()? as usize;
                    let mut utf16_units = Vec::with_capacity(char_count);
                    for _ in 0..char_count {
                        utf16_units.push(cursor.read_u16::<LittleEndian>()?);
                    }
                    let s = String::from_utf16(&utf16_units)
                        .map_err(|e| NetError::Marshal(format!("UTF-16 decoding error: {}", e)))?;
                    FieldValue::WCharString(s)
                }
                TYPE_ROWSET_BLOB => {
                    let blob_len = cursor.read_u32::<LittleEndian>()? as usize;
                    let mut blob = vec![0u8; blob_len];
                    cursor.read_exact(&mut blob)?;
                    FieldValue::Blob(blob)
                }
                other => {
                    return Err(NetError::UnexpectedFieldType {
                        expected: TYPE_INTEGER,
                        found: other,
                    });
                }
            };
            fields.push(MarshalField { token_id, value });
        }

        Ok(Self {
            header_prefix,
            function_id,
            fields,
        })
    }
}

/// Dedicated Server Routing Ticket
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchTicket {
    pub server_host: String,
    pub server_port: u16,
    pub ticket: String,
}

impl MatchTicket {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        ticket: impl Into<String>,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            ticket: ticket.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let host_bytes = self.server_host.as_bytes();
        let _ = buf.write_u16::<LittleEndian>(host_bytes.len() as u16);
        buf.extend_from_slice(host_bytes);
        let _ = buf.write_u16::<LittleEndian>(self.server_port);
        let ticket_bytes = self.ticket.as_bytes();
        let _ = buf.write_u16::<LittleEndian>(ticket_bytes.len() as u16);
        buf.extend_from_slice(ticket_bytes);
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 2 {
            return Err(NetError::Marshal(
                "MatchTicket payload too short for host length".into(),
            ));
        }
        let host_len = data.read_u16::<LittleEndian>()? as usize;
        if data.len() < host_len + 2 {
            return Err(NetError::Marshal(
                "MatchTicket payload too short for host name".into(),
            ));
        }
        let host_bytes = &data[..host_len];
        let server_host = String::from_utf8(host_bytes.to_vec())
            .map_err(|e| NetError::Marshal(format!("Invalid UTF-8 in MatchTicket host: {}", e)))?;
        data = &data[host_len..];

        let server_port = data.read_u16::<LittleEndian>()?;

        if data.len() < 2 {
            return Err(NetError::Marshal(
                "MatchTicket payload too short for ticket length".into(),
            ));
        }
        let ticket_len = data.read_u16::<LittleEndian>()? as usize;
        if data.len() < ticket_len {
            return Err(NetError::Marshal(
                "MatchTicket payload too short for ticket string".into(),
            ));
        }
        let ticket_bytes = &data[..ticket_len];
        let ticket = String::from_utf8(ticket_bytes.to_vec()).map_err(|e| {
            NetError::Marshal(format!("Invalid UTF-8 in MatchTicket ticket: {}", e))
        })?;

        Ok(Self {
            server_host,
            server_port,
            ticket,
        })
    }
}

/// Cleanroom Login Request packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub client_version: String,
    pub platform_token: String,
    pub language: String,
}

impl LoginRequest {
    pub fn new(
        client_version: impl Into<String>,
        platform_token: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Self {
            client_version: client_version.into(),
            platform_token: platform_token.into(),
            language: language.into(),
        }
    }

    pub fn to_marshal_message(&self) -> CMarshalMessage {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_SEND_LOGIN);
        msg.add_string(1, &self.client_version);
        msg.add_string(2, &self.platform_token);
        msg.add_string(3, &self.language);
        msg
    }

    pub fn from_marshal_message(msg: &CMarshalMessage) -> Result<Self, NetError> {
        let client_version = msg.get_string(1).unwrap_or("8.1.5839.0").to_string();
        let platform_token = msg
            .get_string(2)
            .unwrap_or("DEV_OFFLINE_BYPASS")
            .to_string();
        let language = msg.get_string(3).unwrap_or("INT").to_string();

        Ok(Self {
            client_version,
            platform_token,
            language,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, NetError> {
        self.to_marshal_message().encode()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, NetError> {
        let msg = CMarshalMessage::decode(data)?;
        Self::from_marshal_message(&msg)
    }
}

/// Champion Roster rowset (Token 100)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChampionRoster {
    pub champions: Vec<u32>,
}

impl ChampionRoster {
    pub fn new(champions: Vec<u32>) -> Self {
        Self { champions }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.champions.len() * 4);
        let _ = buf.write_u32::<LittleEndian>(self.champions.len() as u32);
        for id in &self.champions {
            let _ = buf.write_u32::<LittleEndian>(*id);
        }
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal("ChampionRoster too short".into()));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut champions = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 4 {
                return Err(NetError::Marshal("ChampionRoster truncated".into()));
            }
            champions.push(data.read_u32::<LittleEndian>()?);
        }
        Ok(Self { champions })
    }
}

/// Weapon device entry linking weapon to champion
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeaponDeviceEntry {
    pub device_id: u32,
    pub champion_id: u32,
}

/// Weapon Devices rowset (Token 102)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeaponDevices {
    pub entries: Vec<WeaponDeviceEntry>,
}

impl WeaponDevices {
    pub fn new(entries: Vec<WeaponDeviceEntry>) -> Self {
        Self { entries }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.entries.len() * 8);
        let _ = buf.write_u32::<LittleEndian>(self.entries.len() as u32);
        for entry in &self.entries {
            let _ = buf.write_u32::<LittleEndian>(entry.device_id);
            let _ = buf.write_u32::<LittleEndian>(entry.champion_id);
        }
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal("WeaponDevices too short".into()));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 8 {
                return Err(NetError::Marshal("WeaponDevices truncated".into()));
            }
            let device_id = data.read_u32::<LittleEndian>()?;
            let champion_id = data.read_u32::<LittleEndian>()?;
            entries.push(WeaponDeviceEntry {
                device_id,
                champion_id,
            });
        }
        Ok(Self { entries })
    }
}

/// Deck loadout entry linking starter deck to champion
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeckLoadoutEntry {
    pub deck_id: u32,
    pub champion_id: u32,
}

/// Deck Loadouts rowset (Token 105)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeckLoadouts {
    pub entries: Vec<DeckLoadoutEntry>,
}

impl DeckLoadouts {
    pub fn new(entries: Vec<DeckLoadoutEntry>) -> Self {
        Self { entries }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.entries.len() * 8);
        let _ = buf.write_u32::<LittleEndian>(self.entries.len() as u32);
        for entry in &self.entries {
            let _ = buf.write_u32::<LittleEndian>(entry.deck_id);
            let _ = buf.write_u32::<LittleEndian>(entry.champion_id);
        }
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal("DeckLoadouts too short".into()));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 8 {
                return Err(NetError::Marshal("DeckLoadouts truncated".into()));
            }
            let deck_id = data.read_u32::<LittleEndian>()?;
            let champion_id = data.read_u32::<LittleEndian>()?;
            entries.push(DeckLoadoutEntry {
                deck_id,
                champion_id,
            });
        }
        Ok(Self { entries })
    }
}

/// Cleanroom Login Response packet (`OnLoginResponse`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub status: i32,
    pub account_id: i32,
    pub session_token: String,
    pub match_ticket: MatchTicket,
    pub champion_roster: Option<ChampionRoster>,
    pub weapon_devices: Option<WeaponDevices>,
    pub deck_loadouts: Option<DeckLoadouts>,
}

impl LoginResponse {
    pub fn new(
        account_id: i32,
        session_token: impl Into<String>,
        match_ticket: MatchTicket,
    ) -> Self {
        Self {
            status: 0,
            account_id,
            session_token: session_token.into(),
            match_ticket,
            champion_roster: None,
            weapon_devices: None,
            deck_loadouts: None,
        }
    }

    pub fn with_inventory(
        mut self,
        champion_roster: ChampionRoster,
        weapon_devices: WeaponDevices,
        deck_loadouts: DeckLoadouts,
    ) -> Self {
        self.champion_roster = Some(champion_roster);
        self.weapon_devices = Some(weapon_devices);
        self.deck_loadouts = Some(deck_loadouts);
        self
    }

    pub fn to_marshal_message(&self) -> CMarshalMessage {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_ON_LOGIN_RESPONSE);
        msg.add_integer(TOKEN_STATUS, self.status);
        msg.add_integer(TOKEN_ACCOUNT_ID, self.account_id);
        msg.add_string(TOKEN_SESSION_TOKEN, &self.session_token);
        msg.add_blob(TOKEN_MATCH_TICKET, self.match_ticket.to_bytes());
        if let Some(roster) = &self.champion_roster {
            msg.add_blob(TOKEN_CHAMPION_ROSTER, roster.to_bytes());
        }
        if let Some(weapons) = &self.weapon_devices {
            msg.add_blob(TOKEN_WEAPON_DEVICES, weapons.to_bytes());
        }
        if let Some(decks) = &self.deck_loadouts {
            msg.add_blob(TOKEN_DECK_LOADOUTS, decks.to_bytes());
        }
        msg
    }

    pub fn from_marshal_message(msg: &CMarshalMessage) -> Result<Self, NetError> {
        let status = msg
            .get_integer(TOKEN_STATUS)
            .ok_or_else(|| NetError::Marshal("Missing Status token in LoginResponse".into()))?;
        let account_id = msg
            .get_integer(TOKEN_ACCOUNT_ID)
            .ok_or_else(|| NetError::Marshal("Missing AccountId token in LoginResponse".into()))?;
        let session_token = msg
            .get_string(TOKEN_SESSION_TOKEN)
            .ok_or_else(|| NetError::Marshal("Missing SessionToken token in LoginResponse".into()))?
            .to_string();
        let ticket_blob = msg.get_blob(TOKEN_MATCH_TICKET).ok_or_else(|| {
            NetError::Marshal("Missing MatchTicket token in LoginResponse".into())
        })?;
        let match_ticket = MatchTicket::from_bytes(ticket_blob)?;

        let champion_roster = match msg.get_blob(TOKEN_CHAMPION_ROSTER) {
            Some(b) => Some(ChampionRoster::from_bytes(b)?),
            None => None,
        };
        let weapon_devices = match msg.get_blob(TOKEN_WEAPON_DEVICES) {
            Some(b) => Some(WeaponDevices::from_bytes(b)?),
            None => None,
        };
        let deck_loadouts = match msg.get_blob(TOKEN_DECK_LOADOUTS) {
            Some(b) => Some(DeckLoadouts::from_bytes(b)?),
            None => None,
        };

        Ok(Self {
            status,
            account_id,
            session_token,
            match_ticket,
            champion_roster,
            weapon_devices,
            deck_loadouts,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, NetError> {
        self.to_marshal_message().encode()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, NetError> {
        let msg = CMarshalMessage::decode(data)?;
        Self::from_marshal_message(&msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marshal_message_roundtrip() {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_SEND_LOGIN);
        msg.add_integer(TOKEN_STATUS, 0);
        msg.add_integer(TOKEN_ACCOUNT_ID, 10001);
        msg.add_string(TOKEN_SESSION_TOKEN, "TEST-SESSION-12345");
        msg.add_blob(TOKEN_MATCH_TICKET, vec![1, 2, 3, 4, 5]);

        let encoded = msg.encode().unwrap();
        assert!(encoded.len() >= MIN_MARSHAL_LEN);

        let decoded = CMarshalMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.function_id, FUNCTION_ID_SEND_LOGIN);
        assert_eq!(decoded.fields.len(), 4);
        assert_eq!(decoded.get_integer(TOKEN_STATUS), Some(0));
        assert_eq!(decoded.get_integer(TOKEN_ACCOUNT_ID), Some(10001));
        assert_eq!(
            decoded.get_string(TOKEN_SESSION_TOKEN),
            Some("TEST-SESSION-12345")
        );
        assert_eq!(
            decoded.get_blob(TOKEN_MATCH_TICKET),
            Some(&[1, 2, 3, 4, 5][..])
        );
    }

    #[test]
    fn test_match_ticket_roundtrip() {
        let ticket = MatchTicket::new("127.0.0.1", 7777, "DEV-TICKET-ABC-XYZ");
        let bytes = ticket.to_bytes();
        let decoded = MatchTicket::from_bytes(&bytes).unwrap();
        assert_eq!(ticket, decoded);
    }

    #[test]
    fn test_login_response_roundtrip() {
        let ticket = MatchTicket::new("127.0.0.1", 7777, "MOCK-ROUTING-TICKET");
        let roster = ChampionRoster::new(vec![CHAMPION_FERNANDO, CHAMPION_CASSIE, CHAMPION_VIKTOR]);
        let weapons = WeaponDevices::new(vec![WeaponDeviceEntry {
            device_id: DEVICE_FERNANDO_FLAME_LANCE,
            champion_id: CHAMPION_FERNANDO,
        }]);
        let decks = DeckLoadouts::new(vec![DeckLoadoutEntry {
            deck_id: DECK_FERNANDO_STARTER,
            champion_id: CHAMPION_FERNANDO,
        }]);

        let response = LoginResponse::new(8302401, "IMMORTAL-DEV-SESSION-TICKET", ticket)
            .with_inventory(roster, weapons, decks);

        let encoded = response.to_bytes().unwrap();
        let decoded = LoginResponse::from_bytes(&encoded).unwrap();

        assert_eq!(response.status, decoded.status);
        assert_eq!(response.account_id, decoded.account_id);
        assert_eq!(response.session_token, decoded.session_token);
        assert_eq!(response.match_ticket, decoded.match_ticket);
        assert_eq!(response.champion_roster, decoded.champion_roster);
        assert_eq!(response.weapon_devices, decoded.weapon_devices);
        assert_eq!(response.deck_loadouts, decoded.deck_loadouts);
    }

    #[test]
    fn test_login_request_roundtrip() {
        let req = LoginRequest::new("8.1.5839.0", "PLATFORM_TOKEN_DEV", "INT");
        let encoded = req.to_bytes().unwrap();
        let decoded = LoginRequest::from_bytes(&encoded).unwrap();

        assert_eq!(req.client_version, decoded.client_version);
        assert_eq!(req.platform_token, decoded.platform_token);
        assert_eq!(req.language, decoded.language);
    }
}
