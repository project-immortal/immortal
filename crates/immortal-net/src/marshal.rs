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

// Champion and Device Constants
pub const CHAMPION_CASSIE: u32 = 1024;
pub const CHAMPION_VIKTOR: u32 = 1025;
pub const CHAMPION_FERNANDO: u32 = 1026;

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

    pub fn add_champion_roster(&mut self, entries: &[ChampionRosterEntry]) {
        self.add_field(TOKEN_CHAMPION_ROSTER, ChampionRosterEntry::to_blob(entries));
    }

    pub fn get_champion_roster(&self) -> Result<Option<Vec<ChampionRosterEntry>>, NetError> {
        match self.get_field(TOKEN_CHAMPION_ROSTER) {
            Some(field) => ChampionRosterEntry::from_blob(&field.value).map(Some),
            None => Ok(None),
        }
    }

    pub fn add_weapon_devices(&mut self, entries: &[DeviceEntry]) {
        self.add_field(TOKEN_WEAPON_DEVICES, DeviceEntry::to_blob(entries));
    }

    pub fn get_weapon_devices(&self) -> Result<Option<Vec<DeviceEntry>>, NetError> {
        match self.get_field(TOKEN_WEAPON_DEVICES) {
            Some(field) => DeviceEntry::from_blob(&field.value).map(Some),
            None => Ok(None),
        }
    }

    pub fn add_deck_loadouts(&mut self, entries: &[DeckEntry]) {
        self.add_field(TOKEN_DECK_LOADOUTS, DeckEntry::to_blob(entries));
    }

    pub fn get_deck_loadouts(&self) -> Result<Option<Vec<DeckEntry>>, NetError> {
        match self.get_field(TOKEN_DECK_LOADOUTS) {
            Some(field) => DeckEntry::from_blob(&field.value).map(Some),
            None => Ok(None),
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

        let remaining = &data[HEADER_PREFIX_LEN..];
        let mut cursor = Cursor::new(remaining);
        let function_id = cursor.read_u32::<LittleEndian>()?;
        let row_count = cursor.read_u32::<LittleEndian>()? as usize;

        if row_count > remaining.len() / 3 {
            return Err(NetError::Marshal(format!(
                "Invalid row_count {} for payload length {}",
                row_count,
                remaining.len()
            )));
        }

        let mut fields = Vec::with_capacity(row_count.min(1024));
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
                    let remaining_bytes =
                        (cursor.get_ref().len() as u64).saturating_sub(cursor.position()) as usize;
                    if char_count * 2 > remaining_bytes || char_count > 65535 {
                        return Err(NetError::Marshal(format!(
                            "Invalid char_count {} (remaining bytes {})",
                            char_count, remaining_bytes
                        )));
                    }
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
                    let remaining_bytes =
                        (cursor.get_ref().len() as u64).saturating_sub(cursor.position()) as usize;
                    if blob_len > remaining_bytes || blob_len > 1_000_000 {
                        return Err(NetError::Marshal(format!(
                            "Invalid blob_len {} (remaining bytes {})",
                            blob_len, remaining_bytes
                        )));
                    }
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Champion Roster Entry in `Token 100` (`ChampionRoster`)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChampionRosterEntry {
    pub champion_id: u32,
    pub owned: bool,
}

impl ChampionRosterEntry {
    pub fn new(champion_id: u32, owned: bool) -> Self {
        Self { champion_id, owned }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5);
        buf.extend_from_slice(&self.champion_id.to_le_bytes());
        buf.push(if self.owned { 1 } else { 0 });
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 5 {
            return Err(NetError::Marshal(
                "ChampionRosterEntry requires at least 5 bytes".into(),
            ));
        }
        let champion_id = data.read_u32::<LittleEndian>()?;
        let owned = data.read_u8()? != 0;
        Ok(Self { champion_id, owned })
    }

    pub fn encode_row_set(entries: &[Self]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + entries.len() * 5);
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf
    }

    pub fn decode_row_set(mut data: &[u8]) -> Result<Vec<Self>, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal(
                "ChampionRoster rowset too short for count header".into(),
            ));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 5 {
                return Err(NetError::Marshal(
                    "ChampionRoster rowset data truncated".into(),
                ));
            }
            let champion_id = data.read_u32::<LittleEndian>()?;
            let owned = data.read_u8()? != 0;
            entries.push(Self { champion_id, owned });
        }
        Ok(entries)
    }

    pub fn to_blob(entries: &[Self]) -> FieldValue {
        FieldValue::Blob(Self::encode_row_set(entries))
    }

    pub fn from_blob(value: &FieldValue) -> Result<Vec<Self>, NetError> {
        match value {
            FieldValue::Blob(bytes) => Self::decode_row_set(bytes),
            _ => Err(NetError::UnexpectedFieldType {
                expected: TYPE_ROWSET_BLOB,
                found: value.type_id(),
            }),
        }
    }
}

/// Weapon Device Entry in `Token 102` (`WeaponDevices`)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceEntry {
    pub device_id: u32,
    pub champion_id: u32,
}

impl DeviceEntry {
    pub fn new(device_id: u32, champion_id: u32) -> Self {
        Self {
            device_id,
            champion_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.device_id.to_le_bytes());
        buf.extend_from_slice(&self.champion_id.to_le_bytes());
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 8 {
            return Err(NetError::Marshal(
                "DeviceEntry requires at least 8 bytes".into(),
            ));
        }
        let device_id = data.read_u32::<LittleEndian>()?;
        let champion_id = data.read_u32::<LittleEndian>()?;
        Ok(Self {
            device_id,
            champion_id,
        })
    }

    pub fn encode_row_set(entries: &[Self]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + entries.len() * 8);
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf
    }

    pub fn decode_row_set(mut data: &[u8]) -> Result<Vec<Self>, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal(
                "WeaponDevices rowset too short for count header".into(),
            ));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 8 {
                return Err(NetError::Marshal(
                    "WeaponDevices rowset data truncated".into(),
                ));
            }
            let device_id = data.read_u32::<LittleEndian>()?;
            let champion_id = data.read_u32::<LittleEndian>()?;
            entries.push(Self {
                device_id,
                champion_id,
            });
        }
        Ok(entries)
    }

    pub fn to_blob(entries: &[Self]) -> FieldValue {
        FieldValue::Blob(Self::encode_row_set(entries))
    }

    pub fn from_blob(value: &FieldValue) -> Result<Vec<Self>, NetError> {
        match value {
            FieldValue::Blob(bytes) => Self::decode_row_set(bytes),
            _ => Err(NetError::UnexpectedFieldType {
                expected: TYPE_ROWSET_BLOB,
                found: value.type_id(),
            }),
        }
    }
}

/// Deck Loadout Entry in `Token 105` (`DeckLoadouts`)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeckEntry {
    pub deck_id: u32,
    pub champion_id: u32,
}

impl DeckEntry {
    pub fn new(deck_id: u32, champion_id: u32) -> Self {
        Self {
            deck_id,
            champion_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.deck_id.to_le_bytes());
        buf.extend_from_slice(&self.champion_id.to_le_bytes());
        buf
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 8 {
            return Err(NetError::Marshal(
                "DeckEntry requires at least 8 bytes".into(),
            ));
        }
        let deck_id = data.read_u32::<LittleEndian>()?;
        let champion_id = data.read_u32::<LittleEndian>()?;
        Ok(Self {
            deck_id,
            champion_id,
        })
    }

    pub fn encode_row_set(entries: &[Self]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + entries.len() * 8);
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf
    }

    pub fn decode_row_set(mut data: &[u8]) -> Result<Vec<Self>, NetError> {
        if data.len() < 4 {
            return Err(NetError::Marshal(
                "DeckLoadouts rowset too short for count header".into(),
            ));
        }
        let count = data.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < 8 {
                return Err(NetError::Marshal(
                    "DeckLoadouts rowset data truncated".into(),
                ));
            }
            let deck_id = data.read_u32::<LittleEndian>()?;
            let champion_id = data.read_u32::<LittleEndian>()?;
            entries.push(Self {
                deck_id,
                champion_id,
            });
        }
        Ok(entries)
    }

    pub fn to_blob(entries: &[Self]) -> FieldValue {
        FieldValue::Blob(Self::encode_row_set(entries))
    }

    pub fn from_blob(value: &FieldValue) -> Result<Vec<Self>, NetError> {
        match value {
            FieldValue::Blob(bytes) => Self::decode_row_set(bytes),
            _ => Err(NetError::UnexpectedFieldType {
                expected: TYPE_ROWSET_BLOB,
                found: value.type_id(),
            }),
        }
    }
}

/// Helper creating standard inventory rowsets with Fernando, Cassie, and Viktor unlocked
pub fn create_default_inventory() -> (Vec<ChampionRosterEntry>, Vec<DeviceEntry>, Vec<DeckEntry>) {
    let champions = vec![
        ChampionRosterEntry::new(CHAMPION_FERNANDO, true),
        ChampionRosterEntry::new(CHAMPION_CASSIE, true),
        ChampionRosterEntry::new(CHAMPION_VIKTOR, true),
    ];
    let devices = vec![DeviceEntry::new(
        DEVICE_FERNANDO_FLAME_LANCE,
        CHAMPION_FERNANDO,
    )];
    let decks = vec![DeckEntry::new(DECK_FERNANDO_STARTER, CHAMPION_FERNANDO)];
    (champions, devices, decks)
}

/// Cleanroom Inventory Response payload
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InventoryResponse {
    pub champion_roster: Vec<ChampionRosterEntry>,
    pub weapon_devices: Vec<DeviceEntry>,
    pub deck_loadouts: Vec<DeckEntry>,
}

impl Default for InventoryResponse {
    fn default() -> Self {
        Self::default_inventory()
    }
}

impl InventoryResponse {
    pub fn new(
        champion_roster: Vec<ChampionRosterEntry>,
        weapon_devices: Vec<DeviceEntry>,
        deck_loadouts: Vec<DeckEntry>,
    ) -> Self {
        Self {
            champion_roster,
            weapon_devices,
            deck_loadouts,
        }
    }

    pub fn default_inventory() -> Self {
        let (champion_roster, weapon_devices, deck_loadouts) = create_default_inventory();
        Self {
            champion_roster,
            weapon_devices,
            deck_loadouts,
        }
    }

    pub fn to_marshal_message(&self) -> CMarshalMessage {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_ON_LOGIN_RESPONSE);
        msg.add_champion_roster(&self.champion_roster);
        msg.add_weapon_devices(&self.weapon_devices);
        msg.add_deck_loadouts(&self.deck_loadouts);
        msg
    }

    pub fn from_marshal_message(msg: &CMarshalMessage) -> Result<Self, NetError> {
        let champion_roster = msg.get_champion_roster()?.unwrap_or_default();
        let weapon_devices = msg.get_weapon_devices()?.unwrap_or_default();
        let deck_loadouts = msg.get_deck_loadouts()?.unwrap_or_default();

        Ok(Self {
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

/// Cleanroom Login Response packet (`OnLoginResponse`)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoginResponse {
    pub status: i32,
    pub account_id: i32,
    pub session_token: String,
    pub match_ticket: MatchTicket,
    pub champion_roster: Vec<ChampionRosterEntry>,
    pub weapon_devices: Vec<DeviceEntry>,
    pub deck_loadouts: Vec<DeckEntry>,
}

impl LoginResponse {
    pub fn new(
        account_id: i32,
        session_token: impl Into<String>,
        match_ticket: MatchTicket,
    ) -> Self {
        let (champion_roster, weapon_devices, deck_loadouts) = create_default_inventory();
        Self {
            status: 0,
            account_id,
            session_token: session_token.into(),
            match_ticket,
            champion_roster,
            weapon_devices,
            deck_loadouts,
        }
    }

    pub fn with_inventory(
        account_id: i32,
        session_token: impl Into<String>,
        match_ticket: MatchTicket,
        champion_roster: Vec<ChampionRosterEntry>,
        weapon_devices: Vec<DeviceEntry>,
        deck_loadouts: Vec<DeckEntry>,
    ) -> Self {
        Self {
            status: 0,
            account_id,
            session_token: session_token.into(),
            match_ticket,
            champion_roster,
            weapon_devices,
            deck_loadouts,
        }
    }

    pub fn to_marshal_message(&self) -> CMarshalMessage {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_ON_LOGIN_RESPONSE);
        msg.add_integer(TOKEN_STATUS, self.status);
        msg.add_integer(TOKEN_ACCOUNT_ID, self.account_id);
        msg.add_string(TOKEN_SESSION_TOKEN, &self.session_token);
        msg.add_blob(TOKEN_MATCH_TICKET, self.match_ticket.to_bytes());
        msg.add_champion_roster(&self.champion_roster);
        msg.add_weapon_devices(&self.weapon_devices);
        msg.add_deck_loadouts(&self.deck_loadouts);
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

        let champion_roster = msg.get_champion_roster()?.unwrap_or_default();
        let weapon_devices = msg.get_weapon_devices()?.unwrap_or_default();
        let deck_loadouts = msg.get_deck_loadouts()?.unwrap_or_default();

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
        let response = LoginResponse::new(10001, "IMMORTAL-DEV-SESSION-TICKET", ticket);

        let encoded = response.to_bytes().unwrap();
        let decoded = LoginResponse::from_bytes(&encoded).unwrap();

        assert_eq!(response.status, decoded.status);
        assert_eq!(response.account_id, decoded.account_id);
        assert_eq!(response.session_token, decoded.session_token);
        assert_eq!(response.match_ticket, decoded.match_ticket);
        assert_eq!(response.champion_roster, decoded.champion_roster);
        assert_eq!(response.weapon_devices, decoded.weapon_devices);
        assert_eq!(response.deck_loadouts, decoded.deck_loadouts);
        assert_eq!(response, decoded);
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

    #[test]
    fn test_champion_roster_roundtrip() {
        let entries = vec![
            ChampionRosterEntry::new(CHAMPION_FERNANDO, true),
            ChampionRosterEntry::new(CHAMPION_CASSIE, true),
            ChampionRosterEntry::new(CHAMPION_VIKTOR, false),
            ChampionRosterEntry::new(9999, true),
        ];

        let bytes = ChampionRosterEntry::encode_row_set(&entries);
        let decoded = ChampionRosterEntry::decode_row_set(&bytes).unwrap();
        assert_eq!(entries, decoded);

        // Single entry roundtrip
        let single = ChampionRosterEntry::new(CHAMPION_FERNANDO, true);
        let single_bytes = single.to_bytes();
        assert_eq!(single_bytes.len(), 5);
        let decoded_single = ChampionRosterEntry::from_bytes(&single_bytes).unwrap();
        assert_eq!(single, decoded_single);

        // Empty roster
        let empty: Vec<ChampionRosterEntry> = Vec::new();
        let empty_bytes = ChampionRosterEntry::encode_row_set(&empty);
        assert_eq!(empty_bytes.len(), 4);
        let decoded_empty = ChampionRosterEntry::decode_row_set(&empty_bytes).unwrap();
        assert_eq!(empty, decoded_empty);
    }

    #[test]
    fn test_device_entry_roundtrip() {
        let entries = vec![
            DeviceEntry::new(DEVICE_FERNANDO_FLAME_LANCE, CHAMPION_FERNANDO),
            DeviceEntry::new(20001, CHAMPION_CASSIE),
        ];

        let bytes = DeviceEntry::encode_row_set(&entries);
        let decoded = DeviceEntry::decode_row_set(&bytes).unwrap();
        assert_eq!(entries, decoded);

        // Single entry roundtrip
        let single = DeviceEntry::new(DEVICE_FERNANDO_FLAME_LANCE, CHAMPION_FERNANDO);
        let single_bytes = single.to_bytes();
        assert_eq!(single_bytes.len(), 8);
        let decoded_single = DeviceEntry::from_bytes(&single_bytes).unwrap();
        assert_eq!(single, decoded_single);

        // Empty devices
        let empty: Vec<DeviceEntry> = Vec::new();
        let empty_bytes = DeviceEntry::encode_row_set(&empty);
        assert_eq!(empty_bytes.len(), 4);
        let decoded_empty = DeviceEntry::decode_row_set(&empty_bytes).unwrap();
        assert_eq!(empty, decoded_empty);
    }

    #[test]
    fn test_deck_entry_roundtrip() {
        let entries = vec![
            DeckEntry::new(DECK_FERNANDO_STARTER, CHAMPION_FERNANDO),
            DeckEntry::new(30001, CHAMPION_VIKTOR),
        ];

        let bytes = DeckEntry::encode_row_set(&entries);
        let decoded = DeckEntry::decode_row_set(&bytes).unwrap();
        assert_eq!(entries, decoded);

        // Single entry roundtrip
        let single = DeckEntry::new(DECK_FERNANDO_STARTER, CHAMPION_FERNANDO);
        let single_bytes = single.to_bytes();
        assert_eq!(single_bytes.len(), 8);
        let decoded_single = DeckEntry::from_bytes(&single_bytes).unwrap();
        assert_eq!(single, decoded_single);

        // Empty decks
        let empty: Vec<DeckEntry> = Vec::new();
        let empty_bytes = DeckEntry::encode_row_set(&empty);
        assert_eq!(empty_bytes.len(), 4);
        let decoded_empty = DeckEntry::decode_row_set(&empty_bytes).unwrap();
        assert_eq!(empty, decoded_empty);
    }

    #[test]
    fn test_default_inventory() {
        let (champions, devices, decks) = create_default_inventory();
        assert_eq!(champions.len(), 3);
        assert!(champions
            .iter()
            .any(|c| c.champion_id == CHAMPION_FERNANDO && c.owned));
        assert!(champions
            .iter()
            .any(|c| c.champion_id == CHAMPION_CASSIE && c.owned));
        assert!(champions
            .iter()
            .any(|c| c.champion_id == CHAMPION_VIKTOR && c.owned));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, DEVICE_FERNANDO_FLAME_LANCE);
        assert_eq!(devices[0].champion_id, CHAMPION_FERNANDO);

        assert_eq!(decks.len(), 1);
        assert_eq!(decks[0].deck_id, DECK_FERNANDO_STARTER);
        assert_eq!(decks[0].champion_id, CHAMPION_FERNANDO);
    }

    #[test]
    fn test_inventory_response_roundtrip() {
        let inv = InventoryResponse::default_inventory();
        let encoded = inv.to_bytes().unwrap();
        let decoded = InventoryResponse::from_bytes(&encoded).unwrap();
        assert_eq!(inv, decoded);

        let empty_inv = InventoryResponse::new(Vec::new(), Vec::new(), Vec::new());
        let encoded_empty = empty_inv.to_bytes().unwrap();
        let decoded_empty = InventoryResponse::from_bytes(&encoded_empty).unwrap();
        assert_eq!(empty_inv, decoded_empty);
    }

    #[test]
    fn test_login_response_backwards_compatibility() {
        // Construct a message without any inventory tokens (like older protocol clients/servers)
        let mut msg = CMarshalMessage::new(FUNCTION_ID_ON_LOGIN_RESPONSE);
        msg.add_integer(TOKEN_STATUS, 0);
        msg.add_integer(TOKEN_ACCOUNT_ID, 8302401);
        msg.add_string(TOKEN_SESSION_TOKEN, "LEGACY_SESSION");
        let ticket = MatchTicket::new("127.0.0.1", 7777, "LEGACY_TICKET");
        msg.add_blob(TOKEN_MATCH_TICKET, ticket.to_bytes());

        let encoded = msg.encode().unwrap();
        let decoded = LoginResponse::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.account_id, 8302401);
        assert_eq!(decoded.session_token, "LEGACY_SESSION");
        assert_eq!(decoded.match_ticket, ticket);
        assert!(decoded.champion_roster.is_empty());
        assert!(decoded.weapon_devices.is_empty());
        assert!(decoded.deck_loadouts.is_empty());
    }

    #[test]
    fn test_login_response_with_custom_inventory() {
        let ticket = MatchTicket::new("10.0.0.1", 7777, "CUSTOM_TICKET");
        let custom_champions = vec![ChampionRosterEntry::new(CHAMPION_FERNANDO, true)];
        let custom_devices = vec![DeviceEntry::new(
            DEVICE_FERNANDO_FLAME_LANCE,
            CHAMPION_FERNANDO,
        )];
        let custom_decks = vec![DeckEntry::new(DECK_FERNANDO_STARTER, CHAMPION_FERNANDO)];

        let response = LoginResponse::with_inventory(
            99999,
            "CUSTOM_SESSION",
            ticket,
            custom_champions.clone(),
            custom_devices.clone(),
            custom_decks.clone(),
        );

        let encoded = response.to_bytes().unwrap();
        let decoded = LoginResponse::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.account_id, 99999);
        assert_eq!(decoded.session_token, "CUSTOM_SESSION");
        assert_eq!(decoded.champion_roster, custom_champions);
        assert_eq!(decoded.weapon_devices, custom_devices);
        assert_eq!(decoded.deck_loadouts, custom_decks);
    }

    #[test]
    fn test_marshal_message_inventory_helpers() {
        let mut msg = CMarshalMessage::new(FUNCTION_ID_ON_LOGIN_RESPONSE);
        let (champions, devices, decks) = create_default_inventory();

        msg.add_champion_roster(&champions);
        msg.add_weapon_devices(&devices);
        msg.add_deck_loadouts(&decks);

        assert_eq!(msg.get_champion_roster().unwrap(), Some(champions));
        assert_eq!(msg.get_weapon_devices().unwrap(), Some(devices));
        assert_eq!(msg.get_deck_loadouts().unwrap(), Some(decks));
    }

    #[test]
    fn test_corrupted_rowsets_handling() {
        // Truncated count header
        assert!(ChampionRosterEntry::decode_row_set(&[0u8, 1u8]).is_err());
        assert!(DeviceEntry::decode_row_set(&[0u8, 1u8]).is_err());
        assert!(DeckEntry::decode_row_set(&[0u8, 1u8]).is_err());

        // Count header says 1 entry, but body is truncated
        let count_one = 1u32.to_le_bytes();
        assert!(ChampionRosterEntry::decode_row_set(&count_one).is_err());
        assert!(DeviceEntry::decode_row_set(&count_one).is_err());
        assert!(DeckEntry::decode_row_set(&count_one).is_err());

        // Truncated single entries
        assert!(ChampionRosterEntry::from_bytes(&[1, 2, 3]).is_err());
        assert!(DeviceEntry::from_bytes(&[1, 2, 3, 4]).is_err());
        assert!(DeckEntry::from_bytes(&[1, 2, 3, 4]).is_err());
    }
}
