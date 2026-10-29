-- SPDX-License-Identifier: AGPL-3.0
-- Copyright (c) 2026 Arafat Zahan (@kuasha420)
-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

-- Schema for Dirty-Room Reverse Engineering Symbol & Analysis Database (paladins_symbols.sqlite)

CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    image_base INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    imported_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    address INTEGER NOT NULL,
    entry_point INTEGER NOT NULL,
    name TEXT NOT NULL,
    demangled_name TEXT,
    signature TEXT,
    size INTEGER NOT NULL,
    is_thunk BOOLEAN DEFAULT 0,
    is_exported BOOLEAN DEFAULT 0,
    UNIQUE(binary_id, address)
);

CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_demangled ON functions(demangled_name);
CREATE INDEX IF NOT EXISTS idx_functions_address ON functions(address);

CREATE TABLE IF NOT EXISTS rtti_classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    class_name TEXT NOT NULL,
    demangled_name TEXT NOT NULL,
    type_descriptor_addr INTEGER NOT NULL,
    complete_object_locator_addr INTEGER,
    class_hierarchy_addr INTEGER,
    vtable_addr INTEGER,
    base_classes_json TEXT,
    UNIQUE(binary_id, type_descriptor_addr)
);

CREATE INDEX IF NOT EXISTS idx_rtti_class_name ON rtti_classes(class_name);
CREATE INDEX IF NOT EXISTS idx_rtti_vtable ON rtti_classes(vtable_addr);

CREATE TABLE IF NOT EXISTS mcts_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_uint32 INTEGER NOT NULL UNIQUE,
    hash_hex TEXT NOT NULL,
    function_id INTEGER REFERENCES functions(id),
    token_name TEXT,
    raw_handler TEXT,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcts_hash_uint32 ON mcts_hashes(hash_uint32);

CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    address INTEGER NOT NULL,
    string_type TEXT NOT NULL, -- 'ascii' or 'utf16'
    value TEXT NOT NULL,
    length INTEGER NOT NULL,
    UNIQUE(binary_id, address)
);

CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value);
CREATE INDEX IF NOT EXISTS idx_strings_address ON strings(address);

CREATE TABLE IF NOT EXISTS xrefs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    from_addr INTEGER NOT NULL,
    to_addr INTEGER NOT NULL,
    xref_type TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_addr);
CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_addr);
