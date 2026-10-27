// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Hermetic synthetic tests and optional real game asset integration tests for UPK parsing.

use std::io::Cursor;
use std::path::Path;

use immortal_extract::{
    write_compressed_chunk, ExportTable, FCompressedChunk, FName, GenerationInfo, ImportTable,
    NameEntry, NameTable, ObjectExport, ObjectImport, PackageIndex, PackageSummary, UpkPackage,
    COMPRESS_LZO, COMPRESS_ZLIB, PKG_COMPRESSED, PKG_COOKED, UPK_MAGIC,
};

/// Helper to build a hermetic synthetic UPK package in memory.
fn build_synthetic_upk(compression_flags: u32, chunk_payloads: &[Vec<u8>]) -> (Vec<u8>, Vec<u8>) {
    let mut header_buf = Vec::new();
    let mut package_buf = Vec::new();

    let mut summary = PackageSummary {
        tag: UPK_MAGIC,
        file_version: 893,
        licensee_version: 0,
        total_header_size: 0, // updated below
        folder_name: "ChaosGame/CookedPCConsole".to_string(),
        package_flags: PKG_COOKED | PKG_COMPRESSED,
        name_count: 10,
        name_offset: 0,
        export_count: 5,
        export_offset: 0,
        import_count: 2,
        import_offset: 0,
        depends_offset: 0,
        import_export_guids_offset: 0,
        import_guids_count: 0,
        export_guids_count: 0,
        thumbnail_table_offset: 0,
        guid: [0x42; 16],
        generations: vec![GenerationInfo {
            export_count: 5,
            name_count: 10,
            net_object_count: 0,
        }],
        engine_version: 10897,
        cooker_version: 393358,
        compression_flags,
        compressed_chunks: Vec::new(),
    };

    // First write dummy summary to get header size
    summary.write(&mut header_buf).unwrap();
    let header_uncompressed_prefix_len = header_buf.len() as u32;

    let mut chunks = Vec::new();
    let mut current_uncompressed_offset = header_uncompressed_prefix_len;

    // Reserve space for header table with chunk metadata in package_buf
    // Chunks will be written starting after a tentative header offset
    let dummy_chunk = FCompressedChunk {
        uncompressed_offset: 0,
        uncompressed_size: 0,
        compressed_offset: 0,
        compressed_size: 0,
    };
    summary.compressed_chunks = vec![dummy_chunk; chunk_payloads.len()];
    header_buf.clear();
    summary.write(&mut header_buf).unwrap();

    let mut compressed_chunks_buf = Vec::new();
    let compressed_offset_start = header_buf.len() as u32;
    let mut current_comp_offset = compressed_offset_start;

    for payload in chunk_payloads {
        let chunk_meta = write_compressed_chunk(
            &mut compressed_chunks_buf,
            current_uncompressed_offset,
            current_comp_offset,
            payload,
            2048,
            compression_flags,
        )
        .unwrap();

        current_uncompressed_offset += payload.len() as u32;
        current_comp_offset += chunk_meta.compressed_size;
        chunks.push(chunk_meta);
    }

    summary.compressed_chunks = chunks;
    summary.total_header_size = current_uncompressed_offset;

    package_buf.clear();
    summary.write(&mut package_buf).unwrap();
    package_buf.extend_from_slice(&compressed_chunks_buf);

    let mut virtual_uncompressed = Vec::new();
    let first_uncomp_offset = summary.compressed_chunks[0].uncompressed_offset as usize;
    virtual_uncompressed.extend_from_slice(&package_buf[..first_uncomp_offset]);
    for payload in chunk_payloads {
        virtual_uncompressed.extend_from_slice(payload);
    }

    (package_buf, virtual_uncompressed)
}

#[test]
fn test_synthetic_upk_compressed_lzo() {
    let payload1 = b"Chunk 1: Synthetic Champion Mesh & Skeletal Animation Data".repeat(200);
    let payload2 = b"Chunk 2: Synthetic Texture LOD and Shader Microcode".repeat(300);

    let (package_data, expected_uncompressed) =
        build_synthetic_upk(COMPRESS_LZO, &[payload1.clone(), payload2.clone()]);

    let cursor = Cursor::new(package_data);
    let mut pkg = UpkPackage::open(cursor).expect("Failed to open synthetic UPK");

    assert_eq!(pkg.summary().tag, UPK_MAGIC);
    assert_eq!(pkg.summary().file_version, 893);
    assert_eq!(pkg.summary().folder_name, "ChaosGame/CookedPCConsole");
    assert!(pkg.summary().is_cooked());
    assert!(pkg.summary().is_compressed());
    assert_eq!(pkg.compressed_chunks().len(), 2);

    // Test individual chunk decompression
    let decomp1 = pkg.decompress_chunk_at(0).unwrap();
    assert_eq!(decomp1, payload1);

    let decomp2 = pkg.decompress_chunk_at(1).unwrap();
    assert_eq!(decomp2, payload2);

    // Test full decompress
    let full = pkg.decompress_all().unwrap();
    assert_eq!(full, expected_uncompressed);

    // Test slice read entirely within uncompressed header prefix
    let header_slice = pkg.read_bytes(0, 50).unwrap();
    assert_eq!(header_slice, expected_uncompressed[0..50]);

    // Test cross-boundary slice read spanning uncompressed header and chunk 0
    let chunk0_off = pkg.compressed_chunks()[0].uncompressed_offset as u64;
    let cross_offset = chunk0_off - 30;
    let cross_len = 100;
    let cross_slice = pkg.read_bytes(cross_offset, cross_len).unwrap();
    assert_eq!(
        cross_slice,
        expected_uncompressed[cross_offset as usize..(cross_offset as usize + cross_len)]
    );

    // Test slice read spanning both chunk 0 and chunk 1
    let offset = chunk0_off + 50;
    let read_len = 200;
    let slice = pkg.read_bytes(offset, read_len).unwrap();
    assert_eq!(
        slice,
        expected_uncompressed[offset as usize..(offset as usize + read_len)]
    );
}

#[test]
fn test_synthetic_upk_compressed_zlib() {
    let payload1 = b"Zlib Synthetic Audio Waveform & SoundCue Nodes".repeat(250);
    let payload2 = b"Zlib Synthetic Collision Mesh Hierarchy & Physics Body".repeat(150);

    let (package_data, expected_uncompressed) =
        build_synthetic_upk(COMPRESS_ZLIB, &[payload1.clone(), payload2.clone()]);

    let cursor = Cursor::new(package_data);
    let mut pkg = UpkPackage::open(cursor).expect("Failed to open synthetic Zlib UPK");

    assert_eq!(pkg.summary().tag, UPK_MAGIC);
    assert_eq!(pkg.summary().compression_flags, COMPRESS_ZLIB);

    let decomp1 = pkg.decompress_chunk_at(0).unwrap();
    assert_eq!(decomp1, payload1);

    let decomp2 = pkg.decompress_chunk_at(1).unwrap();
    assert_eq!(decomp2, payload2);

    let full = pkg.decompress_all().unwrap();
    assert_eq!(full, expected_uncompressed);
}

#[test]
fn test_synthetic_upk_uncompressed() {
    let summary = PackageSummary {
        tag: UPK_MAGIC,
        file_version: 893,
        licensee_version: 0,
        total_header_size: 512,
        folder_name: "ChaosGame/CookedPCConsole".to_string(),
        package_flags: PKG_COOKED,
        name_count: 5,
        name_offset: 100,
        export_count: 2,
        export_offset: 200,
        import_count: 1,
        import_offset: 300,
        depends_offset: 400,
        import_export_guids_offset: 500,
        import_guids_count: 0,
        export_guids_count: 0,
        thumbnail_table_offset: 0,
        guid: [0x55; 16],
        generations: vec![GenerationInfo {
            export_count: 2,
            name_count: 5,
            net_object_count: 0,
        }],
        engine_version: 10897,
        cooker_version: 393358,
        compression_flags: 0,
        compressed_chunks: Vec::new(),
    };

    let mut buf = Vec::new();
    summary.write(&mut buf).unwrap();
    let body = b"Direct uncompressed package body payload data".repeat(20);
    buf.extend_from_slice(&body);

    let cursor = Cursor::new(buf.clone());
    let mut pkg = UpkPackage::open(cursor).unwrap();

    assert!(!pkg.summary().is_compressed());
    let full = pkg.decompress_all().unwrap();
    assert_eq!(full, buf);

    let slice = pkg.read_bytes(10, 25).unwrap();
    assert_eq!(slice, buf[10..35]);
}

#[test]
fn test_synthetic_upk_object_tables_and_path_resolution() {
    let name_table = NameTable::new(vec![
        NameEntry::new("None", 0),
        NameEntry::new("Core", 0),
        NameEntry::new("Package", 0),
        NameEntry::new("Class", 0),
        NameEntry::new("ChaosGame", 0),
        NameEntry::new("Characters", 0),
        NameEntry::new("Fernando", 0),
        NameEntry::new("SkeletalMesh", 0),
        NameEntry::new("akbank", 0),
    ]);

    // Import 0: Package "ChaosGame"
    // Import 1: Package "Characters" with outer = Import 0 ("ChaosGame")
    // Import 2: Class "akbank"
    let import_table = ImportTable::new(vec![
        ObjectImport {
            class_package: FName::new(1, 0), // Core
            class_name: FName::new(2, 0),    // Package
            outer_index: PackageIndex::NULL,
            object_name: FName::new(4, 0), // ChaosGame
        },
        ObjectImport {
            class_package: FName::new(1, 0), // Core
            class_name: FName::new(2, 0),    // Package
            outer_index: PackageIndex::from_import_index(0),
            object_name: FName::new(5, 0), // Characters
        },
        ObjectImport {
            class_package: FName::new(1, 0), // Core
            class_name: FName::new(3, 0),    // Class
            outer_index: PackageIndex::NULL,
            object_name: FName::new(8, 0), // akbank
        },
    ]);

    // Export 0: "Fernando" with outer = Import 1 ("Characters"), class = akbank
    // Export 1: "SkeletalMesh" with outer = Export 0 ("Fernando"), class = akbank
    let export_table = ExportTable::new(vec![
        ObjectExport {
            class_index: PackageIndex::from_import_index(2), // akbank
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::from_import_index(1), // Characters
            object_name: FName::new(6, 0),                   // Fernando
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 1024,
            serial_offset: 2048,
            export_flags: 0,
            generation_net_object_count: 0,
            guid: [0x11; 16],
            package_flags: 0,
        },
        ObjectExport {
            class_index: PackageIndex::from_import_index(2), // akbank
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::from_export_index(0), // Fernando
            object_name: FName::new(7, 0),                   // SkeletalMesh
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 2048,
            serial_offset: 3072,
            export_flags: 0,
            generation_net_object_count: 0,
            guid: [0x22; 16],
            package_flags: 0,
        },
    ]);

    // Serialize tables to a memory buffer
    let mut tables_buf = Vec::new();
    let name_offset = 0u32;
    name_table.write(&mut tables_buf).unwrap();

    let import_offset = tables_buf.len() as u32;
    import_table.write(&mut tables_buf).unwrap();

    let export_offset = tables_buf.len() as u32;
    export_table.write(&mut tables_buf).unwrap();

    let total_table_bytes = tables_buf.len() as u32;

    // Build synthetic uncompressed UPK package
    let summary = PackageSummary {
        tag: UPK_MAGIC,
        file_version: 893,
        licensee_version: 0,
        total_header_size: 1024 + total_table_bytes,
        folder_name: "ChaosGame/CookedPCConsole".to_string(),
        package_flags: PKG_COOKED,
        name_count: name_table.len() as u32,
        name_offset: 1024 + name_offset,
        export_count: export_table.len() as u32,
        export_offset: 1024 + export_offset,
        import_count: import_table.len() as u32,
        import_offset: 1024 + import_offset,
        depends_offset: 0,
        import_export_guids_offset: 0,
        import_guids_count: 0,
        export_guids_count: 0,
        thumbnail_table_offset: 0,
        guid: [0x33; 16],
        generations: vec![GenerationInfo {
            export_count: export_table.len() as i32,
            name_count: name_table.len() as i32,
            net_object_count: 0,
        }],
        engine_version: 10897,
        cooker_version: 393358,
        compression_flags: 0,
        compressed_chunks: Vec::new(),
    };

    let mut pkg_buf = Vec::new();
    summary.write(&mut pkg_buf).unwrap();
    // Pad to offset 1024
    if pkg_buf.len() < 1024 {
        pkg_buf.resize(1024, 0);
    }
    pkg_buf.extend_from_slice(&tables_buf);

    let mut pkg = UpkPackage::open(Cursor::new(pkg_buf)).expect("Open synthetic package failed");

    let (read_names, read_imports, read_exports) = pkg
        .read_tables()
        .expect("Reading tables from synthetic package failed");

    assert_eq!(read_names, name_table);
    assert_eq!(read_imports, import_table);
    assert_eq!(read_exports, export_table);

    // Verify outer chain resolution:
    // Export 0 ("Fernando") -> outer is Import 1 ("Characters") -> outer is Import 0 ("ChaosGame") -> outer is NULL
    let path_exp0 = pkg.resolve_full_path(
        &read_names,
        &read_imports,
        &read_exports,
        PackageIndex::from_export_index(0),
    );
    assert_eq!(path_exp0, "ChaosGame.Characters.Fernando");

    // Export 1 ("SkeletalMesh") -> outer is Export 0 ("Fernando") -> ...
    let path_exp1 = pkg.resolve_full_path(
        &read_names,
        &read_imports,
        &read_exports,
        PackageIndex::from_export_index(1),
    );
    assert_eq!(path_exp1, "ChaosGame.Characters.Fernando.SkeletalMesh");

    // Null index resolution
    assert_eq!(
        pkg.resolve_full_path(
            &read_names,
            &read_imports,
            &read_exports,
            PackageIndex::NULL
        ),
        "None"
    );

    // Class resolution
    let exp0 = read_exports.get(0).unwrap();
    let class_name = exp0
        .resolve_class_name(&read_names, &read_imports, &read_exports)
        .unwrap();
    assert_eq!(class_name, "akbank");
}

#[test]
fn test_probe_paladins_real_game_upk_if_present() {
    let candidate_paths = [
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/FERNANDO_ASSETS_SF.upk",
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/Fernando.upk",
    ];

    let found_path = candidate_paths.iter().find(|path| Path::new(path).exists());

    let path = match found_path {
        Some(p) => *p,
        None => {
            println!("Skipping real game asset integration test: asset file not found on disk");
            return;
        }
    };

    println!("Testing against real Paladins package: {path}");
    let mut pkg = UpkPackage::open_file(path)
        .expect("Failed to parse real Paladins CookedPCConsole package header");

    assert_eq!(pkg.summary().tag, UPK_MAGIC);
    assert!(
        pkg.summary().file_version >= 860,
        "Expected UE3 file version >= 860, got {}",
        pkg.summary().file_version
    );
    assert!(pkg.summary().is_cooked(), "Package must have PKG_Cooked");
    assert!(
        pkg.summary().is_compressed(),
        "Package must have PKG_Compressed"
    );
    assert_eq!(
        pkg.summary().compression_flags,
        COMPRESS_LZO,
        "Expected LZO compression"
    );
    assert!(
        !pkg.compressed_chunks().is_empty(),
        "Package must contain compressed chunks"
    );

    // Decompress chunk 0
    let chunk0 = pkg
        .decompress_chunk_at(0)
        .expect("Failed to decompress chunk 0 with LZO");
    assert_eq!(
        chunk0.len(),
        pkg.compressed_chunks()[0].uncompressed_size as usize,
        "Decompressed chunk size must match uncompressed_size in table"
    );

    println!(
        "Successfully verified real Paladins UPK (chunks: {}, chunk0 decompressed: {} bytes)",
        pkg.compressed_chunks().len(),
        chunk0.len()
    );

    // Read and verify tables
    let (name_table, import_table, export_table) = pkg
        .read_tables()
        .expect("Failed to read package object tables");

    assert_eq!(name_table.len(), pkg.summary().name_count as usize);
    assert_eq!(import_table.len(), pkg.summary().import_count as usize);
    assert_eq!(export_table.len(), pkg.summary().export_count as usize);

    if path.ends_with("FERNANDO_ASSETS_SF.upk") {
        let export0 = export_table.get(0).expect("Export 0 must exist");
        let obj_name = export0
            .resolve_object_name(&name_table)
            .expect("Export 0 object_name should resolve");
        assert_eq!(obj_name, "wwb_pc_knight");

        let class_name = export0
            .resolve_class_name(&name_table, &import_table, &export_table)
            .expect("Export 0 class_name should resolve");
        assert_eq!(class_name.to_lowercase(), "akbank");

        let full_path = pkg.resolve_full_path(
            &name_table,
            &import_table,
            &export_table,
            PackageIndex::from_export_index(0),
        );
        println!("Export 0: path='{full_path}', class='{class_name}'");
    }
}
