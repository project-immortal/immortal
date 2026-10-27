// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Hermetic synthetic tests and optional real game asset integration tests for UPK parsing.

use std::io::Cursor;
use std::path::Path;

use immortal_extract::{
    write_compressed_chunk, FCompressedChunk, GenerationInfo, PackageSummary, UpkPackage,
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
fn test_probe_paladins_real_game_upk_if_present() {
    let candidate_paths = [
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/Fernando.upk",
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/FERNANDO_ASSETS_SF.upk",
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
}
