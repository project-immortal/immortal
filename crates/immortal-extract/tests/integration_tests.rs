// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Hermetic synthetic tests and optional real game asset integration tests for UPK parsing.

use std::io::Cursor;
use std::path::Path;

use immortal_extract::{
    convert_coord_ue3_to_gltf, convert_wem_to_wav, create_bkhd, export_dds,
    export_skeletal_mesh_to_gltf, export_to_wav, export_weapon_skeletal_mesh,
    export_weapon_static_mesh, extract_package_collision, extract_weapon_texture,
    get_weapon_mapping, inspect_weapon_package, parse_bkhd, parse_wav, write_compressed_chunk,
    write_tfc_chunk, ExportTable, FByteBulkData, FCompressedChunk, FMeshBone, FName,
    FSkeletalMeshLODModel, FTexture2DMipMap, GPUSkinVertex, GenerationInfo, ImportTable,
    NameEntry, NameTable, ObjectExport, ObjectImport, PackageIndex, PackageSummary, PckArchive,
    RefSkeleton, TextureFormat, TfcResolver, UpkPackage, WavSpec, WeaponExtractionPipeline,
    BULKDATA_COMPRESSED_LZO, BULKDATA_COMPRESSED_ZLIB, BULKDATA_STORE_IN_SEPARATE_FILE,
    CHAMPION_FERNANDO, COMPRESS_LZO, COMPRESS_ZLIB, DEVICE_FERNANDO_FLAME_LANCE, PKG_COMPRESSED,
    PKG_COOKED, UPK_MAGIC,
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
            generation_net_object_count: vec![],
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
            generation_net_object_count: vec![],
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

#[test]
fn test_integration_synthetic_tfc_and_dds_pipeline() {
    let temp_dir = std::env::temp_dir().join(format!("immortal_test_tfc_{}", std::process::id()));
    let cooked_dir = temp_dir.join("ChaosGame").join("CookedPCConsole");
    std::fs::create_dir_all(&cooked_dir).expect("Failed to create cooked directory");

    let tfc_file_path = cooked_dir.join("CharNormals0.tfc");
    let mut tfc_file = std::fs::File::create(&tfc_file_path).expect("Failed to create TFC file");

    // Write Mip 0: DXT1 compressed with LZO
    let dxt1_pixels = vec![0x55u8; 1024]; // 64x64 DXT1
    let (offset_mip0, size_mip0) =
        write_tfc_chunk(&mut tfc_file, &dxt1_pixels, Some(COMPRESS_LZO)).unwrap();

    // Write Mip 1: DXT5 compressed with ZLIB
    let dxt5_pixels = vec![0xAAu8; 2048]; // 64x64 DXT5
    let (offset_mip1, size_mip1) =
        write_tfc_chunk(&mut tfc_file, &dxt5_pixels, Some(COMPRESS_ZLIB)).unwrap();

    // Write Mip 2: BC7 uncompressed
    let bc7_pixels = vec![0x77u8; 4096]; // 128x64 BC7
    let (offset_mip2, size_mip2) = write_tfc_chunk(&mut tfc_file, &bc7_pixels, None).unwrap();

    drop(tfc_file);

    // Resolve via TfcResolver
    let resolver = TfcResolver::new(&temp_dir);
    let resolved_path = resolver.resolve_tfc_path("CharNormals0");
    assert_eq!(resolved_path, tfc_file_path);

    // Extract Mip 0 and export DDS
    let mip0 = FTexture2DMipMap {
        bulk_data: FByteBulkData {
            bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE | BULKDATA_COMPRESSED_LZO,
            element_count: dxt1_pixels.len() as u32,
            size_on_disk: size_mip0,
            offset_in_file: offset_mip0 as i64,
        },
        size_x: 64,
        size_y: 64,
        inline_data: None,
    };
    let extracted_mip0 = resolver
        .extract_mip_from_tfc("CharNormals0", &mip0)
        .unwrap();
    assert_eq!(extracted_mip0, dxt1_pixels);
    let dds0 = export_dds(64, 64, TextureFormat::Dxt1, &extracted_mip0);
    assert_eq!(&dds0[0..4], b"DDS ");
    assert_eq!(dds0.len(), 128 + dxt1_pixels.len());

    // Extract Mip 1 and export DDS
    let mip1 = FTexture2DMipMap {
        bulk_data: FByteBulkData {
            bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE | BULKDATA_COMPRESSED_ZLIB,
            element_count: dxt5_pixels.len() as u32,
            size_on_disk: size_mip1,
            offset_in_file: offset_mip1 as i64,
        },
        size_x: 64,
        size_y: 64,
        inline_data: None,
    };
    let extracted_mip1 = resolver
        .extract_mip_from_tfc("CharNormals0", &mip1)
        .unwrap();
    assert_eq!(extracted_mip1, dxt5_pixels);
    let dds1 = export_dds(64, 64, TextureFormat::Dxt5, &extracted_mip1);
    assert_eq!(&dds1[0..4], b"DDS ");
    assert_eq!(dds1.len(), 128 + dxt5_pixels.len());

    // Extract Mip 2 and export DDS
    let mip2 = FTexture2DMipMap {
        bulk_data: FByteBulkData {
            bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE,
            element_count: bc7_pixels.len() as u32,
            size_on_disk: size_mip2,
            offset_in_file: offset_mip2 as i64,
        },
        size_x: 128,
        size_y: 64,
        inline_data: None,
    };
    let extracted_mip2 = resolver
        .extract_mip_from_tfc("CharNormals0", &mip2)
        .unwrap();
    assert_eq!(extracted_mip2, bc7_pixels);
    let dds2 = export_dds(128, 64, TextureFormat::Bc7, &extracted_mip2);
    assert_eq!(&dds2[0..4], b"DDS ");
    assert_eq!(&dds2[84..88], b"DX10");
    assert_eq!(dds2.len(), 148 + bc7_pixels.len());

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_synthetic_akpk_soundbank_and_wav_pipeline() {
    let mut pck_stream = Cursor::new(Vec::new());

    // Soundbank BKHD
    let bank_payload = create_bkhd(120, 133742, b"PaladinsWwiseBankData");

    // Two WEM audio streams
    let raw_pcm_stream = [0x34, 0x12].repeat(500); // 1000 bytes
    let wav_stream = export_to_wav(&WavSpec::pcm(44100, 2, 16), &[0x77; 400]);

    PckArchive::write(
        &mut pck_stream,
        1,
        &[(133742, &bank_payload)],
        &[(9001, &raw_pcm_stream), (9002, &wav_stream)],
    )
    .expect("Failed to write synthetic PCK");

    pck_stream.set_position(0);
    let archive = PckArchive::read(&mut pck_stream).expect("Failed to parse PCK archive");

    assert_eq!(archive.soundbanks.len(), 1);
    assert_eq!(archive.streams.len(), 2);

    // Verify BKHD bank extraction
    let bkhd_entry = archive
        .get_soundbank(133742)
        .expect("Soundbank 133742 not found");
    let extracted_bank = archive.extract_entry(&mut pck_stream, bkhd_entry).unwrap();
    let bkhd_header = parse_bkhd(&extracted_bank).unwrap();
    assert_eq!(bkhd_header.soundbank_id, 133742);
    assert_eq!(bkhd_header.generator_version, 120);

    // Verify Stream 1 extraction & conversion to WAV
    let stream1_entry = archive
        .find_entry("9001.wem")
        .expect("Stream 9001 not found");
    let extracted_stream1 = archive
        .extract_entry(&mut pck_stream, stream1_entry)
        .unwrap();
    let wav1 = convert_wem_to_wav(&extracted_stream1, Some(WavSpec::pcm(48000, 1, 16))).unwrap();
    let (spec1, samples1) = parse_wav(&wav1).unwrap();
    assert_eq!(spec1.sample_rate, 48000);
    assert_eq!(spec1.num_channels, 1);
    assert_eq!(samples1, raw_pcm_stream.as_slice());

    // Verify Stream 2 extraction & conversion
    let stream2_entry = archive.find_entry("9002").expect("Stream 9002 not found");
    let extracted_stream2 = archive
        .extract_entry(&mut pck_stream, stream2_entry)
        .unwrap();
    let wav2 = convert_wem_to_wav(&extracted_stream2, None).unwrap();
    let (spec2, samples2) = parse_wav(&wav2).unwrap();
    assert_eq!(spec2.sample_rate, 44100);
    assert_eq!(spec2.num_channels, 2);
    assert_eq!(samples2, &[0x77; 400]);
}

#[test]
fn test_integration_synthetic_skeletal_mesh_to_gltf_pipeline() {
    // 1. RefSkeleton with root and 2 child bones
    let skeleton = RefSkeleton::new(vec![
        FMeshBone {
            name: "Root".to_string(),
            parent_index: -1,
            position: [0.0, 0.0, 0.0],
            orientation: [0.0, 0.0, 0.0, 1.0],
            num_children: 1,
            flags: 0,
        },
        FMeshBone {
            name: "Pelvis".to_string(),
            parent_index: 0,
            position: [0.0, 0.0, 50.0],
            orientation: [0.0, 0.0, 0.0, 1.0],
            num_children: 1,
            flags: 0,
        },
        FMeshBone {
            name: "Spine".to_string(),
            parent_index: 1,
            position: [0.0, 0.0, 40.0],
            orientation: [0.0, 0.0, 0.0, 1.0],
            num_children: 0,
            flags: 0,
        },
    ]);

    // 2. SkeletalMesh LOD model with GPUSkin vertices
    let vertices = vec![
        GPUSkinVertex {
            position: [-10.0, 0.0, 50.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [0.0, 1.0],
            joints_0: [1, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
        GPUSkinVertex {
            position: [10.0, 0.0, 50.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [1.0, 1.0],
            joints_0: [1, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
        GPUSkinVertex {
            position: [0.0, 0.0, 90.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [0.5, 0.0],
            joints_0: [2, 1, 0, 0],
            weights_0: [0.75, 0.25, 0.0, 0.0],
        },
    ];
    let indices = vec![0, 1, 2];
    let lod_model = FSkeletalMeshLODModel { vertices, indices };

    // 3. Export to glTF 2.0
    let export = export_skeletal_mesh_to_gltf(&lod_model, Some(&skeleton), "character.bin")
        .expect("Failed to export glTF");

    // Validate glTF JSON structure
    let root: serde_json::Value = serde_json::from_str(&export.gltf_json).unwrap();
    assert_eq!(root["asset"]["version"], "2.0");
    assert_eq!(root["buffers"][0]["uri"], "character.bin");
    assert_eq!(root["nodes"].as_array().unwrap().len(), 4); // 1 mesh + 3 bones
    assert_eq!(root["skins"].as_array().unwrap().len(), 1);

    // Validate coordinate conversions: UE3 [x, y, z] -> glTF [x, z, -y]
    let converted_pos0 = convert_coord_ue3_to_gltf([-10.0, 0.0, 50.0]);
    assert_eq!(converted_pos0, [-10.0, 50.0, 0.0]);

    // 4. Save to temporary directory
    let temp_dir = std::env::temp_dir().join(format!("immortal_gltf_test_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let (gltf_path, bin_path) = export.save_to_dir(&temp_dir, "character").unwrap();

    assert!(gltf_path.exists());
    assert!(bin_path.exists());
    assert_eq!(
        std::fs::metadata(&bin_path).unwrap().len(),
        export.bin_data.len() as u64
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_synthetic_weapon_package_and_gltf_pipeline() {
    // 1. Verify cleanroom weapon mapping for Flame Lance
    let mapping = get_weapon_mapping(DEVICE_FERNANDO_FLAME_LANCE)
        .expect("Mapping for DEVICE_FERNANDO_FLAME_LANCE must exist");
    assert_eq!(mapping.device_id, 10774);
    assert_eq!(mapping.champion_id, CHAMPION_FERNANDO);
    assert_eq!(mapping.device_name, "Flame Lance");
    assert_eq!(mapping.champion_name, "Fernando");

    // 2. Build synthetic weapon UPK with Name, Import, and Export tables
    let name_table = NameTable::new(vec![
        NameEntry::new("None", 0),
        NameEntry::new("Core", 0),
        NameEntry::new("Class", 0),
        NameEntry::new("SkeletalMesh", 0),
        NameEntry::new("StaticMesh", 0),
        NameEntry::new("Texture2D", 0),
        NameEntry::new("skl_wep_fernando_skin11a_1p", 0),
        NameEntry::new("skl_wep_fernando_skin11a_3p", 0),
        NameEntry::new("sm_fernando_skin11a_aresshield_center", 0),
        NameEntry::new("t_pc_fernando_arms_skin00a_dif", 0),
    ]);

    let import_table = ImportTable::new(vec![
        ObjectImport {
            class_package: FName::new(1, 0),
            class_name: FName::new(2, 0),
            outer_index: PackageIndex::NULL,
            object_name: FName::new(3, 0), // SkeletalMesh
        },
        ObjectImport {
            class_package: FName::new(1, 0),
            class_name: FName::new(2, 0),
            outer_index: PackageIndex::NULL,
            object_name: FName::new(4, 0), // StaticMesh
        },
        ObjectImport {
            class_package: FName::new(1, 0),
            class_name: FName::new(2, 0),
            outer_index: PackageIndex::NULL,
            object_name: FName::new(5, 0), // Texture2D
        },
    ]);

    let export_table = ExportTable::new(vec![
        ObjectExport {
            class_index: PackageIndex::from_import_index(0), // SkeletalMesh
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(6, 0), // skl_wep_fernando_skin11a_1p
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 442925,
            serial_offset: 1000,
            export_flags: 0,
            generation_net_object_count: vec![],
            guid: [0x10; 16],
            package_flags: 0,
        },
        ObjectExport {
            class_index: PackageIndex::from_import_index(0), // SkeletalMesh
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(7, 0), // skl_wep_fernando_skin11a_3p
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 890820,
            serial_offset: 500000,
            export_flags: 0,
            generation_net_object_count: vec![],
            guid: [0x20; 16],
            package_flags: 0,
        },
        ObjectExport {
            class_index: PackageIndex::from_import_index(1), // StaticMesh
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(8, 0), // sm_fernando_skin11a_aresshield_center
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 9809,
            serial_offset: 1400000,
            export_flags: 0,
            generation_net_object_count: vec![],
            guid: [0x30; 16],
            package_flags: 0,
        },
        ObjectExport {
            class_index: PackageIndex::from_import_index(2), // Texture2D
            super_index: PackageIndex::NULL,
            outer_index: PackageIndex::NULL,
            object_name: FName::new(9, 0), // t_pc_fernando_arms_skin00a_dif
            archetype: PackageIndex::NULL,
            object_flags: 0x00070010,
            serial_size: 3420,
            serial_offset: 1500000,
            export_flags: 0,
            generation_net_object_count: vec![],
            guid: [0x40; 16],
            package_flags: 0,
        },
    ]);

    let mut tables_buf = Vec::new();
    let name_offset = 0u32;
    name_table.write(&mut tables_buf).unwrap();

    let import_offset = tables_buf.len() as u32;
    import_table.write(&mut tables_buf).unwrap();

    let export_offset = tables_buf.len() as u32;
    export_table.write(&mut tables_buf).unwrap();

    let total_table_bytes = tables_buf.len() as u32;

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
        guid: [0x77; 16],
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
    if pkg_buf.len() < 1024 {
        pkg_buf.resize(1024, 0);
    }
    pkg_buf.extend_from_slice(&tables_buf);

    let mut pkg = UpkPackage::open(Cursor::new(pkg_buf)).expect("Open synthetic weapon UPK failed");
    let inventory = inspect_weapon_package(&mut pkg, DEVICE_FERNANDO_FLAME_LANCE)
        .expect("Inspect weapon package failed");

    assert_eq!(inventory.device_id, 10774);
    assert_eq!(inventory.champion_id, 1026);
    assert_eq!(inventory.skeletal_meshes.len(), 2);
    assert_eq!(inventory.static_meshes.len(), 1);
    assert_eq!(inventory.textures.len(), 1);

    let mesh_1p = inventory
        .find_skeletal_mesh("1p")
        .expect("Must find 1p mesh");
    assert_eq!(mesh_1p.object_name, "skl_wep_fernando_skin11a_1p");

    let shield_sm = inventory
        .find_static_mesh("shield")
        .expect("Must find shield static mesh");
    assert_eq!(
        shield_sm.object_name,
        "sm_fernando_skin11a_aresshield_center"
    );

    // 3. Export to glTF 2.0
    let vertices = vec![
        GPUSkinVertex {
            position: [0.0, 0.0, 0.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [0.0, 0.0],
            joints_0: [0, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
        GPUSkinVertex {
            position: [10.0, 0.0, 0.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [1.0, 0.0],
            joints_0: [0, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
        GPUSkinVertex {
            position: [0.0, 10.0, 0.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [0.0, 1.0],
            joints_0: [0, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
    ];
    let indices = vec![0, 1, 2];

    let static_export = export_weapon_static_mesh(&vertices, &indices, "flame_lance.bin")
        .expect("Export static weapon mesh failed");
    let json_val: serde_json::Value =
        serde_json::from_str(&static_export.gltf_json).expect("Invalid glTF JSON");
    assert_eq!(json_val["asset"]["version"], "2.0");
    assert_eq!(json_val["buffers"][0]["uri"], "flame_lance.bin");

    let skeleton = RefSkeleton::new(vec![FMeshBone {
        name: "Lance_Root".to_string(),
        parent_index: -1,
        position: [0.0, 0.0, 0.0],
        orientation: [0.0, 0.0, 0.0, 1.0],
        num_children: 0,
        flags: 0,
    }]);
    let lod_model = FSkeletalMeshLODModel { vertices, indices };
    let skel_export =
        export_weapon_skeletal_mesh(&lod_model, Some(&skeleton), "flame_lance_skel.bin")
            .expect("Export skeletal weapon mesh failed");
    assert!(!skel_export.bin_data.is_empty());

    // 4. Test WeaponExtractionPipeline & Weapon Texture Extraction
    let temp_dir =
        std::env::temp_dir().join(format!("immortal_weapon_test_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let tfc_file_path = temp_dir.join("CharNormals0.tfc");
    let mut tfc_file = std::fs::File::create(&tfc_file_path).unwrap();
    let raw_mip_bytes = vec![0x33u8; 512];
    let (offset_mip, size_mip) = write_tfc_chunk(&mut tfc_file, &raw_mip_bytes, None).unwrap();
    drop(tfc_file);

    let pipeline = WeaponExtractionPipeline::new(&temp_dir);
    assert_eq!(pipeline.cooked_dir(), temp_dir.as_path());
    let mip = FTexture2DMipMap {
        bulk_data: FByteBulkData {
            bulk_data_flags: BULKDATA_STORE_IN_SEPARATE_FILE,
            element_count: 512,
            size_on_disk: size_mip,
            offset_in_file: offset_mip as i64,
        },
        size_x: 32,
        size_y: 32,
        inline_data: None,
    };
    let dds_data = extract_weapon_texture(
        pipeline.tfc_resolver(),
        "CharNormals0",
        &mip,
        TextureFormat::Dxt1,
    )
    .unwrap();
    assert_eq!(&dds_data[0..4], b"DDS ");
    assert_eq!(dds_data.len(), 128 + 512);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_probe_paladins_real_weapon_package_if_present() {
    let weapon_path = Path::new(
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole/DEVICE10774_ASSETS_SF.upk",
    );

    if !weapon_path.exists() {
        println!("Skipping real weapon asset test: DEVICE10774_ASSETS_SF.upk not found on disk");
        return;
    }

    println!(
        "Testing against real Paladins weapon package: {}",
        weapon_path.display()
    );
    let mut pkg =
        UpkPackage::open_file(weapon_path).expect("Failed to open real Paladins weapon package");

    assert_eq!(pkg.summary().tag, UPK_MAGIC);
    assert_eq!(pkg.summary().file_version, 893);
    assert!(pkg.summary().is_cooked());
    assert!(pkg.summary().is_compressed());

    let inventory = inspect_weapon_package(&mut pkg, DEVICE_FERNANDO_FLAME_LANCE)
        .expect("Failed to inspect weapon package assets");

    assert_eq!(inventory.device_id, 10774);
    assert_eq!(inventory.champion_id, 1026);

    // Verify presence of Flame Lance skeletal meshes and exact synced counts
    assert_eq!(inventory.skeletal_meshes.len(), 20);
    assert_eq!(inventory.static_meshes.len(), 38);
    assert_eq!(inventory.textures.len(), 172);

    let mesh_1p = inventory.find_skeletal_mesh("1p");
    assert!(
        mesh_1p.is_some(),
        "SkeletalMesh 1p must exist in Flame Lance package"
    );
    assert_eq!(mesh_1p.unwrap().object_name, "skl_wep_lance_skin03a_1p");
    assert!(
        inventory.find_skeletal_mesh("skin11a_1p").is_some(),
        "Skin11a 1p must also exist in Flame Lance package"
    );

    let mesh_3p = inventory.find_skeletal_mesh("3p");
    assert!(
        mesh_3p.is_some(),
        "SkeletalMesh 3p must exist in Flame Lance package"
    );
    assert_eq!(mesh_3p.unwrap().object_name, "skl_wep_lance_skin03a_3p");

    // Verify static meshes (e.g. shield pieces)
    let shield_part = inventory.find_static_mesh("shield");
    assert!(shield_part.is_some(), "Must contain shield static meshes");

    // Verify zero UnknownExport_ failures across the entire package
    let (names, imports, exports) = pkg.read_tables().unwrap();
    for i in 0..exports.len() {
        let full = pkg.resolve_full_path(
            &names,
            &imports,
            &exports,
            PackageIndex::from_export_index(i),
        );
        assert!(
            !full.contains("UnknownExport_"),
            "Unexpected UnknownExport_ in DEVICE10774_ASSETS_SF.upk at #{i}: {full}"
        );
    }

    println!(
        "Successfully verified real Paladins Flame Lance weapon package ({} skeletal meshes, {} static meshes, {} textures)",
        inventory.skeletal_meshes.len(),
        inventory.static_meshes.len(),
        inventory.textures.len()
    );
}

fn count_classes_and_check_unknowns(
    pkg: &mut UpkPackage<std::io::BufReader<std::fs::File>>,
) -> std::collections::BTreeMap<String, usize> {
    let (names, imports, exports) = pkg.read_tables().expect("read_tables failed");
    assert_eq!(names.len(), pkg.summary().name_count as usize);
    assert_eq!(imports.len(), pkg.summary().import_count as usize);
    assert_eq!(exports.len(), pkg.summary().export_count as usize);

    let mut counts = std::collections::BTreeMap::new();
    for (i, exp) in exports.entries().iter().enumerate() {
        let full = pkg.resolve_full_path(
            &names,
            &imports,
            &exports,
            PackageIndex::from_export_index(i),
        );
        assert!(
            !full.contains("UnknownExport_"),
            "Found UnknownExport_ at export #{i}: {full}"
        );
        if let Some(cls) = exp.resolve_class_name(&names, &imports, &exports) {
            *counts.entry(cls.to_ascii_lowercase()).or_insert(0) += 1;
        }
    }
    counts
}

#[test]
fn test_probe_paladins_real_fernando_and_map_collision_upks_if_present() {
    let base = Path::new(
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole",
    );
    if !base.exists() {
        println!("Skipping real UPK collision/export-count tests: CookedPCConsole not found");
        return;
    }

    // 1. FERNANDO_ASSETS_SF.upk
    let fernando_path = base.join("FERNANDO_ASSETS_SF.upk");
    if fernando_path.exists() {
        let mut pkg = UpkPackage::open_file(&fernando_path).unwrap();
        let counts = count_classes_and_check_unknowns(&mut pkg);
        assert_eq!(counts.get("skeletalmesh").copied().unwrap_or(0), 35);
        assert_eq!(counts.get("staticmesh").copied().unwrap_or(0), 93);
        assert_eq!(counts.get("texture2d").copied().unwrap_or(0), 374);
        assert_eq!(counts.get("rb_bodysetup").copied().unwrap_or(0), 36);

        let col = extract_package_collision(&mut pkg).unwrap();
        assert_eq!(col.len(), 36);
        for item in &col {
            assert!(
                item.geometry.validate_closure(0.1),
                "RB_BodySetup {} failed hull closure",
                item.full_path
            );
        }
    }

    // 2. Shootingrange_Collision.upk, SG_JaguarFalls_Rework_P.upk, SG_StoneKeep_P.upk
    let map_expectations = [
        ("Shootingrange_Collision.upk", 90usize, 0usize),
        ("SG_JaguarFalls_Rework_P.upk", 71usize, 7usize),
        ("SG_StoneKeep_P.upk", 62usize, 6usize),
    ];

    for (filename, expected_brushes, expected_bodies) in map_expectations {
        let path = base.join(filename);
        if !path.exists() {
            continue;
        }
        let mut pkg = UpkPackage::open_file(&path).unwrap();
        let counts = count_classes_and_check_unknowns(&mut pkg);
        assert_eq!(
            counts.get("brushcomponent").copied().unwrap_or(0),
            expected_brushes,
            "{filename} BrushComponent count mismatch"
        );
        assert_eq!(
            counts.get("rb_bodysetup").copied().unwrap_or(0),
            expected_bodies,
            "{filename} RB_BodySetup count mismatch"
        );

        let collisions = extract_package_collision(&mut pkg).unwrap();
        assert_eq!(collisions.len(), expected_brushes + expected_bodies);

        let mut total_hulls = 0usize;
        for entry in &collisions {
            assert!(
                entry.geometry.validate_closure(0.1),
                "{filename} {} failed hull closure",
                entry.full_path
            );
            total_hulls += entry.geometry.convex_hulls.len();
        }
        assert!(total_hulls > 0, "{filename} must contain convex hulls");

        if filename == "SG_StoneKeep_P.upk" {
            // Verify SAT raycast against a real StoneKeep blocking hull face plane
            let sample = collisions
                .iter()
                .flat_map(|c| c.geometry.convex_hulls.iter())
                .find(|h| !h.plane_equations.is_empty() && h.aabb_max[0] > h.aabb_min[0] + 1.0)
                .expect("SG_StoneKeep_P must contain a non-degenerate convex hull");

            let center = [
                0.5 * (sample.aabb_min[0] + sample.aabb_max[0]),
                0.5 * (sample.aabb_min[1] + sample.aabb_max[1]),
                0.5 * (sample.aabb_min[2] + sample.aabb_max[2]),
            ];
            let ray_origin = [sample.aabb_max[0] + 100.0, center[1], center[2]];
            let hit = sample
                .raycast(ray_origin, [-1.0, 0.0, 0.0], 500.0)
                .expect("Raycast toward StoneKeep hull +X face must hit");
            assert!(
                (hit.point[0] - sample.aabb_max[0]).abs() <= 0.1,
                "Expected hit at X={:.3}, got {:.3}",
                sample.aabb_max[0],
                hit.point[0]
            );
        }
    }
}

#[test]
fn test_integration_synthetic_upk_collision_extraction() {
    use byteorder::{LittleEndian, WriteBytesExt};

    let name_table = NameTable::new(vec![
        NameEntry::new("None", 0),                 // 0
        NameEntry::new("Core", 0),                 // 1
        NameEntry::new("Class", 0),                // 2
        NameEntry::new("BrushComponent", 0),       // 3
        NameEntry::new("BrushAggGeom", 0),         // 4
        NameEntry::new("StructProperty", 0),       // 5
        NameEntry::new("KAggregateGeom", 0),       // 6
        NameEntry::new("ConvexElems", 0),          // 7
        NameEntry::new("ArrayProperty", 0),        // 8
        NameEntry::new("VertexData", 0),           // 9
        NameEntry::new("FacePlaneData", 0),        // 10
        NameEntry::new("ElemBox", 0),              // 11
        NameEntry::new("Box", 0),                  // 12
        NameEntry::new("BrushComponent_0", 0),     // 13
    ]);

    let import_table = ImportTable::new(vec![ObjectImport {
        class_package: FName::new(1, 0),
        class_name: FName::new(2, 0),
        outer_index: PackageIndex::NULL,
        object_name: FName::new(3, 0), // BrushComponent
    }]);

    let write_fn = |buf: &mut Vec<u8>, idx: i32| {
        buf.write_i32::<LittleEndian>(idx).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap();
    };

    // ConvexElem: box [10, 20] x [-10, 10] x [0, 50]
    let mut ce = Vec::new();
    write_fn(&mut ce, 9);
    write_fn(&mut ce, 8);
    ce.write_u32::<LittleEndian>(4 + 8 * 12).unwrap();
    ce.write_u32::<LittleEndian>(0).unwrap();
    ce.write_u32::<LittleEndian>(8).unwrap();
    for v in [
        [10.0f32, -10.0, 0.0],
        [20.0, -10.0, 0.0],
        [20.0, 10.0, 0.0],
        [10.0, 10.0, 0.0],
        [10.0, -10.0, 50.0],
        [20.0, -10.0, 50.0],
        [20.0, 10.0, 50.0],
        [10.0, 10.0, 50.0],
    ] {
        for c in v {
            ce.write_f32::<LittleEndian>(c).unwrap();
        }
    }
    write_fn(&mut ce, 10);
    write_fn(&mut ce, 8);
    ce.write_u32::<LittleEndian>(4 + 6 * 16).unwrap();
    ce.write_u32::<LittleEndian>(0).unwrap();
    ce.write_u32::<LittleEndian>(6).unwrap();
    for p in [
        [20.0f32, 1.0, 0.0, 0.0],
        [-10.0, -1.0, 0.0, 0.0],
        [10.0, 0.0, 1.0, 0.0],
        [10.0, 0.0, -1.0, 0.0],
        [50.0, 0.0, 0.0, 1.0],
        [0.0, 0.0, 0.0, -1.0],
    ] {
        for c in p {
            ce.write_f32::<LittleEndian>(c).unwrap();
        }
    }
    write_fn(&mut ce, 11);
    write_fn(&mut ce, 5);
    ce.write_u32::<LittleEndian>(25).unwrap();
    ce.write_u32::<LittleEndian>(0).unwrap();
    write_fn(&mut ce, 12);
    for c in [10.0f32, -10.0, 0.0, 20.0, 10.0, 50.0] {
        ce.write_f32::<LittleEndian>(c).unwrap();
    }
    ce.write_u8(1).unwrap();
    write_fn(&mut ce, 0);

    let mut agg = Vec::new();
    write_fn(&mut agg, 7);
    write_fn(&mut agg, 8);
    agg.write_u32::<LittleEndian>(4 + ce.len() as u32).unwrap();
    agg.write_u32::<LittleEndian>(0).unwrap();
    agg.write_u32::<LittleEndian>(1).unwrap();
    agg.extend_from_slice(&ce);
    write_fn(&mut agg, 0);

    let mut export_payload = Vec::new();
    export_payload.write_i32::<LittleEndian>(0).unwrap(); // TemplateOwnerClass
    export_payload.write_i32::<LittleEndian>(1).unwrap(); // NetIndex
    write_fn(&mut export_payload, 4); // BrushAggGeom
    write_fn(&mut export_payload, 5);
    export_payload
        .write_u32::<LittleEndian>(agg.len() as u32)
        .unwrap();
    export_payload.write_u32::<LittleEndian>(0).unwrap();
    write_fn(&mut export_payload, 6);
    export_payload.extend_from_slice(&agg);
    write_fn(&mut export_payload, 0);

    let mut tables_buf = Vec::new();
    let name_offset = 0u32;
    name_table.write(&mut tables_buf).unwrap();
    let import_offset = tables_buf.len() as u32;
    import_table.write(&mut tables_buf).unwrap();
    let export_offset = tables_buf.len() as u32;

    let payload_offset = 1024 + export_offset as usize + ObjectExport::MIN_SERIALIZED_SIZE;
    let export_table = ExportTable::new(vec![ObjectExport {
        class_index: PackageIndex::from_import_index(0),
        super_index: PackageIndex::NULL,
        outer_index: PackageIndex::NULL,
        object_name: FName::new(13, 0),
        archetype: PackageIndex::NULL,
        object_flags: 0x00070000,
        serial_size: export_payload.len() as i32,
        serial_offset: payload_offset as i32,
        export_flags: 0,
        generation_net_object_count: vec![],
        guid: [0x55; 16],
        package_flags: 0,
    }]);
    export_table.write(&mut tables_buf).unwrap();

    let summary = PackageSummary {
        tag: UPK_MAGIC,
        file_version: 893,
        licensee_version: 0,
        total_header_size: payload_offset as u32,
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
        guid: [0x66; 16],
        generations: vec![GenerationInfo {
            export_count: 1,
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
    pkg_buf.resize(1024, 0);
    pkg_buf.extend_from_slice(&tables_buf);
    assert_eq!(pkg_buf.len(), payload_offset);
    pkg_buf.extend_from_slice(&export_payload);

    let mut pkg = UpkPackage::open(Cursor::new(pkg_buf)).unwrap();
    let extracted = extract_package_collision(&mut pkg).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].object_name, "BrushComponent_0");
    assert!(extracted[0].geometry.validate_closure(1e-4));
    assert!(extracted[0]
        .geometry
        .contains_point([15.0, 0.0, 25.0], 1e-4));
    let hit = extracted[0]
        .geometry
        .raycast([100.0, 0.0, 25.0], [-1.0, 0.0, 0.0], 200.0)
        .unwrap();
    assert!((hit.point[0] - 20.0).abs() < 1e-4);
}

#[test]
fn test_paladins_real_upk_netcache_and_manifest_parity_if_present() {
    use immortal_extract::{
        NetCacheRegistry, NetFieldKind, PackageMapManifest, PropertyClass, COMPRESS_LZO,
        COMPRESS_LZO_XOR, MINIMAL_SHOOTING_RANGE_PACKAGES,
    };

    let cooked_dir = Path::new(
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole",
    );
    let required = ["Core", "Engine", "TgGame", "Shootingrange_P"];
    if !required
        .iter()
        .all(|stem| cooked_dir.join(format!("{stem}.upk")).exists())
    {
        println!("Skipping real UPK netcache parity test: Paladins CookedPCConsole not found");
        return;
    }

    let ordered_paths: Vec<_> = MINIMAL_SHOOTING_RANGE_PACKAGES
        .iter()
        .map(|stem| cooked_dir.join(format!("{stem}.upk")))
        .filter(|p| p.exists())
        .collect();

    let manifest = PackageMapManifest::from_package_paths(&ordered_paths)
        .expect("Failed to build PackageMapManifest from real UPKs");

    let core_entry = manifest.get("Core").expect("Core entry missing");
    assert_eq!(core_entry.object_base, 0);
    assert_eq!(core_entry.object_count, 1562);

    let engine_entry = manifest.get("Engine").expect("Engine entry missing");
    assert_eq!(engine_entry.object_base, 1562);
    assert_eq!(engine_entry.object_count, 35793);

    let tggame_entry = manifest.get("TgGame").expect("TgGame entry missing");
    assert_eq!(tggame_entry.object_count, 66967);

    let sr_entry = manifest
        .get("Shootingrange_P")
        .expect("Shootingrange_P entry missing");
    assert_eq!(sr_entry.object_count, 1038);

    let mut registry = NetCacheRegistry::with_manifest(manifest);
    for path in &ordered_paths {
        let stats = registry
            .load_package_file(path)
            .unwrap_or_else(|e| panic!("Failed to load {}: {e}", path.display()));
        assert_eq!(
            stats.properties_failed, 0,
            "Non-zero property parse failures in {}",
            stats.package_name
        );
        assert_eq!(
            stats.functions_failed, 0,
            "Non-zero function parse failures in {}",
            stats.package_name
        );

        match stats.package_name.as_str() {
            "Core" => {
                assert_eq!(stats.compression_flags, COMPRESS_LZO_XOR);
                assert_eq!(stats.properties_parsed, 1132);
                assert_eq!(stats.functions_parsed, 308);
            }
            "Engine" => {
                assert_eq!(stats.compression_flags, COMPRESS_LZO_XOR);
                assert_eq!(stats.properties_parsed, 23_294);
                assert_eq!(stats.net_properties, 164);
                assert_eq!(stats.functions_parsed, 5_250);
                assert_eq!(stats.net_functions, 160);
            }
            "TgGame" => {
                assert_eq!(stats.compression_flags, COMPRESS_LZO_XOR);
                assert_eq!(stats.properties_parsed, 38_009);
                assert_eq!(stats.net_properties, 992);
                assert_eq!(stats.functions_parsed, 13_796);
                assert_eq!(stats.net_functions, 412);
            }
            "Shootingrange_P" => {
                assert_eq!(stats.compression_flags, COMPRESS_LZO);
                assert_eq!(stats.properties_parsed, 0);
                assert_eq!(stats.functions_parsed, 0);
            }
            _ => {}
        }
    }

    // Exact ClassNetCache parity against probe_upk_netcache.py
    let pc = registry
        .build_class_net_cache("TgPlayerController")
        .expect("TgPlayerController ClassNetCache failed");
    assert_eq!(pc.fields_base, 161);
    assert_eq!(pc.own_fields.len(), 142);
    assert_eq!(pc.max_index, 303);
    assert_eq!(pc.own_fields[0].rep_index, 161);
    assert_eq!(pc.own_fields[0].field_name, "PlayNotifySound");
    assert_eq!(pc.own_fields[0].object_net_index, 16952);
    assert!(matches!(pc.own_fields[0].kind, NetFieldKind::Function { .. }));
    let last_pc = pc.own_fields.last().unwrap();
    assert_eq!(last_pc.rep_index, 302);
    assert_eq!(last_pc.field_name, "r_LastPurchasedItems");
    assert_eq!(last_pc.object_net_index, 62203);
    assert_eq!(
        last_pc.kind,
        NetFieldKind::Property {
            property_class: PropertyClass::StructProperty,
            array_dim: 26,
            property_flags: match last_pc.kind {
                NetFieldKind::Property { property_flags, .. } => property_flags,
                _ => 0,
            },
            rep_offset: match last_pc.kind {
                NetFieldKind::Property { rep_offset, .. } => rep_offset,
                _ => 0,
            },
            tail_type_name: Some("TG_LAST_PURCHASE".to_string()),
        }
    );

    let ts = registry
        .lookup_rep_field("TgPlayerController", 291)
        .unwrap()
        .expect("RepIndex 291 missing on TgPlayerController");
    assert_eq!(ts.field_name, "r_fServerTimeStamp");

    let fernando = registry
        .build_class_net_cache("TgPawn_Fernando")
        .expect("TgPawn_Fernando ClassNetCache failed");
    assert_eq!(fernando.fields_base, 261);
    assert_eq!(fernando.own_fields.len(), 3);
    assert_eq!(fernando.max_index, 264);
    assert_eq!(fernando.own_fields[0].field_name, "r_bAegisShieldWasDestroyed");
    assert_eq!(fernando.own_fields[1].field_name, "r_bHasAegisTalent");
    assert_eq!(fernando.own_fields[2].field_name, "r_ShieldDisplayType");
    assert_eq!(
        registry
            .lookup_rep_field("TgPawn_Fernando", 23)
            .unwrap()
            .unwrap()
            .field_name,
        "Velocity"
    );

    let pri = registry
        .build_class_net_cache("TgRepInfo_Player")
        .expect("TgRepInfo_Player ClassNetCache failed");
    assert_eq!(pri.fields_base, 49);
    assert_eq!(pri.own_fields.len(), 101);
    assert_eq!(pri.max_index, 150);
    assert_eq!(pri.own_fields[0].field_name, "r_vWaypoint");
    assert_eq!(pri.own_fields.last().unwrap().field_name, "SetAnnouncerPlaying");

    let gri = registry
        .build_class_net_cache("TgRepInfo_Game")
        .expect("TgRepInfo_Game ClassNetCache failed");
    assert_eq!(gri.fields_base, 35);
    assert_eq!(gri.own_fields.len(), 163);
    assert_eq!(gri.max_index, 198);
    assert_eq!(gri.own_fields[0].field_name, "r_AbyssalEcho");
    assert_eq!(gri.own_fields.last().unwrap().field_name, "ClientHandleAlert");

    // Verify UEnum and UStruct metadata extracted from Engine.upk / TgGame.upk
    let net_role = registry
        .get_enum("ENetRole")
        .expect("ENetRole enum missing");
    assert!(net_role.resolved_names.len() >= 4);

    let last_purchase = registry
        .get_struct("TG_LAST_PURCHASE")
        .expect("TG_LAST_PURCHASE struct missing");
    assert!(!last_purchase.fields.is_empty());
}
