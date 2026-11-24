// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Live workstation smoke test for Project Immortal asset extraction.
//! Dumps real parsed Paladins UPK export tables, collision (`ADOPT-01`), Wwise PCK headers,
//! and TFC availability without synthesizing fake mesh/texture payloads (`PSL-INV-012`).

use immortal_extract::{
    extract_package_collision, PackageIndex, PckArchive, TfcResolver, UpkPackage, UPK_MAGIC,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🔥 PROJECT IMMORTAL: REAL UPK & COLLISION EXTRACTION SMOKE TEST");
    println!("============================================================");

    let cooked_dir = Path::new(
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole",
    );
    let output_dir = Path::new("/tmp/immortal_smoke_assets");
    std::fs::create_dir_all(output_dir)?;

    if !cooked_dir.exists() {
        eprintln!(
            "❌ CookedPCConsole directory not found at: {}",
            cooked_dir.display()
        );
        return Ok(());
    }

    // ------------------------------------------------------------------------
    // 1. Parse Real UPK Package: FERNANDO_ASSETS_SF.upk
    // ------------------------------------------------------------------------
    let upk_path = cooked_dir.join("FERNANDO_ASSETS_SF.upk");
    println!("\n📦 [1/4] Parsing UPK Package: {}", upk_path.display());
    if upk_path.exists() {
        let mut pkg = UpkPackage::open_file(&upk_path)?;
        let summary = pkg.summary();
        println!(
            "  • UPK Magic: 0x{:08X} (Valid: {})",
            summary.tag,
            summary.tag == UPK_MAGIC
        );
        println!("  • File Version: {}", summary.file_version);
        println!("  • Cooker Version: {}", summary.cooker_version);
        println!("  • Compressed Chunks: {}", summary.compressed_chunks.len());
        println!(
            "  • Header Counts: {} names, {} imports, {} exports",
            summary.name_count, summary.import_count, summary.export_count
        );

        let (name_table, import_table, export_table) = pkg.read_tables()?;
        println!(
            "  • Tables parsed: {} names, {} imports, {} exports",
            name_table.len(),
            import_table.len(),
            export_table.len()
        );

        let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut unknown_exports = 0usize;
        let mut skeletal_meshes = Vec::new();
        let mut static_meshes = Vec::new();
        let mut textures = Vec::new();

        for (idx, exp) in export_table.entries().iter().enumerate() {
            let full_path = pkg.resolve_full_path(
                &name_table,
                &import_table,
                &export_table,
                PackageIndex::from_export_index(idx),
            );
            if full_path.contains("UnknownExport_") {
                unknown_exports += 1;
            }
            if let Some(class) = exp.resolve_class_name(&name_table, &import_table, &export_table) {
                let lower = class.to_ascii_lowercase();
                *class_counts.entry(lower.clone()).or_default() += 1;
                let name = exp
                    .resolve_object_name(&name_table)
                    .unwrap_or_else(|| format!("Export_{idx}"));
                match lower.as_str() {
                    "skeletalmesh" => skeletal_meshes.push((idx, name, exp.serial_size)),
                    "staticmesh" => static_meshes.push((idx, name, exp.serial_size)),
                    "texture2d" => textures.push((idx, name, exp.serial_size)),
                    _ => {}
                }
            }
        }

        println!("  • UnknownExport_ failures: {unknown_exports}");
        println!(
            "  • Discovered: {} SkeletalMesh, {} StaticMesh, {} Texture2D, {} RB_BodySetup",
            skeletal_meshes.len(),
            static_meshes.len(),
            textures.len(),
            class_counts.get("rb_bodysetup").copied().unwrap_or(0)
        );
        if let Some((idx, name, sz)) = skeletal_meshes.first() {
            println!("  • Sample SkeletalMesh: Export #{idx} '{name}' ({sz} bytes)");
        }
        if let Some((idx, name, sz)) = static_meshes.first() {
            println!("  • Sample StaticMesh: Export #{idx} '{name}' ({sz} bytes)");
        }
        if let Some((idx, name, sz)) = textures.first() {
            println!("  • Sample Texture2D: Export #{idx} '{name}' ({sz} bytes)");
        }

        let collision = extract_package_collision(&mut pkg)?;
        let total_hulls: usize = collision
            .iter()
            .map(|c| c.geometry.convex_hulls.len())
            .sum();
        let total_boxes: usize = collision.iter().map(|c| c.geometry.boxes.len()).sum();
        let total_spheres: usize = collision.iter().map(|c| c.geometry.spheres.len()).sum();
        let total_sphyls: usize = collision.iter().map(|c| c.geometry.sphyls.len()).sum();
        println!(
            "  • Parsed {} RB_BodySetup collision exports: {} convex hulls, {} boxes, {} spheres, {} capsules",
            collision.len(),
            total_hulls,
            total_boxes,
            total_spheres,
            total_sphyls
        );

        let inv_path = output_dir.join("fernando_collision_dump.json");
        std::fs::write(&inv_path, serde_json::to_string_pretty(&collision)?)?;
        println!("  • Wrote real parsed collision JSON: {}", inv_path.display());
    } else {
        println!("  ⚠️ UPK file not found: {}", upk_path.display());
    }

    // ------------------------------------------------------------------------
    // 2. Parse Real Map Collision UPK: Shootingrange_Collision.upk (ADOPT-01)
    // ------------------------------------------------------------------------
    let map_col_path = cooked_dir.join("Shootingrange_Collision.upk");
    println!(
        "\n🧱 [2/4] Extracting Map Collision (`ADOPT-01`): {}",
        map_col_path.display()
    );
    if map_col_path.exists() {
        let mut pkg = UpkPackage::open_file(&map_col_path)?;
        let collision = extract_package_collision(&mut pkg)?;
        let total_hulls: usize = collision
            .iter()
            .map(|c| c.geometry.convex_hulls.len())
            .sum();
        let closed_hulls = collision
            .iter()
            .flat_map(|c| c.geometry.convex_hulls.iter())
            .filter(|h| h.validate_closure(0.1))
            .count();
        println!(
            "  • Extracted {} BrushComponent exports ({} convex hulls, {} closed within 0.1 UU)",
            collision.len(),
            total_hulls,
            closed_hulls
        );
        if let Some(first) = collision.first() {
            if let Some(hull) = first.geometry.convex_hulls.first() {
                println!(
                    "  • Sample Brush '{}': {} vertices, {} planes, AABB [{:.1}, {:.1}, {:.1}]..[{:.1}, {:.1}, {:.1}]",
                    first.full_path,
                    hull.vertices.len(),
                    hull.plane_equations.len(),
                    hull.aabb_min[0],
                    hull.aabb_min[1],
                    hull.aabb_min[2],
                    hull.aabb_max[0],
                    hull.aabb_max[1],
                    hull.aabb_max[2]
                );
            }
        }
        let map_json = output_dir.join("shootingrange_collision_dump.json");
        std::fs::write(&map_json, serde_json::to_string_pretty(&collision)?)?;
        println!("  • Wrote map collision JSON: {}", map_json.display());
    }

    // ------------------------------------------------------------------------
    // 3. Parse Real Wwise Audio Package: WWB_PC_Knight.pck
    // ------------------------------------------------------------------------
    let pck_path = cooked_dir.join("WWB_PC_Knight.pck");
    println!("\n🔊 [3/4] Parsing Wwise Package: {}", pck_path.display());
    if pck_path.exists() {
        let pck_file = File::open(&pck_path)?;
        let mut reader = BufReader::new(pck_file);
        let archive = PckArchive::read(&mut reader)?;

        println!("  • SoundBanks in PCK: {}", archive.soundbanks.len());
        println!("  • Streamed Audio Files in PCK: {}", archive.streams.len());
        for (idx, bank) in archive.soundbanks.iter().take(3).enumerate() {
            println!(
                "    - Bank #{idx}: ID 0x{:08X}, Size {} bytes (offset 0x{:X})",
                bank.id, bank.file_size, bank.file_offset
            );
        }
    }

    // ------------------------------------------------------------------------
    // 4. Inspect TFC Container Availability
    // ------------------------------------------------------------------------
    println!("\n🎮 [4/4] Inspecting TFC Texture Cache Directory");
    let _tfc_resolver = TfcResolver::new(cooked_dir);
    let sample_tfc = cooked_dir.join("CharNormals0.tfc");
    if sample_tfc.exists() {
        let metadata = std::fs::metadata(&sample_tfc)?;
        println!(
            "  • CharNormals0.tfc Size: {:.2} MB",
            metadata.len() as f64 / (1024.0 * 1024.0)
        );
    }
    println!("  • Note: USkeletalMesh / UTexture2D binary payload deserializers are not yet implemented; no synthetic mesh/DDS files masquerading as extracted UPK assets were emitted.");

    println!("\n============================================================");
    println!("✨ REAL UPK METADATA & COLLISION SMOKE TEST COMPLETE");
    println!("============================================================");

    Ok(())
}
