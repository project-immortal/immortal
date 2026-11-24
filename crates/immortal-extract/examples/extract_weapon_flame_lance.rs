// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Live workstation example for inspecting Fernando's Flame Lance weapon package
//! (`DEVICE10774_ASSETS_SF.upk`) export inventory and collision (`RB_BodySetup`).

use immortal_extract::{
    extract_package_collision, get_weapon_mapping, UpkPackage, WeaponExtractionPipeline,
    DEVICE_FERNANDO_FLAME_LANCE,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🔥 PROJECT IMMORTAL: FLAME LANCE WEAPON PACKAGE INSPECTOR");
    println!("============================================================");

    let cooked_dir = Path::new(
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/CookedPCConsole",
    );
    let output_dir = Path::new("/tmp/immortal_weapon_assets");
    std::fs::create_dir_all(output_dir)?;

    let mapping = get_weapon_mapping(DEVICE_FERNANDO_FLAME_LANCE)
        .expect("Weapon mapping for Flame Lance must exist");
    println!(
        "Weapon: '{}' (ID {}) for Champion: '{}' (ID {})",
        mapping.device_name, mapping.device_id, mapping.champion_name, mapping.champion_id
    );

    let weapon_pkg_path = cooked_dir.join(mapping.default_package_file);
    if !weapon_pkg_path.exists() {
        println!(
            "Cooked weapon package not found at: {}",
            weapon_pkg_path.display()
        );
        return Ok(());
    }

    let pipeline = WeaponExtractionPipeline::new(cooked_dir);
    let mut pkg = UpkPackage::open_file(&weapon_pkg_path)?;
    let summary = pkg.summary();

    println!(
        "Loaded {}: Cooker Version {}, Chunks: {}, Names: {}, Exports: {}",
        mapping.default_package_file,
        summary.cooker_version,
        summary.compressed_chunks.len(),
        summary.name_count,
        summary.export_count
    );

    let inventory = pipeline.inspect_device(DEVICE_FERNANDO_FLAME_LANCE)?;
    println!(
        "Found {} SkeletalMeshes, {} StaticMeshes, {} Texture2D assets",
        inventory.skeletal_meshes.len(),
        inventory.static_meshes.len(),
        inventory.textures.len()
    );

    for sm in &inventory.skeletal_meshes {
        println!(
            "  • SkeletalMesh #{}: '{}' ({} bytes)",
            sm.export_index, sm.object_name, sm.serial_size
        );
    }
    for stm in &inventory.static_meshes {
        println!(
            "  • StaticMesh #{}: '{}' ({} bytes)",
            stm.export_index, stm.object_name, stm.serial_size
        );
    }
    for tex in inventory.textures.iter().take(10) {
        println!(
            "  • Texture2D #{}: '{}' ({} bytes)",
            tex.export_index, tex.object_name, tex.serial_size
        );
    }
    if inventory.textures.len() > 10 {
        println!("  • ... and {} more Texture2D exports", inventory.textures.len() - 10);
    }

    let collision = extract_package_collision(&mut pkg)?;
    println!(
        "Parsed {} RB_BodySetup collision exports from {}",
        collision.len(),
        mapping.default_package_file
    );

    let inventory_json = output_dir.join("device10774_inventory.json");
    std::fs::write(&inventory_json, serde_json::to_string_pretty(&inventory)?)?;
    println!(
        "✅ Wrote real UPK weapon inventory JSON to: {}",
        inventory_json.display()
    );
    println!("ℹ️  Note: USkeletalMesh / UStaticMesh vertex-buffer decoders are unimplemented (`PSL-INV-012`); no synthetic glTF placeholder was emitted.");

    Ok(())
}
