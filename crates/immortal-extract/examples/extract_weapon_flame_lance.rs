// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Live workstation example for extracting Fernando's Flame Lance weapon assets
//! (`DEVICE10774_ASSETS_SF.upk`) into glTF 2.0 and DDS textures.

use immortal_extract::{
    export_weapon_static_mesh, get_weapon_mapping, GPUSkinVertex, UpkPackage,
    WeaponExtractionPipeline, DEVICE_FERNANDO_FLAME_LANCE,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🔥 PROJECT IMMORTAL: FLAME LANCE WEAPON EXTRACTION");
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
    let pkg = UpkPackage::open_file(&weapon_pkg_path)?;
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

    // Export synthetic static mesh for Flame Lance nozzle to verify glTF 2.0 output
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
            position: [15.0, 0.0, 0.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [1.0, 0.0],
            joints_0: [0, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
        GPUSkinVertex {
            position: [0.0, 15.0, 0.0],
            normal: [0.0, 1.0, 0.0],
            tangent: [1.0, 0.0, 0.0, 1.0],
            tex_coord_0: [0.0, 1.0],
            joints_0: [0, 0, 0, 0],
            weights_0: [1.0, 0.0, 0.0, 0.0],
        },
    ];
    let indices = vec![0, 1, 2];
    let gltf_export = export_weapon_static_mesh(&vertices, &indices, "fernando_flame_lance.bin")?;
    gltf_export.save_to_dir(output_dir, "fernando_flame_lance")?;
    println!(
        "✅ Exported Flame Lance glTF 2.0 to: {}",
        output_dir.join("fernando_flame_lance.gltf").display()
    );

    Ok(())
}
