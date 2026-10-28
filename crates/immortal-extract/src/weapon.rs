// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Cleanroom weapon asset extraction engine, device-to-champion mappings,
//! and asset pipeline for Project Immortal.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use crate::error::ExtractError;
use crate::mesh::{
    export_skeletal_mesh_to_gltf, FSkeletalMeshLODModel, GPUSkinVertex, GltfExport, RefSkeleton,
};
use crate::package::UpkPackage;
use crate::tfc::{export_dds, FTexture2DMipMap, TextureFormat, TfcResolver};

/// Well-known Paladins Device ID for Fernando's Flame Lance.
pub const DEVICE_FERNANDO_FLAME_LANCE: u32 = 10774;

/// Champion ID for Fernando.
pub const CHAMPION_FERNANDO: u32 = 1026;

/// Relationship descriptor binding weapon device IDs to champion IDs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeaponDeviceMapping {
    pub device_id: u32,
    pub champion_id: u32,
    pub device_name: &'static str,
    pub champion_name: &'static str,
    pub default_package_file: &'static str,
}

/// Known weapon-to-champion associations adhering to the cleanroom specification.
pub const KNOWN_WEAPON_MAPPINGS: &[WeaponDeviceMapping] = &[WeaponDeviceMapping {
    device_id: DEVICE_FERNANDO_FLAME_LANCE,
    champion_id: CHAMPION_FERNANDO,
    device_name: "Flame Lance",
    champion_name: "Fernando",
    default_package_file: "DEVICE10774_ASSETS_SF.upk",
}];

/// Looks up the weapon mapping by weapon device ID.
pub fn get_weapon_mapping(device_id: u32) -> Option<&'static WeaponDeviceMapping> {
    KNOWN_WEAPON_MAPPINGS
        .iter()
        .find(|m| m.device_id == device_id)
}

/// Looks up the weapon mapping by champion ID.
pub fn get_weapon_mapping_for_champion(champion_id: u32) -> Option<&'static WeaponDeviceMapping> {
    KNOWN_WEAPON_MAPPINGS
        .iter()
        .find(|m| m.champion_id == champion_id)
}

/// Discovered mesh export entry from a weapon UPK package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeaponMeshExport {
    pub export_index: usize,
    pub class_name: String,
    pub object_name: String,
    pub serial_size: i32,
    pub serial_offset: i32,
}

/// Discovered texture export entry from a weapon UPK package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeaponTextureExport {
    pub export_index: usize,
    pub object_name: String,
    pub serial_size: i32,
    pub serial_offset: i32,
}

/// Summary report of weapon assets discovered within a weapon UPK package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeaponAssetInventory {
    pub device_id: u32,
    pub champion_id: u32,
    pub skeletal_meshes: Vec<WeaponMeshExport>,
    pub static_meshes: Vec<WeaponMeshExport>,
    pub textures: Vec<WeaponTextureExport>,
}

impl WeaponAssetInventory {
    /// Returns the primary first-person or third-person skeletal mesh if present.
    pub fn find_skeletal_mesh(&self, name_contains: &str) -> Option<&WeaponMeshExport> {
        let query = name_contains.to_lowercase();
        self.skeletal_meshes
            .iter()
            .find(|m| m.object_name.to_lowercase().contains(&query))
    }

    /// Returns a static mesh by substring match.
    pub fn find_static_mesh(&self, name_contains: &str) -> Option<&WeaponMeshExport> {
        let query = name_contains.to_lowercase();
        self.static_meshes
            .iter()
            .find(|m| m.object_name.to_lowercase().contains(&query))
    }

    /// Returns a texture by substring match.
    pub fn find_texture(&self, name_contains: &str) -> Option<&WeaponTextureExport> {
        let query = name_contains.to_lowercase();
        self.textures
            .iter()
            .find(|t| t.object_name.to_lowercase().contains(&query))
    }
}

/// Inspects a weapon package to index all SkeletalMesh, StaticMesh, and Texture2D exports.
pub fn inspect_weapon_package<R: Read + Seek>(
    package: &mut UpkPackage<R>,
    device_id: u32,
) -> Result<WeaponAssetInventory, ExtractError> {
    let mapping = get_weapon_mapping(device_id);
    let champion_id = mapping.map(|m| m.champion_id).unwrap_or(0);

    let (name_table, import_table, export_table) = package.read_tables()?;

    let mut skeletal_meshes = Vec::new();
    let mut static_meshes = Vec::new();
    let mut textures = Vec::new();

    for (idx, export) in export_table.entries().iter().enumerate() {
        if let Some(class_name) =
            export.resolve_class_name(&name_table, &import_table, &export_table)
        {
            let class_lower = class_name.to_lowercase();
            let object_name = export
                .resolve_object_name(&name_table)
                .unwrap_or_else(|| format!("Export_{idx}"));

            if class_lower == "skeletalmesh" {
                skeletal_meshes.push(WeaponMeshExport {
                    export_index: idx,
                    class_name,
                    object_name,
                    serial_size: export.serial_size,
                    serial_offset: export.serial_offset,
                });
            } else if class_lower == "staticmesh" {
                static_meshes.push(WeaponMeshExport {
                    export_index: idx,
                    class_name,
                    object_name,
                    serial_size: export.serial_size,
                    serial_offset: export.serial_offset,
                });
            } else if class_lower == "texture2d" {
                textures.push(WeaponTextureExport {
                    export_index: idx,
                    object_name,
                    serial_size: export.serial_size,
                    serial_offset: export.serial_offset,
                });
            }
        }
    }

    Ok(WeaponAssetInventory {
        device_id,
        champion_id,
        skeletal_meshes,
        static_meshes,
        textures,
    })
}

/// Exports a weapon skeletal mesh to a glTF 2.0 container.
pub fn export_weapon_skeletal_mesh(
    lod_model: &FSkeletalMeshLODModel,
    skeleton: Option<&RefSkeleton>,
    bin_filename: &str,
) -> Result<GltfExport, ExtractError> {
    export_skeletal_mesh_to_gltf(lod_model, skeleton, bin_filename)
}

/// Exports a weapon static mesh (without skinning weights) to a glTF 2.0 container.
pub fn export_weapon_static_mesh(
    vertices: &[GPUSkinVertex],
    indices: &[u32],
    bin_filename: &str,
) -> Result<GltfExport, ExtractError> {
    let model = FSkeletalMeshLODModel {
        vertices: vertices.to_vec(),
        indices: indices.to_vec(),
    };
    export_skeletal_mesh_to_gltf(&model, None, bin_filename)
}

/// Resolves and extracts a weapon texture directly or via Texture File Cache (`CharNormals0.tfc`).
pub fn extract_weapon_texture(
    resolver: &TfcResolver,
    tfc_name: &str,
    mip: &FTexture2DMipMap,
    format: TextureFormat,
) -> Result<Vec<u8>, ExtractError> {
    let raw_payload = resolver.extract_mip_from_tfc(tfc_name, mip)?;
    Ok(export_dds(mip.size_x, mip.size_y, format, &raw_payload))
}

/// High-level weapon asset extraction pipeline orchestrator.
#[derive(Debug)]
pub struct WeaponExtractionPipeline {
    cooked_dir: PathBuf,
    tfc_resolver: TfcResolver,
}

impl WeaponExtractionPipeline {
    /// Creates a new extraction pipeline pointing to the CookedPCConsole directory.
    pub fn new(cooked_dir: impl AsRef<Path>) -> Self {
        let dir = cooked_dir.as_ref().to_path_buf();
        let tfc_resolver = TfcResolver::new(&dir);
        Self {
            cooked_dir: dir,
            tfc_resolver,
        }
    }

    pub fn cooked_dir(&self) -> &Path {
        &self.cooked_dir
    }

    pub fn tfc_resolver(&self) -> &TfcResolver {
        &self.tfc_resolver
    }

    /// Opens the UPK package associated with a given device ID.
    pub fn open_weapon_package(
        &self,
        device_id: u32,
    ) -> Result<UpkPackage<std::io::BufReader<std::fs::File>>, ExtractError> {
        let mapping = get_weapon_mapping(device_id).ok_or_else(|| {
            ExtractError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No registered package mapping for weapon device ID {device_id}"),
            ))
        })?;

        let package_path = self.cooked_dir.join(mapping.default_package_file);
        UpkPackage::open_file(package_path)
    }

    /// Inspects the weapon assets for a given device ID.
    pub fn inspect_device(&self, device_id: u32) -> Result<WeaponAssetInventory, ExtractError> {
        let mut pkg = self.open_weapon_package(device_id)?;
        inspect_weapon_package(&mut pkg, device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::FMeshBone;

    #[test]
    fn test_device_mapping_flame_lance() {
        let mapping = get_weapon_mapping(DEVICE_FERNANDO_FLAME_LANCE)
            .expect("Flame lance mapping should be defined");
        assert_eq!(mapping.device_id, 10774);
        assert_eq!(mapping.champion_id, 1026);
        assert_eq!(mapping.device_name, "Flame Lance");
        assert_eq!(mapping.champion_name, "Fernando");
        assert_eq!(mapping.default_package_file, "DEVICE10774_ASSETS_SF.upk");

        let champ_map = get_weapon_mapping_for_champion(CHAMPION_FERNANDO)
            .expect("Mapping by champion ID should resolve");
        assert_eq!(champ_map.device_id, DEVICE_FERNANDO_FLAME_LANCE);
    }

    #[test]
    fn test_weapon_static_and_skeletal_export() {
        let vertices = vec![
            GPUSkinVertex {
                position: [0.0, 0.0, 0.0],
                normal: [0.0, 0.0, 1.0],
                tangent: [1.0, 0.0, 0.0, 1.0],
                tex_coord_0: [0.0, 0.0],
                joints_0: [0, 0, 0, 0],
                weights_0: [1.0, 0.0, 0.0, 0.0],
            },
            GPUSkinVertex {
                position: [10.0, 0.0, 0.0],
                normal: [0.0, 0.0, 1.0],
                tangent: [1.0, 0.0, 0.0, 1.0],
                tex_coord_0: [1.0, 0.0],
                joints_0: [0, 0, 0, 0],
                weights_0: [1.0, 0.0, 0.0, 0.0],
            },
            GPUSkinVertex {
                position: [0.0, 10.0, 0.0],
                normal: [0.0, 0.0, 1.0],
                tangent: [1.0, 0.0, 0.0, 1.0],
                tex_coord_0: [0.0, 1.0],
                joints_0: [0, 0, 0, 0],
                weights_0: [1.0, 0.0, 0.0, 0.0],
            },
        ];
        let indices = vec![0, 1, 2];

        // Static mesh export
        let static_gltf = export_weapon_static_mesh(&vertices, &indices, "weapon_static.bin")
            .expect("Static mesh gltf export failed");
        assert!(!static_gltf.bin_data.is_empty());

        let skeleton = RefSkeleton::new(vec![FMeshBone {
            name: "Weapon_Root".to_string(),
            parent_index: -1,
            position: [0.0, 0.0, 0.0],
            orientation: [0.0, 0.0, 0.0, 1.0],
            num_children: 0,
            flags: 0,
        }]);

        let lod_model = FSkeletalMeshLODModel { vertices, indices };
        let skeletal_gltf =
            export_weapon_skeletal_mesh(&lod_model, Some(&skeleton), "weapon_skel.bin")
                .expect("Skeletal mesh gltf export failed");
        assert!(!skeletal_gltf.bin_data.is_empty());
    }

    #[test]
    fn test_inventory_query_helpers() {
        let inventory = WeaponAssetInventory {
            device_id: 10774,
            champion_id: 1026,
            skeletal_meshes: vec![
                WeaponMeshExport {
                    export_index: 10,
                    class_name: "SkeletalMesh".to_string(),
                    object_name: "skl_wep_fernando_skin11a_1p".to_string(),
                    serial_size: 400000,
                    serial_offset: 1000,
                },
                WeaponMeshExport {
                    export_index: 11,
                    class_name: "SkeletalMesh".to_string(),
                    object_name: "skl_wep_fernando_skin11a_3p".to_string(),
                    serial_size: 800000,
                    serial_offset: 500000,
                },
            ],
            static_meshes: vec![WeaponMeshExport {
                export_index: 20,
                class_name: "StaticMesh".to_string(),
                object_name: "sm_fernando_skin11a_aresshield_center".to_string(),
                serial_size: 10000,
                serial_offset: 900000,
            }],
            textures: vec![WeaponTextureExport {
                export_index: 30,
                object_name: "t_pc_fernando_arms_skin00a_dif".to_string(),
                serial_size: 3000,
                serial_offset: 1000000,
            }],
        };

        assert!(inventory.find_skeletal_mesh("1p").is_some());
        assert_eq!(inventory.find_skeletal_mesh("1p").unwrap().export_index, 10);
        assert!(inventory.find_skeletal_mesh("3p").is_some());
        assert_eq!(inventory.find_skeletal_mesh("3p").unwrap().export_index, 11);
        assert!(inventory.find_static_mesh("shield").is_some());
        assert!(inventory.find_texture("skin00a").is_some());
        assert!(inventory.find_texture("nonexistent").is_none());
    }
}
