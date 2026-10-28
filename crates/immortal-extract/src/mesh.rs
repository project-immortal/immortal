// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! SkeletalMesh GPUSkin vertex buffer parsing, `RefSkeleton` bone hierarchies,
//! UE3-to-glTF coordinate conversions, and glTF 2.0 exporter.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::ExtractError;

/// Converts a UE3 coordinate `[x, y, z]` (Z-up left-handed)
/// to glTF 2.0 `[x, z, -y]` (Y-up right-handed).
#[inline]
pub fn convert_coord_ue3_to_gltf(coord: [f32; 3]) -> [f32; 3] {
    [coord[0], coord[2], -coord[1]]
}

/// Converts a UE3 rotation quaternion `[qx, qy, qz, qw]`
/// to glTF 2.0 `[qx, qz, -qy, qw]`.
#[inline]
pub fn convert_quat_ue3_to_gltf(quat: [f32; 4]) -> [f32; 4] {
    [quat[0], quat[2], -quat[1], quat[3]]
}

/// Describes a bone in the Unreal Engine 3 `RefSkeleton`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FMeshBone {
    /// Bone name (e.g. "Root", "Pelvis", "Spine_01").
    pub name: String,
    /// Parent bone index (-1 for root, or parent bone index).
    pub parent_index: i32,
    /// Position translation in UE3 coordinates [x, y, z].
    pub position: [f32; 3],
    /// Orientation quaternion in UE3 coordinates [qx, qy, qz, qw].
    pub orientation: [f32; 4],
    /// Number of direct children.
    pub num_children: i32,
    /// Bone flags.
    pub flags: u32,
}

impl FMeshBone {
    /// Reads an `FMeshBone` from a binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        // Read string: length (u32) followed by UTF-8 bytes
        let name_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut name_buf = vec![0u8; name_len];
        reader.read_exact(&mut name_buf)?;
        let name = String::from_utf8_lossy(&name_buf).to_string();

        let parent_index = reader.read_i32::<LittleEndian>()?;
        let px = reader.read_f32::<LittleEndian>()?;
        let py = reader.read_f32::<LittleEndian>()?;
        let pz = reader.read_f32::<LittleEndian>()?;

        let qx = reader.read_f32::<LittleEndian>()?;
        let qy = reader.read_f32::<LittleEndian>()?;
        let qz = reader.read_f32::<LittleEndian>()?;
        let qw = reader.read_f32::<LittleEndian>()?;

        let num_children = reader.read_i32::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            name,
            parent_index,
            position: [px, py, pz],
            orientation: [qx, qy, qz, qw],
            num_children,
            flags,
        })
    }

    /// Writes an `FMeshBone` to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), ExtractError> {
        let name_bytes = self.name.as_bytes();
        writer.write_u32::<LittleEndian>(name_bytes.len() as u32)?;
        writer.write_all(name_bytes)?;

        writer.write_i32::<LittleEndian>(self.parent_index)?;
        writer.write_f32::<LittleEndian>(self.position[0])?;
        writer.write_f32::<LittleEndian>(self.position[1])?;
        writer.write_f32::<LittleEndian>(self.position[2])?;

        writer.write_f32::<LittleEndian>(self.orientation[0])?;
        writer.write_f32::<LittleEndian>(self.orientation[1])?;
        writer.write_f32::<LittleEndian>(self.orientation[2])?;
        writer.write_f32::<LittleEndian>(self.orientation[3])?;

        writer.write_i32::<LittleEndian>(self.num_children)?;
        writer.write_u32::<LittleEndian>(self.flags)?;
        Ok(())
    }
}

/// Unreal Engine 3 `RefSkeleton` containing bone array.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RefSkeleton {
    pub bones: Vec<FMeshBone>,
}

impl RefSkeleton {
    pub fn new(bones: Vec<FMeshBone>) -> Self {
        Self { bones }
    }

    /// Reads `RefSkeleton` from a binary stream.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let count = reader.read_u32::<LittleEndian>()? as usize;
        let mut bones = Vec::with_capacity(count);
        for _ in 0..count {
            bones.push(FMeshBone::read(reader)?);
        }
        Ok(Self { bones })
    }

    /// Writes `RefSkeleton` to a binary stream.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), ExtractError> {
        writer.write_u32::<LittleEndian>(self.bones.len() as u32)?;
        for bone in &self.bones {
            bone.write(writer)?;
        }
        Ok(())
    }
}

/// A GPUSkin vertex with standard UE3 attributes.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GPUSkinVertex {
    pub position: [f32; 3],
    pub normal: [f32; 3],
    pub tangent: [f32; 4],
    pub tex_coord_0: [f32; 2],
    pub joints_0: [u16; 4],
    pub weights_0: [f32; 4],
}

impl GPUSkinVertex {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let px = reader.read_f32::<LittleEndian>()?;
        let py = reader.read_f32::<LittleEndian>()?;
        let pz = reader.read_f32::<LittleEndian>()?;

        let nx = reader.read_f32::<LittleEndian>()?;
        let ny = reader.read_f32::<LittleEndian>()?;
        let nz = reader.read_f32::<LittleEndian>()?;

        let tx = reader.read_f32::<LittleEndian>()?;
        let ty = reader.read_f32::<LittleEndian>()?;
        let tz = reader.read_f32::<LittleEndian>()?;
        let tw = reader.read_f32::<LittleEndian>()?;

        let u = reader.read_f32::<LittleEndian>()?;
        let v = reader.read_f32::<LittleEndian>()?;

        let j0 = reader.read_u16::<LittleEndian>()?;
        let j1 = reader.read_u16::<LittleEndian>()?;
        let j2 = reader.read_u16::<LittleEndian>()?;
        let j3 = reader.read_u16::<LittleEndian>()?;

        let w0 = reader.read_f32::<LittleEndian>()?;
        let w1 = reader.read_f32::<LittleEndian>()?;
        let w2 = reader.read_f32::<LittleEndian>()?;
        let w3 = reader.read_f32::<LittleEndian>()?;

        Ok(Self {
            position: [px, py, pz],
            normal: [nx, ny, nz],
            tangent: [tx, ty, tz, tw],
            tex_coord_0: [u, v],
            joints_0: [j0, j1, j2, j3],
            weights_0: [w0, w1, w2, w3],
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), ExtractError> {
        writer.write_f32::<LittleEndian>(self.position[0])?;
        writer.write_f32::<LittleEndian>(self.position[1])?;
        writer.write_f32::<LittleEndian>(self.position[2])?;

        writer.write_f32::<LittleEndian>(self.normal[0])?;
        writer.write_f32::<LittleEndian>(self.normal[1])?;
        writer.write_f32::<LittleEndian>(self.normal[2])?;

        writer.write_f32::<LittleEndian>(self.tangent[0])?;
        writer.write_f32::<LittleEndian>(self.tangent[1])?;
        writer.write_f32::<LittleEndian>(self.tangent[2])?;
        writer.write_f32::<LittleEndian>(self.tangent[3])?;

        writer.write_f32::<LittleEndian>(self.tex_coord_0[0])?;
        writer.write_f32::<LittleEndian>(self.tex_coord_0[1])?;

        writer.write_u16::<LittleEndian>(self.joints_0[0])?;
        writer.write_u16::<LittleEndian>(self.joints_0[1])?;
        writer.write_u16::<LittleEndian>(self.joints_0[2])?;
        writer.write_u16::<LittleEndian>(self.joints_0[3])?;

        writer.write_f32::<LittleEndian>(self.weights_0[0])?;
        writer.write_f32::<LittleEndian>(self.weights_0[1])?;
        writer.write_f32::<LittleEndian>(self.weights_0[2])?;
        writer.write_f32::<LittleEndian>(self.weights_0[3])?;

        Ok(())
    }
}

/// Skeletal mesh LOD model containing GPUSkin vertices and index buffer.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FSkeletalMeshLODModel {
    pub vertices: Vec<GPUSkinVertex>,
    pub indices: Vec<u32>,
}

impl FSkeletalMeshLODModel {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ExtractError> {
        let v_count = reader.read_u32::<LittleEndian>()? as usize;
        let mut vertices = Vec::with_capacity(v_count);
        for _ in 0..v_count {
            vertices.push(GPUSkinVertex::read(reader)?);
        }

        let i_count = reader.read_u32::<LittleEndian>()? as usize;
        let mut indices = Vec::with_capacity(i_count);
        for _ in 0..i_count {
            indices.push(reader.read_u32::<LittleEndian>()?);
        }

        Ok(Self { vertices, indices })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), ExtractError> {
        writer.write_u32::<LittleEndian>(self.vertices.len() as u32)?;
        for v in &self.vertices {
            v.write(writer)?;
        }

        writer.write_u32::<LittleEndian>(self.indices.len() as u32)?;
        for idx in &self.indices {
            writer.write_u32::<LittleEndian>(*idx)?;
        }
        Ok(())
    }
}

/// glTF 2.0 export container with companion `.bin` data.
#[derive(Debug, Clone, PartialEq)]
pub struct GltfExport {
    /// Valid glTF 2.0 JSON string.
    pub gltf_json: String,
    /// Binary buffer payload.
    pub bin_data: Vec<u8>,
    /// Companion binary filename referenced in the glTF JSON `buffers[0].uri`.
    pub bin_filename: String,
}

impl GltfExport {
    /// Writes the `.gltf` and `.bin` files to target paths on disk.
    pub fn write_to_disk(&self, gltf_path: &Path, bin_path: &Path) -> std::io::Result<()> {
        let mut f_gltf = File::create(gltf_path)?;
        f_gltf.write_all(self.gltf_json.as_bytes())?;

        let mut f_bin = File::create(bin_path)?;
        f_bin.write_all(&self.bin_data)?;
        Ok(())
    }

    /// Convenience method to save both files into a directory using `name.gltf` and `name.bin`.
    pub fn save_to_dir(&self, dir: &Path, base_name: &str) -> std::io::Result<(PathBuf, PathBuf)> {
        let gltf_path = dir.join(format!("{base_name}.gltf"));
        let bin_path = dir.join(format!("{base_name}.bin"));
        self.write_to_disk(&gltf_path, &bin_path)?;
        Ok((gltf_path, bin_path))
    }
}

/// Computes the 4x4 matrix for translation and quaternion rotation.
/// Stored in column-major order (standard for glTF 2.0).
fn transform_matrix_column_major(t: [f32; 3], q: [f32; 4]) -> [f32; 16] {
    let x = q[0];
    let y = q[1];
    let z = q[2];
    let w = q[3];

    let xx = x * x;
    let yy = y * y;
    let zz = z * z;
    let xy = x * y;
    let xz = x * z;
    let yz = y * z;
    let wx = w * x;
    let wy = w * y;
    let wz = w * z;

    // Rotation columns
    let r00 = 1.0 - 2.0 * (yy + zz);
    let r10 = 2.0 * (xy + wz);
    let r20 = 2.0 * (xz - wy);

    let r01 = 2.0 * (xy - wz);
    let r11 = 1.0 - 2.0 * (xx + zz);
    let r21 = 2.0 * (yz + wx);

    let r02 = 2.0 * (xz + wy);
    let r12 = 2.0 * (yz - wx);
    let r22 = 1.0 - 2.0 * (xx + yy);

    [
        r00, r10, r20, 0.0, // Column 0
        r01, r11, r21, 0.0, // Column 1
        r02, r12, r22, 0.0, // Column 2
        t[0], t[1], t[2], 1.0, // Column 3
    ]
}

/// Multiplies two 4x4 column-major matrices: `C = A * B`.
fn multiply_mat4(a: &[f32; 16], b: &[f32; 16]) -> [f32; 16] {
    let mut out = [0.0f32; 16];
    for col in 0..4 {
        for row in 0..4 {
            let mut sum = 0.0;
            for k in 0..4 {
                sum += a[k * 4 + row] * b[col * 4 + k];
            }
            out[col * 4 + row] = sum;
        }
    }
    out
}

/// Inverts a 4x4 affine rigid transform matrix (orthonormal rotation + translation).
fn invert_affine_rigid_matrix(m: &[f32; 16]) -> [f32; 16] {
    // Rotation part R is in columns 0..2, rows 0..2.
    // Inverse of rotation is transpose R^T.
    let r00 = m[0];
    let r01 = m[4];
    let r02 = m[8];

    let r10 = m[1];
    let r11 = m[5];
    let r12 = m[9];

    let r20 = m[2];
    let r21 = m[6];
    let r22 = m[10];

    let tx = m[12];
    let ty = m[13];
    let tz = m[14];

    // -R^T * T
    let itx = -(r00 * tx + r10 * ty + r20 * tz);
    let ity = -(r01 * tx + r11 * ty + r21 * tz);
    let itz = -(r02 * tx + r12 * ty + r22 * tz);

    [
        r00, r01, r02, 0.0, // Column 0
        r10, r11, r12, 0.0, // Column 1
        r20, r21, r22, 0.0, // Column 2
        itx, ity, itz, 1.0, // Column 3
    ]
}

/// Exports a `FSkeletalMeshLODModel` and optional `RefSkeleton` to glTF 2.0 JSON and companion binary.
pub fn export_skeletal_mesh_to_gltf(
    model: &FSkeletalMeshLODModel,
    skeleton: Option<&RefSkeleton>,
    bin_filename: &str,
) -> Result<GltfExport, ExtractError> {
    let mut bin = Vec::new();
    let mut buffer_views = Vec::new();
    let mut accessors = Vec::new();

    // 1. Indices BufferView & Accessor
    let indices_offset = bin.len();
    let mut min_idx = u32::MAX;
    let mut max_idx = 0;
    for &idx in &model.indices {
        min_idx = min_idx.min(idx);
        max_idx = max_idx.max(idx);
        bin.extend_from_slice(&idx.to_le_bytes());
    }
    let indices_len = bin.len() - indices_offset;
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": indices_offset,
        "byteLength": indices_len,
        "target": 34963 // ELEMENT_ARRAY_BUFFER
    }));
    let indices_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": 0,
        "byteOffset": 0,
        "componentType": 5125, // UNSIGNED_INT
        "count": model.indices.len(),
        "type": "SCALAR",
        "min": [if model.indices.is_empty() { 0 } else { min_idx }],
        "max": [if model.indices.is_empty() { 0 } else { max_idx }]
    }));

    // Align buffer to 4 bytes
    while bin.len() % 4 != 0 {
        bin.push(0);
    }

    // 2. Positions (converted to glTF coordinate system [x, z, -y])
    let pos_offset = bin.len();
    let mut min_pos = [f32::MAX, f32::MAX, f32::MAX];
    let mut max_pos = [f32::MIN, f32::MIN, f32::MIN];
    for v in &model.vertices {
        let p = convert_coord_ue3_to_gltf(v.position);
        for i in 0..3 {
            min_pos[i] = min_pos[i].min(p[i]);
            max_pos[i] = max_pos[i].max(p[i]);
            bin.extend_from_slice(&p[i].to_le_bytes());
        }
    }
    let (min_pos, max_pos) = if model.vertices.is_empty() {
        ([0.0, 0.0, 0.0], [0.0, 0.0, 0.0])
    } else {
        (min_pos, max_pos)
    };
    let pos_len = bin.len() - pos_offset;
    let pos_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": pos_offset,
        "byteLength": pos_len,
        "target": 34962 // ARRAY_BUFFER
    }));
    let pos_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": pos_bv_idx,
        "byteOffset": 0,
        "componentType": 5126, // FLOAT
        "count": model.vertices.len(),
        "type": "VEC3",
        "min": [min_pos[0], min_pos[1], min_pos[2]],
        "max": [max_pos[0], max_pos[1], max_pos[2]]
    }));

    // 3. Normals (converted to glTF coordinate system [nx, nz, -ny])
    let norm_offset = bin.len();
    for v in &model.vertices {
        let n = convert_coord_ue3_to_gltf(v.normal);
        for val in n {
            bin.extend_from_slice(&val.to_le_bytes());
        }
    }
    let norm_len = bin.len() - norm_offset;
    let norm_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": norm_offset,
        "byteLength": norm_len,
        "target": 34962
    }));
    let norm_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": norm_bv_idx,
        "byteOffset": 0,
        "componentType": 5126,
        "count": model.vertices.len(),
        "type": "VEC3"
    }));

    // 4. Tangents (converted to glTF coordinate system [tx, tz, -ty, tw])
    let tang_offset = bin.len();
    for v in &model.vertices {
        let t = [v.tangent[0], v.tangent[2], -v.tangent[1], v.tangent[3]];
        for val in t {
            bin.extend_from_slice(&val.to_le_bytes());
        }
    }
    let tang_len = bin.len() - tang_offset;
    let tang_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": tang_offset,
        "byteLength": tang_len,
        "target": 34962
    }));
    let tang_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": tang_bv_idx,
        "byteOffset": 0,
        "componentType": 5126,
        "count": model.vertices.len(),
        "type": "VEC4"
    }));

    // 5. TexCoords (TEXCOORD_0)
    let uv_offset = bin.len();
    for v in &model.vertices {
        bin.extend_from_slice(&v.tex_coord_0[0].to_le_bytes());
        bin.extend_from_slice(&v.tex_coord_0[1].to_le_bytes());
    }
    let uv_len = bin.len() - uv_offset;
    let uv_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": uv_offset,
        "byteLength": uv_len,
        "target": 34962
    }));
    let uv_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": uv_bv_idx,
        "byteOffset": 0,
        "componentType": 5126,
        "count": model.vertices.len(),
        "type": "VEC2"
    }));

    // 6. Joints (JOINTS_0)
    let joints_offset = bin.len();
    for v in &model.vertices {
        for j in 0..4 {
            bin.extend_from_slice(&v.joints_0[j].to_le_bytes());
        }
    }
    let joints_len = bin.len() - joints_offset;
    let joints_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": joints_offset,
        "byteLength": joints_len,
        "target": 34962
    }));
    let joints_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": joints_bv_idx,
        "byteOffset": 0,
        "componentType": 5123, // UNSIGNED_SHORT
        "count": model.vertices.len(),
        "type": "VEC4"
    }));

    // 7. Weights (WEIGHTS_0)
    let weights_offset = bin.len();
    for v in &model.vertices {
        for w in 0..4 {
            bin.extend_from_slice(&v.weights_0[w].to_le_bytes());
        }
    }
    let weights_len = bin.len() - weights_offset;
    let weights_bv_idx = buffer_views.len();
    buffer_views.push(json!({
        "buffer": 0,
        "byteOffset": weights_offset,
        "byteLength": weights_len,
        "target": 34962
    }));
    let weights_accessor_idx = accessors.len();
    accessors.push(json!({
        "bufferView": weights_bv_idx,
        "byteOffset": 0,
        "componentType": 5126,
        "count": model.vertices.len(),
        "type": "VEC4"
    }));

    // Optional 8: Inverse Bind Matrices for RefSkeleton
    let mut inv_bind_accessor_idx = None;
    if let Some(skel) = skeleton {
        if !skel.bones.is_empty() {
            // Align buffer to 4 bytes
            while bin.len() % 4 != 0 {
                bin.push(0);
            }

            let ibm_offset = bin.len();
            // Compute world matrices in glTF coordinates
            let mut world_matrices = Vec::with_capacity(skel.bones.len());
            for (i, bone) in skel.bones.iter().enumerate() {
                let pos = convert_coord_ue3_to_gltf(bone.position);
                let rot = convert_quat_ue3_to_gltf(bone.orientation);
                let local = transform_matrix_column_major(pos, rot);

                let world = if bone.parent_index >= 0 && (bone.parent_index as usize) < i {
                    multiply_mat4(&world_matrices[bone.parent_index as usize], &local)
                } else {
                    local
                };
                world_matrices.push(world);
            }

            // Invert each world matrix to obtain inverse bind matrix
            for world in &world_matrices {
                let inv = invert_affine_rigid_matrix(world);
                for val in inv {
                    bin.extend_from_slice(&val.to_le_bytes());
                }
            }

            let ibm_len = bin.len() - ibm_offset;
            let ibm_bv_idx = buffer_views.len();
            buffer_views.push(json!({
                "buffer": 0,
                "byteOffset": ibm_offset,
                "byteLength": ibm_len
            }));

            inv_bind_accessor_idx = Some(accessors.len());
            accessors.push(json!({
                "bufferView": ibm_bv_idx,
                "byteOffset": 0,
                "componentType": 5126,
                "count": skel.bones.len(),
                "type": "MAT4"
            }));
        }
    }

    // Build Nodes & Scenes
    let mut nodes = Vec::new();
    let mut scene_nodes = Vec::new();

    // Node 0: Mesh node
    let mut mesh_node = json!({
        "name": "SkeletalMeshNode",
        "mesh": 0
    });
    if let Some(skel) = skeleton {
        if !skel.bones.is_empty() {
            mesh_node["skin"] = json!(0);
        }
    }
    nodes.push(mesh_node);
    scene_nodes.push(0);

    // Bone nodes
    let mut skin_joints = Vec::new();
    if let Some(skel) = skeleton {
        if !skel.bones.is_empty() {
            let bone_node_start = 1;
            // Build children mapping
            let mut children_map: Vec<Vec<u32>> = vec![Vec::new(); skel.bones.len()];
            for (idx, bone) in skel.bones.iter().enumerate() {
                if bone.parent_index >= 0
                    && (bone.parent_index as usize) < skel.bones.len()
                    && bone.parent_index as usize != idx
                {
                    children_map[bone.parent_index as usize].push((bone_node_start + idx) as u32);
                }
            }

            for (idx, bone) in skel.bones.iter().enumerate() {
                let node_id = (bone_node_start + idx) as u32;
                skin_joints.push(node_id);

                let pos = convert_coord_ue3_to_gltf(bone.position);
                let rot = convert_quat_ue3_to_gltf(bone.orientation);

                let mut b_node = json!({
                    "name": bone.name,
                    "translation": [pos[0], pos[1], pos[2]],
                    "rotation": [rot[0], rot[1], rot[2], rot[3]]
                });

                if !children_map[idx].is_empty() {
                    b_node["children"] = json!(children_map[idx]);
                }

                // If root bone (parent_index < 0 or self), add to scene nodes
                if bone.parent_index < 0 || bone.parent_index as usize == idx {
                    scene_nodes.push(node_id);
                }

                nodes.push(b_node);
            }
        }
    }

    // Meshes definition
    let mesh_def = json!({
        "name": "SkeletalMesh",
        "primitives": [
            {
                "attributes": {
                    "POSITION": pos_accessor_idx,
                    "NORMAL": norm_accessor_idx,
                    "TANGENT": tang_accessor_idx,
                    "TEXCOORD_0": uv_accessor_idx,
                    "JOINTS_0": joints_accessor_idx,
                    "WEIGHTS_0": weights_accessor_idx
                },
                "indices": indices_accessor_idx,
                "mode": 4 // TRIANGLES
            }
        ]
    });

    // Skins definition
    let mut skins = Vec::new();
    if let Some(ibm_idx) = inv_bind_accessor_idx {
        skins.push(json!({
            "name": "Armature",
            "inverseBindMatrices": ibm_idx,
            "joints": skin_joints
        }));
    }

    // Final glTF Root JSON
    let mut gltf_root = json!({
        "asset": {
            "version": "2.0",
            "generator": "Project Immortal Cleanroom UE3 SkeletalMesh Exporter"
        },
        "scene": 0,
        "scenes": [
            {
                "name": "DefaultScene",
                "nodes": scene_nodes
            }
        ],
        "nodes": nodes,
        "meshes": [mesh_def],
        "accessors": accessors,
        "bufferViews": buffer_views,
        "buffers": [
            {
                "byteLength": bin.len(),
                "uri": bin_filename
            }
        ]
    });

    if !skins.is_empty() {
        gltf_root["skins"] = json!(skins);
    }

    let gltf_json =
        serde_json::to_string_pretty(&gltf_root).map_err(|e| ExtractError::GltfExport {
            reason: format!("JSON serialization failed: {e}"),
        })?;

    Ok(GltfExport {
        gltf_json,
        bin_data: bin,
        bin_filename: bin_filename.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_coordinate_conversion() {
        // UE3: X forward, Y right, Z up
        // glTF: [x, z, -y]
        let ue3_pos = [10.0, 20.0, 30.0];
        let gltf_pos = convert_coord_ue3_to_gltf(ue3_pos);
        assert_eq!(gltf_pos, [10.0, 30.0, -20.0]);

        let ue3_rot = [0.0, 0.5, 0.0, 0.5];
        let gltf_rot = convert_quat_ue3_to_gltf(ue3_rot);
        assert_eq!(gltf_rot, [0.0, 0.0, -0.5, 0.5]);
    }

    #[test]
    fn test_mesh_bone_roundtrip() {
        let bone = FMeshBone {
            name: "Bip01_Spine".to_string(),
            parent_index: 0,
            position: [1.0, 2.0, 3.0],
            orientation: [0.1, 0.2, 0.3, 0.9],
            num_children: 2,
            flags: 0x1234,
        };

        let mut buf = Vec::new();
        bone.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let read_bone = FMeshBone::read(&mut cursor).unwrap();
        assert_eq!(read_bone, bone);
    }

    #[test]
    fn test_skeletal_mesh_lod_model_roundtrip() {
        let model = FSkeletalMeshLODModel {
            vertices: vec![
                GPUSkinVertex {
                    position: [0.0, 0.0, 0.0],
                    normal: [0.0, 1.0, 0.0],
                    tangent: [1.0, 0.0, 0.0, 1.0],
                    tex_coord_0: [0.0, 0.0],
                    joints_0: [0, 1, 0, 0],
                    weights_0: [0.75, 0.25, 0.0, 0.0],
                },
                GPUSkinVertex {
                    position: [10.0, 0.0, 0.0],
                    normal: [0.0, 1.0, 0.0],
                    tangent: [1.0, 0.0, 0.0, 1.0],
                    tex_coord_0: [1.0, 0.0],
                    joints_0: [1, 0, 0, 0],
                    weights_0: [1.0, 0.0, 0.0, 0.0],
                },
            ],
            indices: vec![0, 1, 0],
        };

        let mut buf = Vec::new();
        model.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let read_model = FSkeletalMeshLODModel::read(&mut cursor).unwrap();
        assert_eq!(read_model, model);
    }

    #[test]
    fn test_export_skeletal_mesh_to_gltf_json_validity() {
        let model = FSkeletalMeshLODModel {
            vertices: vec![
                GPUSkinVertex {
                    position: [0.0, 0.0, 0.0],
                    normal: [0.0, 0.0, 1.0],
                    tangent: [1.0, 0.0, 0.0, 1.0],
                    tex_coord_0: [0.0, 0.0],
                    joints_0: [0, 0, 0, 0],
                    weights_0: [1.0, 0.0, 0.0, 0.0],
                },
                GPUSkinVertex {
                    position: [1.0, 0.0, 0.0],
                    normal: [0.0, 0.0, 1.0],
                    tangent: [1.0, 0.0, 0.0, 1.0],
                    tex_coord_0: [1.0, 0.0],
                    joints_0: [0, 0, 0, 0],
                    weights_0: [1.0, 0.0, 0.0, 0.0],
                },
                GPUSkinVertex {
                    position: [0.0, 1.0, 0.0],
                    normal: [0.0, 0.0, 1.0],
                    tangent: [1.0, 0.0, 0.0, 1.0],
                    tex_coord_0: [0.0, 1.0],
                    joints_0: [0, 0, 0, 0],
                    weights_0: [1.0, 0.0, 0.0, 0.0],
                },
            ],
            indices: vec![0, 1, 2],
        };

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
                name: "Spine".to_string(),
                parent_index: 0,
                position: [0.0, 0.0, 10.0],
                orientation: [0.0, 0.0, 0.0, 1.0],
                num_children: 0,
                flags: 0,
            },
        ]);

        let export =
            export_skeletal_mesh_to_gltf(&model, Some(&skeleton), "test_model.bin").unwrap();
        assert!(!export.bin_data.is_empty());
        assert_eq!(export.bin_filename, "test_model.bin");

        // Parse JSON to verify glTF 2.0 validity
        let json_val: serde_json::Value =
            serde_json::from_str(&export.gltf_json).expect("Invalid glTF JSON");
        assert_eq!(json_val["asset"]["version"], "2.0");
        assert_eq!(json_val["buffers"][0]["uri"], "test_model.bin");
        assert_eq!(json_val["meshes"].as_array().unwrap().len(), 1);
        assert_eq!(json_val["skins"].as_array().unwrap().len(), 1);
        assert_eq!(json_val["nodes"].as_array().unwrap().len(), 3); // 1 mesh + 2 bones
    }

    #[test]
    fn test_empty_mesh_gltf_export_bounds() {
        let empty_model = FSkeletalMeshLODModel {
            vertices: Vec::new(),
            indices: Vec::new(),
        };

        let export = export_skeletal_mesh_to_gltf(&empty_model, None, "empty.bin")
            .expect("Empty mesh should export cleanly");

        let json_val: serde_json::Value = serde_json::from_str(&export.gltf_json).unwrap();
        let pos_accessor = &json_val["accessors"][1];
        let min_arr = pos_accessor["min"].as_array().unwrap();
        let max_arr = pos_accessor["max"].as_array().unwrap();

        assert_eq!(min_arr, &[0.0, 0.0, 0.0]);
        assert_eq!(max_arr, &[0.0, 0.0, 0.0]);
        for i in 0..3 {
            let min_val = min_arr[i].as_f64().unwrap();
            let max_val = max_arr[i].as_f64().unwrap();
            assert!(min_val <= max_val, "min must be <= max");
        }
    }
}
