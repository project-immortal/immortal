// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Server-authoritative physical collision extractor (`ADOPT-01` / `OBL-COL-001`).
//!
//! Parses UE3 `UBrushComponent` (`BrushAggGeom`) and `URB_BodySetup` (`AggGeom`)
//! into pure-Rust `AggregateGeometry` / `ConvexHull` primitives and provides
//! Separating Axis Theorem (SAT) raycast, sphere-sweep, point-containment, and
//! hull-closure queries without linking external C++ physics engines.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek};

use crate::error::ExtractError;
use crate::index::PackageIndex;
use crate::name::NameTable;
use crate::package::UpkPackage;
use crate::property::{find_property, read_object_properties, FPropertyTag, PropertyValue, StructValue};

const IDENTITY_MATRIX: [[f32; 4]; 4] = [
    [1.0, 0.0, 0.0, 0.0],
    [0.0, 1.0, 0.0, 0.0],
    [0.0, 0.0, 1.0, 0.0],
    [0.0, 0.0, 0.0, 1.0],
];

/// Result of a raycast or sphere sweep against collision geometry.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RaycastHit {
    /// Distance along the ray direction (`t >= 0`).
    pub distance: f32,
    /// World/local-space intersection point (`origin + dir * distance`).
    pub point: [f32; 3],
    /// Outward surface unit normal at the hit point.
    pub normal: [f32; 3],
}

/// Precomputed convex polyhedron extracted from UE3 `FKConvexElem`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConvexHull {
    pub vertices: Vec<[f32; 3]>,
    /// SIMD SoA-permuted vertex blocks from UE3 `PermutedVertexData`.
    pub permuted_planes: Vec<[f32; 4]>,
    pub edge_directions: Vec<[f32; 3]>,
    pub face_normals: Vec<[f32; 3]>,
    /// Half-space plane equations `[A, B, C, D]` such that interior points satisfy
    /// `A*x + B*y + C*z + D <= 0`.
    pub plane_equations: Vec<[f32; 4]>,
    pub aabb_min: [f32; 3],
    pub aabb_max: [f32; 3],
}

/// Oriented box primitive extracted from UE3 `FKBoxElem`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoxElem {
    pub transform: [[f32; 4]; 4],
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub no_rb_collision: bool,
    pub per_poly_shape: bool,
}

/// Sphere primitive extracted from UE3 `FKSphereElem`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SphereElem {
    pub transform: [[f32; 4]; 4],
    pub radius: f32,
    pub no_rb_collision: bool,
    pub per_poly_shape: bool,
}

/// Capsule primitive extracted from UE3 `FKSphylElem`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SphylElem {
    pub transform: [[f32; 4]; 4],
    pub radius: f32,
    pub length: f32,
    pub no_rb_collision: bool,
    pub per_poly_shape: bool,
}

/// Pure-Rust representation of UE3 `FKAggregateGeom`.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregateGeometry {
    pub convex_hulls: Vec<ConvexHull>,
    pub boxes: Vec<BoxElem>,
    pub spheres: Vec<SphereElem>,
    pub sphyls: Vec<SphylElem>,
}

/// Collision geometry extracted from a single package export (`UBrushComponent` or `URB_BodySetup`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CollisionExport {
    pub export_index: usize,
    pub class_name: String,
    pub object_name: String,
    pub full_path: String,
    pub geometry: AggregateGeometry,
}

#[inline]
fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

#[inline]
fn sub3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

#[inline]
fn cross3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

#[inline]
fn len3(v: [f32; 3]) -> f32 {
    dot3(v, v).sqrt()
}

#[inline]
fn normalize3(v: [f32; 3]) -> [f32; 3] {
    let l = len3(v);
    if l > 1e-12 {
        [v[0] / l, v[1] / l, v[2] / l]
    } else {
        [0.0, 0.0, 1.0]
    }
}

/// Transforms a point from world/geometry space into the local space of an orthonormal rigid `transform`
/// (`row[3][0..3]` = translation, `row[0..3][0..3]` = rotation basis).
fn world_to_local_point(tm: &[[f32; 4]; 4], p: [f32; 3]) -> [f32; 3] {
    let rel = [p[0] - tm[3][0], p[1] - tm[3][1], p[2] - tm[3][2]];
    [
        dot3(rel, [tm[0][0], tm[0][1], tm[0][2]]),
        dot3(rel, [tm[1][0], tm[1][1], tm[1][2]]),
        dot3(rel, [tm[2][0], tm[2][1], tm[2][2]]),
    ]
}

fn world_to_local_dir(tm: &[[f32; 4]; 4], d: [f32; 3]) -> [f32; 3] {
    [
        dot3(d, [tm[0][0], tm[0][1], tm[0][2]]),
        dot3(d, [tm[1][0], tm[1][1], tm[1][2]]),
        dot3(d, [tm[2][0], tm[2][1], tm[2][2]]),
    ]
}

fn local_to_world_dir(tm: &[[f32; 4]; 4], n: [f32; 3]) -> [f32; 3] {
    [
        n[0] * tm[0][0] + n[1] * tm[1][0] + n[2] * tm[2][0],
        n[0] * tm[0][1] + n[1] * tm[1][1] + n[2] * tm[2][1],
        n[0] * tm[0][2] + n[1] * tm[1][2] + n[2] * tm[2][2],
    ]
}

impl ConvexHull {
    /// Computes the maximum signed distance `Ax + By + Cz + D` across all vertices and planes.
    /// Returns `f32::INFINITY` if `vertices` or `plane_equations` is empty.
    pub fn max_plane_violation(&self) -> f32 {
        if self.vertices.is_empty() || self.plane_equations.is_empty() {
            return f32::INFINITY;
        }
        let mut max_v = f32::NEG_INFINITY;
        for p in &self.plane_equations {
            for v in &self.vertices {
                let d = p[0] * v[0] + p[1] * v[1] + p[2] * v[2] + p[3];
                if d > max_v {
                    max_v = d;
                }
            }
        }
        max_v
    }

    /// Validates hull closure: every vertex lies on or inside every half-space plane within `epsilon`.
    pub fn validate_closure(&self, epsilon: f32) -> bool {
        self.max_plane_violation() <= epsilon
    }

    /// Returns `true` if `point` lies inside (or within `epsilon` of) this convex hull.
    pub fn contains_point(&self, point: [f32; 3], epsilon: f32) -> bool {
        if self.plane_equations.is_empty() {
            return false;
        }
        if point[0] < self.aabb_min[0] - epsilon
            || point[0] > self.aabb_max[0] + epsilon
            || point[1] < self.aabb_min[1] - epsilon
            || point[1] > self.aabb_max[1] + epsilon
            || point[2] < self.aabb_min[2] - epsilon
            || point[2] > self.aabb_max[2] + epsilon
        {
            return false;
        }

        self.plane_equations
            .iter()
            .all(|p| p[0] * point[0] + p[1] * point[1] + p[2] * point[2] + p[3] <= epsilon)
    }

    /// Performs a raycast (`origin + t * dir`, `0 <= t <= max_distance`) against the convex hull
    /// via half-space / SAT slab clipping.
    pub fn raycast(&self, origin: [f32; 3], dir: [f32; 3], max_distance: f32) -> Option<RaycastHit> {
        self.raycast_inflated(origin, dir, 0.0, max_distance)
    }

    /// Performs a sphere sweep of `radius` along `origin + t * dir` (`0 <= t <= max_distance`)
    /// using Minkowski-expanded convex half-space planes.
    pub fn sphere_sweep(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        self.raycast_inflated(origin, dir, radius.max(0.0), max_distance)
    }

    fn raycast_inflated(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        if self.plane_equations.is_empty() || max_distance < 0.0 {
            return None;
        }

        let mut t_enter = 0.0f32;
        let mut t_exit = max_distance;
        let mut hit_normal: Option<[f32; 3]> = None;

        for p in &self.plane_equations {
            let n = [p[0], p[1], p[2]];
            let n_len = len3(n);
            let d = p[3] - radius * n_len;
            let dist = dot3(n, origin) + d;
            let denom = dot3(n, dir);

            if denom.abs() < 1e-8 {
                if dist > 1e-4 {
                    return None;
                }
            } else {
                let t = -dist / denom;
                if denom < 0.0 {
                    if t > t_enter {
                        t_enter = t;
                        hit_normal = Some(normalize3(n));
                    }
                } else if t < t_exit {
                    t_exit = t;
                }

                if t_enter > t_exit {
                    return None;
                }
            }
        }

        if t_enter <= t_exit && t_enter >= 0.0 && t_enter <= max_distance {
            let normal = hit_normal.unwrap_or_else(|| normalize3([-dir[0], -dir[1], -dir[2]]));
            let point = [
                origin[0] + dir[0] * t_enter,
                origin[1] + dir[1] * t_enter,
                origin[2] + dir[2] * t_enter,
            ];
            Some(RaycastHit {
                distance: t_enter,
                point,
                normal,
            })
        } else {
            None
        }
    }

    /// Separating Axis Theorem (SAT) overlap test between this convex hull and an axis-aligned bounding box.
    pub fn intersects_aabb(&self, box_min: [f32; 3], box_max: [f32; 3]) -> bool {
        if self.vertices.is_empty() {
            return false;
        }
        // 1. AABB axes (3 axes)
        for axis in 0..3 {
            if self.aabb_max[axis] < box_min[axis] || self.aabb_min[axis] > box_max[axis] {
                return false;
            }
        }

        let box_center = [
            0.5 * (box_min[0] + box_max[0]),
            0.5 * (box_min[1] + box_max[1]),
            0.5 * (box_min[2] + box_max[2]),
        ];
        let box_extents = [
            0.5 * (box_max[0] - box_min[0]),
            0.5 * (box_max[1] - box_min[1]),
            0.5 * (box_max[2] - box_min[2]),
        ];

        let separated_on_axis = |axis: [f32; 3]| -> bool {
            if dot3(axis, axis) < 1e-10 {
                return false;
            }
            let mut hull_min = f32::INFINITY;
            let mut hull_max = f32::NEG_INFINITY;
            for v in &self.vertices {
                let p = dot3(*v, axis);
                hull_min = hull_min.min(p);
                hull_max = hull_max.max(p);
            }
            let box_c = dot3(box_center, axis);
            let box_r = box_extents[0] * axis[0].abs()
                + box_extents[1] * axis[1].abs()
                + box_extents[2] * axis[2].abs();
            hull_max < box_c - box_r || hull_min > box_c + box_r
        };

        // 2. Hull face normals
        for p in &self.plane_equations {
            if separated_on_axis([p[0], p[1], p[2]]) {
                return false;
            }
        }

        // 3. Cross products of box principal axes and hull edge directions
        const CARDINAL: [[f32; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        for edge in &self.edge_directions {
            for cardinal in &CARDINAL {
                if separated_on_axis(cross3(*cardinal, *edge)) {
                    return false;
                }
            }
        }

        true
    }
}

impl BoxElem {
    /// Checks whether a point lies inside (or within `epsilon` of) this oriented box.
    pub fn contains_point(&self, point: [f32; 3], epsilon: f32) -> bool {
        let local = world_to_local_point(&self.transform, point);
        let hx = 0.5 * self.x + epsilon;
        let hy = 0.5 * self.y + epsilon;
        let hz = 0.5 * self.z + epsilon;
        local[0].abs() <= hx && local[1].abs() <= hy && local[2].abs() <= hz
    }

    /// Raycasts against this oriented box (`radius >= 0` inflates half-extents conservatively).
    pub fn raycast(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        let lo = world_to_local_point(&self.transform, origin);
        let ld = world_to_local_dir(&self.transform, dir);
        let half = [
            0.5 * self.x + radius,
            0.5 * self.y + radius,
            0.5 * self.z + radius,
        ];

        let mut t_enter = 0.0f32;
        let mut t_exit = max_distance;
        let mut hit_local_normal: Option<[f32; 3]> = None;

        for axis in 0..3 {
            if ld[axis].abs() < 1e-8 {
                if lo[axis].abs() > half[axis] {
                    return None;
                }
            } else {
                let inv = 1.0 / ld[axis];
                let mut t1 = (-half[axis] - lo[axis]) * inv;
                let mut t2 = (half[axis] - lo[axis]) * inv;
                let mut n1 = [0.0f32; 3];
                n1[axis] = -1.0;
                if t1 > t2 {
                    std::mem::swap(&mut t1, &mut t2);
                    n1[axis] = 1.0;
                }
                if t1 > t_enter {
                    t_enter = t1;
                    hit_local_normal = Some(n1);
                }
                t_exit = t_exit.min(t2);
                if t_enter > t_exit {
                    return None;
                }
            }
        }

        if t_enter <= t_exit && t_enter >= 0.0 && t_enter <= max_distance {
            let local_n = hit_local_normal.unwrap_or_else(|| normalize3([-ld[0], -ld[1], -ld[2]]));
            let normal = normalize3(local_to_world_dir(&self.transform, local_n));
            let point = [
                origin[0] + dir[0] * t_enter,
                origin[1] + dir[1] * t_enter,
                origin[2] + dir[2] * t_enter,
            ];
            Some(RaycastHit {
                distance: t_enter,
                point,
                normal,
            })
        } else {
            None
        }
    }
}

impl SphereElem {
    /// Checks whether a point lies inside (or within `epsilon` of) this sphere.
    pub fn contains_point(&self, point: [f32; 3], epsilon: f32) -> bool {
        let center = [
            self.transform[3][0],
            self.transform[3][1],
            self.transform[3][2],
        ];
        let diff = sub3(point, center);
        let r = self.radius + epsilon;
        dot3(diff, diff) <= r * r
    }

    /// Raycasts against this sphere (`extra_radius >= 0` supports sphere sweeps).
    pub fn raycast(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        extra_radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        let center = [
            self.transform[3][0],
            self.transform[3][1],
            self.transform[3][2],
        ];
        let oc = sub3(origin, center);
        let r = self.radius + extra_radius;
        let a = dot3(dir, dir);
        if a < 1e-12 {
            return None;
        }
        let b = dot3(oc, dir);
        let c = dot3(oc, oc) - r * r;
        if c <= 0.0 {
            let normal = if dot3(oc, oc) > 1e-12 {
                normalize3(oc)
            } else {
                normalize3([-dir[0], -dir[1], -dir[2]])
            };
            return Some(RaycastHit {
                distance: 0.0,
                point: origin,
                normal,
            });
        }
        let disc = b * b - a * c;
        if disc < 0.0 {
            return None;
        }
        let t = (-b - disc.sqrt()) / a;
        if t < 0.0 || t > max_distance {
            return None;
        }
        let point = [
            origin[0] + dir[0] * t,
            origin[1] + dir[1] * t,
            origin[2] + dir[2] * t,
        ];
        Some(RaycastHit {
            distance: t,
            point,
            normal: normalize3(sub3(point, center)),
        })
    }
}

impl SphylElem {
    /// Checks whether a point lies inside (or within `epsilon` of) this capsule (`Z`-axis aligned in local space).
    pub fn contains_point(&self, point: [f32; 3], epsilon: f32) -> bool {
        let local = world_to_local_point(&self.transform, point);
        let half_len = 0.5 * self.length;
        let clamped_z = local[2].clamp(-half_len, half_len);
        let dx = local[0];
        let dy = local[1];
        let dz = local[2] - clamped_z;
        let r = self.radius + epsilon;
        dx * dx + dy * dy + dz * dz <= r * r
    }
}

impl AggregateGeometry {
    /// Returns `true` if all convex hulls satisfy hull closure within `epsilon`.
    pub fn validate_closure(&self, epsilon: f32) -> bool {
        self.convex_hulls
            .iter()
            .all(|h| h.validate_closure(epsilon))
    }

    /// Returns `true` if `point` is contained in any primitive of this `AggregateGeometry`.
    pub fn contains_point(&self, point: [f32; 3], epsilon: f32) -> bool {
        self.convex_hulls
            .iter()
            .any(|h| h.contains_point(point, epsilon))
            || self
                .boxes
                .iter()
                .any(|b| !b.no_rb_collision && b.contains_point(point, epsilon))
            || self
                .spheres
                .iter()
                .any(|s| !s.no_rb_collision && s.contains_point(point, epsilon))
            || self
                .sphyls
                .iter()
                .any(|c| !c.no_rb_collision && c.contains_point(point, epsilon))
    }

    /// Finds the closest raycast intersection across all primitives in this `AggregateGeometry`.
    pub fn raycast(&self, origin: [f32; 3], dir: [f32; 3], max_distance: f32) -> Option<RaycastHit> {
        self.sweep_internal(origin, dir, 0.0, max_distance)
    }

    /// Finds the closest sphere-sweep intersection across convex hulls, boxes, and spheres.
    pub fn sphere_sweep(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        self.sweep_internal(origin, dir, radius.max(0.0), max_distance)
    }

    fn sweep_internal(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        radius: f32,
        max_distance: f32,
    ) -> Option<RaycastHit> {
        let mut best: Option<RaycastHit> = None;
        let mut limit = max_distance;

        fn consider(best: &mut Option<RaycastHit>, limit: &mut f32, hit: Option<RaycastHit>) {
            if let Some(h) = hit {
                if best.is_none_or(|b| h.distance < b.distance) {
                    *limit = h.distance;
                    *best = Some(h);
                }
            }
        }

        for hull in &self.convex_hulls {
            let hit = hull.raycast_inflated(origin, dir, radius, limit);
            consider(&mut best, &mut limit, hit);
        }
        for b in &self.boxes {
            if !b.no_rb_collision {
                let hit = b.raycast(origin, dir, radius, limit);
                consider(&mut best, &mut limit, hit);
            }
        }
        for s in &self.spheres {
            if !s.no_rb_collision {
                let hit = s.raycast(origin, dir, radius, limit);
                consider(&mut best, &mut limit, hit);
            }
        }
        best
    }
}

fn read_vec3_array(raw: &[u8], count: u32) -> Result<Vec<[f32; 3]>, ExtractError> {
    let needed = (count as usize) * 12;
    if raw.len() < needed {
        return Err(ExtractError::BufferOverflow {
            required: needed,
            available: raw.len(),
        });
    }
    let mut c = Cursor::new(raw);
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push([
            c.read_f32::<LittleEndian>()?,
            c.read_f32::<LittleEndian>()?,
            c.read_f32::<LittleEndian>()?,
        ]);
    }
    Ok(out)
}

fn read_fplane_array_raw(raw: &[u8], count: u32) -> Result<Vec<[f32; 4]>, ExtractError> {
    let needed = (count as usize) * 16;
    if raw.len() < needed {
        return Err(ExtractError::BufferOverflow {
            required: needed,
            available: raw.len(),
        });
    }
    let mut c = Cursor::new(raw);
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push([
            c.read_f32::<LittleEndian>()?,
            c.read_f32::<LittleEndian>()?,
            c.read_f32::<LittleEndian>()?,
            c.read_f32::<LittleEndian>()?,
        ]);
    }
    Ok(out)
}

fn compute_aabb_from_vertices(vertices: &[[f32; 3]]) -> ([f32; 3], [f32; 3]) {
    if vertices.is_empty() {
        return ([0.0; 3], [0.0; 3]);
    }
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for v in vertices {
        for i in 0..3 {
            min[i] = min[i].min(v[i]);
            max[i] = max[i].max(v[i]);
        }
    }
    (min, max)
}

fn parse_convex_elem(tags: &[FPropertyTag]) -> Result<ConvexHull, ExtractError> {
    let mut vertices = Vec::new();
    let mut permuted_planes = Vec::new();
    let mut edge_directions = Vec::new();
    let mut face_normals = Vec::new();
    let mut plane_equations = Vec::new();
    let mut elem_box: Option<([f32; 3], [f32; 3])> = None;

    for tag in tags {
        match tag.name.to_ascii_lowercase().as_str() {
            "vertexdata" => {
                if let PropertyValue::Array {
                    count,
                    raw_elements,
                } = &tag.value
                {
                    vertices = read_vec3_array(raw_elements, *count)?;
                }
            }
            "permutedvertexdata" => {
                if let PropertyValue::Array {
                    count,
                    raw_elements,
                } = &tag.value
                {
                    permuted_planes = read_fplane_array_raw(raw_elements, *count)?;
                }
            }
            "edgedirections" => {
                if let PropertyValue::Array {
                    count,
                    raw_elements,
                } = &tag.value
                {
                    edge_directions = read_vec3_array(raw_elements, *count)?;
                }
            }
            "facenormaldirections" => {
                if let PropertyValue::Array {
                    count,
                    raw_elements,
                } = &tag.value
                {
                    face_normals = read_vec3_array(raw_elements, *count)?;
                }
            }
            "faceplanedata" => {
                if let PropertyValue::Array {
                    count,
                    raw_elements,
                } = &tag.value
                {
                    // In Paladins UE3 v893, FacePlaneData stores FPlane as (W, X, Y, Z)
                    // representing X*x + Y*y + Z*z - W <= 0. Convert to [A, B, C, D] = [X, Y, Z, -W].
                    let raw_planes = read_fplane_array_raw(raw_elements, *count)?;
                    plane_equations = raw_planes
                        .into_iter()
                        .map(|[w, x, y, z]| [x, y, z, -w])
                        .collect();
                }
            }
            "elembox" => {
                if let PropertyValue::Struct {
                    data: StructValue::Box { min, max, is_valid },
                    ..
                } = &tag.value
                {
                    if *is_valid {
                        elem_box = Some((*min, *max));
                    }
                }
            }
            _ => {}
        }
    }

    let (aabb_min, aabb_max) = elem_box.unwrap_or_else(|| compute_aabb_from_vertices(&vertices));

    Ok(ConvexHull {
        vertices,
        permuted_planes,
        edge_directions,
        face_normals,
        plane_equations,
        aabb_min,
        aabb_max,
    })
}

fn extract_matrix_and_flags(tags: &[FPropertyTag]) -> ([[f32; 4]; 4], bool, bool) {
    let mut transform = IDENTITY_MATRIX;
    let mut no_rb_collision = false;
    let mut per_poly_shape = false;

    for tag in tags {
        match tag.name.to_ascii_lowercase().as_str() {
            "tm" => {
                if let PropertyValue::Struct {
                    data: StructValue::Matrix(m),
                    ..
                } = &tag.value
                {
                    transform = *m;
                }
            }
            "bnorbcollision" => {
                if let PropertyValue::Bool(b) = tag.value {
                    no_rb_collision = b;
                }
            }
            "bperpolyshape" => {
                if let PropertyValue::Bool(b) = tag.value {
                    per_poly_shape = b;
                }
            }
            _ => {}
        }
    }

    (transform, no_rb_collision, per_poly_shape)
}

fn parse_box_elem(tags: &[FPropertyTag]) -> BoxElem {
    let (transform, no_rb_collision, per_poly_shape) = extract_matrix_and_flags(tags);
    let mut x = 0.0;
    let mut y = 0.0;
    let mut z = 0.0;
    for tag in tags {
        if let PropertyValue::Float(v) = tag.value {
            match tag.name.to_ascii_lowercase().as_str() {
                "x" => x = v,
                "y" => y = v,
                "z" => z = v,
                _ => {}
            }
        }
    }
    BoxElem {
        transform,
        x,
        y,
        z,
        no_rb_collision,
        per_poly_shape,
    }
}

fn parse_sphere_elem(tags: &[FPropertyTag]) -> SphereElem {
    let (transform, no_rb_collision, per_poly_shape) = extract_matrix_and_flags(tags);
    let radius = tags
        .iter()
        .find_map(|t| match (&t.value, t.name.to_ascii_lowercase().as_str()) {
            (PropertyValue::Float(v), "radius") => Some(*v),
            _ => None,
        })
        .unwrap_or(0.0);
    SphereElem {
        transform,
        radius,
        no_rb_collision,
        per_poly_shape,
    }
}

fn parse_sphyl_elem(tags: &[FPropertyTag]) -> SphylElem {
    let (transform, no_rb_collision, per_poly_shape) = extract_matrix_and_flags(tags);
    let mut radius = 0.0;
    let mut length = 0.0;
    for tag in tags {
        if let PropertyValue::Float(v) = tag.value {
            match tag.name.to_ascii_lowercase().as_str() {
                "radius" => radius = v,
                "length" => length = v,
                _ => {}
            }
        }
    }
    SphylElem {
        transform,
        radius,
        length,
        no_rb_collision,
        per_poly_shape,
    }
}

/// Parses an `AggregateGeometry` from the tagged properties of a `KAggregateGeom` struct.
pub fn parse_aggregate_geom(
    agg_tags: &[FPropertyTag],
    name_table: &NameTable,
) -> Result<AggregateGeometry, ExtractError> {
    let mut geom = AggregateGeometry::default();

    for tag in agg_tags {
        match tag.name.to_ascii_lowercase().as_str() {
            "convexelems" => {
                for elem_tags in tag.parse_struct_array(name_table)? {
                    geom.convex_hulls.push(parse_convex_elem(&elem_tags)?);
                }
            }
            "boxelems" => {
                for elem_tags in tag.parse_struct_array(name_table)? {
                    geom.boxes.push(parse_box_elem(&elem_tags));
                }
            }
            "sphereelems" => {
                for elem_tags in tag.parse_struct_array(name_table)? {
                    geom.spheres.push(parse_sphere_elem(&elem_tags));
                }
            }
            "sphylelems" => {
                for elem_tags in tag.parse_struct_array(name_table)? {
                    geom.sphyls.push(parse_sphyl_elem(&elem_tags));
                }
            }
            _ => {}
        }
    }

    Ok(geom)
}

fn extract_from_object_tags(
    tags: &[FPropertyTag],
    prop_name: &str,
    name_table: &NameTable,
) -> Result<AggregateGeometry, ExtractError> {
    let Some(prop) = find_property(tags, prop_name) else {
        return Ok(AggregateGeometry::default());
    };
    let Some(agg_tags) = prop.as_tagged_struct() else {
        return Err(ExtractError::InvalidCollision {
            reason: format!("Property '{prop_name}' is not a tagged KAggregateGeom struct"),
        });
    };
    parse_aggregate_geom(agg_tags, name_table)
}

/// Extracts `AggregateGeometry` from a serialized `UBrushComponent` export (`BrushAggGeom`).
pub fn extract_brush_component_collision(
    raw_export: &[u8],
    name_table: &NameTable,
) -> Result<AggregateGeometry, ExtractError> {
    let (_, tags, _) = read_object_properties(raw_export, name_table, true)?;
    extract_from_object_tags(&tags, "BrushAggGeom", name_table)
}

/// Extracts `AggregateGeometry` from a serialized `URB_BodySetup` export (`AggGeom`).
pub fn extract_body_setup_collision(
    raw_export: &[u8],
    name_table: &NameTable,
) -> Result<AggregateGeometry, ExtractError> {
    let (_, tags, _) = read_object_properties(raw_export, name_table, false)?;
    extract_from_object_tags(&tags, "AggGeom", name_table)
}

/// Extracts all `BrushComponent` and `RB_BodySetup` collision geometries from a UPK package.
pub fn extract_package_collision<R: Read + Seek>(
    package: &mut UpkPackage<R>,
) -> Result<Vec<CollisionExport>, ExtractError> {
    let (name_table, import_table, export_table) = package.read_tables()?;
    let mut results = Vec::new();

    for (idx, exp) in export_table.entries().iter().enumerate() {
        let Some(class_name) =
            exp.resolve_class_name(&name_table, &import_table, &export_table)
        else {
            continue;
        };

        let lower = class_name.to_ascii_lowercase();
        if lower != "brushcomponent" && lower != "rb_bodysetup" {
            continue;
        }

        let raw = package.read_export_data(exp)?;
        let geometry = if lower == "brushcomponent" {
            extract_brush_component_collision(&raw, &name_table)?
        } else {
            extract_body_setup_collision(&raw, &name_table)?
        };

        let object_name = exp
            .resolve_object_name(&name_table)
            .unwrap_or_else(|| format!("Export_{idx}"));
        let full_path = package.resolve_full_path(
            &name_table,
            &import_table,
            &export_table,
            PackageIndex::from_export_index(idx),
        );

        results.push(CollisionExport {
            export_index: idx,
            class_name,
            object_name,
            full_path,
            geometry,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::NameEntry;
    use byteorder::WriteBytesExt;

    fn write_fname(buf: &mut Vec<u8>, idx: i32) {
        buf.write_i32::<LittleEndian>(idx).unwrap();
        buf.write_i32::<LittleEndian>(0).unwrap();
    }

    fn build_synthetic_brush_component_payload() -> (NameTable, Vec<u8>) {
        // Box [0, 100] x [-50, 50] x [0, 200]
        let names = NameTable::new(vec![
            NameEntry::new("None", 0),                 // 0
            NameEntry::new("StructProperty", 0),       // 1
            NameEntry::new("ArrayProperty", 0),        // 2
            NameEntry::new("FloatProperty", 0),        // 3
            NameEntry::new("BoolProperty", 0),         // 4
            NameEntry::new("BrushAggGeom", 0),         // 5
            NameEntry::new("KAggregateGeom", 0),       // 6
            NameEntry::new("ConvexElems", 0),          // 7
            NameEntry::new("VertexData", 0),           // 8
            NameEntry::new("PermutedVertexData", 0),   // 9
            NameEntry::new("EdgeDirections", 0),       // 10
            NameEntry::new("FaceNormalDirections", 0), // 11
            NameEntry::new("FacePlaneData", 0),        // 12
            NameEntry::new("ElemBox", 0),              // 13
            NameEntry::new("Box", 0),                  // 14
            NameEntry::new("SphereElems", 0),          // 15
            NameEntry::new("TM", 0),                   // 16
            NameEntry::new("Matrix", 0),               // 17
            NameEntry::new("Radius", 0),               // 18
        ]);

        // Build one ConvexElem
        let mut convex_elem = Vec::new();
        let verts: [[f32; 3]; 8] = [
            [0.0, -50.0, 0.0],
            [100.0, -50.0, 0.0],
            [100.0, 50.0, 0.0],
            [0.0, 50.0, 0.0],
            [0.0, -50.0, 200.0],
            [100.0, -50.0, 200.0],
            [100.0, 50.0, 200.0],
            [0.0, 50.0, 200.0],
        ];
        write_fname(&mut convex_elem, 8); // VertexData
        write_fname(&mut convex_elem, 2); // ArrayProperty
        convex_elem.write_u32::<LittleEndian>(4 + 8 * 12).unwrap();
        convex_elem.write_u32::<LittleEndian>(0).unwrap();
        convex_elem.write_u32::<LittleEndian>(8).unwrap();
        for v in &verts {
            for &c in v {
                convex_elem.write_f32::<LittleEndian>(c).unwrap();
            }
        }

        // FacePlaneData in UE3 v893 (W, X, Y, Z)
        let planes_wxyz: [[f32; 4]; 6] = [
            [100.0, 1.0, 0.0, 0.0], // x <= 100
            [0.0, -1.0, 0.0, 0.0],  // x >= 0
            [50.0, 0.0, 1.0, 0.0],  // y <= 50
            [50.0, 0.0, -1.0, 0.0], // y >= -50
            [200.0, 0.0, 0.0, 1.0], // z <= 200
            [0.0, 0.0, 0.0, -1.0],  // z >= 0
        ];
        write_fname(&mut convex_elem, 12); // FacePlaneData
        write_fname(&mut convex_elem, 2);
        convex_elem.write_u32::<LittleEndian>(4 + 6 * 16).unwrap();
        convex_elem.write_u32::<LittleEndian>(0).unwrap();
        convex_elem.write_u32::<LittleEndian>(6).unwrap();
        for p in &planes_wxyz {
            for &c in p {
                convex_elem.write_f32::<LittleEndian>(c).unwrap();
            }
        }

        // EdgeDirections
        write_fname(&mut convex_elem, 10);
        write_fname(&mut convex_elem, 2);
        convex_elem.write_u32::<LittleEndian>(4 + 3 * 12).unwrap();
        convex_elem.write_u32::<LittleEndian>(0).unwrap();
        convex_elem.write_u32::<LittleEndian>(3).unwrap();
        for d in [[1.0f32, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]] {
            for c in d {
                convex_elem.write_f32::<LittleEndian>(c).unwrap();
            }
        }

        // ElemBox
        write_fname(&mut convex_elem, 13);
        write_fname(&mut convex_elem, 1);
        convex_elem.write_u32::<LittleEndian>(25).unwrap();
        convex_elem.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut convex_elem, 14); // Box
        for c in [0.0f32, -50.0, 0.0, 100.0, 50.0, 200.0] {
            convex_elem.write_f32::<LittleEndian>(c).unwrap();
        }
        convex_elem.write_u8(1).unwrap();
        write_fname(&mut convex_elem, 0); // None

        // Build SphereElem
        let mut sphere_elem = Vec::new();
        write_fname(&mut sphere_elem, 16); // TM
        write_fname(&mut sphere_elem, 1);
        sphere_elem.write_u32::<LittleEndian>(64).unwrap();
        sphere_elem.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut sphere_elem, 17); // Matrix
        // 4 FPlanes (W, X, Y, Z) with translation (500, 0, 50)
        for p in [
            [0.0f32, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
            [1.0, 500.0, 0.0, 50.0],
        ] {
            for c in p {
                sphere_elem.write_f32::<LittleEndian>(c).unwrap();
            }
        }
        write_fname(&mut sphere_elem, 18); // Radius
        write_fname(&mut sphere_elem, 3);
        sphere_elem.write_u32::<LittleEndian>(4).unwrap();
        sphere_elem.write_u32::<LittleEndian>(0).unwrap();
        sphere_elem.write_f32::<LittleEndian>(25.0).unwrap();
        write_fname(&mut sphere_elem, 0);

        // KAggregateGeom body
        let mut agg = Vec::new();
        write_fname(&mut agg, 7); // ConvexElems
        write_fname(&mut agg, 2);
        agg.write_u32::<LittleEndian>(4 + convex_elem.len() as u32)
            .unwrap();
        agg.write_u32::<LittleEndian>(0).unwrap();
        agg.write_u32::<LittleEndian>(1).unwrap();
        agg.extend_from_slice(&convex_elem);

        write_fname(&mut agg, 15); // SphereElems
        write_fname(&mut agg, 2);
        agg.write_u32::<LittleEndian>(4 + sphere_elem.len() as u32)
            .unwrap();
        agg.write_u32::<LittleEndian>(0).unwrap();
        agg.write_u32::<LittleEndian>(1).unwrap();
        agg.extend_from_slice(&sphere_elem);
        write_fname(&mut agg, 0); // None

        // Full BrushComponent export
        let mut export = Vec::new();
        export.write_i32::<LittleEndian>(0).unwrap(); // TemplateOwnerClass
        export.write_i32::<LittleEndian>(1).unwrap(); // NetIndex
        write_fname(&mut export, 5); // BrushAggGeom
        write_fname(&mut export, 1);
        export.write_u32::<LittleEndian>(agg.len() as u32).unwrap();
        export.write_u32::<LittleEndian>(0).unwrap();
        write_fname(&mut export, 6); // KAggregateGeom
        export.extend_from_slice(&agg);
        write_fname(&mut export, 0); // None

        (names, export)
    }

    #[test]
    fn test_synthetic_brush_component_collision_closure_and_sat_queries() {
        let (names, payload) = build_synthetic_brush_component_payload();
        let geom = extract_brush_component_collision(&payload, &names).unwrap();

        assert_eq!(geom.convex_hulls.len(), 1);
        assert_eq!(geom.spheres.len(), 1);
        assert!(geom.validate_closure(1e-4));

        let hull = &geom.convex_hulls[0];
        assert_eq!(hull.aabb_min, [0.0, -50.0, 0.0]);
        assert_eq!(hull.aabb_max, [100.0, 50.0, 200.0]);
        assert!(hull.contains_point([50.0, 0.0, 100.0], 1e-4));
        assert!(!hull.contains_point([101.0, 0.0, 100.0], 1e-4));

        // Raycast from X = 250 toward X = 100 wall plane
        let hit = geom
            .raycast([250.0, 0.0, 100.0], [-1.0, 0.0, 0.0], 500.0)
            .expect("Expected raycast hit on X=100 wall plane");
        assert!((hit.distance - 150.0).abs() < 1e-4);
        assert!((hit.point[0] - 100.0).abs() < 1e-4);
        assert_eq!(hit.normal, [1.0, 0.0, 0.0]);

        // Sphere sweep of radius 10 hits at X = 110 (distance 140)
        let sweep_hit = geom
            .sphere_sweep([250.0, 0.0, 100.0], [-1.0, 0.0, 0.0], 10.0, 500.0)
            .expect("Expected sphere sweep hit");
        assert!((sweep_hit.distance - 140.0).abs() < 1e-4);
        assert!((sweep_hit.point[0] - 110.0).abs() < 1e-4);

        // SAT AABB intersection
        assert!(hull.intersects_aabb([95.0, -10.0, 10.0], [120.0, 10.0, 30.0]));
        assert!(!hull.intersects_aabb([105.0, -10.0, 10.0], [120.0, 10.0, 30.0]));

        // Sphere containment & raycast at (500, 0, 50), r=25
        assert!(geom.contains_point([510.0, 0.0, 50.0], 1e-4));
        let sphere_hit = geom
            .raycast([600.0, 0.0, 50.0], [-1.0, 0.0, 0.0], 200.0)
            .expect("Expected sphere hit");
        assert!((sphere_hit.point[0] - 525.0).abs() < 1e-4);
    }

    #[test]
    fn test_hull_closure_detects_invalid_open_plane() {
        let hull = ConvexHull {
            vertices: vec![[0.0, 0.0, 0.0], [10.0, 10.0, 10.0]],
            permuted_planes: vec![],
            edge_directions: vec![],
            face_normals: vec![],
            plane_equations: vec![[1.0, 0.0, 0.0, -5.0]], // x <= 5 violates x=10 by +5
            aabb_min: [0.0, 0.0, 0.0],
            aabb_max: [10.0, 10.0, 10.0],
        };
        assert!(!hull.validate_closure(0.1));
        assert!((hull.max_plane_violation() - 5.0).abs() < 1e-5);
    }
}
