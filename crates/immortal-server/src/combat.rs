// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Server-Authoritative Combat & Dual-Stage Hitbox Engine (`ADOPT-02`)
//! Cleanroom implementation of `OBL-COMBAT-001` (`SPEC-TEMPEST-ADOPT-2026-01`):
//! - Stage 1: Upright `CylinderComponent` (`CollisionRadius`, `CollisionHeight`) ray/sphere check.
//! - Stage 2: Secondary `b_head` sphere headshot check gated on Stage 1 intersection, with
//!   skin hitbox normalization clamping cosmetic/animation head displacements inside the
//!   canonical cylinder bounds.
//! - Fernando ability collision & damage math (`TgDevice_FlameThrower`, `TgDevice_Shield`,
//!   `TgDevice_Fireball`, `TgDevice_Charge`, `TgDevice_Immortal`).

use immortal_core::ChampionId;

/// Canonical UE3 skeletal head bone name queried during Stage 2 headshot checks.
pub const HEAD_BONE_NAME: &str = "b_head";

/// Fernando Flame Lance (`TgDevice_FlameThrower`) cone length in Unreal Units.
pub const FLAME_LANCE_RANGE_UU: f32 = 1200.0;
/// Fernando Flame Lance cone half-angle in degrees.
pub const FLAME_LANCE_HALF_ANGLE_DEG: f32 = 15.0;
/// Fernando Flame Lance base damage per tick (`0.1s` tick interval).
pub const FLAME_LANCE_TICK_DAMAGE: f32 = 35.0;
/// Fernando Flame Lance tick interval in seconds.
pub const FLAME_LANCE_TICK_INTERVAL_SEC: f32 = 0.1;

/// Fernando Shield (`TgDevice_Shield`) pool in HP.
pub const SHIELD_MAX_HP: f32 = 4000.0;
/// Fernando Shield planar barrier width in Unreal Units.
pub const SHIELD_WIDTH_UU: f32 = 400.0;
/// Fernando Shield planar barrier height in Unreal Units.
pub const SHIELD_HEIGHT_UU: f32 = 300.0;

/// Fernando Fireball (`TgDevice_Fireball`) sphere sweep radius in Unreal Units.
pub const FIREBALL_RADIUS_UU: f32 = 40.0;
/// Fernando Fireball linear velocity in Unreal Units per second.
pub const FIREBALL_VELOCITY_UU_PER_SEC: f32 = 3500.0;
/// Fernando Fireball damage multiplier increase per subsequent champion pierced (+20%).
pub const FIREBALL_PIERCE_BONUS_RATIO: f32 = 0.20;

/// Fernando Charge (`TgDevice_Charge`) movement speed in Unreal Units per second.
pub const CHARGE_SPEED_UU_PER_SEC: f32 = 1500.0;
/// Fernando Charge impact damage on first champion struck.
pub const CHARGE_DAMAGE: f32 = 200.0;

/// Fernando Immortal (`TgDevice_Immortal`) spherical aura radius in Unreal Units.
pub const IMMORTAL_AURA_RADIUS_UU: f32 = 600.0;
/// Fernando Immortal minimum health clamp floor in HP.
pub const IMMORTAL_MIN_HEALTH_FLOOR: f32 = 1500.0;
/// Fernando Immortal active duration in seconds.
pub const IMMORTAL_DURATION_SEC: f32 = 4.0;

/// Result of a dual-stage weapon raycast or swept-sphere hit evaluation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HitResult {
    pub struck: bool,
    pub hit_location: [f32; 3],
    pub is_headshot: bool,
}

impl HitResult {
    /// Returns a canonical miss result.
    pub const fn miss() -> Self {
        Self {
            struck: false,
            hit_location: [0.0, 0.0, 0.0],
            is_headshot: false,
        }
    }
}

/// Upright vertical cylinder capsule (`UE3 CylinderComponent`) rooted at `base` (`+Z` up).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CylinderHitbox {
    /// Bottom center `(x, y, z_min)` of the cylinder in Unreal Units.
    pub base: [f32; 3],
    /// Horizontal collision radius `R` in Unreal Units.
    pub radius: f32,
    /// Vertical cylinder height `H` in Unreal Units (`z_max = base[2] + height`).
    pub height: f32,
}

impl CylinderHitbox {
    /// Constructs a cylinder hitbox from bottom-center `base`, `radius`, and `height`.
    pub fn new(base: [f32; 3], radius: f32, height: f32) -> Self {
        Self {
            base,
            radius: radius.max(0.0),
            height: height.max(0.0),
        }
    }

    /// Constructs a cylinder hitbox from geometric `center`, `radius`, and `half_height`.
    pub fn from_center(center: [f32; 3], radius: f32, half_height: f32) -> Self {
        let hh = half_height.max(0.0);
        Self::new([center[0], center[1], center[2] - hh], radius, hh * 2.0)
    }

    /// Returns the geometric center of the cylinder.
    pub fn center(&self) -> [f32; 3] {
        [self.base[0], self.base[1], self.base[2] + self.height * 0.5]
    }

    /// Returns the earliest non-negative intersection `(distance, point)` of ray `origin + t * dir`
    /// with this finite upright cylinder, where `dir` does not need to be pre-normalized.
    pub fn intersect_ray(&self, origin: [f32; 3], dir: [f32; 3]) -> Option<(f32, [f32; 3])> {
        let dir = normalize3(dir)?;
        intersect_ray_vertical_cylinder(origin, dir, self.base, self.radius, self.height)
    }

    /// Tests a swept sphere of `sweep_radius` along ray `origin + t * dir` against this cylinder
    /// via Minkowski expansion `(radius + sweep_radius, height + 2 * sweep_radius)`.
    pub fn intersect_swept_sphere(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        sweep_radius: f32,
    ) -> Option<(f32, [f32; 3])> {
        let dir = normalize3(dir)?;
        let r = sweep_radius.max(0.0);
        let expanded_base = [self.base[0], self.base[1], self.base[2] - r];
        intersect_ray_vertical_cylinder(
            origin,
            dir,
            expanded_base,
            self.radius + r,
            self.height + 2.0 * r,
        )
    }
}

/// Skeletal head sphere (`PhysicsAsset` `b_head` bone) tested only after Stage 1 cylinder hit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeadHitbox {
    pub bone_name: &'static str,
    pub center: [f32; 3],
    pub radius: f32,
}

impl HeadHitbox {
    /// Creates a head sphere centered at `center` with `radius` for `b_head`.
    pub fn new(center: [f32; 3], radius: f32) -> Self {
        Self {
            bone_name: HEAD_BONE_NAME,
            center,
            radius: radius.max(0.0),
        }
    }

    /// Returns the earliest non-negative intersection `(distance, point)` against this sphere.
    pub fn intersect_ray(&self, origin: [f32; 3], dir: [f32; 3]) -> Option<(f32, [f32; 3])> {
        let dir = normalize3(dir)?;
        intersect_ray_sphere(origin, dir, self.center, self.radius)
    }
}

/// Authoritative champion hitbox combining the Stage 1 cylinder and normalized Stage 2 `b_head`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TargetHitbox {
    pub champion_id: ChampionId,
    pub cylinder: CylinderHitbox,
    pub head: HeadHitbox,
}

impl TargetHitbox {
    /// Creates a `TargetHitbox` and normalizes `raw_head` inside `cylinder` bounds so cosmetic
    /// accessories or extreme animations cannot displace `b_head` outside the hit envelope.
    pub fn new_normalized(
        champion_id: ChampionId,
        cylinder: CylinderHitbox,
        raw_head: HeadHitbox,
    ) -> Self {
        let head = normalize_head_to_cylinder(&cylinder, raw_head);
        Self {
            champion_id,
            cylinder,
            head,
        }
    }

    /// Evaluates a hitscan ray against this target using the two-stage hitbox model.
    ///
    /// `headshot_tolerance` bounds how far deeper than the cylinder shell entry `b_head` may lie
    /// (defaults to `cylinder.radius + 1.0`, allowing horizontal headshots through the cylinder
    /// while preventing upward shots entering through the feet/torso from promoting to headshots).
    pub fn evaluate_ray_hit(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        headshot_tolerance: Option<f32>,
    ) -> HitResult {
        self.evaluate_swept_sphere_hit(origin, dir, 0.0, headshot_tolerance)
    }

    /// Evaluates a swept-sphere projectile trace `(origin, dir, sweep_radius)` against this target.
    pub fn evaluate_swept_sphere_hit(
        &self,
        origin: [f32; 3],
        dir: [f32; 3],
        sweep_radius: f32,
        headshot_tolerance: Option<f32>,
    ) -> HitResult {
        let Some(unit_dir) = normalize3(dir) else {
            return HitResult::miss();
        };
        let Some((cyl_dist, cyl_hit)) =
            self.cylinder.intersect_swept_sphere(origin, unit_dir, sweep_radius)
        else {
            return HitResult::miss();
        };

        let tolerance = headshot_tolerance.unwrap_or(self.cylinder.radius + 1.0);
        let effective_head_r = self.head.radius + sweep_radius.max(0.0);
        if let Some((head_dist, head_hit)) =
            intersect_ray_sphere(origin, unit_dir, self.head.center, effective_head_r)
        {
            if head_dist <= cyl_dist + tolerance {
                return HitResult {
                    struck: true,
                    hit_location: head_hit,
                    is_headshot: true,
                };
            }
        }

        HitResult {
            struck: true,
            hit_location: cyl_hit,
            is_headshot: false,
        }
    }
}

/// Normalizes a raw skeletal `b_head` sphere to reside strictly inside `cylinder` bounds,
/// eliminating skin/cosmetic pay-to-win or pay-to-lose hitbox artifacts.
pub fn normalize_head_to_cylinder(cylinder: &CylinderHitbox, raw_head: HeadHitbox) -> HeadHitbox {
    let max_head_r = (cylinder.radius * 0.6).max(1.0).min(cylinder.radius);
    let clamped_r = raw_head.radius.clamp(1.0_f32.min(max_head_r), max_head_r);

    let dx = raw_head.center[0] - cylinder.base[0];
    let dy = raw_head.center[1] - cylinder.base[1];
    let dist_xy = (dx * dx + dy * dy).sqrt();
    let max_xy_offset = (cylinder.radius - clamped_r).max(0.0);
    let (nx, ny) = if dist_xy > max_xy_offset && dist_xy > f32::EPSILON {
        let scale = max_xy_offset / dist_xy;
        (cylinder.base[0] + dx * scale, cylinder.base[1] + dy * scale)
    } else {
        (raw_head.center[0], raw_head.center[1])
    };

    let min_z = cylinder.base[2] + clamped_r;
    let max_z = cylinder.base[2] + cylinder.height - clamped_r;
    let nz = if min_z <= max_z {
        raw_head.center[2].clamp(min_z, max_z)
    } else {
        cylinder.base[2] + cylinder.height * 0.5
    };

    HeadHitbox::new([nx, ny, nz], clamped_r)
}

/// Checks whether a target cylinder falls inside Fernando's Flame Lance cone
/// (`1200 UU` length, `15°` half-angle).
pub fn evaluate_flame_lance_cone(
    origin: [f32; 3],
    forward: [f32; 3],
    target: &CylinderHitbox,
) -> bool {
    let Some(fwd) = normalize3(forward) else {
        return false;
    };
    let target_center = target.center();
    let clamped_z = origin[2].clamp(target.base[2], target.base[2] + target.height);
    let sample_point = [target_center[0], target_center[1], clamped_z];
    let to_target = sub3(sample_point, origin);
    let dist = len3(to_target);
    if dist > FLAME_LANCE_RANGE_UU + target.radius {
        return false;
    }
    if dist <= target.radius {
        return true;
    }

    let cos_half_angle = FLAME_LANCE_HALF_ANGLE_DEG.to_radians().cos();
    let dir_to_target = scale3(to_target, 1.0 / dist);
    let center_cos = dot3(fwd, dir_to_target);
    if center_cos >= cos_half_angle {
        return true;
    }

    // Account for target cylinder radius subtended angular half-width at `dist`.
    let angular_margin = (target.radius / dist).min(1.0).asin();
    let center_angle = center_cos.clamp(-1.0, 1.0).acos();
    center_angle <= FLAME_LANCE_HALF_ANGLE_DEG.to_radians() + angular_margin
}

/// Outcome of an incoming trace/projectile hitting or missing Fernando's Shield Barrier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ShieldInterceptResult {
    pub intercepted: bool,
    pub hit_location: [f32; 3],
    pub absorbed_damage: f32,
    pub remaining_shield_hp: f32,
    pub shield_broken: bool,
}

/// Directional planar shield barrier (`TgDevice_Shield`: `400 x 300 UU`, `4000 HP`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ShieldBarrier {
    pub center: [f32; 3],
    pub forward: [f32; 3],
    pub right: [f32; 3],
    pub up: [f32; 3],
    pub half_width: f32,
    pub half_height: f32,
    pub health: f32,
    pub max_health: f32,
}

impl ShieldBarrier {
    /// Creates Fernando's canonical `400 x 300 UU`, `4000 HP` shield barrier facing `forward`.
    pub fn new_fernando(center: [f32; 3], forward: [f32; 3]) -> Option<Self> {
        let fwd = normalize3(forward)?;
        let world_up = if fwd[2].abs() < 0.99 {
            [0.0, 0.0, 1.0]
        } else {
            [0.0, 1.0, 0.0]
        };
        let right = normalize3(cross3(fwd, world_up))?;
        let up = normalize3(cross3(right, fwd))?;
        Some(Self {
            center,
            forward: fwd,
            right,
            up,
            half_width: SHIELD_WIDTH_UU * 0.5,
            half_height: SHIELD_HEIGHT_UU * 0.5,
            health: SHIELD_MAX_HP,
            max_health: SHIELD_MAX_HP,
        })
    }

    /// Tests whether an incoming ray intercepts the active shield plane and subtracts
    /// `incoming_damage` from the `4000 HP` pool with zero bleed-through to Fernando.
    pub fn intercept_ray(
        &mut self,
        origin: [f32; 3],
        dir: [f32; 3],
        incoming_damage: f32,
    ) -> ShieldInterceptResult {
        if self.health <= 0.0 {
            return ShieldInterceptResult {
                intercepted: false,
                hit_location: [0.0; 3],
                absorbed_damage: 0.0,
                remaining_shield_hp: 0.0,
                shield_broken: true,
            };
        }
        let Some(unit_dir) = normalize3(dir) else {
            return ShieldInterceptResult {
                intercepted: false,
                hit_location: [0.0; 3],
                absorbed_damage: 0.0,
                remaining_shield_hp: self.health,
                shield_broken: false,
            };
        };

        let denom = dot3(unit_dir, self.forward);
        if denom.abs() < 1e-6 {
            return ShieldInterceptResult {
                intercepted: false,
                hit_location: [0.0; 3],
                absorbed_damage: 0.0,
                remaining_shield_hp: self.health,
                shield_broken: false,
            };
        }

        let t = dot3(sub3(self.center, origin), self.forward) / denom;
        if t < 0.0 {
            return ShieldInterceptResult {
                intercepted: false,
                hit_location: [0.0; 3],
                absorbed_damage: 0.0,
                remaining_shield_hp: self.health,
                shield_broken: false,
            };
        }

        let hit = add3(origin, scale3(unit_dir, t));
        let rel = sub3(hit, self.center);
        let u = dot3(rel, self.right);
        let v = dot3(rel, self.up);
        if u.abs() > self.half_width || v.abs() > self.half_height {
            return ShieldInterceptResult {
                intercepted: false,
                hit_location: [0.0; 3],
                absorbed_damage: 0.0,
                remaining_shield_hp: self.health,
                shield_broken: false,
            };
        }

        // Zero bleed-through: shield absorbs the full hit even if damage exceeds remaining HP.
        let dmg = incoming_damage.max(0.0);
        self.health = (self.health - dmg).max(0.0);
        ShieldInterceptResult {
            intercepted: true,
            hit_location: hit,
            absorbed_damage: dmg,
            remaining_shield_hp: self.health,
            shield_broken: self.health <= 0.0,
        }
    }
}

/// Computes Fernando Fireball damage for target `pierce_index` (`0`-based), scaling `+20%`
/// per subsequent champion pierced.
#[inline]
pub fn fireball_pierce_damage(base_damage: f32, pierce_index: usize) -> f32 {
    base_damage.max(0.0) * (1.0 + FIREBALL_PIERCE_BONUS_RATIO * (pierce_index as f32))
}

/// Sweeps Fernando's Fireball (`radius = 40 UU`) along `origin + t * dir` up to `max_distance`,
/// piercing all struck targets in ascending distance order with `+20%` per-pierce damage scaling.
pub fn evaluate_fireball_sweep(
    origin: [f32; 3],
    dir: [f32; 3],
    max_distance: f32,
    targets: &[TargetHitbox],
    base_damage: f32,
) -> Vec<(usize, f32, HitResult)> {
    let Some(unit_dir) = normalize3(dir) else {
        return Vec::new();
    };
    let mut hits: Vec<(usize, f32, HitResult)> = Vec::new();
    for (idx, target) in targets.iter().enumerate() {
        if let Some((dist, _)) =
            target
                .cylinder
                .intersect_swept_sphere(origin, unit_dir, FIREBALL_RADIUS_UU)
        {
            if dist <= max_distance {
                let res =
                    target.evaluate_swept_sphere_hit(origin, unit_dir, FIREBALL_RADIUS_UU, None);
                if res.struck {
                    hits.push((idx, dist, res));
                }
            }
        }
    }
    hits.sort_by(|a, b| a.1.total_cmp(&b.1));
    hits.into_iter()
        .enumerate()
        .map(|(pierce_idx, (target_idx, _dist, res))| {
            (
                target_idx,
                fireball_pierce_damage(base_damage, pierce_idx),
                res,
            )
        })
        .collect()
}

/// Result of Fernando's Charge (`TgDevice_Charge`) capsule sweep along a dash vector.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChargeSweepResult {
    pub struck_target_index: Option<usize>,
    pub damage: f32,
    pub hit_location: [f32; 3],
}

/// Sweeps Fernando's Charge capsule (`pawn_radius`) along `origin + t * dir` up to `max_distance`,
/// returning the first champion struck (`200` damage).
pub fn evaluate_charge_sweep(
    origin: [f32; 3],
    dir: [f32; 3],
    max_distance: f32,
    pawn_radius: f32,
    targets: &[TargetHitbox],
) -> ChargeSweepResult {
    let Some(unit_dir) = normalize3(dir) else {
        return ChargeSweepResult {
            struck_target_index: None,
            damage: 0.0,
            hit_location: [0.0; 3],
        };
    };
    let mut best: Option<(usize, f32, [f32; 3])> = None;
    for (idx, target) in targets.iter().enumerate() {
        if let Some((dist, hit_loc)) =
            target
                .cylinder
                .intersect_swept_sphere(origin, unit_dir, pawn_radius.max(0.0))
        {
            if dist <= max_distance && best.is_none_or(|(_, best_d, _)| dist < best_d) {
                best = Some((idx, dist, hit_loc));
            }
        }
    }

    match best {
        Some((idx, _, hit_location)) => ChargeSweepResult {
            struck_target_index: Some(idx),
            damage: CHARGE_DAMAGE,
            hit_location,
        },
        None => ChargeSweepResult {
            struck_target_index: None,
            damage: 0.0,
            hit_location: [0.0; 3],
        },
    }
}

/// Clamps an ally's health during Fernando's Immortal (`TgDevice_Immortal`) aura when within
/// `600 UU` of `aura_center`.
pub fn apply_immortal_aura_clamp(
    aura_center: [f32; 3],
    target_pos: [f32; 3],
    current_hp: f32,
    max_hp: f32,
) -> f32 {
    let dist = len3(sub3(target_pos, aura_center));
    if dist <= IMMORTAL_AURA_RADIUS_UU {
        current_hp.max(IMMORTAL_MIN_HEALTH_FLOOR.min(max_hp))
    } else {
        current_hp
    }
}

fn intersect_ray_vertical_cylinder(
    origin: [f32; 3],
    dir: [f32; 3],
    base: [f32; 3],
    radius: f32,
    height: f32,
) -> Option<(f32, [f32; 3])> {
    let z_min = base[2];
    let z_max = base[2] + height;
    let ox = origin[0] - base[0];
    let oy = origin[1] - base[1];
    let dx = dir[0];
    let dy = dir[1];

    let mut best_t: Option<f32> = None;
    let mut record = |t: f32| {
        if t >= 0.0 && best_t.is_none_or(|b| t < b) {
            best_t = Some(t);
        }
    };

    // 1. Curved side wall: (ox + t*dx)^2 + (oy + t*dy)^2 = radius^2
    let a = dx * dx + dy * dy;
    let r2 = radius * radius;
    if a > 1e-8 {
        let b = 2.0 * (ox * dx + oy * dy);
        let c = ox * ox + oy * oy - r2;
        let disc = b * b - 4.0 * a * c;
        if disc >= 0.0 {
            let sqrt_d = disc.sqrt();
            let inv_2a = 0.5 / a;
            for t in [(-b - sqrt_d) * inv_2a, (-b + sqrt_d) * inv_2a] {
                if t >= 0.0 {
                    let z = origin[2] + t * dir[2];
                    if z >= z_min && z <= z_max {
                        record(t);
                    }
                }
            }
        }
    }

    // 2. Bottom and top circular caps: z = z_min and z = z_max
    if dir[2].abs() > 1e-8 {
        for z_cap in [z_min, z_max] {
            let t = (z_cap - origin[2]) / dir[2];
            if t >= 0.0 {
                let x = ox + t * dx;
                let y = oy + t * dy;
                if x * x + y * y <= r2 + 1e-4 {
                    record(t);
                }
            }
        }
    }

    best_t.map(|t| (t, add3(origin, scale3(dir, t))))
}

fn intersect_ray_sphere(
    origin: [f32; 3],
    dir: [f32; 3],
    center: [f32; 3],
    radius: f32,
) -> Option<(f32, [f32; 3])> {
    let oc = sub3(origin, center);
    let b = dot3(oc, dir);
    let c = dot3(oc, oc) - radius * radius;
    let disc = b * b - c;
    if disc < 0.0 {
        return None;
    }
    let sqrt_d = disc.sqrt();
    let t0 = -b - sqrt_d;
    let t1 = -b + sqrt_d;
    let t = if t0 >= 0.0 {
        t0
    } else if t1 >= 0.0 {
        t1
    } else {
        return None;
    };
    Some((t, add3(origin, scale3(dir, t))))
}

#[inline]
fn sub3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

#[inline]
fn add3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

#[inline]
fn scale3(v: [f32; 3], s: f32) -> [f32; 3] {
    [v[0] * s, v[1] * s, v[2] * s]
}

#[inline]
fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
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

fn normalize3(v: [f32; 3]) -> Option<[f32; 3]> {
    let len = len3(v);
    if !len.is_finite() || len <= 1e-8 {
        None
    } else {
        Some(scale3(v, 1.0 / len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fernando_target() -> TargetHitbox {
        let cyl = CylinderHitbox::new([0.0, 0.0, 0.0], 42.0, 176.0);
        let head = HeadHitbox::new([0.0, 0.0, 150.0], 16.0);
        TargetHitbox::new_normalized(ChampionId::Fernando, cyl, head)
    }

    #[test]
    fn test_dual_stage_ray_misses_cylinder() {
        let target = sample_fernando_target();
        let res = target.evaluate_ray_hit([-200.0, 80.0, 90.0], [1.0, 0.0, 0.0], None);
        assert!(!res.struck);
        assert!(!res.is_headshot);
    }

    #[test]
    fn test_dual_stage_chest_hit_is_body_shot() {
        let target = sample_fernando_target();
        let res = target.evaluate_ray_hit([-200.0, 0.0, 90.0], [1.0, 0.0, 0.0], None);
        assert!(res.struck);
        assert!(!res.is_headshot);
        assert!((res.hit_location[0] - (-42.0)).abs() < 1e-3);
        assert!((res.hit_location[2] - 90.0).abs() < 1e-3);
    }

    #[test]
    fn test_dual_stage_head_bone_hit_promotes_to_headshot() {
        let target = sample_fernando_target();
        let res = target.evaluate_ray_hit([-200.0, 0.0, 150.0], [1.0, 0.0, 0.0], None);
        assert!(res.struck);
        assert!(res.is_headshot);
        assert!((res.hit_location[0] - (-16.0)).abs() < 1e-3);
        assert!((res.hit_location[2] - 150.0).abs() < 1e-3);
    }

    #[test]
    fn test_skin_normalization_clamps_displaced_head_inside_cylinder() {
        let cyl = CylinderHitbox::new([0.0, 0.0, 0.0], 42.0, 176.0);
        // Simulate extreme cosmetic/animation offset pushing b_head outside cylinder bounds.
        let displaced_head = HeadHitbox::new([120.0, 0.0, 220.0], 80.0);
        let normalized = TargetHitbox::new_normalized(ChampionId::Evie, cyl, displaced_head);

        let dx = normalized.head.center[0] - cyl.base[0];
        let dy = normalized.head.center[1] - cyl.base[1];
        let radial_dist = (dx * dx + dy * dy).sqrt();
        assert!(radial_dist + normalized.head.radius <= cyl.radius + 1e-4);
        assert!(normalized.head.center[2] + normalized.head.radius <= cyl.base[2] + cyl.height + 1e-4);

        // Aiming at normalized head center must pass Stage 1 cylinder and register headshot.
        let res = normalized.evaluate_ray_hit(
            [-200.0, normalized.head.center[1], normalized.head.center[2]],
            [1.0, 0.0, 0.0],
            None,
        );
        assert!(res.struck);
        assert!(res.is_headshot);
    }

    #[test]
    fn test_fernando_flame_lance_cone_bounds() {
        let in_cone = CylinderHitbox::new([600.0, 0.0, 0.0], 42.0, 176.0);
        assert!(evaluate_flame_lance_cone([0.0, 0.0, 90.0], [1.0, 0.0, 0.0], &in_cone));

        let out_of_range = CylinderHitbox::new([1400.0, 0.0, 0.0], 42.0, 176.0);
        assert!(!evaluate_flame_lance_cone(
            [0.0, 0.0, 90.0],
            [1.0, 0.0, 0.0],
            &out_of_range
        ));

        let out_of_angle = CylinderHitbox::new([200.0, 400.0, 0.0], 42.0, 176.0);
        assert!(!evaluate_flame_lance_cone(
            [0.0, 0.0, 90.0],
            [1.0, 0.0, 0.0],
            &out_of_angle
        ));
    }

    #[test]
    fn test_fernando_shield_4000hp_zero_bleedthrough() {
        let mut shield = ShieldBarrier::new_fernando([100.0, 0.0, 100.0], [1.0, 0.0, 0.0])
            .expect("valid forward");
        assert_eq!(shield.health, 4000.0);

        let hit1 = shield.intercept_ray([500.0, 50.0, 120.0], [-1.0, 0.0, 0.0], 1200.0);
        assert!(hit1.intercepted);
        assert_eq!(hit1.absorbed_damage, 1200.0);
        assert_eq!(hit1.remaining_shield_hp, 2800.0);
        assert!(!hit1.shield_broken);

        // Overkill hit: breaks shield with zero bleed-through
        let hit2 = shield.intercept_ray([500.0, 0.0, 100.0], [-1.0, 0.0, 0.0], 3500.0);
        assert!(hit2.intercepted);
        assert_eq!(hit2.remaining_shield_hp, 0.0);
        assert!(hit2.shield_broken);

        // Subsequent ray passes through broken shield
        let hit3 = shield.intercept_ray([500.0, 0.0, 100.0], [-1.0, 0.0, 0.0], 500.0);
        assert!(!hit3.intercepted);
    }

    #[test]
    fn test_fernando_fireball_pierce_scaling_and_charge() {
        let t0 = TargetHitbox::new_normalized(
            ChampionId::Evie,
            CylinderHitbox::new([300.0, 0.0, 0.0], 36.0, 160.0),
            HeadHitbox::new([300.0, 0.0, 140.0], 14.0),
        );
        let t1 = TargetHitbox::new_normalized(
            ChampionId::Viktor,
            CylinderHitbox::new([600.0, 0.0, 0.0], 38.0, 170.0),
            HeadHitbox::new([600.0, 0.0, 145.0], 15.0),
        );
        let t2 = TargetHitbox::new_normalized(
            ChampionId::Cassie,
            CylinderHitbox::new([900.0, 0.0, 0.0], 36.0, 165.0),
            HeadHitbox::new([900.0, 0.0, 140.0], 14.0),
        );

        let hits = evaluate_fireball_sweep(
            [0.0, 0.0, 90.0],
            [1.0, 0.0, 0.0],
            2000.0,
            &[t2, t0, t1],
            450.0,
        );
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].0, 1); // t0 closest
        assert!((hits[0].1 - 450.0).abs() < 1e-4);
        assert_eq!(hits[1].0, 2); // t1 second (+20%)
        assert!((hits[1].1 - 540.0).abs() < 1e-4);
        assert_eq!(hits[2].0, 0); // t2 third (+40%)
        assert!((hits[2].1 - 630.0).abs() < 1e-4);

        let charge = evaluate_charge_sweep([0.0, 0.0, 90.0], [1.0, 0.0, 0.0], 1000.0, 42.0, &[t1, t0]);
        assert_eq!(charge.struck_target_index, Some(1));
        assert_eq!(charge.damage, 200.0);

        // Immortal aura floor
        assert_eq!(
            apply_immortal_aura_clamp([0.0, 0.0, 0.0], [300.0, 0.0, 0.0], 100.0, 4600.0),
            1500.0
        );
        assert_eq!(
            apply_immortal_aura_clamp([0.0, 0.0, 0.0], [700.0, 0.0, 0.0], 100.0, 4600.0),
            100.0
        );
    }
}
