// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! # Server Movement & Rooftop / Heavy Wall Physics Correction (`ADOPT-03`)
//! Cleanroom implementation of `OBL-PHYS-001` (`SPEC-TEMPEST-ADOPT-2026-01`):
//! Enforces the `cos(45°)` steepness invariant on `Actor.m_bCanBaseOn` contacts so
//! accidental `m_bCanBaseOn = false` flags on vertical walls/trees do not trigger
//! downward rooftop slide stickiness ("heavy walls"), while genuine steep rooftops
//! (`45° < angle <= ~84°`) slide smoothly down the surface tangent.

/// `cos(45°) ≈ 0.70710677` threshold separating walkable surfaces from steep slopes.
pub const STEEP_SURFACE_COS_45: f32 = std::f32::consts::FRAC_1_SQRT_2;

/// `|normal.z|` threshold below which a surface is classified as a vertical wall.
pub const VERTICAL_WALL_NORMAL_Z_EPS: f32 = 0.1;

/// Outcome of evaluating a pawn collision contact against a surface normal and `m_bCanBaseOn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceInteraction {
    pub can_stand: bool,
    pub apply_rooftop_slide: bool,
}

/// Evaluates `m_bCanBaseOn` against the contact surface normal using the `ADOPT-03`
/// geometric angle invariant (`cos(45°)`).
///
/// - Vertical walls (`|N_z| < 0.1`) never enter rooftop slide even when `m_bCanBaseOn == false`.
/// - Steep upward slopes (`0.1 <= N_z < cos(45°)`) with `m_bCanBaseOn == false` enter rooftop slide.
/// - Walkable slopes (`N_z >= cos(45°)`) with `m_bCanBaseOn == true` allow standing.
pub fn evaluate_surface_interaction(normal: [f32; 3], m_b_can_base_on: bool) -> SurfaceInteraction {
    let Some(n) = normalize3(normal) else {
        return SurfaceInteraction {
            can_stand: false,
            apply_rooftop_slide: false,
        };
    };

    let is_steep = n[2] < STEEP_SURFACE_COS_45;
    let is_vertical = n[2].abs() < VERTICAL_WALL_NORMAL_Z_EPS;
    let is_upward_slope = n[2] >= VERTICAL_WALL_NORMAL_Z_EPS;
    let apply_rooftop_slide = !m_b_can_base_on && is_steep && !is_vertical && is_upward_slope;
    let can_stand = m_b_can_base_on && !is_steep;

    SurfaceInteraction {
        can_stand,
        apply_rooftop_slide,
    }
}

/// Updates pawn `velocity` for a contact with `normal` over step `dt` (seconds):
/// - Strips inward normal penetration (`dot(v, n) < 0`) by projecting onto the contact tangent.
/// - Applies downward gravity along the surface tangent ONLY when `apply_rooftop_slide` is `true`
///   (never applying rooftop drag on vertical walls).
pub fn resolve_surface_velocity(
    velocity: [f32; 3],
    normal: [f32; 3],
    m_b_can_base_on: bool,
    gravity_uu_per_sec2: f32,
    dt: f32,
) -> ([f32; 3], SurfaceInteraction) {
    let interaction = evaluate_surface_interaction(normal, m_b_can_base_on);
    let Some(n) = normalize3(normal) else {
        return (velocity, interaction);
    };

    let mut v = velocity;
    let vn = dot3(v, n);
    if vn < 0.0 {
        v = [v[0] - vn * n[0], v[1] - vn * n[1], v[2] - vn * n[2]];
    }

    if interaction.apply_rooftop_slide && dt > 0.0 {
        // Project downward gravity vector [0, 0, -g] onto the slope tangent plane.
        let g_vec = [0.0, 0.0, -gravity_uu_per_sec2.abs()];
        let gn = dot3(g_vec, n);
        let slide_accel = [
            g_vec[0] - gn * n[0],
            g_vec[1] - gn * n[1],
            g_vec[2] - gn * n[2],
        ];
        v = [
            v[0] + slide_accel[0] * dt,
            v[1] + slide_accel[1] * dt,
            v[2] + slide_accel[2] * dt,
        ];
    }

    (v, interaction)
}

#[inline]
fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn normalize3(v: [f32; 3]) -> Option<[f32; 3]> {
    let len = dot3(v, v).sqrt();
    if !len.is_finite() || len <= 1e-8 {
        None
    } else {
        Some([v[0] / len, v[1] / len, v[2] / len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertical_wall_with_can_base_false_does_not_slide() {
        // Pure vertical wall (normal_z = 0.0) with accidental m_bCanBaseOn = false
        let res = evaluate_surface_interaction([1.0, 0.0, 0.0], false);
        assert!(!res.can_stand);
        assert!(
            !res.apply_rooftop_slide,
            "Vertical wall must never enter rooftop slide (ADOPT-03 heavy-wall fix)"
        );

        // Near-vertical wall (normal_z = 0.05 < 0.1)
        let near_vert = evaluate_surface_interaction([0.9987, 0.0, 0.05], false);
        assert!(!near_vert.can_stand);
        assert!(!near_vert.apply_rooftop_slide);

        // Upward jump velocity along a vertical wall must keep positive Z velocity intact
        let (v_out, interaction) =
            resolve_surface_velocity([-200.0, 0.0, 400.0], [1.0, 0.0, 0.0], false, 980.0, 0.016);
        assert!(!interaction.apply_rooftop_slide);
        assert!(v_out[0].abs() < 1e-4);
        assert!((v_out[2] - 400.0).abs() < 1e-4);
    }

    #[test]
    fn test_60_degree_rooftop_slides_down_smoothly() {
        // 60-degree roof slope: normal_z = cos(60°) = 0.5, normal_x = sin(60°) ≈ 0.8660254
        let angle_rad = 60.0_f32.to_radians();
        let normal = [angle_rad.sin(), 0.0, angle_rad.cos()];
        let res = evaluate_surface_interaction(normal, false);
        assert!(!res.can_stand);
        assert!(res.apply_rooftop_slide);

        let (v_out, interaction) =
            resolve_surface_velocity([0.0, 0.0, 0.0], normal, false, 980.0, 0.1);
        assert!(interaction.apply_rooftop_slide);
        assert!(v_out[0] > 0.0, "Slide must push outward along +X slope");
        assert!(v_out[2] < 0.0, "Slide must push downward along -Z slope");
        // Verify resulting slide velocity is tangent to surface normal
        assert!(dot3(v_out, normal).abs() < 1e-3);
    }

    #[test]
    fn test_walkable_floor_and_30_degree_ramp() {
        let flat = evaluate_surface_interaction([0.0, 0.0, 1.0], true);
        assert!(flat.can_stand);
        assert!(!flat.apply_rooftop_slide);

        let ramp_30 = 30.0_f32.to_radians();
        let ramp = evaluate_surface_interaction([ramp_30.sin(), 0.0, ramp_30.cos()], true);
        assert!(ramp.can_stand);
        assert!(!ramp.apply_rooftop_slide);
    }

    #[test]
    fn test_ceiling_and_degenerate_normals_safe() {
        let ceiling = evaluate_surface_interaction([0.0, 0.0, -1.0], false);
        assert!(!ceiling.can_stand);
        assert!(!ceiling.apply_rooftop_slide);

        let zero = evaluate_surface_interaction([0.0, 0.0, 0.0], false);
        assert!(!zero.can_stand);
        assert!(!zero.apply_rooftop_slide);
    }
}
