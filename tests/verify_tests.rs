//! Tests for verify_name_note (the main verification entry point).

use zns_verify::{base_from_bytes, pallas, verify_name_note};

// The same fixed inputs pinned by `tests/vectors.rs::commit_matches`, so the
// capstone is anchored to the same `cmx` the cross-language vectors commit
// to -- a non-circular end-to-end check.
const G_D: [u8; 32] = [0x11u8; 32];
const PK_D: [u8; 32] = [0x22u8; 32];
const PINNED_CMX_HEX: &str = "e9dba3d63fd866ca2ce29e1a102b2e3ffd3816817e28d74a6969efc019226a0d";

fn rho() -> pallas::Base {
    base_from_bytes([0x33u8; 32])
}

fn pinned_cmx() -> pallas::Base {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(PINNED_CMX_HEX, &mut bytes).unwrap();
    base_from_bytes(bytes)
}

#[test]
fn matches_pinned_vector() {
    // (claim, alice, u1xxx, none, 0) over the pinned note components reproduces
    // the pinned `cmx`.
    assert!(verify_name_note(
        b"claim",
        b"alice",
        b"u1xxx",
        b"none",
        &[0u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        pinned_cmx()
    ));
}

#[test]
fn rejects_tampered_ua() {
    assert!(!verify_name_note(
        b"claim",
        b"alice",
        b"u1evil",
        b"none",
        &[0u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        pinned_cmx()
    ));
}

#[test]
fn rejects_tampered_name() {
    assert!(!verify_name_note(
        b"claim",
        b"bob",
        b"u1xxx",
        b"none",
        &[0u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        pinned_cmx()
    ));
}

#[test]
fn rejects_tampered_action_and_prev_rcm() {
    assert!(!verify_name_note(
        b"update",
        b"alice",
        b"u1xxx",
        b"none",
        &[0u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        pinned_cmx()
    ));
    assert!(!verify_name_note(
        b"claim",
        b"alice",
        b"u1xxx",
        b"none",
        &[1u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        pinned_cmx()
    ));
}

#[test]
fn rejects_wrong_expected_cmx() {
    let mut wrong = [0u8; 32];
    hex::decode_to_slice(PINNED_CMX_HEX, &mut wrong).unwrap();
    wrong[0] ^= 1;
    let wrong_cmx = base_from_bytes(wrong);
    assert!(!verify_name_note(
        b"claim",
        b"alice",
        b"u1xxx",
        b"none",
        &[0u8; 32],
        G_D,
        PK_D,
        0,
        rho(),
        wrong_cmx
    ));
}
