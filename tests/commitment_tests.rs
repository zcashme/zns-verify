//! Tests for the commitment layer: zns_psi_rcm derivation and note_commitment_cmx.

use zns_verify::{zns_psi_rcm, PrimeField};

#[test]
fn deterministic() {
    let a = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
    let b = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
    assert_eq!(a.0, b.0);
    assert_eq!(a.1, b.1);
}

#[test]
fn field_tag_separation() {
    // ψ and rcm differ even with identical inputs.
    let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
    // pallas::Base and pallas::Scalar live in different fields, but we
    // can compare their byte representations to confirm they aren't the
    // same 64-byte hash output reduced two different ways.
    let psi_bytes = psi.to_repr();
    let rcm_bytes = rcm.to_repr();
    assert_ne!(&psi_bytes[..], &rcm_bytes[..]);
}

#[test]
fn length_prefix_prevents_collision() {
    // "ali" || "cebob" vs "alice" || ":bob" — without length prefixes
    // the concatenation collides. Confirm our prefixing actually
    // distinguishes these.
    let a = zns_psi_rcm(b"claim", b"ali", b"cebob", &[0u8; 32]);
    let b = zns_psi_rcm(b"claim", b"alice", b":bob", &[0u8; 32]);
    assert_ne!(a.0, b.0);
    assert_ne!(a.1, b.1);
}

#[test]
fn prev_rcm_and_action_change_output() {
    let base = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
    let other_prev = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[1u8; 32]);
    assert_ne!(base.0, other_prev.0);
    assert_ne!(base.1, other_prev.1);

    let update = zns_psi_rcm(b"update", b"alice", b"u1xxx", &[0u8; 32]);
    assert_ne!(base.0, update.0);
    assert_ne!(base.1, update.1);
}
