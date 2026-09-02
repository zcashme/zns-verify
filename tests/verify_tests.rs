//! Tests for verify_name_note.

use zns_verify::{
    verify_name_note, verify_name_note_with_witness, ExtractedNoteCommitment, Memo, NameNote, Rho,
};

// The same fixed inputs pinned by `tests/vectors.rs::commit_matches`, so the
// capstone is anchored to the same `cmx` the cross-language vectors commit
// to -- a non-circular end-to-end check.
const G_D: [u8; 32] = [0x11u8; 32];
const PK_D: [u8; 32] = [0x22u8; 32];
const PINNED_CMX_HEX: &str = "e9dba3d63fd866ca2ce29e1a102b2e3ffd3816817e28d74a6969efc019226a0d";
const CLAIM_MEMO: &[u8] =
    b"ZNS:claim:alice:u1xxx:none:0000000000000000000000000000000000000000000000000000000000000000";

fn rho() -> Rho {
    Rho::from_bytes(&[0x33u8; 32]).unwrap()
}

fn pinned_cmx() -> ExtractedNoteCommitment {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(PINNED_CMX_HEX, &mut bytes).unwrap();
    ExtractedNoteCommitment::from_bytes(&bytes).unwrap()
}

fn pinned_memo() -> Memo {
    Memo::from_bytes(CLAIM_MEMO).unwrap()
}

fn pinned_note(m: &Memo) -> NameNote<'_> {
    NameNote::parse(m).unwrap()
}

#[test]
fn matches_pinned_vector() {
    let m = pinned_memo();
    let note = pinned_note(&m);
    assert!(verify_name_note(&note, G_D, PK_D, 0, rho(), pinned_cmx()));
}

#[test]
fn witness_matches_and_carries_the_opening() {
    let m = pinned_memo();
    let note = pinned_note(&m);
    let (psi, rcm) =
        verify_name_note_with_witness(&note, G_D, PK_D, 0, rho(), pinned_cmx()).unwrap();
    let (want_psi, want_rcm) =
        zns_verify::zns_psi_rcm(b"claim", b"alice", b"u1xxx", b"none", &[0u8; 32]);
    assert_eq!(psi, want_psi);
    assert_eq!(rcm, want_rcm);
}

#[test]
fn rejects_tampered_ua() {
    let m = Memo::from_bytes(
        b"ZNS:claim:alice:u1evil:none:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let note = NameNote::parse(&m).unwrap();
    assert!(!verify_name_note(&note, G_D, PK_D, 0, rho(), pinned_cmx()));
}

#[test]
fn rejects_tampered_name() {
    let m = Memo::from_bytes(
        b"ZNS:claim:bob:u1xxx:none:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let note = NameNote::parse(&m).unwrap();
    assert!(!verify_name_note(&note, G_D, PK_D, 0, rho(), pinned_cmx()));
}

#[test]
fn rejects_tampered_action_and_prev_rcm() {
    let m = Memo::from_bytes(
        b"ZNS:update:alice:u1xxx:none:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    )
    .unwrap();
    let note = NameNote::parse(&m).unwrap();
    assert!(!verify_name_note(&note, G_D, PK_D, 0, rho(), pinned_cmx()));
}

#[test]
fn rejects_wrong_expected_cmx() {
    let mut wrong = [0u8; 32];
    hex::decode_to_slice(PINNED_CMX_HEX, &mut wrong).unwrap();
    wrong[0] ^= 1;
    let wrong_cmx = ExtractedNoteCommitment::from_bytes(&wrong).unwrap();
    let m = pinned_memo();
    let note = pinned_note(&m);
    assert!(!verify_name_note(&note, G_D, PK_D, 0, rho(), wrong_cmx));
}
