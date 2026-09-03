//! Verification: recomputes a Name Note's commitment from its fields and
//! compares it to the on-chain `cmx` (WP §3.4).

use crate::commitment::{note_commitment_cmx, zns_psi_rcm, ExtractedNoteCommitment, Rho};
use crate::memo::{NameNote, PrevRcm};
use pasta_curves::pallas;

/// Verifies that a Name Note's fields reproduce the on-chain `cmx`.
pub fn verify_name_note(
    note: &NameNote,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    cmx: ExtractedNoteCommitment,
) -> bool {
    verify_name_note_with_witness(note, g_d, pk_d, value, rho, cmx).is_some()
}

/// Same as [`verify_name_note`], returning the re-derived `(ψ, rcm)` opening
/// on match, so callers (resolvers indexing the name chain, fraud proofs)
/// do not re-hash. `rcm` is the chain link: the next transition's
/// `prev_rcm`, and the input to the note's spend-revealed nullifier.
///
/// Returns `None` on mismatch, including the identity-commitment case.
pub fn verify_name_note_with_witness(
    note: &NameNote,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    cmx: ExtractedNoteCommitment,
) -> Option<(pallas::Base, pallas::Scalar)> {
    let (expires_at, prev) = match note {
        NameNote::Claim { expires_at, .. } => (expires_at.field_bytes(), PrevRcm::ZERO),
        NameNote::Update {
            expires_at,
            prev_rcm,
            ..
        } => (expires_at.field_bytes(), *prev_rcm),
        NameNote::Release { prev_rcm, .. } => ("none", *prev_rcm),
    };
    let (psi, rcm) = zns_psi_rcm(
        note.action().as_bytes(),
        note.name().as_str().as_bytes(),
        note.ua().as_str().as_bytes(),
        expires_at.as_bytes(),
        prev.as_bytes(),
    );
    let computed = note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)?;
    (computed == cmx).then_some((psi, rcm))
}
