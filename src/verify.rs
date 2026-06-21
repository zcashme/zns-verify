//! Verifies a name binding by recomputing its note commitment from raw fields.
//!

use crate::pallas;
use crate::{NoteCommitment, Rho};

use crate::commitment::{note_commitment_cmx, zns_psi_rcm};

/// Verify that a Name Note's claimed fields, recipient, and value reproduce
/// `expected_cmx`. Returns `true` on match.
#[allow(clippy::too_many_arguments)]
pub fn verify_name_note(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    expected_cmx: NoteCommitment,
) -> bool {
    verify_name_note_with_witness(action, name, ua, prev_rcm, g_d, pk_d, value, rho, expected_cmx)
        .is_some()
}

/// Same as [`verify_name_note`] but returns the rederived `(psi, rcm)` witness
/// on match, so callers that need to store or republish it (a resolver
/// indexing the name chain, a fraud proof, a re-broadcast) do not have to
/// recompute the hash a second time.
///
/// Returns `None` when the recomputed `cmx` does not match `expected_cmx`.
/// This includes the identity-commitment case, where
/// [`note_commitment_cmx`] returns `None` because the x-coordinate is
/// undefined; an identity commitment cannot equal a real on-chain `cmx`, so
/// it is treated as a non-match.
#[allow(clippy::too_many_arguments)]
pub fn verify_name_note_with_witness(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    expected_cmx: NoteCommitment,
) -> Option<(pallas::Base, pallas::Scalar)> {
    let (psi, rcm) = zns_psi_rcm(action, name, ua, prev_rcm);
    let cmx = note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)?;
    (cmx == expected_cmx).then_some((psi, rcm))
}

