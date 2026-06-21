//! Verifies a name binding by recomputing its note commitment from raw fields.
//!

use crate::{NoteCommitment, Rho};

use crate::commitment::{note_commitment_cmx, zns_psi_rcm};

/// Verify that a Name Note's claimed fields, recipient, and value reproduce
/// `expected_cmx`.
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
    let (psi, rcm) = zns_psi_rcm(action, name, ua, prev_rcm);
    match note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) {
        Some(cmx) => cmx == expected_cmx,
        // Identity commitment has no x-coordinate; it cannot equal a real
        // on-chain `cmx`, so this is a non-match.
        None => false,
    }
}

