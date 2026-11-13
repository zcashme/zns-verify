//! Name Note **commitment** verification (WP §4.5).
//!
//! [`verify_bound_name_note`] checks **consistency**: the parsed memo fields,
//! the note components you supply (`g_d`, `pk_d`, `value`, `rho`), and the
//! on-chain `cmx` all agree. It does **not** check **authorship**. A wallet
//! that treats `true` as "this name is mine" can accept a forged binding. The
//! spend rule is [`crate::authorized_transition`]: the transaction must reveal
//! the predecessor nullifier. Both have to hold.
//!
//! [`crate::prev_for`] is the per-name chain-shape rule.
//! [`crate::authorized_transition`] applies it together with the revealed
//! nullifiers.

use crate::commitment::{
    name_note_rseed, note_commitment_cmx, psi_from_rseed, rcm_from_rseed, ExtractedNoteCommitment,
    Rho,
};
use crate::memo::{NameNote, PrevCmx};

/// Returns `true` when a Name Note's fields reproduce the on-chain `cmx`
/// (WP §4.5).
///
/// The transition gives the rseed ([`name_note_rseed`]); the rseed gives ψ and
/// rcm as for any Ironwood note. The check is for an Ironwood note (lead byte
/// `0x03`) only: an Orchard-pool note derives its rcm differently and fails it.
///
/// **Consistent, not authorised.** Anyone can build a zero-value note to the
/// published registry address whose commitment verifies. The Registry spend
/// is [`crate::authorized_transition`], which this function does not run.
pub fn verify_bound_name_note(
    note: &NameNote,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    cmx: ExtractedNoteCommitment,
) -> bool {
    let Ok(memo) = note.encode() else {
        return false;
    };
    let Some(fields) = memo.fields() else {
        return false;
    };
    let prev = note.prev().unwrap_or(PrevCmx::ZERO);
    let rseed = name_note_rseed(fields, prev.as_bytes());
    let psi = psi_from_rseed(&rseed, rho);
    let rcm = rcm_from_rseed(&rseed, rho, g_d, pk_d, value, psi);
    note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) == Some(cmx)
}
