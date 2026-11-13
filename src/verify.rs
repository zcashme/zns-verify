//! Name Note **commitment** verification (WP §3.4).
//!
//! [`verify_bound_name_note`] checks **consistency**: the parsed memo fields,
//! the note components you supply (`g_d`, `pk_d`, `value`, `rho`), and the
//! on-chain `cmx` all agree. It does **not** check **authorship**. A wallet
//! that treats `true` as "this name is mine" can accept a forged binding. The
//! spend rule is [`crate::authorized_transition`]: the transaction must reveal
//! the predecessor nullifier. Both have to hold.
//!
//! [`crate::prev_rcm_for`] is the per-name chain-shape rule.
//! [`crate::authorized_transition`] applies it together with the revealed
//! nullifiers.

use crate::commitment::{
    name_note_rseed, note_commitment_cmx, psi_from_rseed, rcm_from_rseed, ExtractedNoteCommitment,
    Rho,
};
use crate::memo::{Expiry, NameNote, PrevRcm};

/// Returns `true` when a bound Name Note's fields reproduce the on-chain
/// `cmx` (zcashme/zns-mint#480).
///
/// The record gives the rseed ([`name_note_rseed`]); the rseed gives ψ and rcm
/// as for any Ironwood note. For a bound note the memo's last field, read here
/// through `prev_rcm`, is the predecessor's cmx.
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
    let (expires_at, prev) = expiry_and_prev(note);
    let terms = note.terms();
    let rseed = name_note_rseed(
        note.action().as_bytes(),
        note.name().as_str().as_bytes(),
        note.ua().as_str().as_bytes(),
        expires_at.as_bytes(),
        &terms[..note.term_count()],
        prev.as_bytes(),
    );
    let psi = psi_from_rseed(&rseed, rho);
    let rcm = rcm_from_rseed(&rseed, rho, g_d, pk_d, value, psi);
    note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) == Some(cmx)
}

fn expiry_and_prev<'a>(note: &NameNote<'a>) -> (&'a str, PrevRcm) {
    (
        note.expires_at().unwrap_or(Expiry::NEVER).field_bytes(),
        note.prev_rcm().unwrap_or(PrevRcm::ZERO),
    )
}
