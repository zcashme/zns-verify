//! Note commitment derivation, standalone.
//!
//! Implements `NoteCommit^Orchard` (Zcash protocol spec §5.4.8.4) without
//! going through orchard's `pub(super) NoteCommitment::derive`. Uses
//! upstream `sinsemilla` directly so verifying consumers do not need the
//! orchard fork.

use bitvec::{array::BitArray, order::Lsb0, view::BitView};
use group::ff::PrimeFieldBits;
use pasta_curves::pallas;
use sinsemilla::CommitDomain;

/// Sinsemilla personalization tag for Orchard note commitments.
const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";

/// Number of bits taken from each Pallas base-field input (`rho`, `psi`).
/// Matches orchard's `L_ORCHARD_BASE`.
const L_ORCHARD_BASE: usize = 255;

/// Computes `cmx`, the x-coordinate of the Sinsemilla note commitment, from
/// the raw note components plus caller-supplied `(ψ, rcm)`.
pub fn note_commitment_cmx(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<pallas::Base> {
    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
    let value_bytes = value.to_le_bytes();
    let g_d_bits = BitArray::<_, Lsb0>::new(g_d);
    let pk_d_bits = BitArray::<_, Lsb0>::new(pk_d);
    let rho_bits = rho.to_le_bits();
    let psi_bits = psi.to_le_bits();
    let bits = g_d_bits
        .iter()
        .by_vals()
        .chain(pk_d_bits.iter().by_vals())
        .chain(value_bytes.view_bits::<Lsb0>().iter().by_vals())
        .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
        .chain(psi_bits.iter().by_vals().take(L_ORCHARD_BASE));
    Option::<pallas::Base>::from(domain.short_commit(bits, &rcm))
}
