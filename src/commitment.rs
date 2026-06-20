//! Cryptographic material derivation for ZNS bindings.
//!

// ============================================================================
// (ψ, rcm) derivation — BLAKE2b with ZNS length-prefixed domain separation
// ============================================================================

use blake2b_simd::Params;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

use crate::{ExtractedNoteCommitment, Rho};

/// Domain separation tag
pub const ZNS_DOMAIN_TAG: &[u8] = b"ZcashName/v1";

/// Field tags for the two distinct outputs of `zns_psi_rcm`.
const TAG_PSI: &[u8] = b"psi";
const TAG_RCM: &[u8] = b"rcm";

/// Derive `(ψ, rcm)` from a ZNS registration tuple.
pub fn zns_psi_rcm(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    let psi =
        pallas::Base::from_uniform_bytes(&tagged_zns_hash(TAG_PSI, action, name, ua, prev_rcm));
    let rcm =
        pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(TAG_RCM, action, name, ua, prev_rcm));
    (psi, rcm)
}

/// Compute the domain-tagged, length-prefixed BLAKE2b-512 hash that backs
/// both `(ψ, rcm)` derivations.
fn tagged_zns_hash(
    field_tag: &[u8],
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
) -> [u8; 64] {
    let mut h = Params::new().hash_length(64).to_state();
    let mut absorb_with_length_prefix = |b: &[u8]| {
        h.update(&(b.len() as u32).to_le_bytes());
        h.update(b);
    };
    absorb_with_length_prefix(ZNS_DOMAIN_TAG);
    absorb_with_length_prefix(field_tag);
    absorb_with_length_prefix(action);
    absorb_with_length_prefix(name);
    absorb_with_length_prefix(ua);
    h.update(prev_rcm);
    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// ============================================================================
// Note commitment (Sinsemilla)
// ============================================================================

use bitvec::{array::BitArray, order::Lsb0, view::BitView};
use group::ff::PrimeFieldBits;
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
    rho: Rho,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<ExtractedNoteCommitment> {
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
    Option::<ExtractedNoteCommitment>::from(domain.short_commit(bits, &rcm))
}
