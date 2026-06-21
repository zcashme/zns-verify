//! Cryptographic material derivation for ZNS bindings.
//!

// ============================================================================
// (ψ, rcm) derivation -- BLAKE2b with ZNS length-prefixed domain separation
// ============================================================================

use blake2b_simd::Params;
use group::ff::PrimeField;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

/// The ρ value used in an Orchard note commitment.
pub type Rho = pallas::Base;

/// The note commitment (on-chain `cmx`).
pub type NoteCommitment = pallas::Base;

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

use sinsemilla::CommitDomain;

/// Sinsemilla personalization tag for Orchard note commitments.
const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";

/// Number of bits taken from each Pallas base-field input (`rho`, `psi`).
/// Matches orchard's `L_ORCHARD_BASE`.
const L_ORCHARD_BASE: usize = 255;

/// Yields the bits of the bytes in little-endian bit order (LSB of each byte first).
/// This is the exact order expected by Sinsemilla for Orchard note commitments.
fn le_bytes_lsb0(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .copied()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 != 0))
}

/// Computes `cmx`, the x-coordinate of the Sinsemilla note commitment, from
/// the raw note components plus caller-supplied `(ψ, rcm)`.
pub fn note_commitment_cmx(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<NoteCommitment> {
    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
    let value_bytes = value.to_le_bytes();
    let rho_bytes = rho.to_repr();
    let psi_bytes = psi.to_repr();

    let bits = le_bytes_lsb0(&g_d)
        .chain(le_bytes_lsb0(&pk_d))
        .chain(le_bytes_lsb0(&value_bytes))
        .chain(le_bytes_lsb0(&rho_bytes).take(L_ORCHARD_BASE))
        .chain(le_bytes_lsb0(&psi_bytes).take(L_ORCHARD_BASE));

    Option::<NoteCommitment>::from(domain.short_commit(bits, &rcm))
}
