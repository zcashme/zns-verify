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
///
/// The tuple is σ = (α, n, u, e, p) per WP §3.2, where `e` is the
/// `expires_at` field bytes (canonical decimal or `none`).
pub fn zns_psi_rcm(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    let psi = pallas::Base::from_uniform_bytes(&tagged_zns_hash(
        TAG_PSI, action, name, ua, expires_at, prev_rcm,
    ));
    let rcm = pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(
        TAG_RCM, action, name, ua, expires_at, prev_rcm,
    ));
    (psi, rcm)
}

/// Compute the domain-tagged, length-prefixed BLAKE2b-512 hash that backs
/// both `(ψ, rcm)` derivations (WP §3.3).
///
/// Field order: `LP(T) ∥ LP(t) ∥ LP(α) ∥ LP(n) ∥ LP(u) ∥ LP(e) ∥ p`.
fn tagged_zns_hash(
    field_tag: &[u8],
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
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
    absorb_with_length_prefix(expires_at);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_from_bytes;

    /// WP §3.5 conformance: the whitepaper's golden vector.
    /// Inputs: all-zero seed, account m/32'/133'/1', diversifier 0, external, mainnet.
    /// value=0, rho=[0x33;32], expires_at=none, prev_rcm=zeroes.
    #[test]
    fn wp_section_3_5_golden_vector() {
        let g_d: [u8; 32] =
            hex::decode("de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_d: [u8; 32] =
            hex::decode("6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996")
                .unwrap()
                .try_into()
                .unwrap();
        let rho = base_from_bytes([0x33u8; 32]);
        let ua = b"u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

        let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", ua, b"none", &[0u8; 32]);

        assert_eq!(
            hex::encode(psi.to_repr()),
            "9f8a61b860c737d4564f12c635d654b843bc7115d9dc6cf6f09e409c81b8d13e",
            "WP §3.5 psi mismatch"
        );
        assert_eq!(
            hex::encode(rcm.to_repr()),
            "daa928be21d0ec13b5dbb0244699dbfeba546c71591d24d7824db78e4670c504",
            "WP §3.5 rcm mismatch"
        );

        let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm).unwrap();
        assert_eq!(
            hex::encode(cmx.to_repr()),
            "cc320736a0c1df1e4ffcee2b64aa73a9e6d06bb218e155a6fef422e1ecb1f70c",
            "WP §3.5 cmx mismatch"
        );
    }
}
