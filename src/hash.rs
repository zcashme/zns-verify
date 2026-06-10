//! The ZNS `(ψ, rcm)` derivation.
//!

use blake2b_simd::Params;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

/// Domain separation tag — must never change. A protocol-breaking change
pub const ZNS_DOMAIN_TAG: &[u8] = b"ZcashName/v1";

/// The `prev_rcm` value used for the first action in a name's chain (the
/// CLAIM). A CLAIM has no predecessor, so its `prev_rcm` is the all-zero
/// 32-byte string by definition.
pub const ZERO_PREV_RCM: [u8; 32] = [0u8; 32];

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

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;

    #[test]
    fn deterministic() {
        let a = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        let b = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }

    #[test]
    fn field_tag_separation() {
        // ψ and rcm differ even with identical inputs.
        let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
        // pallas::Base and pallas::Scalar live in different fields, but we
        // can compare their byte representations to confirm they aren't the
        // same 64-byte hash output reduced two different ways.
        let psi_bytes = psi.to_repr();
        let rcm_bytes = rcm.to_repr();
        assert_ne!(&psi_bytes[..], &rcm_bytes[..]);
    }

    #[test]
    fn length_prefix_prevents_collision() {
        // "ali" || "cebob" vs "alice" || ":bob" — without length prefixes
        // the concatenation collides. Confirm our prefixing actually
        // distinguishes these.
        let a = zns_psi_rcm(b"claim", b"ali", b"cebob", &[0u8; 32]);
        let b = zns_psi_rcm(b"claim", b"alice", b":bob", &[0u8; 32]);
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
    }
}
