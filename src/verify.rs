//! The capstone "wallet trusts the answer" check.
//!
//! Composes [`crate::hash`] and [`crate::commit`] into the single operation a
//! resolver or wallet SDK performs: given a Name Note's *already-parsed* fields
//! (`action`, `name`, `ua`, `prev_rcm`) plus the note components a wallet
//! decrypted from chain, confirm they reproduce the on-chain `cmx`. A match
//! means the `(name, ua)` binding is the one committed on chain — it cannot
//! have been tampered with by a resolver, because the verifier re-derives the
//! binding itself.
//!
//! Parsing the canonical memo grammar into these fields is [`crate::memo`]'s
//! job — the single shared parser (`DESIGN.md §17`). This function stays
//! parse-agnostic so a caller with already-parsed fields (or a non-memo
//! source, like a proof bundle's claims) pays no string cost.

use pasta_curves::pallas;

use crate::{commit::note_commitment_cmx, hash::zns_psi_rcm};

/// Verify that a Name Note's claimed fields, recipient, and value reproduce
/// `expected_cmx`.
///
/// Re-derives `(ψ, rcm)` from `(action, name, ua, prev_rcm)`, recomputes the
/// Sinsemilla note commitment over `(g_d, pk_d, value, ρ, ψ, rcm)`, and
/// compares its x-coordinate to `expected_cmx`.
///
/// `action`, `name`, and `ua` are the raw field bytes the caller parsed from
/// the canonical memo; they are hashed verbatim (see [`crate::hash`]). Returns
/// `true` iff the recomputed commitment equals the one the wallet read from
/// chain. `cmx` is public, so the comparison is ordinary (non-secret) equality.
#[allow(clippy::too_many_arguments)]
pub fn verify_name_note(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: pallas::Base,
    expected_cmx: pallas::Base,
) -> bool {
    let (psi, rcm) = zns_psi_rcm(action, name, ua, prev_rcm);
    match note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) {
        Some(cmx) => cmx == expected_cmx,
        // Identity commitment has no x-coordinate; it cannot equal a real
        // on-chain `cmx`, so this is a non-match.
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;

    // The same fixed inputs pinned by `tests/vectors.rs::commit_matches`, so the
    // capstone is anchored to the same `cmx` the cross-language vectors commit
    // to — a non-circular end-to-end check.
    const G_D: [u8; 32] = [0x11u8; 32];
    const PK_D: [u8; 32] = [0x22u8; 32];
    const PINNED_CMX_HEX: &str =
        "53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02";

    fn rho() -> pallas::Base {
        pallas::Base::from_repr([0x33u8; 32]).unwrap()
    }

    fn pinned_cmx() -> pallas::Base {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(PINNED_CMX_HEX, &mut bytes).unwrap();
        pallas::Base::from_repr(bytes).unwrap()
    }

    #[test]
    fn matches_pinned_vector() {
        // (claim, alice, u1xxx, 0) over the pinned note components reproduces
        // the pinned `cmx`.
        assert!(verify_name_note(
            b"claim", b"alice", b"u1xxx", &[0u8; 32], G_D, PK_D, 0, rho(), pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_ua() {
        // Same on-chain `cmx`, but a different claimed `ua`. The verifier
        // re-derives `(ψ, rcm)` from `ua`, so the recomputed `cmx` no longer
        // matches — the swap is caught.
        assert!(!verify_name_note(
            b"claim", b"alice", b"u1evil", &[0u8; 32], G_D, PK_D, 0, rho(), pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_name() {
        // Likewise for a swapped name.
        assert!(!verify_name_note(
            b"claim", b"bob", b"u1xxx", &[0u8; 32], G_D, PK_D, 0, rho(), pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_action_and_prev_rcm() {
        assert!(!verify_name_note(
            b"update", b"alice", b"u1xxx", &[0u8; 32], G_D, PK_D, 0, rho(), pinned_cmx()
        ));
        assert!(!verify_name_note(
            b"claim", b"alice", b"u1xxx", &[1u8; 32], G_D, PK_D, 0, rho(), pinned_cmx()
        ));
    }

    #[test]
    fn rejects_wrong_expected_cmx() {
        let mut wrong = pinned_cmx().to_repr();
        wrong[0] ^= 1;
        let wrong_cmx = pallas::Base::from_repr(wrong).unwrap();
        assert!(!verify_name_note(
            b"claim", b"alice", b"u1xxx", &[0u8; 32], G_D, PK_D, 0, rho(), wrong_cmx
        ));
    }
}
