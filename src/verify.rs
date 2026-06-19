//! The capstone "wallet trusts the answer" check.
//!
//! Composes [`crate::commitment`] (the `(ψ, rcm)` derivation and Sinsemilla
//! commitment) with caller-supplied note data.
//!
//! Parsing the canonical memo grammar into the four fields
//! (`action`, `name`, `ua`, `prev_rcm`) is [`crate::memo`]'s job — the single
//! shared parser. This function is deliberately parse-agnostic so a caller
//! with already-parsed fields (or a non-memo source) pays no string cost.

use pasta_curves::pallas;

use crate::commitment::{note_commitment_cmx, zns_psi_rcm};

/// Verify that a Name Note's claimed fields, recipient, and value reproduce
/// `expected_cmx`.
///
/// Re-derives `(ψ, rcm)` from `(action, name, ua, prev_rcm)`, recomputes the
/// Sinsemilla note commitment over `(g_d, pk_d, value, ρ, ψ, rcm)`, and
/// compares its x-coordinate to `expected_cmx`.
///
/// `action`, `name`, and `ua` are the raw field bytes the caller parsed from
/// the canonical memo; they are hashed verbatim (see [`crate::commitment`]).
/// Returns `true` iff the recomputed commitment equals the one the wallet read
/// from chain. `cmx` is public, so the comparison is ordinary (non-secret)
/// equality.
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
            b"claim",
            b"alice",
            b"u1xxx",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_ua() {
        // Same on-chain `cmx`, but a different claimed `ua`. The verifier
        // re-derives `(ψ, rcm)` from `ua`, so the recomputed `cmx` no longer
        // matches — the swap is caught.
        assert!(!verify_name_note(
            b"claim",
            b"alice",
            b"u1evil",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_name() {
        // Likewise for a swapped name.
        assert!(!verify_name_note(
            b"claim",
            b"bob",
            b"u1xxx",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }

    #[test]
    fn rejects_tampered_action_and_prev_rcm() {
        assert!(!verify_name_note(
            b"update",
            b"alice",
            b"u1xxx",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
        assert!(!verify_name_note(
            b"claim",
            b"alice",
            b"u1xxx",
            &[1u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            pinned_cmx()
        ));
    }

    #[test]
    fn rejects_wrong_expected_cmx() {
        let mut wrong = pinned_cmx().to_repr();
        wrong[0] ^= 1;
        let wrong_cmx = pallas::Base::from_repr(wrong).unwrap();
        assert!(!verify_name_note(
            b"claim",
            b"alice",
            b"u1xxx",
            &[0u8; 32],
            G_D,
            PK_D,
            0,
            rho(),
            wrong_cmx
        ));
    }
}

// ============================================================================
// Decrypt feature (relaxed Orchard trial decryption)
// ============================================================================

/// Relaxed Orchard trial decryption — the scanning half of the ZNS kernel.
///
/// Only compiled when the `decrypt` feature is enabled (it pulls `orchard` +
/// the cipher crates and forces `std`).
///
/// Standard note decryption ([`zcash_note_encryption`]) reconstructs `cmx` from
/// the plaintext `rseed` (ZIP-212) and rejects any note whose commitment does
/// not match. ZcashName Name Notes deliberately derive `(rcm, ψ)` from a
/// deterministic hash rather than `rseed`, so that check throws them away. The
/// functions here re-implement the inner decrypt up to — but not including —
/// that reconstruction, so Name Notes survive scanning. Confirming the
/// commitment is then [`verify_name_note`](crate::verify_name_note)'s job: a hit
/// here means "addressed to `ivk`", and the binding is only *true* once its
/// recomputed `cmx` matches the on-chain value.
#[cfg(feature = "decrypt")]
pub mod decrypt {
    use orchard::{
        keys::PreparedIncomingViewingKey as OrchardPreparedIvk,
        note_encryption::{CompactAction, OrchardDomain},
        Action,
    };
    use zcash_protocol::memo::MemoBytes;

    /// Compact-block orchard trial decryption, **without** the ZIP-212 commitment
    /// (`cmx`) check.
    ///
    /// ECDH → KDF → ChaCha20 → parse, stopping short of reconstructing `cmx` from
    /// `rseed`. The compact path carries no AEAD tag, so a hit means only
    /// "addressed to `ivk`", not "binding valid" — the caller compares its own
    /// recomputed `cmx` against the on-chain value. This is what lets ZcashName
    /// Name Notes, whose `rcm`/`psi` are a deterministic hash rather than
    /// `rseed`-derived, survive scanning.
    pub fn try_compact_orchard(
        ivk: &OrchardPreparedIvk,
        action: &CompactAction,
    ) -> Option<(orchard::Note, orchard::Address)> {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::ChaCha20;
        use zcash_note_encryption::{Domain, ShieldedOutput, COMPACT_NOTE_SIZE};

        let domain = OrchardDomain::for_compact_action(action);
        let ephemeral_key =
            ShieldedOutput::<OrchardDomain, COMPACT_NOTE_SIZE>::ephemeral_key(action);
        let epk = OrchardDomain::prepare_epk(OrchardDomain::epk(&ephemeral_key)?);
        let shared_secret = OrchardDomain::ka_agree_dec(ivk, &epk);
        let key = OrchardDomain::kdf(shared_secret, &ephemeral_key);

        let mut plaintext = [0u8; COMPACT_NOTE_SIZE];
        plaintext.copy_from_slice(
            ShieldedOutput::<OrchardDomain, COMPACT_NOTE_SIZE>::enc_ciphertext(action),
        );
        // Skip the Poly1305 keying block, exactly as the upstream compact path does.
        let mut keystream = ChaCha20::new(key.as_ref().into(), [0u8; 12][..].into());
        keystream.seek(64u64);
        keystream.apply_keystream(&mut plaintext);

        // NB: no `check_note_validity` — the commitment rule is the caller's job.
        domain.parse_note_plaintext_without_memo_ivk(ivk, &plaintext)
    }

    /// Full-transaction orchard trial decryption, **without** the ZIP-212
    /// commitment (`cmx`) check, recovering the memo.
    ///
    /// The ChaCha20-Poly1305 tag is still verified, so only ciphertexts
    /// authenticated to `ivk` decrypt; only the `rseed`→`cmx` reconstruction is
    /// skipped — the full-ciphertext analogue of [`try_compact_orchard`], used to
    /// recover the memo that compact blocks truncate.
    pub fn try_decrypt_orchard<A>(
        action: &Action<A>,
        ivk: &OrchardPreparedIvk,
    ) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::ChaCha20Poly1305;
        use zcash_note_encryption::{
            Domain, NotePlaintextBytes, ShieldedOutput, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
        };

        let domain = OrchardDomain::for_action(action);
        let ephemeral_key =
            ShieldedOutput::<OrchardDomain, ENC_CIPHERTEXT_SIZE>::ephemeral_key(action);
        let epk = OrchardDomain::prepare_epk(OrchardDomain::epk(&ephemeral_key)?);
        let shared_secret = OrchardDomain::ka_agree_dec(ivk, &epk);
        let key = OrchardDomain::kdf(shared_secret, &ephemeral_key);

        let enc = ShieldedOutput::<OrchardDomain, ENC_CIPHERTEXT_SIZE>::enc_ciphertext(action);
        let mut plaintext = NotePlaintextBytes(enc[..NOTE_PLAINTEXT_SIZE].try_into().unwrap());
        ChaCha20Poly1305::new(key.as_ref().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut plaintext.0,
                enc[NOTE_PLAINTEXT_SIZE..].into(),
            )
            .ok()?;

        // NB: no `check_note_validity` — the commitment rule is the caller's job.
        let (note, recipient) = domain.parse_note_plaintext_without_memo_ivk(ivk, &plaintext.0)?;
        let memo = domain.extract_memo(&plaintext);
        Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
    }
}
