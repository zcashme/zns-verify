//! Relaxed Orchard trial decryption — the scanning half of the ZNS kernel.
//!
//! Standard note decryption ([`zcash_note_encryption`]) reconstructs `cmx` from
//! the plaintext `rseed` (ZIP-212) and rejects any note whose commitment does
//! not match. ZcashName Name Notes deliberately derive `(rcm, ψ)` from a
//! deterministic hash rather than `rseed`, so that check throws them away. The
//! functions here re-implement the inner decrypt up to — but not including —
//! that reconstruction, so Name Notes survive scanning. Confirming the
//! commitment is then [`verify_name_note`](crate::verify_name_note)'s job: a hit
//! here means "addressed to `ivk`", and the binding is only *true* once its
//! recomputed `cmx` matches the on-chain value.
//!
//! Only available with the `decrypt` feature (it pulls `orchard` + the cipher
//! crates and forces `std`).

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
    plaintext
        .copy_from_slice(ShieldedOutput::<OrchardDomain, COMPACT_NOTE_SIZE>::enc_ciphertext(action));
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
