//! Feature-gated relaxed Ironwood trial decryption for ZNS.
//!
//! Name Notes are Ironwood-pool notes (ZIP 2005, NU6.3). They carry V3 note
//! plaintexts (lead byte `0x03`) and are encrypted under the Ironwood
//! note-encryption domain ([`IronwoodDomain`]), not the Orchard domain. The two
//! domains share identical key agreement, KDF, and AEAD; they differ only in
//! which note plaintext lead byte they accept during parsing.
//!
//! Standard Orchard/Ironwood decryption derives the note commitment (`cmx`)
//! from the `rseed` in the decrypted plaintext and rejects the note if the
//! reconstructed commitment does not match the on-chain value. ZNS Name Notes
//! deliberately do not use `rseed` for `(rcm, ψ)`. Instead those values are
//! produced by hashing the binding tuple `(action, name, ua, prev_rcm)` with a
//! domain-separated BLAKE2b construction (see [`crate::commitment`]). As a
//! result, any decryption path that enforces the normal `cmx` check will
//! discard every valid Name Note.
//!
//! The functions here perform the actual trial-decryption work (key agreement,
//! keystream derivation, AEAD tag verification) but stop short of the `cmx`
//! reconstruction and validity check. They return the `Note` (and the memo,
//! when available). Responsibility for verifying that the note really binds the
//! claimed name moves to the caller, which uses [`crate::verify_name_note`].
//!
//! - Compact blocks yield no memo; use [`try_compact_ironwood`].
//! - Full transactions yield the memo; use [`try_decrypt_ironwood`].
//! - Proving the note was created by the account (self-send rule) uses
//!   [`try_decrypt_ironwood_sent`] with the outgoing viewing key.
//!
//! All three functions still authenticate the ciphertext to the account's
//! viewing keys. They only relax the subsequent commitment rule.

use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey as OrchardPreparedIvk, Scope},
    note_encryption::{CompactAction, IronwoodDomain},
    Action,
};
use zcash_note_encryption::try_output_recovery_with_ovk;
use zcash_protocol::memo::MemoBytes;

/// Compact-block Ironwood trial decryption, **without** the ZIP-212 commitment
/// (`cmx`) check, using the account's FullViewingKey.
///
/// The FVK is used to derive the appropriate IVK. A hit means the note is
/// addressed to the account. Name Notes are Ironwood-pool notes, so this uses
/// [`IronwoodDomain`], which accepts V3 note plaintexts (lead byte `0x03`).
pub fn try_compact_ironwood(
    fvk: &FullViewingKey,
    action: &CompactAction,
) -> Option<(orchard::Note, orchard::Address)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::ChaCha20;
    use zcash_note_encryption::{Domain, ShieldedOutput, COMPACT_NOTE_SIZE};

    let domain = IronwoodDomain::for_compact_action(action);
    let ephemeral_key =
        ShieldedOutput::<IronwoodDomain, COMPACT_NOTE_SIZE>::ephemeral_key(action);
    let epk = IronwoodDomain::prepare_epk(IronwoodDomain::epk(&ephemeral_key)?);
    let shared_secret = IronwoodDomain::ka_agree_dec(&ivk, &epk);
    let key = IronwoodDomain::kdf(shared_secret, &ephemeral_key);

    let mut plaintext = [0u8; COMPACT_NOTE_SIZE];
    plaintext.copy_from_slice(
        ShieldedOutput::<IronwoodDomain, COMPACT_NOTE_SIZE>::enc_ciphertext(action),
    );
    // Skip the Poly1305 keying block, exactly as the upstream compact path does.
    let mut keystream = ChaCha20::new(key.as_ref().into(), [0u8; 12][..].into());
    keystream.seek(64u64);
    keystream.apply_keystream(&mut plaintext);

    // No `check_note_validity`. The ZNS commitment check is the caller's
    // responsibility (via verify_name_note).
    domain.parse_note_plaintext_without_memo_ivk(&ivk, &plaintext)
}

/// Full-transaction Ironwood trial decryption, **without** the ZIP-212
/// commitment (`cmx`) check, recovering the memo. Uses the account's
/// FullViewingKey (derives the IVK internally).
///
/// The ChaCha20-Poly1305 tag is still verified, so only ciphertexts
/// authenticated to the FVK decrypt. Only the `rseed`-derived `cmx`
/// reconstruction is skipped; this is the full-ciphertext analogue of
/// [`try_compact_ironwood`], used to recover the memo that compact blocks
/// truncate. Name Notes are Ironwood-pool notes, so this uses
/// [`IronwoodDomain`], which accepts V3 note plaintexts (lead byte `0x03`).
pub fn try_decrypt_ironwood<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    use zcash_note_encryption::{
        Domain, NotePlaintextBytes, ShieldedOutput, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
    };

    let domain = IronwoodDomain::for_action(action);
    let ephemeral_key =
        ShieldedOutput::<IronwoodDomain, ENC_CIPHERTEXT_SIZE>::ephemeral_key(action);
    let epk = IronwoodDomain::prepare_epk(IronwoodDomain::epk(&ephemeral_key)?);
    let shared_secret = IronwoodDomain::ka_agree_dec(&ivk, &epk);
    let key = IronwoodDomain::kdf(shared_secret, &ephemeral_key);

    let enc = ShieldedOutput::<IronwoodDomain, ENC_CIPHERTEXT_SIZE>::enc_ciphertext(action);
    let mut plaintext = NotePlaintextBytes(enc[..NOTE_PLAINTEXT_SIZE].try_into().unwrap());
    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place_detached(
            [0u8; 12][..].into(),
            &[],
            &mut plaintext.0,
            enc[NOTE_PLAINTEXT_SIZE..].into(),
        )
        .ok()?;

    // No `check_note_validity`. The ZNS commitment check is the caller's
    // responsibility (via verify_name_note).
    let (note, recipient) = domain.parse_note_plaintext_without_memo_ivk(&ivk, &plaintext.0)?;
    let memo = domain.extract_memo(&plaintext);
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}

/// Full-transaction Ironwood "sent" recovery using the account's FullViewingKey.
/// This recovers the note via the outgoing ciphertext, proving the note
/// was created by the account (self-send check for name notes).
///
/// Name Notes are Ironwood-pool notes, so this uses [`IronwoodDomain`], which
/// accepts V3 note plaintexts (lead byte `0x03`).
pub fn try_decrypt_ironwood_sent<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let ovk = fvk.to_ovk(Scope::External);
    let (note, recipient, memo) = try_output_recovery_with_ovk(
        &IronwoodDomain::for_action(action),
        &ovk,
        action,
        action.cv_net(),
        &action.encrypted_note().out_ciphertext,
    )?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}