//! Trial decryption for Name Notes, on upstream `orchard`.
//!
//! A bound Name Note is an ordinary Ironwood note: its rseed reproduces its
//! published `cmx`, so upstream `IronwoodDomain` decrypts it unchanged.

use crate::commitment::ExtractedNoteCommitment;
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note_encryption::{CompactAction, IronwoodDomain};
use orchard::{Action, Address, Note};
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ovk,
};
use zcash_protocol::memo::MemoBytes;

/// Compact-block trial decryption; the caller validates after fetching the full tx.
pub fn try_compact_ironwood(
    fvk: &FullViewingKey,
    action: &CompactAction,
) -> Option<(Note, Address, ExtractedNoteCommitment)> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let domain = IronwoodDomain::for_compact_action(action);
    let (note, recipient) = try_compact_note_decryption(&domain, &ivk, action)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&action.cmx().to_bytes())?;
    Some((note, recipient, cmx))
}

/// Full-transaction trial decryption returning the memo.
///
/// [`crate::verify_bound_name_note`] checks the memo against `cmx`.
/// [`crate::authorized_transition`] checks that the transaction spent the
/// name's live tip or claim anchor.
pub fn try_decrypt_ironwood<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(Note, Address, MemoBytes, ExtractedNoteCommitment)> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let domain = IronwoodDomain::for_action(action);
    let (note, recipient, memo) = try_note_decryption(&domain, &ivk, action)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&action.cmx().to_bytes())?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).ok()?, cmx))
}

/// Outgoing recovery via the FVK's OVK proving the note was created by this account.
pub fn try_decrypt_ironwood_sent<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(Note, Address, MemoBytes, ExtractedNoteCommitment)> {
    let ovk = fvk.to_ovk(Scope::External);
    let domain = IronwoodDomain::for_action(action);
    let (note, recipient, memo) = try_output_recovery_with_ovk(
        &domain,
        &ovk,
        action,
        action.cv_net(),
        &action.encrypted_note().out_ciphertext,
    )?;
    let cmx = ExtractedNoteCommitment::from_bytes(&action.cmx().to_bytes())?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).ok()?, cmx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::PrimeField;
    use orchard::keys::SpendingKey;
    use orchard::note::{
        ExtractedNoteCommitment as Cmx, Nullifier, RandomSeed, Rho as OrchardRho,
        TransmittedNoteCiphertext,
    };
    use orchard::note_encryption::IronwoodNoteEncryption;
    use orchard::value::{NoteValue, ValueCommitment};
    use orchard::NoteVersion;
    use pasta_curves::pallas;
    use zcash_note_encryption::Domain;

    /// A key, and a zero-value V3 note to its first external address, from a fixed scan.
    fn received_note() -> (FullViewingKey, Note) {
        let sk = (1u8..=255)
            .find_map(|byte| {
                let mut bytes = [0x5a; 32];
                bytes[0] = byte;
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .unwrap();
        let fvk = FullViewingKey::from(&sk);
        let rho = OrchardRho::from_bytes(&[0x33; 32]).unwrap();
        let rseed = (1u8..=255)
            .find_map(|byte| {
                let mut bytes = [0x11; 32];
                bytes[0] = byte;
                Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho))
            })
            .unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(0),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        (fvk, note)
    }

    /// `note`, encrypted by upstream orchard for `fvk`, published under `cmx`.
    ///
    /// Only the ciphertext and `cmx` matter to decryption; `rk` and `cv_net`
    /// are any valid values (an `ak` and a `pk_d` are both such points).
    fn ironwood_action(fvk: &FullViewingKey, note: Note, cmx: Cmx, memo: [u8; 512]) -> Action<()> {
        let encryption = IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, memo);
        let pk_d: [u8; 32] = note.recipient().to_raw_address_bytes()[11..]
            .try_into()
            .unwrap();
        let cv_net = ValueCommitment::from_bytes(&pk_d).unwrap();
        let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
        Action::from_parts(
            Nullifier::from_bytes(&note.rho().to_bytes()).unwrap(),
            ak.try_into().unwrap(),
            cmx,
            TransmittedNoteCiphertext {
                epk_bytes: IronwoodDomain::epk_bytes(encryption.epk()).0,
                enc_ciphertext: encryption.encrypt_note_plaintext(),
                out_ciphertext: encryption.encrypt_outgoing_plaintext(
                    &cv_net,
                    &cmx,
                    &mut rand::rng(),
                ),
            },
            cv_net,
            (),
        )
        .unwrap()
    }

    /// A note decrypts on every path under the cmx its rseed gives, and on
    /// none under another one.
    #[test]
    fn a_note_decrypts_only_under_its_own_cmx() {
        let (fvk, note) = received_note();
        let cmx = Cmx::from(note.commitment());
        let action = ironwood_action(&fvk, note, cmx, [0x77; 512]);

        let ours = ExtractedNoteCommitment::from_bytes(&cmx.to_bytes()).unwrap();
        let (n, _, c) = try_compact_ironwood(&fvk, &CompactAction::from(&action)).unwrap();
        assert_eq!((n, c), (note, ours));
        let (n, _, memo, c) = try_decrypt_ironwood(&action, &fvk).unwrap();
        assert_eq!((n, *memo.as_array(), c), (note, [0x77; 512], ours));
        let (n, _, memo, c) = try_decrypt_ironwood_sent(&action, &fvk).unwrap();
        assert_eq!((n, *memo.as_array(), c), (note, [0x77; 512], ours));

        let foreign = Cmx::from_bytes(&pallas::Base::from(42u64).to_repr()).unwrap();
        let action = ironwood_action(&fvk, note, foreign, [0x77; 512]);
        assert!(try_compact_ironwood(&fvk, &CompactAction::from(&action)).is_none());
        assert!(try_decrypt_ironwood(&action, &fvk).is_none());
        assert!(try_decrypt_ironwood_sent(&action, &fvk).is_none());
    }
}
