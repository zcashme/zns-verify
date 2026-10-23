//! Trial decryption for Name Notes

use crate::ExtractedNoteCommitment;
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey as OrchardPreparedIvk, Scope},
    note_encryption::{CompactAction, ZnsIronwoodDomain},
    Action,
};
use pasta_curves::pallas;
use zcash_protocol::memo::MemoBytes;

/// Compact-block trial decryption; the caller validates after fetching the full tx.
pub fn try_compact_ironwood(
    fvk: &FullViewingKey,
    action: &CompactAction,
) -> Option<(orchard::Note, orchard::Address, ExtractedNoteCommitment)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    let (candidate, recipient) =
        ZnsIronwoodDomain::for_compact_action(action).try_decrypt_compact(action, &ivk)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&candidate.cmx().to_bytes())?;
    Some((*candidate.note(), recipient, cmx))
}

/// Full-transaction trial decryption returning the memo.
///
/// [`crate::verify_name_note`] checks the memo against `cmx`.
/// [`crate::authorized_transition`] checks that the transaction spent the
/// name's live tip or claim anchor. [`name_note_nullifier`] is the nullifier
/// to store for the next spend.
pub fn try_decrypt_ironwood<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(
    orchard::Note,
    orchard::Address,
    MemoBytes,
    ExtractedNoteCommitment,
)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    let (candidate, recipient, memo) =
        ZnsIronwoodDomain::for_action(action).try_decrypt(action, &ivk)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&candidate.cmx().to_bytes())?;
    Some((
        *candidate.note(),
        recipient,
        MemoBytes::from_bytes(&memo).ok()?,
        cmx,
    ))
}

/// Outgoing recovery via the FVK's OVK proving the note was created by this account.
pub fn try_decrypt_ironwood_sent<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(
    orchard::Note,
    orchard::Address,
    MemoBytes,
    ExtractedNoteCommitment,
)> {
    let ovk = fvk.to_ovk(Scope::External);
    let (candidate, recipient, memo) =
        ZnsIronwoodDomain::for_action(action).try_decrypt_sent(action, &ovk)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&candidate.cmx().to_bytes())?;
    Some((
        *candidate.note(),
        recipient,
        MemoBytes::from_bytes(&memo).ok()?,
        cmx,
    ))
}

/// The nullifier this Name Note reveals when the Registry next spends it.
///
/// `psi` and `rcm` are the opening from [`crate::verify_name_note_with_witness`].
/// Store the result as this name's next tip nullifier and pass it to
/// [`crate::authorized_transition`]. Returns `None` when the commitment is the
/// identity.
#[must_use]
pub fn name_note_nullifier(
    note: &orchard::Note,
    fvk: &FullViewingKey,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<[u8; 32]> {
    note.zns_nullifier(
        fvk,
        orchard::note::NoteCommitTrapdoor::from_inner(rcm),
        orchard::note::Psi::from_inner(psi),
    )
    .map(|nullifier| nullifier.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{Scope, SpendingKey};
    use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
    use orchard::value::NoteValue;

    fn spending_key() -> SpendingKey {
        for byte in 1u8..=255 {
            let mut bytes = [0x5a; 32];
            bytes[0] = byte;
            if let Some(key) = SpendingKey::from_bytes(bytes).into() {
                return key;
            }
        }
        panic!("no spending key in the fixed scan");
    }

    fn random_seed(rho: &Rho) -> RandomSeed {
        for byte in 1u8..=255 {
            let mut bytes = [0x11; 32];
            bytes[0] = byte;
            if let Some(seed) = RandomSeed::from_bytes(bytes, rho).into() {
                return seed;
            }
        }
        panic!("no random seed in the fixed scan");
    }

    #[test]
    fn the_nullifier_follows_the_opening() {
        let key = spending_key();
        let fvk = FullViewingKey::from(&key);
        let rho = Rho::from_bytes(&[0x33; 32]).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(0),
            rho,
            random_seed(&rho),
            NoteVersion::V3,
        )
        .unwrap();
        let psi = pallas::Base::from(1u64);
        let rcm = pallas::Scalar::from(2u64);
        let nullifier = name_note_nullifier(&note, &fvk, psi, rcm).unwrap();
        assert_eq!(
            nullifier,
            name_note_nullifier(&note, &fvk, psi, rcm).unwrap()
        );
        assert_ne!(
            nullifier,
            name_note_nullifier(&note, &fvk, pallas::Base::from(3u64), rcm).unwrap()
        );
    }
}
