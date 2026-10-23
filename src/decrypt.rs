//! Trial decryption for Name Notes, on upstream `orchard`.

mod domain;

pub use domain::{CandidateNote, ZnsIronwoodDomain};

use crate::commitment::{diversify_hash, ExtractedNoteCommitment, Rho};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note_encryption::CompactAction;
use orchard::{Action, Address, Note};
use pasta_curves::pallas;
use zcash_protocol::memo::MemoBytes;

/// Compact-block trial decryption; the caller validates after fetching the full tx.
pub fn try_compact_ironwood(
    fvk: &FullViewingKey,
    action: &CompactAction,
) -> Option<(Note, Address, ExtractedNoteCommitment)> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
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
) -> Option<(Note, Address, MemoBytes, ExtractedNoteCommitment)> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
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
) -> Option<(Note, Address, MemoBytes, ExtractedNoteCommitment)> {
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
///
/// This is [`crate::name_note_nullifier`] fed from `orchard` types.
#[must_use]
pub fn name_note_nullifier(
    note: &Note,
    fvk: &FullViewingKey,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<[u8; 32]> {
    let raw = note.recipient().to_raw_address_bytes();
    let diversifier: [u8; 11] = raw[..11].try_into().expect("11-byte diversifier");
    let pk_d: [u8; 32] = raw[11..].try_into().expect("32-byte pk_d");
    let nk: [u8; 32] = fvk.to_bytes()[32..64].try_into().expect("32-byte nk");
    let rho = Rho::from_bytes(&note.rho().to_bytes())?;
    crate::commitment::name_note_nullifier(
        &nk,
        diversify_hash(&diversifier),
        pk_d,
        note.value().inner(),
        rho,
        psi,
        rcm,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{note_commitment_cmx, verify_name_note_with_witness, zns_psi_rcm, Memo, NameNote};
    use group::ff::FromUniformBytes;
    use orchard::keys::SpendingKey;
    use orchard::note::{
        ExtractedNoteCommitment as Cmx, Nullifier, RandomSeed, Rho as OrchardRho,
        TransmittedNoteCiphertext,
    };
    use orchard::note_encryption::{IronwoodDomain, IronwoodNoteEncryption};
    use orchard::value::{NoteValue, ValueCommitment};
    use orchard::NoteVersion;
    use zcash_note_encryption::Domain;

    const UA: &str = "u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

    /// A key, and a zero-value note to its first external address, from a fixed scan.
    fn received_note(version: NoteVersion) -> (FullViewingKey, Note, RandomSeed) {
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
            version,
        )
        .unwrap();
        (fvk, note, rseed)
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

    /// `PRF^expand_sk(t)` (Protocol Spec §5.4.2), to recover the rseed-derived
    /// opening that orchard keeps private.
    fn prf_expand(sk: &[u8; 32], t: u8, rho: &[u8; 32]) -> [u8; 64] {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state()
            .update(sk)
            .update(&[t])
            .update(rho)
            .finalize();
        hash.as_bytes().try_into().unwrap()
    }

    /// What an explorer does with a block: a whitepaper Name Note, encrypted
    /// by upstream orchard, is rejected by Ironwood, decrypted here, parsed,
    /// verified, and nullified by the kernel.
    #[test]
    fn a_whitepaper_name_note_round_trips() {
        let (fvk, note, _) = received_note(NoteVersion::V3);
        let raw = note.recipient().to_raw_address_bytes();
        let g_d = diversify_hash(&raw[..11].try_into().unwrap());
        let pk_d: [u8; 32] = raw[11..].try_into().unwrap();
        let rho = Rho::from_bytes(&note.rho().to_bytes()).unwrap();

        let memo =
            Memo::from_bytes(format!("ZNS:claim:alice:{UA}:none:{}", "0".repeat(64)).as_bytes())
                .unwrap();
        let claim = NameNote::parse(&memo).unwrap();
        let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", UA.as_bytes(), b"none", &[0; 32]);
        let cmx = note_commitment_cmx(g_d, pk_d, note.value().inner(), rho, psi, rcm).unwrap();
        let published = Cmx::from_bytes(&cmx.to_bytes()).unwrap();
        assert_ne!(published, Cmx::from(note.commitment()));
        let action = ironwood_action(&fvk, note, published, *memo.as_array());

        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let ironwood = IronwoodDomain::for_action(&action);
        assert!(zcash_note_encryption::try_note_decryption(&ironwood, &ivk, &action).is_none());

        let (seen, _, seen_cmx) =
            try_compact_ironwood(&fvk, &CompactAction::from(&action)).unwrap();
        assert_eq!((seen, seen_cmx), (note, cmx));
        let (seen, _, _, seen_cmx) = try_decrypt_ironwood_sent(&action, &fvk).unwrap();
        assert_eq!((seen, seen_cmx), (note, cmx));

        let (seen, _, seen_memo, seen_cmx) = try_decrypt_ironwood(&action, &fvk).unwrap();
        assert_eq!((seen, seen_cmx), (note, cmx));
        let seen_memo = Memo::from_array(*seen_memo.as_array());
        assert_eq!(NameNote::parse(&seen_memo).unwrap(), claim);
        assert_eq!(
            verify_name_note_with_witness(&claim, g_d, pk_d, note.value().inner(), rho, seen_cmx),
            Some((psi, rcm))
        );

        let nk: [u8; 32] = fvk.to_bytes()[32..64].try_into().unwrap();
        let nullifier = name_note_nullifier(&seen, &fvk, psi, rcm);
        assert!(nullifier.is_some());
        assert_eq!(
            nullifier,
            crate::name_note_nullifier(&nk, g_d, pk_d, note.value().inner(), rho, psi, rcm)
        );
        assert_ne!(nullifier, Some(note.nullifier(&fvk).to_bytes()));
    }

    /// The kernel nullifier is orchard's: fed the opening a V2 note's rseed
    /// derives (PRF^expand with 0x09 and 0x05, §4.7.3), it reproduces
    /// `note.commitment()` and `note.nullifier(&fvk)`. V3 derives rcm by
    /// ZIP 2005; the math under test does not depend on either.
    #[test]
    fn the_nullifier_is_orchards_for_the_rseed_opening() {
        let (fvk, note, rseed) = received_note(NoteVersion::V2);
        let rho = note.rho().to_bytes();
        let psi = pallas::Base::from_uniform_bytes(&prf_expand(rseed.as_bytes(), 0x09, &rho));
        let rcm = pallas::Scalar::from_uniform_bytes(&prf_expand(rseed.as_bytes(), 0x05, &rho));

        let raw = note.recipient().to_raw_address_bytes();
        let cmx = note_commitment_cmx(
            diversify_hash(&raw[..11].try_into().unwrap()),
            raw[11..].try_into().unwrap(),
            note.value().inner(),
            Rho::from_bytes(&rho).unwrap(),
            psi,
            rcm,
        )
        .unwrap();
        assert_eq!(cmx.to_bytes(), Cmx::from(note.commitment()).to_bytes());
        assert_eq!(
            name_note_nullifier(&note, &fvk, psi, rcm),
            Some(note.nullifier(&fvk).to_bytes())
        );
    }
}
