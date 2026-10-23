//! Trial decryption for Name Notes, on upstream `orchard`.
//!
//! `IronwoodDomain` rejects any note whose `cmx` does not match the
//! rseed-derived commitment: `zcash_note_encryption` compares
//! `Domain::cmstar(note)` with the action's `cmx`. A Name Note's `cmx` comes
//! from the ZNS opening (WP §3.4), not from rseed, so every valid Name Note
//! fails that check. [`ZnsIronwoodDomain`] wraps `IronwoodDomain`, inherits
//! everything by delegation, and passes the action's `cmx` through `cmstar`
//! so the comparison is trivially true. The AEAD tag still authenticates the
//! ciphertext; the commitment check moves to [`crate::verify_name_note`].

use crate::commitment::{diversify_hash, ExtractedNoteCommitment, Rho};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note_encryption::{CompactAction, IronwoodDomain};
use orchard::{Action, Address, Note};
use pasta_curves::pallas;
use zcash_note_encryption::{
    BatchDomain, Domain, EphemeralKeyBytes, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput,
};
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

/// Trial-decryption domain for Name Notes in the Ironwood pool.
///
/// Every shared behaviour is `IronwoodDomain`'s; only `cmstar` differs, and it
/// returns the action's published `cmx` instead of re-deriving one from the
/// plaintext. The result is a [`CandidateNote`]: a note that decrypted, whose
/// binding to that `cmx` the caller must still verify.
#[derive(Debug)]
pub struct ZnsIronwoodDomain {
    ironwood: IronwoodDomain,
    cmx: orchard::note::ExtractedNoteCommitment,
}

/// A note that decrypted under [`ZnsIronwoodDomain`], alongside the `cmx` the
/// action published for it. The two are not yet known to agree: run
/// [`crate::verify_name_note`] with the memo before trusting the note.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CandidateNote {
    note: Note,
    cmx: orchard::note::ExtractedNoteCommitment,
}

impl CandidateNote {
    /// The decrypted note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The `cmx` the action published, to verify against the note's ZNS binding.
    pub fn cmx(&self) -> &orchard::note::ExtractedNoteCommitment {
        &self.cmx
    }
}

impl ZnsIronwoodDomain {
    /// The domain for an Ironwood action.
    pub fn for_action<T>(action: &Action<T>) -> Self {
        Self {
            ironwood: IronwoodDomain::for_action(action),
            cmx: *action.cmx(),
        }
    }

    /// The domain for a compact Ironwood action. Candidates from the compact
    /// path cannot be verified until the full transaction supplies the memo.
    pub fn for_compact_action(action: &CompactAction) -> Self {
        Self {
            ironwood: IronwoodDomain::for_compact_action(action),
            cmx: action.cmx(),
        }
    }

    /// Trial-decrypts an action with an incoming viewing key.
    pub fn try_decrypt<T>(
        &self,
        action: &Action<T>,
        ivk: &PreparedIncomingViewingKey,
    ) -> Option<(CandidateNote, Address, [u8; 512])> {
        zcash_note_encryption::try_note_decryption(self, ivk, action)
    }

    /// Trial-decrypts a compact action with an incoming viewing key.
    pub fn try_decrypt_compact(
        &self,
        action: &CompactAction,
        ivk: &PreparedIncomingViewingKey,
    ) -> Option<(CandidateNote, Address)> {
        zcash_note_encryption::try_compact_note_decryption(self, ivk, action)
    }

    /// Recovers a sent note with an outgoing viewing key.
    pub fn try_decrypt_sent<T>(
        &self,
        action: &Action<T>,
        ovk: &OutgoingViewingKey,
    ) -> Option<(CandidateNote, Address, [u8; 512])> {
        zcash_note_encryption::try_output_recovery_with_ovk(
            self,
            ovk,
            action,
            action.cv_net(),
            &action.encrypted_note().out_ciphertext,
        )
    }
}

impl Domain for ZnsIronwoodDomain {
    type EphemeralSecretKey = <IronwoodDomain as Domain>::EphemeralSecretKey;
    type EphemeralPublicKey = <IronwoodDomain as Domain>::EphemeralPublicKey;
    type PreparedEphemeralPublicKey = <IronwoodDomain as Domain>::PreparedEphemeralPublicKey;
    type SharedSecret = <IronwoodDomain as Domain>::SharedSecret;
    type SymmetricKey = <IronwoodDomain as Domain>::SymmetricKey;
    type Note = CandidateNote;
    type Recipient = Address;
    type DiversifiedTransmissionKey = <IronwoodDomain as Domain>::DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = <IronwoodDomain as Domain>::ValueCommitment;
    type ExtractedCommitment = orchard::note::ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; 512];
    type NotePlaintextBytes = <IronwoodDomain as Domain>::NotePlaintextBytes;
    type NoteCiphertextBytes = <IronwoodDomain as Domain>::NoteCiphertextBytes;
    type CompactNotePlaintextBytes = <IronwoodDomain as Domain>::CompactNotePlaintextBytes;
    type CompactNoteCiphertextBytes = <IronwoodDomain as Domain>::CompactNoteCiphertextBytes;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        IronwoodDomain::derive_esk(&note.note)
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        IronwoodDomain::get_pk_d(&note.note)
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        IronwoodDomain::prepare_epk(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        IronwoodDomain::ka_derive_public(&note.note, esk)
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        IronwoodDomain::ka_agree_enc(esk, pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        IronwoodDomain::ka_agree_dec(ivk, epk)
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        IronwoodDomain::kdf(secret, ephemeral_key)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> Self::NotePlaintextBytes {
        IronwoodDomain::note_plaintext_bytes(&note.note, memo)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        IronwoodDomain::derive_ock(ovk, cv, cmstar_bytes, ephemeral_key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        IronwoodDomain::outgoing_plaintext_bytes(&note.note, esk)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        IronwoodDomain::epk_bytes(epk)
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        IronwoodDomain::epk(ephemeral_key)
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        // The published commitment, passed through for the caller to verify.
        note.cmx
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &Self::CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let (note, recipient) = self
            .ironwood
            .parse_note_plaintext_without_memo_ivk(ivk, plaintext)?;
        Some((
            CandidateNote {
                note,
                cmx: self.cmx,
            },
            recipient,
        ))
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &Self::CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let (note, recipient) = self
            .ironwood
            .parse_note_plaintext_without_memo_ovk(pk_d, plaintext)?;
        Some((
            CandidateNote {
                note,
                cmx: self.cmx,
            },
            recipient,
        ))
    }

    fn split_plaintext_at_memo(
        &self,
        plaintext: &Self::NotePlaintextBytes,
    ) -> Option<(Self::CompactNotePlaintextBytes, Self::Memo)> {
        self.ironwood.split_plaintext_at_memo(plaintext)
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        IronwoodDomain::extract_pk_d(out_plaintext)
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        IronwoodDomain::extract_esk(out_plaintext)
    }
}

impl BatchDomain for ZnsIronwoodDomain {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        <IronwoodDomain as BatchDomain>::batch_kdf(items)
    }

    fn batch_epk(
        ephemeral_keys: impl Iterator<Item = EphemeralKeyBytes>,
    ) -> Vec<(Option<Self::PreparedEphemeralPublicKey>, EphemeralKeyBytes)> {
        <IronwoodDomain as BatchDomain>::batch_epk(ephemeral_keys)
    }

    fn batch_ka_agree_dec<'a>(
        ivk: &Self::IncomingViewingKey,
        epks: impl Iterator<Item = Option<&'a Self::PreparedEphemeralPublicKey>>,
    ) -> Vec<Option<Self::SharedSecret>>
    where
        Self::PreparedEphemeralPublicKey: 'a,
    {
        <IronwoodDomain as BatchDomain>::batch_ka_agree_dec(ivk, epks)
    }
}

// The output impls mirror `IronwoodDomain`'s, through them: the action
// types keep their ciphertext fields private.
impl<T> ShieldedOutput<ZnsIronwoodDomain> for Action<T> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        <Self as ShieldedOutput<IronwoodDomain>>::ephemeral_key(self)
    }

    fn cmstar(&self) -> &orchard::note::ExtractedNoteCommitment {
        <Self as ShieldedOutput<IronwoodDomain>>::cmstar(self)
    }

    fn enc_ciphertext(&self) -> Option<&<ZnsIronwoodDomain as Domain>::NoteCiphertextBytes> {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext(self)
    }

    fn enc_ciphertext_compact(&self) -> <ZnsIronwoodDomain as Domain>::CompactNoteCiphertextBytes {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext_compact(self)
    }
}

impl ShieldedOutput<ZnsIronwoodDomain> for CompactAction {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        <Self as ShieldedOutput<IronwoodDomain>>::ephemeral_key(self)
    }

    fn cmstar(&self) -> &orchard::note::ExtractedNoteCommitment {
        <Self as ShieldedOutput<IronwoodDomain>>::cmstar(self)
    }

    fn enc_ciphertext(&self) -> Option<&<ZnsIronwoodDomain as Domain>::NoteCiphertextBytes> {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext(self)
    }

    fn enc_ciphertext_compact(&self) -> <ZnsIronwoodDomain as Domain>::CompactNoteCiphertextBytes {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext_compact(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::{FromUniformBytes, PrimeField};
    use orchard::keys::SpendingKey;
    use orchard::note::{
        ExtractedNoteCommitment as Cmx, Nullifier, RandomSeed, TransmittedNoteCiphertext,
    };
    use orchard::note_encryption::IronwoodNoteEncryption;
    use orchard::value::{NoteValue, ValueCommitment};
    use orchard::NoteVersion;

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

    fn random_seed(rho: &orchard::note::Rho) -> RandomSeed {
        for byte in 1u8..=255 {
            let mut bytes = [0x11; 32];
            bytes[0] = byte;
            if let Some(seed) = RandomSeed::from_bytes(bytes, rho).into() {
                return seed;
            }
        }
        panic!("no random seed in the fixed scan");
    }

    /// `PRF^expand_sk(t)` (Protocol Spec §5.4.2), to recover the rseed-derived
    /// opening that `orchard` keeps private.
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

    /// A note to the key's external address, with a fixed rseed.
    fn note(fvk: &FullViewingKey, version: NoteVersion) -> (Note, RandomSeed) {
        let rho = orchard::note::Rho::from_bytes(&[0x33; 32]).unwrap();
        let rseed = random_seed(&rho);
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(7),
            rho,
            rseed,
            version,
        )
        .unwrap();
        (note, rseed)
    }

    /// Fed the opening its own rseed derives, the kernel reproduces the
    /// commitment and the nullifier `orchard` derives: same K, same Poseidon,
    /// same reduction. A V2 note, whose opening is `(psi, rcm)` with domain
    /// separators 0x09 and 0x05 (§4.7.3); V3 derives rcm by ZIP 2005.
    #[test]
    fn the_nullifier_matches_orchard_for_the_rseed_opening() {
        let fvk = FullViewingKey::from(&spending_key());
        let (note, rseed) = note(&fvk, NoteVersion::V2);
        let rho = note.rho().to_bytes();
        let psi = pallas::Base::from_uniform_bytes(&prf_expand(rseed.as_bytes(), 0x09, &rho));
        let rcm = pallas::Scalar::from_uniform_bytes(&prf_expand(rseed.as_bytes(), 0x05, &rho));

        // The same opening reproduces the note's own commitment through the
        // kernel, so the nullifier below is built on the right point.
        let raw = note.recipient().to_raw_address_bytes();
        let cmx = crate::note_commitment_cmx(
            diversify_hash(&raw[..11].try_into().unwrap()),
            raw[11..].try_into().unwrap(),
            note.value().inner(),
            Rho::from_bytes(&note.rho().to_bytes()).unwrap(),
            psi,
            rcm,
        )
        .unwrap();
        assert_eq!(cmx.to_bytes(), Cmx::from(note.commitment()).to_bytes());

        assert_eq!(
            name_note_nullifier(&note, &fvk, psi, rcm).unwrap(),
            note.nullifier(&fvk).to_bytes()
        );
        assert_ne!(
            name_note_nullifier(&note, &fvk, psi + pallas::Base::one(), rcm).unwrap(),
            note.nullifier(&fvk).to_bytes()
        );
    }

    /// An Ironwood action carrying `note` encrypted by upstream `orchard`, but
    /// published under `cmx` instead of the note's own commitment: the shape
    /// of a Name Note on chain.
    fn action_with_published_cmx(
        fvk: &FullViewingKey,
        note: Note,
        cmx: Cmx,
        memo: [u8; 512],
    ) -> Action<()> {
        let pk_d: [u8; 32] = note.recipient().to_raw_address_bytes()[11..]
            .try_into()
            .unwrap();
        // Any valid non-identity point serves as cv_net; pk_d is one.
        let cv_net = ValueCommitment::from_bytes(&pk_d).unwrap();
        let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
        let encryption = IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, memo);
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

    /// The whole point of the domain: a note whose published `cmx` is not its
    /// rseed commitment is invisible to `IronwoodDomain` and visible here, on
    /// the full, compact and outgoing paths, carrying the published `cmx`.
    #[test]
    fn a_note_under_a_foreign_cmx_decrypts_only_through_the_zns_domain() {
        let fvk = FullViewingKey::from(&spending_key());
        let (note, _) = note(&fvk, NoteVersion::V3);
        let published = Cmx::from_bytes(&pallas::Base::from(42u64).to_repr()).unwrap();
        assert_ne!(published, Cmx::from(note.commitment()));
        let memo = [0x77; 512];
        let action = action_with_published_cmx(&fvk, note, published, memo);
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

        assert!(zcash_note_encryption::try_note_decryption(
            &IronwoodDomain::for_action(&action),
            &ivk,
            &action
        )
        .is_none());

        let (got, recipient, got_memo, cmx) = try_decrypt_ironwood(&action, &fvk).unwrap();
        assert_eq!(got, note);
        assert_eq!(recipient, note.recipient());
        assert_eq!(got_memo.as_array(), &memo);
        assert_eq!(cmx.to_bytes(), published.to_bytes());

        let (got, _, cmx) = try_compact_ironwood(&fvk, &CompactAction::from(&action)).unwrap();
        assert_eq!(got, note);
        assert_eq!(cmx.to_bytes(), published.to_bytes());

        let (got, _, got_memo, cmx) = try_decrypt_ironwood_sent(&action, &fvk).unwrap();
        assert_eq!(got, note);
        assert_eq!(got_memo.as_array(), &memo);
        assert_eq!(cmx.to_bytes(), published.to_bytes());
    }

    /// Another key sees nothing: the AEAD check is intact.
    #[test]
    fn a_foreign_key_decrypts_nothing() {
        let fvk = FullViewingKey::from(&spending_key());
        let (note, _) = note(&fvk, NoteVersion::V3);
        let action = action_with_published_cmx(&fvk, note, Cmx::from(note.commitment()), [0; 512]);

        let mut other = [0x5a; 32];
        other[0] = 0xff;
        let other = FullViewingKey::from(&SpendingKey::from_bytes(other).unwrap());
        assert!(try_decrypt_ironwood(&action, &other).is_none());
        assert!(try_compact_ironwood(&other, &CompactAction::from(&action)).is_none());
        assert!(try_decrypt_ironwood_sent(&action, &other).is_none());
    }
}
