use orchard::keys::{OutgoingViewingKey, PreparedIncomingViewingKey};
use orchard::note::ExtractedNoteCommitment;
use orchard::note_encryption::{CompactAction, IronwoodDomain};
use orchard::{Action, Address, Note};
use zcash_note_encryption::{
    BatchDomain, Domain, EphemeralKeyBytes, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput,
};

/// Trial-decryption domain for Name Notes in the Ironwood pool.
///
/// Every shared behaviour is `IronwoodDomain`'s; only `cmstar` differs, and it
/// returns the action's published `cmx` instead of re-deriving one from the
/// plaintext. The result is a [`CandidateNote`]: a note that decrypted, whose
/// binding to that `cmx` the caller must still verify.
#[derive(Debug)]
pub struct ZnsIronwoodDomain {
    ironwood: IronwoodDomain,
    cmx: ExtractedNoteCommitment,
}

/// A note that decrypted under [`ZnsIronwoodDomain`], alongside the `cmx` the
/// action published for it. The two are not yet known to agree: run
/// [`crate::verify_name_note`] with the memo before trusting the note.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CandidateNote {
    note: Note,
    cmx: ExtractedNoteCommitment,
}

impl CandidateNote {
    /// The decrypted note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The `cmx` the action published, to verify against the note's ZNS binding.
    pub fn cmx(&self) -> &ExtractedNoteCommitment {
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
    type ExtractedCommitment = ExtractedNoteCommitment;
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

    fn cmstar(&self) -> &ExtractedNoteCommitment {
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

    fn cmstar(&self) -> &ExtractedNoteCommitment {
        <Self as ShieldedOutput<IronwoodDomain>>::cmstar(self)
    }

    fn enc_ciphertext(&self) -> Option<&<ZnsIronwoodDomain as Domain>::NoteCiphertextBytes> {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext(self)
    }

    fn enc_ciphertext_compact(&self) -> <ZnsIronwoodDomain as Domain>::CompactNoteCiphertextBytes {
        <Self as ShieldedOutput<IronwoodDomain>>::enc_ciphertext_compact(self)
    }
}
