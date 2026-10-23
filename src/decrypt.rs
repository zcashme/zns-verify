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
    use group::ff::{FromUniformBytes, PrimeField};
    use orchard::keys::{OutgoingViewingKey, SpendingKey};
    use orchard::note::{
        ExtractedNoteCommitment as Cmx, Nullifier, RandomSeed, Rho as OrchardRho,
        TransmittedNoteCiphertext,
    };
    use orchard::note_encryption::{
        IronwoodDomain, IronwoodNoteEncryption, OrchardDomain, OrchardNoteEncryption,
    };
    use orchard::value::{NoteValue, ValueCommitment};
    use orchard::NoteVersion;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use zcash_note_encryption::{Domain, NoteEncryption};

    const UA: &str = "u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

    fn arb_spending_key() -> impl Strategy<Value = SpendingKey> {
        prop::array::uniform32(any::<u8>()).prop_filter_map("valid spending key", |b| {
            Option::from(SpendingKey::from_bytes(b))
        })
    }

    fn arb_rho() -> impl Strategy<Value = OrchardRho> {
        any::<u64>().prop_map(|v| OrchardRho::from_bytes(&pallas::Base::from(v).to_repr()).unwrap())
    }

    fn arb_memo() -> impl Strategy<Value = [u8; 512]> {
        prop::collection::vec(any::<u8>(), 512).prop_map(|v| v.try_into().unwrap())
    }

    /// A note of the given version, received at the key's external address.
    fn arb_received_note(
        version: NoteVersion,
    ) -> impl Strategy<Value = (FullViewingKey, Note, RandomSeed)> {
        (
            arb_spending_key(),
            any::<u32>(),
            any::<u64>(),
            arb_rho(),
            prop::array::uniform32(any::<u8>()),
        )
            .prop_filter_map("valid rseed", move |(sk, index, value, rho, rseed)| {
                let fvk = FullViewingKey::from(&sk);
                let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho))?;
                let note = Note::from_parts(
                    fvk.address_at(index, Scope::External),
                    NoteValue::from_raw(value),
                    rho,
                    rseed,
                    version,
                )
                .unwrap();
                Some((fvk, note, rseed))
            })
    }

    /// An action carrying `encryption`'s output, published under `cmx`.
    ///
    /// Only the ciphertext and `cmx` matter to decryption; `rk` and `cv_net`
    /// are any valid values (an `ak` and a `pk_d` are both such points).
    fn publish<D>(
        encryption: NoteEncryption<D>,
        fvk: &FullViewingKey,
        note: &Note,
        cmx: Cmx,
    ) -> Action<()>
    where
        D: Domain<
            Note = Note,
            ValueCommitment = ValueCommitment,
            ExtractedCommitment = Cmx,
            NoteCiphertextBytes = <IronwoodDomain as Domain>::NoteCiphertextBytes,
            OutgoingViewingKey = OutgoingViewingKey,
        >,
    {
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
                epk_bytes: D::epk_bytes(encryption.epk()).0,
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

    /// `note`, encrypted by upstream orchard for `fvk`, published under `cmx`.
    fn ironwood_action(fvk: &FullViewingKey, note: Note, cmx: Cmx, memo: [u8; 512]) -> Action<()> {
        let ovk = fvk.to_ovk(Scope::External);
        publish(
            IronwoodNoteEncryption::new(Some(ovk), note, memo),
            fvk,
            &note,
            cmx,
        )
    }

    fn ivk(fvk: &FullViewingKey) -> PreparedIncomingViewingKey {
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External))
    }

    /// Everything the three paths return for an action, with the cmx dropped
    /// from the candidate so results can be compared across domains.
    type Decryptions = (
        Option<(Note, Address, [u8; 512])>,
        Option<(Note, Address)>,
        Option<(Note, Address, [u8; 512])>,
    );

    fn ironwood_decrypts(fvk: &FullViewingKey, action: &Action<()>) -> Decryptions {
        let domain = IronwoodDomain::for_action(action);
        let compact = CompactAction::from(action);
        (
            zcash_note_encryption::try_note_decryption(&domain, &ivk(fvk), action),
            zcash_note_encryption::try_compact_note_decryption(
                &IronwoodDomain::for_compact_action(&compact),
                &ivk(fvk),
                &compact,
            ),
            zcash_note_encryption::try_output_recovery_with_ovk(
                &domain,
                &fvk.to_ovk(Scope::External),
                action,
                action.cv_net(),
                &action.encrypted_note().out_ciphertext,
            ),
        )
    }

    /// The ZNS paths, asserting every candidate carries the published cmx.
    fn zns_decrypts(fvk: &FullViewingKey, action: &Action<()>) -> Decryptions {
        let domain = ZnsIronwoodDomain::for_action(action);
        let compact = CompactAction::from(action);
        let carried = |candidate: CandidateNote| {
            assert_eq!(candidate.cmx(), action.cmx());
            *candidate.note()
        };
        (
            domain
                .try_decrypt(action, &ivk(fvk))
                .map(|(c, r, m)| (carried(c), r, m)),
            ZnsIronwoodDomain::for_compact_action(&compact)
                .try_decrypt_compact(&compact, &ivk(fvk))
                .map(|(c, r)| (carried(c), r)),
            domain
                .try_decrypt_sent(action, &fvk.to_ovk(Scope::External))
                .map(|(c, r, m)| (carried(c), r, m)),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// The domain is `IronwoodDomain` plus one change. On an ordinary
        /// note every path returns what Ironwood returns, and the candidate
        /// carries the action's cmx.
        #[test]
        fn agrees_with_ironwood_on_ordinary_notes(
            (fvk, note, _) in arb_received_note(NoteVersion::V3),
            memo in arb_memo(),
        ) {
            let action = ironwood_action(&fvk, note, Cmx::from(note.commitment()), memo);
            let expected = ironwood_decrypts(&fvk, &action);
            prop_assert!(expected.0.is_some() && expected.1.is_some() && expected.2.is_some());
            prop_assert_eq!(zns_decrypts(&fvk, &action), expected);
        }

        /// The published cmx is passed through and changes nothing else:
        /// the same ciphertext under two different cmx values yields the
        /// same note, recipient and memo, while Ironwood rejects both.
        #[test]
        fn the_published_cmx_is_passed_through_and_changes_nothing_else(
            (fvk, note, _) in arb_received_note(NoteVersion::V3),
            memo in arb_memo(),
            a in any::<u64>(),
            b in any::<u64>(),
        ) {
            let cmx = |v: u64| Cmx::from_bytes(&pallas::Base::from(v).to_repr()).unwrap();
            prop_assume!(a != b);
            let under_a = ironwood_action(&fvk, note, cmx(a), memo);
            let under_b = ironwood_action(&fvk, note, cmx(b), memo);

            prop_assert_eq!(ironwood_decrypts(&fvk, &under_a), (None, None, None));
            let got = zns_decrypts(&fvk, &under_a);
            prop_assert_eq!(&got, &zns_decrypts(&fvk, &under_b));
            prop_assert_eq!(got.0, Some((note, note.recipient(), memo)));
            prop_assert_eq!(got.1, Some((note, note.recipient())));
            prop_assert_eq!(got.2, Some((note, note.recipient(), memo)));
        }

        /// Fed the opening its own rseed derives, the kernel reproduces the
        /// commitment and the nullifier orchard derives: same K, same
        /// Poseidon, same reduction. V2, whose opening is PRF^expand with
        /// domain separators 0x09 and 0x05 (§4.7.3); V3 derives rcm by
        /// ZIP 2005, and the math under test does not depend on either.
        #[test]
        fn the_nullifier_is_orchards_for_the_rseed_opening(
            (fvk, note, rseed) in arb_received_note(NoteVersion::V2),
        ) {
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
            prop_assert_eq!(cmx.to_bytes(), Cmx::from(note.commitment()).to_bytes());
            prop_assert_eq!(
                name_note_nullifier(&note, &fvk, psi, rcm),
                Some(note.nullifier(&fvk).to_bytes())
            );
        }
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

    /// One key and note from the same generator, fixed by `seed`.
    fn fixed(version: NoteVersion, seed: u8) -> (FullViewingKey, Note) {
        use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
        let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &[seed; 32]);
        let mut runner = TestRunner::new_with_rng(ProptestConfig::default(), rng);
        let (fvk, note, _) = arb_received_note(version)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        (fvk, note)
    }

    /// `action` with its cmx and ciphertext replaced.
    fn republish(
        action: &Action<()>,
        cmx: Cmx,
        ciphertext: TransmittedNoteCiphertext,
    ) -> Action<()> {
        Action::from_parts(
            *action.nullifier(),
            action.rk().clone(),
            cmx,
            ciphertext,
            action.cv_net().clone(),
            (),
        )
        .unwrap()
    }

    /// Integrity is intact: the AEAD tag covers the ciphertext and the epk,
    /// the outgoing ciphertext covers the out plaintext, and another key sees
    /// nothing.
    #[test]
    fn a_flipped_byte_or_another_key_decrypts_nothing() {
        let (fvk, note) = fixed(NoteVersion::V3, 1);
        let action = ironwood_action(&fvk, note, Cmx::from(note.commitment()), [0x77; 512]);
        let intact = zns_decrypts(&fvk, &action);
        assert!(intact.0.is_some() && intact.1.is_some() && intact.2.is_some());

        let tampered = |edit: &dyn Fn(&mut TransmittedNoteCiphertext)| {
            let mut ciphertext = action.encrypted_note().clone();
            edit(&mut ciphertext);
            republish(&action, *action.cmx(), ciphertext)
        };
        let flipped_ciphertext = tampered(&|c| c.enc_ciphertext.0[3] ^= 1);
        assert_eq!(zns_decrypts(&fvk, &flipped_ciphertext), (None, None, None));
        let flipped_tag = tampered(&|c| c.enc_ciphertext.0[c.enc_ciphertext.0.len() - 1] ^= 1);
        assert_eq!(zns_decrypts(&fvk, &flipped_tag).0, None);
        assert_eq!(zns_decrypts(&fvk, &flipped_tag).2, None);
        let flipped_epk = tampered(&|c| c.epk_bytes[31] ^= 0x80);
        assert_eq!(zns_decrypts(&fvk, &flipped_epk), (None, None, None));
        let flipped_out = tampered(&|c| c.out_ciphertext[0] ^= 1);
        assert_eq!(zns_decrypts(&fvk, &flipped_out).2, None);
        assert_eq!(zns_decrypts(&fvk, &flipped_out).0, intact.0);

        let (other, _) = fixed(NoteVersion::V2, 2);
        assert_ne!(other.to_bytes(), fvk.to_bytes());
        assert_eq!(zns_decrypts(&other, &action), (None, None, None));
    }

    /// Outgoing recovery is bound to the cmx the action publishes, because
    /// the ock derives from it. A mint therefore encrypts the outgoing
    /// plaintext under the Name Note's cmx, not the rseed one.
    #[test]
    fn outgoing_recovery_is_bound_to_the_published_cmx() {
        let (fvk, note) = fixed(NoteVersion::V3, 1);
        let rseed_cmx = Cmx::from(note.commitment());
        let published = Cmx::from_bytes(&pallas::Base::from(42u64).to_repr()).unwrap();
        let encrypted_under_rseed = ironwood_action(&fvk, note, rseed_cmx, [0; 512]);
        let mismatched = republish(
            &encrypted_under_rseed,
            published,
            encrypted_under_rseed.encrypted_note().clone(),
        );

        let got = zns_decrypts(&fvk, &mismatched);
        assert_eq!(got.0, Some((note, note.recipient(), [0; 512])));
        assert_eq!(got.2, None);
    }

    /// Name Notes are Ironwood notes: a V2 plaintext is rejected, because
    /// the version policy is inherited.
    #[test]
    fn a_v2_plaintext_is_rejected() {
        let (fvk, note) = fixed(NoteVersion::V2, 1);
        let ovk = fvk.to_ovk(Scope::External);
        let cmx = Cmx::from(note.commitment());
        let action = publish(
            OrchardNoteEncryption::new(Some(ovk), note, [0; 512]),
            &fvk,
            &note,
            cmx,
        );

        let orchard_sees_it = zcash_note_encryption::try_note_decryption(
            &OrchardDomain::for_action(&action),
            &ivk(&fvk),
            &action,
        );
        assert_eq!(orchard_sees_it.map(|(n, _, _)| n), Some(note));
        assert_eq!(zns_decrypts(&fvk, &action), (None, None, None));
    }

    /// A whitepaper Name Note round-trips, with no fork anywhere: memo by
    /// `NameNote`, opening by `zns_psi_rcm`, cmx by `note_commitment_cmx`,
    /// encrypted by upstream orchard. Ironwood rejects it; this module
    /// decrypts it, the kernel verifies it and derives its nullifier.
    #[test]
    fn a_whitepaper_name_note_round_trips() {
        let (fvk, note) = fixed(NoteVersion::V3, 1);
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

        assert_eq!(ironwood_decrypts(&fvk, &action), (None, None, None));

        let (seen, _, seen_cmx) =
            try_compact_ironwood(&fvk, &CompactAction::from(&action)).unwrap();
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
}
