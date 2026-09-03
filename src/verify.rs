//! Verification: recomputes a Name Note's commitment from its fields and
//! compares it to the on-chain `cmx` (WP §3.4).

use crate::commitment::{note_commitment_cmx, zns_psi_rcm, ExtractedNoteCommitment, Rho};
use crate::memo::{NameNote, PrevRcm};
use pasta_curves::pallas;

/// Verifies that a Name Note's fields reproduce the on-chain `cmx`.
pub fn verify_name_note(
    note: &NameNote,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    cmx: ExtractedNoteCommitment,
) -> bool {
    verify_name_note_with_witness(note, g_d, pk_d, value, rho, cmx).is_some()
}

/// Same as [`verify_name_note`], returning the re-derived `(ψ, rcm)` opening
/// on match, so callers (resolvers indexing the name chain, fraud proofs)
/// do not re-hash. `rcm` is the chain link: the next transition's
/// `prev_rcm`, and the input to the note's spend-revealed nullifier.
///
/// Returns `None` on mismatch, including the identity-commitment case.
pub fn verify_name_note_with_witness(
    note: &NameNote,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    cmx: ExtractedNoteCommitment,
) -> Option<(pallas::Base, pallas::Scalar)> {
    let (expires_at, prev) = match note {
        NameNote::Claim { expires_at, .. } => (expires_at.field_bytes(), PrevRcm::ZERO),
        NameNote::Update {
            expires_at,
            prev_rcm,
            ..
        } => (expires_at.field_bytes(), *prev_rcm),
        NameNote::Release { prev_rcm, .. } => ("none", *prev_rcm),
    };
    let (psi, rcm) = zns_psi_rcm(
        note.action().as_bytes(),
        note.name().as_str().as_bytes(),
        note.ua().as_str().as_bytes(),
        expires_at.as_bytes(),
        prev.as_bytes(),
    );
    let computed = note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)?;
    (computed == cmx).then_some((psi, rcm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{zns_psi_rcm, ExtractedNoteCommitment, Rho};
    use crate::memo::{Memo, Tip};
    use crate::{prev_rcm_for, Action, PrimeField};

    const G_D: [u8; 32] = [
        0xde, 0x43, 0x38, 0xf2, 0xab, 0x9f, 0xd8, 0x30, 0x0a, 0x3a, 0x1c, 0x20, 0xdd, 0x69, 0x0c,
        0xe2, 0x70, 0x26, 0xc6, 0x00, 0x1c, 0x29, 0x5d, 0x7c, 0x64, 0x1a, 0x06, 0x7c, 0xe8, 0x09,
        0xb1, 0x1e,
    ];
    const PK_D: [u8; 32] = [
        0x6d, 0xf6, 0x09, 0xf5, 0x71, 0x0f, 0x3b, 0x5d, 0xee, 0xcd, 0x4e, 0xe4, 0xb8, 0xf0, 0x17,
        0x3b, 0x44, 0xaf, 0x6c, 0xf8, 0x91, 0x8a, 0xc0, 0x02, 0x69, 0x52, 0x60, 0x31, 0xba, 0x62,
        0x89, 0x96,
    ];
    const UA: &str = "u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";
    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn rho() -> Rho {
        Rho::from_bytes(&[0x33u8; 32]).unwrap()
    }

    fn compute_cmx(
        action: &[u8],
        name: &[u8],
        ua: &[u8],
        expires_at: &[u8],
        prev_rcm: &[u8; 32],
    ) -> (pallas::Base, pallas::Scalar, ExtractedNoteCommitment) {
        let (psi, rcm) = zns_psi_rcm(action, name, ua, expires_at, prev_rcm);
        let cmx = note_commitment_cmx(G_D, PK_D, 0, rho(), psi, rcm).unwrap();
        (psi, rcm, cmx)
    }

    fn memo(text: &str) -> Memo {
        Memo::from_bytes(text.as_bytes()).unwrap()
    }

    #[test]
    fn name_chain_lifecycle() {
        let claim_memo = memo(&format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX));
        let claim = NameNote::parse(&claim_memo).unwrap();
        let (psi1, rcm1, cmx1) =
            compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);

        assert!(verify_name_note(&claim, G_D, PK_D, 0, rho(), cmx1));
        assert_eq!(
            verify_name_note_with_witness(&claim, G_D, PK_D, 0, rho(), cmx1),
            Some((psi1, rcm1))
        );

        let rcm1_bytes = rcm1.to_repr();
        let rcm1_hex = hex::encode(rcm1_bytes);

        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Claim,
                    rcm: rcm1_bytes
                }),
                Action::Update
            ),
            Some(rcm1_bytes)
        );

        let update_memo = memo(&format!("ZNS:update:alice:{}:none:{}", UA, rcm1_hex));
        let update = NameNote::parse(&update_memo).unwrap();
        let (psi2, rcm2, cmx2) =
            compute_cmx(b"update", b"alice", UA.as_bytes(), b"none", &rcm1_bytes);

        assert!(verify_name_note(&update, G_D, PK_D, 0, rho(), cmx2));
        assert_eq!(
            verify_name_note_with_witness(&update, G_D, PK_D, 0, rho(), cmx2),
            Some((psi2, rcm2))
        );

        let rcm2_bytes = rcm2.to_repr();
        let rcm2_hex = hex::encode(rcm2_bytes);

        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Update,
                    rcm: rcm2_bytes
                }),
                Action::Release
            ),
            Some(rcm2_bytes)
        );

        let release_memo = memo(&format!("ZNS:release:alice:{}:none:{}", UA, rcm2_hex));
        let release = NameNote::parse(&release_memo).unwrap();
        let (_, _, cmx3) = compute_cmx(b"release", b"alice", UA.as_bytes(), b"none", &rcm2_bytes);

        assert!(verify_name_note(&release, G_D, PK_D, 0, rho(), cmx3));

        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Release,
                    rcm: rcm2_bytes
                }),
                Action::Claim
            ),
            Some([0u8; 32])
        );
    }

    #[test]
    fn rejects_tampered_ua() {
        let (_, _, cmx) = compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);
        let evil_memo = memo(&format!("ZNS:claim:alice:u1evil:none:{}", ZERO_HEX));
        let evil = NameNote::parse(&evil_memo).unwrap();
        assert!(!verify_name_note(&evil, G_D, PK_D, 0, rho(), cmx));
    }

    #[test]
    fn rejects_tampered_name() {
        let (_, _, cmx) = compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);
        let evil_memo = memo(&format!("ZNS:claim:bob:{}:none:{}", UA, ZERO_HEX));
        let evil = NameNote::parse(&evil_memo).unwrap();
        assert!(!verify_name_note(&evil, G_D, PK_D, 0, rho(), cmx));
    }

    #[test]
    fn rejects_tampered_expires_at() {
        let (_, _, cmx) = compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);
        let evil_memo = memo(&format!("ZNS:claim:alice:{}:0:{}", UA, ZERO_HEX));
        let evil = NameNote::parse(&evil_memo).unwrap();
        assert!(!verify_name_note(&evil, G_D, PK_D, 0, rho(), cmx));
    }

    #[test]
    fn rejects_tampered_action() {
        let rcm = [0xabu8; 32];
        let rcm_hex = hex::encode(rcm);
        let (_, _, cmx) = compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &rcm);
        let evil_memo = memo(&format!("ZNS:update:alice:{}:none:{}", UA, rcm_hex));
        let evil = NameNote::parse(&evil_memo).unwrap();
        assert!(!verify_name_note(&evil, G_D, PK_D, 0, rho(), cmx));
    }

    #[test]
    fn rejects_wrong_cmx() {
        let (_, _, cmx) = compute_cmx(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);
        let note_memo = memo(&format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX));
        let note = NameNote::parse(&note_memo).unwrap();
        let mut wrong = cmx.to_bytes();
        wrong[0] ^= 1;
        let wrong_cmx = ExtractedNoteCommitment::from_bytes(&wrong).unwrap();
        assert!(!verify_name_note(&note, G_D, PK_D, 0, rho(), wrong_cmx));
    }

    #[test]
    fn wp_golden_vector_verifies() {
        let note_memo = memo(&format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX));
        let note = NameNote::parse(&note_memo).unwrap();
        let cmx = ExtractedNoteCommitment::from_bytes(
            &hex::decode("cc320736a0c1df1e4ffcee2b64aa73a9e6d06bb218e155a6fef422e1ecb1f70c")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(verify_name_note(&note, G_D, PK_D, 0, rho(), cmx));
    }
}
