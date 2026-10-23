//! Registry spend lineage for one Name Note.
//!
//! [`authorized_transition`] is true when this transaction spends the
//! predecessor the action requires and the note's `prev_rcm` extends that
//! tip. [`crate::verify_name_note`] is separate: a memo can reproduce `cmx`
//! without the Registry key having spent anything.

use crate::memo::{prev_rcm_for, Action, NameNote, PrevRcm, Tip};

/// The facts of one transaction, as the caller observed them.
///
/// `tip_nullifier` is the nullifier stored for `tip` when the previous
/// transition was admitted. `live_names` and `live_anchors` are the
/// nullifiers still live. `revealed` is every Ironwood nullifier this
/// transaction revealed.
pub struct Transition<'a, 'n> {
    /// The candidate Name Note.
    pub note: &'a NameNote<'n>,
    /// The name's current tip. `None` when the name is free.
    pub tip: Option<&'a Tip>,
    /// Nullifier of `tip`. Required for an update or a release.
    pub tip_nullifier: Option<&'a [u8; 32]>,
    /// Ironwood nullifiers this transaction revealed.
    pub revealed: &'a [[u8; 32]],
    /// Nullifiers of every live name, including this one when it is live.
    pub live_names: &'a [[u8; 32]],
    /// Nullifiers of every live claim anchor.
    pub live_anchors: &'a [[u8; 32]],
    /// The transaction contains one Name Note.
    pub single_name_note: bool,
    /// Besides the candidate Name Note, a claim's only registry output is its
    /// zero-value successor anchor. Ignored for an update or a release.
    pub claim_successor: bool,
}

/// Whether this transaction is the Registry's transition for the note.
///
/// An update or a release must reveal that name's tip nullifier, no other
/// live name, and no live anchor. A claim must reveal exactly one live
/// anchor, no live name, and carry the successor flag. In every case
/// `prev_rcm` must be what [`prev_rcm_for`] requires, and the transaction
/// must contain one Name Note.
///
/// A match here does not inspect `cmx`. Call [`crate::verify_name_note`] too.
#[must_use]
pub fn authorized_transition(transition: &Transition<'_, '_>) -> bool {
    if !transition.single_name_note || !chain_ok(transition.note, transition.tip) {
        return false;
    }
    match transition.note.action() {
        Action::Claim => {
            count_in(transition.revealed, transition.live_anchors) == 1
                && !spends_live_name(transition)
                && transition.claim_successor
        }
        Action::Update | Action::Release => {
            let Some(tip_nullifier) = transition.tip_nullifier else {
                return false;
            };
            transition.revealed.contains(tip_nullifier)
                && !spends_other_live_name(transition, tip_nullifier)
                && count_in(transition.revealed, transition.live_anchors) == 0
        }
    }
}

/// `prev_rcm` is the one [`prev_rcm_for`] names for this tip and action.
fn chain_ok(note: &NameNote<'_>, tip: Option<&Tip>) -> bool {
    let Some(expected) = prev_rcm_for(tip, note.action()) else {
        return false;
    };
    let disclosed = note.prev_rcm().unwrap_or(PrevRcm::ZERO);
    disclosed.as_bytes() == &expected
}

fn spends_live_name(transition: &Transition<'_, '_>) -> bool {
    transition
        .revealed
        .iter()
        .any(|nullifier| transition.live_names.contains(nullifier))
}

fn spends_other_live_name(transition: &Transition<'_, '_>, tip_nullifier: &[u8; 32]) -> bool {
    transition
        .revealed
        .iter()
        .any(|nullifier| transition.live_names.contains(nullifier) && nullifier != tip_nullifier)
}

fn count_in(revealed: &[[u8; 32]], set: &[[u8; 32]]) -> usize {
    revealed
        .iter()
        .filter(|nullifier| set.contains(*nullifier))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{note_commitment_cmx, zns_psi_rcm, Rho};
    use crate::{verify_name_note, Action, Memo, NameNote, PrimeField, Tip};

    const G_D: [u8; 32] = [0x44; 32];
    const PK_D: [u8; 32] = [0x55; 32];
    const UA: &str = "u1holder";
    const ATTACKER: &str = "u1attacker";
    const TIP_NF: [u8; 32] = [0x11; 32];
    const OTHER_NF: [u8; 32] = [0x22; 32];
    const ANCHOR: [u8; 32] = [0x33; 32];

    fn rho() -> Rho {
        Rho::from_bytes(&[0x33; 32]).unwrap()
    }

    fn memo(text: &str) -> Memo {
        Memo::from_bytes(text.as_bytes()).unwrap()
    }

    fn parse<'a>(memo: &'a Memo) -> NameNote<'a> {
        NameNote::parse(memo).unwrap()
    }

    /// `rcm` of a claim for `UA`: the public tip an update can copy.
    fn claim_rcm() -> [u8; 32] {
        let (_, rcm) = zns_psi_rcm(b"claim", b"alice", UA.as_bytes(), b"none", &[0u8; 32]);
        rcm.to_repr()
    }

    fn tip_of(rcm: [u8; 32]) -> Tip {
        Tip {
            action: Action::Claim,
            rcm,
        }
    }

    fn update_transition<'a, 'n>(
        note: &'a NameNote<'n>,
        tip: &'a Tip,
        revealed: &'a [[u8; 32]],
        live_names: &'a [[u8; 32]],
        live_anchors: &'a [[u8; 32]],
        single_name_note: bool,
    ) -> Transition<'a, 'n> {
        Transition {
            note,
            tip: Some(tip),
            tip_nullifier: Some(&TIP_NF),
            revealed,
            live_names,
            live_anchors,
            single_name_note,
            claim_successor: false,
        }
    }

    #[test]
    fn a_consistent_forgery_fails_without_the_tip_spend() {
        let prev = claim_rcm();
        let prev_hex = hex::encode(prev);
        let forged_memo = memo(&format!("ZNS:update:alice:{ATTACKER}:none:{prev_hex}"));
        let forged = parse(&forged_memo);
        let (psi, rcm) = zns_psi_rcm(b"update", b"alice", ATTACKER.as_bytes(), b"none", &prev);
        let cmx = note_commitment_cmx(G_D, PK_D, 0, rho(), psi, rcm).unwrap();
        assert!(verify_name_note(&forged, G_D, PK_D, 0, rho(), cmx));

        let tip = tip_of(prev);
        assert!(!authorized_transition(&update_transition(
            &forged,
            &tip,
            &[],
            &[TIP_NF],
            &[],
            true,
        )));
        assert!(authorized_transition(&update_transition(
            &forged,
            &tip,
            &[TIP_NF],
            &[TIP_NF],
            &[],
            true,
        )));
    }

    #[test]
    fn an_update_that_spends_more_than_its_tip_is_refused() {
        let prev = claim_rcm();
        let owned = memo(&format!("ZNS:update:alice:{UA}:none:{}", hex::encode(prev)));
        let note = parse(&owned);
        let tip = tip_of(prev);

        assert!(!authorized_transition(&update_transition(
            &note,
            &tip,
            &[TIP_NF, ANCHOR],
            &[TIP_NF],
            &[ANCHOR],
            true,
        )));
        assert!(!authorized_transition(&update_transition(
            &note,
            &tip,
            &[TIP_NF, OTHER_NF],
            &[TIP_NF, OTHER_NF],
            &[],
            true,
        )));
        assert!(!authorized_transition(&update_transition(
            &note,
            &tip,
            &[TIP_NF],
            &[TIP_NF],
            &[],
            false,
        )));
    }

    #[test]
    fn a_wrong_prev_rcm_is_refused_even_when_the_tip_is_spent() {
        let prev = claim_rcm();
        let other = [0xab; 32];
        let owned = memo(&format!(
            "ZNS:update:alice:{UA}:none:{}",
            hex::encode(other)
        ));
        let note = parse(&owned);
        let tip = tip_of(prev);
        assert!(!authorized_transition(&update_transition(
            &note,
            &tip,
            &[TIP_NF],
            &[TIP_NF],
            &[],
            true,
        )));
    }

    #[test]
    fn a_claim_needs_one_live_anchor_and_the_successor() {
        let owned = memo(&format!(
            "ZNS:claim:alice:{UA}:none:{}",
            hex::encode([0u8; 32])
        ));
        let note = parse(&owned);
        let admit = |revealed: &[[u8; 32]], live_names: &[[u8; 32]], successor: bool| {
            authorized_transition(&Transition {
                note: &note,
                tip: None,
                tip_nullifier: None,
                revealed,
                live_names,
                live_anchors: &[ANCHOR],
                single_name_note: true,
                claim_successor: successor,
            })
        };
        assert!(admit(&[ANCHOR], &[], true));
        assert!(!admit(&[], &[], true));
        assert!(!admit(&[ANCHOR, OTHER_NF], &[OTHER_NF], true));
        assert!(!admit(&[ANCHOR], &[], false));
        assert!(!admit(&[ANCHOR, ANCHOR], &[], true));
    }

    #[test]
    fn a_release_spends_the_same_tip_as_an_update() {
        let prev = claim_rcm();
        let owned = memo(&format!(
            "ZNS:release:alice:{UA}:none:{}",
            hex::encode(prev)
        ));
        let note = parse(&owned);
        let tip = tip_of(prev);
        assert!(authorized_transition(&update_transition(
            &note,
            &tip,
            &[TIP_NF],
            &[TIP_NF],
            &[],
            true,
        )));
        assert!(!authorized_transition(&update_transition(
            &note,
            &tip,
            &[],
            &[TIP_NF],
            &[],
            true,
        )));
    }
}
