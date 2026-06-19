//! The per-name transition rule — the fold over a name's hash chain.
//!
//! `DESIGN.md §5`: each name's Name Notes form an `rcm`-linked chain. This
//! module is the rule for how that chain may advance, shared by everything
//! that walks it — the resolver's index, the proof verifier, the registry's
//! minter. It is deliberately tiny and pure: the rule *is* the protocol's
//! state machine, so there must be exactly one copy of it.

use crate::{action::Action, hash::ZERO_PREV_RCM};

/// A name's chain tip as the fold sees it: the latest applied action —
/// *including* RELEASE, which resolution hides but the rule needs — and that
/// note's `rcm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    /// The latest applied action.
    pub action: Action,
    /// That Name Note's `rcm` — the link the next action must extend.
    pub rcm: [u8; 32],
}

/// The `prev_rcm` an `action` must extend given the name's current `tip`, or
/// `None` if the action does not fit the chain:
///
/// - CLAIM starts a fresh chain ([`ZERO_PREV_RCM`] genesis) on an unseen *or*
///   released name;
/// - UPDATE / RELEASE extend a live (non-released) tip, chaining off its
///   `rcm`.
pub fn prev_rcm_for(tip: Option<&Tip>, action: Action) -> Option<[u8; 32]> {
    match (action, tip) {
        (Action::Claim, None) => Some(ZERO_PREV_RCM),
        (Action::Claim, Some(t)) if t.action == Action::Release => Some(ZERO_PREV_RCM),
        (Action::Update | Action::Release, Some(t)) if t.action != Action::Release => Some(t.rcm),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(action: Action, rcm: [u8; 32]) -> Tip {
        Tip { action, rcm }
    }

    #[test]
    fn claim_fits_unseen_or_released_name() {
        assert_eq!(prev_rcm_for(None, Action::Claim), Some(ZERO_PREV_RCM));
        let released = tip(Action::Release, [9u8; 32]);
        assert_eq!(prev_rcm_for(Some(&released), Action::Claim), Some(ZERO_PREV_RCM));
        let live = tip(Action::Claim, [1u8; 32]);
        assert_eq!(prev_rcm_for(Some(&live), Action::Claim), None);
    }

    #[test]
    fn update_release_need_a_live_tip() {
        let live = tip(Action::Claim, [7u8; 32]);
        assert_eq!(prev_rcm_for(Some(&live), Action::Update), Some([7u8; 32]));
        assert_eq!(prev_rcm_for(Some(&live), Action::Release), Some([7u8; 32]));
        assert_eq!(prev_rcm_for(None, Action::Update), None);
        assert_eq!(prev_rcm_for(None, Action::Release), None);
        let released = tip(Action::Release, [7u8; 32]);
        assert_eq!(prev_rcm_for(Some(&released), Action::Update), None);
        assert_eq!(prev_rcm_for(Some(&released), Action::Release), None);
    }

    #[test]
    fn update_extends_update_tip() {
        let after_update = tip(Action::Update, [0xabu8; 32]);
        assert_eq!(
            prev_rcm_for(Some(&after_update), Action::Update),
            Some([0xabu8; 32])
        );
        assert_eq!(
            prev_rcm_for(Some(&after_update), Action::Release),
            Some([0xabu8; 32])
        );
        assert_eq!(prev_rcm_for(Some(&after_update), Action::Claim), None);
    }
}
