//! Tests for the chain rule (Tip + prev_rcm_for).

use zns_verify::{prev_rcm_for, Action, Tip, ZERO_PREV_RCM};

fn tip(action: Action, rcm: [u8; 32]) -> Tip {
    Tip { action, rcm }
}

#[test]
fn claim_fits_unseen_or_released_name() {
    assert_eq!(prev_rcm_for(None, Action::Claim), Some(ZERO_PREV_RCM));
    let released = tip(Action::Release, [9u8; 32]);
    assert_eq!(
        prev_rcm_for(Some(&released), Action::Claim),
        Some(ZERO_PREV_RCM)
    );
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
