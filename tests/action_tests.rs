//! Tests for the Action enum (public API surface).

use zns_verify::Action;

#[test]
fn as_bytes_round_trip() {
    for action in [Action::Claim, Action::Update, Action::Release] {
        assert_eq!(Action::from_bytes(action.as_bytes()), Some(action));
    }
}

#[test]
fn from_bytes_rejects_non_canonical() {
    assert_eq!(Action::from_bytes(b"Claim"), None);
    assert_eq!(Action::from_bytes(b"CLAIM"), None);
    assert_eq!(Action::from_bytes(b"claim "), None);
    assert_eq!(Action::from_bytes(b""), None);
    assert_eq!(Action::from_bytes(b"transfer"), None);
}
