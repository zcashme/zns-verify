//! ZNS action kinds.
//!
//! See DESIGN.md §4 for the canonical strings; they're hashed verbatim and
//! must never change without a domain-tag bump.

/// Lifecycle event for a registered name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// First registration of a name. Has no predecessor in the chain;
    /// `prev_rcm` is [`crate::hash::ZERO_PREV_RCM`].
    Claim,
    /// Rebinds a name to a new UA. Used both for "rotate my own UA" and
    /// for handing the name to a different party — the protocol does not
    /// distinguish them.
    Update,
    /// Terminates a name's chain. The UA field is empty by convention.
    Release,
}

impl Action {
    /// The canonical ASCII bytes for this action, as fed into [`crate::hash::zns_psi_rcm`].
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Action::Claim => b"claim",
            Action::Update => b"update",
            Action::Release => b"release",
        }
    }

    /// Parse the canonical ASCII form (case-sensitive).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"claim" => Some(Action::Claim),
            b"update" => Some(Action::Update),
            b"release" => Some(Action::Release),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Action;

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
}

