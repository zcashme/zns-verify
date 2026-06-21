#![doc = include_str!("../README.md")]
#![cfg_attr(all(not(test), not(feature = "decrypt")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The three canonical modules.
pub mod commitment;
pub mod memo;
pub mod verify;

#[cfg(feature = "decrypt")]
pub mod decrypt;

// -----------------------------------------------------------------------------
// ZNS Core Primitives
// -----------------------------------------------------------------------------

pub use memo::Action;
pub use memo::{prev_rcm_for, Tip, ZERO_PREV_RCM};

pub use commitment::{note_commitment_cmx, zns_psi_rcm, NoteCommitment, Rho, ZNS_DOMAIN_TAG};

pub use memo::{
    parse_claim_memo, parse_name_note, parse_release_memo, parse_update_memo, NameNote, MEMO_SIZE,
};

pub use verify::verify_name_note;

// Curve and field types provided so callers don't need direct dependencies
// on `pasta_curves` and `group` just to construct `rho` and `cmx`.
pub use group::ff::PrimeField;
pub use pasta_curves::pallas;

/// Construct a Pallas base-field element from its 32-byte little-endian representation.
pub fn base_from_bytes(bytes: [u8; 32]) -> pallas::Base {
    Option::from(pallas::Base::from_repr(bytes)).expect("invalid Pallas base field element")
}
