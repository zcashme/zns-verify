#![doc = include_str!("../README.md")]
#![cfg_attr(all(not(test), not(feature = "decrypt")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The three canonical modules.
pub mod commitment;
pub mod memo;
pub mod verify;

// Feature-gated relaxed trial decryption. Declared as a top-level module
// (rather than nested inside verify) because it is a substantial, self-
// contained unit that pulls in heavy optional dependencies.
#[cfg(feature = "decrypt")]
pub mod decrypt;

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

pub use memo::Action;
pub use memo::{prev_rcm_for, Tip, ZERO_PREV_RCM};

pub use commitment::{note_commitment_cmx, zns_psi_rcm, NoteCommitment, Rho, ZNS_DOMAIN_TAG};

pub use memo::{
    parse_claim_memo, parse_memo, parse_name_note_memo, parse_release_memo, parse_update_memo,
    ParsedMemo, MEMO_SIZE,
};

pub use verify::verify_name_note;

// Re-export the curve and field types so users don't need direct dependencies
// on `pasta_curves` and `group` just to construct `rho` and `cmx`.
pub use group::ff::PrimeField;
pub use pasta_curves::pallas;

/// Construct a Pallas base-field element from its 32-byte little-endian
/// representation.
pub fn base_from_bytes(bytes: [u8; 32]) -> pallas::Base {
    Option::from(pallas::Base::from_repr(bytes)).expect("invalid Pallas base field element")
}

/// Convenience alias for `base_from_bytes` when you are constructing
/// the on-chain `cmx` value.
pub use base_from_bytes as cmx_from_bytes;
