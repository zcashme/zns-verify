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

pub use memo::{
    prev_rcm_for, Action, Expiry, Memo, Name, NameNote, PrevRcm, Tip, Ua, ZERO_PREV_RCM,
};

pub use commitment::{
    note_commitment_cmx, zns_psi_rcm, ExtractedNoteCommitment, Rho, ZNS_DOMAIN_TAG,
};

pub use memo::MemoError;

pub use verify::{verify_name_note, verify_name_note_with_witness};

pub use group::ff::PrimeField;
pub use pasta_curves::pallas;
