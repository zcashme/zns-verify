#![doc = include_str!("../README.md")]
#![cfg_attr(all(not(test), not(feature = "decrypt")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The three canonical modules.
pub mod commitment;
pub mod memo;
pub mod verify;

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

pub use memo::Action;
pub use memo::{prev_rcm_for, Tip, ZERO_PREV_RCM};

pub use commitment::{note_commitment_cmx, zns_psi_rcm, ZNS_DOMAIN_TAG};

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
///
/// This is intended for test vectors and known-good constants. It will
/// panic if the bytes are not a valid field element.
pub fn base_from_bytes(bytes: [u8; 32]) -> pallas::Base {
    Option::from(pallas::Base::from_repr(bytes)).expect("invalid Pallas base field element")
}

/// Convenience alias for `base_from_bytes` when you are constructing
/// the on-chain `cmx` value.
pub use base_from_bytes as cmx_from_bytes;

// -----------------------------------------------------------------------------
// Compatibility shims for the previous inlined-module structure.
//
// Before the refactor the crate exposed:
//   zns_verify::action, ::chain, ::commit, ::hash, ::memo, ::verify
//
// Callers that used the nested paths (rare, but possible) continue to work.
// New code is encouraged to use the root re-exports or the three canonical
// modules (`memo`, `commitment`, `verify`).
// -----------------------------------------------------------------------------

/// Compatibility shim. New code should use [`crate::Action`] or [`crate::memo`].
pub mod action {
    pub use crate::memo::Action;
}

/// Compatibility shim. New code should use [`crate::prev_rcm_for`], [`crate::Tip`],
/// or [`crate::memo`].
pub mod chain {
    pub use crate::memo::{prev_rcm_for, Tip};
}

/// Compatibility shim. New code should use [`crate::note_commitment_cmx`] or
/// [`crate::commitment`].
pub mod commit {
    pub use crate::commitment::note_commitment_cmx;
}

/// Compatibility shim. New code should use [`crate::zns_psi_rcm`],
/// [`crate::ZNS_DOMAIN_TAG`], [`crate::ZERO_PREV_RCM`], or [`crate::commitment`].
pub mod hash {
    pub use crate::commitment::{zns_psi_rcm, ZNS_DOMAIN_TAG};
    pub use crate::memo::ZERO_PREV_RCM;
}

// The `pub mod verify;` declaration above makes the old path
// `zns_verify::verify::verify_name_note` continue to work without any extra shim.
//
// Re-export decrypt at the crate root when the feature is on, preserving the
// previous path `zns_verify::decrypt::*`.
#[cfg(feature = "decrypt")]
pub use verify::decrypt;
