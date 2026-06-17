#![doc = include_str!("../README.md")]
#![cfg_attr(
    all(
        not(test),
        not(feature = "decrypt"),
        not(feature = "proof"),
        not(feature = "address")
    ),
    no_std
)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod action;
pub mod chain;
pub mod commit;
pub mod hash;
pub mod memo;
pub mod verify;

#[cfg(feature = "decrypt")]
pub mod decrypt;

#[cfg(feature = "proof")]
pub mod proof;

pub use action::Action;
pub use chain::{prev_rcm_for, Tip};
pub use commit::note_commitment_cmx;
pub use hash::{zns_psi_rcm, ZERO_PREV_RCM, ZNS_DOMAIN_TAG};
pub use memo::{parse_memo, ParsedMemo, MEMO_SIZE};
#[cfg(feature = "address")]
pub use memo::{parse_memo_validated, validate_orchard_ua};
pub use verify::verify_name_note;
