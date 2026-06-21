# zns-verify External Code Review

## Purpose

zns-verify is the reference implementation of the ZcashName (ZNS) binding verification kernel.

A Name Note carries a memo in a fixed grammar and a commitment (cmx). The binding (name to UA) is encoded by deriving deterministic values (psi, rcm) from the action, name, UA, and previous rcm, then feeding those plus the normal note fields into a Sinsemilla note commitment. The on-chain cmx must match the recomputed value.

The kernel lets any party recompute the expected cmx from the claimed fields and compare it to the value observed on chain. A match means the (name, UA) pair is the one the note actually committed to.


## Non-Negotiable Constraints (Default Build)

- `#![no_std]` when the `decrypt` feature is not enabled.
- `#![forbid(unsafe_code)]`
- `#![deny(missing_docs)]`
- Default dependencies are limited to: `blake2b_simd`, `pasta_curves`, `sinsemilla`, `bitvec`, `group`.
- The `decrypt` feature is opt-in only. It pulls additional crates and forces `std`.

## Current Module Structure

- `src/lib.rs` - crate root, re-exports, small helpers (`base_from_bytes`, `Rho`, `NoteCommitment` types).
- `src/memo.rs` - `Action`, chain rule (`Tip`, `prev_rcm_for`, `ZERO_PREV_RCM`), and the canonical memo parser/encoder (`parse_memo`, `parse_*_memo`, `encode_*`, `validate_name`).
- `src/commitment.rs` - domain tag, BLAKE2b derivation of (psi, rcm), and Sinsemilla note commitment (`zns_psi_rcm`, `note_commitment_cmx`, `ZNS_DOMAIN_TAG`).
- `src/verify.rs` - `verify_name_note` (the core binding check).
- `src/decrypt.rs` - gated behind the `decrypt` feature; relaxed Orchard trial decryption (`try_*_orchard*` functions).

Public API is reached primarily through the root re-exports.

## Chain Rule (Canonical in This Kernel)

The kernel defines the per-name transition rule in `memo.rs`:

```rust
pub struct Tip {
    pub action: Action,
    pub rcm: [u8; 32],
}

pub fn prev_rcm_for(tip: Option<&Tip>, action: Action) -> Option<[u8; 32]>;
```

Behavior (directly from the match):

- `Claim` on `None` or on a `Release` tip yields `ZERO_PREV_RCM`.
- `Update` or `Release` on a live (non-Release) tip yields the tip's `rcm`.
- All other combinations yield `None`.

`ZERO_PREV_RCM` is the all-zero 32-byte array and is the only valid predecessor for the first claim of a name (or a reclaim after release).

This function, together with `Action`, is the kernel's definition of legal name lifecycle steps. It is re-exported at the crate root.

## Memo Grammar

The grammar is implemented in `parse_memo` and the `encode_*` family (all in `memo.rs`).

Supported forms (from the code and tests):

- Request forms (no prev_rcm): `ZNS:claim:<name>:<ua>`, `ZNS:update:<name>:<ua>`, `ZNS:release:<name>`, plus `challenge` and `confirm`.
- Name Note forms (include prev_rcm as 64 lowercase hex): `ZNS:claim:<name>:<ua>:<prev_rcm>`, `ZNS:update:<name>:<ua>:<prev_rcm>`, `ZNS:release::<prev_rcm>` (empty ua slot is positional).

`parse_name_note_memo` is the convenience entry point that requires the prev_rcm form and returns the four values needed for verification.

The grammar is strict:

- Exact field counts. Extra fields after the expected set are rejected (using `split` followed by an explicit check for a sixth field).
- `prev_rcm` must be exactly 64 lowercase hex characters (manual decoder; uppercase and wrong length are rejected).
- Names must be 1-63 bytes, `a-z0-9-`, no leading or trailing hyphen (DNS label rule).
- RELEASE Name Note form uses an explicit empty ua field (`::`) so that the prev_rcm witness remains in a fixed column across all lifecycle actions.
- UTF-8 after stripping ZIP-302 trailing zero padding. Non-ZNS memos are rejected early with `NotZns`.

The design goal visible in the implementation and tests is that every correct consumer of the same memo bytes must extract identical `(action, name, ua, prev_rcm)` values. The parser rejects many "almost valid" inputs precisely to prevent divergent interpretations across implementations.

`encode_request` and `encode_name_note` are required to round-trip through `parse_memo`.

## Cryptographic Construction

### Domain tag and hash

From `commitment.rs`:

```rust
pub const ZNS_DOMAIN_TAG: &[u8] = b"ZcashName/v1";
```

`zns_psi_rcm` produces:

- `psi` as `pallas::Base::from_uniform_bytes(...)`
- `rcm` as `pallas::Scalar::from_uniform_bytes(...)`

Both are derived from `tagged_zns_hash` using distinct field tags (`b"psi"` and `b"rcm"`).

The hash construction (length-prefixed BLAKE2b-512):

```rust
let mut absorb_with_length_prefix = |b: &[u8]| {
    h.update(&(b.len() as u32).to_le_bytes());
    h.update(b);
};
absorb_with_length_prefix(ZNS_DOMAIN_TAG);
absorb_with_length_prefix(field_tag);
absorb_with_length_prefix(action);
absorb_with_length_prefix(name);
absorb_with_length_prefix(ua);
h.update(prev_rcm);   // raw, no length prefix
```

### Sinsemilla note commitment

`note_commitment_cmx` builds the message bits for `CommitDomain::new("z.cash:Orchard-NoteCommit").short_commit(...)`:

- `g_d` (256 bits, Lsb0)
- `pk_d` (256 bits, Lsb0)
- `value` (64 bits, little-endian bytes viewed as Lsb0)
- `rho` (first 255 bits)
- `psi` (first 255 bits)

`L_ORCHARD_BASE = 255`.

The function returns `Option<NoteCommitment>` (the x-coordinate). `None` occurs only for the identity point.

In `verify_name_note`, a `None` result is treated as a non-match.

## Verification Entry Point

```rust
pub fn verify_name_note(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    prev_rcm: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    expected_cmx: NoteCommitment,
) -> bool
```

It calls `zns_psi_rcm` then `note_commitment_cmx` and returns true only if the recomputed commitment x-coordinate equals the supplied value. Action, name, and ua bytes are passed through verbatim to the hash.

## Decrypt Feature (Feature-flag Gated)

The `decrypt` feature (Cargo.toml) adds `orchard`, `zcash_note_encryption`, `zcash_protocol`, and pinned versions of `chacha20` and `chacha20poly1305`. It forces `std`.

When enabled, the `decrypt` module provides:

- `try_compact_orchard` - compact-block trial decryption without the normal ZIP-212 cmx reconstruction/check.
- `try_decrypt_orchard` - full transaction trial decryption (still verifies the AEAD tag) that also returns the memo, again without the cmx validity check.
- `try_decrypt_orchard_sent` - full transaction "sent" recovery via OVK (used for the self-send authorization check on name notes).

All three are documented with the note that the commitment rule remains the caller's responsibility (via `verify_name_note`). The feature exists because Name Notes derive `(rcm, psi)` from the ZNS hash rather than from `rseed`, so standard Orchard decryption would discard them.

The feature is strictly opt-in; the default build has no dependency on orchard or the cipher crates.

## Test Vectors and Pinning

`tests/vectors.rs` contains a small set of cross-language vectors for `(action, name, ua, prev_rcm) -> (psi, rcm)`.

Additional tests (`commit_matches*`) pin full end-to-end cmx values for the same constructions.

The vectors are the interoperability contract. Existing entries are not modified when the code changes.

`verify_tests.rs` re-uses the pinned cmx values to test that `verify_name_note` accepts the correct tuple and rejects tampered fields.

## Exact Construction Contract (for Ports or Independent Re-Implementations)

Any implementation that must produce identical results for the same inputs must match these details exactly (all taken directly from the source):

- Domain separation tag is the bytes `b"ZcashName/v1"`.
- Five length-prefixed fields (u32 little-endian length, then content) in order: domain tag, field tag, action, name, ua.
- `prev_rcm` (32 bytes) is appended raw after the five prefixed items.
- `psi` uses `pallas::Base::from_uniform_bytes` on the 64-byte output.
- `rcm` uses `pallas::Scalar::from_uniform_bytes` on the 64-byte output.
- Sinsemilla personalization is exactly `"z.cash:Orchard-NoteCommit"`.
- Bit order is `Lsb0` for all fields.
- Value is serialized as 8-byte little-endian before bit view.
- `rho` and `psi` each contribute exactly the first 255 bits.
- Commitment uses `short_commit`, not the full commit method.
- `note_commitment_cmx` returns `None` (treated as mismatch in verification) if the resulting point is the identity.

Changes to any of the above require a domain tag version bump and new vectors.

## How to Build and Test

- Default (pure kernel): `cargo test`
- With decrypt feature: `cargo test --features decrypt`
- Documentation: `cargo doc --no-deps`
- Clippy: `cargo clippy --all-features`

## QUESTIONS 

i) are we handling the pallas vectors correctly? (i.e., are we using the correct endianness and bit order for the inputs and outputs of the hash and Sinsemilla functions?)

ii) is the memo parser strict enough to prevent divergent interpretations across implementations? (e.g., are we rejecting extra fields, uppercase hex, invalid names, etc.?) while still being useful for wallets and resolvers?

iii) is the note commitment construction correct and consistent with the Orchard spec? (e.g., are we using the right personalization, bit order, and field serialization?)
