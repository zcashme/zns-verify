# zns-verify

The ZcashName verification kernel — the minimal primitive the trust model rests
on.

A ZcashName binding lives inside a Name Note's commitment. Its `(rcm, ψ)` are a
deterministic hash of `(action, name, ua, prev_rcm)`, and the chain commits to
that hash through the note's `cmx`. This crate recomputes the commitment from
the note's fields and compares it to the on-chain `cmx`. 


## What it does

- `zns_psi_rcm(action, name, ua, prev_rcm) -> (ψ, rcm)` — re-derive the
  deterministic commitment randomness.
- `note_commitment_cmx(...)` — recompute the Sinsemilla note commitment.
- `verify_name_note(...)` — both at once: recompute and compare against `cmx`,
  returning a plain `bool`.
- `parse_name_note` — parse a committed on-chain Name Note into a `NameNote`.
- `parse_claim_memo` / `parse_update_memo` / `parse_release_memo` — parse user request memos.
- `encode_*` — encoders for requests and Name Notes (round-trip with the parser).
- `prev_rcm_for` — the per-name transition rule: which `prev_rcm` an action must extend.
- The canonical strict ZNS memo grammar (one parser for registry, resolver, etc.).

This kernel is the protocol's shared core — the crypto plus the two pure
rules every party must compute identically — which is what lets it drop
unchanged into a wallet, SDK, resolver, enclave, or embedded target.

## Features & capabilities

- **Pure verification kernel** (default): `no_std`, no orchard, minimal math-only
  dependencies (`blake2b_simd`, `pasta_curves`, `sinsemilla`, `bitvec`, `group`).
  Intended to be dropped into wallets, SDKs, enclaves, or embedded targets.
- **`decrypt` feature** (opt-in): relaxed Orchard trial decryption that skips
  the ZIP-212 `cmx` check. Useful for scanning Name Notes. Pulls `orchard` +
  pinned ciphers and forces `std`.
- `NameNote<'a>` — clean struct representing a committed on-chain Name Note
  (with guaranteed `prev_rcm` witness).
- Full strict ZNS memo grammar with exact field counts, DNS-label name rules,
  and 64-lowercase-hex `prev_rcm`.
- `Action` enum and name validation (`validate_name`).
- Lifecycle / chain rules (`prev_rcm_for`, `Tip`, `ZERO_PREV_RCM`).
- `MemoError` for all grammar violations.
- `base_from_bytes` / `cmx_from_bytes` helpers.
- Re-exports for `pallas` and `PrimeField` (so you don't need direct curve dependencies).
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- "Recompute, don't trust" design — fully standalone verification with no
  reliance on registry/resolver/indexer.
- Support for `prev_rcm` as a witness (enables single-note verification,
  tail-scan backstops, and fraud proofs).

## Footprint

`#![no_std]` (except with the `decrypt` feature), `#![forbid(unsafe_code)]`,
and minimal dependencies. Production crates: `blake2b_simd`, `pasta_curves`,
`sinsemilla`, `bitvec`, `group`.

## Usage

```rust
use zns_verify::{
    parse_claim_memo, parse_name_note, parse_release_memo, parse_update_memo, verify_name_note,
    ZERO_PREV_RCM,
};

# let (g_d, pk_d) = ([0x11u8; 32], [0x22u8; 32]);
# let rho = zns_verify::base_from_bytes([0x33u8; 32]);
# let on_chain_cmx = zns_verify::base_from_bytes(
#     <[u8; 32]>::try_from(
#         hex::decode("53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02").unwrap(),
#     )
#     .unwrap(),
# );

// Claim request memo (user → registry)
let (action, name, ua) = parse_claim_memo(b"ZNS:claim:alice:u1xxx")?;

// Similarly:
let (action, name, ua) = parse_update_memo(b"ZNS:update:alice:u1new")?;
let (action, name, ua) = parse_release_memo(b"ZNS:release:alice")?;
let ok = verify_name_note(
    action, name, ua, &ZERO_PREV_RCM,
    g_d, pk_d, 0, rho, on_chain_cmx,
);

// Name Note memo (from on chain)
let note = parse_name_note(
    b"ZNS:claim:alice:u1xxx:0000000000000000000000000000000000000000000000000000000000000000"
)?;
let ok = verify_name_note(
    note.action.as_bytes(),
    note.name.as_bytes(),
    note.ua.as_bytes(),
    &note.prev_rcm,
    g_d, pk_d, 0, rho, on_chain_cmx,
);

# Ok::<(), zns_verify::MemoError>(())
```
