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
- `memo::parse_memo` / `memo::encode_*` — the canonical ZNS memo grammar.
  One strict parser shared by registry, resolver, and slash contract
  (`DESIGN.md §17`); agreement is by construction.
- `memo::prev_rcm_for` — the per-name transition rule (`DESIGN.md §5`):
  which `prev_rcm` an action must extend, given the name's tip.

This kernel is the protocol's shared core — the crypto plus the two pure
rules every party must compute identically — which is what lets it drop
unchanged into a wallet, SDK, resolver, enclave, or embedded target.

## Footprint

`#![no_std]`, `#![forbid(unsafe_code)]`, and no `orchard` dependency.
Production dependencies: `blake2b_simd`, `pasta_curves`, `sinsemilla`,
`bitvec`, `group`.

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
