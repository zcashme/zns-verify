# zns-verify

The ZcashName verification kernel — the minimal primitive the trust model rests
on.

A ZcashName binding lives inside a Name Note's commitment. Its `(rcm, ψ)` are a
deterministic hash of `(action, name, ua, prev_rcm)`, and the chain commits to
that hash through the note's `cmx`. This crate recomputes the commitment from
the note's fields and compares it to the on-chain `cmx`. Match: the
`(name → ua)` binding is real. No match: it isn't — and you reached that
conclusion without trusting any registry, resolver, or indexer.

That is the entire point. Resolution can come from anywhere, because anyone can
check the answer here.

## What it does

- `zns_psi_rcm(action, name, ua, prev_rcm) -> (ψ, rcm)` — re-derive the
  deterministic commitment randomness.
- `note_commitment_cmx(...)` — recompute the Sinsemilla note commitment.
- `verify_name_note(...)` — both at once: recompute and compare against `cmx`,
  returning a plain `bool`.
- `memo::parse_memo` / `memo::encode_*` — the canonical ZNS memo grammar.
  One strict parser shared by registry, resolver, and slash contract
  (`DESIGN.md §17`); agreement is by construction.
- `chain::prev_rcm_for` — the per-name transition rule (`DESIGN.md §5`):
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
use group::ff::PrimeField;
use pasta_curves::pallas;
use zns_verify::{parse_name_note_memo, verify_name_note, NameAction};

// For verifying a Name Note that was actually committed on chain,
// parse directly to the inputs it claims were used.
let NameAction { action, name, ua, prev_rcm } =
    parse_name_note_memo(b"ZNS:claim:alice:u1xxx:0000000000000000000000000000000000000000000000000000000000000000")?;

# let (g_d, pk_d) = ([0x11u8; 32], [0x22u8; 32]);
# let rho = pallas::Base::from_repr([0x33u8; 32]).unwrap();
# let on_chain_cmx = pallas::Base::from_repr(
#     <[u8; 32]>::try_from(
#         hex::decode("53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02").unwrap(),
#     )
#     .unwrap(),
# )
# .unwrap();

// Feed the pieces (you still control the source of each one) into the
// explicit verification function.
let ok = verify_name_note(
    action, name, ua, &prev_rcm,
    g_d, pk_d, 0, rho,
    on_chain_cmx,
);
assert!(ok);
# Ok::<(), zns_verify::memo::MemoError>(())
```
