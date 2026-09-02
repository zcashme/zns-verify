# zns-verify

The ZcashName verification kernel turns Ironwood note commitments into a name system without adding any trust.

A ZcashName binding lives inside a Name Note's commitment whose `(rcm, ψ)` are a
deterministic hash of `(action, name, ua, expires_at, prev_rcm)` -- this leaves an on-chain record to
that hash through the note's `cmx`.

The zns-verify crate recomputes the commitment from
the note's fields and compares it to the on-chain `cmx`.

## Name Notes are Ironwood-pool notes

Name Notes live in the Ironwood shielded pool (ZIP 2005, NU6.3), not the
Orchard pool. Ironwood is an Orchard-protocol pool: it reuses the same Pallas
curves, Sinsemilla commitments, Action encoding, and key components. The
differences are at the state layer (separate note commitment tree, nullifier
set, value pool) and in the note plaintext: Ironwood notes carry V3 plaintexts
(lead byte `0x03`) rather than V2 (`0x02`).

At NU6.3 the Orchard pool is frozen -- cross-address transfers are disabled
(`enableCrossAddress` must be 0, enforced by the circuit). Name Notes move
between the Mint's own accounts (treasury -> registry), which is inherently a
cross-address transfer, so Name Notes must be in the Ironwood pool.

Name Notes are public record: they are minted to the Mint's registry account,
and the Mint's full viewing key is published (WP §6) so any resolver can
decrypt them. The bound user UA lives in the memo and the commitment, not in
the note's recipient.

## Why Standard Decryption Rejects Name Notes

- Standard ZIP-212 derives `rcm` from `rseed` and checks the recomputed `cmx` against the on-chain value.
- A Name Note's `rcm` comes from `zns_psi_rcm(action, name, ua, expires_at, prev_rcm)`, not `rseed`.
- So `zcash_note_encryption`'s `try_decrypt` returns `None` for every valid Name Note.
- The `decrypt` feature uses `IronwoodDomain` (accepts V3 lead byte `0x03`),
  skips the `cmx` check, but keeps the AEAD authentication; binding integrity
  moves to `verify_name_note`.

## What it does

- `zns_psi_rcm(action, name, ua, expires_at, prev_rcm) -> (ψ, rcm)` -- re-derive the
  deterministic commitment randomness.
- `note_commitment_cmx(...)` -- recompute the Sinsemilla note commitment.
- `verify_name_note(...)` -- both at once: recompute and compare against `cmx`,
  returning a plain `bool`.
- `parse_name_note` -- parse a committed on-chain Name Note into a `NameNote`.
- `encode_name_note` -- encode a Name Note memo (round-trip with the parser).
- `prev_rcm_for` -- the per-name transition rule: which `prev_rcm` an action must extend.
- The canonical strict Name Note memo grammar (one parser for registry, resolver, etc.).
- Out of scope: request memos (user -> Mint treasury intake). They are never
  committed on chain and have no role in verification.

This kernel is the protocol's shared core -- the crypto plus the two pure
rules every party must compute identically -- which is what lets it drop
unchanged into a wallet, SDK, resolver, enclave, or embedded target.

## Features & capabilities

- **Pure verification kernel** (default): `no_std`, no orchard, minimal math-only
  dependencies (`blake2b_simd`, `pasta_curves`, `sinsemilla`, `group`).
  Intended to be dropped into wallets, SDKs, enclaves, or embedded targets.
- **`decrypt` feature** (opt-in): relaxed Ironwood trial decryption that skips
  the ZIP-212 `cmx` check. Uses `IronwoodDomain` (V3 note plaintexts, lead byte
  `0x03`). Useful for scanning Name Notes. Pulls `orchard` + pinned ciphers and
  forces `std`.
- `NameNote<'a>` -- clean struct representing a committed on-chain Name Note
  (with guaranteed `prev_rcm` witness).
- Strict Name Note memo grammar with exact field counts, ZNS name rules,
  and 64-lowercase-hex `prev_rcm`.
- `Action` enum and name validation (`validate_name`).
- Lifecycle / chain rules (`prev_rcm_for`, `Tip`, `ZERO_PREV_RCM`).
- `MemoError` for all grammar violations.
- `base_from_bytes` helper.
- Re-exports for `pallas` and `PrimeField` (so you don't need direct curve dependencies).
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- "Recompute, don't trust" design -- fully standalone verification with no
  reliance on registry/resolver/indexer.
- Support for `prev_rcm` as a witness (enables single-note verification,
  tail-scan backstops, and fraud proofs).

## Footprint

`#![no_std]` (except with the `decrypt` feature), `#![forbid(unsafe_code)]`,
and minimal dependencies. Production crates: `blake2b_simd`, `pasta_curves`,
`sinsemilla`, `group`.

## Usage

```rust
use zns_verify::{verify_name_note, ExtractedNoteCommitment, Memo, NameNote, Rho};

# let g_d: [u8; 32] = [0x11u8; 32];
# let pk_d: [u8; 32] = [0x22u8; 32];
# let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
# let on_chain_cmx = ExtractedNoteCommitment::from_bytes(
#     &<[u8; 32]>::try_from(
#         hex::decode("53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02").unwrap(),
#     )
#     .unwrap(),
# )
# .unwrap();

// Name Note memo (from on chain)
let memo = Memo::from_bytes(
    b"ZNS:claim:alice:u1xxx:none:0000000000000000000000000000000000000000000000000000000000000000",
)?;
let note = NameNote::parse(&memo)?;
let ok = verify_name_note(
    &note,
    g_d, pk_d, 0, rho, on_chain_cmx,
);

# Ok::<(), zns_verify::MemoError>(())
```
