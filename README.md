# zns-verify

The ZcashName verification kernel recomputes Ironwood Name Note commitments so
wallets and resolvers need not trust an indexer for hash math. It does **not** by
itself prove that the Mint Registry authorised a transition; see [Trust
boundary](#trust-boundary) below.

A ZcashName binding lives inside a Name Note's commitment, through the note's
`cmx`. An rcm/ψ Name Note's `(rcm, ψ)` are a deterministic hash of
`(action, name, ua, expires_at, prev_rcm)`. A bound Name Note's `rseed` is a
deterministic hash of the same record, and its `(rcm, ψ)` follow from that
`rseed` (see [Bound Name Notes](#bound-name-notes)).

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

## Why Standard Decryption Rejects rcm/ψ Name Notes

- Standard ZIP-212 derives `rcm` from `rseed` and checks the recomputed `cmx` against the on-chain value.
- An rcm/ψ Name Note's `rcm` comes from `zns_psi_rcm(action, name, ua, expires_at, prev_rcm)`, not `rseed`.
- So `zcash_note_encryption`'s `try_decrypt` returns `None` for every valid rcm/ψ Name Note.
- A bound Name Note's `rcm` does come from its `rseed`, so standard decryption accepts it.
- The `decrypt` feature wraps upstream `IronwoodDomain` (accepts V3 lead byte
  `0x03`), passes the published `cmx` through instead of re-deriving it, and
  keeps the AEAD authentication. It returns both kinds of Name Note; the `cmx`
  consistency check moves to `verify_name_note` or `verify_bound_name_note`.

## What it does

- `zns_psi_rcm(action, name, ua, expires_at, prev_rcm) -> (ψ, rcm)` -- re-derive the
  deterministic commitment randomness.
- `note_commitment_cmx(...)` -- recompute the Sinsemilla note commitment.
- `verify_name_note(...)` -- recompute and compare against `cmx`, returning
  `true` when the memo fields are **consistent** with the note (not when the
  transition is **authorised**; see [Trust boundary](#trust-boundary)).
- `verify_name_note_with_witness(...)` -- same, returning the re-derived `(ψ, rcm)`
  opening on match.
- `authorized_transition(...)` -- the Registry spend check: the transaction
  reveals this name's live tip (or exactly one claim anchor), and `prev_rcm`
  extends that tip. Both this and `verify_name_note` have to hold.
- `NameNote::parse(&Memo)` / `note.encode()` -- the canonical Name Note memo
  grammar (`Claim`, `Update`, `Release`, `Sale`, `List`, `Auction`, `Delist`)
  with validated field types (`Name`, `Ua`, `Expiry`, `PrevRcm`). A list's terms
  are `t1:price` and an auction's are `t1:start:min:start-block:end-block`,
  between the expiry and the predecessor.
- `prev_rcm_for` -- the per-name transition rule: which `prev_rcm` an action must extend.

### Bound Name Notes

Name Notes are moving to bound notes (zcashme/zns-mint#480): the note's `rseed`
is computed from its record, and ψ and rcm follow from that `rseed` as for any
Ironwood note. The memo grammar is the same; the last field holds the
predecessor's `cmx` instead of its `rcm`.

- `name_note_rseed(action, name, ua, expires_at, terms, prev)` -- BLAKE2b-256
  with personalization `ZNS___Name_Notes` over `0x01 ‖ I2LEOSP64(len) ‖
  action:name:ua:expires_at[:terms] ‖ prev`. Empty `terms` is a claim, update,
  release, sale, or delist.
- `psi_from_rseed` / `rcm_from_rseed` -- the Ironwood derivations from an `rseed`.
- `verify_bound_name_note(...)` -- the commitment check for a bound Name Note
  (consistent, not authorised, as above). `authorized_transition` applies as
  is, with the tip's `cmx` in `Tip::rcm`.

A caller knows which kind of Name Note it is checking from where it reads it:
notes from before the Registry's move are rcm/ψ notes (`verify_name_note`),
notes after it are bound notes (`verify_bound_name_note`).
- The canonical strict Name Note memo grammar (one parser for registry, resolver, etc.).
- Out of scope: request memos (user -> Mint treasury intake). They are never
  committed on chain and have no role in verification.

This kernel is the protocol's shared core -- the crypto plus the chain-shape
and spend rules every party must compute identically. It has no dependencies
that keep it out of a wallet, SDK, resolver, enclave, or embedded target. A
consumer that turns names into payment addresses calls `authorized_transition`
with the nullifiers it stored; `verify_name_note` alone does not resolve a name
(see [Trust boundary](#trust-boundary)).

## Features & capabilities

- **Pure verification kernel** (default): `no_std`, no orchard, minimal math-only
  dependencies (`blake2b_simd`, `pasta_curves`, `sinsemilla`, `group`).
  Small enough for wallets, SDKs, enclaves, or embedded targets (see [Trust
  boundary](#trust-boundary) for what it does not check).
- **`decrypt` feature** (opt-in): relaxed Ironwood trial decryption that skips
  the ZIP-212 `cmx` check. Wraps upstream `IronwoodDomain` (V3 note plaintexts,
  lead byte `0x03`). Useful for scanning Name Notes. Pulls crates.io `orchard`
  and forces `std`.
- `NameNote<'a>` -- three-variant enum representing a committed on-chain Name Note.
- `Name<'a>`, `Ua<'a>`, `Expiry<'a>`, `PrevRcm` -- validated domain types.
- `Memo` -- zero-padded ZIP-302 memo with canonical padding enforcement.
- `Rho`, `ExtractedNoteCommitment` -- newtypes with canonical byte codecs.
- Strict Name Note memo grammar with exact field counts, ZNS name rules
  (`a-z 0-9`, 1-63 bytes), and 64-lowercase-hex `prev_rcm`.
- `Action` enum and name validation (`Name::parse`).
- Lifecycle / chain rules (`prev_rcm_for`, `Tip`, `ZERO_PREV_RCM`) and the
  spend rule (`authorized_transition`).
- `MemoError` for all grammar violations.
- Re-exports for `pallas` and `PrimeField` (so you don't need direct curve dependencies).
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- "Recompute, don't trust" for **commitment math** -- no reliance on a registry
  or indexer to tell you whether `(action, name, ua, …)` matches `cmx`. Spend
  lineage is `authorized_transition`. Term and liveness clocks stay with the
  mint (see [Trust boundary](#trust-boundary)).
- Support for `prev_rcm` as a witness (enables single-note verification,
  tail-scan backstops, and fraud proofs).

## Trust boundary

In ZNS, authority to bind a name comes from the Registry spend key creating a
Name Note by spending the right predecessor (claim anchor or live tip).
`verify_name_note` does not see that spend. `authorized_transition` does, from
the nullifiers the caller supplies.

`verify_name_note` takes an already-parsed `NameNote` and the note components
the caller supplies (`g_d`, `pk_d`, `value`, `rho`). It re-derives `(ψ, rcm)`
from the note's fields, recomputes the note commitment, and returns `true` when
that equals the supplied `cmx`. That is the whole check. It does not see a tip,
does not call `prev_rcm_for`, and does not parse the memo (`NameNote::parse`
does that, separately).

Because `(ψ, rcm)` are hashes of public fields, anyone can create a zero-value
note to the published registry address whose commitment verifies, copying a
public tip's `rcm` as `prev_rcm`. That note also passes `NameNote::parse` and
`prev_rcm_for`.

`authorized_transition` is the spend check. It is true when `prev_rcm` extends
the tip you pass and the transaction's revealed nullifiers are the predecessor
that action requires: this name's live tip for an update or release, or exactly
one live anchor for a claim. A second live name, or an anchor spent beside an
update, is refused. The forged note fails it unless the transaction reveals the
stored tip nullifier, which only the Registry key can do.

A binding needs both results. `verify_name_note_with_witness` returns the
`(ψ, rcm)` opening, from which the caller derives the nullifier to store as the
next tip.

All of this holds for bound Name Notes, with `verify_bound_name_note` as the
commitment check: their `rseed` is a hash of public fields too, so a forged
bound note verifies just as easily, and only the Registry spend separates it.

## Footprint

`#![no_std]` (except with the `decrypt` feature), `#![forbid(unsafe_code)]`,
and minimal dependencies. Production crates: `blake2b_simd`, `pasta_curves`,
`sinsemilla`, `group`.

## Usage

```rust
use zns_verify::{verify_bound_name_note, ExtractedNoteCommitment, Memo, NameNote, Rho};

# let g_d: [u8; 32] = hex::decode("dd0c23bc9720ff21aaab76a7b7276231ee212f156e9c318c355972628efed408").unwrap().try_into().unwrap();
# let pk_d: [u8; 32] = hex::decode("81a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d").unwrap().try_into().unwrap();
# let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
# let on_chain_cmx = ExtractedNoteCommitment::from_bytes(
#     &<[u8; 32]>::try_from(
#         hex::decode("a8e6da4a73de6efa14c13e565a8701f210b17e4de4b067a41a41910383b9da18").unwrap(),
#     )
#     .unwrap(),
# )
# .unwrap();

// Name Note memo (from on chain)
let memo = Memo::from_bytes(
    b"ZNS:claim:alice:u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q:none:0000000000000000000000000000000000000000000000000000000000000000",
)?;
let note = NameNote::parse(&memo)?;
// `consistent` means the memo fields reproduce `cmx`. The Registry spend is
// `authorized_transition`, a separate call (see Trust boundary).
let consistent = verify_bound_name_note(
    &note,
    g_d, pk_d, 0, rho, on_chain_cmx,
);
assert!(consistent);

# Ok::<(), zns_verify::MemoError>(())
```
