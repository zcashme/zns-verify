# zns-verify

The ZcashName verification kernel recomputes Ironwood Name Note commitments so
wallets and resolvers need not trust an indexer for hash math. It does **not** by
itself prove that the Mint Registry authorised a transition; see [Trust
boundary](#trust-boundary) below.

A ZcashName binding lives inside a Name Note's commitment, through the note's
`cmx`. A Name Note is a bound note: its `rseed` is a deterministic hash of its
memo fields and its predecessor (WP §4.4), and its `(rcm, ψ)` follow
from that `rseed` as for any Ironwood note.

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
and the Mint's full viewing key is published (WP §8.1) so any resolver can
decrypt them. The bound user UA lives in the memo and the commitment, not in
the note's recipient.

## Bound Name Notes

A Name Note is a bound note (WP §4.4):

- Binding domain: `ZNS___Name_Notes`, the BLAKE2b personalization.
- Kind: `0x01` for every Name Note. The verb is the first field.
- Fields: the memo text between `ZNS:` and the predecessor,
  `action:name:ua:expires_at`, then `:terms` for a list or an auction.
- Predecessor: the cmx of the note this one spends, or 32 zero bytes for a
  claim.

`rseed = BLAKE2b-256(domain, kind ‖ I2LEOSP64(len(fields)) ‖ fields ‖ prev)`.
ψ and rcm follow from the `rseed` by the Ironwood (lead byte `0x03`)
derivations of ZIP 2005, so a standard receiver decrypts a Name Note and
recomputes its `cmx`.

zns-verify 0.2.1 is the last release that also reads the earlier rcm/ψ Name
Notes, whose `(rcm, ψ)` came straight from the record.

## What it does

- `name_note_rseed(fields, prev)` -- derive a Name Note's `rseed` from its
  memo fields and its predecessor (WP §4.4). `Memo::fields` gives the fields.
- `psi_from_rseed` / `rcm_from_rseed` -- the Ironwood derivations from an `rseed`.
- `note_commitment_cmx(...)` -- recompute the Sinsemilla note commitment.
- `verify_bound_name_note(...)` -- recompute and compare against `cmx`, returning
  `true` when the memo fields are **consistent** with the note (not when the
  transition is **authorised**; see [Trust boundary](#trust-boundary)). It
  checks an Ironwood note only.
- `authorized_transition(...)` -- the Registry spend check: the transaction
  reveals this name's live tip (or exactly one claim anchor), and `prev`
  extends that tip. Both this and `verify_bound_name_note` have to hold.
- `NameNote::parse(&Memo)` / `note.encode()` -- the canonical Name Note memo
  grammar (`Claim`, `Update`, `Release`, `Sale`, `List`, `Auction`, `Delist`)
  with validated field types (`Name`, `Ua`, `Expiry`, `PrevCmx`). A list's terms
  are `t1:price` and an auction's are `t1:start:min:start-block:end-block`,
  between the expiry and the predecessor.
- `prev_for` -- the per-name transition rule: which predecessor an action must extend.
- The canonical strict Name Note memo grammar (one parser for registry, resolver, etc.).
- Out of scope: request memos (user -> Mint treasury intake). They are never
  committed on chain and have no role in verification.

This kernel is the protocol's shared core -- the crypto plus the chain-shape
and spend rules every party must compute identically. It has no dependencies
that keep it out of a wallet, SDK, resolver, enclave, or embedded target. A
consumer that turns names into payment addresses calls `authorized_transition`
with the nullifiers it stored; `verify_bound_name_note` alone does not resolve
a name (see [Trust boundary](#trust-boundary)).

## Features & capabilities

- **Pure verification kernel** (default): `no_std`, no orchard, minimal math-only
  dependencies (`blake2b_simd`, `pasta_curves`, `sinsemilla`, `group`).
  Small enough for wallets, SDKs, enclaves, or embedded targets (see [Trust
  boundary](#trust-boundary) for what it does not check).
- **`decrypt` feature** (opt-in): Ironwood trial decryption of Name Notes on
  upstream `IronwoodDomain` (V3 note plaintexts, lead byte `0x03`). Pulls
  crates.io `orchard` and forces `std`.
- `NameNote<'a>` -- seven-variant enum representing a committed on-chain Name Note.
- `Name<'a>`, `Ua<'a>`, `Expiry<'a>`, `PrevCmx` -- validated domain types.
- `Memo` -- zero-padded ZIP-302 memo with canonical padding enforcement.
- `Rho`, `ExtractedNoteCommitment` -- newtypes with canonical byte codecs.
- Strict Name Note memo grammar with exact field counts, ZNS name rules
  (`a-z 0-9`, 1-63 bytes), and a 64-lowercase-hex predecessor.
- `Action` enum and name validation (`Name::parse`).
- Lifecycle / chain rules (`prev_for`, `Tip`) and the spend rule
  (`authorized_transition`).
- `MemoError` for all grammar violations.
- Re-exports for `pallas` and `PrimeField` (so you don't need direct curve dependencies).
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- "Recompute, don't trust" for **commitment math** -- no reliance on a registry
  or indexer to tell you whether `(action, name, ua, …)` matches `cmx`. Spend
  lineage is `authorized_transition`. Term and liveness clocks stay with the
  mint (see [Trust boundary](#trust-boundary)).

## Trust boundary

In ZNS, authority to bind a name comes from the Registry spend key creating a
Name Note by spending the right predecessor (claim anchor or live tip).
`verify_bound_name_note` does not see that spend. `authorized_transition` does,
from the nullifiers the caller supplies.

`verify_bound_name_note` takes an already-parsed `NameNote` and the note
components the caller supplies (`g_d`, `pk_d`, `value`, `rho`). It re-derives
the `rseed` from the note's fields, then `(ψ, rcm)`, recomputes the note
commitment, and returns `true` when that equals the supplied `cmx`. That is
the whole check. It does not see a tip, does not call `prev_for`, and does not
parse the memo (`NameNote::parse` does that, separately).

Because the `rseed` is a hash of public fields, anyone can create a zero-value
note to the published registry address whose commitment verifies, copying a
public tip's `cmx` as its predecessor. That note also passes `NameNote::parse`
and `prev_for`.

`authorized_transition` is the spend check. It is true when `prev` extends the
tip you pass and the transaction's revealed nullifiers are the predecessor
that action requires: this name's live tip for every action but a claim, or
exactly one live anchor for a claim. A second live name, or an anchor spent
beside an update, is refused. The forged note fails it unless the transaction
reveals the stored tip nullifier, which only the Registry key can do.

A binding needs both results.

## Footprint

`#![no_std]` (except with the `decrypt` feature), `#![forbid(unsafe_code)]`,
and minimal dependencies. Production crates: `blake2b_simd`, `pasta_curves`,
`sinsemilla`, `group`.

## Usage

```rust
use zns_verify::{verify_bound_name_note, ExtractedNoteCommitment, Memo, NameNote, Rho};

# let g_d: [u8; 32] = hex::decode("de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e").unwrap().try_into().unwrap();
# let pk_d: [u8; 32] = hex::decode("6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996").unwrap().try_into().unwrap();
# let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
# let on_chain_cmx = ExtractedNoteCommitment::from_bytes(
#     &<[u8; 32]>::try_from(
#         hex::decode("617b189869560cdd3928456693c1d4060752f18173425294141641e4b05d0f1a").unwrap(),
#     )
#     .unwrap(),
# )
# .unwrap();

// The claim of WP §4.6, as its memo appears on chain.
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
