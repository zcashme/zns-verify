# zns-verify

The ZcashName verification kernel recomputes Ironwood Name Note commitments so
wallets and resolvers need not trust an indexer for hash math. It does **not** by
itself prove that the Mint Registry authorised a transition; see [Trust
boundary](#trust-boundary) below.

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
  skips the `cmx` check, but keeps the AEAD authentication; the `cmx`
  consistency check moves to `verify_name_note`.

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
- `name_note_nullifier(...)` (`decrypt`) -- the nullifier to store as the next
  tip, from the decrypted note and the `(ψ, rcm)` opening.
- `NameNote::parse(&Memo)` / `note.encode()` -- the canonical Name Note memo
  grammar as a three-variant enum (`Claim` / `Update` / `Release`) with validated
  field types (`Name`, `Ua`, `Expiry`, `PrevRcm`).
- `prev_rcm_for` -- the per-name transition rule: which `prev_rcm` an action must extend.
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
  the ZIP-212 `cmx` check. Uses `IronwoodDomain` (V3 note plaintexts, lead byte
  `0x03`). Useful for scanning Name Notes. Pulls `orchard` + pinned ciphers and
  forces `std`.
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
`(ψ, rcm)` opening. With the `decrypt` feature, `name_note_nullifier` turns that
opening and the decrypted note into the nullifier to store as the next tip.

## Footprint

`#![no_std]` (except with the `decrypt` feature), `#![forbid(unsafe_code)]`,
and minimal dependencies. Production crates: `blake2b_simd`, `pasta_curves`,
`sinsemilla`, `group`.

## Usage

```rust
use zns_verify::{verify_name_note, ExtractedNoteCommitment, Memo, NameNote, Rho};

# let g_d: [u8; 32] = hex::decode("de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e").unwrap().try_into().unwrap();
# let pk_d: [u8; 32] = hex::decode("6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996").unwrap().try_into().unwrap();
# let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
# let on_chain_cmx = ExtractedNoteCommitment::from_bytes(
#     &<[u8; 32]>::try_from(
#         hex::decode("cc320736a0c1df1e4ffcee2b64aa73a9e6d06bb218e155a6fef422e1ecb1f70c").unwrap(),
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
let consistent = verify_name_note(
    &note,
    g_d, pk_d, 0, rho, on_chain_cmx,
);
assert!(consistent);

# Ok::<(), zns_verify::MemoError>(())
```
