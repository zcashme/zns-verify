# Threat Model for zns-verify

**ZcashName (ZNS) Verification Kernel -- the minimal primitive the trust model rests on.**

This document expands the adversaries and attack trees from the Security Review Plan (`docs/SECURITY_REVIEW_PLAN.md`) into concrete attack stories. Each story is written from the perspective of the security review plan: precise about the verification kernel, line-specific where possible, tied to the assets, invariants, and non-negotiables defined in the plan.

## Assets (from SECURITY_REVIEW_PLAN.md)

1. Name ownership binding correctness -- `verify_name_note` returns true iff the `(name -> ua)` binding matches the on-chain `cmx`.
2. Slashability -- the memo grammar is identical across registry, resolver, and any future slash contract (DESIGN.md section 17).
3. Wallet scanning correctness -- `decrypt` + `verify_name_note` correctly identify Name Notes addressed to an IVK without false positives/negatives.
4. Cross-impl consensus -- all implementations produce identical `(psi, rcm, cmx)` for the same inputs.

## Adversaries and Attack Stories

The following table is reproduced from the plan. Each entry is followed by a detailed attack story.

| Adversary | Capabilities | Goals |
|-----------|--------------|-------|
| **Malicious registry minter** | Controls `sk_R`; authors all Name Notes | Forge bindings, double-mint, equivocate |
| **Withholding / lying resolver** | Controls index, may drop or alter data | Prevent verification, cause resolution forks |
| **Chain observer / network attacker** | Sees all memos, can reorder, replay | Confusion, DoS on resolution |
| **Compromised dependency** | Malicious update to `blake2b_simd`, `sinsemilla`, `pasta_curves`, etc. | Subvert hashes, commitments, field math |
| **Malicious user feeding bad memos** | Submits crafted memos to wallet/resolver | Trigger parser differentials, DoS |
| **Supply-chain attacker** | Poisons crates.io, git, build env | Inject code or alter vectors |

---

### 1. Malicious Registry Minter

**Capabilities**: Controls the Orchard spending key `sk_R` used to create valid Name Notes. Decides the exact `(action, name, ua, prev_rcm)` tuple that is placed in the memo and used to derive `psi`/`rcm` for every Name Note on chain. Can produce ciphertexts and commitments that will pass standard Orchard validation.

**Goals**: Forge bindings (make a verifier conclude `name` maps to an address the minter chose rather than the one the rightful registrant intended), double-mint (have two live owners for the same name), equivocate (different honest parties reach different conclusions about current ownership from the same on-chain notes).

**Attack Story: Double-Mint via Genesis Claim on Live Name**

The minter has already processed (or directly emitted) a legitimate `Claim` for "alice" -> victim_ua. A live tip exists:

```
Tip { action: Claim, rcm: <victim_rcm> }
```

Per the chain rule (src/lib.rs:89-98 in `prev_rcm_for`), a second `Claim` must be rejected:

```rust
(Action::Claim, Some(t)) if t.action != Release => None   // live tip blocks new Claim
```

The minter, however, authors a second Name Note anyway:

- action = "claim"
- name = "alice"
- ua = "u1attacker..."
- prev_rcm = ZERO_PREV_RCM  (the genesis value, src/lib.rs:208)

They call `zns_psi_rcm` (src/lib.rs:214) with these values. Because the length-prefixed hash (src/lib.rs:242-247) and subsequent Sinsemilla `note_commitment_cmx` (src/lib.rs:170) are pure functions of the inputs the minter chose, they obtain a `(psi, rcm)` and a `cmx` that is a perfectly valid on-chain commitment for *those exact inputs*.

They mint the Orchard note carrying the canonical memo:

```
ZNS:claim:alice:u1attacker...:0000000000000000000000000000000000000000000000000000000000000000
```

(See memo encoding at src/lib.rs:595 and the RELEASE positional-empty rule at 521-525 for contrast.)

Any party that calls only `verify_name_note` (src/lib.rs:915) with the fields parsed from this memo plus the note's `(g_d, pk_d, value, rho, expected_cmx)` will obtain:

```rust
let (psi, rcm) = zns_psi_rcm(...);
let cmx = note_commitment_cmx(...);
cmx == expected_cmx   // true
```

`verify_name_note` has no knowledge of the name's `Tip`; it is deliberately a per-note recomputation (see plan "Recompute, don't trust").

A resolver or wallet that trusts the minter's output, or that only checks the per-note `verify_name_note` result without also calling `prev_rcm_for(tip, Claim)` before admitting the note into its index, will record a second live binding for "alice".

Even a party that does call `prev_rcm_for` can be equivocated against if the minter controls the public history view or if multiple indexers ingest the notes in different orders.

**Impact**: Two different UAs both appear to own "alice". Funds or messages intended for the name can be directed to the attacker's UA. A future slash contract that sees only one of the notes reaches a different conclusion than a resolver that saw both.

**Why the kernel primitives enable it**: The kernel's `verify_name_note` and `zns_psi_rcm` are correct by construction for whatever bytes the minter supplies. The security property "only one live binding" lives in `memo::prev_rcm_for` + the registry admission policy that calls it. The minter bypasses or equivocates around that policy while still producing notes whose individual bindings verify.

**Related plan invariants**:
- `verify_name_note` returns true iff re-derived `(psi, rcm)` + caller-supplied note fields produce `cmx == expected_cmx` (Summary of Key Invariants #5).
- `prev_rcm_for(None, Claim) = Some(ZERO...)`; `Claim` on a non-Release tip returns None (invariants #7).
- One source of truth for the chain rule (PRAGMATISM.md).

**Detection / Hardening surface**: Cross-check every admitted note with `prev_rcm_for` using the single implementation; require all indexers and the future slash contract to share the same tip reconstruction; expand vectors to cover rejected Claim-on-live cases.

---

### 2. Withholding / Lying Resolver

**Capabilities**: Controls the index that wallets and other resolvers query. Can omit Name Notes entirely, return partial data, substitute one note's memo/fields for another, or present an inconsistent view of the name's tip history.

**Goals**: Prevent verification (wallets cannot obtain the four-tuple needed for `verify_name_note`), cause resolution forks (different parties compute different current owners or different "is this note valid" results for the same on-chain notes).

**Attack Story: Selective Withholding + Inconsistent Tip Presentation**

A name "alice" has a history of Claim (victim) -> Update (new_ua).

The resolver has seen both notes and knows the current tip `rcm` from the Update.

When wallet A (the owner) asks for its names, the resolver returns only the first note's data or drops the memo bytes for the latest Update. The wallet cannot call `parse_name_note_memo` (src/lib.rs:415) followed by `verify_name_note`, so it cannot confirm ownership. Verification is prevented.

When wallet B (or a competing resolver) queries, the lying resolver returns the Update note but substitutes a memo containing a different `prev_rcm` (or claims a different tip rcm in its auxiliary index data). Wallet B calls `prev_rcm_for(its_view_of_tip, Update)` and obtains `None`, while the lying resolver's own view accepts the note. The two parties now disagree on whether the Update is a valid extension.

Because the note itself carries its disclosed `prev_rcm` (for standalone verification per DESIGN.md section 19.4), a sufficiently complete wallet can still verify the single note once it obtains the memo by other means (e.g., direct chain scan or tail-scan proof). The resolver's lie is therefore detectable by a determined verifier, but the resolver can still cause widespread confusion and temporary loss of resolution for the majority of users who rely on the index.

**Attack Story: Memo Substitution Leading to Verify Failure (Soft Fork Signal)**

The resolver returns a memo whose parsed `(action, name, ua, prev_rcm)` differ from the ones the original minter used to produce the on-chain `cmx`. The caller feeds those fields to `verify_name_note`:

```rust
let (psi, rcm) = zns_psi_rcm(action_from_lying_memo, ...);  // different inputs
let cmx = note_commitment_cmx(...);
cmx == on_chain_cmx   // false
```

`verify_name_note` correctly returns false. The caller treats the name as unresolvable or as evidence of a registry fork. The resolver has successfully made an honest binding appear invalid to its clients without ever touching the on-chain ciphertext or commitment.

**Impact**: Names become unresolvable for users of the lying resolver. Conflicting views of the same name's owner set between different resolvers/wallets. A slash contract fed one view may slash a party that another view considers honest.

**Why the kernel is relevant**: The lying resolver does not break `verify_name_note` or the hash/commit; it abuses the fact that verification requires the four-tuple that only the index (or full chain scan + decryption) can supply. The kernel's job is to make any lie detectable once the fields are obtained.

**Related plan points**:
- "Withholding / lying resolver" explicitly listed with goal "Prevent verification, cause resolution forks".
- Memo grammar strictness is load-bearing for slashability (plan section 4 P3 and PRAGMATISM.md).
- Standalone `prev_rcm` witness in Name Notes exists precisely to limit the power of a withholding resolver.

---

### 3. Chain Observer / Network Attacker

**Capabilities**: Observes every ZNS memo that appears in a decrypted Name Note (or is otherwise indexed publicly). Can delay, reorder, replay, or inject crafted memos into any channel that accepts them (wallet submission paths, resolver APIs, future challenge/confirm flows).

**Goals**: Create confusion about ownership timelines, cause DoS on resolution (wallets or resolvers enter bad states or refuse further updates), induce users to act on stale or replayed bindings.

**Attack Story: Replay of Genesis Claim After Release + Update**

An honest owner Releases "alice", then later a new owner Claims it.

The observer captures the original `ZNS:claim:alice:original_ua:0000...` memo bytes (or reconstructs the four-tuple).

Later, after the release, the observer submits (or causes a compromised wallet to submit) the old memo bytes as if they were a fresh request, or directly feeds the old four-tuple + a freshly decrypted note's `(g_d, pk_d, ...)` to verification code.

If a resolver or wallet does not bind the disclosed `prev_rcm` to the actual on-chain note's context or does not check `prev_rcm_for` against current tip, it may treat the replayed Claim as a new valid genesis binding.

Even when `verify_name_note` itself rejects (because the cmx on the replayed note does not match a current on-chain note), the observer can flood resolvers with many old memos, causing excessive parse/verify work or polluting caches with "seen but unresolvable" entries.

**Attack Story: Reordering to Break Expected Tip Transitions**

The attacker sees a Claim followed quickly by an Update on the wire/indexer feed. By delaying delivery of the Claim note to one resolver instance while delivering the Update note first, the resolver builds a tip that makes the subsequent Update appear to be a Claim-on-live (or vice versa). `prev_rcm_for` returns None for what should have been a legal transition.

Different resolver replicas now have divergent tips for the same name. When they later reconcile, one may reject the other's note as invalid, creating a fork in the observed name state.

**Impact**: Users see names appear/disappear or flip owners. Automated systems that rely on stable resolution (wallets showing "your names", dapps resolving names) experience flapping or outages.

**Why the kernel matters**: All memos are processed through `parse_memo` (src/lib.rs:470) and then either `parse_name_note_memo` or direct `verify_name_note`. The observer does not need to break the primitives; the public visibility of the memo grammar plus any state machine that consumes the stream without full ordering guarantees is sufficient for confusion and DoS.

**Related plan**:
- "Chain observer / network attacker" goals: "Confusion, DoS on resolution".
- Memos are public once decrypted; the grammar is intentionally strict so that all parties see exactly the same fields.

---

### 4. Compromised Dependency

**Capabilities**: A malicious or backdoored update to one of the default dependencies (`blake2b_simd`, `sinsemilla`, `pasta_curves`, `bitvec`, `group`) or to a `decrypt`-feature dependency. The attacker can control the output of the hash, the Sinsemilla commitment, or field element construction/reduction.

**Goals**: Make the kernel compute `(psi, rcm)` or `cmx` values that do not match the honest mathematical definition, allowing forgery of bindings that `verify_name_note` will accept for attacker-chosen `(name, ua)`.

**Attack Story: Backdoored BLAKE2b Absorption**

A malicious `blake2b_simd` crate update is released. When `tagged_zns_hash` (src/lib.rs:230) runs:

```rust
let mut h = Params::new().hash_length(64).to_state();
...
absorb_with_length_prefix(ZNS_DOMAIN_TAG);  // L242
...
h.update(prev_rcm);                         // L247 -- raw, no prefix
let out = h.finalize()...
```

The compromised implementation, for inputs containing the attacker's chosen name or a recognizable pattern, returns a 64-byte digest that the attacker selected in advance.

Consequently `zns_psi_rcm` (L214) produces attacker-chosen `psi` (Base) and `rcm` (Scalar) for chosen `(action, name, ua, prev_rcm)`.

The attacker (or a colluding minter) now mints a note for "alice" -> attacker_ua using the backdoored hash. Later they claim the binding was for victim_ua. Because the on-chain `cmx` was produced using the backdoored `(psi, rcm)`, `verify_name_note` using the victim fields will (by construction of the backdoor) still produce a matching `cmx` for the victim tuple as well, or the attacker can directly supply fields that the backdoored reduction maps to a desired commitment point.

Even without a colluding minter: an attacker who can influence any note's content can search for preimages or colliding inputs under the backdoored hash until they find a `(name, ua)` pair that produces the same `(psi, rcm)` as an honest binding, then present the alternate tuple to verifiers.

**Attack Story: Compromised Sinsemilla or Pallas Field Math**

A malicious `sinsemilla` or `pasta_curves` update alters `short_commit` behavior or the `from_uniform_bytes` / bit decomposition.

`note_commitment_cmx` (src/lib.rs:170-192) builds the bit string explicitly:

```rust
let bits = g_d_bits.iter()...
    .chain(pk_d_bits...)
    .chain(value_bytes.view_bits::<Lsb0>()...)
    .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
    .chain(psi_bits.iter().by_vals().take(L_ORCHARD_BASE));
Option::<pallas::Base>::from(domain.short_commit(bits, &rcm))
```

If `short_commit` or the `to_le_bits` / truncation logic is subverted, an attacker can produce a `cmx` value for arbitrary `(g_d, pk_d, value, rho, psi, rcm)` or make the x-coordinate extraction land on attacker-chosen points. Any `verify_name_note` call will then match attacker-supplied bindings.

**Impact**: Total loss of binding correctness. Every asset (name ownership, slashability, cross-impl consensus) collapses because the mathematical root is no longer trustworthy. A single poisoned dependency update poisons all downstream consumers of the crate.

**Why the kernel is fragile here**: The plan lists "Default build: only `blake2b_simd`, `pasta_curves`, `sinsemilla`..." as part of the minimal TCB. There is no wrapper or independent implementation of the BLAKE2b length-prefix or Sinsemilla message construction inside the crate; it trusts the crates for the primitive operations (plan section 1, P6).

**Detection / Hardening**: `cargo audit`, reproducible builds, multiple independent implementations of the hash/commit for differential testing, pinning + hash verification of dependency artifacts, formal models of the exact absorption and commit bit ordering.

---

### 5. Malicious User Feeding Bad Memos

**Capabilities**: Can submit arbitrary byte strings that will be fed to `parse_memo`, `parse_claim_memo`, `parse_name_note_memo`, or directly to code paths that later call `verify_name_note` with extracted fields. This can occur via wallet receive paths (a shielded note memo), resolver submission APIs, or future challenge/confirm flows.

**Goals**: Trigger parser differentials (different parties extract different `(action, name, ua, prev_rcm)` from the identical memo bytes), or cause DoS / resource exhaustion in memo processing.

**Attack Story: Trailing Field Absorption Attempt (Differential Trigger)**

The attacker crafts and causes to be minted (or simply sends to a resolver endpoint) a memo:

```
ZNS:update:alice:u1victim:deadbeef...extra garbage after the witness
```

Per the strict parser (src/lib.rs:486):

```rust
if fields.next().is_some() {
    return Err(MemoError::FieldCount);
}
```

This is rejected with `FieldCount` (or later `InvalidPrevRcm` depending on exact bytes).

However, any implementation that used `splitn` or that silently absorbed trailing content into `ua` or ignored it would parse a different `ua` or treat the memo as a valid Name Note with a truncated `prev_rcm`. The plan explicitly calls out this historic divergence as the reason for the strict grammar.

If a registry, resolver, and slash contract disagree on whether this memo is valid or what `ua` it binds, the slash mechanism (asset #2) is broken.

**Attack Story: Resource Exhaustion and Validation Order**

The attacker sends many 512-byte memos that are valid UTF-8 "ZNS:..." strings but with:

- 64-char names full of hyphens and alphanumerics that pass `validate_name` only after expensive checks, or
- prev_rcm fields that are 64 hex but with invalid nibbles late in the string (decode_prev_rcm walks the whole thing, src/lib.rs:543-558).

If a resolver or wallet performs expensive operations (database lookups, chain queries, or even just repeated allocation) before or on every field of `parse_memo`, the attacker can drive high CPU or memory usage with a stream of "almost ZNS" memos that ultimately reject at `FieldCount`, `InvalidName`, or `InvalidPrevRcm`.

Memos that are exactly 512 zero bytes or start with "ZNS:" but contain invalid UTF-8 after zero stripping are also cheap to generate in volume.

**Attack Story: Uppercase prev_rcm + Mixed Case Action**

A memo is submitted with:

```
ZNS:claim:alice:u1x:001122...FF (uppercase hex)
```

`decode_prev_rcm` (src/lib.rs:548-551) only accepts `0-9a-f`; uppercase returns `InvalidPrevRcm`. A lenient port that lowercases first would accept it and extract a different (or same) `prev_rcm` value.

If the action bytes are also non-canonical in some path ("Claim" instead of "claim"), `Action::from_bytes` (src/lib.rs:34) rejects while another implementation folds case.

The result is differential parsing of the same memo bytes.

**Impact**: Parser differentials break slashability. DoS affects availability of resolution and wallet scanning.

**Why the kernel is the target**: `parse_memo` (src/lib.rs:470) and its callees are the single shared implementation whose strictness is intended to prevent exactly these differentials (plan section 4 P3, PRAGMATISM.md "Memo parser strictness is load-bearing").

---

### 6. Supply-Chain Attacker

**Capabilities**: Can publish malicious versions of `zns-verify` (or its dependencies) on crates.io, push altered commits to the git repository that downstreams consume, or compromise the build environment / CI so that published artifacts differ from the reviewed source.

**Goals**: Inject code that weakens verification, alter the sacred cross-language contract (vectors), or introduce subtle changes that only manifest under certain feature flags or on certain platforms.

**Attack Story: Poisoned Release Alters Domain Tag or Vectors**

The attacker publishes `zns-verify 0.2.0` (or a patch release) in which:

- `ZNS_DOMAIN_TAG` is changed from `b"ZcashName/v1"` (src/lib.rs:203) to `b"ZcashNameService/v1"` (the value mentioned in the whitepaper per plan open question).

All existing vectors in `tests/vectors.rs` now produce different `(psi, rcm)` because the first length-prefixed field in `tagged_zns_hash` has changed. New users who run the crate's own tests see the vectors fail (or the attacker also mutates the expected hex in the vectors so tests pass).

Any downstream (JS port, circuit, zns-mint copy) that was pinned to the old tag now computes different bindings than Rust consumers of the poisoned crate.

An honest `verify_name_note` on a note minted under the original tag will now fail against a poisoned verifier (or succeed against a note minted by a poisoned minter).

**Attack Story: Weakened Memo Parser in Published Crate**

The published source has a one-line "improvement":

```rust
// was: if fields.next().is_some() { reject }
let _ = fields.next(); // ignore extra
```

Now `ZNS:claim:alice:u1x:extra` parses with `ua = "u1x"` (or absorbs into prev_rcm handling). The parser round-trips with `encode_*` still, but now disagrees with every other honest implementation and with the slash contract.

Because the crate is small and single-file, the diff is easy to miss on casual review of a "routine release".

**Attack Story: Tampered Vectors + CI Guard Bypass**

The attacker also modifies one or more expected hex values in `tests/vectors.rs` (the four core vectors plus the cmx pins at L74 and L95). They add a comment "updated for v2 tag -- old vectors no longer apply".

Any project that vendors the vectors or treats `tests/vectors.rs` as the contract now has a drifted baseline. Future differential testing against zns-mint copies will appear to pass because both sides were poisoned consistently, or one side was not.

**Impact**: The cross-impl consensus asset (plan asset #4) is destroyed at the root. All verifiers using the poisoned crate will accept or reject bindings differently than the rest of the ecosystem. Because vectors are the "interop/security contract" (plan section 1), altering them is equivalent to changing the protocol without a version bump.

**Why this is high blast radius**: The plan lists "Supply-chain attacker" explicitly. It also requires "Vector policy is inviolable. Existing vectors ... NEVER change." (plan section 10) and "Reproducible builds / cargo audit" as ongoing practice. The crate's design (single file, few deps) reduces but does not eliminate supply-chain risk.

---

## Summary of High-Value Attack Surfaces

- Anything that lets an attacker cause `verify_name_note` (src/lib.rs:915) to return true for `(action, name, ua)` bytes that did not produce the on-chain `cmx` under the honest `tagged_zns_hash` + `note_commitment_cmx`.
- Divergence in `parse_memo` (src/lib.rs:470) output between implementations (especially field count, prev_rcm casing, RELEASE ua positioning).
- Bypassing or duplicating the logic in `prev_rcm_for` (src/lib.rs:89) so that a note that verifies is treated as a legal extension when it should not be.
- Any change to `ZNS_DOMAIN_TAG`, length-prefixing, bit ordering in the commit, or the raw `prev_rcm` append (L247) without a coordinated v2 and new vectors.
- Trusting a resolver index or minter output without re-running the kernel recomputation on obtained fields.

These stories are intended to be living material for the security review. They should be updated as the codebase, usage sites (zns-mint, zns-resolver, future slash contract), and threat intelligence evolve.

## References

- `docs/SECURITY_REVIEW_PLAN.md` (source of the adversary table and many invariants)
- `PRAGMATISM.md` (core mandates on fidelity, strictness, single source of truth)
- `src/lib.rs` (the entire reviewable kernel)
- `tests/vectors.rs` (the sacred cross-language contract)
