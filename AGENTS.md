# AGENTS.md for zns-verify

This file contains standing instructions for AI agents (and humans acting as agents) working on the zns-verify crate.

Use the content of PRAGMATISM.md (or the principles below) when writing, reviewing, refactoring, or extending code.

## Project Overview

zns-verify is the ZcashName (ZNS) verification kernel -- the minimal primitive the trust model rests on.

A ZcashName binding lives inside a Name Note's commitment. Its (rcm, psi) are a deterministic hash of (action, name, ua, prev_rcm), and the chain commits to that hash through the note's cmx. This crate recomputes the commitment from the note's fields and compares it to the on-chain cmx. Match: the (name to ua) binding is real. No match: it is not. You reach that conclusion without trusting any registry, resolver, or indexer.

That is the entire point. Resolution can come from anywhere, because anyone can check the answer here.

### What the crate provides

- `zns_psi_rcm(action, name, ua, prev_rcm) -> (psi, rcm)` -- re-derive the deterministic commitment randomness.
- `note_commitment_cmx(...)` -- recompute the Sinsemilla note commitment.
- `verify_name_note(...)` -- both at once: recompute and compare against cmx, returning a plain bool.
- `memo::parse_memo` / `memo::encode_*` -- the canonical ZNS memo grammar. One strict parser shared by registry, resolver, and slash contract. Agreement is by construction.
- `memo::prev_rcm_for` -- the per-name transition rule: which prev_rcm an action must extend, given the name's tip.

This kernel is the protocol's shared core -- the crypto plus the two pure rules every party must compute identically -- which lets it drop unchanged into a wallet, SDK, resolver, enclave, or embedded target.

## Core Mandate

This crate exists so that **anyone can independently recompute the binding and reach the same answer without trusting a registry, resolver, or indexer**.

Auditability, determinism, and minimality are the product. "Looks nice in Rust" is not.

## Non-Negotiable Constraints (Default Build)

- `#![no_std]`
- `#![forbid(unsafe_code)]`
- `#![deny(missing_docs)]`
- Default feature compiles **only** the pure verification kernel: `blake2b_simd`, `pasta_curves`, `sinsemilla`, `bitvec`, `group`.
- The `decrypt` feature is **strictly opt-in**. It pulls orchard + ciphers + forces `std`. Never pull heavy Zcash crates into the default path.

## Architectural Principles

1. **Reviewability**  
   The implementation lives in a small number of focused modules under `src/` (lib.rs as thin coordinator + commitment.rs, memo.rs, verify.rs). A reviewer or agent must be able to hold the entire kernel in their head. Do not create a deep module tree or spread logic without strong justification.

2. **Protocol fidelity over Rust idioms**  
   - Length-prefixed BLAKE2b construction is required for collision resistance across languages. Do not "make it nicer" with serde or higher-level combinators if they change the wire or hash bytes.
   - The memo grammar is **strict** by design. Exact field counts, positional empty `ua` for RELEASE, lowercase hex only for `prev_rcm`. A lenient parser would let implementations drift. This parser is the single source of truth so that "agreement is by construction rather than by review."
   - DNS label rules for names are exact (1-63 bytes, `a-z0-9-`, no leading or trailing hyphen). Do not relax or add "helpful" normalization.
   - Cross-language test vectors in `tests/vectors.rs` are sacred. Existing vectors never change. They are the interop contract.

3. **Recompute, don't trust**  
   `verify_name_note` is the capstone: it re-derives `(psi, rcm)` from `(action, name, ua, prev_rcm)` and recomputes the Sinsemilla `cmx`. The entire point is that the caller does not have to believe any external party.

4. **One copy of the state machine**  
   `memo::prev_rcm_for` (re-exported at crate root) *is* the protocol rule. There must be exactly one implementation that registry minter, resolver, and verifier all use identically.

5. **Minimal surface, explicit opt-in for weight**  
   The common case (verification, parsing, note commitment derivation) must stay tiny and dependency-light. Anything that brings orchard, std-only crypto, or heavy lifting must live behind a feature flag and be clearly labeled as such.

## Coding Style for This Crate

- **Prefer boring and explicit.** Manual length prefixing, manual hex encoding/decoding, manual bit decomposition. When the spec demands byte-for-byte reproducibility, write the operations directly.
- `#[allow(clippy::too_many_arguments)]` on `verify_name_note` is intentional. The protocol tuple is what it is; do not hide it behind a big struct unless you have a stronger reason than "fewer arguments."
- Error types are small and C-like (`MemoError`). Do not reach for `thiserror` or rich error hierarchies in the core path unless it measurably improves the call sites that matter (wallets, resolvers, slash contracts).
- Public API is deliberately small. Re-exports are curated. Adding new pub items requires justification against the "shared kernel" goal.
- Comments should explain *why* the rule exists (protocol section, security property, cross-language requirement), not just what the code does.

## Absolute Rule: No Em-Dashes or En-Dashes

- The em-dash character (Unicode U+2014) is **forbidden** in every `.rs` file (source, comments, doc comments, strings) and in **every** `.md` file in the repository.
- En-dashes (Unicode U+2013) are also banned.
- Only the ASCII hyphen-minus `-` (U+002D) is allowed for separators and pauses.
- Rephrase sentences or use `--` (two ASCII hyphens) when a grammatical dash is needed.
- This rule applies universally. No exceptions. It guarantees clean grep, diffs, terminals, copy-paste, and cross-platform behavior.

When editing any file, scan for and remove any em-dashes or en-dashes you introduce or encounter.

## Decision Checklist (Apply on Every Change)

When considering a change, ask:

- Does this increase the default build's dependencies or force `std`? Almost always no.
- Does this change any hash input ordering, length prefixing, or field serialization? Only with a domain tag bump and new vectors.
- Does this make the memo parser more lenient or add fallback behavior? No. Strictness is load-bearing.
- Does this hide protocol details behind a "nicer" abstraction that other implementations (JS, Go, circuits) cannot easily replicate? Usually the wrong direction.
- Can a reviewer still read the entire core logic in one sitting after this change? Preserve this property.
- Would this change cause two honest implementations to produce different `cmx` or different parse results for the same on-chain memo? Unacceptable.

## What "Pragmatic" Means Here

- Using `sinsemilla` + `pasta_curves` directly instead of `orchard::NoteCommitment` (removes a massive dependency for verifiers).
- Pinning chacha20 / chacha20poly1305 versions to match `zcash_note_encryption` internals byte-for-byte inside the `decrypt` feature.
- Keeping the `Action` enum as a simple exhaustive match rather than a fancy newtype or stringly-typed thing.
- Accepting that `verify_name_note` has 9 arguments because that is the exact set a wallet holds after decrypting a note and parsing its memo.
- Writing the obvious loop for hex decoding instead of pulling in another crate.

## Anti-Patterns to Reject

- Adding convenience methods "just because Rust makes it easy."
- Using `std::collections`, `serde`, `anyhow`, or `thiserror` in the default build.
- Making the parser accept "close enough" memos.
- Refactoring the length-prefixed hash into something "more idiomatic" that changes the output.
- Spreading the kernel across many small files "for cleanliness."
- Adding features that pull in more crypto unless they are explicitly optional and narrowly scoped.

## Testing and Verification

- Run `cargo test` for the default kernel.
- Run `cargo test --features decrypt` when touching the decrypt path.
- All vector tests and cmx pin tests must continue to pass. Existing vectors are immutable.
- Run `cargo clippy --all-features` and `cargo doc --no-deps`.
- Changes that affect hash outputs or parsing must be accompanied by new vectors only when introducing a deliberate protocol version change (domain tag bump).

## When in Doubt

Optimize for (in priority order):

1. Independent verifiability
2. Byte-stable cross-language reproducibility
3. Small, reviewable trusted computing base
4. One shared implementation of the rules

Everything else is secondary.

## Key Files

- `README.md` -- high-level description and usage examples.
- `PRAGMATISM.md` -- the full original pragmatism prompt (source of many rules above).
- `src/lib.rs`, `src/memo.rs`, `src/commitment.rs`, `src/verify.rs` -- the implementation.
- `tests/vectors.rs` -- sacred cross-language contract and pins.
- `docs/code_review.md` -- briefing for external auditors (reflects current structure).

When editing, the source code is authoritative. Describe behavior based on what the code actually does.

## For Agents

- Read the relevant source files before proposing edits.
- Make the smallest change that achieves the goal.
- After edits, always run tests and clippy.
- Preserve or improve the reviewability of the kernel.
- Obey the no em-dashes rule in all files you touch or create.
- When the user asks for a plan first, produce one instead of editing immediately.

This document and PRAGMATISM.md take precedence over generic Rust advice when they conflict.