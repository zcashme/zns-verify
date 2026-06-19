# ZNS-Verify Rust Pragmatism Prompt

Use this prompt (or paste its content) when asking an LLM to write, review, refactor, or extend code in this crate.

---

You are working on **zns-verify**, the ZcashName verification kernel. Its Rust pragmatism is deliberate and opinionated. Internalize these principles and apply them ruthlessly.

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

1. **Single file for review**  
   Everything lives in `src/lib.rs`. Modules are inlined ("Inlined modules for review"). Do not create a deep module tree unless the user explicitly asks to split for a very good reason. A reviewer must be able to hold the entire kernel in their head.

2. **Protocol fidelity over Rust idioms**  
   - Length-prefixed BLAKE2b construction is required for collision resistance across languages. Do not "make it nicer" with serde or higher-level combinators if they change the wire/hash bytes.
   - The memo grammar is **strict** by design. Exact field counts, positional empty `ua` for RELEASE, lowercase hex only for `prev_rcm`. A lenient parser would let implementations drift - this parser is the single source of truth so that "agreement is by construction rather than by review."
   - DNS label rules for names are exact (1-63 bytes, `a-z0-9-`, no leading/trailing hyphen). Do not relax or add "helpful" normalization.
   - Cross-language test vectors in `tests/vectors.rs` are sacred. Existing vectors never change. They are the interop contract.

3. **Recompute, don't trust**  
   `verify_name_note` is the capstone: it re-derives `(ψ, rcm)` from `(action, name, ua, prev_rcm)` and recomputes the Sinsemilla `cmx`. The entire point is that the caller does not have to believe any external party.

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

## No Em-Dashes (Absolute Rule)

- **No em-dashes anywhere.** The em-dash character (Unicode code point U+2014, the long dash) is **forbidden** in every `.rs` file (source, comments, `//!` and `///` docs, strings) and in **every** `.md` file in the repository.
- En-dashes (Unicode U+2013) are also banned.
- Only the ASCII hyphen-minus `-` (U+002D) is allowed for separators and pauses.
- Rephrase sentences or use `--` (two hyphens) when a grammatical dash is needed.
- This rule applies universally. No exceptions in code or documentation. It guarantees clean grep, diffs, terminals, copy-paste, and cross-platform behavior.

## Decision Checklist (Apply on Every Change)

When considering a change, ask:

- Does this increase the default build's dependencies or force `std`? → Almost always no.
- Does this change any hash input ordering, length prefixing, or field serialization? → Only with a domain tag bump and new vectors.
- Does this make the memo parser more lenient or add fallback behavior? → No. Strictness is load-bearing.
- Does this hide protocol details behind a "nicer" abstraction that other implementations (JS, Go, circuits) cannot easily replicate? → Usually the wrong direction.
- Can a reviewer still read the entire core logic in one file and one sitting after this change? → Preserve this property.
- Would this change cause two honest implementations to produce different `cmx` or different parse results for the same on-chain memo? → Unacceptable.

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

---

When in doubt, optimize for:

1. Independent verifiability
2. Byte-stable cross-language reproducibility
3. Small, reviewable trusted computing base
4. One shared implementation of the rules

Everything else is secondary.
