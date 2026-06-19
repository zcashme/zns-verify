# Security Review / Audit Plan for zns-verify

**The ZcashName (ZNS) Verification Kernel — "the minimal primitive the trust model rests on"**

---

## 1. Risk Profile / Why This Crate Is Special

**zns-verify is the root of trust for name ownership on Zcash.**

| Dimension | Assessment |
|-----------|------------|
| **Blast radius** | Extreme. A bug here can forge name bindings, break slash mechanisms (memo parser drift), cause chain resolution forks, or enable wallet fund/privacy loss. |
| **Trust model** | Zero-trust by design: anyone (wallet, resolver, SDK, enclave, circuit, slash contract) can independently recompute and verify that a Name Note's `cmx` was honestly derived from `(action, name, ua, prev_rcm)`. |
| **Cross-language contract** | `tests/vectors.rs` vectors are **sacred** — existing vectors NEVER change. They are the interop/security contract. |
| **Reviewability constraint** | Single-file `src/lib.rs` with "Inlined modules for review" — a human must hold the entire kernel in their head. |
| **TCB minimality** | Default build: only `blake2b_simd`, `pasta_curves`, `sinsemilla`, `bitvec`, `group`. `decrypt` feature (opt-in) pulls orchard + pinned ciphers + forces std. |
| **Non-negotiables** | `#![no_std]` (except decrypt/tests), `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`. |

**Note:** This document predates the 3-module refactor (memo / commitment / verify). Old references to `action::`, `chain::`, `hash::`, `commit::` submodules are historical. Current canonical modules are `memo`, `commitment`, and `verify`. Root re-exports remain the primary stable surface.

---

## 2. Proposed Threat Model

### Assets
1. **Name ownership binding correctness** — that `verify_name_note` returns `true` iff the `(name → ua)` binding matches the on-chain `cmx`.
2. **Slashability** — that the memo grammar is identical across registry, resolver, and any future slash contract (`DESIGN.md §17`).
3. **Wallet scanning correctness** — that `decrypt` + `verify_name_note` correctly identify Name Notes addressed to an IVK without false positives/negatives.
4. **Cross-impl consensus** — that all implementations (Rust kernel, zns-mint signer/chain copies, future JS/Go/Python/circuit ports) produce identical `(ψ, rcm, cmx)` for the same inputs.

### Adversaries
| Adversary | Capabilities | Goals |
|-----------|--------------|-------|
| **Malicious registry minter** | Controls `sk_R`; authors all Name Notes | Forge bindings, double-mint, equivocate |
| **Withholding / lying resolver** | Controls index, may drop or alter data | Prevent verification, cause resolution forks |
| **Chain observer / network attacker** | Sees all memos, can reorder, replay | Confusion, DoS on resolution |
| **Compromised dependency** | Malicious update to `blake2b_simd`, `sinsemilla`, `pasta_curves`, etc. | Subvert hashes, commitments, field math |
| **Malicious user feeding bad memos** | Submits crafted memos to wallet/resolver | Trigger parser differentials, DoS |
| **Supply-chain attacker** | Poisons crates.io, git, build env | Inject code or alter vectors |

### Attack Trees (Examples)
- `verify_name_note` returns `true` for wrong `(ua)` → user pays to forged address
- Memo parser accepts `ZNS:claim:alice:u1x:extra` differently across impls → slash contract sees different `ua` than resolver
- `prev_rcm_for` allows `Claim` on a live tip → name can be re-registered while owned
- `tagged_zns_hash` length-prefix omitted for one field → collision between `"ali"+"cebob"` and `"alice"+":bob"`
- `note_commitment_cmx` uses wrong bit order or truncation → all cmx computations diverge from orchard path

---

## 3. Scope Boundaries

| In Scope | Out of Scope |
|----------|--------------|
| `zns-verify` crate only (all code, vectors, docs) | Full ZNS system (zns-mint, zns-resolver, zns-orchard) |
| Crypto: `zns_psi_rcm`, `tagged_zns_hash`, `note_commitment_cmx` | Zcash consensus rules, Orchard circuit soundness |
| Memo grammar: `parse_memo`, `encode_*`, `validate_name` | TEE attestation, registry policy enforcement |
| Chain rule: `prev_rcm_for`, `Tip` | Light client security, network transport |
| Feature `decrypt`: `try_compact_orchard`, `try_decrypt_orchard` | zns-orchard `unsafe-zns` fork internals (except interface) |
| Re-exports and public API surface | Performance / DoS under load (except algorithmic) |
| Cross-language vector contract | External DESIGN.md correctness (but note inconsistencies) |

**Note:** While out of scope for direct review, zns-verify's independent copies in `zns-mint/{signer,chain}` and usage in `zns-resolver` are relevant for **differential analysis** and **API usage correctness**.

---

## 4. Prioritized Review Areas (with file:line references)

### P0 — Immediate / Hygiene
| Area | Location | Rationale |
|------|----------|-----------|
| `missing_docs` hygiene | `src/lib.rs:14` (`pub enum Action`) | Currently blocks docs build; `#![deny(missing_docs)]` |
| API re-exports | `src/lib.rs:1164-1191` | Ensure public surface matches documented usage |
| `parse_memo_validated` | Imported at `zns-resolver/src/registry/lifecycle.rs:4` but **does not exist** in zns-verify | Resolver will not compile against this crate |

### P1 — Crypto Core (Byte-Identical Constructions)
| Area | Location | Rationale |
|------|----------|-----------|
| Domain tag & field tags | `src/lib.rs:209,216-217` (`ZNS_DOMAIN_TAG`, `TAG_PSI`, `TAG_RCM`) | Protocol constant; must never change without v2 bump |
| Length-prefixed absorption | `src/lib.rs:244-253` (`absorb_with_length_prefix` closure) | `prev_rcm` is **raw** (L253: `h.update(prev_rcm)`) — special case |
| `from_uniform_bytes` reduction | `src/lib.rs:227-230` | `pallas::Base` vs `pallas::Scalar` on same 64-byte input |
| Sinsemilla commit | `src/lib.rs:168-198` (`note_commitment_cmx`) | `L_ORCHARD_BASE=255`, `Lsb0`, `short_commit`, value LE, truncation |
| Vector pins | `tests/vectors.rs:64-138` (`commit_matches` + 4 vectors) | Sacred contract; any change moves pins |

### P2 — State Machine (Per-Name Chain Rule)
| Area | Location | Rationale |
|------|----------|-----------|
| `prev_rcm_for` logic | `src/lib.rs:95-104` | Single source of truth per PRAGMATISM.md L38; 9 cases in tests |
| `Tip` struct | `src/lib.rs:81-86` | Carries `action` (including `Release`) and `rcm` |
| Genesis vs extension | `src/lib.rs:97-102` | `Claim` on `None` or `Release` tip → `ZERO_PREV_RCM`; `Update`/`Release` require live tip |
| Usage in resolver | `zns-resolver/src/registry/lifecycle.rs:48,62` | `prev_rcm_for(tip, action)` called in `try_admit_name_note` and `warn_registry_fork` |
| **Non-usage** in zns-mint | — | zns-mint does not call `prev_rcm_for`; it has its own state machine? |

### P3 — Memo Grammar (Slashability Contract)
| Area | Location | Rationale |
|------|----------|-----------|
| `parse_memo` strictness | `src/lib.rs:476-546` | `split` not `splitn` (L480); extra field at L492-493 rejects; positional empty `ua` for RELEASE (L518-532) |
| `decode_prev_rcm` | `src/lib.rs:549-564` | Exactly 64 lowercase hex; manual nibble loop |
| `validate_name` | `src/lib.rs:568-583` | 1-63 bytes, `a-z0-9-`, no lead/trail hyphen; DNS label rule |
| `encode_*` round-trip | `src/lib.rs:588-670` | Must produce what `parse_memo` accepts |
| zns-core independent copy | `zns-mint/core/src/memo.rs` | Producer-side parser; must match semantics exactly |
| `parse_name_note_memo` | `src/lib.rs:421-431` | Requires `prev_rcm: Some(_)`; rejects request forms |

### P4 — Decrypt Feature (Larger TCB)
| Area | Location | Rationale |
|------|----------|-----------|
| `try_compact_orchard` | `src/lib.rs:1094-1120` | Replicates zcash_note_encryption compact path; skips `check_note_validity` (L1118) |
| `try_decrypt_orchard` | `src/lib.rs:1129-1161` | Replicates full path; ChaCha20-Poly1305 tag verified (L1148-1155); skips cmx check |
| Pinned cipher versions | `Cargo.toml:42-43` | `chacha20 = "0.9"`, `chacha20poly1305 = "0.10"` to match zcash_note_encryption 0.4 |
| Feature gating | `src/lib.rs:1061` (`#[cfg(feature = "decrypt")]`) | Must not leak into default build |
| Usage in resolver | `zns-resolver/src/orchard.rs:92,121` | Calls `zns_verify::decrypt::*` for Name Note scanning |

### P5 — API Ergonomics & Footguns
| Area | Location | Rationale |
|------|----------|-----------|
| 9-arg `verify_name_note` | `src/lib.rs:921-939` | `#[allow(clippy::too_many_arguments)]` intentional per PRAGMATISM.md L46 |
| Raw byte inputs | `src/lib.rs:922-925` | `action`, `name`, `ua` are `&[u8]` — hashed verbatim; no normalization |
| `base_from_bytes` panics | `src/lib.rs:1184-1186` | `expect("invalid Pallas base field element")` — for test vectors only |
| `Action::from_bytes` case-sensitivity | `src/lib.rs:34-41` | Rejects `"Claim"`, `"CLAIM"`; canonical is lowercase |

### P6 — Dependency & Build Surface
| Area | Location | Rationale |
|------|----------|-----------|
| Default deps | `Cargo.toml:25-33` | `blake2b_simd`, `pasta_curves`, `sinsemilla`, `bitvec`, `group` |
| `decrypt` deps | `Cargo.toml:39-43` | `orchard 0.14`, `zcash_note_encryption 0.4`, `zcash_protocol 0.9`, pinned ciphers |
| `Cargo.lock` pin audit | — | Exact versions for reproducibility |
| `no_std` enforcement | `src/lib.rs:2` | `cfg_attr(all(not(test), not(feature="decrypt")), no_std)` |

---

## 5. Recommended Techniques & Tools

| Technique | Target | How |
|-----------|--------|-----|
| **Manual code review** | All P0-P6 areas | Line-by-line with emphasis on L236-257 (hash), L176-198 (commit), L476-546 (memo), L95-104 (chain) |
| **Differential testing** | Hash / commit | Run zns-verify vectors against zns-mint/signer `derive.rs` and zns-mint/chain `hash.rs` + `commit.rs` |
| **Vector expansion analysis** | `tests/vectors.rs` | Per VECTOR_REVIEW_PROMPT.md: enumerate every byte-level decision; gap analysis; propose 0-4 additions |
| **Fuzzing (memo parser)** | `parse_memo` | `cargo fuzz` or `arbitrary` on byte strings; target field counts, `:` in fields, non-UTF8, upper-hex prev_rcm |
| **Property-based tests (chain)** | `prev_rcm_for` | QuickCheck / proptest: for any sequence of actions, only legal transitions produce `Some(prev_rcm)` |
| **cargo audit / dep review** | All deps | `cargo audit`; review `blake2b_simd`, `sinsemilla`, `pasta_curves`, `group` histories |
| **Constant-time analysis** | N/A (mostly) | Pure functions; no secrets in verify path. `decrypt` path inherits orchard ct properties |
| **Formal methods (optional)** | Hash / commit | If appetite exists: model BLAKE2b absorption + field reduction + Sinsemilla message in Lean/Coq; compare to vectors |
| **Cross-impl conformance** | Future ports | JSON vector export (per VECTOR_REVIEW_PROMPT.md) for JS/Go/Python/circuit consumers |

---

## 6. Phased Execution Plan

### Phase 1: Quick Wins + Hygiene + Architecture (1-2 days)
1. (Historical) Fix `missing_docs` on Action (the issue has been resolved in the current structure).
2. Confirm `parse_memo_validated` gap — either implement in zns-verify or correct resolver import.
3. Run `cargo test`, `cargo clippy`, `cargo doc --no-deps`.
4. Map all public APIs to call sites across monorepo (grep + manual trace).
5. Produce initial threat model doc (this plan as starting point).
6. Inventory: every constant, every protocol decision, every parser rule.

**Deliverable:** Phase 1 report (hygiene status, API map, open questions list).

### Phase 2: Deep Crypto + State Machine + Parser (3-5 days)
1. Line-by-line review of `commitment` module (ψ/rcm derivation + Sinsemilla note commitment).
2. Line-by-line review of `memo` module (Action + chain rule via `prev_rcm_for`/`Tip` + strict memo grammar).
3. Line-by-line review of `verify` module (`verify_name_note` composition + optional decrypt).
5. Differential run: zns-verify vectors vs zns-mint copies.
6. Vector sufficiency review (per VECTOR_REVIEW_PROMPT.md); propose additions if justified.
7. Cross-check Sinsemilla message construction vs zns-orchard `note/commitment.rs:59-79` (orchard path uses `domain.commit(...)` not `short_commit` — verify equivalence).

**Deliverable:** Phase 2 findings doc; updated/expanded vectors if needed; JSON vector export.

### Phase 3: Adversarial Testing + Feature Review (2-4 days)
1. Fuzz `parse_memo` (target strictness violations, field absorption, hex casing).
2. Property tests for `prev_rcm_for` (legal/illegal transitions).
3. `decrypt` feature: manual review + differential against zns-mint/chain `decrypt.rs`.
4. Dependency audit (`cargo audit`, license scan, crate history).
5. Edge case enumeration: empty name, 63-byte name, hyphen edge, max-length memo, identity commitment (`note_commitment_cmx` returning `None`).

**Deliverable:** Fuzz/property test harness + results; decrypt TCB assessment.

### Phase 4: Integration & Ongoing (ongoing)
1. Verify zns-resolver and zns-mint compile against fixed zns-verify.
2. Add CI: `cargo test`, `cargo clippy`, `cargo doc`, vector JSON diff guard.
3. Document: "how to add a vector" (never mutate existing), "how to change domain tag" (v2 + new vectors).
4. Re-export audit: ensure no accidental surface growth.
5. Periodic: re-run cargo audit on dep updates; re-diff against zns-mint copies on any hash change.

**Deliverable:** CI additions; maintenance guide; review sign-off.

---

## 7. Resource / Effort Estimates (Rough)

| Phase | Effort | Primary Skill |
|-------|--------|---------------|
| Phase 1 | 1-2 days | Rust familiarity, basic audit hygiene |
| Phase 2 | 3-5 days | Cryptography, protocol spec reading, cross-impl diff |
| Phase 3 | 2-4 days | Fuzzing, property testing, TCB analysis |
| Phase 4 | Ongoing | DevOps, documentation |

**Total for initial audit pass:** ~1-2 person-weeks for a senior Rust/crypto reviewer.

---

## 8. Open Questions (Actionable)

| Category | Question | Who to Ask / Input Needed |
|----------|----------|---------------------------|
| **Design** | Whitepaper says domain tag `"ZcashNameService/v1"` (19 bytes); code + forum-grant-proposal say `"ZcashName/v1"` (13 bytes). Which is authoritative? Is whitepaper stale? | ZNS design owner; confirm before any vector or tag change |
| **Prior reviews** | Has zns-verify or the ZNS construction received any prior audit (internal or external)? | Project leads |
| **Usage sites** | Complete inventory of zns-verify consumers: zns-mint (signer, chain, core), zns-resolver, zns-orchard (unsafe-zns), ZNS/ crate, future wallets/circuits. | Monorepo grep + owners |
| **prev_rcm_for adoption** | zns-mint does not appear to call `prev_rcm_for` (single source of truth per PRAGMATISM.md). Does zns-mint have a duplicate chain rule? | zns-mint owners |
| **parse_memo_validated** | Resolver imports `parse_memo_validated(memo, network)` from zns-verify, which does not exist. Is this a planned extension (network-specific validation) or a bug? | Resolver owner |
| **Slash contract** | Is there (or will there be) a slash contract that must parse memos identically? Current state of that work? | ZNS roadmap |
| **Formal methods appetite** | Is there interest / budget for a machine-checked model of the hash or memo grammar? | Project sponsors |
| **Performance vs security** | Any constraints on verification time (e.g., mobile wallets)? Affects fuzz depth or optimization review. | Wallet integrators |
| **Responsible disclosure** | Process for reporting issues in zns-verify or vectors? Coordinated disclosure with dependent crates? | Security policy owner |
| **Vector portability** | Is the JSON vector export (per VECTOR_REVIEW_PROMPT.md) required for any current downstream? | Consumers of vectors |

---

## 9. Deliverables

| Deliverable | Description |
|-------------|-------------|
| `docs/SECURITY_REVIEW_PLAN.md` | This document (or refined version) checked in |
| `docs/THREAT_MODEL.md` | Assets, adversaries, attack trees; updated as review progresses |
| `tests/vectors.json` (or generated) | Portable JSON form of sacred vectors + commit pins (see VECTOR_REVIEW_PROMPT.md) |
| Phase reports | 1-4 short docs capturing findings per phase |
| Review sign-off template | Checklist of areas reviewed, techniques applied, open questions |
| CI additions | GitHub Actions (or equivalent): test, clippy, doc, vector JSON guard |
| Maintenance guide | "How to change a constant", "How to add a vector", "How to review a PR" |

---

## 10. Recommendations for Future Change Audibility

Per PRAGMATISM.md and observed practice:

1. **Preserve single-file reviewability.** Do not split `src/lib.rs` without strong justification.
2. **Vector policy is inviolable.** Existing vectors in `tests/vectors.rs` NEVER change. Additions only when they close a real interop gap.
3. **Protocol fidelity > Rust idioms.** Manual length prefixing, manual hex, manual bit work are deliberate. Do not "improve" them.
4. **Domain tag bump is a breaking change.** Requires new vectors, version bump, and cross-impl coordination.
5. **Memo parser strictness is load-bearing.** Any leniency (trailing field absorption, case folding, etc.) breaks slashability.
6. **Document why, not just what.** Comments should reference protocol sections, security properties, or cross-language requirements.
7. **Feature flag discipline.** Anything pulling orchard, std-only crypto, or heavy deps must be opt-in and clearly labeled.
8. **Re-exports are curated.** Adding new `pub` items requires justification against the "shared kernel" goal.

---

## 11. Immediate Red Flags (Observed During Analysis)

| # | Observation | Location | Severity for Review |
|---|-------------|----------|---------------------|
| 1 | (Historical) `missing_docs` on Action | (resolved) | Hygiene item from pre-refactor single-file layout |
| 2 | `parse_memo_validated` imported by resolver but does not exist in zns-verify | `zns-resolver/src/registry/lifecycle.rs:4,27` | **P0** — resolver will not build |
| 3 | Domain tag discrepancy: whitepaper.tex `"ZcashNameService/v1"` vs code `"ZcashName/v1"` | Whitepaper + `src/lib.rs:209` + `zns-mint/*` | **Open question** — must resolve |
| 4 | `memo::prev_rcm_for` is "single source of truth" per PRAGMATISM.md but zns-mint does not appear to use it | grep across monorepo | **Design consistency** — is zns-mint duplicating the rule? |
| 5 | Three independent copies of `zns_psi_rcm` + `tagged_zns_hash` (zns-verify, signer, chain) | `src/lib.rs:220-257`; `zns-mint/signer/src/derive.rs:21-56`; `zns-mint/chain/src/name_note/hash.rs:17-50` | **Differential risk** — must stay byte-identical |
| 6 | `decrypt` feature has large TCB and forces std; copies logic from zcash_note_encryption internals | `src/lib.rs:1061-1162`; `Cargo.toml:16-22,39-43` | **TCB expansion** — opt-in is correct; review needed |
| 7 | `verify_name_note` has 9 args; `#[allow(clippy::too_many_arguments)]` intentional | `src/lib.rs:920` | **Ergonomic footgun** — document why |
| 8 | `prev_rcm` is appended raw (no length prefix) after length-prefixed fields | `src/lib.rs:253` (`h.update(prev_rcm)`) | **Special case** — easy to get wrong in a port |
| 9 | `note_commitment_cmx` uses `short_commit` + 255-bit truncation; orchard path uses `commit` | `src/lib.rs:197`; compare to `zns-orchard/src/note/commitment.rs:69` | **Equivalence must be verified** |
| 10 | zns-mint/chain `tests.rs` comment: "4th vector synced from zns-verify (was missing; drift risk)" | `zns-mint/chain/src/name_note/tests.rs:45` | **Drift already happened once** — vectors are sacred |

---

## Summary of Key Invariants (for Reviewers)

1. `ZNS_DOMAIN_TAG = b"ZcashName/v1"` is fixed; changing it requires a v2 protocol and new vectors.
2. `tagged_zns_hash` applies length prefix to: domain, field_tag, action, name, ua; `prev_rcm` is raw 32 bytes.
3. `ψ` and `rcm` are distinct reductions (`Base` vs `Scalar`) of two separate hashes with different field tags.
4. `note_commitment_cmx` message order: `g_d` (256), `pk_d` (256), `value` (64 LE), `rho` (255), `psi` (255); `Lsb0`; `short_commit`.
5. `verify_name_note` returns `true` iff re-derived `(ψ, rcm)` + caller-supplied `(g_d, pk_d, value, rho)` produce `cmx == expected_cmx`.
6. Memo grammar is strict: exact field counts, positional empty `ua` for RELEASE Name Notes, lowercase hex `prev_rcm`.
7. `prev_rcm_for(None, Claim) = Some(ZERO_PREV_RCM)`; `prev_rcm_for(Some(Release), Claim) = Some(ZERO_PREV_RCM)`; `Update`/`Release` require a non-Release tip.
8. Cross-language vectors are the contract; existing entries are immutable.

---

## Open Questions (Repeated for Emphasis)

1. **Domain tag**: whitepaper vs code discrepancy — which is correct?
2. **`parse_memo_validated`**: does not exist; resolver depends on it. Implement or fix caller?
3. **Chain rule duplication**: does zns-mint need to adopt `prev_rcm_for`, or is its state machine intentionally separate?
4. **Slash contract**: current status and memo-parser requirements?
5. **Prior audits**: any historical review artifacts to incorporate?

---

**End of Plan.** This document is intended to be actionable for a team or future auditor. It is deliberately scoped to zns-verify as the verification kernel, while noting the broader ecosystem context required for complete assurance.

---
*Generated by security review subagent (audit-context-building:function-analyzer) on 2026-06-19. Subagent id: 019edfef-47bb-7353-ab58-fb7438af28a0*
