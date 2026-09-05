# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Action::as_str()`: the canonical ASCII spelling of an action as text.
  `Action::as_bytes()` now derives from it, so the byte and text forms share
  one source and cannot drift. Downstream code (registry, resolver, JSON-RPC)
  should use this instead of hand-rolling the verb spelling.
- GitHub Actions CI on pull requests and pushes to `master`: default and
  `decrypt` tests, clippy `-D warnings`, rustfmt, `cargo doc --no-deps
  --all-features`, and llvm-cov coverage artifacts (no percentage gate).

### Removed

- **Breaking:** the request-memo grammar (`parse_claim_memo`, `parse_update_memo`,
  `parse_release_memo`, `encode_request`). Request memos are treasury intake
  (user -> Mint) and never enter the verification path; their implementation
  lives with the mint, the grammar's only consumer. The kernel now covers Name
  Notes only.
- **Breaking:** the free-function memo API. `NameNote::parse(&Memo)` and
  `NameNote::encode()` replace `parse_name_note` / `encode_name_note`; parsing
  is the only way to construct a `NameNote`.
- **Breaking:** `base_from_bytes` and `validate_name` (replaced by the `Rho`,
  `Cmx`, and `Name` constructors), and the `NoteCommitment`/`Rho` type aliases
  (now newtypes; the extracted commitment is `ExtractedNoteCommitment`, named
  as upstream).
- `tests/vectors.rs` and `context.md`. The WP §3.5 golden vector remains as a
  unit test in `src/commitment.rs`.

### Changed

- **Breaking:** `NameNote` is a three-variant enum (`Claim` / `Update` /
  `Release`) whose fields are validated domain types (`Name`, `Expiry`,
  `PrevRcm`): a release has no expiry field and a claim has no predecessor
  field, so those constraints are structural. `NameNote::parse(&Memo)` is the
  only construction path from untrusted bytes, and it enforces canonical
  ZIP-302 padding, canonical decimal `expires_at` (WP §3.1), 64-lowercase-hex
  `prev_rcm`, and predecessor/action consistency.
- **Breaking:** `verify_name_note(note: &NameNote, g_d, pk_d, value, rho, cmx)`
  with `verify_name_note_with_witness` as the primitive returning the re-derived
  `(ψ, rcm)` opening. `Rho` and `ExtractedNoteCommitment` are newtypes with
  canonical codecs.

- Name Notes include `expires_at` in the memo and the ZNS hash (WP §3).
  `zns_psi_rcm` / `verify_name_note` take `expires_at` as raw field bytes
  (`none` or canonical decimal). Name Notes are six fields:
  `ZNS:<verb>:<name>:<ua>:<expires_at>:<prev_rcm>`. RELEASE retains the
  released UA and must encode `none`. Golden vectors and the WP §3.5 pin
  are updated. This is a breaking API and interop change.
- Name Notes are Ironwood-pool notes (ZIP 2005, NU6.3), not Orchard-pool
  notes. At NU6.3 the Orchard pool is frozen (cross-address transfers
  disabled, enforced by the circuit), so Name Notes must be in the Ironwood
  pool. Ironwood is an Orchard-protocol pool: same Pallas curves, Sinsemilla
  commitments, Action encoding, and keys -- the differences are separate state
  (note commitment tree, nullifier set, value pool) and the note plaintext
  version (V3, lead byte `0x03`, vs V2's `0x02`).
- `decrypt` feature: swapped `OrchardDomain` for `IronwoodDomain`. The two
  domains share identical key agreement, KDF, and AEAD; they differ only in
  which note plaintext lead byte they accept (`0x03` vs `0x02`). Using
  `OrchardDomain` would silently reject every Name Note because the V3 lead
  byte would fail the domain's version check.
- Renamed `try_compact_orchard` / `try_decrypt_orchard` /
  `try_decrypt_orchard_sent` to `try_compact_ironwood` /
  `try_decrypt_ironwood` / `try_decrypt_ironwood_sent`.
- Bumped `orchard` dependency from `0.14` to `0.15` (introduces
  `IronwoodDomain`, `NoteVersion`, `BundleVersion`).
- Bumped `zcash_note_encryption` from `0.4` to `0.4.2` (required by
  `orchard` 0.15).

The Ironwood pool rename does not change Sinsemilla note commitment
math. The ZNS BLAKE2b hash *did* change: it now length-prefixes `expires_at`
before the raw `prev_rcm` (WP §3.3).

## [0.0.1] - 2026-06-21

Initial verification kernel. Default build is `no_std`, `forbid(unsafe_code)`,
and depends only on `blake2b_simd`, `pasta_curves`, `sinsemilla`, and `group`.

### Added

- `zns_psi_rcm(action, name, ua, prev_rcm) -> (ψ, rcm)` -- BLAKE2b-512
  length-prefixed derivation with the `ZcashName/v1` domain tag.
- `note_commitment_cmx(g_d, pk_d, v, ρ, ψ, rcm) -> Option<NoteCommitment>` --
  Sinsemilla note commitment recompute (`z.cash:Orchard-NoteCommit`,
  `L_ORCHARD_BASE = 255`, `Lsb0` bit order).
- `verify_name_note(...)` -- capstone: re-derives `(ψ, rcm)`, recomputes `cmx`,
  returns `bool`.
- `verify_name_note_with_witness(...)` -- byte-oriented variant for scanners
  and resolvers; returns `(psi, rcm)` as `[u8; 32]` on match.
- Strict ZNS memo grammar: `parse_name_note`, `parse_claim_memo`,
  `parse_update_memo`, `parse_release_memo`. Exact field counts, DNS-label name
  rules, 64-lowercase-hex `prev_rcm`, positional empty `ua` for RELEASE.
- `encode_request` / `encode_name_note` -- zero-padded 512-byte encoders that
  round-trip with the corresponding parser.
- `NameNote<'a>` -- struct carrying `(action, name, ua, prev_rcm)`.
- `Action` enum (Claim, Update, Release) with `Action::from_bytes`.
- `prev_rcm_for(tip, action)` / `Tip` / `ZERO_PREV_RCM` -- the per-name chain
  transition rule. One implementation for registry, resolver, and verifier.
- `validate_name` -- DNS-label rule (1 to 63 bytes of `a-z 0-9 -`, no
  leading or trailing hyphen).
- `MemoError` -- C-like enum for all grammar violations.
- `base_from_bytes` helper and `pallas` / `PrimeField` re-exports so callers
  can avoid direct curve dependencies.
- `decrypt` feature (opt-in) -- relaxed Ironwood trial decryption that skips
  the ZIP-212 `cmx` check but keeps ChaCha20-Poly1305 AEAD authentication
  against IVK/OVK. `try_compact_ironwood`, `try_decrypt_ironwood`,
  `try_decrypt_ironwood_sent`. Uses `IronwoodDomain` (V3 note plaintexts, lead
  byte `0x03`). Pulls `orchard` + pinned ciphers and forces `std`.
- Cross-language test vectors for `(action, name, ua, prev_rcm) -> (ψ, rcm)`
  and pinned `cmx` values for claim, update, release, and long-name inputs
  (`tests/vectors.rs`).
- MIT license.

[Unreleased]: https://github.com/zcashme/zns-verify/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/zcashme/zns-verify/releases/tag/v0.0.1
