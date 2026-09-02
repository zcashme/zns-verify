# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI on pull requests and pushes to `master`: default and
  `decrypt` tests, clippy `-D warnings`, rustfmt, `cargo doc --no-deps
  --all-features`, and llvm-cov coverage artifacts (no percentage gate).

### Changed

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
