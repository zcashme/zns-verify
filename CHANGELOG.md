# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `commitment::tagged_zns_hash` inlines the length-prefixed absorb steps as
  five explicit `(to_le_bytes(len); State::update(len); State::update(bytes))`
  pairs instead of routing through a single closure. Same byte input to
  BLAKE2b, same `(psi, rcm)` outputs, same cross-language vectors pass -- the
  on-wire hash layout is now readable straight off the source (relevant to
  the D1 byte-stability invariant audited in `docs/code_review.md`).
- `memo::encode_request` and `memo::encode_name_note` share a single
  `classify_action(action, ua)` helper for the Release-must-have-empty-ua /
  Claim-and-Update-must-have-non-empty-ua policy. The two encoders can no
  longer drift apart on the policy check; one call site, one audit. No
  change to any emitted or accepted memo bytes.

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
- `decrypt` feature (opt-in) -- relaxed Orchard trial decryption that skips
  the ZIP-212 `cmx` check but keeps ChaCha20-Poly1305 AEAD authentication
  against IVK/OVK. `try_compact_orchard`, `try_decrypt_orchard`,
  `try_decrypt_orchard_sent`. Pulls `orchard` + pinned ciphers and forces `std`.
- Cross-language test vectors for `(action, name, ua, prev_rcm) -> (ψ, rcm)`
  and pinned `cmx` values for claim, update, release, and long-name inputs
  (`tests/vectors.rs`).
- MIT license.

[Unreleased]: https://github.com/zcashme/zns-verify/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/zcashme/zns-verify/releases/tag/v0.0.1
