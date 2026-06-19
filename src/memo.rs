//! Protocol rules for ZNS — the single source of truth for cross-implementation agreement.
//!
//! This module is the canonical definition of:
//!
//! - The three actions: [`Action`]
//! - The name lifecycle transition rule: [`Tip`] and [`prev_rcm_for`]
//! - The strict memo grammar and its (de)serializers: [`parse_memo`],
//!   [`ParsedMemo`], [`encode_request`], [`encode_name_note`], etc.
//! - Name validation and the `ZERO_PREV_RCM` genesis constant.
//!
//! The Registry (what to mint), the Resolver (what was minted), and any future
//! slash contract (what *should* have been minted) **must** produce and consume
//! identical bytes. Leniency would let two correct-looking implementations
//! disagree on the meaning of the same on-chain memo — breaking slashability
//! and independent verifiability (`DESIGN.md §17`).
//!
//! All other code (wallets, indexers, alternative implementations in any
//! language) should treat the behavior of this module as the specification for
//! memo shape, name syntax, and legal chain transitions.

// ============================================================================
// Action
// ============================================================================

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

impl Action {
    /// The canonical ASCII bytes for a name action, use in hash inputs (case-sensitive).
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Action::Claim => b"claim",
            Action::Update => b"update",
            Action::Release => b"release",
        }
    }

    /// Parse the name-action bytes from their canonical ASCII form (case-sensitive).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"claim" => Some(Action::Claim),
            b"update" => Some(Action::Update),
            b"release" => Some(Action::Release),
            _ => None,
        }
    }
}

#[cfg(test)]
mod action_tests {
    use super::Action;

    #[test]
    fn as_bytes_round_trip() {
        for action in [Action::Claim, Action::Update, Action::Release] {
            assert_eq!(Action::from_bytes(action.as_bytes()), Some(action));
        }
    }

    #[test]
    fn from_bytes_rejects_non_canonical() {
        assert_eq!(Action::from_bytes(b"Claim"), None);
        assert_eq!(Action::from_bytes(b"CLAIM"), None);
        assert_eq!(Action::from_bytes(b"claim "), None);
        assert_eq!(Action::from_bytes(b""), None);
        assert_eq!(Action::from_bytes(b"transfer"), None);
    }
}

// ============================================================================
// Chain rule (name lifecycle transitions)
// ============================================================================

/// The `prev_rcm` value used for the first action in a name's chain (the
/// CLAIM). A CLAIM has no predecessor, so its `prev_rcm` is the all-zero
/// 32-byte string by definition.
///
/// This constant is part of the protocol rule, not a hash parameter.
pub const ZERO_PREV_RCM: [u8; 32] = [0u8; 32];

/// A name's chain tip as the fold sees it: the latest applied action —
/// *including* RELEASE, which resolution hides but the rule needs — and that
/// note's `rcm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    /// The latest applied action.
    pub action: Action,
    /// That Name Note's `rcm` — the link the next action must extend.
    pub rcm: [u8; 32],
}

/// The `prev_rcm` an `action` must extend given the name's current `tip`, or
/// `None` if the action does not fit the chain:
///
/// - CLAIM starts a fresh chain ([`ZERO_PREV_RCM`] genesis) on an unseen *or*
///   released name;
/// - UPDATE / RELEASE extend a live (non-released) tip, chaining off its
///   `rcm`.
pub fn prev_rcm_for(tip: Option<&Tip>, action: Action) -> Option<[u8; 32]> {
    match (action, tip) {
        (Action::Claim, None) => Some(ZERO_PREV_RCM),
        (Action::Claim, Some(t)) if t.action == Action::Release => Some(ZERO_PREV_RCM),
        (Action::Update | Action::Release, Some(t)) if t.action != Action::Release => {
            Some(t.rcm)
        }
        _ => None,
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    fn tip(action: Action, rcm: [u8; 32]) -> Tip {
        Tip { action, rcm }
    }

    #[test]
    fn claim_fits_unseen_or_released_name() {
        assert_eq!(prev_rcm_for(None, Action::Claim), Some(ZERO_PREV_RCM));
        let released = tip(Action::Release, [9u8; 32]);
        assert_eq!(
            prev_rcm_for(Some(&released), Action::Claim),
            Some(ZERO_PREV_RCM)
        );
        let live = tip(Action::Claim, [1u8; 32]);
        assert_eq!(prev_rcm_for(Some(&live), Action::Claim), None);
    }

    #[test]
    fn update_release_need_a_live_tip() {
        let live = tip(Action::Claim, [7u8; 32]);
        assert_eq!(prev_rcm_for(Some(&live), Action::Update), Some([7u8; 32]));
        assert_eq!(prev_rcm_for(Some(&live), Action::Release), Some([7u8; 32]));
        assert_eq!(prev_rcm_for(None, Action::Update), None);
        assert_eq!(prev_rcm_for(None, Action::Release), None);
        let released = tip(Action::Release, [7u8; 32]);
        assert_eq!(prev_rcm_for(Some(&released), Action::Update), None);
        assert_eq!(prev_rcm_for(Some(&released), Action::Release), None);
    }

    #[test]
    fn update_extends_update_tip() {
        let after_update = tip(Action::Update, [0xabu8; 32]);
        assert_eq!(
            prev_rcm_for(Some(&after_update), Action::Update),
            Some([0xabu8; 32])
        );
        assert_eq!(
            prev_rcm_for(Some(&after_update), Action::Release),
            Some([0xabu8; 32])
        );
        assert_eq!(prev_rcm_for(Some(&after_update), Action::Claim), None);
    }
}

// ============================================================================
// Memo grammar (canonical parser + encoder)
// ============================================================================

/*
The canonical ZNS memo grammar — one parser for every party.

`DESIGN.md §17`: the Registry (what to mint), the Resolver (what was
minted), and the future slash contract (what *should* have been minted)
must parse memos identically — if their parsers disagree, the slash
mechanism breaks. This module is that single parser, plus the matching
serializer, so agreement is by construction rather than by review.

The grammar covers every ZNS memo that appears on chain:

```text
ZNS:claim:<name>:<ua>                  lifecycle request (user → registry)
ZNS:update:<name>:<ua>                 lifecycle request
ZNS:release:<name>                     lifecycle request
ZNS:claim:<name>:<ua>:<prev_rcm>       Name Note canonical form (registry mint)
ZNS:update:<name>:<ua>:<prev_rcm>      Name Note canonical form
ZNS:release:<name>::<prev_rcm>         Name Note canonical form (ua empty)
ZNS:challenge:<name>:<nonce>           registry → owner: the OTP for a mutation
ZNS:confirm:<name>:<nonce>             owner → registry: the OTP echoed back
```

`<prev_rcm>` is 64 lowercase hex chars (`DESIGN.md §6`). It is the
*witness* for note-local verification: the commitment already binds
`prev_rcm` as a hash input, so disclosing it in the Name Note's memo lets
any scanner verify a single note's binding without first reconstructing
the name's whole chain — which is what makes the tail-scan backstop and
single-note fraud proofs (`DESIGN.md §19.4`, `§12`) work against a
withholding resolver. Fields stay positional in all forms: a RELEASE Name
Note has an explicitly empty `ua`, so `prev_rcm` never shifts columns.

The grammar is **strict**: exact field counts (extra or empty fields
reject — a lenient parser that ignores trailing fields would let two
implementations read different `ua`s from the same memo), and names follow
the DNS-label rule (≤ [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`, no leading or
trailing hyphen). Memos are ZIP-302: 512 bytes, zero-padded; trailing
zeros are stripped before parsing.
*/

/// The fixed ZIP-302 memo size, in bytes.
pub const MEMO_SIZE: usize = 512;

/// Maximum name length in bytes (the DNS label bound).
pub const MAX_NAME_LEN: usize = 63;

/// A parsed ZNS memo, borrowing from the input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedMemo<'a> {
    /// A lifecycle action: a user request, or a Name Note's canonical memo.
    /// `ua` is empty exactly for RELEASE.
    Lifecycle {
        /// CLAIM, UPDATE, or RELEASE.
        action: Action,
        /// The name acted on.
        name: &'a str,
        /// The UA being bound (empty for RELEASE).
        ua: &'a str,
        /// The disclosed chain-link witness — present exactly in the Name
        /// Note canonical form, absent in user requests. With it, the note's
        /// binding is verifiable standalone; an indexer still derives the
        /// canonical `prev_rcm` from its own tip and treats a mismatch as
        /// fork evidence.
        prev_rcm: Option<[u8; 32]>,
    },
    /// Registry → owner: the OTP challenge for a pending mutation.
    Challenge {
        /// The name under mutation.
        name: &'a str,
        /// The one-time nonce.
        nonce: &'a str,
    },
    /// Owner → registry: the OTP echoed back to authorize the mutation.
    Confirm {
        /// The name under mutation.
        name: &'a str,
        /// The echoed nonce.
        nonce: &'a str,
    },
}

/// Why a memo failed to parse.
///
/// [`MemoError::NotZns`] is the common bulk case for a scanner (an ordinary
/// payment memo); everything else means the memo claimed to be ZNS but broke
/// the grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// Not a ZNS memo at all (no `ZNS:` prefix, or not UTF-8).
    NotZns,
    /// A `ZNS:` memo with an unknown verb.
    UnknownVerb,
    /// Wrong number of `:`-separated fields for the verb.
    FieldCount,
    /// The name violates the DNS-label rule.
    InvalidName,
    /// A required argument (`ua` or `nonce`) is empty.
    EmptyArg,
    /// `prev_rcm` is not exactly 64 lowercase hex chars.
    InvalidPrevRcm,
    /// The encoded memo would exceed [`MEMO_SIZE`] bytes.
    TooLong,
}

/// Parse a committed Name Note memo and return the four values needed for
/// verification: (action, name, ua, prev_rcm).
///
/// This is the simplest entry point for the common case.
/// You only need to import `parse_name_note_memo` and `verify_name_note`.
///
/// Returns an error for request forms (no prev_rcm), non-lifecycle memos,
/// or invalid input.
pub fn parse_name_note_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8], [u8; 32]), MemoError> {
    match parse_memo(raw)? {
        ParsedMemo::Lifecycle {
            action,
            name,
            ua,
            prev_rcm: Some(prev_rcm),
        } => Ok((action.as_bytes(), name.as_bytes(), ua.as_bytes(), prev_rcm)),
        _ => Err(MemoError::FieldCount),
    }
}

fn parse_lifecycle_request(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    match parse_memo(raw)? {
        ParsedMemo::Lifecycle {
            action,
            name,
            ua,
            prev_rcm: None,
        } => Ok((action.as_bytes(), name.as_bytes(), ua.as_bytes())),
        _ => Err(MemoError::FieldCount),
    }
}

/// Parse a "claim" request memo (the user → registry form "ZNS:claim:<name>:<ua>").
/// Returns (action, name, ua).
pub fn parse_claim_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (action, name, ua) = parse_lifecycle_request(raw)?;
    if action != b"claim" {
        return Err(MemoError::UnknownVerb);
    }
    Ok((action, name, ua))
}

/// Parse an "update" request memo (the user → registry form "ZNS:update:<name>:<ua>").
/// Returns (action, name, ua).
pub fn parse_update_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (action, name, ua) = parse_lifecycle_request(raw)?;
    if action != b"update" {
        return Err(MemoError::UnknownVerb);
    }
    Ok((action, name, ua))
}

/// Parse a "release" request memo (the user → registry form "ZNS:release:<name>").
/// Returns (action, name, ua) where ua is empty.
pub fn parse_release_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (action, name, ua) = parse_lifecycle_request(raw)?;
    if action != b"release" {
        return Err(MemoError::UnknownVerb);
    }
    Ok((action, name, ua))
}

/// Parse raw memo bytes (zero-padded per ZIP-302) as a ZNS memo.
pub fn parse_memo(raw: &[u8]) -> Result<ParsedMemo<'_>, MemoError> {
    let end = raw.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
    let text = core::str::from_utf8(&raw[..end]).map_err(|_| MemoError::NotZns)?;

    let mut fields = text.split(':');
    if fields.next() != Some("ZNS") {
        return Err(MemoError::NotZns);
    }
    let verb = fields.next().ok_or(MemoError::FieldCount)?;
    let name = fields.next().ok_or(MemoError::FieldCount)?;
    validate_name(name)?;

    // Fields four and five; a sixth always rejects. Strictness here is
    // load-bearing: `split` (not `splitn`) means a `ua` containing `:` cannot
    // silently absorb trailing fields differently across implementations.
    let (arg, fifth) = (fields.next(), fields.next());
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }
    // The fifth field, when present, is always the Name Note form's
    // `prev_rcm` witness.
    let prev_rcm = fifth.map(decode_prev_rcm).transpose()?;
    fn required(arg: Option<&str>) -> Result<&str, MemoError> {
        match arg {
            Some("") | None => Err(MemoError::EmptyArg),
            Some(a) => Ok(a),
        }
    }

    match verb {
        "claim" => Ok(ParsedMemo::Lifecycle {
            action: Action::Claim,
            name,
            ua: required(arg)?,
            prev_rcm,
        }),
        "update" => Ok(ParsedMemo::Lifecycle {
            action: Action::Update,
            name,
            ua: required(arg)?,
            prev_rcm,
        }),
        "release" => match (arg, prev_rcm) {
            // Request form: exactly three fields.
            (None, None) => Ok(ParsedMemo::Lifecycle {
                action: Action::Release,
                name,
                ua: "",
                prev_rcm: None,
            }),
            // Name Note form: positional empty `ua`, then the witness.
            (Some(""), Some(_)) => Ok(ParsedMemo::Lifecycle {
                action: Action::Release,
                name,
                ua: "",
                prev_rcm,
            }),
            _ => Err(MemoError::FieldCount),
        },
        "challenge" if prev_rcm.is_none() => Ok(ParsedMemo::Challenge {
            name,
            nonce: required(arg)?,
        }),
        "confirm" if prev_rcm.is_none() => Ok(ParsedMemo::Confirm {
            name,
            nonce: required(arg)?,
        }),
        "challenge" | "confirm" => Err(MemoError::FieldCount),
        _ => Err(MemoError::UnknownVerb),
    }
}

/// Decode a `prev_rcm` field: exactly 64 lowercase hex chars.
fn decode_prev_rcm(s: &str) -> Result<[u8; 32], MemoError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(MemoError::InvalidPrevRcm);
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(MemoError::InvalidPrevRcm),
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Validate a ZNS name: 1–[`MAX_NAME_LEN`] bytes of `a-z 0-9 -`, with no
/// leading or trailing hyphen (the DNS-label rule).
pub fn validate_name(name: &str) -> Result<(), MemoError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
        return Err(MemoError::InvalidName);
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(MemoError::InvalidName);
    }
    if !bytes
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(MemoError::InvalidName);
    }
    Ok(())
}

/// Encode a lifecycle *request* memo (user → registry), zero-padded to
/// [`MEMO_SIZE`]. It round-trips through [`parse_memo`] by construction.
/// RELEASE requires an empty `ua`.
pub fn encode_request(
    action: Action,
    name: &str,
    ua: &str,
) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    let verb = lifecycle_verb(action, ua)?;
    match action {
        Action::Release => encode(&["ZNS", verb, name]),
        _ => encode(&["ZNS", verb, name, ua]),
    }
}

/// Encode a Name Note's canonical memo (registry mint), zero-padded to
/// [`MEMO_SIZE`]: the request fields plus the `prev_rcm` witness that makes
/// the note's binding verifiable standalone. RELEASE takes an empty `ua`
/// (the field stays positional).
pub fn encode_name_note(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    let verb = lifecycle_verb(action, ua)?;
    let mut hex = [0u8; 64];
    for (i, b) in prev_rcm.iter().enumerate() {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        hex[2 * i] = DIGITS[(b >> 4) as usize];
        hex[2 * i + 1] = DIGITS[(b & 0xf) as usize];
    }
    let hex = core::str::from_utf8(&hex).expect("hex digits are ASCII");
    encode(&["ZNS", verb, name, ua, hex])
}

/// The verb for a lifecycle `action`, after checking its `ua` arity:
/// CLAIM/UPDATE require a `ua`, RELEASE forbids one.
fn lifecycle_verb(action: Action, ua: &str) -> Result<&'static str, MemoError> {
    match action {
        Action::Release if !ua.is_empty() => Err(MemoError::FieldCount),
        Action::Claim | Action::Update if ua.is_empty() => Err(MemoError::EmptyArg),
        Action::Claim => Ok("claim"),
        Action::Update => Ok("update"),
        Action::Release => Ok("release"),
    }
}

/// Encode the registry's OTP challenge memo: `ZNS:challenge:<name>:<nonce>`.
pub fn encode_challenge(name: &str, nonce: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    if nonce.is_empty() {
        return Err(MemoError::EmptyArg);
    }
    encode(&["ZNS", "challenge", name, nonce])
}

/// Encode the owner's OTP echo memo: `ZNS:confirm:<name>:<nonce>`.
pub fn encode_confirm(name: &str, nonce: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    if nonce.is_empty() {
        return Err(MemoError::EmptyArg);
    }
    encode(&["ZNS", "confirm", name, nonce])
}

/// Join `fields` with `:` into a zero-padded ZIP-302 memo.
fn encode(fields: &[&str]) -> Result<[u8; MEMO_SIZE], MemoError> {
    let len = fields.iter().map(|f| f.len()).sum::<usize>() + fields.len() - 1;
    if len > MEMO_SIZE {
        return Err(MemoError::TooLong);
    }
    let mut memo = [0u8; MEMO_SIZE];
    let mut at = 0;
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            memo[at] = b':';
            at += 1;
        }
        memo[at..at + f.len()].copy_from_slice(f.as_bytes());
        at += f.len();
    }
    Ok(memo)
}

#[cfg(test)]
mod memo_tests {
    use super::*;

    fn padded(s: &str) -> [u8; MEMO_SIZE] {
        let mut m = [0u8; MEMO_SIZE];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    fn lifecycle<'a>(
        action: Action,
        name: &'a str,
        ua: &'a str,
        prev_rcm: Option<[u8; 32]>,
    ) -> ParsedMemo<'a> {
        ParsedMemo::Lifecycle {
            action,
            name,
            ua,
            prev_rcm,
        }
    }

    #[test]
    fn parses_request_forms() {
        assert_eq!(
            parse_memo(b"ZNS:claim:alice:u1xxx"),
            Ok(lifecycle(Action::Claim, "alice", "u1xxx", None)),
        );
        assert_eq!(
            parse_memo(b"ZNS:update:alice:u1new"),
            Ok(lifecycle(Action::Update, "alice", "u1new", None)),
        );
        assert_eq!(
            parse_memo(b"ZNS:release:alice"),
            Ok(lifecycle(Action::Release, "alice", "", None)),
        );
        assert_eq!(
            parse_memo(b"ZNS:challenge:alice:deadbeef"),
            Ok(ParsedMemo::Challenge {
                name: "alice",
                nonce: "deadbeef"
            }),
        );
        assert_eq!(
            parse_memo(b"ZNS:confirm:alice:deadbeef"),
            Ok(ParsedMemo::Confirm {
                name: "alice",
                nonce: "deadbeef"
            }),
        );
    }

    #[test]
    fn parses_name_note_forms() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut want = [0u8; 32];
        hex::decode_to_slice(hex, &mut want).unwrap();

        let m = format!("ZNS:claim:alice:u1xxx:{hex}");
        assert_eq!(
            parse_memo(m.as_bytes()),
            Ok(lifecycle(Action::Claim, "alice", "u1xxx", Some(want))),
        );
        // RELEASE keeps `ua` positional (explicitly empty).
        let m = format!("ZNS:release:alice::{hex}");
        assert_eq!(
            parse_memo(m.as_bytes()),
            Ok(lifecycle(Action::Release, "alice", "", Some(want)))
        );

        // The witness must be exactly 64 lowercase hex chars.
        assert_eq!(
            parse_memo(b"ZNS:claim:alice:u1xxx:abcd"),
            Err(MemoError::InvalidPrevRcm)
        );
        let upper = format!("ZNS:claim:alice:u1xxx:{}", hex.to_uppercase());
        assert_eq!(parse_memo(upper.as_bytes()), Err(MemoError::InvalidPrevRcm));
        // Auth verbs never take a fifth field.
        let m = format!("ZNS:confirm:alice:nonce:{hex}");
        assert_eq!(parse_memo(m.as_bytes()), Err(MemoError::FieldCount));
    }

    #[test]
    fn zero_padding_is_stripped() {
        assert_eq!(
            parse_memo(&padded("ZNS:claim:alice:u1xxx")),
            Ok(lifecycle(Action::Claim, "alice", "u1xxx", None)),
        );
    }

    #[test]
    fn non_zns_memos_are_not_zns() {
        assert_eq!(parse_memo(b"just a payment note"), Err(MemoError::NotZns));
        assert_eq!(parse_memo(b"ZEC:claim:alice:u1"), Err(MemoError::NotZns));
        assert_eq!(parse_memo(&[0u8; MEMO_SIZE]), Err(MemoError::NotZns));
        assert_eq!(parse_memo(&[0xff, 0xfe]), Err(MemoError::NotZns));
    }

    #[test]
    fn strict_field_counts() {
        // The historic divergence this parser exists to kill: trailing fields
        // must reject, never be absorbed into `ua` or silently ignored. (A
        // fifth lifecycle field is legal only as a valid prev_rcm witness.)
        assert_eq!(
            parse_memo(b"ZNS:update:alice:u1x:extra"),
            Err(MemoError::InvalidPrevRcm)
        );
        assert_eq!(
            parse_memo(b"ZNS:release:alice:junk"),
            Err(MemoError::FieldCount)
        );
        assert_eq!(
            parse_memo(b"ZNS:release:alice:"),
            Err(MemoError::FieldCount)
        );
        assert_eq!(parse_memo(b"ZNS:claim:alice"), Err(MemoError::EmptyArg));
        assert_eq!(parse_memo(b"ZNS:claim:alice:"), Err(MemoError::EmptyArg));
        assert_eq!(parse_memo(b"ZNS:confirm:alice"), Err(MemoError::EmptyArg));
        assert_eq!(parse_memo(b"ZNS:claim"), Err(MemoError::FieldCount));
        assert_eq!(
            parse_memo(b"ZNS:settle:alice:u1x"),
            Err(MemoError::UnknownVerb)
        );
    }

    #[test]
    fn name_rule_is_dns_label() {
        assert_eq!(validate_name("alice"), Ok(()));
        assert_eq!(validate_name("a-1"), Ok(()));
        assert_eq!(validate_name(""), Err(MemoError::InvalidName));
        assert_eq!(validate_name("-alice"), Err(MemoError::InvalidName));
        assert_eq!(validate_name("alice-"), Err(MemoError::InvalidName));
        assert_eq!(validate_name("Alice"), Err(MemoError::InvalidName));
        assert_eq!(validate_name("al ice"), Err(MemoError::InvalidName));
        assert_eq!(validate_name(&"a".repeat(63)), Ok(()));
        assert_eq!(validate_name(&"a".repeat(64)), Err(MemoError::InvalidName));
        // And through the parser:
        assert_eq!(
            parse_memo(b"ZNS:claim:Alice:u1x"),
            Err(MemoError::InvalidName)
        );
    }

    #[test]
    fn encode_round_trips() {
        let m = encode_request(Action::Claim, "alice", "u1xxx").unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(lifecycle(Action::Claim, "alice", "u1xxx", None))
        );
        let m = encode_request(Action::Release, "alice", "").unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(lifecycle(Action::Release, "alice", "", None))
        );

        let prev = [0xa5u8; 32];
        let m = encode_name_note(Action::Update, "alice", "u1new", &prev).unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(lifecycle(Action::Update, "alice", "u1new", Some(prev)))
        );
        let m = encode_name_note(Action::Release, "alice", "", &prev).unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(lifecycle(Action::Release, "alice", "", Some(prev)))
        );

        let m = encode_challenge("alice", "deadbeef").unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(ParsedMemo::Challenge {
                name: "alice",
                nonce: "deadbeef"
            })
        );
        let m = encode_confirm("alice", "deadbeef").unwrap();
        assert_eq!(
            parse_memo(&m),
            Ok(ParsedMemo::Confirm {
                name: "alice",
                nonce: "deadbeef"
            })
        );
    }

    #[test]
    fn encode_rejects_what_parse_rejects() {
        assert_eq!(
            encode_request(Action::Claim, "alice", ""),
            Err(MemoError::EmptyArg)
        );
        assert_eq!(
            encode_request(Action::Release, "alice", "u1x"),
            Err(MemoError::FieldCount)
        );
        assert_eq!(
            encode_request(Action::Claim, "Alice", "u1x"),
            Err(MemoError::InvalidName)
        );
        assert_eq!(
            encode_name_note(Action::Claim, "alice", "", &[0u8; 32]),
            Err(MemoError::EmptyArg)
        );
        assert_eq!(encode_challenge("alice", ""), Err(MemoError::EmptyArg));
        // A ua that cannot fit the ZIP-302 memo.
        let huge = "u".repeat(MEMO_SIZE);
        assert_eq!(
            encode_request(Action::Claim, "alice", &huge),
            Err(MemoError::TooLong)
        );
    }
}
