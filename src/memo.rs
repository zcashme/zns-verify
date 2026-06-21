//! Protocol rules for ZNS — the single source of truth for cross-implementation agreement.
//!

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
        (Action::Update | Action::Release, Some(t)) if t.action != Action::Release => Some(t.rcm),
        _ => None,
    }
}

// ============================================================================
// Memo grammar (canonical parser + encoder)
// ============================================================================

/*
The canonical ZNS memo grammar — one parser for every party.

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

/// A committed ZNS Name Note (the form that appears on-chain).
///
/// This is the only memo shape that carries a `prev_rcm` witness and can be
/// directly used with `verify_name_note`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameNote<'a> {
    /// CLAIM, UPDATE, or RELEASE.
    pub action: Action,
    /// The name being acted on.
    pub name: &'a str,
    /// The UA being bound (empty for RELEASE).
    pub ua: &'a str,
    /// The disclosed `prev_rcm` witness from the on-chain Name Note.
    pub prev_rcm: [u8; 32],
}

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
/// **Legacy tuple API.** Prefer [`parse_name_note`] for new code — it returns
/// the clean `NameNote` struct with a non-optional `prev_rcm`.
pub fn parse_name_note_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8], [u8; 32]), MemoError> {
    let note = parse_name_note(raw)?;
    Ok((
        note.action.as_bytes(),
        note.name.as_bytes(),
        note.ua.as_bytes(),
        note.prev_rcm,
    ))
}

/// Parse a committed Name Note memo (the on-chain form) returning a `NameNote`.
///
/// This is the preferred API for verification: it returns a structured `NameNote`
/// with a guaranteed `prev_rcm` instead of an `Option`.
pub fn parse_name_note(raw: &[u8]) -> Result<NameNote<'_>, MemoError> {
    let (action_bytes, name_bytes, ua_bytes, prev_rcm) = parse_name_note_memo(raw)?;
    let action = Action::from_bytes(action_bytes)
        .ok_or(MemoError::UnknownVerb)?;
    let name = core::str::from_utf8(name_bytes)
        .expect("name bytes came from validated &str");
    let ua = core::str::from_utf8(ua_bytes)
        .expect("ua bytes came from validated &str");
    Ok(NameNote {
        action,
        name,
        ua,
        prev_rcm,
    })
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
pub fn encode_request(action: Action, name: &str, ua: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
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
