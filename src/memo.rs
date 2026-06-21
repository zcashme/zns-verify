//! Protocol rules for ZNS -- the reference definition of the memo grammar and lifecycle rules.

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

/// The genesis `prev_rcm` for CLAIM (initial value at the start of a name's chain).
pub const ZERO_PREV_RCM: [u8; 32] = [0u8; 32];

/// Name chain tip for the lifecycle rule (includes RELEASE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    /// Latest action.
    pub action: Action,
    /// `rcm` the next action must extend.
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
The canonical ZNS memo grammar -- one parser for every party.

The grammar covers the ZNS memos that appear on chain:

```text
ZNS:claim:<name>:<ua>                  lifecycle request (user → registry)
ZNS:update:<name>:<ua>                 lifecycle request
ZNS:release:<name>                     lifecycle request
ZNS:claim:<name>:<ua>:<prev_rcm>       Name Note canonical form (registry mint)
ZNS:update:<name>:<ua>:<prev_rcm>      Name Note canonical form
ZNS:release:<name>::<prev_rcm>         Name Note canonical form (ua empty)
```

`<prev_rcm>` is 64 lowercase hex chars. It is the *witness* for note-local
verification: the commitment already binds `prev_rcm` as a hash input, so
disclosing it in the Name Note's memo lets any scanner verify a single note's
binding without first reconstructing the name's whole chain. Fields stay
positional in all forms: a RELEASE Name Note has an explicitly empty `ua`,
so `prev_rcm` never shifts columns.

The grammar is **strict**: exact field counts (extra or empty fields reject),
and names follow the DNS-label rule (≤ [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`,
no leading or trailing hyphen). Memos are ZIP-302: 512 bytes, zero-padded;
trailing zeros are stripped before parsing.
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

/// Common logic for splitting a ZNS: memo into its fields.
/// This is the single strict implementation of the grammar rules
/// (field counts, name validation, prev_rcm hex decoding, etc.).
fn parse_zns_memo_fields(raw: &[u8]) -> Result<(&str, &str, Option<&str>, Option<[u8; 32]>), MemoError> {
    let end = raw.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
    let text = core::str::from_utf8(&raw[..end]).map_err(|_| MemoError::NotZns)?;

    let mut fields = text.split(':');
    if fields.next() != Some("ZNS") {
        return Err(MemoError::NotZns);
    }
    let verb = fields.next().ok_or(MemoError::FieldCount)?;
    let name = fields.next().ok_or(MemoError::FieldCount)?;
    validate_name(name)?;

    let (arg, fifth) = (fields.next(), fields.next());
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }
    let prev_rcm = fifth.map(decode_prev_rcm).transpose()?;
    Ok((verb, name, arg, prev_rcm))
}

/// Parse a committed Name Note (the on-chain form) into its fields.
pub fn parse_name_note(raw: &[u8]) -> Result<NameNote<'_>, MemoError> {
    let (verb, name, arg, prev_rcm) = parse_zns_memo_fields(raw)?;
    let prev_rcm = prev_rcm.ok_or(MemoError::FieldCount)?;

    fn required(arg: Option<&str>) -> Result<&str, MemoError> {
        match arg {
            Some("") | None => Err(MemoError::EmptyArg),
            Some(a) => Ok(a),
        }
    }

    match verb {
        "claim" => Ok(NameNote {
            action: Action::Claim,
            name,
            ua: required(arg)?,
            prev_rcm,
        }),
        "update" => Ok(NameNote {
            action: Action::Update,
            name,
            ua: required(arg)?,
            prev_rcm,
        }),
        "release" => {
            if arg != Some("") {
                return Err(MemoError::FieldCount);
            }
            Ok(NameNote {
                action: Action::Release,
                name,
                ua: "",
                prev_rcm,
            })
        }
        _ => Err(MemoError::UnknownVerb),
    }
}

/// Parse a "claim" request memo (the user → registry form "ZNS:claim:<name>:<ua>").
/// Returns (action, name, ua).
pub fn parse_claim_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (verb, name, arg, prev_rcm) = parse_zns_memo_fields(raw)?;
    if prev_rcm.is_some() {
        return Err(MemoError::FieldCount);
    }
    if verb != "claim" {
        return Err(MemoError::UnknownVerb);
    }
    let ua = match arg {
        Some(a) if !a.is_empty() => a,
        _ => return Err(MemoError::EmptyArg),
    };
    Ok((b"claim", name.as_bytes(), ua.as_bytes()))
}

/// Parse an "update" request memo (the user → registry form "ZNS:update:<name>:<ua>").
/// Returns (action, name, ua).
pub fn parse_update_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (verb, name, arg, prev_rcm) = parse_zns_memo_fields(raw)?;
    if prev_rcm.is_some() {
        return Err(MemoError::FieldCount);
    }
    if verb != "update" {
        return Err(MemoError::UnknownVerb);
    }
    let ua = match arg {
        Some(a) if !a.is_empty() => a,
        _ => return Err(MemoError::EmptyArg),
    };
    Ok((b"update", name.as_bytes(), ua.as_bytes()))
}

/// Parse a "release" request memo (the user → registry form "ZNS:release:<name>").
/// Returns (action, name, ua) where ua is empty.
pub fn parse_release_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    let (verb, name, arg, prev_rcm) = parse_zns_memo_fields(raw)?;
    if prev_rcm.is_some() {
        return Err(MemoError::FieldCount);
    }
    if verb != "release" {
        return Err(MemoError::UnknownVerb);
    }
    if arg.is_some() {
        return Err(MemoError::FieldCount);
    }
    Ok((b"release", name.as_bytes(), b""))
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

/// Validate a ZNS name: 1 to [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`, with no
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
/// [`MEMO_SIZE`]. It round-trips through the strict grammar parser by construction.
/// RELEASE requires an empty `ua`.
pub fn encode_request(action: Action, name: &str, ua: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    let verb = match action {
        Action::Release if !ua.is_empty() => return Err(MemoError::FieldCount),
        Action::Claim | Action::Update if ua.is_empty() => return Err(MemoError::EmptyArg),
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    };
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
    let verb = match action {
        Action::Release if !ua.is_empty() => return Err(MemoError::FieldCount),
        Action::Claim | Action::Update if ua.is_empty() => return Err(MemoError::EmptyArg),
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    };
    let mut hex = [0u8; 64];
    for (i, b) in prev_rcm.iter().enumerate() {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        hex[2 * i] = DIGITS[(b >> 4) as usize];
        hex[2 * i + 1] = DIGITS[(b & 0xf) as usize];
    }
    let hex = core::str::from_utf8(&hex).expect("hex digits are ASCII");
    encode(&["ZNS", verb, name, ua, hex])
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
