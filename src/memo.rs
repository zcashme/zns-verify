//! Protocol rules for ZNS -- the reference definition of the Name Note memo grammar and lifecycle rules.

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
// Name Note memo grammar (canonical parser + encoder)
// ============================================================================

/*

The canonical Name Note memo grammar -- one parser for every party.

This kernel covers only the memos that appear on chain (WP §3.1). Request
memos (user -> Mint treasury intake) are a separate lane with its own
implementation and are deliberately out of scope here.

```text
ZNS:claim:<name>:<ua>:<expires_at>:<prev_rcm>   Name Note canonical form (WP §3.1)
ZNS:update:<name>:<ua>:<expires_at>:<prev_rcm>  Name Note canonical form
ZNS:release:<name>:<ua>:none:<prev_rcm>          Name Note canonical form
```

`<prev_rcm>` is 64 lowercase hex chars. It is the *witness* for note-local
verification: the commitment already binds `prev_rcm` as a hash input, so
disclosing it in the Name Note's memo lets any scanner verify a single note's
binding without first reconstructing the name's whole chain. `<expires_at>`
is canonical ASCII decimal or the exact bytes `none` (WP §3.1). A RELEASE
MUST encode the released UA and exactly `none` for `expires_at`. Fields stay
positional in all forms.

The grammar is **strict**: exact field counts (extra or empty fields reject),
and names follow the ZNS name rule (≤ [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`,
no leading or trailing hyphen). Memos are ZIP-302: 512 bytes, zero-padded;
trailing zeros are stripped before parsing.
*/

/// The fixed ZIP-302 memo size, in bytes.
pub const MEMO_SIZE: usize = 512;

/// Maximum name length in bytes (the ZNS name rule bound).
pub const MAX_NAME_LEN: usize = 63;

/// A committed ZNS Name Note (the form that appears on-chain).
///
/// This is the only memo shape that carries a `prev_rcm` witness and can be
/// directly used with `verify_name_note`.
///
/// The `expires_at` field is the raw ASCII bytes from the memo: canonical
/// decimal for a fixed-term registration, or the exact bytes `none` for a
/// registration without fixed expiration (WP §3.1). A RELEASE MUST encode
/// `none` (WP §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameNote<'a> {
    /// CLAIM, UPDATE, or RELEASE.
    pub action: Action,
    /// The name being acted on.
    pub name: &'a str,
    /// The UA being bound (the released UA for RELEASE; never empty).
    pub ua: &'a str,
    /// The `expires_at` field: canonical decimal or `none`.
    pub expires_at: &'a str,
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
    /// The name violates the ZNS name rule.
    InvalidName,
    /// The required `ua` field is empty.
    EmptyArg,
    /// `prev_rcm` is not exactly 64 lowercase hex chars.
    InvalidPrevRcm,
    /// The encoded memo would exceed [`MEMO_SIZE`] bytes.
    TooLong,
}

/// Parse a committed Name Note (the on-chain form) into its fields.
///
/// The canonical form is six fields (WP §3.1):
/// `ZNS:<verb>:<name>:<ua>:<expires_at>:<prev_rcm>`
///
/// A RELEASE must encode the released UA (not empty) and exactly `none`
/// for `expires_at` (WP §3.1). Request forms (fewer fields) are rejected.
pub fn parse_name_note(raw: &[u8]) -> Result<NameNote<'_>, MemoError> {
    let end = raw.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
    let text = core::str::from_utf8(&raw[..end]).map_err(|_| MemoError::NotZns)?;

    let mut fields = text.split(':');
    if fields.next() != Some("ZNS") {
        return Err(MemoError::NotZns);
    }
    let verb = fields.next().ok_or(MemoError::FieldCount)?;
    let name = fields.next().ok_or(MemoError::FieldCount)?;
    validate_name(name)?;

    // Fields four to six; a seventh always rejects. Strictness here is
    // load-bearing: `split` (not `splitn`) means a `ua` containing `:` cannot
    // silently absorb trailing fields differently across implementations.
    let ua = fields.next().ok_or(MemoError::FieldCount)?;
    let expires_at = fields.next().ok_or(MemoError::FieldCount)?;
    let prev_hex = fields.next().ok_or(MemoError::FieldCount)?;
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }
    if ua.is_empty() {
        return Err(MemoError::EmptyArg);
    }
    let prev_rcm = decode_prev_rcm(prev_hex)?;

    match verb {
        "claim" => Ok(NameNote {
            action: Action::Claim,
            name,
            ua,
            expires_at,
            prev_rcm,
        }),
        "update" => Ok(NameNote {
            action: Action::Update,
            name,
            ua,
            expires_at,
            prev_rcm,
        }),
        "release" => {
            if expires_at != "none" {
                return Err(MemoError::FieldCount);
            }
            Ok(NameNote {
                action: Action::Release,
                name,
                ua,
                expires_at,
                prev_rcm,
            })
        }
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
    let (pairs, _) = bytes.as_chunks::<2>();
    for (i, pair) in pairs.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Validate a ZNS name: 1 to [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`, with no
/// leading or trailing hyphen (the ZNS name rule).
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

/// Encode a Name Note's canonical memo (registry mint), zero-padded to
/// [`MEMO_SIZE`]: the binding fields plus `expires_at` and the `prev_rcm`
/// witness that makes the note's binding verifiable standalone (WP §3.1).
///
/// A RELEASE must encode the released UA and exactly `none` for `expires_at`.
pub fn encode_name_note(
    action: Action,
    name: &str,
    ua: &str,
    expires_at: &str,
    prev_rcm: &[u8; 32],
) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    let verb = match action {
        Action::Release if expires_at != "none" => return Err(MemoError::FieldCount),
        Action::Release if ua.is_empty() => return Err(MemoError::EmptyArg),
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
    encode(&["ZNS", verb, name, ua, expires_at, hex])
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
