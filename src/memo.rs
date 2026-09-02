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

Request memos (user -> Mint / treasury), WP intake / mint RequestMemo::parse:

```text
ZNS:claim:<name>:<ua>                           claim request (user -> Mint)
ZNS:update:<name>:<ua>                          update request
ZNS:update:<name>:<ua>:<otp>                    update request with OTP
ZNS:release:<name>:<ua>                         release request
ZNS:release:<name>:<ua>:<otp>                   release request with OTP
```

Name Notes (Mint -> chain), WP §3.1:

```text
ZNS:claim:<name>:<ua>:<expires_at>:<prev_rcm>   Name Note canonical form (WP §3.1)
ZNS:update:<name>:<ua>:<expires_at>:<prev_rcm>  Name Note canonical form
ZNS:release:<name>:<ua>:none:<prev_rcm>          Name Note canonical form
```

Claim, update, and release requests all require a non-empty UA. Claim MUST
NOT carry an OTP. Update/release MAY append exactly six ASCII decimal digits
(leading zeroes allowed). Requests MUST NOT carry `expires_at` or `prev_rcm`.
`ZNS:otp:<otp>:<name>:<verb>:<ua>` relay memos (otp first) are not
requests ([`MemoError::UnknownVerb`]).

Name Notes are six fields. `<prev_rcm>` is 64 lowercase hex chars. It is the
witness for note-local verification: the commitment already binds `prev_rcm`
as a hash input, so disclosing it in the memo lets any scanner verify a
single note without reconstructing the name's whole chain. `<expires_at>` is
exactly `none` or canonical ASCII decimal (digits only, no sign, no leading
zeroes except `0`). A RELEASE MUST encode the released UA and exactly `none`.

The grammar is **strict**: extra or empty required fields reject, and names
follow the DNS-label rule (≤ [`MAX_NAME_LEN`] bytes of `a-z 0-9 -`, no
leading or trailing hyphen). Memos are ZIP-302: 512 bytes, zero-padded;
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

/// A parsed user request memo (user -> Mint), matching mint `RequestMemo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMemo<'a> {
    /// `ZNS:claim:<name>:<ua>` -- no OTP field.
    Claim {
        /// Canonical name.
        name: &'a str,
        /// Opaque UA bytes as UTF-8 (not ZIP-316-decoded).
        ua: &'a str,
    },
    /// `ZNS:update:<name>:<ua>` or `ZNS:update:<name>:<ua>:<otp>`.
    Update {
        /// Canonical name.
        name: &'a str,
        /// Opaque UA bytes as UTF-8 (not ZIP-316-decoded).
        ua: &'a str,
        /// Optional six ASCII decimal digits.
        otp: Option<[u8; 6]>,
    },
    /// `ZNS:release:<name>:<ua>` or `ZNS:release:<name>:<ua>:<otp>`.
    Release {
        /// Canonical name.
        name: &'a str,
        /// Opaque UA bytes as UTF-8 (not ZIP-316-decoded).
        ua: &'a str,
        /// Optional six ASCII decimal digits.
        otp: Option<[u8; 6]>,
    },
}

impl<'a> RequestMemo<'a> {
    /// The action for this request.
    pub fn action(self) -> Action {
        match self {
            RequestMemo::Claim { .. } => Action::Claim,
            RequestMemo::Update { .. } => Action::Update,
            RequestMemo::Release { .. } => Action::Release,
        }
    }

    /// The canonical name.
    pub fn name(self) -> &'a str {
        match self {
            RequestMemo::Claim { name, .. }
            | RequestMemo::Update { name, .. }
            | RequestMemo::Release { name, .. } => name,
        }
    }

    /// The opaque UA field.
    pub fn ua(self) -> &'a str {
        match self {
            RequestMemo::Claim { ua, .. }
            | RequestMemo::Update { ua, .. }
            | RequestMemo::Release { ua, .. } => ua,
        }
    }

    /// The OTP digits, if this is an update/release that carried one.
    pub fn otp(self) -> Option<[u8; 6]> {
        match self {
            RequestMemo::Claim { .. } => None,
            RequestMemo::Update { otp, .. } | RequestMemo::Release { otp, .. } => otp,
        }
    }
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
    /// A required argument (`ua`) is empty.
    EmptyArg,
    /// `prev_rcm` is not exactly 64 lowercase hex chars.
    InvalidPrevRcm,
    /// `otp` is not exactly six ASCII decimal digits.
    InvalidOtp,
    /// The encoded memo would exceed [`MEMO_SIZE`] bytes.
    TooLong,
}

/// Strip ZIP-302 trailing zeros and require a `ZNS:` prefix.
fn zns_text(raw: &[u8]) -> Result<&str, MemoError> {
    let end = raw.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
    let text = core::str::from_utf8(&raw[..end]).map_err(|_| MemoError::NotZns)?;
    if !text.starts_with("ZNS:") {
        return Err(MemoError::NotZns);
    }
    Ok(text)
}

/// A required UA field: missing is [`MemoError::FieldCount`], empty is [`MemoError::EmptyArg`].
fn required_ua(ua: Option<&str>) -> Result<&str, MemoError> {
    match ua {
        None => Err(MemoError::FieldCount),
        Some("") => Err(MemoError::EmptyArg),
        Some(a) => Ok(a),
    }
}

/// Parse a user request memo into [`RequestMemo`] (mint intake grammar).
///
/// Six-field Name Notes and `ZNS:otp:<otp>:<name>:<verb>:<ua>` relays are
/// rejected here.
pub fn parse_request(raw: &[u8]) -> Result<RequestMemo<'_>, MemoError> {
    let text = zns_text(raw)?;
    let mut fields = text.split(':');
    let _ = fields.next();
    let verb = fields.next().ok_or(MemoError::FieldCount)?;
    // Relay memos (`otp`) and any other verb are not requests, even if the
    // rest of the field layout could look like an update/release.
    let action = Action::from_bytes(verb.as_bytes()).ok_or(MemoError::UnknownVerb)?;

    let name = fields.next().ok_or(MemoError::FieldCount)?;
    validate_name(name)?;
    let ua = required_ua(fields.next())?;
    let otp_str = fields.next();
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }

    match action {
        Action::Claim => {
            if otp_str.is_some() {
                return Err(MemoError::FieldCount);
            }
            Ok(RequestMemo::Claim { name, ua })
        }
        Action::Update => Ok(RequestMemo::Update {
            name,
            ua,
            otp: otp_str.map(decode_otp).transpose()?,
        }),
        Action::Release => Ok(RequestMemo::Release {
            name,
            ua,
            otp: otp_str.map(decode_otp).transpose()?,
        }),
    }
}

/// Parse a committed Name Note (the on-chain form) into its fields.
///
/// The canonical form is six fields (WP §3.1):
/// `ZNS:<verb>:<name>:<ua>:<expires_at>:<prev_rcm>`
///
/// A RELEASE must encode the released UA (not empty) and exactly `none`
/// for `expires_at` (WP §3.1). Request forms (no `prev_rcm`) are rejected.
pub fn parse_name_note(raw: &[u8]) -> Result<NameNote<'_>, MemoError> {
    let text = zns_text(raw)?;
    let mut fields = text.split(':');
    let _ = fields.next();
    let verb = fields.next().ok_or(MemoError::FieldCount)?;
    let name = fields.next().ok_or(MemoError::FieldCount)?;
    validate_name(name)?;
    let ua = required_ua(fields.next())?;
    let expires_at = fields.next().ok_or(MemoError::FieldCount)?;
    let prev_hex = fields.next().ok_or(MemoError::FieldCount)?;
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }

    validate_expires_at(expires_at)?;
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

/// Parse a claim request: `ZNS:claim:<name>:<ua>`.
///
/// Returns `(action, name, ua)`.
#[allow(clippy::type_complexity)]
pub fn parse_claim_memo(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MemoError> {
    match parse_request(raw)? {
        RequestMemo::Claim { name, ua } => Ok((b"claim", name.as_bytes(), ua.as_bytes())),
        _ => Err(MemoError::UnknownVerb),
    }
}

/// Parse an update request: `ZNS:update:<name>:<ua>[:<otp>]`.
///
/// Returns `(action, name, ua, otp)`.
#[allow(clippy::type_complexity)]
pub fn parse_update_memo(
    raw: &[u8],
) -> Result<(&[u8], &[u8], &[u8], Option<[u8; 6]>), MemoError> {
    match parse_request(raw)? {
        RequestMemo::Update { name, ua, otp } => {
            Ok((b"update", name.as_bytes(), ua.as_bytes(), otp))
        }
        _ => Err(MemoError::UnknownVerb),
    }
}

/// Parse a release request: `ZNS:release:<name>:<ua>[:<otp>]`.
///
/// Returns `(action, name, ua, otp)`. The UA is never empty.
#[allow(clippy::type_complexity)]
pub fn parse_release_memo(
    raw: &[u8],
) -> Result<(&[u8], &[u8], &[u8], Option<[u8; 6]>), MemoError> {
    match parse_request(raw)? {
        RequestMemo::Release { name, ua, otp } => {
            Ok((b"release", name.as_bytes(), ua.as_bytes(), otp))
        }
        _ => Err(MemoError::UnknownVerb),
    }
}

/// `expires_at`: exactly `none`, or canonical ASCII decimal (digits only,
/// no sign, no leading zeroes except `0`, at most 20 digits and a valid `u64`).
fn validate_expires_at(s: &str) -> Result<(), MemoError> {
    if s == "none" {
        return Ok(());
    }
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MemoError::FieldCount);
    }
    if s.len() > 1 && s.as_bytes()[0] == b'0' {
        return Err(MemoError::FieldCount);
    }
    s.parse::<u64>().map(|_| ()).map_err(|_| MemoError::FieldCount)
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

/// Decode an `otp` field: exactly six ASCII decimal digits.
fn decode_otp(s: &str) -> Result<[u8; 6], MemoError> {
    let bytes = s.as_bytes();
    if bytes.len() != 6 {
        return Err(MemoError::InvalidOtp);
    }
    let mut out = [0u8; 6];
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_digit() {
            return Err(MemoError::InvalidOtp);
        }
        out[i] = b;
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

fn action_verb(action: Action, ua: &str) -> Result<&'static str, MemoError> {
    if ua.is_empty() {
        return Err(MemoError::EmptyArg);
    }
    Ok(match action {
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    })
}

/// Encode a lifecycle request memo without an OTP, zero-padded to
/// [`MEMO_SIZE`]. Claim, update, and release all take a non-empty `ua`.
pub fn encode_request(action: Action, name: &str, ua: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
    encode_request_inner(action, name, ua, None)
}

/// Encode an update or release request that carries a six-digit OTP.
///
/// Claim with an OTP is [`MemoError::FieldCount`]. Non-digit OTP bytes are
/// [`MemoError::InvalidOtp`].
pub fn encode_request_with_otp(
    action: Action,
    name: &str,
    ua: &str,
    otp: &[u8; 6],
) -> Result<[u8; MEMO_SIZE], MemoError> {
    encode_request_inner(action, name, ua, Some(otp))
}

fn encode_request_inner(
    action: Action,
    name: &str,
    ua: &str,
    otp: Option<&[u8; 6]>,
) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    let verb = action_verb(action, ua)?;
    match (action, otp) {
        (Action::Claim, Some(_)) => Err(MemoError::FieldCount),
        (_, None) => encode(&["ZNS", verb, name, ua]),
        (_, Some(digits)) => {
            if !digits.iter().all(|b| b.is_ascii_digit()) {
                return Err(MemoError::InvalidOtp);
            }
            let otp_s = core::str::from_utf8(digits).expect("ASCII digits");
            encode(&["ZNS", verb, name, ua, otp_s])
        }
    }
}

/// Encode a Name Note's canonical memo (registry mint), zero-padded to
/// [`MEMO_SIZE`]: the request fields plus `expires_at` and the `prev_rcm`
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
    let verb = action_verb(action, ua)?;
    if action == Action::Release && expires_at != "none" {
        return Err(MemoError::FieldCount);
    }
    validate_expires_at(expires_at)?;
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
