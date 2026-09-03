//! The Name Note memo grammar and lifecycle rules.

/// The fixed ZIP-302 memo size, in bytes.
pub const MEMO_SIZE: usize = 512;

/// A zero-padded ZIP-302 memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memo([u8; MEMO_SIZE]);

impl Memo {
    /// Creates a memo from bytes, zero-padded to [`MEMO_SIZE`].
    ///
    /// Returns [`MemoError::TooLong`] when `bytes` exceeds [`MEMO_SIZE`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
        if bytes.len() > MEMO_SIZE {
            return Err(MemoError::TooLong);
        }
        let mut memo = [0u8; MEMO_SIZE];
        memo[..bytes.len()].copy_from_slice(bytes);
        Ok(Memo(memo))
    }

    /// Creates a memo directly from a fixed-size array.
    pub const fn from_array(bytes: [u8; MEMO_SIZE]) -> Self {
        Memo(bytes)
    }

    /// The underlying bytes, including zero padding.
    pub const fn as_array(&self) -> &[u8; MEMO_SIZE] {
        &self.0
    }

    /// The memo text, provided the padding is canonical and the content is UTF-8.
    pub fn text(&self) -> Option<&str> {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        if self.0[end..].iter().any(|&b| b != 0) {
            return None;
        }
        core::str::from_utf8(&self.0[..end]).ok()
    }
}

/// The maximum name length in bytes (the ZNS name rule bound).
pub const MAX_NAME_LEN: usize = 63;

/// A validated ZNS name: 1 to [`MAX_NAME_LEN`] bytes of `a-z 0-9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a>(&'a str);

impl<'a> Name<'a> {
    /// Validates a name per the ZNS name rule.
    pub fn parse(s: &'a str) -> Result<Self, MemoError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return Err(MemoError::InvalidName);
        }
        if !bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9')) {
            return Err(MemoError::InvalidName);
        }
        Ok(Name(s))
    }

    /// The validated name.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// A validated Zcash unified address: non-empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ua<'a>(&'a str);

impl<'a> Ua<'a> {
    /// Validates a UA per the ZNS memo rule.
    pub fn parse(s: &'a str) -> Result<Self, MemoError> {
        if s.is_empty() {
            return Err(MemoError::EmptyUa);
        }
        Ok(Ua(s))
    }

    /// The validated UA.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// The committed expiration of a registration: exactly `none`, or a
/// canonical ASCII decimal Unix timestamp in whole seconds (WP §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expiry<'a>(&'a str);

impl<'a> Expiry<'a> {
    /// The expiry of a registration without fixed expiration.
    pub const NEVER: Self = Expiry("none");

    /// Validates the `expires_at` memo field (WP §3.1).
    ///
    /// Non-canonical spellings are rejected because the raw field bytes are
    /// hashed into the commitment: `1` and `01` are different transitions.
    pub fn from_field(s: &'a str) -> Result<Self, MemoError> {
        if s == "none" {
            return Ok(Expiry("none"));
        }
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(MemoError::InvalidExpiry);
        }
        if bytes.len() > 1 && bytes[0] == b'0' {
            return Err(MemoError::InvalidExpiry);
        }
        Ok(Expiry(s))
    }

    /// The raw field bytes, hashed verbatim into the commitment.
    pub const fn field_bytes(&self) -> &'a str {
        self.0
    }

    /// Whether the registration has no fixed expiration.
    pub fn is_never(&self) -> bool {
        self.0 == "none"
    }
}

/// The disclosed predecessor witness of a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrevRcm([u8; 32]);

impl PrevRcm {
    /// The 64-zero predecessor of a claim (WP §3.1).
    pub const ZERO: Self = PrevRcm([0u8; 32]);

    /// Decodes exactly 64 lowercase hex chars.
    pub fn from_hex(s: &str) -> Result<Self, MemoError> {
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
        Ok(PrevRcm(out))
    }

    /// The 64-char lowercase hex encoding.
    pub fn to_hex(&self) -> [u8; 64] {
        let mut hex = [0u8; 64];
        for (i, b) in self.0.iter().enumerate() {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            hex[2 * i] = DIGITS[(b >> 4) as usize];
            hex[2 * i + 1] = DIGITS[(b & 0xf) as usize];
        }
        hex
    }

    /// The raw predecessor bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is the zero predecessor.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// A ZNS name action.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Point a name to an address.
    Claim,
    /// Rebind a name to a new address.
    Update,
    /// Terminate a name's linkage to an address.
    Release,
}

impl Action {
    /// The canonical ASCII bytes used in hash inputs.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Action::Claim => b"claim",
            Action::Update => b"update",
            Action::Release => b"release",
        }
    }

    /// Parses the canonical ASCII form, case-sensitive.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"claim" => Some(Action::Claim),
            b"update" => Some(Action::Update),
            b"release" => Some(Action::Release),
            _ => None,
        }
    }
}

/// The genesis `prev_rcm` for a claim.
pub const ZERO_PREV_RCM: [u8; 32] = [0u8; 32];

/// The live tip of a name's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    /// The latest action.
    pub action: Action,
    /// The `rcm` the next action must extend.
    pub rcm: [u8; 32],
}

/// The `prev_rcm` an `action` must extend given the name's current tip.
pub fn prev_rcm_for(tip: Option<&Tip>, action: Action) -> Option<[u8; 32]> {
    match (action, tip) {
        (Action::Claim, None) => Some(ZERO_PREV_RCM),
        (Action::Claim, Some(t)) if t.action == Action::Release => Some(ZERO_PREV_RCM),
        (Action::Update | Action::Release, Some(t)) if t.action != Action::Release => Some(t.rcm),
        _ => None,
    }
}

/// A committed Name Note (WP §3.1): the form that appears on chain.
///
/// A release has no expiry field, and a claim has no predecessor field: the
/// type makes those constraints structural rather than checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameNote<'a> {
    /// Bind `name` to `ua` for `expires_at`; no predecessor exists.
    Claim {
        /// The name being claimed.
        name: Name<'a>,
        /// The UA being bound.
        ua: Ua<'a>,
        /// The committed expiration.
        expires_at: Expiry<'a>,
    },
    /// Rebind `name` to `ua`, chaining off the predecessor.
    Update {
        /// The name being updated.
        name: Name<'a>,
        /// The new UA.
        ua: Ua<'a>,
        /// The carried-forward or extended expiration.
        expires_at: Expiry<'a>,
        /// The disclosed predecessor witness.
        prev_rcm: PrevRcm,
    },
    /// Terminate the registration, retaining the released UA.
    Release {
        /// The name being released.
        name: Name<'a>,
        /// The UA being released.
        ua: Ua<'a>,
        /// The disclosed predecessor witness.
        prev_rcm: PrevRcm,
    },
}

impl<'a> NameNote<'a> {
    /// Parses a Name Note from its zero-padded 512-byte memo (WP §3.1).
    ///
    /// The returned note borrows from `memo`. This is the only way to
    /// construct a `NameNote` from untrusted bytes.
    pub fn parse(memo: &'a Memo) -> Result<Self, MemoError> {
        let text = memo.text().ok_or(MemoError::NotZns)?;
        let mut fields = text.split(':');
        if fields.next() != Some("ZNS") {
            return Err(MemoError::NotZns);
        }
        let verb = fields.next().ok_or(MemoError::FieldCount)?;
        let name = Name::parse(fields.next().ok_or(MemoError::FieldCount)?)?;
        let ua = Ua::parse(fields.next().ok_or(MemoError::FieldCount)?)?;
        let expires_field = fields.next().ok_or(MemoError::FieldCount)?;
        let prev_hex = fields.next().ok_or(MemoError::FieldCount)?;
        if fields.next().is_some() {
            return Err(MemoError::FieldCount);
        }
        let prev = PrevRcm::from_hex(prev_hex)?;

        match verb {
            "claim" => {
                if !prev.is_zero() {
                    return Err(MemoError::InvalidPrevRcm);
                }
                Ok(NameNote::Claim {
                    name,
                    ua,
                    expires_at: Expiry::from_field(expires_field)?,
                })
            }
            "update" | "release" if prev.is_zero() => Err(MemoError::InvalidPrevRcm),
            "update" => Ok(NameNote::Update {
                name,
                ua,
                expires_at: Expiry::from_field(expires_field)?,
                prev_rcm: prev,
            }),
            "release" => {
                if expires_field != "none" {
                    return Err(MemoError::InvalidExpiry);
                }
                Ok(NameNote::Release {
                    name,
                    ua,
                    prev_rcm: prev,
                })
            }
            _ => Err(MemoError::UnknownVerb),
        }
    }

    /// Encodes the canonical zero-padded memo.
    ///
    /// Returns [`MemoError::TooLong`] if the UA cannot fit, which valid
    /// protocol transitions never trigger (WP §4, on-chain completeness).
    pub fn encode(&self) -> Result<Memo, MemoError> {
        let verb = self.action().as_bytes();
        let (name, ua, expires_bytes, prev_hex) = match self {
            NameNote::Claim {
                name,
                ua,
                expires_at,
            } => {
                const ZERO_HEX: [u8; 64] = [b'0'; 64];
                (
                    name.as_str().as_bytes(),
                    ua.as_str().as_bytes(),
                    expires_at.field_bytes().as_bytes(),
                    ZERO_HEX,
                )
            }
            NameNote::Update {
                name,
                ua,
                expires_at,
                prev_rcm,
            } => (
                name.as_str().as_bytes(),
                ua.as_str().as_bytes(),
                expires_at.field_bytes().as_bytes(),
                prev_rcm.to_hex(),
            ),
            NameNote::Release { name, ua, prev_rcm } => (
                name.as_str().as_bytes(),
                ua.as_str().as_bytes(),
                b"none".as_slice(),
                prev_rcm.to_hex(),
            ),
        };
        let mut memo = [0u8; MEMO_SIZE];
        memo[..3].copy_from_slice(b"ZNS");
        let mut at = 3;
        for field in [verb, name, ua, expires_bytes, &prev_hex] {
            if at + 1 + field.len() > MEMO_SIZE {
                return Err(MemoError::TooLong);
            }
            memo[at] = b':';
            at += 1;
            memo[at..at + field.len()].copy_from_slice(field);
            at += field.len();
        }
        Ok(Memo(memo))
    }

    /// The transition kind.
    pub fn action(&self) -> Action {
        match self {
            NameNote::Claim { .. } => Action::Claim,
            NameNote::Update { .. } => Action::Update,
            NameNote::Release { .. } => Action::Release,
        }
    }

    /// The validated name.
    pub const fn name(&self) -> &Name<'a> {
        match self {
            NameNote::Claim { name, .. }
            | NameNote::Update { name, .. }
            | NameNote::Release { name, .. } => name,
        }
    }

    /// The validated UA; a release retains the released UA.
    pub fn ua(&self) -> &Ua<'a> {
        match self {
            NameNote::Claim { ua, .. }
            | NameNote::Update { ua, .. }
            | NameNote::Release { ua, .. } => ua,
        }
    }

    /// The committed expiration; absent on a release.
    pub fn expires_at(&self) -> Option<Expiry<'a>> {
        match self {
            NameNote::Claim { expires_at, .. } | NameNote::Update { expires_at, .. } => {
                Some(*expires_at)
            }
            NameNote::Release { .. } => None,
        }
    }

    /// The disclosed predecessor witness; absent on a claim.
    pub fn prev_rcm(&self) -> Option<PrevRcm> {
        match self {
            NameNote::Claim { .. } => None,
            NameNote::Update { prev_rcm, .. } | NameNote::Release { prev_rcm, .. } => {
                Some(*prev_rcm)
            }
        }
    }
}

/// Why a memo failed to parse or encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// Not a ZNS memo (no `ZNS:` prefix, non-UTF-8, or non-canonical padding).
    NotZns,
    /// An unknown verb.
    UnknownVerb,
    /// Wrong number of `:`-separated fields.
    FieldCount,
    /// The name violates the ZNS name rule.
    InvalidName,
    /// The `ua` field is empty.
    EmptyUa,
    /// The `expires_at` field is non-canonical, or present on a release.
    InvalidExpiry,
    /// `prev_rcm` is not 64 lowercase hex chars, or inconsistent with the action.
    InvalidPrevRcm,
    /// The encoded memo would exceed [`MEMO_SIZE`].
    TooLong,
}
