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
    pub const ZERO: Self = PrevRcm(ZERO_PREV_RCM);

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
        let (pairs, _) = bytes.as_chunks::<2>();
        for (i, pair) in pairs.iter().enumerate() {
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
    /// Hand the name to a buyer. The name stays live.
    Sale,
    /// Put the name up for sale at one price. The owner and expiry carry forward.
    List,
    /// Put the name up for sale on a falling price. The owner and expiry carry forward.
    Auction,
    /// Take the name off the market. The owner and expiry carry forward.
    Delist,
}

impl Action {
    /// The canonical ASCII spelling used in memos, hash inputs, and any
    /// downstream rendering or storage of an action. Single source of the
    /// spelling: `as_bytes` derives from it, so the two cannot drift.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
            Action::Sale => "sale",
            Action::List => "list",
            Action::Auction => "auction",
            Action::Delist => "delist",
        }
    }

    /// The canonical ASCII bytes used in hash inputs.
    pub const fn as_bytes(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// Parses the canonical ASCII form, case-sensitive.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"claim" => Some(Action::Claim),
            b"update" => Some(Action::Update),
            b"release" => Some(Action::Release),
            b"sale" => Some(Action::Sale),
            b"list" => Some(Action::List),
            b"auction" => Some(Action::Auction),
            b"delist" => Some(Action::Delist),
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
    /// The value the next action must extend: the tip's `rcm` for an rcm/ψ
    /// Name Note, its `cmx` for a bound Name Note.
    pub rcm: [u8; 32],
}

/// The `prev_rcm` an `action` must extend given the name's current tip.
///
/// Chain shape only. For an update or a release,
/// [`crate::authorized_transition`] also requires the transaction to reveal
/// that tip's nullifier. A claim spends a live claim anchor instead, never the
/// tip.
pub fn prev_rcm_for(tip: Option<&Tip>, action: Action) -> Option<[u8; 32]> {
    match (action, tip) {
        (Action::Claim, None) => Some(ZERO_PREV_RCM),
        (Action::Claim, Some(t)) if t.action == Action::Release => Some(ZERO_PREV_RCM),
        (
            Action::Update
            | Action::Release
            | Action::Sale
            | Action::List
            | Action::Auction
            | Action::Delist,
            Some(t),
        ) if t.action != Action::Release => Some(t.rcm),
        _ => None,
    }
}

/// A committed Name Note (WP §3.1): the form that appears on chain.
///
/// A release has no expiry. A claim has no predecessor. A list or an auction
/// carries its terms between the expiry and the predecessor. A sale, list,
/// auction, or delist spends a predecessor and leaves the name live.
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
    /// Hand `name` to `ua`. The name stays live.
    Sale {
        /// The name being sold.
        name: Name<'a>,
        /// The buyer's UA.
        ua: Ua<'a>,
        /// The carried-forward expiration.
        expires_at: Expiry<'a>,
        /// The disclosed predecessor witness.
        prev_rcm: PrevRcm,
    },
    /// Offer `name` at one price. The owner and expiry carry forward.
    List {
        /// The name being listed.
        name: Name<'a>,
        /// The owner's UA.
        ua: Ua<'a>,
        /// The carried-forward expiration.
        expires_at: Expiry<'a>,
        /// The transparent payment address, as written.
        pay_to: &'a str,
        /// The price in ZEC, as written.
        price: &'a str,
        /// The disclosed predecessor witness.
        prev_rcm: PrevRcm,
    },
    /// Offer `name` on a falling price. The owner and expiry carry forward.
    Auction {
        /// The name being auctioned.
        name: Name<'a>,
        /// The owner's UA.
        ua: Ua<'a>,
        /// The carried-forward expiration.
        expires_at: Expiry<'a>,
        /// The transparent payment address, as written.
        pay_to: &'a str,
        /// The opening price in ZEC, as written.
        start_price: &'a str,
        /// The floor price in ZEC, as written.
        min_price: &'a str,
        /// The opening block height, as written.
        start: &'a str,
        /// The closing block height, as written.
        end: &'a str,
        /// The disclosed predecessor witness.
        prev_rcm: PrevRcm,
    },
    /// Take `name` off the market. The owner and expiry carry forward.
    Delist {
        /// The name being delisted.
        name: Name<'a>,
        /// The owner's UA.
        ua: Ua<'a>,
        /// The carried-forward expiration.
        expires_at: Expiry<'a>,
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
        let action = Action::from_bytes(verb.as_bytes());

        match action {
            Some(Action::List) => {
                let pay_to = fields.next().ok_or(MemoError::FieldCount)?;
                let price = fields.next().ok_or(MemoError::FieldCount)?;
                let prev = predecessor(&mut fields)?;
                if !valid_list(pay_to, price) {
                    return Err(MemoError::InvalidTerms);
                }
                Ok(NameNote::List {
                    name,
                    ua,
                    expires_at: Expiry::from_field(expires_field)?,
                    pay_to,
                    price,
                    prev_rcm: prev,
                })
            }
            Some(Action::Auction) => {
                let pay_to = fields.next().ok_or(MemoError::FieldCount)?;
                let start_price = fields.next().ok_or(MemoError::FieldCount)?;
                let min_price = fields.next().ok_or(MemoError::FieldCount)?;
                let start = fields.next().ok_or(MemoError::FieldCount)?;
                let end = fields.next().ok_or(MemoError::FieldCount)?;
                let prev = predecessor(&mut fields)?;
                if !valid_auction(pay_to, start_price, min_price, start, end) {
                    return Err(MemoError::InvalidTerms);
                }
                Ok(NameNote::Auction {
                    name,
                    ua,
                    expires_at: Expiry::from_field(expires_field)?,
                    pay_to,
                    start_price,
                    min_price,
                    start,
                    end,
                    prev_rcm: prev,
                })
            }
            Some(Action::Claim) => {
                let prev_hex = fields.next().ok_or(MemoError::FieldCount)?;
                if fields.next().is_some() {
                    return Err(MemoError::FieldCount);
                }
                let prev = PrevRcm::from_hex(prev_hex)?;
                if !prev.is_zero() {
                    return Err(MemoError::InvalidPrevRcm);
                }
                Ok(NameNote::Claim {
                    name,
                    ua,
                    expires_at: Expiry::from_field(expires_field)?,
                })
            }
            Some(Action::Update) => Ok(NameNote::Update {
                name,
                ua,
                expires_at: Expiry::from_field(expires_field)?,
                prev_rcm: predecessor(&mut fields)?,
            }),
            Some(Action::Sale) => Ok(NameNote::Sale {
                name,
                ua,
                expires_at: Expiry::from_field(expires_field)?,
                prev_rcm: predecessor(&mut fields)?,
            }),
            Some(Action::Delist) => Ok(NameNote::Delist {
                name,
                ua,
                expires_at: Expiry::from_field(expires_field)?,
                prev_rcm: predecessor(&mut fields)?,
            }),
            Some(Action::Release) => {
                let prev = predecessor(&mut fields)?;
                if expires_field != "none" {
                    return Err(MemoError::InvalidExpiry);
                }
                Ok(NameNote::Release {
                    name,
                    ua,
                    prev_rcm: prev,
                })
            }
            None => {
                // A short memo is a field-count error even when the verb is unknown.
                let _prev = fields.next().ok_or(MemoError::FieldCount)?;
                if fields.next().is_some() {
                    return Err(MemoError::FieldCount);
                }
                Err(MemoError::UnknownVerb)
            }
        }
    }

    /// Encodes the canonical zero-padded memo.
    ///
    /// Returns [`MemoError::TooLong`] if the UA cannot fit, which valid
    /// protocol transitions never trigger (WP §4, on-chain completeness).
    /// Returns the parse error when the fields are not a Name Note.
    pub fn encode(&self) -> Result<Memo, MemoError> {
        let verb = self.action().as_bytes();
        let name = self.name().as_str().as_bytes();
        let ua = self.ua().as_str().as_bytes();
        let expires = self
            .expires_at()
            .unwrap_or(Expiry::NEVER)
            .field_bytes()
            .as_bytes();
        let prev_hex = self.prev_rcm().unwrap_or(PrevRcm::ZERO).to_hex();
        let terms = self.terms();
        let mut memo = [0u8; MEMO_SIZE];
        memo[..3].copy_from_slice(b"ZNS");
        let mut at = 3;
        for field in [verb, name, ua, expires] {
            write_field(&mut memo, &mut at, field)?;
        }
        for field in &terms[..self.term_count()] {
            write_field(&mut memo, &mut at, field)?;
        }
        write_field(&mut memo, &mut at, &prev_hex)?;
        let memo = Memo(memo);
        // The written bytes have to be a note parse accepts.
        NameNote::parse(&memo)?;
        Ok(memo)
    }

    /// The transition kind.
    pub fn action(&self) -> Action {
        match self {
            NameNote::Claim { .. } => Action::Claim,
            NameNote::Update { .. } => Action::Update,
            NameNote::Release { .. } => Action::Release,
            NameNote::Sale { .. } => Action::Sale,
            NameNote::List { .. } => Action::List,
            NameNote::Auction { .. } => Action::Auction,
            NameNote::Delist { .. } => Action::Delist,
        }
    }

    /// Listing fields between the expiry and the predecessor.
    ///
    /// [`Self::term_count`] is how many leading entries are live: two for a
    /// list, five for an auction, none otherwise.
    pub fn terms(&self) -> [&'a [u8]; 5] {
        match self {
            NameNote::List { pay_to, price, .. } => {
                [pay_to.as_bytes(), price.as_bytes(), b"", b"", b""]
            }
            NameNote::Auction {
                pay_to,
                start_price,
                min_price,
                start,
                end,
                ..
            } => [
                pay_to.as_bytes(),
                start_price.as_bytes(),
                min_price.as_bytes(),
                start.as_bytes(),
                end.as_bytes(),
            ],
            NameNote::Claim { .. }
            | NameNote::Update { .. }
            | NameNote::Release { .. }
            | NameNote::Sale { .. }
            | NameNote::Delist { .. } => [b""; 5],
        }
    }

    /// How many [`Self::terms`] entries belong to the record.
    pub fn term_count(&self) -> usize {
        match self {
            NameNote::List { .. } => 2,
            NameNote::Auction { .. } => 5,
            NameNote::Claim { .. }
            | NameNote::Update { .. }
            | NameNote::Release { .. }
            | NameNote::Sale { .. }
            | NameNote::Delist { .. } => 0,
        }
    }

    /// The validated name.
    pub const fn name(&self) -> &Name<'a> {
        match self {
            NameNote::Claim { name, .. }
            | NameNote::Update { name, .. }
            | NameNote::Release { name, .. }
            | NameNote::Sale { name, .. }
            | NameNote::List { name, .. }
            | NameNote::Auction { name, .. }
            | NameNote::Delist { name, .. } => name,
        }
    }

    /// The validated UA; a release retains the released UA.
    pub fn ua(&self) -> &Ua<'a> {
        match self {
            NameNote::Claim { ua, .. }
            | NameNote::Update { ua, .. }
            | NameNote::Release { ua, .. }
            | NameNote::Sale { ua, .. }
            | NameNote::List { ua, .. }
            | NameNote::Auction { ua, .. }
            | NameNote::Delist { ua, .. } => ua,
        }
    }

    /// The committed expiration; absent on a release.
    pub fn expires_at(&self) -> Option<Expiry<'a>> {
        match self {
            NameNote::Claim { expires_at, .. }
            | NameNote::Update { expires_at, .. }
            | NameNote::Sale { expires_at, .. }
            | NameNote::List { expires_at, .. }
            | NameNote::Auction { expires_at, .. }
            | NameNote::Delist { expires_at, .. } => Some(*expires_at),
            NameNote::Release { .. } => None,
        }
    }

    /// The disclosed predecessor witness; absent on a claim.
    pub fn prev_rcm(&self) -> Option<PrevRcm> {
        match self {
            NameNote::Claim { .. } => None,
            NameNote::Update { prev_rcm, .. }
            | NameNote::Release { prev_rcm, .. }
            | NameNote::Sale { prev_rcm, .. }
            | NameNote::List { prev_rcm, .. }
            | NameNote::Auction { prev_rcm, .. }
            | NameNote::Delist { prev_rcm, .. } => Some(*prev_rcm),
        }
    }
}

/// The next field is a nonzero predecessor, and nothing follows it.
fn predecessor<'a>(fields: &mut impl Iterator<Item = &'a str>) -> Result<PrevRcm, MemoError> {
    let prev_hex = fields.next().ok_or(MemoError::FieldCount)?;
    if fields.next().is_some() {
        return Err(MemoError::FieldCount);
    }
    let prev = PrevRcm::from_hex(prev_hex)?;
    if prev.is_zero() {
        return Err(MemoError::InvalidPrevRcm);
    }
    Ok(prev)
}

fn write_field(memo: &mut [u8; MEMO_SIZE], at: &mut usize, field: &[u8]) -> Result<(), MemoError> {
    if *at + 1 + field.len() > MEMO_SIZE {
        return Err(MemoError::TooLong);
    }
    memo[*at] = b':';
    *at += 1;
    memo[*at..*at + field.len()].copy_from_slice(field);
    *at += field.len();
    Ok(())
}

/// A list's payment address is non-empty and its price is ZEC text.
fn valid_list(pay_to: &str, price: &str) -> bool {
    valid_pay_to(pay_to) && zec_zatoshis(price).is_some()
}

/// An auction pays a non-empty address, opens above its floor, and ends
/// on a later block.
fn valid_auction(pay_to: &str, start_price: &str, min_price: &str, start: &str, end: &str) -> bool {
    let (Some(start_price), Some(min_price), Some(start), Some(end)) = (
        zec_zatoshis(start_price),
        zec_zatoshis(min_price),
        block_height(start),
        block_height(end),
    ) else {
        return false;
    };
    valid_pay_to(pay_to) && end > start && start_price > min_price
}

/// The payment address is non-empty text. The mint checks the transparent
/// encoding when it writes the note.
fn valid_pay_to(text: &str) -> bool {
    !text.is_empty()
}

/// ZEC with at most eight decimal places, in zatoshis. A dot requires
/// at least one decimal digit.
fn zec_zatoshis(text: &str) -> Option<u64> {
    let (whole, frac) = match text.split_once('.') {
        Some((whole, frac)) if !frac.is_empty() => (whole, frac),
        Some(_) => return None,
        None => (text, ""),
    };
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 8
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    whole
        .checked_mul(100_000_000)?
        .checked_add(frac_zats(frac)?)
}

fn frac_zats(frac: &str) -> Option<u64> {
    if frac.is_empty() {
        return Some(0);
    }
    let mut n = 0u64;
    for b in frac.bytes() {
        n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    let mut scale = 1u64;
    for _ in frac.len()..8 {
        scale = scale.checked_mul(10)?;
    }
    n.checked_mul(scale)
}

/// A block height as a decimal `u32`. A leading zero is refused.
fn block_height(text: &str) -> Option<u32> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
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
    /// A list or auction term is empty, non-canonical, or out of order.
    InvalidTerms,
    /// The encoded memo would exceed [`MEMO_SIZE`].
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";
    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn name_validation() {
        assert!(Name::parse("alice").is_ok());
        assert!(Name::parse("a1").is_ok());
        assert!(Name::parse("123").is_ok());
        assert!(Name::parse(&"a".repeat(63)).is_ok());
        assert!(Name::parse("").is_err());
        assert!(Name::parse(&"a".repeat(64)).is_err());
        assert!(Name::parse("Alice").is_err());
        assert!(Name::parse("a-1").is_err());
        assert!(Name::parse("al ice").is_err());
        assert!(Name::parse("a.b").is_err());
    }

    #[test]
    fn expiry_validation() {
        assert_eq!(Expiry::from_field("none"), Ok(Expiry::NEVER));
        assert!(Expiry::from_field("0").is_ok());
        assert!(Expiry::from_field("1775000000").is_ok());
        assert!(Expiry::from_field("01").is_err());
        assert!(Expiry::from_field("+1").is_err());
        assert!(Expiry::from_field("1.0").is_err());
        assert!(Expiry::from_field("").is_err());
        assert!(Expiry::from_field("None").is_err());
        assert_eq!(Expiry::from_field("none").unwrap().field_bytes(), "none");
    }

    #[test]
    fn prev_rcm_hex_codec() {
        let prev = PrevRcm::from_hex(HEX).unwrap();
        assert_eq!(prev.to_hex(), HEX.as_bytes());
        assert!(PrevRcm::from_hex(&HEX.to_uppercase()).is_err());
        assert!(PrevRcm::from_hex("abcd").is_err());
        assert!(PrevRcm::ZERO.is_zero());
        assert!(!prev.is_zero());
    }

    #[test]
    fn ua_validation() {
        assert!(Ua::parse("u1xxx").is_ok());
        assert!(Ua::parse(UA).is_ok());
        assert!(Ua::parse("").is_err());
    }

    #[test]
    fn action_spelling_is_canonical() {
        assert_eq!(Action::Claim.as_str(), "claim");
        assert_eq!(Action::Update.as_str(), "update");
        assert_eq!(Action::Release.as_str(), "release");
        assert_eq!(Action::Sale.as_str(), "sale");
        assert_eq!(Action::List.as_str(), "list");
        assert_eq!(Action::Auction.as_str(), "auction");
        assert_eq!(Action::Delist.as_str(), "delist");
        // as_bytes must stay the byte view of as_str: the spelling is
        // load-bearing, it is hashed into name_note_rseed.
        for action in [
            Action::Claim,
            Action::Update,
            Action::Release,
            Action::Sale,
            Action::List,
            Action::Auction,
            Action::Delist,
        ] {
            assert_eq!(action.as_str().as_bytes(), action.as_bytes());
            assert_eq!(Action::from_bytes(action.as_bytes()), Some(action));
        }
    }

    #[test]
    fn action_round_trip() {
        for action in [
            Action::Claim,
            Action::Update,
            Action::Release,
            Action::Sale,
            Action::List,
            Action::Auction,
            Action::Delist,
        ] {
            assert_eq!(Action::from_bytes(action.as_bytes()), Some(action));
        }
        assert_eq!(Action::from_bytes(b"Claim"), None);
        assert_eq!(Action::from_bytes(b"CLAIM"), None);
        assert_eq!(Action::from_bytes(b""), None);
        assert_eq!(Action::from_bytes(b"transfer"), None);
    }

    #[test]
    fn wp_golden_memo_parses_and_round_trips() {
        let golden = format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX);
        let m = Memo::from_bytes(golden.as_bytes()).unwrap();
        let note = NameNote::parse(&m).unwrap();
        match note {
            NameNote::Claim {
                name,
                ua,
                expires_at,
            } => {
                assert_eq!(name.as_str(), "alice");
                assert!(ua.as_str().starts_with("u1897"));
                assert_eq!(expires_at, Expiry::NEVER);
            }
            _ => panic!("expected claim"),
        }
        assert_eq!(note.encode().unwrap().as_array(), m.as_array());
    }

    #[test]
    fn parse_encode_round_trip() {
        let texts = [
            format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX),
            format!("ZNS:claim:alice:{}:0:{}", UA, ZERO_HEX),
            format!("ZNS:update:alice:{}:1775000000:{}", UA, HEX),
            format!("ZNS:release:alice:{}:none:{}", UA, HEX),
            format!("ZNS:sale:alice:{}:none:{}", UA, HEX),
            format!("ZNS:delist:alice:{}:1775000000:{}", UA, HEX),
            format!("ZNS:list:alice:{UA}:none:t1abc:5:{HEX}"),
            format!("ZNS:list:alice:{UA}:none:t1abc:1.5:{HEX}"),
            format!("ZNS:auction:alice:{UA}:none:t1abc:9:1:3000000:3001000:{HEX}"),
        ];
        for text in &texts {
            let m = Memo::from_bytes(text.as_bytes()).unwrap();
            let note = NameNote::parse(&m).unwrap();
            let encoded = note.encode().unwrap();
            assert_eq!(encoded.as_array()[..text.len()], *text.as_bytes());
            assert!(encoded.as_array()[text.len()..].iter().all(|&b| b == 0));
        }
    }

    fn memo(text: &str) -> Memo {
        Memo::from_bytes(text.as_bytes()).unwrap()
    }

    #[test]
    fn memo_padding_must_be_canonical() {
        let good = format!("ZNS:claim:alice:{}:none:{}", UA, ZERO_HEX);
        let good_memo = memo(&good);
        assert!(NameNote::parse(&good_memo).is_ok());

        let mut bytes = *good_memo.as_array();
        bytes[300] = b'x';
        assert!(NameNote::parse(&Memo::from_array(bytes)).is_err());
    }

    #[test]
    fn rejects_non_zns_memos() {
        let m = memo(&format!("just a payment note:{}", HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::NotZns));
        let m = memo(&format!("ZEC:claim:alice:{}:none:{}", UA, HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::NotZns));
        assert_eq!(
            NameNote::parse(&Memo::from_array([0u8; MEMO_SIZE])),
            Err(MemoError::NotZns)
        );

        let mut b = [0u8; MEMO_SIZE];
        b[0] = 0xff;
        b[1] = 0xfe;
        assert_eq!(
            NameNote::parse(&Memo::from_array(b)),
            Err(MemoError::NotZns)
        );
    }

    #[test]
    fn rejects_invalid_grammar() {
        let m = memo(&format!("ZNS:settle:alice:{}:none:{}", UA, HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::UnknownVerb));
        let m = memo("ZNS:claim:alice");
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:claim:alice:{}", UA));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:claim:alice:{}:none", UA));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:claim:alice:{}:none:{}:extra", UA, ZERO_HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:claim:alice::none:{}", HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::EmptyUa));
        let m = memo(&format!("ZNS:claim:alice:{}:none:{}", UA, HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));
        let zeros = "0".repeat(64);
        let m = memo(&format!("ZNS:update:alice:{}:none:{}", UA, zeros));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));
        let m = memo(&format!("ZNS:release:alice:{}:1000:{}", UA, HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidExpiry));
        let m = memo(&format!("ZNS:claim:Alice:{}:none:{}", UA, ZERO_HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidName));
        let m = memo(&format!("ZNS:claim:alice:{}:01:{}", UA, ZERO_HEX));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidExpiry));
        let m = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:5:5:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:9:1:3000000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:delist:alice:{UA}:none:t1abc:5:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!("ZNS:update:alice:{UA}:none:t1abc:5:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:1:9:3000000:3001000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:9:9:3000000:3001000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:9:1:3001000:3000000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!("ZNS:list:alice:{UA}:none::5:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:01:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:5.:{HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:9.:1:3000000:3001000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!(
            "ZNS:auction:alice:{UA}:none:t1abc:9:1:01:3001000:{HEX}"
        ));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidTerms));
        let m = memo(&format!("ZNS:sale:alice:{UA}:none:{ZERO_HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));
        let m = memo(&format!("ZNS:delist:alice:{UA}:none:{ZERO_HEX}"));
        assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));
    }

    #[test]
    fn listing_terms_change_the_rseed() {
        let cheap_memo = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:5:{HEX}"));
        let dear_memo = memo(&format!("ZNS:list:alice:{UA}:none:t1abc:6:{HEX}"));
        let cheap = NameNote::parse(&cheap_memo).unwrap();
        let dear = NameNote::parse(&dear_memo).unwrap();
        assert_ne!(rseed_of(&cheap), rseed_of(&dear));
        assert_eq!(cheap.term_count(), 2);
        assert_eq!(dear.terms()[1], b"6");
    }

    #[test]
    fn encode_refuses_terms_parse_rejects() {
        let name = Name::parse("alice").unwrap();
        let ua = Ua::parse(UA).unwrap();
        let prev_rcm = PrevRcm::from_hex(HEX).unwrap();
        let list = NameNote::List {
            name,
            ua,
            expires_at: Expiry::NEVER,
            pay_to: "t1abc",
            price: "-1",
            prev_rcm,
        };
        assert_eq!(list.encode(), Err(MemoError::InvalidTerms));
        let auction = NameNote::Auction {
            name,
            ua,
            expires_at: Expiry::NEVER,
            pay_to: "t1abc",
            start_price: "1",
            min_price: "9",
            start: "3000000",
            end: "3001000",
            prev_rcm,
        };
        assert_eq!(auction.encode(), Err(MemoError::InvalidTerms));
    }

    fn rseed_of(note: &NameNote<'_>) -> [u8; 32] {
        let terms = note.terms();
        crate::name_note_rseed(
            note.action().as_bytes(),
            note.name().as_str().as_bytes(),
            note.ua().as_str().as_bytes(),
            note.expires_at()
                .unwrap_or(Expiry::NEVER)
                .field_bytes()
                .as_bytes(),
            &terms[..note.term_count()],
            note.prev_rcm().unwrap_or(PrevRcm::ZERO).as_bytes(),
        )
    }

    #[test]
    fn chain_transitions() {
        assert_eq!(prev_rcm_for(None, Action::Claim), Some(ZERO_PREV_RCM));
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Release,
                    rcm: [9; 32]
                }),
                Action::Claim
            ),
            Some(ZERO_PREV_RCM)
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Claim,
                    rcm: [1; 32]
                }),
                Action::Claim
            ),
            None
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Claim,
                    rcm: [7; 32]
                }),
                Action::Update
            ),
            Some([7; 32])
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Claim,
                    rcm: [7; 32]
                }),
                Action::Release
            ),
            Some([7; 32])
        );
        assert_eq!(prev_rcm_for(None, Action::Update), None);
        assert_eq!(prev_rcm_for(None, Action::Release), None);
        assert_eq!(prev_rcm_for(None, Action::List), None);
        assert_eq!(prev_rcm_for(None, Action::Sale), None);
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Update,
                    rcm: [0xab; 32]
                }),
                Action::List
            ),
            Some([0xab; 32])
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::List,
                    rcm: [0xcd; 32]
                }),
                Action::Sale
            ),
            Some([0xcd; 32])
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Release,
                    rcm: [0xcd; 32]
                }),
                Action::Delist
            ),
            None
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Release,
                    rcm: [7; 32]
                }),
                Action::Update
            ),
            None
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Release,
                    rcm: [7; 32]
                }),
                Action::Release
            ),
            None
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Update,
                    rcm: [0xab; 32]
                }),
                Action::Update
            ),
            Some([0xab; 32])
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Update,
                    rcm: [0xab; 32]
                }),
                Action::Release
            ),
            Some([0xab; 32])
        );
        assert_eq!(
            prev_rcm_for(
                Some(&Tip {
                    action: Action::Update,
                    rcm: [0xab; 32]
                }),
                Action::Claim
            ),
            None
        );
    }
}
