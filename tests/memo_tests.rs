//! Tests for the Name Note memo grammar (parse_name_note, encode_name_note, validate_name).

use zns_verify::{
    memo::{encode_name_note, validate_name, MemoError},
    parse_name_note, Action, NameNote, MEMO_SIZE,
};

fn padded(s: &str) -> [u8; MEMO_SIZE] {
    let mut m = [0u8; MEMO_SIZE];
    m[..s.len()].copy_from_slice(s.as_bytes());
    m
}

fn name_note<'a>(
    action: Action,
    name: &'a str,
    ua: &'a str,
    expires_at: &'a str,
    prev_rcm: [u8; 32],
) -> NameNote<'a> {
    NameNote {
        action,
        name,
        ua,
        expires_at,
        prev_rcm,
    }
}

const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[test]
fn parses_name_note_forms() {
    let mut want = [0u8; 32];
    hex::decode_to_slice(HEX, &mut want).unwrap();

    // Claim: 6 fields with expires_at (WP §3.1)
    let m = format!("ZNS:claim:alice:u1xxx:none:{HEX}");
    assert_eq!(
        parse_name_note(m.as_bytes()),
        Ok(name_note(Action::Claim, "alice", "u1xxx", "none", want)),
    );
    // Update with a fixed expiration
    let m = format!("ZNS:update:alice:u1new:1775000000:{HEX}");
    assert_eq!(
        parse_name_note(m.as_bytes()),
        Ok(name_note(
            Action::Update,
            "alice",
            "u1new",
            "1775000000",
            want
        )),
    );
    // Release: retains UA, expires_at = none (WP §3.1)
    let m = format!("ZNS:release:alice:u1old:none:{HEX}");
    assert_eq!(
        parse_name_note(m.as_bytes()),
        Ok(name_note(Action::Release, "alice", "u1old", "none", want))
    );

    // The witness must be exactly 64 lowercase hex chars.
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1xxx:none:abcd"),
        Err(MemoError::InvalidPrevRcm)
    );
    let upper = format!("ZNS:claim:alice:u1xxx:none:{}", HEX.to_uppercase());
    assert_eq!(
        parse_name_note(upper.as_bytes()),
        Err(MemoError::InvalidPrevRcm)
    );
    // A request-form memo (no expires_at/prev_rcm) is not a Name Note.
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1xxx"),
        Err(MemoError::FieldCount)
    );
    // A Name Note without expires_at (5 fields) is rejected.
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1xxx:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        Err(MemoError::FieldCount)
    );
}

#[test]
fn release_must_have_none_expiry() {
    // Release with a non-none expires_at is rejected (WP §3.1)
    let m = format!("ZNS:release:alice:u1old:1000:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::FieldCount));
}

#[test]
fn zero_padding_is_stripped() {
    let m = padded(&format!("ZNS:claim:alice:u1xxx:none:{HEX}"));
    let parsed = parse_name_note(&m).unwrap();
    assert_eq!(parsed.name, "alice");
    assert_eq!(parsed.ua, "u1xxx");
    assert_eq!(parsed.expires_at, "none");
}

#[test]
fn non_zns_memos_are_not_zns() {
    let m = format!("just a payment note:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::NotZns));
    let m = format!("ZEC:claim:alice:u1:none:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::NotZns));
    assert_eq!(parse_name_note(&[0u8; MEMO_SIZE]), Err(MemoError::NotZns));
    assert_eq!(parse_name_note(&[0xff, 0xfe]), Err(MemoError::NotZns));
}

#[test]
fn strict_field_counts() {
    // A sixth field that is not valid prev_rcm hex must reject.
    assert_eq!(
        parse_name_note(b"ZNS:update:alice:u1x:none:extra"),
        Err(MemoError::InvalidPrevRcm)
    );
    // Missing fields reject; they are never absorbed into the ua.
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1x"),
        Err(MemoError::FieldCount)
    );
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1x:none"),
        Err(MemoError::FieldCount)
    );
    // An empty ua rejects.
    let m = format!("ZNS:claim:alice::none:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::EmptyArg));
    // Unknown verbs reject.
    let m = format!("ZNS:settle:alice:u1x:none:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::UnknownVerb));
}

#[test]
fn enforces_zns_name_rules() {
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
    let m = format!("ZNS:claim:Alice:u1x:none:{HEX}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::InvalidName));
}

#[test]
fn encode_round_trips() {
    let prev = [0xa5u8; 32];
    let m = encode_name_note(Action::Update, "alice", "u1new", "none", &prev).unwrap();
    assert_eq!(
        parse_name_note(&m),
        Ok(name_note(Action::Update, "alice", "u1new", "none", prev))
    );
    let m = encode_name_note(Action::Release, "alice", "u1old", "none", &prev).unwrap();
    assert_eq!(
        parse_name_note(&m),
        Ok(name_note(Action::Release, "alice", "u1old", "none", prev))
    );
    let m = encode_name_note(Action::Claim, "alice", "u1new", "1775000000", &[0u8; 32]).unwrap();
    assert_eq!(
        parse_name_note(&m),
        Ok(name_note(
            Action::Claim,
            "alice",
            "u1new",
            "1775000000",
            [0u8; 32]
        ))
    );
}

#[test]
fn encode_rejects_what_parse_rejects() {
    // An empty ua rejects.
    assert_eq!(
        encode_name_note(Action::Claim, "alice", "", "none", &[0u8; 32]),
        Err(MemoError::EmptyArg)
    );
    // Release must use "none" for expires_at
    assert_eq!(
        encode_name_note(Action::Release, "alice", "u1x", "1000", &[0u8; 32]),
        Err(MemoError::FieldCount)
    );
    // Release must have a UA
    assert_eq!(
        encode_name_note(Action::Release, "alice", "", "none", &[0u8; 32]),
        Err(MemoError::EmptyArg)
    );
    // An invalid name rejects.
    assert_eq!(
        encode_name_note(Action::Claim, "Alice", "u1x", "none", &[0u8; 32]),
        Err(MemoError::InvalidName)
    );
    // A ua that cannot fit the ZIP-302 memo.
    let huge = "u".repeat(MEMO_SIZE);
    assert_eq!(
        encode_name_note(Action::Claim, "alice", &huge, "none", &[0u8; 32]),
        Err(MemoError::TooLong)
    );
}
