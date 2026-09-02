//! Tests for the memo grammar (parse_*_memo, parse_name_note, encode_*, validate_name).

use zns_verify::{
    memo::{encode_name_note, encode_request, validate_name, MemoError},
    parse_claim_memo, parse_name_note, parse_release_memo, parse_update_memo, Action, NameNote,
    MEMO_SIZE,
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

#[test]
fn parses_request_forms() {
    assert_eq!(
        parse_claim_memo(b"ZNS:claim:alice:u1xxx"),
        Ok((&b"claim"[..], &b"alice"[..], &b"u1xxx"[..])),
    );
    assert_eq!(
        parse_update_memo(b"ZNS:update:alice:u1new"),
        Ok((&b"update"[..], &b"alice"[..], &b"u1new"[..])),
    );
    assert_eq!(
        parse_release_memo(b"ZNS:release:alice"),
        Ok((&b"release"[..], &b"alice"[..], &b""[..])),
    );
}

#[test]
fn parses_name_note_forms() {
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let mut want = [0u8; 32];
    hex::decode_to_slice(hex, &mut want).unwrap();

    // Claim: 6 fields with expires_at (WP §3.1)
    let m = format!("ZNS:claim:alice:u1xxx:none:{hex}");
    assert_eq!(
        parse_name_note(m.as_bytes()),
        Ok(name_note(Action::Claim, "alice", "u1xxx", "none", want)),
    );
    // Update with a fixed expiration
    let m = format!("ZNS:update:alice:u1new:1775000000:{hex}");
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
    let m = format!("ZNS:release:alice:u1old:none:{hex}");
    assert_eq!(
        parse_name_note(m.as_bytes()),
        Ok(name_note(Action::Release, "alice", "u1old", "none", want))
    );

    // The witness must be exactly 64 lowercase hex chars.
    assert_eq!(
        parse_name_note(b"ZNS:claim:alice:u1xxx:none:abcd"),
        Err(MemoError::InvalidPrevRcm)
    );
    let upper = format!("ZNS:claim:alice:u1xxx:none:{}", hex.to_uppercase());
    assert_eq!(
        parse_name_note(upper.as_bytes()),
        Err(MemoError::InvalidPrevRcm)
    );
    // A request-form verb (no expires_at/prev_rcm) is not a Name Note.
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
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    // Release with a non-none expires_at is rejected (WP §3.1)
    let m = format!("ZNS:release:alice:u1old:1000:{hex}");
    assert_eq!(parse_name_note(m.as_bytes()), Err(MemoError::FieldCount));
}

#[test]
fn request_parsers_reject_name_note_fields() {
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let m = format!("ZNS:claim:alice:u1xxx:none:{hex}");
    assert_eq!(parse_claim_memo(m.as_bytes()), Err(MemoError::FieldCount));
    let m = format!("ZNS:update:alice:u1new:none:{hex}");
    assert_eq!(parse_update_memo(m.as_bytes()), Err(MemoError::FieldCount));
    let m = format!("ZNS:release:alice:none:{hex}");
    assert_eq!(parse_release_memo(m.as_bytes()), Err(MemoError::FieldCount));
}

#[test]
fn zero_padding_is_stripped() {
    assert_eq!(
        parse_claim_memo(&padded("ZNS:claim:alice:u1xxx")),
        Ok((&b"claim"[..], &b"alice"[..], &b"u1xxx"[..])),
    );
}

#[test]
fn non_zns_memos_are_not_zns() {
    assert_eq!(
        parse_claim_memo(b"just a payment note"),
        Err(MemoError::NotZns)
    );
    assert_eq!(
        parse_claim_memo(b"ZEC:claim:alice:u1"),
        Err(MemoError::NotZns)
    );
    assert_eq!(parse_claim_memo(&[0u8; MEMO_SIZE]), Err(MemoError::NotZns));
    assert_eq!(parse_claim_memo(&[0xff, 0xfe]), Err(MemoError::NotZns));
}

#[test]
fn strict_field_counts() {
    // A sixth field that is not valid prev_rcm hex must reject.
    assert_eq!(
        parse_name_note(b"ZNS:update:alice:u1x:none:extra"),
        Err(MemoError::InvalidPrevRcm)
    );
    assert_eq!(
        parse_release_memo(b"ZNS:release:alice:junk"),
        Err(MemoError::FieldCount)
    );
    assert_eq!(
        parse_release_memo(b"ZNS:release:alice:"),
        Err(MemoError::FieldCount)
    );
    assert_eq!(
        parse_claim_memo(b"ZNS:claim:alice"),
        Err(MemoError::EmptyArg)
    );
    assert_eq!(
        parse_claim_memo(b"ZNS:claim:alice:"),
        Err(MemoError::EmptyArg)
    );
    assert_eq!(parse_claim_memo(b"ZNS:claim"), Err(MemoError::FieldCount));
    assert_eq!(
        parse_claim_memo(b"ZNS:settle:alice:u1x"),
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
        parse_claim_memo(b"ZNS:claim:Alice:u1x"),
        Err(MemoError::InvalidName)
    );
}

#[test]
fn encode_round_trips() {
    let m = encode_request(Action::Claim, "alice", "u1xxx").unwrap();
    assert_eq!(
        parse_claim_memo(&m),
        Ok((&b"claim"[..], &b"alice"[..], &b"u1xxx"[..]))
    );
    let m = encode_request(Action::Release, "alice", "").unwrap();
    assert_eq!(
        parse_release_memo(&m),
        Ok((&b"release"[..], &b"alice"[..], &b""[..]))
    );

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
    // A ua that cannot fit the ZIP-302 memo.
    let huge = "u".repeat(MEMO_SIZE);
    assert_eq!(
        encode_request(Action::Claim, "alice", &huge),
        Err(MemoError::TooLong)
    );
}
