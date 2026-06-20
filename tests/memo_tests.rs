//! Tests for the memo grammar (parse_memo, encode_*, validate_name, etc.).

use zns_verify::{
    memo::{
        encode_challenge, encode_confirm, encode_name_note, encode_request, validate_name,
        MemoError,
    },
    parse_memo, Action, ParsedMemo, MEMO_SIZE,
};

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
