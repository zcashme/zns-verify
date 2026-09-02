//! Tests for the Name Note memo grammar.

use zns_verify::memo::MEMO_SIZE;
use zns_verify::{Action, Expiry, Memo, MemoError, Name, NameNote, PrevRcm};

const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn memo(text: &str) -> Memo {
    Memo::from_bytes(text.as_bytes()).unwrap()
}

#[test]
fn parses_the_wp_golden_memo() {
    let golden = "ZNS:claim:alice:u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q:none:0000000000000000000000000000000000000000000000000000000000000000";
    let m = memo(golden);
    let note = NameNote::parse(&m).unwrap();
    match note {
        NameNote::Claim {
            name,
            ua,
            expires_at,
        } => {
            assert_eq!(name.as_str(), "alice");
            assert!(ua.starts_with("u1897"));
            assert_eq!(expires_at, Expiry::NEVER);
        }
        _ => panic!("expected claim"),
    }
    assert_eq!(note.encode().unwrap().as_array(), m.as_array());
}

#[test]
fn parses_name_note_forms() {
    let prev = PrevRcm::from_hex(HEX).unwrap();

    let m = memo(&format!("ZNS:claim:alice:u1xxx:none:{ZERO_HEX}"));
    let note = NameNote::parse(&m).unwrap();
    assert_eq!(note.action(), Action::Claim);
    assert_eq!(note.prev_rcm(), None);

    let m = memo(&format!("ZNS:update:alice:u1new:1775000000:{HEX}"));
    let note = NameNote::parse(&m).unwrap();
    assert_eq!(
        note.expires_at(),
        Some(Expiry::from_field("1775000000").unwrap())
    );
    assert_eq!(note.prev_rcm(), Some(prev));

    let m = memo(&format!("ZNS:release:alice:u1old:none:{HEX}"));
    let note = NameNote::parse(&m).unwrap();
    assert_eq!(note.action(), Action::Release);
    assert_eq!(note.expires_at(), None);
    assert_eq!(note.prev_rcm(), Some(prev));
}

#[test]
fn encodes_canonical_bytes() {
    let m = memo(&format!("ZNS:update:alice:u1new:1775000000:{HEX}"));
    let note = NameNote::parse(&m).unwrap();
    let encoded = note.encode().unwrap();
    let expected = format!("ZNS:update:alice:u1new:1775000000:{HEX}");
    assert_eq!(&encoded.as_array()[..expected.len()], expected.as_bytes());
    assert!(encoded.as_array()[expected.len()..].iter().all(|&b| b == 0));
}

#[test]
fn parse_encode_is_idempotent() {
    let texts = [
        format!("ZNS:claim:alice:u1xxx:none:{ZERO_HEX}"),
        format!("ZNS:claim:alice:u1xxx:0:{ZERO_HEX}"),
        format!("ZNS:update:alice:u1new:1775000000:{HEX}"),
        format!("ZNS:release:alice:u1old:none:{HEX}"),
    ];
    for text in texts {
        let m = memo(&text);
        let note = NameNote::parse(&m).unwrap();
        let reencoded = note.encode().unwrap();
        assert_eq!(
            reencoded.as_array()[..text.len()],
            *text.as_bytes(),
            "non-canonical re-encoding of {text}"
        );
    }
}

#[test]
fn memo_padding_must_be_canonical() {
    let mut bytes = *memo(&format!("ZNS:claim:alice:u1xxx:none:{ZERO_HEX}")).as_array();
    bytes[30] = b'x';
    let bad = Memo::from_array(bytes);
    assert!(NameNote::parse(&bad).is_err());

    let good = memo(&format!("ZNS:claim:alice:u1xxx:none:{ZERO_HEX}"));
    assert!(NameNote::parse(&good).is_ok());
}

#[test]
fn expiry_field_is_canonical_or_none() {
    for bad in ["01", "+1", "1.0", "", "None"] {
        let m = memo(&format!("ZNS:claim:alice:u1x:{bad}:{ZERO_HEX}"));
        assert_eq!(
            NameNote::parse(&m),
            Err(MemoError::InvalidExpiry),
            "expires_at {bad:?}"
        );
    }
    for good in ["0", "none", "1775000000"] {
        let m = memo(&format!("ZNS:claim:alice:u1x:{good}:{ZERO_HEX}"));
        assert!(NameNote::parse(&m).is_ok());
    }
}

#[test]
fn predecessor_consistency_is_structural() {
    let m = memo(&format!("ZNS:claim:alice:u1x:none:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));

    let zeros = "0".repeat(64);
    let m = memo(&format!("ZNS:claim:alice:u1x:none:{zeros}"));
    assert!(NameNote::parse(&m).is_ok());

    let m = memo(&format!("ZNS:update:alice:u1x:none:{zeros}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));

    let m = memo(&format!("ZNS:release:alice:u1old:none:{HEX}"));
    assert!(NameNote::parse(&m).is_ok());
}

#[test]
fn release_expiry_is_structurally_absent() {
    let m = memo(&format!("ZNS:release:alice:u1old:1000:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidExpiry));
}

#[test]
fn non_zns_memos_are_not_zns() {
    let m = memo(&format!("just a payment note:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::NotZns));
    let m = memo(&format!("ZEC:claim:alice:u1:none:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::NotZns));
    let empty = Memo::from_array([0u8; MEMO_SIZE]);
    assert_eq!(NameNote::parse(&empty), Err(MemoError::NotZns));
    let invalid_utf8 = Memo::from_array({
        let mut b = [0u8; MEMO_SIZE];
        b[0] = 0xff;
        b[1] = 0xfe;
        b
    });
    assert_eq!(NameNote::parse(&invalid_utf8), Err(MemoError::NotZns));
}

#[test]
fn strict_field_counts() {
    let m = memo("ZNS:update:alice:u1x:none:extra");
    assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidPrevRcm));
    let m = memo("ZNS:claim:alice:u1x");
    assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
    let m = memo("ZNS:claim:alice:u1x:none");
    assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
    let m = memo("ZNS:claim:alice");
    assert_eq!(NameNote::parse(&m), Err(MemoError::FieldCount));
    let m = memo(&format!("ZNS:claim:alice::none:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::EmptyUa));
    let m = memo(&format!("ZNS:settle:alice:u1x:none:{HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::UnknownVerb));
}

#[test]
fn enforces_zns_name_rules() {
    assert!(Name::parse("alice").is_ok());
    assert!(Name::parse("a-1").is_ok());
    assert!(Name::parse("").is_err());
    assert!(Name::parse("-alice").is_err());
    assert!(Name::parse("alice-").is_err());
    assert!(Name::parse("Alice").is_err());
    assert!(Name::parse("al ice").is_err());
    assert!(Name::parse(&"a".repeat(63)).is_ok());
    assert!(Name::parse(&"a".repeat(64)).is_err());
    let m = memo(&format!("ZNS:claim:Alice:u1x:none:{ZERO_HEX}"));
    assert_eq!(NameNote::parse(&m), Err(MemoError::InvalidName));
}

#[test]
fn expiry_type_is_canonical_only() {
    assert_eq!(Expiry::from_field("none"), Ok(Expiry::NEVER));
    assert!(Expiry::from_field("0").is_ok());
    assert!(Expiry::from_field("1775000000").is_ok());
    assert!(Expiry::from_field("01").is_err());
    assert!(Expiry::from_field("+1").is_err());
    assert!(Expiry::from_field("").is_err());
    assert_eq!(Expiry::from_field("none").unwrap().field_bytes(), "none");
}

#[test]
fn prev_rcm_hex_codec() {
    let prev = PrevRcm::from_hex(HEX).unwrap();
    assert_eq!(prev.to_hex(), HEX.as_bytes());
    let round = PrevRcm::from_hex(core::str::from_utf8(&prev.to_hex()).unwrap()).unwrap();
    assert_eq!(prev, round);
    assert!(PrevRcm::from_hex(&HEX.to_uppercase()).is_err());
    assert!(PrevRcm::from_hex("abcd").is_err());
    assert!(PrevRcm::ZERO.is_zero());
    assert!(!prev.is_zero());
}

#[test]
fn chain_rule() {
    use zns_verify::{prev_rcm_for, Tip};

    let tip = Tip {
        action: Action::Claim,
        rcm: [1u8; 32],
    };
    assert_eq!(prev_rcm_for(None, Action::Claim), Some([0u8; 32]));
    assert_eq!(prev_rcm_for(Some(&tip), Action::Update), Some([1u8; 32]));
    assert_eq!(prev_rcm_for(Some(&tip), Action::Release), Some([1u8; 32]));
    assert_eq!(prev_rcm_for(Some(&tip), Action::Claim), None);
}
