//! Cross-language test vectors for bound Name Notes: the record's rseed
//! (`name_note_rseed`) and the cmx of the Ironwood note built from it.
//!
//! The note goes to a fixed Registry address (`G_D`, `PK_D`) with
//! rho = [0x33; 32] and value = 0. The bound UA is the WP §4.6 address.

use zns_verify::{
    name_note_rseed, note_commitment_cmx, psi_from_rseed, rcm_from_rseed, verify_bound_name_note,
    ExtractedNoteCommitment, Memo, NameNote, Rho,
};

const G_D: &str = "dd0c23bc9720ff21aaab76a7b7276231ee212f156e9c318c355972628efed408";
const PK_D: &str = "81a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d";
const UA: &[u8] =
    b"u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

struct Vector {
    label: &'static str,
    action: &'static [u8],
    name: &'static [u8],
    expires_at: &'static [u8],
    terms: &'static [&'static [u8]],
    prev: [u8; 32],
    expected_rseed_hex: &'static str,
    expected_cmx_hex: &'static str,
}

/// The t1 the list and auction vectors pay.
const PAY_TO: &[u8] = b"t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKcQB";

const VECTORS: &[Vector] = &[
    Vector {
        label: "claim, zero prev",
        action: b"claim",
        name: b"alice",
        expires_at: b"none",
        terms: &[],
        prev: [0u8; 32],
        expected_rseed_hex: "5bcb6b8f30d7f8cd75f253b738c6fb034841e31c70d137373f3b36b0c595e56d",
        expected_cmx_hex: "a8e6da4a73de6efa14c13e565a8701f210b17e4de4b067a41a41910383b9da18",
    },
    Vector {
        label: "update, fixed expiry",
        action: b"update",
        name: b"alice",
        expires_at: b"1893456000",
        terms: &[],
        prev: [0xabu8; 32],
        expected_rseed_hex: "5500949ebcf01bb4e5794dfbec49aa86cd626e5ff6876a42e8c0a4bb51e06ce8",
        expected_cmx_hex: "be3ed1474405ae3aaa45618b7321f83122e394469277efdd750a5e1565ef9208",
    },
    Vector {
        label: "release, retained ua",
        action: b"release",
        name: b"alice",
        expires_at: b"none",
        terms: &[],
        prev: [0xcdu8; 32],
        expected_rseed_hex: "a63a0403921bf6f32984d313669179688d7b2145b39e2e884be78f7e4f70b232",
        expected_cmx_hex: "61e9d4dd9d4dea44f88d5a8eff37971b9c117350ecf88d2bb17dc3fd78bede32",
    },
    Vector {
        label: "list, t1 and price",
        action: b"list",
        name: b"alice",
        expires_at: b"none",
        terms: &[PAY_TO, b"1.5"],
        prev: [0x1bu8; 32],
        expected_rseed_hex: "28714cde41f553202e317b93f5663aac95f7370c3c9f95ea45d0bf91a1d6a4f5",
        expected_cmx_hex: "11db7667dae5d4a431432d77a5547c33568b005c1f954b3e58dd8dd94a500616",
    },
    Vector {
        label: "auction, five terms",
        action: b"auction",
        name: b"alice",
        expires_at: b"1893456000",
        terms: &[PAY_TO, b"9", b"1", b"3000000", b"3001000"],
        prev: [0x1bu8; 32],
        expected_rseed_hex: "8883dd40d097b898621837334e08bbfd65a1cbe4b05fbec28396a458b953774e",
        expected_cmx_hex: "9b960b4a53a12016a24b831fb47542651024788ecc807b5cf8193282f33e510d",
    },
    Vector {
        label: "sale, buyer ua",
        action: b"sale",
        name: b"alice",
        expires_at: b"none",
        terms: &[],
        prev: [0x1bu8; 32],
        expected_rseed_hex: "5d056a80415b632c5913dd6379ffffbd59663c545368aeade779ae5f6ada69ee",
        expected_cmx_hex: "722c8a79a10b5f39786f316bfc8e1a2aba74960a63e1708a34d6e297c48c2610",
    },
    Vector {
        label: "delist, fixed expiry",
        action: b"delist",
        name: b"alice",
        expires_at: b"1893456000",
        terms: &[],
        prev: [0x1bu8; 32],
        expected_rseed_hex: "f6a1999153eb3e06f7712bbaae8f90473c0247092a2bbf2b371bf5cc15c65f9a",
        expected_cmx_hex: "d267f0de8846358574e71f31b4c845fce7a83873003bf0f993b34d2430c6130b",
    },
];

fn bytes32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

#[test]
fn rseed_vectors_match() {
    for v in VECTORS {
        let mut fields = [v.action, v.name, UA, v.expires_at].join(&b':');
        for term in v.terms {
            fields.push(b':');
            fields.extend_from_slice(term);
        }
        let rseed = name_note_rseed(&fields, &v.prev);
        assert_eq!(hex::encode(rseed), v.expected_rseed_hex, "{}", v.label);
    }
}

#[test]
fn memo_verifies_against_its_cmx_only() {
    let (g_d, pk_d) = (bytes32(G_D), bytes32(PK_D));
    let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
    let text = format!(
        "ZNS:claim:alice:{}:none:{}",
        core::str::from_utf8(UA).unwrap(),
        "0".repeat(64)
    );
    let memo = Memo::from_bytes(text.as_bytes()).unwrap();
    let note = NameNote::parse(&memo).unwrap();

    let claim_cmx = ExtractedNoteCommitment::from_bytes(&bytes32(VECTORS[0].expected_cmx_hex));
    let update_cmx = ExtractedNoteCommitment::from_bytes(&bytes32(VECTORS[1].expected_cmx_hex));
    assert!(verify_bound_name_note(
        &note,
        g_d,
        pk_d,
        0,
        rho,
        claim_cmx.unwrap()
    ));
    assert!(!verify_bound_name_note(
        &note,
        g_d,
        pk_d,
        0,
        rho,
        update_cmx.unwrap()
    ));
}

#[test]
fn a_changed_listing_term_misses_the_original_commitment() {
    let (g_d, pk_d) = (bytes32(G_D), bytes32(PK_D));
    let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
    let ua = core::str::from_utf8(UA).unwrap();
    let prev = hex::encode([0xabu8; 32]);
    let list = format!("ZNS:list:alice:{ua}:none:t1abc:5:{prev}");
    let auction = format!("ZNS:auction:alice:{ua}:none:t1abc:9:1:3000000:3001000:{prev}");
    rejects_each_term(
        &list,
        &[
            &format!("ZNS:list:alice:{ua}:none:t1xyz:5:{prev}"),
            &format!("ZNS:list:alice:{ua}:none:t1abc:6:{prev}"),
        ],
        g_d,
        pk_d,
        rho,
    );
    rejects_each_term(
        &auction,
        &[
            &format!("ZNS:auction:alice:{ua}:none:t1xyz:9:1:3000000:3001000:{prev}"),
            &format!("ZNS:auction:alice:{ua}:none:t1abc:8:1:3000000:3001000:{prev}"),
            &format!("ZNS:auction:alice:{ua}:none:t1abc:9:2:3000000:3001000:{prev}"),
            &format!("ZNS:auction:alice:{ua}:none:t1abc:9:1:3000001:3001000:{prev}"),
            &format!("ZNS:auction:alice:{ua}:none:t1abc:9:1:3000000:3001001:{prev}"),
        ],
        g_d,
        pk_d,
        rho,
    );
}

fn rejects_each_term(original: &str, altered: &[&str], g_d: [u8; 32], pk_d: [u8; 32], rho: Rho) {
    let memo = Memo::from_bytes(original.as_bytes()).unwrap();
    let note = NameNote::parse(&memo).unwrap();
    let cmx = commitment_of(&note, g_d, pk_d, rho);
    assert!(verify_bound_name_note(&note, g_d, pk_d, 0, rho, cmx));
    for text in altered {
        let memo = Memo::from_bytes(text.as_bytes()).unwrap();
        let tampered = NameNote::parse(&memo).unwrap();
        assert!(
            !verify_bound_name_note(&tampered, g_d, pk_d, 0, rho, cmx),
            "{text}"
        );
    }
}

fn commitment_of(
    note: &NameNote<'_>,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    rho: Rho,
) -> ExtractedNoteCommitment {
    let memo = note.encode().unwrap();
    let rseed = name_note_rseed(memo.fields().unwrap(), note.prev().unwrap().as_bytes());
    let psi = psi_from_rseed(&rseed, rho);
    let rcm = rcm_from_rseed(&rseed, rho, g_d, pk_d, 0, psi);
    note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm).unwrap()
}

#[test]
fn cmx_vectors_match() {
    let (g_d, pk_d) = (bytes32(G_D), bytes32(PK_D));
    let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
    for v in VECTORS {
        let rseed = bytes32(v.expected_rseed_hex);
        let psi = psi_from_rseed(&rseed, rho);
        let rcm = rcm_from_rseed(&rseed, rho, g_d, pk_d, 0, psi);
        let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm).unwrap();
        assert_eq!(
            hex::encode(cmx.to_bytes()),
            v.expected_cmx_hex,
            "{}",
            v.label
        );
    }
}
