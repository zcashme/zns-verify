//! Cross-language test vectors for bound Name Notes: the record's rseed
//! (`name_note_rseed`) and the cmx of the Ironwood note built from it.
//!
//! The note goes to a fixed Registry address (`G_D`, `PK_D`) with
//! rho = [0x33; 32] and value = 0. The bound UA is the WP §3.5 address.

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
    prev: [u8; 32],
    expected_rseed_hex: &'static str,
    expected_cmx_hex: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        label: "claim, zero prev",
        action: b"claim",
        name: b"alice",
        expires_at: b"none",
        prev: [0u8; 32],
        expected_rseed_hex: "5bcb6b8f30d7f8cd75f253b738c6fb034841e31c70d137373f3b36b0c595e56d",
        expected_cmx_hex: "a8e6da4a73de6efa14c13e565a8701f210b17e4de4b067a41a41910383b9da18",
    },
    Vector {
        label: "update, fixed expiry",
        action: b"update",
        name: b"alice",
        expires_at: b"1893456000",
        prev: [0xabu8; 32],
        expected_rseed_hex: "5500949ebcf01bb4e5794dfbec49aa86cd626e5ff6876a42e8c0a4bb51e06ce8",
        expected_cmx_hex: "be3ed1474405ae3aaa45618b7321f83122e394469277efdd750a5e1565ef9208",
    },
    Vector {
        label: "release, retained ua",
        action: b"release",
        name: b"alice",
        expires_at: b"none",
        prev: [0xcdu8; 32],
        expected_rseed_hex: "a63a0403921bf6f32984d313669179688d7b2145b39e2e884be78f7e4f70b232",
        expected_cmx_hex: "61e9d4dd9d4dea44f88d5a8eff37971b9c117350ecf88d2bb17dc3fd78bede32",
    },
];

fn bytes32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

#[test]
fn rseed_vectors_match() {
    for v in VECTORS {
        let rseed = name_note_rseed(v.action, v.name, UA, v.expires_at, &[], &v.prev);
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
