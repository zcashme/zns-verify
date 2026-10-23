//! Cross-language test vectors for the `zns_psi_rcm` hash construction
//! and the Sinsemilla note commitment.
//!
//! All vectors use the WP §3.5 golden vector's g_d, pk_d, and unified
//! address, with rho = [0x33; 32] and value = 0.

use zns_verify::{note_commitment_cmx, zns_psi_rcm, PrimeField, Rho};

const G_D: [u8; 32] = [
    0xde, 0x43, 0x38, 0xf2, 0xab, 0x9f, 0xd8, 0x30, 0x0a, 0x3a, 0x1c, 0x20, 0xdd, 0x69, 0x0c, 0xe2,
    0x70, 0x26, 0xc6, 0x00, 0x1c, 0x29, 0x5d, 0x7c, 0x64, 0x1a, 0x06, 0x7c, 0xe8, 0x09, 0xb1, 0x1e,
];
const PK_D: [u8; 32] = [
    0x6d, 0xf6, 0x09, 0xf5, 0x71, 0x0f, 0x3b, 0x5d, 0xee, 0xcd, 0x4e, 0xe4, 0xb8, 0xf0, 0x17, 0x3b,
    0x44, 0xaf, 0x6c, 0xf8, 0x91, 0x8a, 0xc0, 0x02, 0x69, 0x52, 0x60, 0x31, 0xba, 0x62, 0x89, 0x96,
];
const UA: &[u8] =
    b"u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

struct Vector {
    label: &'static str,
    action: &'static [u8],
    name: &'static [u8],
    ua: &'static [u8],
    expires_at: &'static [u8],
    prev_rcm: [u8; 32],
    expected_psi_hex: &'static str,
    expected_rcm_hex: &'static str,
    expected_cmx_hex: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        label: "claim, zero prev (WP §3.5)",
        action: b"claim",
        name: b"alice",
        ua: UA,
        expires_at: b"none",
        prev_rcm: [0u8; 32],
        expected_psi_hex: "9f8a61b860c737d4564f12c635d654b843bc7115d9dc6cf6f09e409c81b8d13e",
        expected_rcm_hex: "daa928be21d0ec13b5dbb0244699dbfeba546c71591d24d7824db78e4670c504",
        expected_cmx_hex: "cc320736a0c1df1e4ffcee2b64aa73a9e6d06bb218e155a6fef422e1ecb1f70c",
    },
    Vector {
        label: "update, non-zero prev",
        action: b"update",
        name: b"alice",
        ua: UA,
        expires_at: b"none",
        prev_rcm: [0xabu8; 32],
        expected_psi_hex: "f5ee106d053a8ed04746b3d53c9d01155f095dd058e3ab9de5fc6706f2052631",
        expected_rcm_hex: "3b488c9e8a31b50bc4ae7833bd4e2f7f762596d9d71273ce102f9b737d007d20",
        expected_cmx_hex: "e02652d02242b8362af9de9c10593c0cd5853252ba26279f31ca85c37af7071e",
    },
    Vector {
        label: "release, retained ua",
        action: b"release",
        name: b"alice",
        ua: UA,
        expires_at: b"none",
        prev_rcm: [0xffu8; 32],
        expected_psi_hex: "4a5b312d519ed28f75755b4720ddaa4d94c7079c29552f79e93126c4bda72714",
        expected_rcm_hex: "ad952d64ab0f74ea12326781bb1a18c10e0c82f60b69be7b7a4f2f12263a1d3c",
        expected_cmx_hex: "5364ebb6e50bc45e698d17fffc50461ae5b12ac183357970b643f078180d2610",
    },
    Vector {
        label: "claim, long name, non-zero prev",
        action: b"claim",
        name: b"abcdefghijklmnopqrstuvwxyz0123456789",
        ua: UA,
        expires_at: b"none",
        prev_rcm: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ],
        expected_psi_hex: "ab921f392583a755ccd9710d17bb5905c4145dbe2a36b7f768c974bec3962b1b",
        expected_rcm_hex: "9b007d319cbe7b5331c2bd0e3b6bfc0c9e971983fc608f1e3a6be31c6ed3e81a",
        expected_cmx_hex: "c1a38407fee76550fa24e1cf82892a9929e3f206c05dc614287ca7842265d317",
    },
    Vector {
        label: "claim, non-none expires_at",
        action: b"claim",
        name: b"alice",
        ua: UA,
        expires_at: b"1775000000",
        prev_rcm: [0u8; 32],
        expected_psi_hex: "7e5d7deaf75a1f9bfd9cc983087176b00a4ef2215c91e0f0ddeb8b9493e79416",
        expected_rcm_hex: "e25159b43e877133b1a4b4978c66b76a3beb226eb8d5fd2a5e1f8074c2628c1c",
        expected_cmx_hex: "ec09921f8a455c359dc53aff9c279ebcf739f2268b0baa8c3c5333224fec7300",
    },
];

#[test]
fn hash_vectors_match() {
    for v in VECTORS {
        let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
        assert_eq!(
            hex::encode(psi.to_repr()),
            v.expected_psi_hex,
            "psi: {}",
            v.label,
        );
        assert_eq!(
            hex::encode(rcm.to_repr()),
            v.expected_rcm_hex,
            "rcm: {}",
            v.label,
        );
    }
}

#[test]
fn cmx_vectors_match() {
    let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
    for v in VECTORS {
        let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
        let cmx = note_commitment_cmx(G_D, PK_D, 0, rho, psi, rcm)
            .expect("commit must land off identity");
        assert_eq!(
            hex::encode(cmx.to_bytes()),
            v.expected_cmx_hex,
            "cmx: {}",
            v.label,
        );
    }
}
