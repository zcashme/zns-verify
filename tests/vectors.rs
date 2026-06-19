//! Cross-language test vectors for the `zns_psi_rcm` hash construction.

use pasta_curves::group::ff::PrimeField;
use zns_verify::{note_commitment_cmx, zns_psi_rcm};

struct Vector {
    label: &'static str,
    action: &'static [u8],
    name: &'static [u8],
    ua: &'static [u8],
    prev_rcm: [u8; 32],
    expected_psi_hex: &'static str,
    expected_rcm_hex: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        label: "minimal claim, short ua",
        action: b"claim",
        name: b"alice",
        ua: b"u1xxx",
        prev_rcm: [0u8; 32],
        expected_psi_hex: "bde12553f1d349d9ca6836f6711a256cd353fc2376d5d861324766845bcfbd08",
        expected_rcm_hex: "ab91154ea92a1796a0d088e4909ab7f72b0e20896a130c5bb53910044565b020",
    },
    Vector {
        label: "update with non-zero prev_rcm",
        action: b"update",
        name: b"alice",
        ua: b"u1other",
        prev_rcm: [0xabu8; 32],
        expected_psi_hex: "2a880309afdfc77dbd30a1d1b2fc9da6aafc7083db42c1dd8e20604c699e3d3f",
        expected_rcm_hex: "2e7cdb8b1afc60d8199780a6c8ad718703523b3f29441c4b69710945f04dc735",
    },
    Vector {
        label: "release, empty ua",
        action: b"release",
        name: b"alice",
        ua: b"",
        prev_rcm: [0xffu8; 32],
        expected_psi_hex: "5e04e5022bb0e9065745094969863c1f4f33c6109e1372438d360d91f629a824",
        expected_rcm_hex: "3e7d5b6a33beef0c7503eea750d2bb43585b7b70524ad7bef634616ebfe97c0c",
    },
    Vector {
        label: "longer name + ua",
        action: b"claim",
        name: b"abcdefghijklmnopqrstuvwxyz0123456789",
        ua: b"u1pkdv3v7emc63xnxgrwn8anlj9k6tvxhd3w7zwxhlsx2dssznml",
        prev_rcm: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ],
        expected_psi_hex: "0b333eab8c727074a981e8c276ad69ff0da5ff40b08016e1a1aa4dd9dfd09a14",
        expected_rcm_hex: "792cdf99ed43ca07303f9aac00c28b52fc8f5fd02a1a9f700137f958632ce704",
    },
];

/// Pins one full commitment derivation: takes (g_d, pk_d, v, ρ) plus the
/// (ψ, rcm) produced by `zns_psi_rcm` for a known tuple, and asserts the
/// resulting `cmx` is byte-stable. Any change to the Sinsemilla
/// personalization, the bit decomposition, or the field reductions will
/// move this value and break the test.
#[test]
fn commit_matches() {
    use pasta_curves::pallas;
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let value: u64 = 0;
    let rho = pallas::Base::from_repr([0x33u8; 32]).unwrap();
    let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", b"u1xxx", &[0u8; 32]);
    let cmx = note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)
        .expect("commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "53accd0df1c569731e8ad4fc8bcb483b953e3713ecc7a95202442daa026c4a02",
        "cmx for fixed test inputs",
    );
}

/// Additional cmx pin using the release vector inputs. Exercises the
/// "release" action bytes + explicit empty ua through the full Sinsemilla
/// construction (different from the primary claim-based commit_matches).
#[test]
fn commit_matches_release_vector() {
    use pasta_curves::pallas;
    let v = &VECTORS[2];
    let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, &v.prev_rcm);
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let rho = pallas::Base::from_repr([0x33u8; 32]).unwrap();
    let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm)
        .expect("release commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "eb8a35b09bba153273435546921ef84a48aeda7eae0969cd8c6c097ea7a0651e",
        "cmx for release vector inputs",
    );
}

#[test]
fn vectors_match() {
    for v in VECTORS {
        let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, &v.prev_rcm);
        assert_eq!(
            hex::encode(psi.to_repr()),
            v.expected_psi_hex,
            "psi mismatch for vector {:?}",
            v.label,
        );
        assert_eq!(
            hex::encode(rcm.to_repr()),
            v.expected_rcm_hex,
            "rcm mismatch for vector {:?}",
            v.label,
        );
    }
}
