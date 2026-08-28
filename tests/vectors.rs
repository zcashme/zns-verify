//! Cross-language test vectors for the `zns_psi_rcm` hash construction.

use zns_verify::{base_from_bytes, note_commitment_cmx, PrimeField, zns_psi_rcm};

struct Vector {
    label: &'static str,
    action: &'static [u8],
    name: &'static [u8],
    ua: &'static [u8],
    expires_at: &'static [u8],
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
        expires_at: b"none",
        prev_rcm: [0u8; 32],
        expected_psi_hex: "b2b6ffd3a3b1051b03ffe74a87770aed5c404b9464c3af72341a9b2667578e15",
        expected_rcm_hex: "c0ef8eecb947fdec6e4c4f964681f12a7f3b166cb590bec2a24a5e27b909ba0b",
    },
    Vector {
        label: "update with non-zero prev_rcm",
        action: b"update",
        name: b"alice",
        ua: b"u1other",
        expires_at: b"none",
        prev_rcm: [0xabu8; 32],
        expected_psi_hex: "2eab69b72608401995a1e8b9467b11507d92288788229983658a9a6c6b72dc12",
        expected_rcm_hex: "1428d72ac8e6bf8d223131095d0bd715e5767d03037ea33effd723c778e39914",
    },
    Vector {
        label: "release, retained ua",
        action: b"release",
        name: b"alice",
        ua: b"u1old",
        expires_at: b"none",
        prev_rcm: [0xffu8; 32],
        expected_psi_hex: "cfdb31d484583fdc80228f5c0cbb2056b839ed26e38a6a3f37ae120a6fe2a510",
        expected_rcm_hex: "309a62731d98a32bfd6f053e91d8cd2bc05440edda10b2b7e560f0641d832e12",
    },
    Vector {
        label: "longer name + ua",
        action: b"claim",
        name: b"abcdefghijklmnopqrstuvwxyz0123456789",
        ua: b"u1pkdv3v7emc63xnxgrwn8anlj9k6tvxhd3w7zwxhlsx2dssznml",
        expires_at: b"none",
        prev_rcm: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ],
        expected_psi_hex: "7baa7bc9c2c3ac146de9d84c766f010f1f7526c9fe22a5cc98ec26c12cfbf32c",
        expected_rcm_hex: "790b76fb58aecbe4e0798d8af693faa34b8b9c968bef20ab3eaf292742f9da19",
    },
];

/// Pins one full commitment derivation: takes (g_d, pk_d, v, ρ) plus the
/// (ψ, rcm) produced by `zns_psi_rcm` for a known tuple, and asserts the
/// resulting `cmx` is byte-stable. Any change to the Sinsemilla
/// personalization, the bit decomposition, or the field reductions will
/// move this value and break the test.
#[test]
fn commit_matches() {
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let value: u64 = 0;
    let rho = base_from_bytes([0x33u8; 32]);
    let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", b"u1xxx", b"none", &[0u8; 32]);
    let cmx = note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm)
        .expect("commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "e9dba3d63fd866ca2ce29e1a102b2e3ffd3816817e28d74a6969efc019226a0d",
        "cmx for fixed test inputs",
    );
}

/// Additional cmx pin using the release vector inputs. Exercises the
/// "release" action bytes + retained ua through the full Sinsemilla
/// construction.
#[test]
fn commit_matches_release_vector() {
    let v = &VECTORS[2];
    let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let rho = base_from_bytes([0x33u8; 32]);
    let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm)
        .expect("release commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "668c1996e653808e1b42e0ed11bdb6e02b4ab7cf4e6a203262691a7f8627210e",
        "cmx for release vector inputs",
    );
}

/// Additional cmx pin using the update vector inputs.
#[test]
fn commit_matches_update_vector() {
    let v = &VECTORS[1];
    let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let rho = base_from_bytes([0x33u8; 32]);
    let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm)
        .expect("update commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "fd06466171c6fd7e09db946a6769c071086830a02c6724d7ccb1f1bf596ba137",
        "cmx for update vector inputs",
    );
}

/// Additional cmx pin using the longer name + ua vector inputs.
#[test]
fn commit_matches_long_vector() {
    let v = &VECTORS[3];
    let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
    let g_d = [0x11u8; 32];
    let pk_d = [0x22u8; 32];
    let rho = base_from_bytes([0x33u8; 32]);
    let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm)
        .expect("long commit must land off identity");
    assert_eq!(
        hex::encode(cmx.to_repr()),
        "4f0449805a9df867fee64c3468798542caf5fd5537bbb5ca6f4f8eaa2e03ec18",
        "cmx for long vector inputs",
    );
}

#[test]
fn vectors_match() {
    for v in VECTORS {
        let (psi, rcm) = zns_psi_rcm(v.action, v.name, v.ua, v.expires_at, &v.prev_rcm);
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