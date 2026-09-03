//! The ZNS commitment derivation: (ψ, rcm) from the binding tuple (WP §3.3),
//! and the Sinsemilla note commitment (WP §3.4).

use blake2b_simd::Params;
use group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;

/// The protocol domain tag (WP §3.3).
pub const ZNS_DOMAIN_TAG: &[u8] = b"ZcashName/v1";

const TAG_PSI: &[u8] = b"psi";
const TAG_RCM: &[u8] = b"rcm";

/// Number of bits taken from each Pallas base-field input (`rho`, `psi`).
const L_ORCHARD_BASE: usize = 255;

/// Derives `(ψ, rcm)` from the transition tuple (WP §3.3).
///
/// Hash input (BLAKE2b-512, unkeyed, 64-byte output):
///
/// `LP(T) || LP(t) || LP(action) || LP(name) || LP(ua) || LP(expires_at) || prev_rcm`
///
/// where `LP(x)` is the 4-byte little-endian length of `x` followed by `x`
/// itself. `prev_rcm` (32 bytes) is appended raw, without a length prefix.
///
/// `rcm` = `ToScalar(H_rcm(sigma))`, `psi` = `ToBase(H_psi(sigma))`.
pub fn zns_psi_rcm(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    let psi = pallas::Base::from_uniform_bytes(&tagged_zns_hash(
        TAG_PSI, action, name, ua, expires_at, prev_rcm,
    ));
    let rcm = pallas::Scalar::from_uniform_bytes(&tagged_zns_hash(
        TAG_RCM, action, name, ua, expires_at, prev_rcm,
    ));
    (psi, rcm)
}

fn tagged_zns_hash(
    field_tag: &[u8],
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    prev_rcm: &[u8; 32],
) -> [u8; 64] {
    let mut h = Params::new().hash_length(64).to_state();
    let mut absorb_with_length_prefix = |b: &[u8]| {
        h.update(&(b.len() as u32).to_le_bytes());
        h.update(b);
    };
    absorb_with_length_prefix(ZNS_DOMAIN_TAG);
    absorb_with_length_prefix(field_tag);
    absorb_with_length_prefix(action);
    absorb_with_length_prefix(name);
    absorb_with_length_prefix(ua);
    absorb_with_length_prefix(expires_at);
    h.update(prev_rcm);
    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// The extracted note commitment (`cmx`) of a Name Note (WP §3.4) -- the
/// x-coordinate of the Sinsemilla commitment to the note contents.
/// Verification recomputes `cmx` from the note's fields and compares it to
/// the value recorded on chain.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExtractedNoteCommitment(pallas::Base);

impl ExtractedNoteCommitment {
    /// Deserializes from bytes, enforcing the consensus rule that the byte
    /// representation of `cmx` MUST be canonical.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        pallas::Base::from_repr(*bytes).map(Self).into()
    }

    /// Serializes to the canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// The ρ value of a Name Note.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Rho(pallas::Base);

impl Rho {
    /// Deserializes from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        pallas::Base::from_repr(*bytes).map(Rho).into()
    }

    /// Serializes to the canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// Derives `cmx` from the note components and the ZNS opening (WP §3.4).
///
/// Returns `None` when the commitment is the identity point; such a value
/// cannot equal a real on-chain `cmx`.
pub fn note_commitment_cmx(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<ExtractedNoteCommitment> {
    let domain = sinsemilla::CommitDomain::new("z.cash:Orchard-NoteCommit");
    let value_bytes = value.to_le_bytes();
    let rho_bytes = rho.to_bytes();
    let psi_bytes = psi.to_repr();

    let bits = le_bytes_lsb0(&g_d)
        .chain(le_bytes_lsb0(&pk_d))
        .chain(le_bytes_lsb0(&value_bytes))
        .chain(le_bytes_lsb0(&rho_bytes).take(L_ORCHARD_BASE))
        .chain(le_bytes_lsb0(&psi_bytes).take(L_ORCHARD_BASE));

    Option::<pallas::Base>::from(domain.short_commit(bits, &rcm)).map(ExtractedNoteCommitment)
}

fn le_bytes_lsb0(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .copied()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp_section_3_5_golden_vector() {
        let g_d: [u8; 32] =
            hex::decode("de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_d: [u8; 32] =
            hex::decode("6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996")
                .unwrap()
                .try_into()
                .unwrap();
        let rho = Rho::from_bytes(&[0x33u8; 32]).unwrap();
        let ua = b"u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";

        let (psi, rcm) = zns_psi_rcm(b"claim", b"alice", ua, b"none", &[0u8; 32]);

        assert_eq!(
            hex::encode(psi.to_repr()),
            "9f8a61b860c737d4564f12c635d654b843bc7115d9dc6cf6f09e409c81b8d13e"
        );
        assert_eq!(
            hex::encode(rcm.to_repr()),
            "daa928be21d0ec13b5dbb0244699dbfeba546c71591d24d7824db78e4670c504"
        );

        let cmx = note_commitment_cmx(g_d, pk_d, 0, rho, psi, rcm).unwrap();
        assert_eq!(
            hex::encode(cmx.to_bytes()),
            "cc320736a0c1df1e4ffcee2b64aa73a9e6d06bb218e155a6fef422e1ecb1f70c"
        );
    }
}
