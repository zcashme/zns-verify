//! The ZNS commitment derivation: (ψ, rcm) from the binding tuple (WP §3.3),
//! and the Sinsemilla note commitment (WP §3.4).

use blake2b_simd::Params;
use group::ff::{FromUniformBytes, PrimeField};
use group::{Curve, Group, GroupEncoding};
use halo2_poseidon::{ConstantLength, P128Pow5T3};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
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
    note_commitment(g_d, pk_d, value, rho, psi, rcm)
        .map(|cm| ExtractedNoteCommitment(extract_p(&cm)))
}

/// The Sinsemilla note commitment point itself (Protocol Spec §5.4.8.4).
/// `cmx` is its x-coordinate; the nullifier needs the whole point.
fn note_commitment(
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<pallas::Point> {
    let domain = sinsemilla::CommitDomain::new("z.cash:Orchard-NoteCommit");
    let value_bytes = value.to_le_bytes();
    let rho_bytes = rho.to_bytes();
    let psi_bytes = psi.to_repr();

    let bits = le_bytes_lsb0(&g_d)
        .chain(le_bytes_lsb0(&pk_d))
        .chain(le_bytes_lsb0(&value_bytes))
        .chain(le_bytes_lsb0(&rho_bytes).take(L_ORCHARD_BASE))
        .chain(le_bytes_lsb0(&psi_bytes).take(L_ORCHARD_BASE));

    let cm = Option::<pallas::Point>::from(domain.commit(bits, &rcm))?;
    // The identity has no x-coordinate, so it can never be an on-chain cmx.
    (!bool::from(cm.is_identity())).then_some(cm)
}

/// `g_d` for a diversifier (Protocol Spec §5.4.1.6, `DiversifyHash`): the
/// base point every address with that diversifier shares. If the hash lands
/// on the identity the spec substitutes the hash of the empty string.
pub fn diversify_hash(diversifier: &[u8; 11]) -> [u8; 32] {
    let hash = pallas::Point::hash_to_curve("z.cash:Orchard-gd");
    let g_d = hash(diversifier);
    if bool::from(g_d.is_identity()) {
        hash(&[]).to_bytes()
    } else {
        g_d.to_bytes()
    }
}

/// The nullifier a Name Note reveals when the Registry spends it (Protocol
/// Spec §4.16, `DeriveNullifier`, with the ZNS opening in place of the
/// rseed-derived one):
///
/// `nf = ExtractP([PRF^nfOrchard_nk(ρ) + ψ mod r] K + cm)`
///
/// `nk` is the nullifier deriving key, bytes 32..64 of the raw Orchard full
/// viewing key encoding (§5.6.4.4). `cm` is the commitment the other inputs
/// open, so `psi` and `rcm` are the pair [`crate::verify_name_note_with_witness`]
/// returns. Store the result as the name's tip nullifier and hand it to
/// [`crate::authorized_transition`] when the next transition arrives.
///
/// Returns `None` when `nk` is not a canonical field element or the
/// commitment is the identity point.
pub fn name_note_nullifier(
    nk: &[u8; 32],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    rho: Rho,
    psi: pallas::Base,
    rcm: pallas::Scalar,
) -> Option<[u8; 32]> {
    let nk = Option::<pallas::Base>::from(pallas::Base::from_repr(*nk))?;
    let cm = note_commitment(g_d, pk_d, value, rho, psi, rcm)?;
    let prf_nf =
        halo2_poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([nk, rho.0]);
    // Base field elements are below the scalar modulus, so this always parses.
    let scalar =
        Option::<pallas::Scalar>::from(pallas::Scalar::from_repr((prf_nf + psi).to_repr()))?;
    let k = pallas::Point::hash_to_curve("z.cash:Orchard")(b"K");
    Some(extract_p(&(k * scalar + cm)).to_repr())
}

/// `ExtractP` (Protocol Spec §5.4.9.7): the x-coordinate, or zero for the
/// identity.
fn extract_p(point: &pallas::Point) -> pallas::Base {
    point
        .to_affine()
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or(pallas::Base::zero())
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
