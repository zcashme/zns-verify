//! A bound Name Note's commitment: its rseed from its record
//! ([`name_note_rseed`]), ψ and rcm from that rseed as for any Ironwood note
//! ([`psi_from_rseed`], [`rcm_from_rseed`]), and the Sinsemilla note
//! commitment over them (WP §3.4).

use blake2b_simd::Params;
use group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;

/// Number of bits taken from each Pallas base-field input (`rho`, `psi`).
const L_ORCHARD_BASE: usize = 255;

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

/// The binding domain of a bound Name Note's rseed: its BLAKE2b
/// personalization (zcashme/zns-mint#480).
pub const NAME_NOTE_PERSONALIZATION: &[u8; 16] = b"ZNS___Name_Notes";

/// The record kind of every Name Note.
pub const NAME_NOTE_KIND: u8 = 0x01;

/// Derives a bound Name Note's rseed from its record (bound-notes draft ZIP):
/// BLAKE2b-256, personalization [`NAME_NOTE_PERSONALIZATION`], over
/// `kind ‖ I2LEOSP64(len(fields)) ‖ fields ‖ prev`.
///
/// `fields` is the memo text between `ZNS:` and the predecessor:
/// `action:name:ua:expires_at`, then `:terms` when `terms` is non-empty.
/// An empty `terms` is a claim, update, release, sale, or delist. `prev` is
/// the predecessor's cmx, or all zero for a claim.
pub fn name_note_rseed(
    action: &[u8],
    name: &[u8],
    ua: &[u8],
    expires_at: &[u8],
    terms: &[&[u8]],
    prev: &[u8; 32],
) -> [u8; 32] {
    let mut fields_len = action.len() + name.len() + ua.len() + expires_at.len() + 3;
    for term in terms {
        fields_len += 1 + term.len();
    }
    let mut h = Params::new()
        .hash_length(32)
        .personal(NAME_NOTE_PERSONALIZATION)
        .to_state();
    h.update(&[NAME_NOTE_KIND]);
    h.update(&(fields_len as u64).to_le_bytes());
    h.update(action);
    h.update(b":");
    h.update(name);
    h.update(b":");
    h.update(ua);
    h.update(b":");
    h.update(expires_at);
    for term in terms {
        h.update(b":");
        h.update(term);
    }
    h.update(prev);
    h.finalize()
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output is 32 bytes")
}

/// `PRF^expand` personalization.
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// `PRF^expand` domain separator for ψ (`PrfExpand::PSI`).
const PRF_EXPAND_PSI: u8 = 0x09;

/// `PRF^expand` domain separator for an Ironwood note's rcm ([ZIP 2005]).
///
/// [ZIP 2005]: https://zips.z.cash/zip-2005
const PRF_EXPAND_RCM_IRONWOOD: u8 = 0x0B;

/// Derives an Ironwood note's ψ from its `rseed`:
/// $\psi = \mathsf{ToBase}^\mathsf{Orchard}(\mathsf{PRF}^\mathsf{expand}_\mathsf{rseed}([\mathtt{0x09}] \| \underline{\rho}))$.
///
/// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
///
/// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
pub fn psi_from_rseed(rseed: &[u8; 32], rho: Rho) -> pallas::Base {
    to_base(&prf_expand(rseed, PRF_EXPAND_PSI, &[&rho.to_bytes()]))
}

/// Derives an Ironwood note's rcm from its `rseed`, for note plaintext lead
/// byte `0x03`:
///
/// $$
/// \mathsf{pre}_\mathsf{rcm} = [\mathtt{0x0B}] \| \mathsf{g}^\star_\mathsf{d} \| \mathsf{pk}^\star_\mathsf{d}
/// \| \mathsf{I2LEOSP}_{64}(\mathsf{v}) \| \underline{\rho} \| \mathsf{I2LEOSP}_{256}(\psi)
/// $$
///
/// $$
/// \mathsf{rcm} = \mathsf{ToScalar}^\mathsf{Orchard}(\mathsf{PRF}^\mathsf{expand}_\mathsf{rseed}(\mathsf{pre}_\mathsf{rcm}))
/// $$
///
/// Defined in [ZIP 2005].
///
/// [ZIP 2005]: https://zips.z.cash/zip-2005
pub fn rcm_from_rseed(
    rseed: &[u8; 32],
    rho: Rho,
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
    psi: pallas::Base,
) -> pallas::Scalar {
    to_scalar(&prf_expand(
        rseed,
        PRF_EXPAND_RCM_IRONWOOD,
        &[
            // g_d: LEBS2OSP_256(repr_P(g_d)), compressed Pallas point (32 bytes)
            &g_d,
            // pk_d: LEBS2OSP_256(repr_P(pk_d)), compressed Pallas point (32 bytes)
            &pk_d,
            // v: I2LEOSP_64(v), unsigned 64-bit little-endian (8 bytes)
            &value.to_le_bytes(),
            // rho: Pallas base field canonical repr (32 bytes)
            &rho.to_bytes(),
            // psi: Pallas base field canonical repr (32 bytes)
            &psi.to_repr(),
        ],
    ))
}

/// $\mathsf{PRF}^\mathsf{expand}(sk, dst, a, b, ...) := \mathsf{BLAKE2b\text{-}512}(\texttt{"Zcash\_ExpandSeed"}, sk \| dst \| a \| b \| ...)$
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/protocol.pdf#concreteprfs
fn prf_expand(sk: &[u8; 32], dst: u8, ts: &[&[u8]]) -> [u8; 64] {
    let mut h = Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    h.update(&[dst]);
    for t in ts {
        h.update(t);
    }
    *h.finalize().as_array()
}

/// $\mathsf{ToBase}^\mathsf{Orchard}(x) := LEOS2IP_{\ell_\mathsf{PRFexpand}}(x) \pmod{q_P}$
///
/// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
fn to_base(x: &[u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(x)
}

/// $\mathsf{ToScalar}^\mathsf{Orchard}(x) := LEOS2IP_{\ell_\mathsf{PRFexpand}}(x) \pmod{r_P}$
///
/// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
fn to_scalar(x: &[u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(x)
}

fn le_bytes_lsb0(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .copied()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 != 0))
}
