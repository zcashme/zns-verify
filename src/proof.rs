//! Proof-bundle verification — the wallet-side walk.
//!
//! The contract is `zns-resolver/PROOFS.md`: a resolver serves, per name, a
//! chain of links — `(action, ua)` claims plus pure chain artifacts (the raw
//! transaction, the block header, and the Merkle branch joining them). This
//! module is the verifier: it recomputes everything the resolver asserted and
//! returns the resolution together with the `(height, block hash)` anchors.
//!
//! **PoW policy belongs to the caller.** A valid walk proves "this chain of
//! bindings is internally valid and committed under these headers" — whether
//! those headers sit in the canonical Zcash chain is the wallet's question
//! (match them against its own synced headers, ask its node, or check work
//! directly). Across several resolvers, take the longest valid chain
//! (`DESIGN.md §19.4`): a stale answer is a provable prefix; a forged one
//! fails here.

use group::ff::PrimeField;
use pasta_curves::pallas;
use sha2::{Digest, Sha256};
use zcash_primitives::block::BlockHeader;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

use crate::{
    action::Action,
    chain::{prev_rcm_for, Tip},
    commit::note_commitment_cmx,
    hash::zns_psi_rcm,
};

/// One link of a name's proof chain, as served by a resolver.
///
/// `action` and `ua` are the resolver's only *claims*; they need no separate
/// authentication because the walk hashes them — wrong claims produce a wrong
/// `rcm`, hence a commitment mismatch. Everything else is chain artifact the
/// walk recomputes or checks.
#[derive(Debug, Clone)]
pub struct ProofLink {
    /// The claimed lifecycle action.
    pub action: Action,
    /// The claimed binding target (empty for RELEASE).
    pub ua: String,
    /// The block height the Name Note was mined at.
    pub height: u32,
    /// Which Orchard action in the transaction is the Name Note.
    pub action_index: usize,
    /// The full raw transaction (its ZIP-244 txid is recomputed on parse).
    pub tx: Vec<u8>,
    /// The raw block header (Merkle root + the PoW anchor).
    pub header: Vec<u8>,
    /// The Merkle branch from the txid up to the header's root.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The transaction's leaf position in the block's Merkle tree.
    pub merkle_index: u32,
}

/// A PoW anchor the walk verified a link under. The caller decides whether
/// this block hash sits in the chain it trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// The link's block height.
    pub height: u32,
    /// The block's hash (the double-SHA256 of the verified header).
    pub block_hash: [u8; 32],
}

/// A verified resolution: what the chain says the name's tip is, and the
/// headers that statement is anchored under.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// The tip link's action.
    pub tip_action: Action,
    /// The resolved UA — `None` when the tip is a RELEASE (the name is free).
    pub ua: Option<String>,
    /// One anchor per link, in chain order.
    pub anchors: Vec<Anchor>,
}

/// Why a proof chain failed verification. Each variant carries the index of
/// the offending link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The chain has no links.
    Empty,
    /// The link's action does not fit the chain state (`DESIGN.md §5`) —
    /// e.g. a non-CLAIM first link, or an UPDATE after a RELEASE.
    ChainBreak(usize),
    /// The block header bytes failed to parse.
    HeaderParse(usize),
    /// The raw transaction failed to parse under the height's consensus
    /// branch.
    TxParse(usize),
    /// The Merkle branch does not join the txid to the header's root.
    MerkleMismatch(usize),
    /// The transaction has no Orchard bundle.
    NoOrchardBundle(usize),
    /// `action_index` is out of range for the transaction's Orchard bundle.
    ActionIndex(usize),
    /// The action's `nf` is not a valid Pallas base element (corrupt tx).
    BadRho(usize),
    /// The action's `cmx` is not a valid Pallas base element (corrupt tx).
    BadCmx(usize),
    /// The recomputed commitment does not match the on-chain `cmx` — the
    /// claimed `(action, ua)` is not what this Name Note binds.
    BindingMismatch(usize),
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProofError::Empty => write!(f, "proof chain is empty"),
            ProofError::ChainBreak(i) => write!(f, "link {i}: action does not fit chain state"),
            ProofError::HeaderParse(i) => write!(f, "link {i}: block header failed to parse"),
            ProofError::TxParse(i) => write!(f, "link {i}: transaction failed to parse"),
            ProofError::MerkleMismatch(i) => {
                write!(f, "link {i}: Merkle branch does not reach the header root")
            }
            ProofError::NoOrchardBundle(i) => write!(f, "link {i}: no Orchard bundle"),
            ProofError::ActionIndex(i) => write!(f, "link {i}: action index out of range"),
            ProofError::BadRho(i) => write!(f, "link {i}: invalid nullifier encoding"),
            ProofError::BadCmx(i) => write!(f, "link {i}: invalid cmx encoding"),
            ProofError::BindingMismatch(i) => {
                write!(f, "link {i}: recomputed commitment does not match on-chain cmx")
            }
        }
    }
}

impl std::error::Error for ProofError {}

/// Verify a name's proof chain, genesis → tip.
///
/// `(g_d, pk_d)` and `value` are the registry's published spec constants
/// (`PROOFS.md §4`) — supplied by the caller's configuration, never by the
/// resolver. On success the caller must still check the returned
/// [`Anchor`]s against a header chain it trusts.
pub fn verify_chain(
    network: &impl Parameters,
    name: &str,
    links: &[ProofLink],
    g_d: [u8; 32],
    pk_d: [u8; 32],
    value: u64,
) -> Result<Resolution, ProofError> {
    if links.is_empty() {
        return Err(ProofError::Empty);
    }

    let mut tip: Option<Tip> = None;
    let mut anchors = Vec::with_capacity(links.len());
    for (i, link) in links.iter().enumerate() {
        // §5 fold rule: which prev_rcm this link must extend.
        let prev_rcm = prev_rcm_for(tip.as_ref(), link.action).ok_or(ProofError::ChainBreak(i))?;

        // Chain context: header, tx (parsing recomputes the ZIP-244 txid),
        // and the Merkle branch joining them.
        let header =
            BlockHeader::read(&link.header[..]).map_err(|_| ProofError::HeaderParse(i))?;
        let branch_id = BranchId::for_height(network, BlockHeight::from_u32(link.height));
        let tx =
            Transaction::read(&link.tx[..], branch_id).map_err(|_| ProofError::TxParse(i))?;
        let txid: [u8; 32] = *tx.txid().as_ref();
        if merkle_fold(txid, &link.merkle_branch, link.merkle_index) != header.merkle_root {
            return Err(ProofError::MerkleMismatch(i));
        }

        // The Name Note's action: its nf is the output note's ρ (the circuit
        // constrains ρ_new = nf_old within an action), its cmx the commitment.
        let bundle = tx.orchard_bundle().ok_or(ProofError::NoOrchardBundle(i))?;
        let action = bundle.actions().get(link.action_index).ok_or(ProofError::ActionIndex(i))?;
        let rho = pallas::Base::from_repr(action.nullifier().to_bytes())
            .into_option()
            .ok_or(ProofError::BadRho(i))?;
        let cmx = pallas::Base::from_repr(action.cmx().to_bytes())
            .into_option()
            .ok_or(ProofError::BadCmx(i))?;

        // The binding: re-derive (ψ, rcm) from the claims and recompute the
        // commitment. A match authenticates the claims and advances the tip.
        let (psi, rcm) =
            zns_psi_rcm(link.action.as_bytes(), name.as_bytes(), link.ua.as_bytes(), &prev_rcm);
        if note_commitment_cmx(g_d, pk_d, value, rho, psi, rcm) != Some(cmx) {
            return Err(ProofError::BindingMismatch(i));
        }

        tip = Some(Tip { action: link.action, rcm: rcm.to_repr() });
        anchors.push(Anchor { height: link.height, block_hash: header.hash().0 });
    }

    let last = links.last().expect("non-empty");
    Ok(Resolution {
        tip_action: last.action,
        ua: (last.action != Action::Release).then(|| last.ua.clone()),
        anchors,
    })
}

/// Fold a txid up a Merkle branch (Bitcoin-style double-SHA256 pairs;
/// `index` selects each level's left/right orientation). Returns the implied
/// root. An empty branch means a single-tx block: leaf == root.
pub fn merkle_fold(leaf: [u8; 32], branch: &[[u8; 32]], index: u32) -> [u8; 32] {
    let mut cur = leaf;
    let mut idx = index;
    for sibling in branch {
        cur = if idx & 1 == 1 { sha256d(sibling, &cur) } else { sha256d(&cur, sibling) };
        idx >>= 1;
    }
    cur
}

fn sha256d(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let first = Sha256::new().chain_update(left).chain_update(right).finalize();
    Sha256::digest(first).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_fold_single_tx_block() {
        // A one-tx block: the txid is the root.
        let leaf = [7u8; 32];
        assert_eq!(merkle_fold(leaf, &[], 0), leaf);
    }

    #[test]
    fn merkle_fold_orientation() {
        // Two leaves: leaf 0 hashes (self, sibling); leaf 1 hashes
        // (sibling, self). Both must reach the same root.
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let root = sha256d(&a, &b);
        assert_eq!(merkle_fold(a, &[b], 0), root);
        assert_eq!(merkle_fold(b, &[a], 1), root);
        // Wrong orientation must not.
        assert_ne!(merkle_fold(b, &[a], 0), root);
    }

    #[test]
    fn empty_chain_rejects() {
        let net = zcash_protocol::consensus::Network::TestNetwork;
        let err = verify_chain(&net, "alice", &[], [0; 32], [0; 32], 0);
        assert_eq!(err.unwrap_err(), ProofError::Empty);
    }

    #[test]
    fn first_link_must_be_claim() {
        let link = ProofLink {
            action: Action::Update,
            ua: "u1xxx".into(),
            height: 100,
            action_index: 0,
            tx: vec![],
            header: vec![],
            merkle_branch: vec![],
            merkle_index: 0,
        };
        let net = zcash_protocol::consensus::Network::TestNetwork;
        let err = verify_chain(&net, "alice", &[link], [0; 32], [0; 32], 0);
        assert_eq!(err.unwrap_err(), ProofError::ChainBreak(0));
    }
}
