//! Trial decryption for Name Notes

use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey as OrchardPreparedIvk, Scope},
    note_encryption::{CompactAction, ZnsIronwoodDomain},
    Action,
};
use zcash_protocol::memo::MemoBytes;

/// Compact-block trial decryption; the caller validates after fetching the full tx.
pub fn try_compact_ironwood(
    fvk: &FullViewingKey,
    action: &CompactAction,
) -> Option<(orchard::Note, orchard::Address)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    ZnsIronwoodDomain::for_compact_action(action).try_decrypt_compact(action, &ivk)
}

/// Full-transaction trial decryption returning the memo; validate with [`crate::verify_name_note`].
pub fn try_decrypt_ironwood<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let ivk = OrchardPreparedIvk::new(&fvk.to_ivk(Scope::External));
    let (note, recipient, memo) =
        ZnsIronwoodDomain::for_action(action).try_decrypt(action, &ivk, |_, _, _| 1u8.into())?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).ok()?))
}

/// Outgoing recovery via the FVK's OVK proving the note was created by this account.
pub fn try_decrypt_ironwood_sent<A>(
    action: &Action<A>,
    fvk: &FullViewingKey,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let ovk = fvk.to_ovk(Scope::External);
    let (note, recipient, memo) =
        ZnsIronwoodDomain::for_action(action).try_decrypt_sent(action, &ovk)?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).ok()?))
}
