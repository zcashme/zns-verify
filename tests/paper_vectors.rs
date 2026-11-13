//! The whitepaper's conformance vectors: the claim of WP §4.6 and the
//! listing of WP §4.7, which spends that claim.
//!
//! Both notes go to the same Name Note address (`G_D`, `PK_D`) with
//! rho = [0x33; 32] and value = 0.

use zns_verify::{
    name_note_rseed, note_commitment_cmx, psi_from_rseed, rcm_from_rseed, verify_bound_name_note,
    ExtractedNoteCommitment, Memo, NameNote, PrimeField, Rho,
};

const G_D: &str = "de4338f2ab9fd8300a3a1c20dd690ce27026c6001c295d7c641a067ce809b11e";
const PK_D: &str = "6df609f5710f3b5deecd4ee4b8f0173b44af6cf8918ac00269526031ba628996";
const UA: &str =
    "u1897y9pzw3zk6n9twtzu2z5kpkzw3hms2c54fpyv8lnr79m73tazljkk3veaxrtwncp66lf45p3f274xy2amqckx0sraje4v835yw8q0q";
const PAY_TO: &str = "t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKcQB";

const CLAIM_RSEED: &str = "5bcb6b8f30d7f8cd75f253b738c6fb034841e31c70d137373f3b36b0c595e56d";
const CLAIM_PSI: &str = "b174aa83656d538b12d561e9048352bbd8bf1b66fe8d396977b4b597b962f70d";
const CLAIM_RCM: &str = "19cb8bab986250c69207bb4cc005f9944f913c635d543ed3323fcd5f1b7b8d1e";
const CLAIM_CMX: &str = "617b189869560cdd3928456693c1d4060752f18173425294141641e4b05d0f1a";

const LIST_RSEED: &str = "5e9eb93343116f23cc562503dba988a91530d90f3be17edd4c9d595fe3b78abb";
const LIST_CMX: &str = "0f881dc3a96b71d5abe7958a20747c7e177d5758090bddc0f63315b41719543e";

fn bytes32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn rho() -> Rho {
    Rho::from_bytes(&[0x33u8; 32]).unwrap()
}

#[test]
fn the_claim_of_section_4_6() {
    let (g_d, pk_d) = (bytes32(G_D), bytes32(PK_D));
    let text = format!("ZNS:claim:alice:{UA}:none:{}", "0".repeat(64));
    let memo = Memo::from_bytes(text.as_bytes()).unwrap();
    let note = NameNote::parse(&memo).unwrap();

    let fields = memo.fields().unwrap();
    assert_eq!(fields.len(), 123);
    let rseed = name_note_rseed(fields, &[0u8; 32]);
    assert_eq!(hex::encode(rseed), CLAIM_RSEED);
    let psi = psi_from_rseed(&rseed, rho());
    assert_eq!(hex::encode(psi.to_repr()), CLAIM_PSI);
    let rcm = rcm_from_rseed(&rseed, rho(), g_d, pk_d, 0, psi);
    assert_eq!(hex::encode(rcm.to_repr()), CLAIM_RCM);
    let cmx = note_commitment_cmx(g_d, pk_d, 0, rho(), psi, rcm).unwrap();
    assert_eq!(hex::encode(cmx.to_bytes()), CLAIM_CMX);

    assert!(verify_bound_name_note(&note, g_d, pk_d, 0, rho(), cmx));
}

#[test]
fn the_listing_of_section_4_7() {
    let (g_d, pk_d) = (bytes32(G_D), bytes32(PK_D));
    let text = format!("ZNS:list:alice:{UA}:none:{PAY_TO}:1.5:{CLAIM_CMX}");
    let memo = Memo::from_bytes(text.as_bytes()).unwrap();
    let note = NameNote::parse(&memo).unwrap();

    let fields = memo.fields().unwrap();
    assert_eq!(fields.len(), 162);
    let rseed = name_note_rseed(fields, &bytes32(CLAIM_CMX));
    assert_eq!(hex::encode(rseed), LIST_RSEED);

    let cmx = ExtractedNoteCommitment::from_bytes(&bytes32(LIST_CMX)).unwrap();
    assert!(verify_bound_name_note(&note, g_d, pk_d, 0, rho(), cmx));
}
