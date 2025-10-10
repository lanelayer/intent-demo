//! Cryptographic primitives for P2TR + MuSig2
//!
//! This module provides:
//! - MuSig2 key aggregation
//! - Taproot address generation  
//! - Key tweaking for BIP-341

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{Address, Network, ScriptBuf, XOnlyPublicKey as BitcoinXOnly, taproot};
use bitcoin::opcodes::all as op;
use secp256k1::musig::KeyAggCache;
use secp256k1::{PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

use crate::types::Result;

/// Create a P2TR funding address from two x-only pubkeys
///
/// # Arguments
/// * `user_pk_bytes` - 32-byte x-only public key
/// * `solver_pk_bytes` - 32-byte x-only public key  
/// * `intent_commit` - Optional 32-byte commitment to include in taptweak
/// * `network` - Bitcoin network
///
/// # Returns
/// A P2TR address
pub fn create_funding_address(
    user_pk_bytes: &[u8],
    solver_pk_bytes: &[u8],
    intent_commit: Option<&[u8]>,
    network: Network,
) -> Result<Address> {
    if user_pk_bytes.len() != 32 {
        return Err("User pubkey must be 32 bytes".to_string());
    }
    if solver_pk_bytes.len() != 32 {
        return Err("Solver pubkey must be 32 bytes".to_string());
    }

    // Convert to secp256k1::XOnlyPublicKey
    let mut user_arr = [0u8; 32];
    user_arr.copy_from_slice(user_pk_bytes);
    let user_xonly = XOnlyPublicKey::from_byte_array(user_arr)
        .map_err(|e| format!("Invalid user pubkey: {}", e))?;
    
    let mut solver_arr = [0u8; 32];
    solver_arr.copy_from_slice(solver_pk_bytes);
    let solver_xonly = XOnlyPublicKey::from_byte_array(solver_arr)
        .map_err(|e| format!("Invalid solver pubkey: {}", e))?;

    // Convert to full public keys (even parity for taproot)
    let user_pk = PublicKey::from_x_only_public_key(user_xonly, secp256k1::Parity::Even);
    let solver_pk = PublicKey::from_x_only_public_key(solver_xonly, secp256k1::Parity::Even);

    // Aggregate keys with MuSig2
    let pubkeys = vec![&user_pk, &solver_pk];
    let key_agg_cache = KeyAggCache::new(&pubkeys);
    let agg_pk = key_agg_cache.agg_pk();

    // Apply taptweak if intent commitment provided
    let output_key = if let Some(commit) = intent_commit {
        let tweak = compute_taptweak(&agg_pk, Some(commit))?;
        let tweaked_pk = apply_tweak(&agg_pk, &tweak)?;
        tweaked_pk
    } else {
        // No commitment, just use plain taproot tweak (internal key only)
        let tweak = compute_taptweak(&agg_pk, None)?;
        let tweaked_pk = apply_tweak(&agg_pk, &tweak)?;
        tweaked_pk
    };

    // Convert to bitcoin::XOnlyPublicKey
    let btc_xonly = BitcoinXOnly::from_slice(&output_key.serialize())
        .map_err(|e| format!("Invalid output key: {}", e))?;

    // Create P2TR address
    let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(btc_xonly);
    Ok(Address::p2tr_tweaked(tweaked, network))
}

/// Compute BIP-341 taptweak: t = H_taptweak(P || c)
fn compute_taptweak(internal_key: &XOnlyPublicKey, commitment: Option<&[u8]>) -> Result<Scalar> {
    let mut eng = sha256::Hash::engine();

    // BIP-341 tagged hash
    let tag = b"TapTweak";
    let tag_hash = sha256::Hash::hash(tag);
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());

    // Add internal key
    eng.input(&internal_key.serialize());

    // Add commitment if present
    if let Some(c) = commitment {
        eng.input(c);
    }

    let hash = sha256::Hash::from_engine(eng);
    Scalar::from_be_bytes(hash.to_byte_array())
        .map_err(|_| "Invalid tweak scalar".to_string())
}

/// Apply tweak to a public key: Q = P + t*G
fn apply_tweak(pubkey: &XOnlyPublicKey, tweak: &Scalar) -> Result<XOnlyPublicKey> {
    // Convert x-only to full pubkey
    let full_pk = PublicKey::from_x_only_public_key(*pubkey, secp256k1::Parity::Even);

    // Add tweak
    let tweaked = full_pk
        .add_exp_tweak(tweak)
        .map_err(|e| format!("Tweak failed: {:?}", e))?;

    // Convert back to x-only
    let (xonly, _parity) = tweaked.x_only_public_key();
    Ok(xonly)
}

/// Aggregate public keys using MuSig2
pub fn aggregate_pubkeys(pubkeys: &[PublicKey]) -> KeyAggCache {
    let refs: Vec<&PublicKey> = pubkeys.iter().collect();
    KeyAggCache::new(&refs)
}

/// Create a CSV refund leaf script: <Δ> CSV DROP <UserXOnly> CHECKSIG
/// 
/// This allows the user to unilaterally refund after Δ blocks using only their key.
pub fn refund_leaf_script(user_x: XOnlyPublicKey, csv_delta_blocks: u32) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_int(i64::from(csv_delta_blocks))
        .push_opcode(op::OP_CSV)
        .push_opcode(op::OP_DROP)
        .push_slice(&user_x.serialize())
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

/// Taproot address with refund leaf
pub struct TrWithRefund {
    pub address: Address,
    pub output_key: XOnlyPublicKey,
    pub internal_key: XOnlyPublicKey,  // The untweaked aggregated key
    pub control_block_refund: taproot::ControlBlock,
    pub refund_leaf: taproot::TapLeafHash,
    pub refund_script: ScriptBuf,
    pub merkle_root: Option<taproot::TapNodeHash>,
}

/// Build Taproot address with key-path=P_agg (MuSig2) and one refund leaf (CSV)
/// 
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `agg_x` - Aggregated x-only public key from MuSig2
/// * `refund_script` - Script for the refund leaf (CSV)
/// * `network` - Bitcoin network
/// 
/// # Returns
/// TrWithRefund containing address and control block for script-path spend
pub fn build_tr_with_refund_leaf(
    _secp: &Secp256k1<secp256k1::All>,
    agg_x: XOnlyPublicKey,
    refund_script: ScriptBuf,
    network: Network,
) -> Result<TrWithRefund> {
    // Create taproot builder with refund leaf
    let builder = taproot::TaprootBuilder::new()
        .add_leaf(0, refund_script.clone())
        .map_err(|e| format!("Failed to add leaf: {:?}", e))?;
    
    // Convert to bitcoin XOnlyPublicKey
    let btc_xonly = BitcoinXOnly::from_slice(&agg_x.serialize())
        .map_err(|e| format!("Invalid agg key: {}", e))?;
    
    // Create a bitcoin secp256k1 context for finalize
    let btc_secp = bitcoin::secp256k1::Secp256k1::verification_only();
    
    // Finalize taproot tree
    let spend_info = builder
        .finalize(&btc_secp, btc_xonly)
        .map_err(|e| format!("Failed to finalize taproot: {:?}", e))?;
    
    let output_key_btc = spend_info.output_key();
    let address = Address::p2tr_tweaked(output_key_btc, network);
    let merkle_root = spend_info.merkle_root();
    
    // Get control block for the refund leaf
    let leaf_hash = taproot::TapLeafHash::from_script(&refund_script, taproot::LeafVersion::TapScript);
    let control_block_refund = spend_info
        .control_block(&(refund_script.clone(), taproot::LeafVersion::TapScript))
        .ok_or("Failed to get control block")?;
    
    // Convert output key back to secp256k1 XOnlyPublicKey
    let output_key_bytes: [u8; 32] = output_key_btc.to_x_only_public_key().serialize();
    let output_key = XOnlyPublicKey::from_byte_array(output_key_bytes)
        .map_err(|e| format!("Invalid output key: {:?}", e))?;
    
    Ok(TrWithRefund {
        address,
        output_key,
        internal_key: agg_x,  // Store the untweaked key
        control_block_refund,
        refund_leaf: leaf_hash,
        refund_script,
        merkle_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_create_funding_address() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();

        let kp1 = secp256k1::Keypair::new(&mut rng);
        let kp2 = secp256k1::Keypair::new(&mut rng);

        let (pk1, _) = kp1.x_only_public_key();
        let (pk2, _) = kp2.x_only_public_key();

        let addr = create_funding_address(
            &pk1.serialize(),
            &pk2.serialize(),
            None,
            Network::Testnet,
        )
        .unwrap();

        assert!(addr.to_string().starts_with("tb1p"));
    }

    #[test]
    fn test_taptweak() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();

        let kp = secp256k1::Keypair::new(&mut rng);
        let (xonly, _) = kp.x_only_public_key();

        // Without commitment
        let tweak1 = compute_taptweak(&xonly, None).unwrap();
        assert_eq!(tweak1.to_be_bytes().len(), 32);

        // With commitment
        let commit = [42u8; 32];
        let tweak2 = compute_taptweak(&xonly, Some(&commit)).unwrap();
        assert_ne!(tweak1.to_be_bytes(), tweak2.to_be_bytes());
    }
}

