//! Cryptographic primitives for P2TR + MuSig2
//!
//! This module provides:
//! - MuSig2 key aggregation
//! - Taproot address generation  
//! - Key tweaking for BIP-341

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{Address, Network, XOnlyPublicKey as BitcoinXOnly};
use secp256k1::musig::KeyAggCache;
use secp256k1::{PublicKey, Scalar, XOnlyPublicKey};

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

