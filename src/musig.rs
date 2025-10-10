//! Cooperative key-path signing (MuSig2)

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{psbt::Psbt, sighash::TapSighashType, TxOut};
use secp256k1::musig::{AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, Session, SessionSecretRand};
use secp256k1::{Keypair, Secp256k1};

use crate::sighash::keyspend_sighash;
use crate::solver_stub::{NonceCommit, NonceReveal, PartialSig, SolverWire};
use crate::types::Result;

/// Perform MuSig2 signing for key-path spend
/// 
/// This implements the full MuSig2 protocol:
/// 1. Generate nonces
/// 2. Commit to nonces
/// 3. Reveal nonces
/// 4. Verify commitments
/// 5. Aggregate nonces
/// 6. Create partial signatures
/// 7. Verify and aggregate into final signature
/// 
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `my_keypair` - My keypair for signing
/// * `key_agg_cache` - MuSig2 key aggregation cache
/// * `psbt` - PSBT to sign
/// * `prevout` - Previous output being spent
/// * `sighash_ty` - Sighash type (e.g., All, AllPlusAnyoneCanPay)
/// * `wire` - Communication channel with the other signer(s)
/// 
/// # Returns
/// 64-byte Schnorr signature
pub async fn musig2_sign_keypath<W: SolverWire>(
    _secp: &Secp256k1<secp256k1::All>,
    my_keypair: &Keypair,
    key_agg_cache: &KeyAggCache,
    psbt: &Psbt,
    prevout: &TxOut,
    sighash_ty: TapSighashType,
    wire: &mut W,
) -> Result<[u8; 64]> {
    // 1) Compute sighash
    let msg32 = keyspend_sighash(psbt, prevout, sighash_ty)?;
    
    // 2) Generate secret nonce
    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);
    let (sec_nonce, pub_nonce) = 
        key_agg_cache.nonce_gen(session_rand, my_keypair.public_key(), &msg32, None);
    
    // 3) Commit: H(R)
    let pub_nonce_ser = pub_nonce.serialize();
    let commit_hash = sha256::Hash::hash(&pub_nonce_ser);
    let my_commit = NonceCommit(commit_hash.to_byte_array());
    wire.send_commit(my_commit.clone()).await;
    let their_commit = wire.recv_commit().await;
    
    // 4) Reveal nonces
    let my_reveal = NonceReveal(pub_nonce_ser.to_vec());
    wire.send_reveal(my_reveal.clone()).await;
    let their_reveal = wire.recv_reveal().await;
    
    // 5) Verify their commitment
    let their_commit_check = sha256::Hash::hash(&their_reveal.0);
    if their_commit_check.to_byte_array() != their_commit.0 {
        return Err("Nonce commitment mismatch".to_string());
    }
    
    // 6) Parse their public nonce (66 bytes)
    if their_reveal.0.len() != 66 {
        return Err(format!("Invalid nonce length: {}", their_reveal.0.len()));
    }
    let mut nonce_bytes = [0u8; 66];
    nonce_bytes.copy_from_slice(&their_reveal.0);
    let their_pub_nonce = PublicNonce::from_byte_array(&nonce_bytes)
        .map_err(|e| format!("Invalid nonce: {:?}", e))?;
    
    // 7) Aggregate nonces
    let agg_nonce = AggregatedNonce::new(&[&pub_nonce, &their_pub_nonce]);
    
    // 8) Create session and sign
    let session = Session::new(key_agg_cache, agg_nonce, &msg32);
    let partial_sig = session.partial_sign(sec_nonce, my_keypair, key_agg_cache);
    
    // 9) Exchange partial signatures
    let my_partial = PartialSig(partial_sig.serialize().to_vec());
    wire.send_partial(my_partial.clone()).await;
    let their_partial = wire.recv_partial().await;
    
    // 10) Parse their partial signature (32 bytes)
    if their_partial.0.len() != 32 {
        return Err(format!("Invalid partial sig length: {}", their_partial.0.len()));
    }
    let mut sig_bytes = [0u8; 32];
    sig_bytes.copy_from_slice(&their_partial.0);
    let their_partial_sig = PartialSignature::from_byte_array(&sig_bytes)
        .map_err(|e| format!("Invalid partial sig: {:?}", e))?;
    
    // 11) Aggregate signatures
    let agg_sig = session.partial_sig_agg(&[&partial_sig, &their_partial_sig]);
    
    // 12) Verify the aggregated signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &msg32)
        .map_err(|e| format!("Signature verification failed: {:?}", e))?;
    
    Ok(*final_sig.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver_stub::MockSolverWire;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute};
    use secp256k1::PublicKey;
    
    #[tokio::test]
    async fn test_musig2_sign_keypath() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();
        
        let kp1 = Keypair::new(&mut rng);
        let kp2 = Keypair::new(&mut rng);
        
        let pk1 = PublicKey::from_keypair(&kp1);
        let pk2 = PublicKey::from_keypair(&kp2);
        
        let key_agg_cache = KeyAggCache::new(&[&pk1, &pk2]);
        
        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(20000),
            script_pubkey: ScriptBuf::new(),
        };
        
        let mut wire = MockSolverWire::new(kp2.clone(), key_agg_cache.clone());
        
        let result = musig2_sign_keypath(
            &secp,
            &kp1,
            &key_agg_cache,
            &psbt,
            &prevout,
            TapSighashType::All,
            &mut wire,
        ).await;
        
        assert!(result.is_ok());
        let sig = result.unwrap();
        assert_eq!(sig.len(), 64);
    }
}


