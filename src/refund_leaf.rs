//! Unilateral refund signer (script-path via CSV leaf)

use bitcoin::{Transaction, TxOut, ScriptBuf, Witness, taproot::ControlBlock};
use secp256k1::{Keypair, Secp256k1};

use crate::sighash::scriptspend_sighash;
use crate::types::Result;

/// Sign refund leaf with user's key (script-path, CSV)
/// 
/// This produces a Schnorr signature for the refund leaf script-path spend.
/// The user can broadcast this unilaterally after the CSV delay expires.
/// 
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `user_kp` - User's keypair
/// * `tx` - Unsigned refund transaction (with nSequence = csv_delta)
/// * `prevout` - Previous output being spent
/// * `refund_leaf_script` - The CSV refund script
/// 
/// # Returns
/// 64-byte Schnorr signature
pub fn sign_refund_leaf(
    _secp: &Secp256k1<secp256k1::All>,
    user_kp: &Keypair,
    tx: &Transaction,
    prevout: &TxOut,
    refund_leaf_script: &ScriptBuf,
) -> Result<[u8; 64]> {
    let sighash = scriptspend_sighash(tx, prevout, refund_leaf_script)?;
    
    // Sign using the Keypair's built-in Schnorr signing
    // The git version of secp256k1 has sign_schnorr on the Keypair directly
    let sig = user_kp.sign_schnorr(&sighash);
    
    // Convert signature to 64 bytes
    Ok(*sig.as_ref())
}

/// Attach witness for script-path spend: <sig> <leaf_script> <control_block>
/// 
/// This finalizes the refund transaction with the signature, script, and control block.
/// 
/// # Arguments
/// * `tx` - Unsigned transaction
/// * `sig64` - 64-byte Schnorr signature
/// * `leaf_script` - The refund script
/// * `control` - Control block proving the leaf is in the taproot tree
/// 
/// # Returns
/// Fully signed transaction ready to broadcast
pub fn attach_refund_witness(
    mut tx: Transaction,
    sig64: [u8; 64],
    leaf_script: ScriptBuf,
    control: ControlBlock,
) -> Transaction {
    let mut w = Witness::new();
    w.push(&sig64);
    w.push(leaf_script.as_bytes());
    w.push(&control.serialize());
    tx.input[0].witness = w;
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, absolute};
    use secp256k1::Secp256k1;
    use crate::crypto::{refund_leaf_script, build_tr_with_refund_leaf, aggregate_pubkeys};
    use secp256k1::PublicKey;
    
    #[test]
    fn test_sign_refund_leaf() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();
        
        let user_kp = Keypair::new(&mut rng);
        let solver_kp = Keypair::new(&mut rng);
        
        let (user_x, _) = user_kp.x_only_public_key();
        let (solver_x, _) = solver_kp.x_only_public_key();
        
        // Aggregate keys
        let user_pk = PublicKey::from_keypair(&user_kp);
        let solver_pk = PublicKey::from_keypair(&solver_kp);
        let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
        let agg_x = key_agg_cache.agg_pk();
        
        // Create refund script
        let csv_delta = 144;
        let refund_script = refund_leaf_script(user_x, csv_delta);
        
        // Build taproot address
        let tr = build_tr_with_refund_leaf(
            &secp,
            agg_x,
            refund_script.clone(),
            bitcoin::Network::Regtest,
        ).unwrap();
        
        // Create refund transaction
        let funding = OutPoint::default();
        let funding_value = Amount::from_sat(20000);
        
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(csv_delta),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(19000),
                script_pubkey: tr.address.script_pubkey(),
            }],
        };
        
        let prevout = TxOut {
            value: funding_value,
            script_pubkey: tr.address.script_pubkey(),
        };
        
        // Sign
        let sig = sign_refund_leaf(&secp, &user_kp, &tx, &prevout, &refund_script);
        assert!(sig.is_ok());
        assert_eq!(sig.unwrap().len(), 64);
    }
    
    #[test]
    fn test_attach_refund_witness() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();
        
        let user_kp = Keypair::new(&mut rng);
        let solver_kp = Keypair::new(&mut rng);
        
        let (user_x, _) = user_kp.x_only_public_key();
        let (solver_x, _) = solver_kp.x_only_public_key();
        
        let user_pk = PublicKey::from_keypair(&user_kp);
        let solver_pk = PublicKey::from_keypair(&solver_kp);
        let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
        let agg_x = key_agg_cache.agg_pk();
        
        let csv_delta = 144;
        let refund_script = refund_leaf_script(user_x, csv_delta);
        
        let tr = build_tr_with_refund_leaf(
            &secp,
            agg_x,
            refund_script.clone(),
            bitcoin::Network::Regtest,
        ).unwrap();
        
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(csv_delta),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(19000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        
        let sig = [0xAB; 64]; // Dummy sig
        let tx_with_witness = attach_refund_witness(
            tx,
            sig,
            refund_script,
            tr.control_block_refund,
        );
        
        assert_eq!(tx_with_witness.input[0].witness.len(), 3);
    }
}

