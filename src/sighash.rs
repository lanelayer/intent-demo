//! Sighash helpers for key-path and script-path spends

use bitcoin::{
    Transaction, TxOut, psbt::Psbt,
    sighash::{SighashCache, TapSighashType, Prevouts},
    ScriptBuf, taproot::LeafVersion,
};
use bitcoin::hashes::Hash;

use crate::types::Result;

/// Compute BIP-341 key-path sighash for taproot key-spend
pub fn keyspend_sighash(
    psbt: &Psbt,
    prevout: &TxOut,
    sighash_ty: TapSighashType,
) -> Result<[u8; 32]> {
    let tx = &psbt.unsigned_tx;
    let mut cache = SighashCache::new(tx);
    
    let hash = cache
        .taproot_key_spend_signature_hash(
            0, 
            &Prevouts::All(&[prevout.clone()]), 
            sighash_ty
        )
        .map_err(|e| format!("Key-path sighash error: {}", e))?;
    
    Ok(*hash.as_byte_array())
}

/// Compute BIP-341 script-path sighash for taproot script-spend (e.g., CSV refund leaf)
pub fn scriptspend_sighash(
    tx: &Transaction,
    prevout: &TxOut,
    leaf_script: &ScriptBuf,
) -> Result<[u8; 32]> {
    use bitcoin::taproot::TapLeafHash;
    
    let mut cache = SighashCache::new(tx);
    
    // Create leaf hash
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    
    let hash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout.clone()]),
            leaf_hash,
            TapSighashType::All,
        )
        .map_err(|e| format!("Script-path sighash error: {}", e))?;
    
    Ok(*hash.as_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute};
    
    #[test]
    fn test_keyspend_sighash() {
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
        
        let sighash = keyspend_sighash(&psbt, &prevout, TapSighashType::All);
        assert!(sighash.is_ok());
        assert_eq!(sighash.unwrap().len(), 32);
    }
}

