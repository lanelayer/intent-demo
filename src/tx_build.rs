//! Transaction builders for payout, burn, and refund

use bitcoin::{
    absolute, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, opcodes::all as op,
};
use bitcoin::psbt::Psbt;
use secp256k1::{PublicKey, XOnlyPublicKey};
use secp256k1::musig::KeyAggCache;

use crate::crypto::{aggregate_pubkeys, create_funding_address};
use crate::types::Result;

// ---------- Funding address ----------

pub struct FundingAddress {
    pub address: Address,
    pub agg_pk: XOnlyPublicKey,
    pub key_agg_cache: KeyAggCache,
}

pub fn build_funding_address(
    user_x: &XOnlyPublicKey,
    solver_x: &XOnlyPublicKey,
    intent_commit_opt: Option<&[u8; 32]>,
    network: Network,
) -> Result<FundingAddress> {
    // Convert to full public keys
    let user_pk = PublicKey::from_x_only_public_key(*user_x, secp256k1::Parity::Even);
    let solver_pk = PublicKey::from_x_only_public_key(*solver_x, secp256k1::Parity::Even);

    // Aggregate keys
    let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_pk = key_agg_cache.agg_pk();

    // Build address
    let address = create_funding_address(
        &user_x.serialize(),
        &solver_x.serialize(),
        intent_commit_opt.map(|x| x.as_slice()),
        network,
    )?;

    Ok(FundingAddress {
        address,
        agg_pk,
        key_agg_cache,
    })
}

// ---------- Helpers ----------

fn op_return(payload: &[u8]) -> ScriptBuf {
    // Build OP_RETURN script with payload
    use bitcoin::script::PushBytesBuf;
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(payload).expect("push bytes");
    
    bitcoin::script::Builder::new()
        .push_opcode(op::OP_RETURN)
        .push_slice(push_bytes)
        .into_script()
}

// ---------- Cooperative payout (key-path) ----------

pub fn build_payout_psbt(
    funding_outpoint: OutPoint,
    funding_value: Amount,
    payout_spk: ScriptBuf,
    payout_value: Amount,
) -> Result<Psbt> {
    let txin = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let txout = TxOut {
        value: payout_value,
        script_pubkey: payout_spk,
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {}", e))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_value,
        script_pubkey: ScriptBuf::new(),
    });

    Ok(psbt)
}

// ---------- Burn (key-path, optional after funding) ----------

/// Build a proper burn transaction with:
/// 1. P2WSH output (actual burn amount - provably unspendable)
/// 2. OP_RETURN output (0 value, BTI1 metadata)
pub fn build_burn_psbt(
    funding_outpoint: OutPoint,
    funding_value: Amount,
    burn_amount: Amount,
    opret_payload: &[u8],
    network: Network,
) -> Result<Psbt> {
    // 1 input (Taproot key spend), 2 outputs (P2WSH burn + OP_RETURN metadata)
    let txin = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    // Create P2WSH burn output: hash the OP_RETURN script itself
    // This creates an address that requires the preimage of the OP_RETURN script
    // Since OP_RETURN scripts are provably unspendable, the P2WSH is also provably unspendable
    let burn_script = op_return(opret_payload);
    let p2wsh_address = Address::p2wsh(&burn_script, network);
    
    let burn_output = TxOut {
        value: burn_amount,
        script_pubkey: p2wsh_address.script_pubkey(),
    };

    // OP_RETURN metadata output (0 value)
    let opret_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: burn_script,
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![burn_output, opret_output],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {}", e))?;

    // Record previous txout for sighash
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_value,
        script_pubkey: ScriptBuf::new(), // Placeholder; actual script doesn't matter for key-path
    });

    Ok(psbt)
}

// ---------- Unilateral refund (script-path, CSV) ----------

/// Build unilateral refund transaction (script-path; CSV)
/// 
/// This transaction uses the CSV refund leaf, so nSequence MUST be set to csv_delta (BIP-68).
/// The user can sign and broadcast this unilaterally after Δ blocks.
/// 
/// # Arguments
/// * `funding` - Funding outpoint
/// * `funding_value` - Funding amount
/// * `csv_delta` - CSV delay in blocks
/// * `refund_spk` - Script pubkey to send refund to (user's address)
/// * `refund_value` - Refund amount (funding_value - fees)
/// 
/// # Returns
/// Unsigned transaction ready for script-path signing
pub fn build_unilateral_refund_tx(
    funding: OutPoint,
    _funding_value: Amount,
    csv_delta: u32,
    refund_spk: ScriptBuf,
    refund_value: Amount,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(csv_delta), // BIP-68: CSV requires nSequence = delta
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: refund_value,
            script_pubkey: refund_spk,
        }],
    }
}

// ---------- Signature attachment ----------

/// Attach Schnorr sig (key-path) into PSBT's first input (finalize witness)
pub fn attach_keyspend_sig(mut psbt: Psbt, sig64: [u8; 64]) -> Psbt {
    // For key-path spend, witness is [sig64]
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[&sig64]));
    psbt
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use secp256k1::Secp256k1;
    use secp256k1::Keypair;

    #[test]
    fn test_build_funding_address() {
        let _secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();

        let kp1 = Keypair::new(&mut rng);
        let kp2 = Keypair::new(&mut rng);

        let (pk1, _) = kp1.x_only_public_key();
        let (pk2, _) = kp2.x_only_public_key();

        let funding = build_funding_address(&pk1, &pk2, None, Network::Regtest).unwrap();
        assert!(funding.address.to_string().starts_with("bcrt1p"));
    }

    #[test]
    fn test_build_burn_psbt() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let psbt = build_burn_psbt(
            outpoint,
            Amount::from_sat(20_000),
            Amount::from_sat(19_000),
            b"BTI1\x00\x00\x00\x01deadbeefdeadbeefdeadbeef",
            Network::Regtest,
        ).unwrap();
        
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 2); // P2WSH + OP_RETURN
        
        // First output should be P2WSH (burn)
        assert!(psbt.unsigned_tx.output[0].script_pubkey.is_p2wsh());
        assert_eq!(psbt.unsigned_tx.output[0].value, Amount::from_sat(19_000));
        
        // Second output should be OP_RETURN (metadata)
        assert!(psbt.unsigned_tx.output[1].script_pubkey.is_op_return());
        assert_eq!(psbt.unsigned_tx.output[1].value, Amount::ZERO);
    }

    #[test]
    fn test_build_payout_psbt() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let spk = ScriptBuf::new();
        let psbt =
            build_payout_psbt(outpoint, Amount::from_sat(20_000), spk, Amount::from_sat(18_000))
                .unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
    }
    
    #[test]
    fn test_build_unilateral_refund_tx() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        
        let csv_delta = 144;
        let tx = build_unilateral_refund_tx(
            outpoint,
            Amount::from_sat(20_000),
            csv_delta,
            ScriptBuf::new(),
            Amount::from_sat(19_000),
        );
        
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.input[0].sequence.0, csv_delta);
    }
}

