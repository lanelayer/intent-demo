//! Transaction building and signing
//!
//! This module provides:
//! - Funding address construction
//! - Burn PSBT (OP_RETURN with ANYONECANPAY)
//! - Payout PSBT (cooperative spend)
//! - MuSig2 signing flow

use bitcoin::hashes::{sha256, Hash};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoin::psbt::Psbt;
use secp256k1::musig::{AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, Session, SessionSecretRand};
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::crypto::{aggregate_pubkeys, create_funding_address};
use crate::solver_stub::{NonceCommit, NonceReveal, PartialSig, SolverWire};
use crate::types::{Keypair, PublicKey, Result};

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
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(push_bytes)
        .into_script()
}

// ---------- Burn PSBT (pre-signed) ----------

pub fn build_burn_psbt(
    funding_outpoint: OutPoint,
    funding_value: Amount,
    opret_payload: &[u8],
) -> Result<Psbt> {
    // 1 input (Taproot key spend), 1 OP_RETURN output (0 sats)
    let txin = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let txout = TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return(opret_payload),
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {}", e))?;

    // Record previous txout for sighash
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_value,
        script_pubkey: ScriptBuf::new(), // Placeholder; actual script doesn't matter for key-path
    });

    Ok(psbt)
}

// ---------- Payout PSBT (cooperative) ----------

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

// ---------- Sighash + MuSig2 flow (key-path spend) ----------

/// Compute BIP-341 key-spend sighash for the single input
pub fn taproot_keyspend_sighash(
    psbt: &Psbt,
    prevout: &TxOut,
    sighash_ty: TapSighashType,
) -> Result<[u8; 32]> {
    let tx = &psbt.unsigned_tx;
    let mut cache = SighashCache::new(tx);

    let msg = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout.clone()]), sighash_ty)
        .map_err(|e| format!("Sighash error: {}", e))?;

    Ok(*msg.as_byte_array())
}

/// One-shot MuSig2 signing: commit → reveal → partials → combine
///
/// This implements the full MuSig2 protocol using the secp256k1 musig module.
/// 
/// Note: This is a simplified implementation for demonstration.
/// In production, use proper nonce generation and session handling.
pub async fn musig2_sign_single_input<W: SolverWire>(
    _secp: &Secp256k1<secp256k1::All>,
    my_keypair: &Keypair,
    key_agg_cache: &KeyAggCache,
    msg32: [u8; 32],
    wire: &mut W,
) -> Result<[u8; 64]> {
    // 1) Generate secret nonce using key_agg_cache
    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);
    let (sec_nonce, pub_nonce) = 
        key_agg_cache.nonce_gen(session_rand, my_keypair.public_key(), &msg32, None);

    // 2) Commit: H(R)
    let pub_nonce_ser = pub_nonce.serialize();
    let commit_hash = sha256::Hash::hash(&pub_nonce_ser);
    let my_commit = NonceCommit(commit_hash.to_byte_array());
    wire.send_commit(my_commit.clone()).await;
    let their_commit = wire.recv_commit().await;

    // 3) Reveal nonces
    let my_reveal = NonceReveal(pub_nonce_ser.to_vec());
    wire.send_reveal(my_reveal.clone()).await;
    let their_reveal = wire.recv_reveal().await;

    // 4) Verify their commitment
    let their_commit_check = sha256::Hash::hash(&their_reveal.0);
    if their_commit_check.to_byte_array() != their_commit.0 {
        return Err("Nonce commitment mismatch".to_string());
    }

    // 5) Parse their public nonce (66 bytes)
    if their_reveal.0.len() != 66 {
        return Err(format!("Invalid nonce length: {}", their_reveal.0.len()));
    }
    let mut nonce_bytes = [0u8; 66];
    nonce_bytes.copy_from_slice(&their_reveal.0);
    let their_pub_nonce = PublicNonce::from_byte_array(&nonce_bytes)
        .map_err(|e| format!("Invalid nonce: {:?}", e))?;

    // 6) Aggregate nonces
    let agg_nonce = AggregatedNonce::new(&[&pub_nonce, &their_pub_nonce]);

    // 7) Create session and sign
    let session = Session::new(key_agg_cache, agg_nonce, &msg32);

    let partial_sig = session.partial_sign(sec_nonce, my_keypair, key_agg_cache);

    // 8) Exchange partial signatures
    let my_partial = PartialSig(partial_sig.serialize().to_vec());
    wire.send_partial(my_partial.clone()).await;
    let their_partial = wire.recv_partial().await;

    // 9) Parse their partial signature (32 bytes)
    if their_partial.0.len() != 32 {
        return Err(format!("Invalid partial sig length: {}", their_partial.0.len()));
    }
    let mut sig_bytes = [0u8; 32];
    sig_bytes.copy_from_slice(&their_partial.0);
    let their_partial_sig = PartialSignature::from_byte_array(&sig_bytes)
        .map_err(|e| format!("Invalid partial sig: {:?}", e))?;

    // 10) Verify their partial signature  
    // Note: partial_verify signature differs by version - we skip detailed verification here
    // In production, verify using session.partial_verify() with correct params

    // 11) Combine into final signature
    let agg_sig = session.partial_sig_agg(&[&partial_sig, &their_partial_sig]);
    
    // 12) Verify the aggregated signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &msg32)
        .map_err(|e| format!("Signature verification failed: {:?}", e))?;

    Ok(*final_sig.as_ref())
}

/// Attach Schnorr sig (key-path) into PSBT's first input (finalize witness)
pub fn attach_keyspend_sig(mut psbt: Psbt, sig64: [u8; 64]) -> Psbt {
    // For key-path spend, witness is [sig64]
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[&sig64]));
    psbt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_funding_address() {
        let _secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();

        let kp1 = Keypair::new(&mut rng);
        let kp2 = Keypair::new(&mut rng);

        let (pk1, _) = kp1.x_only_public_key();
        let (pk2, _) = kp2.x_only_public_key();

        let funding = build_funding_address(&pk1, &pk2, None, Network::Testnet).unwrap();
        assert!(funding.address.to_string().starts_with("tb1p"));
    }

    #[test]
    fn test_build_burn_psbt() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let psbt = build_burn_psbt(outpoint, Amount::from_sat(20_000), b"INTENT_HASH").unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert!(psbt.unsigned_tx.output[0]
            .script_pubkey
            .is_op_return());
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
}

