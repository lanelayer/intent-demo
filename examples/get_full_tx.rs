//! Get complete transaction hex for testing
//!
//! Run with: cargo run --example get_full_tx

use bitcoin::{consensus::encode::serialize, Amount, Network, OutPoint, Txid};
use bitcoin::hashes::Hash;
use secp256k1::{Keypair, Secp256k1};
use secp256k1::musig::{AggregatedNonce, KeyAggCache, SessionSecretRand};
use wasm_helper::tx::{
    attach_keyspend_sig, build_burn_psbt, build_funding_address, taproot_keyspend_sighash,
};

fn main() {
    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();
    
    // Generate keys
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);
    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();
    
    // Create funding address
    let funding_info = build_funding_address(&user_x, &solver_x, None, Network::Testnet)
        .expect("funding address");
    
    println!("Funding address: {}\n", funding_info.address);
    
    // Fake funding UTXO
    let funding_txid = Txid::from_raw_hash(Hash::from_byte_array([0x42; 32]));
    let funding_outpoint = OutPoint { txid: funding_txid, vout: 0 };
    let funding_value = Amount::from_sat(20_000);
    
    // Build burn PSBT
    let burn_psbt = build_burn_psbt(funding_outpoint, funding_value, b"TEST")
        .expect("burn psbt");
    
    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: funding_info.address.script_pubkey(),
    };
    
    let burn_sighash = taproot_keyspend_sighash(
        &burn_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    )
    .expect("sighash");
    
    // MuSig2 sign
    let user_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (user_sec_nonce, user_pub_nonce) = funding_info.key_agg_cache.nonce_gen(
        user_session_rand,
        user_kp.public_key(),
        &burn_sighash,
        None,
    );
    
    let solver_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (solver_sec_nonce, solver_pub_nonce) = funding_info.key_agg_cache.nonce_gen(
        solver_session_rand,
        solver_kp.public_key(),
        &burn_sighash,
        None,
    );
    
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    let session = secp256k1::musig::Session::new(&funding_info.key_agg_cache, agg_nonce, &burn_sighash);
    
    let user_partial = session.partial_sign(user_sec_nonce, &user_kp, &funding_info.key_agg_cache);
    let solver_partial = session.partial_sign(solver_sec_nonce, &solver_kp, &funding_info.key_agg_cache);
    
    let agg_sig = session.partial_sig_agg(&[&user_partial, &solver_partial]);
    let final_sig = agg_sig.assume_valid();
    let sig_bytes: &[u8; 64] = final_sig.as_ref();
    
    // Attach signature
    let signed_burn_psbt = attach_keyspend_sig(burn_psbt, *sig_bytes);
    let burn_tx = signed_burn_psbt.extract_tx().expect("extract");
    let burn_tx_hex = hex::encode(serialize(&burn_tx));
    
    println!("──────────────────────────────────────────────");
    println!("COMPLETE BURN TRANSACTION");
    println!("──────────────────────────────────────────────\n");
    println!("TXID: {}\n", burn_tx.compute_txid());
    println!("Raw Hex (Full):");
    println!("{}\n", burn_tx_hex);
    println!("Length: {} bytes\n", burn_tx_hex.len() / 2);
    
    println!("──────────────────────────────────────────────");
    println!("TRANSACTION BREAKDOWN");
    println!("──────────────────────────────────────────────\n");
    println!("Inputs: {}", burn_tx.input.len());
    println!("Outputs: {}", burn_tx.output.len());
    println!("Witness items: {}", burn_tx.input[0].witness.len());
    println!("Witness[0] size: {} bytes", burn_tx.input[0].witness.iter().next().map(|w| w.len()).unwrap_or(0));
    println!("\n⚠️  Note: This transaction CANNOT be broadcast because:");
    println!("   - Funding UTXO (4242...4242:0) doesn't exist on-chain");
    println!("   - It's for demonstration purposes only");
    println!("\nTo broadcast a real transaction:");
    println!("   1. Send real testnet BTC to: {}", funding_info.address);
    println!("   2. Use the real TXID and vout");
    println!("   3. Build and sign with that real UTXO");
}
