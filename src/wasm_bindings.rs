//! WASM bindings for P2TR + MuSig2 functionality
//!
//! This module provides JavaScript-friendly interfaces for:
//! - Funding address generation (with CSV refund leaf)
//! - Transaction building (payout, burn, refund)
//! - MuSig2 signing flow

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use bitcoin::hashes::Hash;

const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP");

/// Get WASM build timestamp for debugging
#[wasm_bindgen(js_name = getWasmVersion)]
pub fn get_wasm_version() -> String {
    format!("Built: {}", BUILD_TIMESTAMP)
}

use crate::tx_build::{build_burn_psbt, build_payout_psbt, build_unilateral_refund_tx};
use crate::crypto::{aggregate_pubkeys, build_tr_with_refund_leaf, refund_leaf_script};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Txid};
use bitcoin::consensus::encode::serialize;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Keypair};

#[derive(Serialize, Deserialize)]
pub struct FundingAddressInfo {
    pub address: String,
    pub agg_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefundAddressInfo {
    pub address: String,
    pub agg_pubkey: String,  // internal_key (untweaked)
    pub output_key: String,  // tweaked key (what's on-chain)
    pub refund_script_hex: String,
    pub control_block_hex: String,
    pub csv_delta: u32,
    pub merkle_root_hex: String,
    pub internal_key: String,  // Same as agg_pubkey, for clarity
}

#[derive(Serialize, Deserialize)]
pub struct PsbtInfo {
    pub hex: String,
    pub txid: String,
}

#[derive(Serialize, Deserialize)]
pub struct TxInfo {
    pub hex: String,
    pub txid: String,
    pub size: usize,
}

/// Create a P2TR funding address from two x-only pubkeys
#[wasm_bindgen(js_name = createFundingAddress)]
pub fn wasm_create_funding_address(
    user_pubkey_hex: &str,
    solver_pubkey_hex: &str,
    intent_commit_hex: Option<String>,
    network: &str,
) -> Result<JsValue, JsValue> {
    // Parse network
    let net = match network {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return Err(JsValue::from_str("Invalid network")),
    };

    // Parse pubkeys
    let user_pk = hex::decode(user_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid user pubkey hex: {}", e)))?;
    let solver_pk = hex::decode(solver_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey hex: {}", e)))?;

    if user_pk.len() != 32 || solver_pk.len() != 32 {
        return Err(JsValue::from_str("Pubkeys must be 32 bytes"));
    }

    // Parse intent commit if provided
    let intent_commit = if let Some(commit_hex) = intent_commit_hex {
        let bytes = hex::decode(&commit_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid intent commit hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str("Intent commit must be 32 bytes"));
        }
        Some(bytes)
    } else {
        None
    };

    // Create funding address
    let user_xonly = secp256k1::XOnlyPublicKey::from_byte_array(
        user_pk.as_slice().try_into().unwrap()
    ).map_err(|e| JsValue::from_str(&format!("Invalid user pubkey: {:?}", e)))?;
    
    let solver_xonly = secp256k1::XOnlyPublicKey::from_byte_array(
        solver_pk.as_slice().try_into().unwrap()
    ).map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey: {:?}", e)))?;

    let funding = crate::tx_build::build_funding_address(
        &user_xonly,
        &solver_xonly,
        intent_commit.as_ref().map(|v| {
            let arr: [u8; 32] = v.as_slice().try_into().unwrap();
            arr
        }).as_ref(),
        net,
    ).map_err(|e| JsValue::from_str(&e))?;

    let info = FundingAddressInfo {
        address: funding.address.to_string(),
        agg_pubkey: hex::encode(funding.agg_pk.serialize()),
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
}

/// Create a P2TR funding address with CSV refund leaf
#[wasm_bindgen(js_name = createRefundAddress)]
pub fn wasm_create_refund_address(
    user_secret_hex: &str,
    solver_secret_hex: &str,
    csv_delta_blocks: u32,
    network: &str,
) -> Result<JsValue, JsValue> {
    let secp = Secp256k1::new();
    
    // Parse network
    let net = match network {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return Err(JsValue::from_str("Invalid network")),
    };

    // Parse secret keys
    let user_sk_bytes = hex::decode(user_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret hex: {}", e)))?;
    let solver_sk_bytes = hex::decode(solver_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver secret hex: {}", e)))?;

    if user_sk_bytes.len() != 32 || solver_sk_bytes.len() != 32 {
        return Err(JsValue::from_str("Secret keys must be 32 bytes"));
    }

    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[WASM] Address Gen - User SK (first 8 bytes):   {}",
        hex::encode(&user_sk_bytes[..8])
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[WASM] Address Gen - Solver SK (first 8 bytes): {}",
        hex::encode(&solver_sk_bytes[..8])
    )));

    let user_sk_arr: [u8; 32] = user_sk_bytes.as_slice().try_into().unwrap();
    let solver_sk_arr: [u8; 32] = solver_sk_bytes.as_slice().try_into().unwrap();
    
    let user_sk = SecretKey::from_secret_bytes(user_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret key: {:?}", e)))?;
    let solver_sk = SecretKey::from_secret_bytes(solver_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver secret key: {:?}", e)))?;
    
    let user_kp = Keypair::from_secret_key(&user_sk);
    let solver_kp = Keypair::from_secret_key(&solver_sk);
    
    // Get full public keys with correct parity
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "User full pk (address):   {}",
        hex::encode(user_pk.serialize())
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Solver full pk (address): {}",
        hex::encode(solver_pk.serialize())
    )));
    
    let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();
    
    // Get x-only for refund script (user can unilaterally refund)
    let (user_xonly, _) = user_kp.x_only_public_key();
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Aggregated key (internal): {}",
        hex::encode(agg_x.serialize())
    )));

    // Create refund script
    let refund_script = refund_leaf_script(user_xonly, csv_delta_blocks);

    // Build taproot address with refund leaf
    let tr = build_tr_with_refund_leaf(&secp, agg_x, refund_script.clone(), net)
        .map_err(|e| JsValue::from_str(&e))?;

    let merkle_root_hex = if let Some(root) = tr.merkle_root {
        hex::encode(root.as_byte_array())
    } else {
        String::new()
    };
    
    let internal_key_hex = hex::encode(agg_x.serialize());
    
    let info = RefundAddressInfo {
        address: tr.address.to_string(),
        agg_pubkey: internal_key_hex.clone(),
        output_key: hex::encode(tr.output_key.serialize()),
        refund_script_hex: hex::encode(refund_script.as_bytes()),
        control_block_hex: hex::encode(tr.control_block_refund.serialize()),
        csv_delta: csv_delta_blocks,
        merkle_root_hex,
        internal_key: internal_key_hex,  // For clarity in JS
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
}

/// Build a burn PSBT (OP_RETURN)
#[wasm_bindgen(js_name = buildBurnPsbt)]
pub fn wasm_build_burn_psbt(
    txid_hex: &str,
    vout: u32,
    value_sats: u64,
    payload_hex: &str,
) -> Result<JsValue, JsValue> {
    // Parse txid - use proper parsing that handles display format
    let txid: Txid = txid_hex.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid txid: {:?}", e)))?;

    // Parse payload
    let payload = hex::decode(payload_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid payload hex: {}", e)))?;

    // Build PSBT
    let outpoint = OutPoint { txid, vout };
    let amount = Amount::from_sat(value_sats);
    
    let psbt = build_burn_psbt(outpoint, amount, &payload)
        .map_err(|e| JsValue::from_str(&e))?;

    let tx = psbt.extract_tx().map_err(|e| JsValue::from_str(&format!("Extract tx error: {:?}", e)))?;
    let tx_hex = hex::encode(serialize(&tx));
    let tx_txid = tx.compute_txid();

    let info = PsbtInfo {
        hex: tx_hex,
        txid: tx_txid.to_string(),
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
}

/// Build a payout PSBT (cooperative spend)
#[wasm_bindgen(js_name = buildPayoutPsbt)]
pub fn wasm_build_payout_psbt(
    txid_hex: &str,
    vout: u32,
    input_value_sats: u64,
    output_address: &str,
    output_value_sats: u64,
) -> Result<JsValue, JsValue> {
    // Parse txid - use proper parsing that handles display format
    let txid: Txid = txid_hex.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid txid: {:?}", e)))?;

    // Parse output address
    let addr = output_address.parse::<bitcoin::Address<_>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?
        .assume_checked();

    // Build PSBT
    let outpoint = OutPoint { txid, vout };
    let input_amount = Amount::from_sat(input_value_sats);
    let output_amount = Amount::from_sat(output_value_sats);
    
    let psbt = build_payout_psbt(outpoint, input_amount, addr.script_pubkey(), output_amount)
        .map_err(|e| JsValue::from_str(&e))?;

    let tx = psbt.extract_tx().map_err(|e| JsValue::from_str(&format!("Extract tx error: {:?}", e)))?;
    let tx_hex = hex::encode(serialize(&tx));
    let tx_txid = tx.compute_txid();

    let info = PsbtInfo {
        hex: tx_hex,
        txid: tx_txid.to_string(),
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
}

/// Compute taproot key-spend sighash
#[wasm_bindgen(js_name = computeSighash)]
pub fn wasm_compute_sighash(
    psbt_hex: &str,
    prevout_value_sats: u64,
    prevout_script_hex: &str,
    sighash_type: &str,
) -> Result<String, JsValue> {
    use bitcoin::psbt::Psbt;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

    // Parse PSBT
    let tx_bytes = hex::decode(psbt_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid psbt hex: {}", e)))?;
    let tx: bitcoin::Transaction = deserialize(&tx_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction: {}", e)))?;

    // Parse prevout script
    let script_bytes = hex::decode(prevout_script_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid script hex: {}", e)))?;
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse sighash type
    let sighash_ty = match sighash_type {
        "ALL" => TapSighashType::All,
        "ALL_ANYONECANPAY" => TapSighashType::AllPlusAnyoneCanPay,
        "NONE" => TapSighashType::None,
        "SINGLE" => TapSighashType::Single,
        _ => return Err(JsValue::from_str("Invalid sighash type")),
    };

    // Compute sighash
    let prevout = bitcoin::TxOut {
        value: Amount::from_sat(prevout_value_sats),
        script_pubkey: script,
    };

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), sighash_ty)
        .map_err(|e| JsValue::from_str(&format!("Sighash error: {}", e)))?;

    Ok(hex::encode(sighash.to_byte_array()))
}

/// Build a unilateral refund transaction (script-path with CSV)
#[wasm_bindgen(js_name = buildRefundTx)]
pub fn wasm_build_refund_tx(
    txid_hex: &str,
    vout: u32,
    input_value_sats: u64,
    csv_delta: u32,
    output_address: &str,
    output_value_sats: u64,
) -> Result<JsValue, JsValue> {
    // Parse txid - use proper parsing that handles display format
    let txid: Txid = txid_hex.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid txid: {:?}", e)))?;

    // Parse output address
    let addr = output_address.parse::<bitcoin::Address<_>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?
        .assume_checked();

    // Build refund transaction
    let outpoint = OutPoint { txid, vout };
    let input_amount = Amount::from_sat(input_value_sats);
    let output_amount = Amount::from_sat(output_value_sats);
    
    let tx = build_unilateral_refund_tx(
        outpoint, 
        input_amount,
        csv_delta,
        addr.script_pubkey(), 
        output_amount
    );

    let tx_hex = hex::encode(serialize(&tx));
    let tx_txid = tx.compute_txid();

    let info = TxInfo {
        hex: tx_hex.clone(),
        txid: tx_txid.to_string(),
        size: tx_hex.len() / 2,
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
}

/// Sign a burn PSBT with MuSig2 (demo: simulates both parties locally)
#[wasm_bindgen(js_name = signBurnPsbtDemo)]
pub fn wasm_sign_burn_psbt_demo(
    user_secret_hex: &str,
    solver_secret_hex: &str,
    psbt_hex: &str,
    funding_address: &str,
    funding_value_sats: u64,
    merkle_root_hex: &str,
    expected_internal_key_hex: &str,
    expected_output_key_hex: &str,
) -> Result<JsValue, JsValue> {
    use bitcoin::psbt::Psbt;
    use bitcoin::consensus::encode::deserialize;
    use secp256k1::{Keypair, SecretKey};
    use secp256k1::musig::{AggregatedNonce, Session, SessionSecretRand};
    use crate::tx_build::attach_keyspend_sig;
    
    let secp = Secp256k1::new();
    
    // Parse secret keys
    let user_sk_bytes = hex::decode(user_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret: {}", e)))?;
    let solver_sk_bytes = hex::decode(solver_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver secret: {}", e)))?;
    
    if user_sk_bytes.len() != 32 || solver_sk_bytes.len() != 32 {
        return Err(JsValue::from_str("Secret keys must be 32 bytes"));
    }
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[WASM] Signing - User SK (first 8 bytes):   {}",
        hex::encode(&user_sk_bytes[..8])
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[WASM] Signing - Solver SK (first 8 bytes): {}",
        hex::encode(&solver_sk_bytes[..8])
    )));
    
    let user_sk_arr: [u8; 32] = user_sk_bytes.as_slice().try_into().unwrap();
    let solver_sk_arr: [u8; 32] = solver_sk_bytes.as_slice().try_into().unwrap();
    
    let user_sk = SecretKey::from_secret_bytes(user_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret key: {:?}", e)))?;
    let solver_sk = SecretKey::from_secret_bytes(solver_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver secret key: {:?}", e)))?;
    
    let user_kp = Keypair::from_secret_key(&user_sk);
    let solver_kp = Keypair::from_secret_key(&solver_sk);
    
    // Aggregate keys
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "User full pk (signing):   {}",
        hex::encode(user_pk.serialize())
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Solver full pk (signing): {}",
        hex::encode(solver_pk.serialize())
    )));
    
    let mut key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    
    // Log initial aggregated key for debugging
    let initial_agg_pk_hex = hex::encode(key_agg_cache.agg_pk().serialize());
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Initial agg_pk (internal_key): {}",
        initial_agg_pk_hex
    )));
    
    // SANITY CHECK: Verify our aggregated key matches the expected internal key
    if !expected_internal_key_hex.is_empty() && initial_agg_pk_hex != expected_internal_key_hex {
        let error_msg = format!(
            "SANITY CHECK FAILED: Internal key mismatch!\n\
             Expected internal_key: {}\n\
             Our agg_pk:            {}\n\
             The keys were aggregated differently!",
            expected_internal_key_hex,
            initial_agg_pk_hex
        );
        web_sys::console::error_1(&JsValue::from_str(&error_msg));
        return Err(JsValue::from_str(&error_msg));
    }
    
    if !expected_output_key_hex.is_empty() {
        web_sys::console::log_1(&JsValue::from_str(&format!(
            "Expected output_key (tweaked): {}",
            expected_output_key_hex
        )));
    }
    
    // Apply taproot tweak if merkle root is provided
    if !merkle_root_hex.is_empty() {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        use secp256k1::Scalar;
        
        let merkle_bytes = hex::decode(merkle_root_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid merkle root hex: {}", e)))?;
        if merkle_bytes.len() == 32 {
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "Applying taproot tweak with merkle root: {}",
                merkle_root_hex
            )));
            
            // Compute taproot tweak: t = H_taptweak(P || merkle_root)
            let mut eng = sha256::Hash::engine();
            let tag = b"TapTweak";
            let tag_hash = sha256::Hash::hash(tag);
            eng.input(tag_hash.as_ref());
            eng.input(tag_hash.as_ref());
            eng.input(&key_agg_cache.agg_pk().serialize());
            eng.input(&merkle_bytes);
            let tweak_hash = sha256::Hash::from_engine(eng);
            let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array())
                .map_err(|_| JsValue::from_str("Invalid tweak scalar"))?;
            
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "Taproot tweak scalar: {}",
                hex::encode(tweak_scalar.to_be_bytes())
            )));
            
            // Apply tweak to the KeyAggCache BEFORE nonce generation (required for MuSig2+Taproot)
            // This modifies the cache so that nonce generation and signing incorporate the tweak
            let tweaked_pk = key_agg_cache.pubkey_xonly_tweak_add(&tweak_scalar)
                .map_err(|e| JsValue::from_str(&format!("Failed to apply taproot tweak: {:?}", e)))?;
            
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "Applied tweak to KeyAggCache, new agg_pk: {}",
                hex::encode(key_agg_cache.agg_pk().serialize())
            )));
            
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "Tweaked full pk: {}",
                hex::encode(tweaked_pk.serialize())
            )));
            
            // SANITY CHECK: Verify the tweaked key matches the expected output key
            let tweaked_key_hex = hex::encode(key_agg_cache.agg_pk().serialize());
            if !expected_output_key_hex.is_empty() && tweaked_key_hex != expected_output_key_hex {
                let error_msg = format!(
                    "SANITY CHECK FAILED: Tweaked key mismatch!\n\
                     Expected output_key: {}\n\
                     Our tweaked agg_pk:  {}\n\
                     This means the signature will be invalid on-chain!",
                    expected_output_key_hex,
                    tweaked_key_hex
                );
                web_sys::console::error_1(&JsValue::from_str(&error_msg));
                return Err(JsValue::from_str(&error_msg));
            }
            
            web_sys::console::log_1(&JsValue::from_str("✅ SANITY CHECK: Tweaked key matches output_key"));
        }
    }
    
    // Now key_agg_cache has the tweak applied (if merkle_root was provided)
    // This is correct for MuSig2+Taproot: tweak must be applied BEFORE nonce generation
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "KeyAggCache ready for signing, agg_pk: {}",
        hex::encode(key_agg_cache.agg_pk().serialize())
    )));
    
    // Parse funding address first
    let addr = funding_address.parse::<bitcoin::Address<_>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?
        .assume_checked();
    
    let prevout = bitcoin::TxOut {
        value: Amount::from_sat(funding_value_sats),
        script_pubkey: addr.script_pubkey(),
    };
    
    // Parse PSBT hex as a transaction
    let psbt_bytes = hex::decode(psbt_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid psbt hex: {}", e)))?;
    let tx: bitcoin::Transaction = deserialize(&psbt_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction: {:?}", e)))?;
    
    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| JsValue::from_str(&format!("PSBT error: {:?}", e)))?;
    
    // Add witness_utxo for sighash computation
    psbt.inputs[0].witness_utxo = Some(prevout.clone());
    
    // Compute sighash (use Default for standard key-path spend)
    let sighash = crate::sighash::keyspend_sighash(
        &psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::Default,
    ).map_err(|e| JsValue::from_str(&e))?;
    
    // MuSig2 signing (both parties locally for demo)
    let mut rng = secp256k1::rand::rng();
    
    // User nonce
    let user_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (user_sec_nonce, user_pub_nonce) = key_agg_cache.nonce_gen(
        user_session_rand,
        user_kp.public_key(),
        &sighash,
        None,
    );
    
    // Solver nonce
    let solver_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (solver_sec_nonce, solver_pub_nonce) = key_agg_cache.nonce_gen(
        solver_session_rand,
        solver_kp.public_key(),
        &sighash,
        None,
    );
    
    // Aggregate nonces
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    
    // Create session
    let session = Session::new(&key_agg_cache, agg_nonce, &sighash);
    
    // Partial signatures
    let user_partial = session.partial_sign(user_sec_nonce, &user_kp, &key_agg_cache);
    let solver_partial = session.partial_sign(solver_sec_nonce, &solver_kp, &key_agg_cache);
    
    // Aggregate
    let agg_sig = session.partial_sig_agg(&[&user_partial, &solver_partial]);
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Sighash: {}",
        hex::encode(sighash)
    )));
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "Signing with tweaked agg_pk: {}",
        hex::encode(key_agg_cache.agg_pk().serialize())
    )));
    
    // Verify and extract final signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash)
        .map_err(|e| JsValue::from_str(&format!("Signature verification failed: {:?}", e)))?;
    
    let sig_bytes: [u8; 64] = *final_sig.as_ref();
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "✅ Signature created: {}",
        hex::encode(&sig_bytes[..32])
    )));
    
    // Attach signature to PSBT
    psbt = attach_keyspend_sig(psbt, sig_bytes);
    
    // Extract final transaction
    let signed_tx = psbt.extract_tx()
        .map_err(|e| JsValue::from_str(&format!("Extract tx error: {:?}", e)))?;
    
    // Sanity check: verify witness is attached
    if signed_tx.input[0].witness.is_empty() {
        return Err(JsValue::from_str("SANITY CHECK FAILED: Witness is empty after signing!"));
    }
    
    if signed_tx.input[0].witness.len() != 1 {
        return Err(JsValue::from_str(&format!(
            "SANITY CHECK FAILED: Expected 1 witness item, got {}",
            signed_tx.input[0].witness.len()
        )));
    }
    
    let witness_sig = &signed_tx.input[0].witness[0];
    if witness_sig.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "SANITY CHECK FAILED: Witness signature should be 64 bytes, got {}",
            witness_sig.len()
        )));
    }
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "✅ SANITY CHECK PASSED: Witness has 64-byte signature"
    )));
    
    let tx_hex = hex::encode(serialize(&signed_tx));
    let tx_txid = signed_tx.compute_txid();
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "✅ Final TX: {} ({} bytes)",
        tx_txid,
        tx_hex.len() / 2
    )));
    
    let info = TxInfo {
        hex: tx_hex.clone(),
        txid: tx_txid.to_string(),
        size: tx_hex.len() / 2,
    };
    
    Ok(serde_wasm_bindgen::to_value(&info)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_create_funding_address() {
        let user_pk = "02".repeat(32);
        let solver_pk = "03".repeat(32);
        
        let result = wasm_create_funding_address(&user_pk, &solver_pk, None, "testnet");
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_wasm_create_refund_address() {
        let user_pk = "02".repeat(32);
        let solver_pk = "03".repeat(32);
        
        let result = wasm_create_refund_address(&user_pk, &solver_pk, 144, "regtest");
        assert!(result.is_ok());
    }
}


