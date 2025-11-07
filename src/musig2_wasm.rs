//! MuSig2 WASM bindings for browser-based signing
//! 
//! Provides functions for the user side of MuSig2 protocol

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use secp256k1::{Keypair, PublicKey, SecretKey};
use secp256k1::musig::{SessionSecretRand, PublicNonce, SecretNonce, AggregatedNonce, Session};
use std::sync::Mutex;
use std::collections::HashMap;

// Global storage for nonces (SecretNonce can't be serialized)
struct NonceData {
    sec_nonce: SecretNonce,
    pub_nonce: PublicNonce,
}

lazy_static::lazy_static! {
    static ref NONCE_STORAGE: Mutex<HashMap<String, NonceData>> = Mutex::new(HashMap::new());
}

#[derive(Serialize, Deserialize)]
pub struct NonceGenResult {
    pub nonce_id: String,        // ID to reference the stored secret nonce
    pub pub_nonce: String,       // Send to solver (66 bytes hex)
}

#[derive(Serialize, Deserialize)]
pub struct PartialSigResult {
    pub partial_sig: String,     // Send to solver (32 bytes hex)
}

/// Generate MuSig2 nonce for signing
/// Returns secret nonce (keep private) and public nonce (send to solver)
#[wasm_bindgen(js_name = generateNonce)]
pub fn wasm_generate_nonce(
    user_secret_hex: &str,
    solver_pubkey_hex: &str,
    sighash_hex: &str,
) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&JsValue::from_str("[MuSig2] Generating user nonce..."));
    
    // Parse user secret key
    let user_sk_bytes = hex::decode(user_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret: {}", e)))?;
    if user_sk_bytes.len() != 32 {
        return Err(JsValue::from_str("User secret must be 32 bytes"));
    }
    let user_sk_arr: [u8; 32] = user_sk_bytes.as_slice().try_into().unwrap();
    let user_sk = SecretKey::from_secret_bytes(user_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret: {:?}", e)))?;
    let user_kp = Keypair::from_secret_key(&user_sk);
    let user_pk = PublicKey::from_keypair(&user_kp);
    
    // Parse solver pubkey
    let solver_pk_bytes = hex::decode(solver_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey: {}", e)))?;
    let solver_pk = PublicKey::from_slice(&solver_pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey: {:?}", e)))?;
    
    // Parse sighash
    let sighash_bytes = hex::decode(sighash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid sighash: {}", e)))?;
    if sighash_bytes.len() != 32 {
        return Err(JsValue::from_str("Sighash must be 32 bytes"));
    }
    let sighash: [u8; 32] = sighash_bytes.as_slice().try_into().unwrap();
    
    // Aggregate keys
    let key_agg_cache = crate::aggregate_pubkeys(&[user_pk, solver_pk]);
    
    // Generate nonce
    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);
    let (sec_nonce, pub_nonce) = key_agg_cache.nonce_gen(
        session_rand,
        user_kp.public_key(),
        &sighash,
        None,
    );
    
    // Store both nonces with a unique ID
    // Use the nonce itself as part of the ID (deterministic from pub_nonce)
    let nonce_id = hex::encode(&pub_nonce.serialize()[..8]);
    NONCE_STORAGE.lock().unwrap().insert(nonce_id.clone(), NonceData {
        sec_nonce,
        pub_nonce,
    });
    
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[MuSig2] Generated nonce (ID: {}): {}",
        nonce_id,
        hex::encode(&pub_nonce.serialize()[..16])
    )));
    
    let result = NonceGenResult {
        nonce_id,
        pub_nonce: hex::encode(pub_nonce.serialize()),
    };
    
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Create partial signature using MuSig2
#[wasm_bindgen(js_name = partialSign)]
pub fn wasm_partial_sign(
    user_secret_hex: &str,
    solver_pubkey_hex: &str,
    nonce_id: &str,
    solver_pub_nonce_hex: &str,
    sighash_hex: &str,
    merkle_root_hex: &str,
) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&JsValue::from_str("[MuSig2] Creating user partial signature..."));
    
    // Parse user secret key
    let user_sk_bytes = hex::decode(user_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret: {}", e)))?;
    if user_sk_bytes.len() != 32 {
        return Err(JsValue::from_str("User secret must be 32 bytes"));
    }
    let user_sk_arr: [u8; 32] = user_sk_bytes.as_slice().try_into().unwrap();
    let user_sk = SecretKey::from_secret_bytes(user_sk_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid user secret: {:?}", e)))?;
    let user_kp = Keypair::from_secret_key(&user_sk);
    let user_pk = PublicKey::from_keypair(&user_kp);
    
    // Parse solver pubkey
    let solver_pk_bytes = hex::decode(solver_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey: {}", e)))?;
    let solver_pk = PublicKey::from_slice(&solver_pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver pubkey: {:?}", e)))?;
    
    // Retrieve nonce data from storage
    let nonce_data = NONCE_STORAGE.lock().unwrap()
        .remove(nonce_id)
        .ok_or_else(|| JsValue::from_str(&format!("Nonce not found: {}", nonce_id)))?;
    
    let sec_nonce = nonce_data.sec_nonce;
    let user_pub_nonce = nonce_data.pub_nonce;
    
    // Parse solver's public nonce
    let solver_nonce_bytes = hex::decode(solver_pub_nonce_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid solver nonce: {}", e)))?;
    if solver_nonce_bytes.len() != 66 {
        return Err(JsValue::from_str("Solver nonce must be 66 bytes"));
    }
    let solver_nonce_arr: [u8; 66] = solver_nonce_bytes.as_slice().try_into().unwrap();
    let solver_pub_nonce = PublicNonce::from_byte_array(&solver_nonce_arr)
        .map_err(|_| JsValue::from_str("Invalid solver nonce"))?;
    
    // Parse sighash
    let sighash_bytes = hex::decode(sighash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid sighash: {}", e)))?;
    if sighash_bytes.len() != 32 {
        return Err(JsValue::from_str("Sighash must be 32 bytes"));
    }
    let sighash: [u8; 32] = sighash_bytes.as_slice().try_into().unwrap();
    
    // Aggregate keys
    let mut key_agg_cache = crate::aggregate_pubkeys(&[user_pk, solver_pk]);
    
    // Apply taproot tweak if merkle root provided
    if !merkle_root_hex.is_empty() {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        use secp256k1::Scalar;
        
        let merkle_bytes = hex::decode(merkle_root_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid merkle root: {}", e)))?;
        if merkle_bytes.len() == 32 {
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
            
            key_agg_cache.pubkey_xonly_tweak_add(&tweak_scalar)
                .map_err(|e| JsValue::from_str(&format!("Tweak failed: {:?}", e)))?;
            
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[MuSig2] Applied taproot tweak: {}",
                hex::encode(&merkle_bytes[..8])
            )));
        }
    }
    
    // Aggregate nonces (user + solver)
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    
    // Create session
    let session = Session::new(&key_agg_cache, agg_nonce, &sighash);
    
    // User's partial signature
    let partial_sig = session.partial_sign(sec_nonce, &user_kp, &key_agg_cache);
    
    web_sys::console::log_1(&JsValue::from_str("[MuSig2] ✅ User partial signature created"));
    
    let result = PartialSigResult {
        partial_sig: hex::encode(partial_sig.serialize()),
    };
    
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

