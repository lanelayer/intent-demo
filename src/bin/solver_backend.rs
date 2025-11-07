//! LaneLayer Solver Backend
//!
//! HTTP API server that acts as the solver in BTC → LaneBTC swaps
//! Handles MuSig2 key aggregation, nonce exchange, and transaction signing

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

use secp256k1::{Keypair, PublicKey, Secp256k1};
use secp256k1::musig::{AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SecretNonce, Session, SessionSecretRand};
use bitcoin::hashes::Hash;

type SessionId = String;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    btc_amount: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    solver: String,
    solver_pubkey: String, // hex-encoded 33-byte compressed pubkey
    fee: f64,
    receives: f64,
    timelock: u32,
    reputation: u8,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EscrowInitRequest {
    user_pubkey: String,      // hex-encoded 33-byte compressed pubkey
    btc_amount: f64,
    intent_hash: String,      // 20 bytes hex
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EscrowInitResponse {
    session_id: String,
    solver_pubkey: String,
    address_info: AddressInfo,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    address: String,
    agg_pubkey: String,
    output_key: String,
    merkle_root_hex: String,
    internal_key: String,
    csv_delta: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NonceRequest {
    session_id: String,
    user_pub_nonce: String,   // hex-encoded nonce
    psbt_hex: String,
    sighash_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    solver_pub_nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRequest {
    session_id: String,
    user_partial_sig: String, // hex-encoded partial signature
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignResponse {
    final_sig: String,         // hex-encoded final signature (64 bytes)
    signed_tx_hex: String,     // Full signed transaction with witness
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildBurnRequest {
    session_id: String,
    funding_txid: String,
    funding_vout: u32,
    funding_value_sats: u64,
    burn_amount_sats: u64,
    chain_id: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildBurnResponse {
    psbt_hex: String,
    sighash_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildPayoutRequest {
    session_id: String,
    funding_txid: String,
    funding_vout: u32,
    funding_value_sats: u64,
    payout_address: String,
    payout_amount_sats: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuildPayoutResponse {
    psbt_hex: String,
    sighash_hex: String,
}

// ============================================================================
// Solver State
// ============================================================================

// Separate nonce state for each transaction type
struct NonceState {
    solver_sec_nonce: Option<SecretNonce>,
    solver_pub_nonce: Option<PublicNonce>,
    user_pub_nonce: Option<PublicNonce>,
    sighash: Option<[u8; 32]>,
    psbt_hex: Option<String>,  // Store unsigned tx for witness attachment
}

struct SessionData {
    user_pk: PublicKey,
    solver_kp: Keypair,
    intent_hash: String,
    btc_amount: f64,
    merkle_root: Option<Vec<u8>>,
    key_agg_cache_untweaked: KeyAggCache,
    burn_nonce_state: Option<NonceState>,    // Separate state for burn tx
    payout_nonce_state: Option<NonceState>,  // Separate state for payout tx
    signed_burn_tx: Option<String>,          // Store signed burn tx (backend's copy)
    signed_payout_tx: Option<String>,        // Store signed payout tx (backend's copy)
}

#[derive(Clone)]
struct SolverState {
    sessions: Arc<Mutex<HashMap<SessionId, SessionData>>>,
    secp: Secp256k1<secp256k1::All>,
}

impl SolverState {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            secp: Secp256k1::new(),
        }
    }
}

// ============================================================================
// API Handlers
// ============================================================================

async fn health_check() -> &'static str {
    "LaneLayer Solver - Ready"
}

async fn get_quote(
    Json(req): Json<QuoteRequest>,
) -> Json<QuoteResponse> {
    let fee = 0.0001;
    let receives = req.btc_amount - fee;

    // Generate a temporary keypair just for the quote
    let mut rng = secp256k1::rand::rng();
    let kp = Keypair::new(&mut rng);
    let pk = PublicKey::from_keypair(&kp);
    
    Json(QuoteResponse {
        solver: "LaneLayer".to_string(),
        solver_pubkey: hex::encode(pk.serialize()),
        fee,
        receives,
        timelock: 144,
        reputation: 100,
    })
}

async fn init_escrow(
    State(state): State<SolverState>,
    Json(req): Json<EscrowInitRequest>,
) -> Result<Json<EscrowInitResponse>, StatusCode> {
    println!("📥 Escrow init request:");
    println!("   User pubkey: {}", req.user_pubkey);
    println!("   Amount: {} BTC", req.btc_amount);
    println!("   Intent hash: {}", req.intent_hash);

    // Parse user pubkey
    let user_pk_bytes = hex::decode(&req.user_pubkey)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let user_pk = PublicKey::from_slice(&user_pk_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Generate solver keypair for this session
    let mut rng = secp256k1::rand::rng();
    let solver_kp = Keypair::new(&mut rng);
    let solver_pk = PublicKey::from_keypair(&solver_kp);

    println!("   Generated solver keypair");
    println!("   Solver pubkey: {}", hex::encode(solver_pk.serialize()));

    // Aggregate keys
    let key_agg_cache = wasm_helper::aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();

    // Create refund script
    let (user_xonly, _) = user_pk.x_only_public_key();
    let refund_script = wasm_helper::refund_leaf_script(user_xonly, 144);

    // Build taproot address
    let tr = wasm_helper::build_tr_with_refund_leaf(
        &state.secp,
        agg_x,
        refund_script,
        bitcoin::Network::Regtest,
    ).map_err(|e| {
        eprintln!("Error building address: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let merkle_root_bytes = tr.merkle_root.map(|r| r.as_byte_array().to_vec());
    let merkle_root_hex = if let Some(ref root_bytes) = merkle_root_bytes {
        hex::encode(root_bytes)
    } else {
        String::new()
    };

    let address_info = AddressInfo {
        address: tr.address.to_string(),
        agg_pubkey: hex::encode(agg_x.serialize()),
        output_key: hex::encode(tr.output_key.serialize()),
        merkle_root_hex,
        internal_key: hex::encode(agg_x.serialize()),
        csv_delta: 144,
    };

    // Generate session ID
    let session_id = format!("{:x}", rand::random::<u64>());

    // Store session
    let session_data = SessionData {
        user_pk,
        solver_kp,
        intent_hash: req.intent_hash,
        btc_amount: req.btc_amount,
        merkle_root: merkle_root_bytes,
        key_agg_cache_untweaked: key_agg_cache,
        burn_nonce_state: None,
        payout_nonce_state: None,
        signed_burn_tx: None,
        signed_payout_tx: None,
    };

    state.sessions.lock().unwrap().insert(session_id.clone(), session_data);

    println!("✅ Session created: {}", session_id);
    println!("   Address: {}", address_info.address);

    Ok(Json(EscrowInitResponse {
        session_id,
        solver_pubkey: hex::encode(solver_pk.serialize()),
        address_info,
    }))
}

// Helper function to apply taproot tweak
fn apply_taproot_tweak(
    key_agg_cache: &mut KeyAggCache,
    merkle_bytes: &[u8],
) -> Result<(), StatusCode> {
    use bitcoin::hashes::{sha256, HashEngine};
    use secp256k1::Scalar;
    
    let mut eng = sha256::Hash::engine();
    let tag = b"TapTweak";
    let tag_hash = sha256::Hash::hash(tag);
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(&key_agg_cache.agg_pk().serialize());
    eng.input(merkle_bytes);
    let tweak_hash = sha256::Hash::from_engine(eng);
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    key_agg_cache.pubkey_xonly_tweak_add(&tweak_scalar)
        .map_err(|e| {
            eprintln!("Failed to apply taproot tweak: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(())
}

// Burn transaction nonce exchange
async fn exchange_burn_nonce(
    State(state): State<SolverState>,
    Json(req): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, StatusCode> {
    println!("📥 [BURN] Nonce exchange request:");
    println!("   Session: {}", req.session_id);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Parse user's public nonce
    let user_nonce_bytes = hex::decode(&req.user_pub_nonce)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_nonce_bytes.len() != 66 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut nonce_arr = [0u8; 66];
    nonce_arr.copy_from_slice(&user_nonce_bytes);
    let user_pub_nonce = PublicNonce::from_byte_array(&nonce_arr)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse sighash
    let sighash_bytes = hex::decode(&req.sighash_hex)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if sighash_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    println!("   Sighash: {}", req.sighash_hex);

    // Generate solver's nonce with fresh tweaked cache
    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);
    
    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();

    // Apply taproot tweak if we have a merkle root
    if let Some(ref merkle_bytes) = session.merkle_root {
        println!("   Applying taproot tweak with merkle root");
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
        println!("   Taproot tweak applied, agg_pk: {}", hex::encode(key_agg_cache.agg_pk().serialize()));
    }

    let (solver_sec_nonce, solver_pub_nonce) = key_agg_cache.nonce_gen(
        session_rand,
        session.solver_kp.public_key(),
        &sighash,
        None,
    );

    println!("   Generated solver nonce");

    // Store in burn nonce state
    session.burn_nonce_state = Some(NonceState {
        solver_sec_nonce: Some(solver_sec_nonce),
        solver_pub_nonce: Some(solver_pub_nonce),
        user_pub_nonce: Some(user_pub_nonce),
        sighash: Some(sighash),
        psbt_hex: Some(req.psbt_hex.clone()),
    });

    Ok(Json(NonceResponse {
        solver_pub_nonce: hex::encode(solver_pub_nonce.serialize()),
    }))
}

// Payout transaction nonce exchange
async fn exchange_payout_nonce(
    State(state): State<SolverState>,
    Json(req): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, StatusCode> {
    println!("📥 [PAYOUT] Nonce exchange request:");
    println!("   Session: {}", req.session_id);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Parse user's public nonce
    let user_nonce_bytes = hex::decode(&req.user_pub_nonce)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_nonce_bytes.len() != 66 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut nonce_arr = [0u8; 66];
    nonce_arr.copy_from_slice(&user_nonce_bytes);
    let user_pub_nonce = PublicNonce::from_byte_array(&nonce_arr)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse sighash
    let sighash_bytes = hex::decode(&req.sighash_hex)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if sighash_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    println!("   Sighash: {}", req.sighash_hex);

    // Generate solver's nonce with fresh tweaked cache
    let mut rng = secp256k1::rand::rng();
    let session_rand = SessionSecretRand::from_rng(&mut rng);
    
    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();

    // Apply taproot tweak if we have a merkle root
    if let Some(ref merkle_bytes) = session.merkle_root {
        println!("   Applying taproot tweak with merkle root");
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
        println!("   Taproot tweak applied, agg_pk: {}", hex::encode(key_agg_cache.agg_pk().serialize()));
    }

    let (solver_sec_nonce, solver_pub_nonce) = key_agg_cache.nonce_gen(
        session_rand,
        session.solver_kp.public_key(),
        &sighash,
        None,
    );

    println!("   Generated solver nonce");

    // Store in payout nonce state
    session.payout_nonce_state = Some(NonceState {
        solver_sec_nonce: Some(solver_sec_nonce),
        solver_pub_nonce: Some(solver_pub_nonce),
        user_pub_nonce: Some(user_pub_nonce),
        sighash: Some(sighash),
        psbt_hex: Some(req.psbt_hex.clone()),
    });

    Ok(Json(NonceResponse {
        solver_pub_nonce: hex::encode(solver_pub_nonce.serialize()),
    }))
}

// Burn transaction partial sign
async fn partial_sign_burn(
    State(state): State<SolverState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    println!("📥 [BURN] Partial sign request:");
    println!("   Session: {}", req.session_id);
    println!("   User partial sig: {}", &req.user_partial_sig[..16]);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id)
        .ok_or_else(|| {
            eprintln!("❌ Session not found: {}", req.session_id);
            StatusCode::NOT_FOUND
        })?;

    // Parse user's partial signature
    let user_partial_bytes = hex::decode(&req.user_partial_sig)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_partial_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut partial_arr = [0u8; 32];
    partial_arr.copy_from_slice(&user_partial_bytes);
    let user_partial = PartialSignature::from_byte_array(&partial_arr)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get burn nonce state
    let mut burn_state = session.burn_nonce_state.take()
        .ok_or_else(|| {
            eprintln!("❌ Burn nonce state not found");
            StatusCode::BAD_REQUEST
        })?;
    
    let user_pub_nonce = burn_state.user_pub_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_pub_nonce = burn_state.solver_pub_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let sighash = burn_state.sighash.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_sec_nonce = burn_state.solver_sec_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let psbt_hex = burn_state.psbt_hex.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    
    let solver_kp = session.solver_kp.clone();
    
    // Recreate tweaked key_agg_cache
    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();
    if let Some(ref merkle_bytes) = session.merkle_root {
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
    }
    
    println!("   All session data retrieved successfully");

    // Aggregate nonces
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);

    // Create session
    let musig_session = Session::new(&key_agg_cache, agg_nonce, &sighash);

    // Solver's partial signature
    let solver_partial = musig_session.partial_sign(
        solver_sec_nonce,
        &solver_kp,
        &key_agg_cache,
    );

    println!("   Generated solver partial signature");

    // Aggregate signatures
    let agg_sig = musig_session.partial_sig_agg(&[&user_partial, &solver_partial]);

    // Verify final signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash)
        .map_err(|e| {
            eprintln!("Signature verification failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let sig_bytes: [u8; 64] = *final_sig.as_ref();

    println!("✅ [BURN] Final signature created and verified");

    // Attach witness to create final signed transaction
    let tx_bytes = hex::decode(&psbt_hex)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Attach 65-byte witness (64-byte sig + 0x81 ANYONECANPAY)
    let mut witness_data = sig_bytes.to_vec();
    witness_data.push(0x81);
    tx.input[0].witness = bitcoin::Witness::from_slice(&[&witness_data]);
    
    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
    
    // Store in session (backend's copy)
    session.signed_burn_tx = Some(signed_tx_hex.clone());
    
    println!("   Stored signed burn tx ({} bytes)", signed_tx_hex.len() / 2);

    Ok(Json(SignResponse {
        final_sig: hex::encode(sig_bytes),
        signed_tx_hex,
    }))
}

// Payout transaction partial sign
async fn partial_sign_payout(
    State(state): State<SolverState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    println!("📥 [PAYOUT] Partial sign request:");
    println!("   Session: {}", req.session_id);
    println!("   User partial sig: {}", &req.user_partial_sig[..16]);

    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions.get_mut(&req.session_id)
        .ok_or_else(|| {
            eprintln!("❌ Session not found: {}", req.session_id);
            StatusCode::NOT_FOUND
        })?;

    // Parse user's partial signature
    let user_partial_bytes = hex::decode(&req.user_partial_sig)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_partial_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut partial_arr = [0u8; 32];
    partial_arr.copy_from_slice(&user_partial_bytes);
    let user_partial = PartialSignature::from_byte_array(&partial_arr)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get payout nonce state
    let mut payout_state = session.payout_nonce_state.take()
        .ok_or_else(|| {
            eprintln!("❌ Payout nonce state not found");
            StatusCode::BAD_REQUEST
        })?;
    
    let user_pub_nonce = payout_state.user_pub_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_pub_nonce = payout_state.solver_pub_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let sighash = payout_state.sighash.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let solver_sec_nonce = payout_state.solver_sec_nonce.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let psbt_hex = payout_state.psbt_hex.take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    
    let solver_kp = session.solver_kp.clone();
    
    // Recreate tweaked key_agg_cache
    let mut key_agg_cache = session.key_agg_cache_untweaked.clone();
    if let Some(ref merkle_bytes) = session.merkle_root {
        apply_taproot_tweak(&mut key_agg_cache, merkle_bytes)?;
    }
    
    println!("   All session data retrieved successfully");

    // Aggregate nonces
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);

    // Create session
    let musig_session = Session::new(&key_agg_cache, agg_nonce, &sighash);

    // Solver's partial signature
    let solver_partial = musig_session.partial_sign(
        solver_sec_nonce,
        &solver_kp,
        &key_agg_cache,
    );

    println!("   Generated solver partial signature");

    // Aggregate signatures
    let agg_sig = musig_session.partial_sig_agg(&[&user_partial, &solver_partial]);

    // Verify final signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash)
        .map_err(|e| {
            eprintln!("Signature verification failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let sig_bytes: [u8; 64] = *final_sig.as_ref();

    println!("✅ [PAYOUT] Final signature created and verified");

    // Attach witness to create final signed transaction
    let tx_bytes = hex::decode(&psbt_hex)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Attach 64-byte witness (SIGHASH_DEFAULT, no sighash byte)
    tx.input[0].witness = bitcoin::Witness::from_slice(&[&sig_bytes]);
    
    let signed_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
    
    // Store in session (backend's copy)
    session.signed_payout_tx = Some(signed_tx_hex.clone());
    
    println!("   Stored signed payout tx ({} bytes)", signed_tx_hex.len() / 2);

    Ok(Json(SignResponse {
        final_sig: hex::encode(sig_bytes),
        signed_tx_hex,
    }))
}

async fn build_burn_tx(
    State(_state): State<SolverState>,
    Json(req): Json<BuildBurnRequest>,
) -> Result<Json<BuildBurnResponse>, StatusCode> {
    use bitcoin::{OutPoint, Amount, Txid};
    use bitcoin::consensus::serialize;
    
    println!("📥 Build burn transaction request:");
    println!("   Session: {}", req.session_id);
    println!("   Funding: {}:{}", req.funding_txid, req.funding_vout);
    println!("   Burn amount: {} sats", req.burn_amount_sats);

    // Parse txid
    let txid: Txid = req.funding_txid.parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let outpoint = OutPoint {
        txid,
        vout: req.funding_vout,
    };
    
    let funding_value = Amount::from_sat(req.funding_value_sats);
    let burn_amount = Amount::from_sat(req.burn_amount_sats);
    
    // Build BTI1 payload
    let intent_hash_bytes = hex::decode(&_state.sessions.lock().unwrap()
        .get(&req.session_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .intent_hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let mut payload = Vec::with_capacity(4 + 4 + 20);
    payload.extend_from_slice(b"BTI1");
    payload.extend_from_slice(&req.chain_id.to_be_bytes());
    payload.extend_from_slice(&intent_hash_bytes);
    
    // Build PSBT
    let psbt = wasm_helper::build_burn_psbt(
        outpoint,
        funding_value,
        burn_amount,
        &payload,
        bitcoin::Network::Regtest,
    ).map_err(|e| {
        eprintln!("Error building burn PSBT: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Compute sighash for the burn transaction
    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: bitcoin::ScriptBuf::new(),
    };
    
    let sighash = wasm_helper::keyspend_sighash(
        &psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    ).map_err(|e| {
        eprintln!("Error computing sighash: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    let psbt_hex = hex::encode(serialize(&psbt.extract_tx()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?));
    
    println!("✅ Burn PSBT built");
    println!("   Sighash: {}", hex::encode(sighash));
    
    Ok(Json(BuildBurnResponse {
        psbt_hex,
        sighash_hex: hex::encode(sighash),
    }))
}

async fn build_payout_tx(
    State(_state): State<SolverState>,
    Json(req): Json<BuildPayoutRequest>,
) -> Result<Json<BuildPayoutResponse>, StatusCode> {
    use bitcoin::{OutPoint, Amount, Txid, Address};
    use bitcoin::consensus::serialize;
    use std::str::FromStr;
    
    println!("📥 Build payout transaction request:");
    println!("   Session: {}", req.session_id);
    println!("   Funding: {}:{}", req.funding_txid, req.funding_vout);
    println!("   Payout to: {}", req.payout_address);
    println!("   Amount: {} sats", req.payout_amount_sats);

    // Parse txid
    let txid: Txid = req.funding_txid.parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let outpoint = OutPoint {
        txid,
        vout: req.funding_vout,
    };
    
    let funding_value = Amount::from_sat(req.funding_value_sats);
    let payout_amount = Amount::from_sat(req.payout_amount_sats);
    
    // Parse payout address
    let payout_address = Address::from_str(&req.payout_address)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .assume_checked();
    
    // Build PSBT
    let psbt = wasm_helper::build_payout_psbt(
        outpoint,
        funding_value,
        payout_address.script_pubkey(),
        payout_amount,
    ).map_err(|e| {
        eprintln!("Error building payout PSBT: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Compute sighash for the payout transaction
    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: bitcoin::ScriptBuf::new(),
    };
    
    let sighash = wasm_helper::keyspend_sighash(
        &psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::Default,
    ).map_err(|e| {
        eprintln!("Error computing sighash: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    let psbt_hex = hex::encode(serialize(&psbt.extract_tx()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?));
    
    println!("✅ Payout PSBT built");
    println!("   Sighash: {}", hex::encode(sighash));
    
    Ok(Json(BuildPayoutResponse {
        psbt_hex,
        sighash_hex: hex::encode(sighash),
    }))
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    println!("🚀 LaneLayer Solver Backend");
    println!("============================");

    let solver_state = SolverState::new();

    let app = Router::new()
        .route("/", get(health_check))
        .route("/api/quote", post(get_quote))
        .route("/api/escrow/init", post(init_escrow))
        .route("/api/burn/build", post(build_burn_tx))
        .route("/api/burn/nonce", post(exchange_burn_nonce))
        .route("/api/burn/sign", post(partial_sign_burn))
        .route("/api/payout/build", post(build_payout_tx))
        .route("/api/payout/nonce", post(exchange_payout_nonce))
        .route("/api/payout/sign", post(partial_sign_payout))
        .layer(CorsLayer::permissive())
        .with_state(solver_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");

    println!("✅ Solver listening on http://127.0.0.1:3000");
    println!();

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}

