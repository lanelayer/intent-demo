/// Test MuSig2 + Taproot signing to debug signature verification issues
use bitcoin::{
    consensus::{deserialize, serialize},
    Address, Network, OutPoint, Psbt, Transaction, TxOut, Amount,
    hashes::{Hash, sha256, HashEngine},
};
use secp256k1::{Secp256k1, Keypair, PublicKey, Scalar, SecretKey};
use secp256k1::musig::{KeyAggCache, AggregatedNonce, Session, SessionSecretRand};
use wasm_helper::crypto::{build_tr_with_refund_leaf, refund_leaf_script};
use wasm_helper::tx_build::build_burn_psbt;
use wasm_helper::sighash::keyspend_sighash;

fn aggregate_pubkeys(pubkeys: &[PublicKey; 2]) -> KeyAggCache {
    KeyAggCache::new(&[&pubkeys[0], &pubkeys[1]])
}

fn main() {
    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();
    
    // Step 1: Generate keys (use the same keys from the browser)
    // User secret: from browser logs
    let user_sk = SecretKey::from_slice(&hex::decode("YOUR_USER_SECRET_HERE").unwrap()).unwrap();
    let solver_sk = SecretKey::from_slice(&hex::decode("YOUR_SOLVER_SECRET_HERE").unwrap()).unwrap();
    
    let user_kp = Keypair::from_secret_key(&user_sk);
    let solver_kp = Keypair::from_secret_key(&solver_sk);
    
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    
    println!("User pk:   {}", hex::encode(user_pk.serialize()));
    println!("Solver pk: {}", hex::encode(solver_pk.serialize()));
    
    // Step 2: Aggregate keys
    let mut key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let internal_key = key_agg_cache.agg_pk();
    
    println!("\nInternal key (before tweak): {}", hex::encode(internal_key.serialize()));
    
    // Step 3: Build refund address to get merkle root
    let (user_x, _) = user_kp.x_only_public_key();
    let refund_script = refund_leaf_script(user_x.into(), 144);
    let tr = build_tr_with_refund_leaf(
        &secp,
        internal_key.into(),
        refund_script.clone(),
        Network::Regtest,
    );
    
    println!("Funding address: {}", tr.address);
    println!("Merkle root: {}", hex::encode(tr.merkle_root.unwrap().as_byte_array()));
    println!("Output key (tweaked): {}", hex::encode(tr.output_key.serialize()));
    
    // Step 4: Apply taproot tweak to key_agg_cache
    let merkle_root = tr.merkle_root.unwrap();
    
    // Compute taproot tweak
    let mut eng = sha256::Hash::engine();
    let tag = b"TapTweak";
    let tag_hash = sha256::Hash::hash(tag);
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(&internal_key.serialize());
    eng.input(merkle_root.as_byte_array());
    let tweak_hash = sha256::Hash::from_engine(eng);
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array()).unwrap();
    
    println!("\nTweak scalar: {}", hex::encode(tweak_scalar.to_be_bytes()));
    
    // Apply tweak
    let tweaked_pk = key_agg_cache.pubkey_xonly_tweak_add(&tweak_scalar).unwrap();
    let tweaked_agg_pk = key_agg_cache.agg_pk();
    
    println!("Tweaked agg_pk:  {}", hex::encode(tweaked_agg_pk.serialize()));
    println!("Tweaked full pk: {}", hex::encode(tweaked_pk.serialize()));
    println!("Expected output_key: {}", hex::encode(tr.output_key.serialize()));
    
    // Verify keys match
    assert_eq!(
        hex::encode(tweaked_agg_pk.serialize()),
        hex::encode(tr.output_key.serialize()),
        "Tweaked key mismatch!"
    );
    println!("✅ Keys match!");
    
    // Step 5: Create burn PSBT
    let funding_txid = "YOUR_FUNDING_TXID_HERE".parse().unwrap();
    let funding_vout = 1;
    let funding_amount = 50000u64;
    
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: funding_vout,
    };
    
    let opreturn_data = b"INTENT||0xdeadbeef";
    let mut psbt = build_burn_psbt(funding_outpoint, funding_amount, opreturn_data)
        .expect("build burn psbt");
    
    // Step 6: Compute sighash
    let prevout = TxOut {
        value: Amount::from_sat(funding_amount),
        script_pubkey: tr.address.script_pubkey(),
    };
    
    psbt.inputs[0].witness_utxo = Some(prevout.clone());
    
    let sighash = keyspend_sighash(
        &psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    ).expect("sighash");
    
    println!("\nSighash: {}", hex::encode(sighash));
    
    // Step 7: MuSig2 signing
    let user_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (user_sec_nonce, user_pub_nonce) = key_agg_cache.nonce_gen(
        user_session_rand,
        user_kp.public_key(),
        &sighash,
        None,
    );
    
    let solver_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (solver_sec_nonce, solver_pub_nonce) = key_agg_cache.nonce_gen(
        solver_session_rand,
        solver_kp.public_key(),
        &sighash,
        None,
    );
    
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    let session = Session::new(&key_agg_cache, agg_nonce, &sighash);
    
    let user_partial = session.partial_sign(user_sec_nonce, &user_kp, &key_agg_cache);
    let solver_partial = session.partial_sign(solver_sec_nonce, &solver_kp, &key_agg_cache);
    
    let agg_sig = session.partial_sig_agg(&[&user_partial, &solver_partial]);
    
    // Verify signature
    let final_sig = agg_sig.verify(&key_agg_cache.agg_pk(), &sighash)
        .expect("Signature should verify locally");
    
    let sig_bytes: [u8; 64] = *final_sig.as_ref();
    println!("Signature: {}", hex::encode(&sig_bytes));
    
    // Step 8: Attach witness and extract tx
    use bitcoin::Witness;
    let mut witness = Witness::new();
    witness.push(&sig_bytes);
    psbt.inputs[0].final_script_witness = Some(witness);
    
    let signed_tx = psbt.extract_tx().expect("extract tx");
    let signed_hex = hex::encode(serialize(&signed_tx));
    
    println!("\n✅ Signed transaction:");
    println!("{}", signed_hex);
    println!("\nTXID: {}", signed_tx.compute_txid());
    println!("Size: {} bytes", serialize(&signed_tx).len());
    
    println!("\n📡 Broadcast command:");
    println!("bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 sendrawtransaction {}", signed_hex);
}


