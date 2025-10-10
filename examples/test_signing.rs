//! Test CSV refund address creation and signing natively
//!
//! Run with: cargo run --target x86_64-unknown-linux-gnu --example test_signing

use bitcoin::consensus::encode::serialize;
use bitcoin::{Amount, Network, OutPoint, Txid, TxOut};
use secp256k1::{Keypair, PublicKey, Secp256k1};
use wasm_helper::crypto::{aggregate_pubkeys, build_tr_with_refund_leaf, refund_leaf_script};
use wasm_helper::sighash::keyspend_sighash;
use wasm_helper::tx_build::{attach_keyspend_sig, build_burn_psbt};

fn main() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  Native Signing Test                                ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();

    // Generate keys
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);
    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();

    println!("1️⃣  Keys Generated:");
    println!("   User pubkey:   {}", hex::encode(user_x.serialize()));
    println!("   Solver pubkey: {}", hex::encode(solver_x.serialize()));

    // Aggregate keys
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    
    println!("\n2️⃣  Key Aggregation:");
    println!("   User full pk:   {}", hex::encode(user_pk.serialize()));
    println!("   Solver full pk: {}", hex::encode(solver_pk.serialize()));
    
    let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();
    
    println!("   Aggregated (internal_key): {}", hex::encode(agg_x.serialize()));

    // Create refund script
    let csv_delta = 144;
    let refund_script = refund_leaf_script(user_x, csv_delta);

    // Build taproot address
    println!("\n3️⃣  Building Taproot Address:");
    let tr = build_tr_with_refund_leaf(&secp, agg_x, refund_script.clone(), Network::Regtest)
        .expect("build taproot");

    println!("   Internal key (from tr): {}", hex::encode(tr.internal_key.serialize()));
    println!("   Output key (tweaked):   {}", hex::encode(tr.output_key.serialize()));
    println!("   Address: {}", tr.address);
    
    if let Some(merkle_root) = tr.merkle_root {
        use bitcoin::hashes::Hash;
        println!("   Merkle root: {}", hex::encode(merkle_root.to_byte_array()));
    }

    // Check if keys match
    println!("\n4️⃣  Validation:");
    if tr.internal_key.serialize() == agg_x.serialize() {
        println!("   ✅ Internal keys match!");
    } else {
        println!("   ❌ Internal keys DON'T match!");
        println!("      Expected: {}", hex::encode(tr.internal_key.serialize()));
        println!("      Got:      {}", hex::encode(agg_x.serialize()));
    }

    // Simulate funding
    let funding_txid = Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x42; 32]));
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: 1,
    };
    let funding_value = Amount::from_sat(50_000);

    let prevout = TxOut {
        value: funding_value,
        script_pubkey: tr.address.script_pubkey(),
    };

    // Build burn PSBT
    println!("\n5️⃣  Building Burn Transaction:");
    let burn_psbt = build_burn_psbt(funding_outpoint, funding_value, b"INTENT||0xdeadbeef")
        .expect("burn psbt");

    let sighash = keyspend_sighash(
        &burn_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    )
    .expect("sighash");

    println!("   Sighash: {}", hex::encode(sighash));

    // MuSig2 signing
    println!("\n6️⃣  MuSig2 Signing:");
    
    use secp256k1::musig::{AggregatedNonce, Session, SessionSecretRand};
    
    // Apply taproot tweak to key_agg_cache
    let mut tweaked_cache = key_agg_cache;
    if let Some(merkle_root) = tr.merkle_root {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        use secp256k1::Scalar;
        
        // Compute taproot tweak
        let mut eng = sha256::Hash::engine();
        let tag = b"TapTweak";
        let tag_hash = sha256::Hash::hash(tag);
        eng.input(tag_hash.as_ref());
        eng.input(tag_hash.as_ref());
        eng.input(&agg_x.serialize());
        eng.input(&merkle_root.to_byte_array());
        let tweak_hash = sha256::Hash::from_engine(eng);
        let tweak_scalar = Scalar::from_be_bytes(tweak_hash.to_byte_array()).expect("scalar");
        
        println!("   Taproot tweak: {}", hex::encode(tweak_scalar.to_be_bytes()));
        
        tweaked_cache.pubkey_xonly_tweak_add(&tweak_scalar).expect("apply tweak");
        
        println!("   Tweaked agg_pk: {}", hex::encode(tweaked_cache.agg_pk().serialize()));
        
        // Verify it matches output_key
        if tweaked_cache.agg_pk().serialize() == tr.output_key.serialize() {
            println!("   ✅ Tweaked key matches output_key!");
        } else {
            println!("   ❌ Tweaked key DOESN'T match output_key!");
            println!("      Expected: {}", hex::encode(tr.output_key.serialize()));
            println!("      Got:      {}", hex::encode(tweaked_cache.agg_pk().serialize()));
        }
    }
    
    // Generate nonces
    let user_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (user_sec_nonce, user_pub_nonce) = tweaked_cache.nonce_gen(
        user_session_rand,
        user_kp.public_key(),
        &sighash,
        None,
    );
    
    let solver_session_rand = SessionSecretRand::from_rng(&mut rng);
    let (solver_sec_nonce, solver_pub_nonce) = tweaked_cache.nonce_gen(
        solver_session_rand,
        solver_kp.public_key(),
        &sighash,
        None,
    );
    
    let agg_nonce = AggregatedNonce::new(&[&user_pub_nonce, &solver_pub_nonce]);
    let session = Session::new(&tweaked_cache, agg_nonce, &sighash);
    
    let user_partial = session.partial_sign(user_sec_nonce, &user_kp, &tweaked_cache);
    let solver_partial = session.partial_sign(solver_sec_nonce, &solver_kp, &tweaked_cache);
    
    let agg_sig = session.partial_sig_agg(&[&user_partial, &solver_partial]);
    let final_sig = agg_sig.verify(&tweaked_cache.agg_pk(), &sighash).expect("verify sig");
    
    println!("   ✅ Signature created and verified!");

    // Attach and extract
    let signed_psbt = attach_keyspend_sig(burn_psbt, *final_sig.as_ref());
    let signed_tx = signed_psbt.extract_tx().expect("extract");
    
    println!("\n7️⃣  Final Transaction:");
    println!("   TXID: {}", signed_tx.compute_txid());
    println!("   Size: {} bytes", serialize(&signed_tx).len());
    println!("   Witness items: {}", signed_tx.input[0].witness.len());
    println!("   Witness[0] size: {} bytes", signed_tx.input[0].witness[0].len());
    
    println!("\n✅ Native test complete!");
    println!("   The signature is valid for the tweaked key.");
    println!("   WASM should produce the same result.\n");
}

