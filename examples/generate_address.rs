//! Example: Generate P2TR funding address and pre-signed transactions
//!
//! Run with: cargo run --example generate_address

use bitcoin::{consensus::encode::serialize, Amount, Network, OutPoint, Txid};
use bitcoin::hashes::Hash;
use secp256k1::{Keypair, Secp256k1};
use wasm_helper::tx::{
    attach_keyspend_sig, build_burn_psbt, build_funding_address, build_payout_psbt,
    taproot_keyspend_sighash,
};

fn main() {
    println!("=== P2TR + MuSig2 Address Generation Example ===\n");

    let _secp = Secp256k1::new();

    // 1. Generate ephemeral keypairs for user and solver
    println!("1. Generating ephemeral keypairs...");
    let mut rng = secp256k1::rand::rng();
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);

    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();

    println!("   User pubkey:   {}", hex::encode(user_x.serialize()));
    println!("   Solver pubkey: {}", hex::encode(solver_x.serialize()));
    println!();

    // 2. Optional: Create intent commitment (privacy feature)
    let intent_data = b"Purchase request #12345 for 0.0002 BTC";
    let intent_hash = bitcoin::hashes::sha256::Hash::hash(intent_data);
    let intent_commit = intent_hash.to_byte_array();

    println!("2. Intent commitment (hidden in taptweak):");
    println!("   Intent: {:?}", std::str::from_utf8(intent_data).unwrap());
    println!("   Hash:   {}", hex::encode(intent_commit));
    println!();

    // 3. Generate P2TR funding address
    println!("3. Creating P2TR funding address...");
    let funding_info = build_funding_address(
        &user_x,
        &solver_x,
        Some(&intent_commit),
        Network::Testnet,
    )
    .expect("funding address");

    println!("   ✅ Funding Address: {}", funding_info.address);
    println!("   Aggregated Pubkey:  {}", hex::encode(funding_info.agg_pk.serialize()));
    println!();
    println!("   → User sends funds to this address");
    println!();

    // Simulate: User funded the address with 20,000 sats
    let funding_txid = Txid::from_raw_hash(
        bitcoin::hashes::Hash::from_byte_array([0x42; 32])
    ); // Example txid
    let funding_vout = 0;
    let funding_value = Amount::from_sat(20_000);

    println!("4. Simulated funding transaction:");
    println!("   TXID: {}", funding_txid);
    println!("   Vout: {}", funding_vout);
    println!("   Amount: {} sats", funding_value.to_sat());
    println!();

    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: funding_vout,
    };

    // 5. Build BURN PSBT (pre-signed BEFORE confirmation!)
    println!("5. Building BURN transaction (OP_RETURN)...");
    println!("   ⚠️  This MUST be signed BEFORE funding confirms!");
    println!();

    let burn_payload = format!("INTENT||{}", hex::encode(intent_commit));
    let burn_psbt = build_burn_psbt(
        funding_outpoint,
        funding_value,
        burn_payload.as_bytes(),
    )
    .expect("burn psbt");

    // Compute sighash for burn (ANYONECANPAY)
    let prevout = bitcoin::TxOut {
        value: funding_value,
        script_pubkey: funding_info.address.script_pubkey(),
    };

    let burn_sighash = taproot_keyspend_sighash(
        &burn_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    )
    .expect("burn sighash");

    println!("   Transaction Type: OP_RETURN (all value → fees)");
    println!("   Sighash Type: ALL|ANYONECANPAY");
    println!("   Sighash: {}", hex::encode(burn_sighash));
    println!();

    // Note: In real implementation, both parties would sign via MuSig2 here
    println!("   📝 Note: In production, user + solver sign via MuSig2:");
    println!("      - Exchange nonce commitments");
    println!("      - Reveal nonces");
    println!("      - Exchange partial signatures");
    println!("      - Aggregate into final signature");
    println!();

    // For demo, create a dummy signature (64 bytes of 0xAA)
    let dummy_burn_sig = [0xAA; 64];
    let signed_burn_psbt = attach_keyspend_sig(burn_psbt, dummy_burn_sig);
    let burn_tx = signed_burn_psbt.extract_tx().expect("extract burn tx");
    let burn_tx_hex = hex::encode(serialize(&burn_tx));

    println!("   ✅ Pre-signed Burn Transaction:");
    println!("      Hex: {}...", &burn_tx_hex[..80]);
    println!("      Full length: {} bytes", burn_tx_hex.len() / 2);
    println!("      TXID: {}", burn_tx.compute_txid());
    println!();
    println!("   💾 Store this transaction! Broadcaster can add fee input later.");
    println!();

    // 6. Build PAYOUT PSBT (cooperative spend)
    println!("6. Building PAYOUT transaction (cooperative)...");

    let solver_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" // Example testnet address
        .parse::<bitcoin::Address<_>>()
        .unwrap()
        .assume_checked();

    let fee_sats = 500;
    let payout_value = Amount::from_sat(funding_value.to_sat() - fee_sats);

    let payout_psbt = build_payout_psbt(
        funding_outpoint,
        funding_value,
        solver_address.script_pubkey(),
        payout_value,
    )
    .expect("payout psbt");

    let payout_sighash = taproot_keyspend_sighash(
        &payout_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::All,
    )
    .expect("payout sighash");

    println!("   Transaction Type: Cooperative Payout");
    println!("   Sighash Type: ALL");
    println!("   Sighash: {}", hex::encode(payout_sighash));
    println!("   Recipient: {}", solver_address);
    println!("   Amount: {} sats", payout_value.to_sat());
    println!("   Fee: {} sats", fee_sats);
    println!();

    // For demo, create a dummy signature
    let dummy_payout_sig = [0xBB; 64];
    let signed_payout_psbt = attach_keyspend_sig(payout_psbt, dummy_payout_sig);
    let payout_tx = signed_payout_psbt.extract_tx().expect("extract payout tx");
    let payout_tx_hex = hex::encode(serialize(&payout_tx));

    println!("   ✅ Signed Payout Transaction:");
    println!("      Hex: {}...", &payout_tx_hex[..80]);
    println!("      Full length: {} bytes", payout_tx_hex.len() / 2);
    println!("      TXID: {}", payout_tx.compute_txid());
    println!();

    // 7. Summary
    println!("=== SUMMARY ===\n");
    println!("📍 Funding Address:");
    println!("   {}", funding_info.address);
    println!();
    println!("🔥 Burn Path (Unhappy Case):");
    println!("   - Pre-signed with ANYONECANPAY");
    println!("   - Broadcaster can add fee input");
    println!("   - All {} sats → network fees", funding_value.to_sat());
    println!("   - Reveals intent on-chain: {}", burn_payload);
    println!();
    println!("💰 Payout Path (Happy Case):");
    println!("   - Cooperative spend to solver");
    println!("   - Clean key-path spend (private)");
    println!("   - Solver receives {} sats", payout_value.to_sat());
    println!();
    println!("🔐 Security Properties:");
    println!("   ✅ Burn tx signed BEFORE funding confirms");
    println!("   ✅ Intent committed in taptweak (privacy)");
    println!("   ✅ MuSig2 aggregation (looks like single-key)");
    println!("   ✅ Both parties required for any spend");
    println!();
    println!("📝 Next Steps:");
    println!("   1. User broadcasts funding tx to: {}", funding_info.address);
    println!("   2. Wait for confirmation");
    println!("   3. Execute payout (happy) OR broadcast burn (unhappy)");
    println!();
}

