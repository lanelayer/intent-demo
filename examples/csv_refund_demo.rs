//! CSV Refund Leaf Demo
//!
//! This example demonstrates the new CSV refund leaf architecture where:
//! - User can cooperate with solver for fast payout (key-path)
//! - User can get refund UNILATERALLY after Δ blocks (script-path)
//! - No pre-signing required!
//! - No txid dependency!
//!
//! Run with: cargo run --example csv_refund_demo

use bitcoin::consensus::encode::serialize;
use bitcoin::{Amount, Network, OutPoint, Txid, TxOut};
use secp256k1::{Keypair, PublicKey, Secp256k1};
use wasm_helper::crypto::{aggregate_pubkeys, build_tr_with_refund_leaf, refund_leaf_script};
use wasm_helper::refund_leaf::{attach_refund_witness, sign_refund_leaf};
use wasm_helper::tx_build::{build_payout_psbt, build_unilateral_refund_tx};

fn main() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  CSV Refund Leaf Demo                                ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();

    // Generate keys
    println!("1️⃣  Generating keys...");
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);
    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();
    
    println!("   User:   {}", hex::encode(user_x.serialize()));
    println!("   Solver: {}", hex::encode(solver_x.serialize()));

    // Aggregate keys
    println!("\n2️⃣  Aggregating keys (MuSig2)...");
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();
    println!("   Aggregated: {}", hex::encode(agg_x.serialize()));

    // Create refund leaf
    let csv_delta = 144; // ~1 day
    println!("\n3️⃣  Creating CSV refund leaf (Δ = {} blocks)...", csv_delta);
    let refund_script = refund_leaf_script(user_x, csv_delta);
    println!("   Script: {}", hex::encode(refund_script.as_bytes()));

    // Build taproot address
    println!("\n4️⃣  Building Taproot address...");
    let tr = build_tr_with_refund_leaf(&secp, agg_x, refund_script.clone(), Network::Regtest)
        .expect("build taproot");
    
    println!("\n   ✅ SEND FUNDS TO: {}", tr.address);
    println!("   📝 This address supports:");
    println!("      • Cooperative payout (key-path, both signatures)");
    println!("      • Unilateral refund (script-path, user only, after Δ)");

    // Simulate funding
    let funding_txid = Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x42; 32]));
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: 0,
    };
    let funding_value = Amount::from_sat(50_000);

    println!("\n5️⃣  Simulated funding: {} sats", funding_value.to_sat());

    let prevout = TxOut {
        value: funding_value,
        script_pubkey: tr.address.script_pubkey(),
    };

    // ═══════════════════════════════════════════════════════════
    // OPTION A: Cooperative Payout (Happy Path)
    // ═══════════════════════════════════════════════════════════
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  OPTION A: Cooperative Payout (Key-Path)            ║");
    println!("╚══════════════════════════════════════════════════════╝");

    let payout_value = Amount::from_sat(49_000); // 1000 sats fee
    let payout_psbt = build_payout_psbt(
        funding_outpoint,
        funding_value,
        tr.address.script_pubkey(), // In practice: solver's address
        payout_value,
    )
    .expect("payout psbt");

    println!("\n   ✅ Payout transaction created");
    println!("   Amount: {} sats", payout_value.to_sat());
    println!("   Fee:    {} sats", funding_value.to_sat() - payout_value.to_sat());
    println!("\n   📝 Next: Both parties sign via MuSig2");
    println!("      - Fast (no timelock)");
    println!("      - Private (key-path spend)");
    println!("      - Efficient (lower fees)");

    let payout_tx = payout_psbt.extract_tx().expect("extract");
    println!("\n   TXID: {}", payout_tx.compute_txid());
    println!("   Size: {} bytes", serialize(&payout_tx).len());

    // ═══════════════════════════════════════════════════════════
    // OPTION B: Unilateral Refund (Unhappy Path)
    // ═══════════════════════════════════════════════════════════
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  OPTION B: Unilateral Refund (Script-Path)          ║");
    println!("╚══════════════════════════════════════════════════════╝");

    let refund_value = Amount::from_sat(49_500); // 500 sats fee
    let refund_tx_unsigned = build_unilateral_refund_tx(
        funding_outpoint,
        funding_value,
        csv_delta,
        tr.address.script_pubkey(), // In practice: user's wallet address
        refund_value,
    );

    println!("\n   ✅ Refund transaction created");
    println!("   Amount:    {} sats", refund_value.to_sat());
    println!("   Fee:       {} sats", funding_value.to_sat() - refund_value.to_sat());
    println!("   nSequence: {} (CSV delay)", csv_delta);

    // Sign with user's key ONLY
    println!("\n   🔐 Signing with USER KEY ONLY...");
    let sig = sign_refund_leaf(&secp, &user_kp, &refund_tx_unsigned, &prevout, &refund_script)
        .expect("sign refund");

    let refund_tx = attach_refund_witness(
        refund_tx_unsigned,
        sig,
        refund_script,
        tr.control_block_refund,
    );

    println!("   ✅ Signature created (Schnorr)");
    println!("\n   📝 This transaction can be broadcast AFTER {} blocks", csv_delta);
    println!("      - No solver signature needed!");
    println!("      - User has unilateral escape hatch");
    println!("      - No pre-signing required");

    println!("\n   TXID: {}", refund_tx.compute_txid());
    println!("   Size: {} bytes", serialize(&refund_tx).len());
    println!("   Witness items: {}", refund_tx.input[0].witness.len());

    // Summary
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  SUMMARY                                             ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("📍 Funding Address:");
    println!("   {}\n", tr.address);

    println!("🔐 Security Properties:");
    println!("   ✅ User can ALWAYS get money back (after {} blocks)", csv_delta);
    println!("   ✅ No pre-signing required for refund");
    println!("   ✅ No txid dependency for refund");
    println!("   ✅ Solver incentivized to cooperate (or lose funds)");
    println!("   ✅ Both parties required before timelock expires\n");

    println!("🎯 Use Cases:");
    println!("   • Trustless escrow");
    println!("   • Payment channels");
    println!("   • Dispute resolution");
    println!("   • Atomic swaps");
    println!("   • Conditional payments\n");

    println!("📝 To broadcast on regtest:");
    println!("   # Fund the address");
    println!("   bitcoin-cli -regtest sendtoaddress {} 0.0005", tr.address);
    println!("\n   # For cooperative payout: both parties sign via MuSig2");
    println!("   # For refund: wait {} blocks, then broadcast refund tx\n", csv_delta);

    println!("✅ Demo complete!\n");
}


