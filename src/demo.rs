//! End-to-end demo with CSV refund leaf
//!
//! Demonstrates:
//! 1. Generate ephemeral keypairs (user + solver)
//! 2. Create P2TR funding address with CSV refund leaf
//! 3. Three spending paths:
//!    a) Cooperative payout (key-path, MuSig2)
//!    b) Optional burn (key-path, MuSig2, after funding confirms)
//!    c) Unilateral refund (script-path, CSV, user-only after Δ blocks)

use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Txid, TxOut};
use bitcoin::consensus::encode::serialize;
use secp256k1::{Keypair, PublicKey, Secp256k1};

use crate::crypto::{aggregate_pubkeys, refund_leaf_script, build_tr_with_refund_leaf};
use crate::tx_build::{build_burn_psbt, build_payout_psbt, build_unilateral_refund_tx, attach_keyspend_sig};
use crate::refund_leaf::{sign_refund_leaf, attach_refund_witness};
use crate::sighash::keyspend_sighash;

pub async fn run_demo() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  P2TR + MuSig2 + CSV Refund Leaf Demo                    ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let secp = Secp256k1::new();
    let mut rng = secp256k1::rand::rng();

    // 1) Generate ephemeral keypairs
    println!("📍 Step 1: Generating ephemeral keypairs");
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);
    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();

    println!("   User pubkey:   {}", hex::encode(user_x.serialize()));
    println!("   Solver pubkey: {}", hex::encode(solver_x.serialize()));

    // 2) Aggregate keys with MuSig2
    println!("\n📍 Step 2: Aggregating keys with MuSig2");
    let user_pk = PublicKey::from_keypair(&user_kp);
    let solver_pk = PublicKey::from_keypair(&solver_kp);
    let key_agg_cache = aggregate_pubkeys(&[user_pk, solver_pk]);
    let agg_x = key_agg_cache.agg_pk();
    println!("   Aggregated key: {}", hex::encode(agg_x.serialize()));

    // 3) Create refund leaf script (CSV)
    println!("\n📍 Step 3: Creating CSV refund leaf");
    let csv_delta = 144; // ~1 day
    let refund_script = refund_leaf_script(user_x, csv_delta);
    println!("   CSV delay: {} blocks", csv_delta);
    println!("   Refund script: {}", hex::encode(refund_script.as_bytes()));

    // 4) Build Taproot address with refund leaf
    println!("\n📍 Step 4: Building Taproot address");
    let tr = build_tr_with_refund_leaf(
        &secp,
        agg_x,
        refund_script.clone(),
        Network::Regtest,
    ).expect("build taproot");

    println!("   ✅ Address: {}", tr.address);
    println!("   Output key: {}", hex::encode(tr.output_key.serialize()));

    // Simulate funding
    println!("\n📍 Step 5: Simulated funding transaction");
    let funding_outpoint = OutPoint {
        txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x42; 32])),
        vout: 0,
    };
    let funding_value = Amount::from_sat(20_000);
    println!("   TXID:   {}", funding_outpoint.txid);
    println!("   Amount: {} sats", funding_value.to_sat());

    let prevout = TxOut {
        value: funding_value,
        script_pubkey: tr.address.script_pubkey(),
    };

    // ============================================================
    // PATH A: Cooperative payout (key-path, MuSig2)
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  PATH A: Cooperative Payout (Key-Path)                   ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    let payout_addr = tr.address.clone(); // In practice: solver's address
    let payout_value = Amount::from_sat(18_500); // 1500 sats fee

    let payout_psbt = build_payout_psbt(
        funding_outpoint,
        funding_value,
        payout_addr.script_pubkey(),
        payout_value,
    ).expect("payout psbt");

    let payout_sighash = keyspend_sighash(
        &payout_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::All,
    ).expect("payout sighash");

    println!("\n   Building transaction...");
    println!("   Recipient: {}", payout_addr);
    println!("   Amount:    {} sats", payout_value.to_sat());
    println!("   Sighash:   {}", hex::encode(payout_sighash));
    println!("\n   📝 Note: In production, both parties sign via MuSig2");
    println!("      - Exchange nonce commitments");
    println!("      - Reveal nonces");
    println!("      - Exchange partial signatures");
    println!("      - Aggregate into final signature");

    // Dummy signature for demo
    let dummy_payout_sig = [0xBB; 64];
    let signed_payout_psbt = attach_keyspend_sig(payout_psbt, dummy_payout_sig);
    let payout_tx = signed_payout_psbt.extract_tx().expect("extract payout tx");
    let payout_tx_hex = hex::encode(serialize(&payout_tx));

    println!("\n   ✅ PAYOUT TRANSACTION (with dummy sig):");
    println!("      TXID: {}", payout_tx.compute_txid());
    println!("      Size: {} bytes", payout_tx_hex.len() / 2);

    // ============================================================
    // PATH B: Optional burn (key-path, MuSig2, after funding)
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  PATH B: Optional Burn (Key-Path, After Funding)         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    let burn_payload = b"INTENT||dispute_marker";
    let burn_psbt = build_burn_psbt(
        funding_outpoint,
        funding_value,
        burn_payload,
    ).expect("burn psbt");

    let burn_sighash = keyspend_sighash(
        &burn_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    ).expect("burn sighash");

    println!("\n   Building transaction...");
    println!("   Type:     OP_RETURN (all value → fees)");
    println!("   Sighash:  ALL|ANYONECANPAY");
    println!("   Payload:  {}", String::from_utf8_lossy(burn_payload));
    println!("   Sighash:  {}", hex::encode(burn_sighash));
    println!("\n   📝 Note: Can be co-signed AFTER funding confirms");
    println!("      Broadcaster can add fee inputs (ANYONECANPAY)");

    let dummy_burn_sig = [0xCC; 64];
    let signed_burn_psbt = attach_keyspend_sig(burn_psbt, dummy_burn_sig);
    let burn_tx = signed_burn_psbt.extract_tx().expect("extract burn tx");
    let burn_tx_hex = hex::encode(serialize(&burn_tx));

    println!("\n   ✅ BURN TRANSACTION (with dummy sig):");
    println!("      TXID: {}", burn_tx.compute_txid());
    println!("      Size: {} bytes", burn_tx_hex.len() / 2);

    // ============================================================
    // PATH C: Unilateral refund (script-path, CSV, user-only)
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  PATH C: Unilateral Refund (Script-Path, CSV)            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    let user_refund_addr = tr.address.clone(); // In practice: user's wallet address
    let refund_value = Amount::from_sat(19_400); // 600 sats fee

    let refund_tx_unsigned = build_unilateral_refund_tx(
        funding_outpoint,
        funding_value,
        csv_delta,
        user_refund_addr.script_pubkey(),
        refund_value,
    );

    println!("\n   Building transaction...");
    println!("   Type:      Script-path spend (CSV leaf)");
    println!("   Recipient: {}", user_refund_addr);
    println!("   Amount:    {} sats", refund_value.to_sat());
    println!("   nSequence: {} (CSV delay)", csv_delta);
    println!("\n   ⚠️  Can only be broadcast AFTER {} blocks!", csv_delta);
    println!("   ✅ User can sign UNILATERALLY (no solver needed)");

    // Sign with user's key only
    let sig_refund = sign_refund_leaf(
        &secp,
        &user_kp,
        &refund_tx_unsigned,
        &prevout,
        &refund_script,
    ).expect("sign refund");

    let refund_tx = attach_refund_witness(
        refund_tx_unsigned,
        sig_refund,
        refund_script,
        tr.control_block_refund,
    );

    let refund_tx_hex = hex::encode(serialize(&refund_tx));

    println!("\n   ✅ REFUND TRANSACTION (script-path):");
    println!("      TXID:       {}", refund_tx.compute_txid());
    println!("      Size:       {} bytes", refund_tx_hex.len() / 2);
    println!("      Witness:    {} items", refund_tx.input[0].witness.len());

    // ============================================================
    // SUMMARY
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  SUMMARY                                                  ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    println!("📍 Funding Address (P2TR with CSV refund leaf):");
    println!("   {}\n", tr.address);

    println!("🔐 Three Spending Paths:");
    println!("   A) Cooperative Payout (key-path)");
    println!("      - Requires: User + Solver (MuSig2)");
    println!("      - Fast, private, efficient");
    println!("   B) Optional Burn (key-path)");
    println!("      - Requires: User + Solver (MuSig2)");
    println!("      - After funding confirms");
    println!("      - Reveals intent on-chain");
    println!("   C) Unilateral Refund (script-path)");
    println!("      - Requires: User ONLY");
    println!("      - After {} blocks", csv_delta);
    println!("      - No pre-signing needed!");

    println!("\n✅ Security Properties:");
    println!("   • User can ALWAYS get money back (after Δ)");
    println!("   • No pre-signing required for refund");
    println!("   • No txid dependency for refund");
    println!("   • Key-path spends are private");
    println!("   • Both parties required before Δ");

    println!("\n📝 Next Steps:");
    println!("   1. Implement real MuSig2 wire protocol");
    println!("   2. Test on regtest network");
    println!("   3. Integrate with wallet software");
    println!("   4. Add fee estimation");

    println!("\n🎉 Demo Complete!\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_demo() {
        run_demo().await;
    }
}
