//! End-to-end demo
//!
//! Demonstrates:
//! 1. Generate ephemeral keypairs (user + solver)
//! 2. Create P2TR funding address
//! 3. Build and pre-sign burn PSBT (OP_RETURN)
//! 4. Build and sign payout PSBT (cooperative)

use bitcoin::{Amount, Network, OutPoint, Txid, TxOut};
use secp256k1::{Keypair, Secp256k1};

use crate::solver_stub::Loopback;
use crate::tx::{
    build_burn_psbt, build_funding_address, build_payout_psbt, taproot_keyspend_sighash,
};

pub async fn run_demo() {
    println!("=== P2TR + MuSig2 Demo ===\n");

    let _secp = Secp256k1::new();

    // 1) Per-intent ephemeral keys (you'll import real x-only pubkeys in production)
    let mut rng = secp256k1::rand::rng();
    let user_kp = Keypair::new(&mut rng);
    let solver_kp = Keypair::new(&mut rng);
    let (user_x, _) = user_kp.x_only_public_key();
    let (solver_x, _) = solver_kp.x_only_public_key();

    println!("User pubkey:   {}", hex::encode(user_x.serialize()));
    println!("Solver pubkey: {}\n", hex::encode(solver_x.serialize()));

    // Optional commit: sha256(intent_bytes)
    let intent_commit: Option<[u8; 32]> = None;

    // 2) Build funding address
    let funding_info =
        build_funding_address(&user_x, &solver_x, intent_commit.as_ref(), Network::Testnet)
            .expect("funding address");

    println!("Funding address: {}", funding_info.address);
    println!(
        "Aggregated pubkey: {}\n",
        hex::encode(funding_info.agg_pk.serialize())
    );

    // Simulate: User broadcasts funding tx and it confirms with this UTXO
    let funding_outpoint = OutPoint {
        txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([1u8; 32])),
        vout: 0,
    };
    let funding_value = Amount::from_sat(20_000);

    // Prevout for sighash
    let prevout = TxOut {
        value: funding_value,
        script_pubkey: funding_info.address.script_pubkey(),
    };

    // 3) Pre-sign BURN PSBT
    println!("--- Building Burn PSBT ---");
    let burn_psbt =
        build_burn_psbt(funding_outpoint, funding_value, b"TAG||INTENT_HASH").expect("burn psbt");

    // Sighash for key-path with ANYONECANPAY
    let burn_sighash = taproot_keyspend_sighash(
        &burn_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
    )
    .expect("burn sighash");

    println!("Burn sighash: {}", hex::encode(burn_sighash));

    // MuSig2 sign (simulating both parties locally)
    // In production: user and solver run this in parallel over network
    let _wire = Loopback::new();
    
    // TODO: In a real implementation, this would involve actual network communication
    // For now, we skip the actual signing since Loopback doesn't simulate two separate parties
    println!("Note: Full MuSig2 signing requires two separate parties.");
    println!("In this demo, we'd need to simulate both user and solver signing.\n");

    // 4) Cooperative payout PSBT
    println!("--- Building Payout PSBT ---");
    let payout_addr = funding_info.address.clone(); // In practice: solver's payout address
    let payout_value = Amount::from_sat(18_000); // 2000 sats for fee

    let payout_psbt = build_payout_psbt(
        funding_outpoint,
        funding_value,
        payout_addr.script_pubkey(),
        payout_value,
    )
    .expect("payout psbt");

    // Sighash (ALL)
    let payout_sighash = taproot_keyspend_sighash(
        &payout_psbt,
        &prevout,
        bitcoin::sighash::TapSighashType::All,
    )
    .expect("payout sighash");

    println!("Payout sighash: {}", hex::encode(payout_sighash));
    println!("\n=== Demo Complete ===");
    println!("\nNext steps:");
    println!("1. Implement real SolverWire (WebSocket/HTTP)");
    println!("2. Run user and solver in separate processes");
    println!("3. Complete MuSig2 signing with nonce exchange");
    println!("4. Broadcast signed transactions to Bitcoin network");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_demo() {
        run_demo().await;
    }
}

