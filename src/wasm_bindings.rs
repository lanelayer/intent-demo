//! WASM bindings for P2TR + MuSig2 functionality
//!
//! This module provides JavaScript-friendly interfaces for:
//! - Funding address generation
//! - Transaction building
//! - MuSig2 signing flow

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use bitcoin::hashes::Hash;

use crate::tx::{build_burn_psbt, build_funding_address, build_payout_psbt};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Txid};
use bitcoin::consensus::encode::serialize;

#[derive(Serialize, Deserialize)]
pub struct FundingAddressInfo {
    pub address: String,
    pub agg_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct PsbtInfo {
    pub hex: String,
    pub txid: String,
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

    let funding = build_funding_address(
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

/// Build a burn PSBT (OP_RETURN)
#[wasm_bindgen(js_name = buildBurnPsbt)]
pub fn wasm_build_burn_psbt(
    txid_hex: &str,
    vout: u32,
    value_sats: u64,
    payload_hex: &str,
) -> Result<JsValue, JsValue> {
    // Parse txid
    let txid_bytes = hex::decode(txid_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid txid hex: {}", e)))?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("Txid must be 32 bytes"));
    }
    
    let txid = Txid::from_byte_array(
        txid_bytes.as_slice().try_into().unwrap()
    );

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
    // Parse txid
    let txid_bytes = hex::decode(txid_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid txid hex: {}", e)))?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("Txid must be 32 bytes"));
    }
    
    let txid = Txid::from_byte_array(
        txid_bytes.as_slice().try_into().unwrap()
    );

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
}


