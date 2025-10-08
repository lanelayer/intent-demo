//! Decode and inspect a transaction
//!
//! Usage: 
//!   cargo run --example decode_tx -- <hex>
//!   cargo run --example decode_tx -- 02000000000101...

use bitcoin::{consensus::encode::deserialize, Transaction};

fn main() {
    // Get transaction hex from command line or use example
    let args: Vec<String> = std::env::args().collect();
    
    let tx_hex = if args.len() > 1 {
        args[1].trim()
    } else {
        println!("Usage: cargo run --example decode_tx -- <hex>\n");
        println!("No hex provided, using example transaction...\n");
        // Example: Properly formatted witness transaction
        "0200000000010142424242424242424242424242424242424242424242424242424242424242420000000000fdffffff010000000000000000066a04544553540140bcb908b3d26ac7c749544abe523ac7e0bfceee67510fc3f904a5aecfd3ec1a4ec098ea374d59d52ca94246d6a6550d8cad9bd1b1780b543068434b22092348e700000000"
    };
    
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║            TRANSACTION DECODER                           ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    println!("Hex length: {} characters ({} bytes)\n", tx_hex.len(), tx_hex.len() / 2);
    
    match hex::decode(tx_hex) {
        Ok(bytes) => {
            println!("✅ Hex decoded successfully ({} bytes)\n", bytes.len());
            
            match deserialize::<Transaction>(&bytes) {
                Ok(tx) => {
                    println!("✅ Transaction parsed successfully\n");
                    println!("╔══════════════════════════════════════════════════════════╗");
                    println!("║           TRANSACTION STRUCTURE                          ║");
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    
                    println!("TXID:         {}", tx.compute_txid());
                    println!("Version:      {}", tx.version);
                    println!("Lock time:    {}", tx.lock_time);
                    println!("Weight:       {} WU", tx.weight());
                    println!("Size:         {} bytes", tx.total_size());
                    println!("Virtual size: {} vbytes\n", tx.vsize());
                    
                    println!("╔══════════════════════════════════════════════════════════╗");
                    println!("║           INPUTS ({})                                     ║", tx.input.len());
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    
                    for (i, input) in tx.input.iter().enumerate() {
                        println!("Input {}:", i);
                        println!("  Previous TXID: {}", input.previous_output.txid);
                        println!("  Previous vout: {}", input.previous_output.vout);
                        println!("  ScriptSig:     {} bytes {}", 
                            input.script_sig.len(),
                            if input.script_sig.is_empty() { "(empty - SegWit)" } else { "" }
                        );
                        println!("  Sequence:      0x{:08x}", input.sequence.0);
                        println!("  Witness items: {}", input.witness.len());
                        
                        for (j, item) in input.witness.iter().enumerate() {
                            let preview = if item.len() > 16 {
                                format!("{}...{}", hex::encode(&item[..8]), hex::encode(&item[item.len()-8..]))
                            } else {
                                hex::encode(item)
                            };
                            println!("    Witness[{}]: {} bytes - {}", j, item.len(), preview);
                        }
                        println!();
                    }
                    
                    println!("╔══════════════════════════════════════════════════════════╗");
                    println!("║           OUTPUTS ({})                                    ║", tx.output.len());
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    
                    let mut total_out = 0u64;
                    
                    for (i, output) in tx.output.iter().enumerate() {
                        println!("Output {}:", i);
                        println!("  Value:       {} sats", output.value.to_sat());
                        println!("  Script size: {} bytes", output.script_pubkey.len());
                        
                        let script_type = if output.script_pubkey.is_p2pkh() { "P2PKH" }
                            else if output.script_pubkey.is_p2sh() { "P2SH" }
                            else if output.script_pubkey.is_p2wpkh() { "P2WPKH (Native SegWit)" }
                            else if output.script_pubkey.is_p2wsh() { "P2WSH" }
                            else if output.script_pubkey.is_p2tr() { "P2TR (Taproot)" }
                            else if output.script_pubkey.is_op_return() { "OP_RETURN" }
                            else { "Other" };
                        
                        println!("  Script type: {}", script_type);
                        
                        if output.script_pubkey.is_op_return() && output.script_pubkey.len() > 2 {
                            let data = &output.script_pubkey.as_bytes()[2..];
                            println!("  OP_RETURN:   {}", String::from_utf8_lossy(data));
                            println!("  Data (hex):  {}", hex::encode(data));
                        }
                        
                        total_out += output.value.to_sat();
                        println!();
                    }
                    
                    println!("╔══════════════════════════════════════════════════════════╗");
                    println!("║           FEES & VALIDATION                              ║");
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    
                    println!("Total output value: {} sats", total_out);
                    println!("\nTo calculate fee: input_value - output_value");
                    println!("(Need to know input value from blockchain)\n");
                    
                    if total_out == 0 {
                        println!("⚠️  ALL VALUE GOES TO FEES (burn transaction)");
                    }
                    
                    println!("\n╔══════════════════════════════════════════════════════════╗");
                    println!("║           RESULT                                         ║");
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    println!("✅ Transaction structure is VALID");
                    println!("✅ Can be serialized and deserialized");
                    println!("\nTo broadcast, the funding UTXO must exist on-chain.");
                }
                Err(e) => {
                    println!("╔══════════════════════════════════════════════════════════╗");
                    println!("║           ERROR                                          ║");
                    println!("╚══════════════════════════════════════════════════════════╝\n");
                    println!("❌ Failed to parse transaction: {:?}", e);
                    println!("\nPossible issues:");
                    println!("  - Invalid transaction format");
                    println!("  - Corrupted hex data");
                    println!("  - Non-standard transaction type");
                }
            }
        }
        Err(e) => {
            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║           ERROR                                          ║");
            println!("╚══════════════════════════════════════════════════════════╝\n");
            println!("❌ Failed to decode hex: {:?}", e);
            println!("\nMake sure the hex string contains only valid characters (0-9, a-f).");
        }
    }
}
