//! P2TR + MuSig2 WASM Helper
//!
//! A minimal scaffold for P2TR address generation and MuSig2 signing
//! using the git version of secp256k1 (with musig module)

use wasm_bindgen::prelude::*;

pub mod crypto;
pub mod solver_stub;
pub mod tx;
pub mod types;

#[cfg(any(test, feature = "demo"))]
pub mod demo;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

// Re-export key types
pub use crypto::*;
pub use solver_stub::*;
pub use tx::*;
pub use types::*;

#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct MuSig2Helper {
    secp: secp256k1::Secp256k1<secp256k1::All>,
}

#[wasm_bindgen]
impl MuSig2Helper {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            secp: secp256k1::Secp256k1::new(),
        }
    }

    /// Generate a new keypair
    #[wasm_bindgen(js_name = generateKeypair)]
    pub fn generate_keypair(&self) -> Vec<u8> {
        let mut rng = secp256k1::rand::rng();
        let keypair = secp256k1::Keypair::new(&mut rng);
        keypair.secret_bytes().to_vec()
    }

    /// Get x-only public key from secret key (32 bytes)
    #[wasm_bindgen(js_name = getXOnlyPubkey)]
    pub fn get_xonly_pubkey(&self, secret_bytes: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
        if secret_bytes.len() != 32 {
            return Err(JsValue::from_str("Secret key must be 32 bytes"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(secret_bytes);
        let secret_key = secp256k1::SecretKey::from_secret_bytes(arr)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;

        let keypair = secp256k1::Keypair::from_secret_key(&secret_key);
        let (xonly, _) = keypair.x_only_public_key();

        Ok(xonly.serialize().to_vec())
    }

    /// Create a P2TR address from two x-only pubkeys (user + solver)
    #[wasm_bindgen(js_name = createFundingAddress)]
    pub fn create_funding_address(
        &self,
        user_pubkey: &[u8],
        solver_pubkey: &[u8],
        network: &str,
    ) -> std::result::Result<String, JsValue> {
        let net = match network {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "signet" => bitcoin::Network::Signet,
            "regtest" => bitcoin::Network::Regtest,
            _ => return Err(JsValue::from_str("Invalid network")),
        };

        let addr = crypto::create_funding_address(user_pubkey, solver_pubkey, None, net)
            .map_err(|e| JsValue::from_str(&e))?;

        Ok(addr.to_string())
    }
}

impl Default for MuSig2Helper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let helper = MuSig2Helper::new();
        let sk = helper.generate_keypair();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_xonly_pubkey() {
        let helper = MuSig2Helper::new();
        let sk = helper.generate_keypair();
        let pk = helper.get_xonly_pubkey(&sk).unwrap();
        assert_eq!(pk.len(), 32);
    }
}

