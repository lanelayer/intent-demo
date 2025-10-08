//! Type definitions and re-exports

pub use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, XOnlyPublicKey};
pub use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
pub use secp256k1::musig::{AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SecretNonce, Session, SessionSecretRand};

/// Result type for operations
pub type Result<T> = std::result::Result<T, String>;



