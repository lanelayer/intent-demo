//! Solver wire protocol stub
//!
//! This module defines the interface for MuSig2 message exchange between
//! the user (browser) and solver (server). The Loopback implementation
//! is for local testing; replace with real networking (WebSocket/HTTP) in production.

use serde::{Deserialize, Serialize};

/// Nonce commitment: H(R)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceCommit(pub [u8; 32]);

/// Nonce reveal: R (serialized public nonce)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceReveal(pub Vec<u8>);

/// Partial signature: s_i
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSig(pub Vec<u8>);

/// Wire protocol for MuSig2 signing session
#[async_trait::async_trait]
pub trait SolverWire {
    async fn send_commit(&mut self, c: NonceCommit);
    async fn recv_commit(&mut self) -> NonceCommit;

    async fn send_reveal(&mut self, r: NonceReveal);
    async fn recv_reveal(&mut self) -> NonceReveal;

    async fn send_partial(&mut self, s: PartialSig);
    async fn recv_partial(&mut self) -> PartialSig;
}

/// Local loopback stub for demos (replace with network later)
pub struct Loopback {
    inbox_commit: Option<NonceCommit>,
    inbox_reveal: Option<NonceReveal>,
    inbox_partial: Option<PartialSig>,
}

impl Loopback {
    pub fn new() -> Self {
        Self {
            inbox_commit: None,
            inbox_reveal: None,
            inbox_partial: None,
        }
    }
}

impl Default for Loopback {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SolverWire for Loopback {
    async fn send_commit(&mut self, c: NonceCommit) {
        self.inbox_commit = Some(c);
    }
    
    async fn recv_commit(&mut self) -> NonceCommit {
        self.inbox_commit.take().expect("commit")
    }

    async fn send_reveal(&mut self, r: NonceReveal) {
        self.inbox_reveal = Some(r);
    }
    
    async fn recv_reveal(&mut self) -> NonceReveal {
        self.inbox_reveal.take().expect("reveal")
    }

    async fn send_partial(&mut self, s: PartialSig) {
        self.inbox_partial = Some(s);
    }
    
    async fn recv_partial(&mut self) -> PartialSig {
        self.inbox_partial.take().expect("partial")
    }
}

#[cfg(test)]
pub struct MockSolverWire {
    keypair: secp256k1::Keypair,
    key_agg_cache: secp256k1::musig::KeyAggCache,
    their_commit: Option<NonceCommit>,
    their_reveal: Option<NonceReveal>,
    their_partial: Option<PartialSig>,
}

#[cfg(test)]
impl MockSolverWire {
    pub fn new(keypair: secp256k1::Keypair, key_agg_cache: secp256k1::musig::KeyAggCache) -> Self {
        Self {
            keypair,
            key_agg_cache,
            their_commit: None,
            their_reveal: None,
            their_partial: None,
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl SolverWire for MockSolverWire {
    async fn send_commit(&mut self, c: NonceCommit) {
        self.their_commit = Some(c);
    }
    
    async fn recv_commit(&mut self) -> NonceCommit {
        // For testing, just echo back a dummy commit
        NonceCommit([0x42; 32])
    }

    async fn send_reveal(&mut self, r: NonceReveal) {
        self.their_reveal = Some(r);
    }
    
    async fn recv_reveal(&mut self) -> NonceReveal {
        // For testing, return a valid nonce
        let mut rng = secp256k1::rand::rng();
        let session_rand = secp256k1::musig::SessionSecretRand::from_rng(&mut rng);
        let msg = [0u8; 32]; // dummy message
        let (_sec, pub_nonce) = self.key_agg_cache.nonce_gen(
            session_rand,
            self.keypair.public_key(),
            &msg,
            None
        );
        NonceReveal(pub_nonce.serialize().to_vec())
    }

    async fn send_partial(&mut self, s: PartialSig) {
        self.their_partial = Some(s);
    }
    
    async fn recv_partial(&mut self) -> PartialSig {
        // For testing, return a dummy partial sig
        PartialSig(vec![0x42; 32])
    }
}

