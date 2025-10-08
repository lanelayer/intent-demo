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

