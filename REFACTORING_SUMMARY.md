# Refactoring Summary: CSV Refund Leaf Architecture

## Overview

The codebase has been refactored from a simple 2-of-2 MuSig2 key-path spend to a more robust **Taproot + CSV Refund Leaf** architecture. This eliminates the need for pre-signing and txid dependencies for refunds.

## New Architecture

### Three Spending Paths

1. **Cooperative Payout (Key-Path, MuSig2)**
   - Requires: User + Solver signatures
   - Fast, private, efficient
   - Best case scenario

2. **Optional Burn (Key-Path, MuSig2)**
   - Requires: User + Solver signatures
   - Can be signed AFTER funding confirms
   - Reveals intent on-chain via OP_RETURN
   - Used for dispute markers

3. **Unilateral Refund (Script-Path, CSV)**
   - Requires: User signature ONLY
   - Available after Δ blocks (e.g., 144 blocks ≈ 1 day)
   - **No pre-signing required!**
   - **No txid dependency!**
   - Safety net for users

## File Structure

### New Files Created

- **`src/sighash.rs`** - Sighash helpers for key-path and script-path spends
- **`src/musig.rs`** - Cooperative MuSig2 signing flow
- **`src/refund_leaf.rs`** - Script-path CSV refund signing
- **`src/tx_build.rs`** - Transaction builders (replaces `tx.rs`)

### Modified Files

- **`src/crypto.rs`** - Added:
  - `refund_leaf_script()` - Creates CSV refund script
  - `build_tr_with_refund_leaf()` - Builds taproot address with refund leaf
  - `TrWithRefund` struct

- **`src/lib.rs`** - Exports new modules
- **`src/demo.rs`** - Updated to demonstrate all three spending paths
- **`src/solver_stub.rs`** - Added `MockSolverWire` for testing

### Legacy Support

- `src/tx.rs` is kept as `tx_legacy` for backwards compatibility
- All existing examples will continue to work
- WASM bindings remain unchanged

## Key Functions

### Crypto Functions

```rust
// Create CSV refund script
pub fn refund_leaf_script(user_x: XOnlyPublicKey, csv_delta_blocks: u32) -> ScriptBuf

// Build taproot with refund leaf
pub fn build_tr_with_refund_leaf(
    secp: &Secp256k1<All>,
    agg_x: XOnlyPublicKey,
    refund_script: ScriptBuf,
    network: Network,
) -> Result<TrWithRefund>
```

### Transaction Builders

```rust
// Cooperative payout (key-path)
pub fn build_payout_psbt(...) -> Result<Psbt>

// Optional burn (key-path)
pub fn build_burn_psbt(...) -> Result<Psbt>

// Unilateral refund (script-path, CSV)
pub fn build_unilateral_refund_tx(...) -> Transaction
```

### Signing

```rust
// Key-path cooperative signing (MuSig2)
pub async fn musig2_sign_keypath<W: SolverWire>(...) -> Result<[u8; 64]>

// Script-path refund signing (user only)
pub fn sign_refund_leaf(...) -> Result<[u8; 64]>

// Attach refund witness
pub fn attach_refund_witness(...) -> Transaction
```

## Usage Flow

### 1. Setup

```rust
// Generate keys
let user_kp = Keypair::new(&mut rng);
let solver_kp = Keypair::new(&mut rng);

// Aggregate with MuSig2
let agg_x = key_agg_cache.agg_pk();

// Create refund leaf
let refund_script = refund_leaf_script(user_x, 144);

// Build address
let tr = build_tr_with_refund_leaf(&secp, agg_x, refund_script, Network::Regtest)?;
```

### 2. Fund Address

```bash
bitcoin-cli -regtest sendtoaddress bcrt1p... 0.0002
```

### 3. Spend (Three Options)

#### Option A: Cooperative Payout

```rust
let payout_psbt = build_payout_psbt(...)?;
let sig = musig2_sign_keypath(&secp, &user_kp, &key_agg_cache, &payout_psbt, ...)?;
let signed = attach_keyspend_sig(payout_psbt, sig);
```

#### Option B: Burn (After Funding)

```rust
let burn_psbt = build_burn_psbt(..., b"DISPUTE_MARKER")?;
let sig = musig2_sign_keypath(..., TapSighashType::AllPlusAnyoneCanPay, ...)?;
```

#### Option C: Unilateral Refund (After Δ Blocks)

```rust
let refund_tx = build_unilateral_refund_tx(..., csv_delta, ...);
let sig = sign_refund_leaf(&secp, &user_kp, &refund_tx, ...)?;
let signed = attach_refund_witness(refund_tx, sig, refund_script, control_block);
```

## Security Properties

✅ **User Safety**
- User can ALWAYS get money back after Δ blocks
- No pre-signing required for refund
- No txid dependency for refund

✅ **Privacy**
- Key-path spends look like single-key spends
- Only script-path reveals the refund leaf

✅ **Cooperation**
- Both parties required for spends before Δ
- Solver incentivized to cooperate (or lose funds)

## Network Configuration

All examples and addresses are now configured for **regtest**:
- Addresses start with `bcrt1p...`
- Examples use `Network::Regtest`
- Browser demos generate regtest addresses

## Running the Demo

```bash
# Run the demo showing all three paths
cargo test --features demo run_demo -- --nocapture

# Build WASM
wasm-pack build --target web --out-dir pkg

# Serve browser demo
./serve.sh
# Open: http://localhost:8000/examples/browser_demo.html
```

## Schnorr Signing

✅ **Fully Implemented**

The `sign_refund_leaf()` function uses proper Schnorr signing via the secp256k1 git version:

```rust
pub fn sign_refund_leaf(..., user_kp: &Keypair, ...) -> Result<[u8; 64]> {
    let sighash = scriptspend_sighash(tx, prevout, refund_leaf_script)?;
    let sig = user_kp.sign_schnorr(&sighash);  // ✅ Real Schnorr signature!
    Ok(*sig.as_ref())
}
```

The git version of secp256k1 (v0.31.1) has `sign_schnorr()` directly on the `Keypair` type, making single-key Schnorr signatures straightforward.

## Testing

```bash
# Run all tests
cargo test

# Run demo
cargo test --features demo -- --nocapture

# Build examples
cargo build --examples

# Run example
cargo run --example full_musig2_signing
```

## Migration Guide

### For Existing Code

The old API is still available via `tx_legacy`:

```rust
use wasm_helper::tx_legacy::*;
// Old code continues to work
```

### For New Code

Use the new modules:

```rust
use wasm_helper::{
    crypto::{build_tr_with_refund_leaf, refund_leaf_script},
    tx_build::{build_payout_psbt, build_burn_psbt, build_unilateral_refund_tx},
    musig::musig2_sign_keypath,
    refund_leaf::{sign_refund_leaf, attach_refund_witness},
};
```

## Next Steps

1. ✅ Core architecture implemented
2. ✅ Regtest configuration applied
3. ✅ WASM builds successfully
4. 🔲 Complete Schnorr signing in refund_leaf.rs
5. 🔲 Update browser demo to use new architecture
6. 🔲 Add real network communication for MuSig2
7. 🔲 Implement fee estimation
8. 🔲 Add RBF support

## Questions?

The architecture is based on the specification you provided. Key benefits:

- **No pre-signing for refunds** - User can always get money back
- **No txid dependency** - Refund doesn't depend on funding txid
- **Three clear spending paths** - Cooperative, Burn, Refund
- **Better UX** - User has unilateral escape hatch after Δ

Perfect for trustless escrow, payment channels, and dispute resolution systems!

