# Browser Demos

This project includes several browser-based demos to showcase the P2TR + MuSig2 functionality.

## Available Demos

### 1. **CSV Refund Demo** (NEW! ✨) - `browser_csv_demo.html`

**Modern demo with CSV refund leaf architecture**

- ✅ Uses the new `createRefundAddress()` WASM binding
- ✅ Shows all three spending paths:
  - **Path A**: Cooperative Payout (key-path, both signatures)
  - **Path B**: Optional Burn (key-path, both signatures, OP_RETURN)
  - **Path C**: Unilateral Refund (script-path, user only, CSV)
- ✅ Modern UI with status indicators
- ✅ Uses proper WASM bindings (no manual transaction construction)
- ✅ Demonstrates the safety properties of CSV refund

**URL**: `http://localhost:8000/examples/browser_csv_demo.html`

#### Key Features:
- User can ALWAYS get money back after Δ blocks
- No pre-signing required for refund
- No txid dependency for refund
- Three clear spending paths with visual cards

### 2. **Original Demo** - `browser_demo.html`

**Original demo (legacy architecture)**

- Uses simple P2TR without CSV refund leaf
- Manually constructs transactions
- Good for understanding the basics
- Still works, but doesn't demonstrate CSV refund

**URL**: `http://localhost:8000/examples/browser_demo.html`

### 3. **Simple Demo** - `browser.html`

**Minimal example**

- Basic P2TR address generation
- Simple transaction building
- Good starting point for learning

**URL**: `http://localhost:8000/examples/browser.html`

### 4. **Browser Example** - `browser-example.html`

**Another basic example**

- Similar to `browser.html`
- Alternative implementation

**URL**: `http://localhost:8000/examples/browser-example.html`

## Running the Demos

### Start the Server

```bash
./serve.sh
```

Or manually:

```bash
python3 -m http.server 8000
```

### Open in Browser

Navigate to:
- **NEW CSV Demo**: http://localhost:8000/examples/browser_csv_demo.html
- Original Demo: http://localhost:8000/examples/browser_demo.html
- Simple Demo: http://localhost:8000/examples/browser.html

## WASM API Reference

### New CSV Refund Functions

#### `createRefundAddress(userPubkeyHex, solverPubkeyHex, csvDelta, network)`

Creates a P2TR address with CSV refund leaf.

```javascript
const addressInfo = wasm.createRefundAddress(
    userPkHex,
    solverPkHex,
    144,        // CSV delta (blocks)
    'regtest'
);

// Returns:
// {
//   address: "bcrt1p...",
//   agg_pubkey: "...",
//   output_key: "...",
//   refund_script_hex: "...",
//   control_block_hex: "...",
//   csv_delta: 144
// }
```

#### `buildRefundTx(txidHex, vout, inputValueSats, csvDelta, outputAddress, outputValueSats)`

Builds an unsigned unilateral refund transaction.

```javascript
const tx = wasm.buildRefundTx(
    fundingTxid,
    0,
    50000,      // input amount
    144,        // CSV delta
    userAddress,
    49500       // output amount
);

// Returns:
// {
//   hex: "0200...",
//   txid: "...",
//   size: 236
// }
```

### Legacy Functions (still available)

- `createFundingAddress()` - Simple P2TR without CSV leaf
- `buildBurnPsbt()` - Build OP_RETURN transaction
- `buildPayoutPsbt()` - Build payout transaction
- `computeSighash()` - Compute taproot sighash

## Development

### Rebuild WASM

After modifying Rust code:

```bash
wasm-pack build --target web --out-dir pkg
```

### Update Bindings

WASM bindings are in: `src/wasm_bindings.rs`

## Comparison: Old vs New

| Feature | Old Demo | New CSV Demo |
|---------|----------|--------------|
| Architecture | Simple P2TR | P2TR + CSV Refund Leaf |
| User Safety | Pre-signing required | Unilateral refund after Δ |
| Txid Dependency | Yes (for pre-signed refund) | No (CSV leaf) |
| Spending Paths | 2 (payout, burn) | 3 (payout, burn, refund) |
| Transaction Construction | Manual hex | WASM bindings |
| UI | Basic | Modern with status |

## Security Properties (CSV Demo)

✅ **User Can Always Get Money Back** - After Δ blocks, user can refund unilaterally  
✅ **No Pre-Signing Required** - Refund doesn't need to be signed beforehand  
✅ **No Txid Dependency** - Refund works regardless of funding txid  
✅ **Solver Incentivized** - Must cooperate or user eventually refunds  
✅ **Privacy** - Key-path spends look like single-key spends  

## Use Cases

- Trustless escrow
- Payment channels
- Dispute resolution
- Atomic swaps
- Conditional payments
- Time-locked contracts

## Network Configuration

All demos are configured for **regtest**:
- Addresses start with `bcrt1p...`
- Use with local Bitcoin regtest node
- Perfect for testing without real funds

## Troubleshooting

### WASM not loading

1. Check browser console for errors
2. Ensure server is running on port 8000
3. Rebuild WASM if needed: `wasm-pack build --target web --out-dir pkg`

### Address format wrong

- Ensure network is set to 'regtest' for `bcrt1p...` addresses
- Use 'testnet' for `tb1p...` addresses
- Use 'mainnet' for `bc1p...` addresses

## Next Steps

1. Integrate with wallet software
2. Add real MuSig2 wire protocol (WebSocket/HTTP)
3. Implement fee estimation
4. Add RBF support
5. Create mobile-friendly version

---

For more information, see:
- `REFACTORING_SUMMARY.md` - Architecture overview
- `examples/csv_refund_demo.rs` - Native Rust example
- `src/wasm_bindings.rs` - WASM API implementation


