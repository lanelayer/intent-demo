# Quick Start Guide

## Browser CSV Demo - Complete Flow

The browser demo now has **full MuSig2 signing** built in!

### 🚀 Start the Demo

```bash
./serve.sh
```

Open: **http://localhost:8000/examples/browser_csv_demo.html**

---

## 📋 Step-by-Step Flow

### 1. **Intent Hash** ✅
- Pre-set to `0xdeadbeef`
- Will be revealed in burn transaction

### 2. **Generate Keys** 🔑
- Click "Generate Keys"
- Creates user + solver keypairs
- Shows public keys

### 3. **Create Funding Address** 📍
- Click "Create Address"  
- Generates P2TR with CSV refund leaf (Δ = 144 blocks)
- Copy the funding command

### 4. **Fund the Address** 💰

```bash
bitcoin-cli -regtest sendtoaddress bcrt1p... 0.0005
```

This returns a **funding TXID**, e.g.:
```
116c9719a1a87dfe069903907f699f4d1fbc92496877f55193eed90b0cb7e999
```

### 5. **Check vout** 🔍

```bash
bitcoin-cli -regtest gettransaction 116c9719...
```

Look for `"vout": 1` (or 0) in the details.

### 6. **Paste TXID + vout** 📥
- Paste the funding TXID
- Set vout to 1 (or whatever the transaction shows)
- **Automatic magic happens!** ✨

### 7. **Burn Transaction Auto-Generated** 🔥

The demo automatically:
- ✅ Builds the unsigned burn transaction
- ✅ **Signs it with MuSig2** (both parties)
- ✅ Shows the **fully signed** transaction
- ✅ Provides copy button
- ✅ Shows broadcast command

### 8. **Copy & Broadcast** 📡

Click the copy button, then:

```bash
bitcoin-cli -regtest sendrawtransaction <hex>
```

**It will broadcast successfully!** ✅

---

## 🎯 What's New

### ✅ Real MuSig2 Signing

The demo now performs **actual MuSig2 signing**:
- Nonce generation
- Key aggregation
- Partial signatures
- Signature aggregation
- Verification

### ✅ Fully Signed Transactions

The burn transaction is **ready to broadcast**:
- Has proper witness (64-byte Schnorr signature)
- Valid for Bitcoin network
- Not just a demo - it's real!

### ✅ Automatic Flow

Once you paste the TXID:
1. Validates input
2. Builds unsigned transaction
3. **Signs with MuSig2**
4. Shows signed result

All automatic - no extra buttons!

---

## 🔐 Technical Details

### MuSig2 Signing Process

```javascript
// 1. Build unsigned PSBT
const unsignedPsbt = wasm.buildBurnPsbt(...)

// 2. Sign with both keys (MuSig2)
const signedTx = wasm.signBurnPsbtDemo(
    userSecretKey,
    solverSecretKey,
    unsignedPsbt.hex,
    fundingAddress,
    fundingAmount
)

// 3. Result: Fully signed transaction!
```

### What Happens Inside WASM

1. **Key Aggregation** - Combines user + solver keys
2. **Nonce Generation** - Both parties generate nonces
3. **Session Creation** - Creates MuSig2 session
4. **Partial Signing** - Each party creates partial signature
5. **Aggregation** - Combines into final 64-byte Schnorr sig
6. **Verification** - Verifies signature is valid
7. **Attachment** - Adds signature to transaction witness

### Transaction Structure

```
Unsigned:
  Input: [funding_txid:vout]
  Output: OP_RETURN "INTENT||0xdeadbeef"
  Witness: (empty)

Signed:
  Input: [funding_txid:vout]
  Output: OP_RETURN "INTENT||0xdeadbeef"
  Witness: [64-byte Schnorr signature] ✅
```

---

## 🎉 Success Criteria

✅ Transaction has witness data  
✅ Signature is 64 bytes  
✅ TXID changes after signing  
✅ Broadcasts successfully  
✅ Intent revealed on-chain  

---

## 🧪 Test It!

### Full Test Flow

1. Start server: `./serve.sh`
2. Open demo in browser
3. Click through steps 1-3
4. Fund the address on regtest
5. Paste real TXID + vout
6. **Watch it auto-generate and sign!**
7. Copy the hex
8. Broadcast to regtest
9. Check it on-chain! 🎊

### Expected Result

```bash
$ bitcoin-cli -regtest sendrawtransaction <hex>
<new_txid>  # Success! ✅
```

---

## 🔧 Troubleshooting

### "bad-txns-inputs-missingorspent"
- Check the vout is correct (usually 0 or 1)
- Ensure the funding transaction has confirmed
- Verify you're using the right TXID

### "Invalid signature"
- Keys might not match the address
- Try regenerating keys and creating new address

### Transaction not appearing
- Check browser console for errors
- Verify WASM loaded correctly
- Ensure all inputs are valid hex

---

## 📚 Documentation

- `BROWSER_CSV_FLOW.md` - Flow explanation
- `BROWSER_DEMOS.md` - All demos guide
- `REFACTORING_SUMMARY.md` - Architecture overview
- `UPDATE_SUMMARY.md` - Complete changes

---

## 🎊 You Now Have

✅ **Full CSV Refund Architecture**  
✅ **Real MuSig2 Signing**  
✅ **Working Browser Demo**  
✅ **Ready-to-Broadcast Transactions**  
✅ **Regtest Integration**  

Enjoy! 🚀


