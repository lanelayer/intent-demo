# Browser CSV Demo - User Flow

## Updated Flow (browser_csv_demo.html)

The demo now follows a simplified, linear flow that automatically generates the burn transaction:

---

## Step-by-Step Flow

### 1. **Intent Hash** (Pre-set)
- Intent hash is hardcoded: `0xdeadbeef`
- This will be revealed in the burn transaction

### 2. **Generate Keys**
- Click "Generate Keys"
- Creates ephemeral keypairs for user and solver
- Shows public keys

### 3. **Create Funding Address**
- Click "Create Address"
- Generates P2TR address with CSV refund leaf (Δ = 144 blocks)
- Shows funding address and CLI command to fund it

### 4. **Fund the Address**
```bash
# Example command (shown in the UI)
bitcoin-cli -regtest sendtoaddress bcrt1p... 0.0005
```

This will return a **funding TXID**.

### 5. **Enter Funding TXID**
- Paste the funding transaction ID into the input field
- **Automatic**: As soon as you paste a valid 64-character hex TXID, the burn transaction is automatically generated!

### 6. **Burn Transaction** (Auto-generated)
The demo automatically:
- Builds the burn transaction
- Displays the complete transaction hex
- Shows TXID, size, and intent revealed
- Provides copy button for easy copying
- Shows broadcast command

---

## What Changed

### Old Flow:
- Manual buttons for each path
- User had to click to build transactions
- Used dummy TXIDs

### New Flow:
✅ Intent hash shown upfront (0xdeadbeef)  
✅ Linear progression through steps  
✅ Input field for real funding TXID  
✅ **Automatic** burn transaction generation  
✅ Copy-paste ready transaction hex  

---

## Usage Example

### 1. Start the Server
```bash
./serve.sh
```

### 2. Open in Browser
```
http://localhost:8000/examples/browser_csv_demo.html
```

### 3. Follow the Steps

#### Generate Keys
Click "Generate Keys" button

#### Create Address
Click "Create Address" button

Copy the address shown, e.g.:
```
bcrt1pt0xqc47jmfgh8kyu4tllmjz806xpjy0jxj7has2y3l4vhmm0nc4qe7nlym
```

#### Fund the Address
```bash
bitcoin-cli -regtest sendtoaddress bcrt1pt0xqc47... 0.0005
```

This returns a TXID like:
```
a1b2c3d4e5f6...
```

#### Paste the TXID
- Paste the funding TXID into the input field
- **Boom!** Burn transaction appears automatically

#### Copy the Transaction
- Click the "📋 Copy" button
- Transaction hex is copied to clipboard
- Ready to broadcast!

---

## Key Features

### 🔄 Auto-Generation
The burn transaction is **automatically generated** when you paste a valid funding TXID. No button clicking needed!

### 📋 Copy-Paste Ready
The transaction hex has a copy button that copies to clipboard with visual feedback.

### ✅ Validation
The TXID input validates that you've entered exactly 64 hexadecimal characters before generating the transaction.

### 🎨 Visual Flow
Status indicators show which step you're on:
- ⚫ Pending (gray)
- 🔵 Active (blue, animated)
- 🟢 Complete (green)

---

## Intent Hash: 0xdeadbeef

The burn transaction will reveal:
```
INTENT||0xdeadbeef
```

This is committed to the blockchain as an OP_RETURN output.

---

## Technical Details

### Transaction Structure
```
Burn Transaction:
- 1 input: Funding UTXO
- 1 output: OP_RETURN with intent
- All sats go to fees
- Sighash: ALL|ANYONECANPAY
- Key-path spend (MuSig2)
```

### Why ANYONECANPAY?
The `ANYONECANPAY` flag allows a broadcaster to add additional inputs to cover the transaction fees, since all the funding goes to fees in the burn.

### CSV Refund Leaf
While the demo focuses on the burn path, the address also includes a CSV refund leaf that allows the user to unilaterally refund after 144 blocks.

---

## Broadcasting

### Copy the Transaction Hex
Click the copy button or manually copy the hex.

### Broadcast on Regtest
```bash
bitcoin-cli -regtest sendrawtransaction <hex>
```

The command is also shown in the UI for convenience.

---

## Troubleshooting

### TXID not recognized
- Ensure it's exactly 64 characters
- Must be hexadecimal (0-9, a-f)
- No spaces or special characters

### Burn card doesn't appear
- Check browser console for errors
- Ensure WASM is loaded correctly
- Verify TXID is valid

### Can't copy to clipboard
- Some browsers require HTTPS for clipboard API
- Alternative: manually select and copy the text

---

## Next Steps

After the burn transaction:

1. **Broadcast it** if you want to reveal the intent on-chain
2. **Or** use the cooperative payout path (requires both signatures)
3. **Or** wait 144 blocks and use the unilateral refund (user-only)

---

## Architecture

This demo showcases the **CSV Refund Leaf** architecture where:
- ✅ User can always get money back (after Δ blocks)
- ✅ No pre-signing required
- ✅ No txid dependency
- ✅ Three spending paths available

For more details, see:
- `REFACTORING_SUMMARY.md` - Architecture overview
- `BROWSER_DEMOS.md` - All browser demos
- `UPDATE_SUMMARY.md` - Complete update summary

---

Enjoy the streamlined flow! 🚀


