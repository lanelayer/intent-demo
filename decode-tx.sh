#!/bin/bash
# Transaction decoder wrapper
# Usage: ./decode-tx.sh <hex>

if [ -z "$1" ]; then
    echo "Usage: ./decode-tx.sh <transaction_hex>"
    echo ""
    echo "Example:"
    echo "  ./decode-tx.sh 020000000001014242..."
    echo ""
    cargo run --example decode_tx --target x86_64-unknown-linux-gnu 2>/dev/null
else
    cargo run --example decode_tx --target x86_64-unknown-linux-gnu -- "$1" 2>/dev/null
fi
