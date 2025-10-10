#!/bin/bash
# Helper script to run examples with the correct target
# Usage: ./run-example.sh csv_refund_demo

if [ -z "$1" ]; then
    echo "Usage: ./run-example.sh <example_name>"
    echo ""
    echo "Available examples:"
    echo "  - csv_refund_demo       (New CSV refund leaf demo)"
    echo "  - full_musig2_signing   (Complete MuSig2 signing)"
    echo "  - generate_address      (Address generation)"
    echo "  - get_full_tx           (Get full transaction)"
    echo "  - decode_tx             (Decode transaction)"
    exit 1
fi

echo "🚀 Running example: $1"
echo ""
cargo run --target x86_64-unknown-linux-gnu --example "$1"


