#!/bin/bash
# Simple script to serve the demo

echo "🚀 Starting local server for browser demo..."
echo ""
echo "📍 Open in browser:"
echo "   http://localhost:8001/examples/browser_csv_demo.html (Local demo)"
echo "   http://localhost:8001/examples/browser_backend_demo.html (Backend solver demo)"
echo ""
echo "💡 Make sure the solver backend is running on http://127.0.0.1:3000"
echo "   Run: cargo run --bin solver --features backend --target x86_64-unknown-linux-gnu"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python3 -m http.server 8001