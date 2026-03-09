#!/bin/bash
# Run CharlottesWeb with HTTPS (self-signed certs for development)

set -e

# Check if certificates exist
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    echo "TLS certificates not found!"
    echo "   Run ./scripts/generate_dev_certs.sh first to generate certificates."
    exit 1
fi

echo "Starting CharlottesWeb with HTTPS..."
echo "   https://localhost:8443"
echo "   API Docs: https://localhost:8443/docs"
echo ""
echo "Your browser will show a security warning (self-signed cert)"
echo "   Click 'Advanced' -> 'Proceed to localhost' to continue"
echo ""

PYTHON_BIN="/Users/ct/Python/.venv/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    echo "❌ Expected Python environment not found at $PYTHON_BIN"
    echo "   Create it with: python3.14 -m venv /Users/ct/Python/.venv"
    exit 1
fi

# Set PYTHONPATH and run with uvicorn
export PYTHONPATH=/Users/ct/Python/charlottesweb-app
exec "$PYTHON_BIN" -m uvicorn src.main:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile certs/key.pem \
    --ssl-certfile certs/cert.pem \
    --reload
