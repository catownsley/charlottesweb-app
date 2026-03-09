#!/bin/bash
# Generate self-signed TLS certificates for local development

set -e

CERT_DIR="./certs"
DAYS_VALID=365

echo "Generating self-signed TLS certificates for local development..."

# Create certs directory
mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# Generate certificate signing request (CSR)
openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/csr.pem" \
    -subj "/C=US/ST=California/L=San Francisco/O=CharlottesWeb Dev/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days $DAYS_VALID -in "$CERT_DIR/csr.pem" \
    -signkey "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Clean up CSR
rm "$CERT_DIR/csr.pem"

echo "Certificates generated successfully!"
echo "   Certificate: $CERT_DIR/cert.pem"
echo "   Private Key: $CERT_DIR/key.pem"
echo ""
echo "These are self-signed certificates for DEVELOPMENT ONLY"
echo "   Your browser will show a security warning - this is normal."
echo ""
echo "To run the server with HTTPS:"
echo "   uvicorn src.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem"
