#!/usr/bin/env bash
#
# generate_certs.sh — build the Chain of Trust used by the project.
#
#   ca.crt / ca.key       : our self-signed root Certificate Authority.
#   server.crt / server.key : the server's certificate, SIGNED BY the CA
#                             (issued for CN/SAN = localhost). This is the
#                             chain a verifying client accepts.
#   mitm.crt / mitm.key   : a SELF-SIGNED certificate for the MITM proxy, NOT
#                             signed by the CA. A client that verifies the chain
#                             rejects it — that rejection is the whole point of
#                             the demonstration.
#
# Run once from the project root:  ./certs/generate_certs.sh
set -euo pipefail

cd "$(dirname "$0")"
echo "[certs] working in $(pwd)"

DAYS=825

# --- 1. Root CA ------------------------------------------------------------
echo "[certs] creating root CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "/C=IN/O=SecureChat Lab/CN=SecureChat Root CA" \
    -out ca.crt

# --- 2. Server certificate signed by the CA --------------------------------
echo "[certs] creating server key + CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
    -subj "/C=IN/O=SecureChat Lab/CN=localhost" \
    -out server.csr

cat > server.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

echo "[certs] signing server certificate with the CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -extfile server.ext -out server.crt

# --- 3. Attacker's self-signed cert (NOT signed by the CA) -----------------
echo "[certs] creating attacker's forged (self-signed) certificate..."
openssl genrsa -out mitm.key 2048
openssl req -x509 -new -nodes -key mitm.key -sha256 -days "$DAYS" \
    -subj "/C=IN/O=Totally Legit Server/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -out mitm.crt

# --- cleanup intermediate artefacts ---------------------------------------
rm -f server.csr server.ext ca.srl

echo
echo "[certs] done. Verifying the chain of trust:"
openssl verify -CAfile ca.crt server.crt
echo "[certs] (expect the next check to FAIL — the MITM cert is not CA-signed)"
openssl verify -CAfile ca.crt mitm.crt || true
