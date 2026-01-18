#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="./example_certs"
DAYS=365
SUBJ="/C=US/ST=Test/L=Test/O=TestOrg/CN=localhost"

mkdir -p "$OUT_DIR"

echo "Generating certificates in $OUT_DIR"

#######################################
# RSA 2048
#######################################
echo "→ RSA 2048"
openssl genrsa -out "$OUT_DIR/rsa2048.key" 2048

# Normalize to PEM (explicit, consistent)
openssl pkey \
  -in "$OUT_DIR/rsa2048.key" \
  -out "$OUT_DIR/rsa2048.pem"

openssl req -new -x509 \
  -key "$OUT_DIR/rsa2048.pem" \
  -out "$OUT_DIR/rsa2048.crt" \
  -days "$DAYS" \
  -subj "$SUBJ" \
  -sha256

openssl x509 -in "$OUT_DIR/rsa2048.crt" -outform der -out "$OUT_DIR/rsa2048.der"

#######################################
# ECDSA P-256
#######################################
echo "→ ECDSA P-256"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$OUT_DIR/ecdsa_p256.key"

openssl pkey \
  -in "$OUT_DIR/ecdsa_p256.key" \
  -out "$OUT_DIR/ecdsa_p256.pem"

openssl req -new -x509 \
  -key "$OUT_DIR/ecdsa_p256.pem" \
  -out "$OUT_DIR/ecdsa_p256.crt" \
  -days "$DAYS" \
  -subj "$SUBJ" \
  -sha256

openssl x509 -in "$OUT_DIR/ecdsa_p256.crt" -outform der -out "$OUT_DIR/ecdsa_p256.der"

#######################################
# ECDSA P-384
#######################################
echo "→ ECDSA P-384"
openssl ecparam -name secp384r1 -genkey -noout \
  -out "$OUT_DIR/ecdsa_p384.key"

openssl pkey \
  -in "$OUT_DIR/ecdsa_p384.key" \
  -out "$OUT_DIR/ecdsa_p384.pem"

openssl req -new -x509 \
  -key "$OUT_DIR/ecdsa_p384.pem" \
  -out "$OUT_DIR/ecdsa_p384.crt" \
  -days "$DAYS" \
  -subj "$SUBJ" \
  -sha384

openssl x509 -in "$OUT_DIR/ecdsa_p384.crt" -outform der -out "$OUT_DIR/ecdsa_p384.der"

echo
echo "✅ Done. Generated files:"
ls -1 "$OUT_DIR"
