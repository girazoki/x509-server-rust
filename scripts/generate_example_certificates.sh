#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="./example_certs"
INVALID_OUT_DIR="./example_invalid_certs"
DAYS=365
SUBJ="/C=US/ST=Test/L=Test/O=TestOrg/CN=localhost"
TMP_CA_DIR=$(mktemp -d)

mkdir -p "$OUT_DIR"
mkdir -p "$INVALID_OUT_DIR"
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
echo "✅ Done. Generated good certificate files:"
ls -1 "$OUT_DIR"


#######################################
# CA-signed certificate
#######################################
echo "→ Generating CA-signed certificate"

# --- Generate CA (temporary) ---
openssl genrsa -out "$TMP_CA_DIR/ca.key" 2048
openssl req -new -x509 -days "$DAYS" -key "$TMP_CA_DIR/ca.key" -out "$TMP_CA_DIR/ca.crt" -subj "/C=US/ST=Test/L=Test/O=TestOrg/CN=tempCA"

# --- Generate leaf key & CSR ---
openssl genrsa -out "$INVALID_OUT_DIR/leaf.key" 2048
openssl req -new -key "$INVALID_OUT_DIR/leaf.key" -out "$INVALID_OUT_DIR/leaf.csr" -subj "$SUBJ"

# --- Sign leaf with temp CA ---
openssl x509 -req -in "$INVALID_OUT_DIR/leaf.csr" -CA "$TMP_CA_DIR/ca.crt" -CAkey "$TMP_CA_DIR/ca.key" -CAcreateserial \
  -out "$INVALID_OUT_DIR/leaf.crt" -days "$DAYS" -sha256

# --- DER format (optional) ---
openssl x509 -in "$INVALID_OUT_DIR/leaf.crt" -outform der -out "$INVALID_OUT_DIR/leaf.der"


#######################################
# Wrongly signed self-signed certificate
#######################################

echo "→ Generating wrongly self-signed certificate"

# Normal self-signed cert
openssl genrsa -out "$INVALID_OUT_DIR/bad.key" 2048

# we generate the CSR with bad key so that it looks self-signed
openssl req -new -key "$INVALID_OUT_DIR/bad.key" -out "$INVALID_OUT_DIR/bad.csr" -subj "$SUBJ"

# But instead we sign it with the CA key, which will produce a wrong sig
openssl x509 -req -in "$INVALID_OUT_DIR/bad.csr" -CA "$TMP_CA_DIR/ca.crt" -CAkey "$TMP_CA_DIR/ca.key" -CAcreateserial -out "$INVALID_OUT_DIR/bad.crt" -days "$DAYS"

# DER
openssl x509 -in "$INVALID_OUT_DIR/bad.crt" -outform der -out "$INVALID_OUT_DIR/bad.der"

# Cleanup temp CA
rm -rf "$TMP_CA_DIR"
