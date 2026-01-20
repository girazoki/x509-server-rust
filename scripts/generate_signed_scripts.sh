#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="./example_certs"
OUT_DIR="./example_bash_scripts"
UNSUCCESFUL_OUT_DIR="./example_unsuccesful_bash_scripts"
SCRIPT_BODY="echo hello"

mkdir -p "$OUT_DIR"
mkdir -p "$UNSUCCESFUL_OUT_DIR"

# Helper function for Ed25519 signatures
sign_ed25519() {
    local key_file="$1"
    local script_body="$2"
    local tmpfile
    tmpfile=$(mktemp)

    # Write the script to a temp file
    printf "%s" "$script_body" > "$tmpfile"

    # Sign using OpenSSL pkey
    local sig
    sig=$(openssl pkeyutl -sign -inkey "$key_file" -in "$tmpfile" | base64 -w0)

    rm -f "$tmpfile"
    echo "$sig"
}

# General signing function
sign_script() {
    local key_file="$1"
    local algo="$2"
    local out_name="$3"
    local sig

    case "$algo" in
        rsa)
            sig=$(printf "%s" "$SCRIPT_BODY" \
                | openssl dgst -sha256 -sign "$key_file" \
                | base64 -w0)
            ;;
        ecdsa256)
            sig=$(printf "%s" "$SCRIPT_BODY" \
                | openssl dgst -sha256 -sign "$key_file" \
                | base64 -w0)
            ;;
        ecdsa384)
            sig=$(printf "%s" "$SCRIPT_BODY" \
                | openssl dgst -sha384 -sign "$key_file" \
                | base64 -w0)
            ;;
        *)
            echo "Unknown algorithm: $algo" >&2
            return 1
            ;;
    esac

    {
        echo "# SIGNATURE: $sig"
        echo "$SCRIPT_BODY"
    } > "$OUT_DIR/$out_name.sh"

    echo "Generated $OUT_DIR/$out_name.sh"
}

# Generate valid scripts
sign_script "$CERT_DIR/rsa2048.pem"    "rsa"        "rsa2048"
sign_script "$CERT_DIR/ecdsa_p256.pem" "ecdsa256"   "ecdsa_p256"
sign_script "$CERT_DIR/ecdsa_p384.pem" "ecdsa384"   "ecdsa_p384"

#######################################
# VALID SIGNATURE, NOT A 
#######################################

# Sign the script with the untrusted key
signature=$(printf "%s" "$SCRIPT_BODY" \
    | openssl dgst -sha256 -sign "$CERT_DIR/non_code_signing.pem" \
    | base64 -w0)

# Write the signed script
{
    echo "# SIGNATURE: $signature"
    echo "$SCRIPT_BODY"
} > "$UNSUCCESFUL_OUT_DIR/non_code_siging_cert.sh"

echo "Generated $UNSUCCESFUL_OUT_DIR/non_code_siging_cert.sh"

#######################################
# VALID SIGNATURE, UNTRUSTED CERT (generated on the fly)
#######################################
untrusted_key=$(mktemp)

# Generate a temporary RSA key
openssl genrsa -out "$untrusted_key" 2048

# Sign the script with the untrusted key
sig_untrusted=$(printf "%s" "$SCRIPT_BODY" \
    | openssl dgst -sha256 -sign "$untrusted_key" \
    | base64 -w0)

# Write the signed script
{
    echo "# SIGNATURE: $sig_untrusted"
    echo "$SCRIPT_BODY"
} > "$UNSUCCESFUL_OUT_DIR/untrusted_cert.sh"

echo "Generated $UNSUCCESFUL_OUT_DIR/untrusted.sh"

# Clean up temp files
rm -f "$untrusted_key"

#######################################
# WRONG SIGNATURE FORMAT
#######################################
{
    echo "# SIGNATURE: THIS_IS_NOT_BASE64_AND_NOT_A_SIGNATURE"
    echo "$SCRIPT_BODY"
} > "$UNSUCCESFUL_OUT_DIR/invalid_signature_format.sh"

echo "Generated $UNSUCCESFUL_OUT_DIR/invalid_signature.sh"