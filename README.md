# X509 Server Rust

This project implements a Unix socket-based server that verifies signed bash scripts using X.509 certificates. The server supports multiple algorithms (RSA, ECDSA) and can be tested with example scripts.  The server only accepts **self-signed certificates** for now.

---

## Table of Contents

1. [Requirements](#requirements)  
2. [Compilation](#compilation)
3. [Running Rust tests](#running-rust-tests)    
3. [Generating Example Certificates](#generating-example-certificates) 
4. [Generating Signed Scripts](#generating-signed-scripts)  
5. [Running the Server](#running-the-server)  
6. [Testing Signed Scripts](#testing-signed-scripts)
7. [Testing for wrong certificates](#testing-wrong-certificates)    

---

## Requirements

- Rust (1.70+)  
- OpenSSL (for generating keys and scripts)  
- `bash`  
- `socat` (optional, for testing scripts via Unix socket)  

---

## Compilation

```bash
# Build the project in release mode
cargo build --release
```

This will produce a binary of the format:
```bash
./target/release/x509-server-rust
```

## Running Rust tests

```bash
# Test the project in release mode
cargo test --release
```

This will test all rust unitests that have been written

## Generating Example Certificates
This command generates a set of certificates using RSA and ECDSA256 and ECDSA384 for you to test the server. Simply run 

```bash
./scripts/generate_example_certificates.sh
```

The certificates will be under example_certificates. The script also generates a couple of wrong certificates, specifically:
- one that is signed by a CA, which is not permitted by the server currently (leaf.crt).
- one whose veritifcation does not match the supposed signer (bad.crt).

These will be under example_invalid_certs folder.
## Generating Signed Scripts
Similarly, this command will allow you to generate a set of signatures of a simple `echo "hello world"`bash command. After generating the certificates in the previous step you simply run

```bash
./scripts/generate_signed_scripts.sh
```
Outputs will be in ./example_bash_scripts:

```bash
rsa2048.sh → valid RSA-signed script

ecdsa_p256.sh → valid ECDSA P-256 signed script

ecdsa_p384.sh → valid ECDSA P-384 signed script

wrong_signature.sh → dummy signature (invalid)

untrusted_cert.sh → valid signature from a certificate not trusted by the server
```

Each script has the format:
```bash
# SIGNATURE: <base64-encoded signature>
<bash commands>
```

In this case the bash commands is a simple hello-world

## Running the server
Start the server with:
```bash
./target/release/x509-server-rust \
    --cert-path ./example_certs \
    --socket-path /tmp/x509-server.sock
```

where:
- --cert-path → folder containing trusted certificates (DER/PEM)

- --socket-path → Unix socket path

The server will:

- Load all certificates from the cert path.

- Listen for incoming connections on the Unix socket.

- Verify signed scripts against the trusted certificates.

- Execute the script if the signature is valid, otherwise return INVALID.

Note: Ensure the socket path is writable (/tmp is usually safe).

## Testing Signed Scripts
You can send a signed script to the server using socat:
```bash
socat - UNIX-CONNECT:/tmp/x509-server.sock < ./example_bash_scripts/rsa2048.sh
```
The expected OK response is: 

```bash
STATUS: OK
hello
```

else you will see different errors for different error cases, e.g

```bash
STATUS: INVALID
Signature verification failed
```

## Testing For Wrong Certificates
In order to test for wrong certificates, simply run 

```bash
./target/release/x509-server-rust \
    --cert-path ./example_invalid_certs \
    --socket-path /tmp/x509-server.sock
```

The server should say it does not find any valid certificates