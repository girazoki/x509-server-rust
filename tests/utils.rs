use base64::Engine as _;
use rcgen::SigningKey;
use rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PKCS_RSA_SHA256,
};
/// Supported algorithms
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TestAlgo {
    Rsa2048,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

/// Generates a self-signed certificate, DER bytes, and a signature for a message
pub fn generate_cert_and_signature(algo: TestAlgo, message: &[u8]) -> (Vec<u8>, String) {
    // Generate KeyPair for the requested algorithm
    let key_pair = match algo {
        TestAlgo::Rsa2048 => KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap(),
        TestAlgo::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        TestAlgo::EcdsaP384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
        TestAlgo::Ed25519 => KeyPair::generate_for(&PKCS_ED25519).unwrap(),
    };

    // Create certificate params with the generated key
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();

    // DER bytes of the certificate
    let der_bytes: Vec<u8> = cert.der().to_vec();

    // Sign the message using the KeyPair directly
    let sig_bytes = key_pair.sign(message).unwrap();

    // Base64-encode the signature
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    (der_bytes, sig_b64)
}
